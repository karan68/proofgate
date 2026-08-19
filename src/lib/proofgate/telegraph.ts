import { ExactEvmScheme, toClientEvmSigner } from "@x402/evm";
import {
  decodePaymentResponseHeader,
  wrapFetchWithPaymentFromConfig,
} from "@x402/fetch";
import { privateKeyToAccount } from "viem/accounts";
import { z } from "zod";

import { evaluatePolicy, type PolicyResult } from "./policy";
import { normalizeTargetUrl } from "./target";

const DEFAULT_NODE_URL = "https://devnode.telegraphprotocol.com";
const BASE_SEPOLIA = "eip155:84532";
const DEFAULT_MAX_PAYMENT_ATOMIC = 100_000n;

const minerSchema = z.object({
  id: z.string(),
  name: z.string(),
  slug: z.string(),
  description: z.string().default(""),
  base_url: z.string().optional(),
  capabilities: z.array(z.string()),
  cost_per_call: z.string(),
  protocol: z.string(),
});

const minerDiscoverySchema = z.object({
  count: z.number().int().nonnegative(),
  intent_id: z.literal("URL_SCAN"),
  miners: z.array(minerSchema),
});

const engineMetadataSchema = z
  .object({
    miner_id: z.string().optional(),
    miner_name: z.string().optional(),
    intent: z.string().optional(),
    reasoning: z.string().optional(),
    signal_hash: z.string().optional(),
    cost_usd: z.number().optional(),
    duration_ms: z.number().optional(),
    timestamp: z.string().optional(),
  })
  .passthrough();

export type UrlScanMiner = z.infer<typeof minerSchema>;

export interface UrlScanDiscovery {
  count: number;
  intent_id: "URL_SCAN";
  miners: UrlScanMiner[];
  checked_at: string;
}

export interface TelegraphScanResult {
  target_url: string;
  decision: PolicyResult["decision"];
  finding: PolicyResult["finding"];
  miner_id: string | null;
  miner_name: string | null;
  intent: string | null;
  routing_reason: string | null;
  signal_hash: string | null;
  cost_usd: number | null;
  duration_ms: number | null;
  timestamp: string;
  settlement: unknown | null;
  raw_result: unknown;
}

export class TelegraphConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TelegraphConfigurationError";
  }
}

export class TelegraphRequestError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "TelegraphRequestError";
    this.status = status;
  }
}

function nodeUrl(value?: string): string {
  return (value ?? process.env.TELEGRAPH_NODE_URL ?? DEFAULT_NODE_URL).replace(/\/$/, "");
}

function maxPaymentAtomic(): bigint {
  const configured = process.env.PROOFGATE_MAX_TELEGRAPH_PAYMENT_ATOMIC;
  if (!configured) return DEFAULT_MAX_PAYMENT_ATOMIC;

  try {
    const amount = BigInt(configured);
    if (amount <= 0n) throw new Error("non-positive");
    return amount;
  } catch {
    throw new TelegraphConfigurationError(
      "PROOFGATE_MAX_TELEGRAPH_PAYMENT_ATOMIC must be a positive integer.",
    );
  }
}

export function createCappedEvmPaymentFetch(options: {
  baseFetch?: typeof fetch;
  maxAtomic?: bigint;
  network?: `${string}:${string}`;
} = {}): typeof fetch {
  const privateKey = process.env.TELEGRAPH_EVM_PRIVATE_KEY;
  if (!privateKey || !/^0x[0-9a-fA-F]{64}$/.test(privateKey)) {
    throw new TelegraphConfigurationError(
      "Set a funded Base Sepolia burner key in TELEGRAPH_EVM_PRIVATE_KEY.",
    );
  }

  const account = privateKeyToAccount(privateKey as `0x${string}`);
  const cap = options.maxAtomic ?? maxPaymentAtomic();
  const network = options.network ?? BASE_SEPOLIA;
  if (cap <= 0n) {
    throw new TelegraphConfigurationError("The x402 payment cap must be positive.");
  }

  return wrapFetchWithPaymentFromConfig(options.baseFetch ?? fetch, {
    schemes: [
      {
        network,
        client: new ExactEvmScheme(toClientEvmSigner(account)),
      },
    ],
    policies: [
      (_version, requirements) =>
        requirements.filter(
          (requirement) =>
            requirement.network === network &&
            /^\d+$/.test(requirement.amount) &&
            BigInt(requirement.amount) <= cap,
        ),
    ],
  });
}

async function responseBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return null;

  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function errorDetail(body: unknown): string {
  if (typeof body === "string") return body.slice(0, 500);
  if (typeof body === "object" && body !== null) {
    const record = body as Record<string, unknown>;
    for (const key of ["error", "message", "detail"]) {
      if (typeof record[key] === "string") return record[key].slice(0, 500);
    }
  }
  return "Telegraph returned an unsuccessful response.";
}

export async function discoverUrlScanMiners(options: {
  fetcher?: typeof fetch;
  baseUrl?: string;
} = {}): Promise<UrlScanDiscovery> {
  const fetcher = options.fetcher ?? fetch;
  const response = await fetcher(
    `${nodeUrl(options.baseUrl)}/engine/v1/intents/URL_SCAN/miners`,
    {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(10_000),
      cache: "no-store",
    },
  );
  const body = await responseBody(response);

  if (!response.ok) {
    throw new TelegraphRequestError(response.status, errorDetail(body));
  }

  return {
    ...minerDiscoverySchema.parse(body),
    checked_at: new Date().toISOString(),
  };
}

export async function askTelegraphUrlSafety(
  target: string,
  options: {
    fetcher?: typeof fetch;
    baseUrl?: string;
  } = {},
): Promise<TelegraphScanResult> {
  const normalized = normalizeTargetUrl(target);
  const fetcher = options.fetcher ?? createCappedEvmPaymentFetch();
  const response = await fetcher(`${nodeUrl(options.baseUrl)}/engine/v1/ask`, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      query: `Scan this URL and decide whether it is safe or malicious: ${normalized.url}`,
      context: { url: normalized.url },
    }),
    signal: AbortSignal.timeout(45_000),
    cache: "no-store",
  });
  const body = await responseBody(response);

  if (!response.ok) {
    throw new TelegraphRequestError(response.status, errorDetail(body));
  }

  const metadata = engineMetadataSchema.parse(body);
  const policy = evaluatePolicy(body);
  const settlementHeader = response.headers.get("payment-response");
  let settlement: unknown | null = null;
  if (settlementHeader) {
    try {
      settlement = decodePaymentResponseHeader(settlementHeader);
    } catch {
      settlement = { encoded: settlementHeader };
    }
  }

  return {
    target_url: normalized.url,
    decision: policy.decision,
    finding: policy.finding,
    miner_id: metadata.miner_id ?? null,
    miner_name: metadata.miner_name ?? null,
    intent: metadata.intent ?? null,
    routing_reason: metadata.reasoning ?? null,
    signal_hash: metadata.signal_hash ?? null,
    cost_usd: metadata.cost_usd ?? null,
    duration_ms: metadata.duration_ms ?? null,
    timestamp: metadata.timestamp ?? new Date().toISOString(),
    settlement,
    raw_result: metadata.result ?? body,
  };
}

export function telegraphRuntimeStatus() {
  const key = process.env.TELEGRAPH_EVM_PRIVATE_KEY;
  return {
    node_url: nodeUrl(),
    payment_network: BASE_SEPOLIA,
    payment_ready: Boolean(key && /^0x[0-9a-fA-F]{64}$/.test(key)),
    operator_access_required:
      process.env.NODE_ENV === "production" || Boolean(process.env.PROOFGATE_API_KEY),
    max_payment_atomic: maxPaymentAtomic().toString(),
  };
}