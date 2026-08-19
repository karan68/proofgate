import { createHash } from "node:crypto";

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

const integrationSchema = z
  .object({
    id: z.union([z.string(), z.number()]).transform(String),
    slug: z.string(),
    name: z.string(),
    endpoints: z.array(
      z.object({
        path: z.string(),
        method: z.string(),
      }),
    ),
    input_schema: z
      .object({
        properties: z.record(z.string(), z.unknown()).optional(),
      })
      .passthrough()
      .nullish(),
    output_schema: z
      .object({
        properties: z.record(z.string(), z.unknown()).optional(),
      })
      .passthrough()
      .nullish(),
    signal_mapping: z
      .object({
        confidence_field: z.string().optional(),
        label_field: z.string().optional(),
      })
      .passthrough()
      .nullish(),
    supported_intents: z.array(z.string()),
    min_price_usdc: z.number().nonnegative(),
  })
  .passthrough();

type UrlScanIntegration = z.infer<typeof integrationSchema>;

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

async function selectUrlScanIntegration(
  fetcher: typeof fetch,
  baseUrl?: string,
): Promise<UrlScanIntegration & { scan_path: string }> {
  const response = await fetcher(
    `${nodeUrl(baseUrl)}/miner-dispatcher/integrations`,
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

  const integrations = z.array(integrationSchema).parse(body);
  const candidates = integrations
    .flatMap((integration) => {
      const endpoint = integration.endpoints.find(
        (candidate) =>
          candidate.method.toUpperCase() === "POST" && candidate.path === "/scan",
      );
      const compatible =
        integration.supported_intents.includes("URL_SCAN") &&
        endpoint &&
        BigInt(Math.round(integration.min_price_usdc)) <= maxPaymentAtomic() &&
        "url" in (integration.input_schema?.properties ?? {}) &&
        "verdict" in (integration.output_schema?.properties ?? {}) &&
        "confidence" in (integration.output_schema?.properties ?? {}) &&
        integration.signal_mapping?.label_field === "verdict" &&
        integration.signal_mapping?.confidence_field === "confidence";
      return compatible ? [{ ...integration, scan_path: endpoint.path }] : [];
    })
    .filter((integration) => integration.slug !== "proofgate-url-intelligence")
    .sort((left, right) => left.slug.localeCompare(right.slug));

  const selected = candidates[0];
  if (!selected) {
    throw new TelegraphRequestError(
      503,
      "No live URL_SCAN Miner declares a synchronous verdict/confidence contract.",
    );
  }
  return selected;
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
  const selected = await selectUrlScanIntegration(fetcher, options.baseUrl);
  const startedAt = Date.now();
  const response = await fetcher(
    `${nodeUrl(options.baseUrl)}/miner-dispatcher/v1/${selected.id}${selected.scan_path}`,
    {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url: normalized.url }),
      signal: AbortSignal.timeout(45_000),
      cache: "no-store",
    },
  );
  const body = await responseBody(response);

  if (!response.ok) {
    throw new TelegraphRequestError(response.status, errorDetail(body));
  }

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
    miner_id: selected.id,
    miner_name: selected.name,
    intent: "URL_SCAN",
    routing_reason:
      "Selected from the live URL_SCAN catalog using its declared synchronous verdict/confidence contract.",
    signal_hash: `sha256:${responseHash(body)}`,
    cost_usd: selected.min_price_usdc / 1_000_000,
    duration_ms: Date.now() - startedAt,
    timestamp: new Date().toISOString(),
    settlement,
    raw_result: body,
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

function responseHash(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}