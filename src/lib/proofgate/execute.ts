import { isIP } from "node:net";

import {
  Agent,
  buildConnector,
  fetch as undiciFetch,
  type RequestInit as UndiciRequestInit,
} from "undici";
import { decodePaymentResponseHeader } from "@x402/fetch";

import { createCappedEvmPaymentFetch } from "./telegraph";
import { assertPublicTarget, type AddressLookup } from "./target";

const DEFAULT_MAX_BYTES = 256 * 1024;
const DEFAULT_TARGET_PAYMENT_CAP = 50_000n;

export interface GuardedExecutionResult {
  attempted: true;
  status: number;
  content_type: string | null;
  bytes: number;
  final_url: string;
  redirect_location: string | null;
  preview: string | null;
  payment_settlement: unknown | null;
  error: null;
}

export class TargetExecutionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TargetExecutionError";
  }
}

function targetPaymentCap(): bigint {
  const value = process.env.PROOFGATE_MAX_TARGET_PAYMENT_ATOMIC;
  if (!value) return DEFAULT_TARGET_PAYMENT_CAP;
  try {
    const amount = BigInt(value);
    if (amount <= 0n) throw new Error("non-positive");
    return amount;
  } catch {
    throw new TargetExecutionError(
      "PROOFGATE_MAX_TARGET_PAYMENT_ATOMIC must be a positive integer.",
    );
  }
}

async function readLimitedBody(response: Response, maxBytes: number): Promise<Uint8Array> {
  const declared = response.headers.get("content-length");
  if (declared && Number(declared) > maxBytes) {
    await response.body?.cancel();
    throw new TargetExecutionError(`Target response exceeds the ${maxBytes}-byte limit.`);
  }

  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new TargetExecutionError(`Target response exceeds the ${maxBytes}-byte limit.`);
    }
    chunks.push(value);
  }

  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

function textPreview(bytes: Uint8Array, contentType: string | null): string | null {
  if (
    !contentType ||
    !/(?:json|text|javascript|xml|x-www-form-urlencoded)/i.test(contentType)
  ) {
    return null;
  }

  return new TextDecoder("utf-8", { fatal: false })
    .decode(bytes.slice(0, 2_000))
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .trim();
}

function pinnedAgent(address: string, servername: string): Agent {
  const connector = buildConnector({ timeout: 10_000 });
  return new Agent({
    connect(options, callback) {
      connector(
        {
          ...options,
          hostname: address,
          servername,
        },
        callback,
      );
    },
    headersTimeout: 15_000,
    bodyTimeout: 15_000,
    maxResponseSize: DEFAULT_MAX_BYTES + 1,
    pipelining: 0,
  });
}

export async function executeGuardedTarget(
  input: string,
  options: {
    method?: "GET" | "HEAD";
    lookup?: AddressLookup;
    maxBytes?: number;
    maxPaymentAtomic?: bigint;
    baseFetch?: typeof fetch;
  } = {},
): Promise<GuardedExecutionResult> {
  const target = await assertPublicTarget(input, { lookup: options.lookup });
  const address =
    target.addresses.find((candidate) => isIP(candidate) === 4) ?? target.addresses[0];
  const agent = pinnedAgent(address, target.hostname);
  const maxBytes = Math.max(1, Math.min(options.maxBytes ?? DEFAULT_MAX_BYTES, 1024 * 1024));

  const baseFetch =
    options.baseFetch ??
    ((async (resource, init) => {
      const response = await undiciFetch(resource as string | URL, {
        ...(init as UndiciRequestInit),
        dispatcher: agent,
      });
      return response as unknown as Response;
    }) as typeof fetch);
  const fetchWithPayment = createCappedEvmPaymentFetch({
    baseFetch,
    maxAtomic: options.maxPaymentAtomic ?? targetPaymentCap(),
  });

  try {
    const response = await fetchWithPayment(target.url, {
      method: options.method ?? "GET",
      headers: {
        Accept: "application/json, text/plain;q=0.9, */*;q=0.1",
        "User-Agent": "ProofGate/1.0 guarded-agent",
      },
      redirect: "manual",
      signal: AbortSignal.timeout(30_000),
    });
    const bytes = options.method === "HEAD" ? new Uint8Array() : await readLimitedBody(response, maxBytes);
    const contentType = response.headers.get("content-type");
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
      attempted: true,
      status: response.status,
      content_type: contentType,
      bytes: bytes.byteLength,
      final_url: response.url || target.url,
      redirect_location: response.headers.get("location"),
      preview: textPreview(bytes, contentType),
      payment_settlement: settlement,
      error: null,
    };
  } catch (error) {
    if (error instanceof TargetExecutionError) throw error;
    throw new TargetExecutionError(`Guarded target request failed: ${(error as Error).message}`);
  } finally {
    await agent.close();
  }
}