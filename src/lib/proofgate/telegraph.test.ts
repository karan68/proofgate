import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  askTelegraphUrlSafety,
  createCappedEvmPaymentFetch,
  discoverUrlScanMiners,
  TelegraphConfigurationError,
  TelegraphRequestError,
  telegraphRuntimeStatus,
} from "./telegraph";

const BASE_SEPOLIA_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";

function challenge(amount: string, network = "eip155:84532") {
  return Buffer.from(
    JSON.stringify({
      x402Version: 2,
      error: "Payment required",
      resource: {
        url: "https://example.com/resource",
        description: "Test resource",
        mimeType: "application/json",
      },
      accepts: [
        {
          scheme: "exact",
          network,
          asset: BASE_SEPOLIA_USDC,
          amount,
          payTo: `0x${"22".repeat(20)}`,
          maxTimeoutSeconds: 60,
          extra: { name: "USDC", version: "2" },
        },
      ],
    }),
  ).toString("base64");
}

function paymentRequired(amount: string, network?: string) {
  return new Response(JSON.stringify({ error: "payment required" }), {
    status: 402,
    headers: { "payment-required": challenge(amount, network) },
  });
}

function compatibleIntegration() {
  return {
    id: "5001",
    slug: "url-sentinel",
    name: "URL Sentinel",
    endpoints: [{ path: "/scan", method: "POST" }],
    input_schema: { properties: { url: { type: "string" } } },
    output_schema: {
      properties: {
        verdict: { type: "string" },
        confidence: { type: "number" },
      },
    },
    signal_mapping: {
      label_field: "verdict",
      confidence_field: "confidence",
    },
    supported_intents: ["URL_SCAN"],
    min_price_usdc: 10_000,
  };
}

beforeEach(() => {
  vi.stubEnv("TELEGRAPH_EVM_PRIVATE_KEY", `0x${"11".repeat(32)}`);
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("Telegraph adapter", () => {
  it("parses live URL_SCAN discovery semantics", async () => {
    const fetcher = async () =>
      new Response(
        JSON.stringify({
          count: 1,
          intent_id: "URL_SCAN",
          miners: [
            {
              id: "223",
              name: "URLScan.io",
              slug: "urlscan",
              description: "Browser sandbox",
              base_url: "https://urlscan.io/api/v1",
              capabilities: ["URL_SCAN"],
              cost_per_call: "0.01",
              protocol: "generic",
            },
          ],
        }),
        { status: 200 },
      );

    await expect(
      discoverUrlScanMiners({ fetcher: fetcher as typeof fetch }),
    ).resolves.toMatchObject({
      count: 1,
      intent_id: "URL_SCAN",
      miners: [{ slug: "urlscan" }],
    });
  });

  it("selects a compatible URL_SCAN Miner and normalizes its response", async () => {
    let requestUrl: string | null = null;
    let requestBody: unknown;
    const fetcher = async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith("/miner-dispatcher/integrations")) {
        return Response.json([compatibleIntegration()]);
      }
      requestUrl = String(input);
      requestBody = JSON.parse(String(init?.body));
      return new Response(
        JSON.stringify({
          verdict: "malicious",
          malicious: true,
          confidence: 0.98,
          reason: "Known phishing URL.",
        }),
        { status: 200 },
      );
    };

    const result = await askTelegraphUrlSafety("https://EXAMPLE.com/path#fragment", {
      fetcher: fetcher as typeof fetch,
    });

    expect(requestUrl).toBe(
      "https://devnode.telegraphprotocol.com/miner-dispatcher/v1/5001/scan",
    );
    expect(requestBody).toEqual({
      url: "https://example.com/path",
    });
    expect(result).toMatchObject({
      decision: "BLOCK",
      miner_id: "5001",
      miner_name: "URL Sentinel",
      intent: "URL_SCAN",
      cost_usd: 0.01,
      finding: { verdict: "malicious" },
    });
    expect(result.signal_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("does not turn a failed Telegraph response into a verdict", async () => {
    const fetcher = async (input: RequestInfo | URL) => {
      if (String(input).endsWith("/miner-dispatcher/integrations")) {
        return Response.json([compatibleIntegration()]);
      }
      return new Response(JSON.stringify({ error: "routing unavailable" }), {
        status: 503,
      });
    };

    await expect(
      askTelegraphUrlSafety("https://example.com", {
        fetcher: fetcher as typeof fetch,
      }),
    ).rejects.toEqual(new TelegraphRequestError(503, "routing unavailable"));
  });

  it("refuses before dispatch when no synchronous URL_SCAN Miner is compatible", async () => {
    const incompatible = {
      ...compatibleIntegration(),
      output_schema: { properties: { uuid: { type: "string" } } },
    };
    const fetcher = vi.fn(async () => Response.json([incompatible]));

    await expect(
      askTelegraphUrlSafety("https://example.com", {
        fetcher: fetcher as typeof fetch,
      }),
    ).rejects.toEqual(
      new TelegraphRequestError(
        503,
        "No live URL_SCAN Miner declares a synchronous verdict/confidence contract.",
      ),
    );
    expect(fetcher).toHaveBeenCalledOnce();
  });

  it("signs an exact Base Sepolia requirement at the configured cap", async () => {
    const baseFetch = vi
      .fn()
      .mockResolvedValueOnce(paymentRequired("10000"))
      .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));
    const paidFetch = createCappedEvmPaymentFetch({
      baseFetch: baseFetch as typeof fetch,
      maxAtomic: 10_000n,
    });

    const response = await paidFetch("https://example.com/resource");

    expect(response.status).toBe(200);
    expect(baseFetch).toHaveBeenCalledTimes(2);
    const retry = baseFetch.mock.calls[1][0] as Request;
    expect(retry.headers.get("payment-signature")).toBeTruthy();
  });

  it("refuses an over-cap requirement before sending a signed retry", async () => {
    const baseFetch = vi.fn().mockResolvedValue(paymentRequired("10001"));
    const paidFetch = createCappedEvmPaymentFetch({
      baseFetch: baseFetch as typeof fetch,
      maxAtomic: 10_000n,
    });

    await expect(paidFetch("https://example.com/resource")).rejects.toThrow();
    expect(baseFetch).toHaveBeenCalledOnce();
  });

  it("refuses a requirement on a different network", async () => {
    const baseFetch = vi
      .fn()
      .mockResolvedValue(paymentRequired("10000", "eip155:8453"));
    const paidFetch = createCappedEvmPaymentFetch({
      baseFetch: baseFetch as typeof fetch,
      maxAtomic: 10_000n,
    });

    await expect(paidFetch("https://example.com/resource")).rejects.toThrow();
    expect(baseFetch).toHaveBeenCalledOnce();
  });

  it("rejects missing credentials and invalid configured caps", () => {
    vi.stubEnv("TELEGRAPH_EVM_PRIVATE_KEY", "");
    expect(() => createCappedEvmPaymentFetch()).toThrow(TelegraphConfigurationError);

    vi.stubEnv("TELEGRAPH_EVM_PRIVATE_KEY", `0x${"11".repeat(32)}`);
    for (const invalid of ["0", "-1", "1.5", "not-a-number"]) {
      vi.stubEnv("PROOFGATE_MAX_TELEGRAPH_PAYMENT_ATOMIC", invalid);
      expect(() => telegraphRuntimeStatus()).toThrow(TelegraphConfigurationError);
    }
  });

  it("propagates failed discovery instead of returning an empty pool", async () => {
    const fetcher = async () =>
      new Response(JSON.stringify({ detail: "catalog unavailable" }), { status: 502 });

    await expect(
      discoverUrlScanMiners({ fetcher: fetcher as typeof fetch }),
    ).rejects.toEqual(new TelegraphRequestError(502, "catalog unavailable"));
  });
});