import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  operatorAuthorizationError,
  rateLimitError,
  resetRateLimitsForTests,
} from "./access";

beforeEach(() => {
  resetRateLimitsForTests();
  vi.stubEnv("UPSTASH_REDIS_REST_URL", "");
  vi.stubEnv("UPSTASH_REDIS_REST_TOKEN", "");
});

afterEach(() => {
  vi.unstubAllEnvs();
});

function request(headers: HeadersInit = {}) {
  return new Request("https://proofgate.example/api/guard", { headers });
}

describe("operator access", () => {
  it("allows an unconfigured local development route", () => {
    vi.stubEnv("NODE_ENV", "development");
    vi.stubEnv("PROOFGATE_API_KEY", "");

    expect(operatorAuthorizationError(request())).toBeNull();
  });

  it("fails closed when a production operator key is not configured", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("PROOFGATE_API_KEY", "");

    const response = operatorAuthorizationError(request());
    expect(response?.status).toBe(503);
    await expect(response?.json()).resolves.toMatchObject({
      error: "operator_access_not_configured",
    });
  });

  it("accepts only the configured bearer key", async () => {
    vi.stubEnv("PROOFGATE_API_KEY", "correct-key");

    expect(
      operatorAuthorizationError(
        request({ Authorization: "Bearer correct-key" }),
      ),
    ).toBeNull();

    const missing = operatorAuthorizationError(request());
    const wrong = operatorAuthorizationError(
      request({ Authorization: "Bearer wrong-key" }),
    );
    expect(missing?.status).toBe(401);
    expect(wrong?.status).toBe(401);
    expect(wrong?.headers.get("www-authenticate")).toContain("Bearer");
  });
});

describe("request rate limits", () => {
  it("limits one identity and returns an honourable retry delay", async () => {
    const first = request({
      Authorization: "Bearer operator-a",
      "X-Forwarded-For": "203.0.113.1",
    });

    expect(
      await rateLimitError(first, { scope: "guard", limit: 2, windowMs: 60_000 }),
    ).toBeNull();
    expect(
      await rateLimitError(first, { scope: "guard", limit: 2, windowMs: 60_000 }),
    ).toBeNull();
    const refused = await rateLimitError(first, {
      scope: "guard",
      limit: 2,
      windowMs: 60_000,
    });
    expect(refused?.status).toBe(429);
    expect(Number(refused?.headers.get("retry-after"))).toBeGreaterThan(0);
  });

  it("keeps independent identities in separate buckets", async () => {
    const options = { scope: "guard", limit: 1, windowMs: 60_000 };
    const first = request({ Authorization: "Bearer operator-a" });
    const second = request({ Authorization: "Bearer operator-b" });

    expect(await rateLimitError(first, options)).toBeNull();
    expect((await rateLimitError(first, options))?.status).toBe(429);
    expect(await rateLimitError(second, options)).toBeNull();
  });

  it("rejects invalid limiter settings", async () => {
    await expect(
      rateLimitError(request(), { scope: "guard", limit: 0, windowMs: 1 }),
    ).rejects.toThrow(RangeError);
  });
});
