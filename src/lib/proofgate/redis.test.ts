import { afterEach, describe, expect, it, vi } from "vitest";

import { redisConfiguration, RedisConfigurationError } from "./redis";

afterEach(() => {
  vi.unstubAllEnvs();
});

function clearRedisEnvironment() {
  vi.stubEnv("UPSTASH_REDIS_REST_URL", "");
  vi.stubEnv("UPSTASH_REDIS_REST_TOKEN", "");
  vi.stubEnv("KV_REST_API_URL", "");
  vi.stubEnv("KV_REST_API_TOKEN", "");
}

describe("Redis configuration", () => {
  it("returns null when no Redis variables are present", () => {
    clearRedisEnvironment();
    expect(redisConfiguration()).toBeNull();
  });

  it("accepts standard Upstash REST variables", () => {
    clearRedisEnvironment();
    vi.stubEnv("UPSTASH_REDIS_REST_URL", "https://upstash.example/");
    vi.stubEnv("UPSTASH_REDIS_REST_TOKEN", "upstash-token");

    expect(redisConfiguration()).toEqual({
      url: "https://upstash.example",
      token: "upstash-token",
    });
  });

  it("accepts Vercel Marketplace KV aliases", () => {
    clearRedisEnvironment();
    vi.stubEnv("KV_REST_API_URL", "https://vercel-kv.example/");
    vi.stubEnv("KV_REST_API_TOKEN", "kv-token");

    expect(redisConfiguration()).toEqual({
      url: "https://vercel-kv.example",
      token: "kv-token",
    });
  });

  it("rejects a partial Redis configuration", () => {
    clearRedisEnvironment();
    vi.stubEnv("KV_REST_API_URL", "https://vercel-kv.example");

    expect(() => redisConfiguration()).toThrow(RedisConfigurationError);
  });
});
