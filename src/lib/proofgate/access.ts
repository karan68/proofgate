import { createHash, timingSafeEqual } from "node:crypto";

import { redisCommand, redisConfiguration } from "./redis";

interface RateBucket {
  count: number;
  resetAt: number;
}

const globalState = globalThis as typeof globalThis & {
  proofGateRateBuckets?: Map<string, RateBucket>;
};
const rateBuckets = globalState.proofGateRateBuckets ?? new Map<string, RateBucket>();
globalState.proofGateRateBuckets = rateBuckets;

const RATE_LIMIT_SCRIPT = `
local count = redis.call("INCR", KEYS[1])
if count == 1 then
  redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
local ttl = redis.call("PTTL", KEYS[1])
return {count, ttl}
`;

function constantTimeEqual(actual: string, expected: string): boolean {
  const actualHash = createHash("sha256").update(actual).digest();
  const expectedHash = createHash("sha256").update(expected).digest();
  return timingSafeEqual(actualHash, expectedHash);
}

export function operatorAuthorizationError(request: Request): Response | null {
  const expected = process.env.PROOFGATE_API_KEY?.trim();
  if (!expected) {
    if (process.env.NODE_ENV !== "production") return null;
    return Response.json(
      {
        error: "operator_access_not_configured",
        message: "Configure PROOFGATE_API_KEY before enabling paid production routes.",
      },
      { status: 503 },
    );
  }

  const authorization = request.headers.get("authorization") ?? "";
  const prefix = "Bearer ";
  const provided = authorization.startsWith(prefix)
    ? authorization.slice(prefix.length)
    : "";
  if (!provided || !constantTimeEqual(provided, expected)) {
    return Response.json(
      { error: "unauthorized", message: "A valid operator bearer key is required." },
      {
        status: 401,
        headers: { "WWW-Authenticate": 'Bearer realm="ProofGate"' },
      },
    );
  }

  return null;
}

function requestIdentity(request: Request): string {
  const authorization = request.headers.get("authorization") ?? "anonymous";
  const forwarded =
    request.headers.get("x-vercel-forwarded-for") ??
    request.headers.get("x-forwarded-for") ??
    "local";
  const address = forwarded.split(",")[0].trim();
  return createHash("sha256")
    .update(`${authorization}\u0000${address}`)
    .digest("hex")
    .slice(0, 32);
}

function limitedResponse(limit: number, retryAfterMs: number): Response {
  return Response.json(
    { error: "rate_limited", message: "Too many requests. Retry later." },
    {
      status: 429,
      headers: {
        "Retry-After": String(Math.max(1, Math.ceil(retryAfterMs / 1_000))),
        "X-RateLimit-Limit": String(limit),
      },
    },
  );
}

export async function rateLimitError(
  request: Request,
  options: { scope: string; limit: number; windowMs: number },
): Promise<Response | null> {
  if (
    !Number.isSafeInteger(options.limit) ||
    options.limit < 1 ||
    !Number.isSafeInteger(options.windowMs) ||
    options.windowMs < 1
  ) {
    throw new RangeError("Rate-limit values must be positive safe integers.");
  }

  const key = `proofgate:rate:${options.scope}:${requestIdentity(request)}`;
  const redis = redisConfiguration();
  if (redis) {
    const [count, ttl] = await redisCommand<[number, number]>(
      ["EVAL", RATE_LIMIT_SCRIPT, 1, key, options.windowMs],
      redis,
    );
    return count > options.limit ? limitedResponse(options.limit, ttl) : null;
  }

  const now = Date.now();
  for (const [bucketKey, bucket] of rateBuckets) {
    if (bucket.resetAt <= now) rateBuckets.delete(bucketKey);
  }

  const current = rateBuckets.get(key);
  if (!current) {
    rateBuckets.set(key, { count: 1, resetAt: now + options.windowMs });
    return null;
  }
  current.count += 1;
  if (current.count > options.limit) {
    return limitedResponse(options.limit, current.resetAt - now);
  }
  return null;
}

export function resetRateLimitsForTests(): void {
  rateBuckets.clear();
}
