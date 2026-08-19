export interface RedisConfiguration {
  url: string;
  token: string;
}

export class RedisConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RedisConfigurationError";
  }
}

export function redisConfiguration(): RedisConfiguration | null {
  const url = process.env.UPSTASH_REDIS_REST_URL?.replace(/\/$/, "");
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;

  if (!url && !token) return null;
  if (!url || !token) {
    throw new RedisConfigurationError(
      "Set both UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN.",
    );
  }

  return { url: new URL(url).toString().replace(/\/$/, ""), token };
}

export async function redisCommand<T>(
  command: Array<string | number>,
  configuration = redisConfiguration(),
): Promise<T> {
  if (!configuration) {
    throw new RedisConfigurationError("Persistent Redis is not configured.");
  }

  const response = await fetch(configuration.url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${configuration.token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(command),
    cache: "no-store",
    signal: AbortSignal.timeout(10_000),
  });
  const body = (await response.json()) as { result?: T; error?: string };

  if (!response.ok || body.error) {
    throw new Error(body.error ?? `Redis returned HTTP ${response.status}.`);
  }

  return body.result as T;
}
