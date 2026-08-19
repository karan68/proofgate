import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { auditStore, JsonlAuditStore, RedisAuditStore } from "./audit";

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

function event(decision: "ALLOW" | "BLOCK") {
  return {
    event: "SCAN" as const,
    target_url: "https://example.com/",
    decision,
    finding: {
      verdict: decision === "ALLOW" ? ("safe" as const) : ("malicious" as const),
      confidence: 1,
      reason: "Test finding",
      evidence: ["test"],
    },
    telegraph: {
      miner_id: "223",
      miner_name: "urlscan",
      intent: "URL_SCAN",
      signal_hash: "0xabc",
      cost_usd: 0.01,
      duration_ms: 12,
      settlement: null,
    },
    execution: null,
  };
}

describe("hash-chained audit ledger", () => {
  it("serializes concurrent appends and verifies the chain", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "proofgate-audit-"));
    const store = new JsonlAuditStore(path.join(directory, "audit.jsonl"));

    await Promise.all([store.append(event("ALLOW")), store.append(event("BLOCK"))]);
    const ledger = await store.list();

    expect(ledger.integrity).toEqual({ valid: true, checked: 2, broken_at: null });
    expect(ledger.records).toHaveLength(2);
    expect(ledger.records[0].previous_hash).toBe(ledger.records[1].record_hash);
  });

  it("detects a modified historical record", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "proofgate-audit-"));
    const filePath = path.join(directory, "audit.jsonl");
    const store = new JsonlAuditStore(filePath);

    await store.append(event("ALLOW"));
    const contents = await readFile(filePath, "utf8");
    await writeFile(filePath, contents.replace('"decision":"ALLOW"', '"decision":"BLOCK"'));

    await expect(store.list()).resolves.toMatchObject({
      integrity: { valid: false, checked: 1 },
    });
    await expect(store.append(event("ALLOW"))).rejects.toThrow("integrity failed");
  });

  it("atomically serializes Redis appends across store instances", async () => {
    vi.stubEnv("UPSTASH_REDIS_REST_URL", "https://redis.example");
    vi.stubEnv("UPSTASH_REDIS_REST_TOKEN", "test-token");
    const records: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
        const command = JSON.parse(String(init?.body)) as Array<string | number>;
        if (command[0] === "LRANGE") {
          return Response.json({ result: [...records] });
        }
        if (command[0] === "EVAL") {
          const expected = String(command[4]);
          const serialized = String(command[5]);
          const current = records.length
            ? JSON.parse(records.at(-1) as string).record_hash
            : "GENESIS";
          if (current !== expected) return Response.json({ result: 0 });
          records.push(serialized);
          return Response.json({ result: 1 });
        }
        throw new Error(`Unexpected Redis command ${command[0]}`);
      }),
    );

    const first = new RedisAuditStore("audit:test");
    const second = new RedisAuditStore("audit:test");
    await Promise.all([first.append(event("ALLOW")), second.append(event("BLOCK"))]);

    const ledger = await first.list();
    expect(ledger.integrity).toEqual({ valid: true, checked: 2, broken_at: null });
    expect(ledger.records).toHaveLength(2);
  });

  it("refuses Vercel audit access when persistent Redis is absent", () => {
    vi.stubEnv("VERCEL", "1");
    vi.stubEnv("UPSTASH_REDIS_REST_URL", "");
    vi.stubEnv("UPSTASH_REDIS_REST_TOKEN", "");

    expect(() => auditStore()).toThrow("Persistent audit storage is required");
  });
});