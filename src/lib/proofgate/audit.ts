import { createHash, randomUUID } from "node:crypto";
import { appendFile, mkdir, readFile } from "node:fs/promises";
import path from "node:path";

import { z } from "zod";

import type { GateDecision, NormalizedFinding } from "./policy";
import { redisCommand, redisConfiguration } from "./redis";

const GENESIS_HASH = "GENESIS";

const auditRecordSchema = z.object({
  id: z.string().uuid(),
  created_at: z.string(),
  event: z.enum(["SCAN", "ACTION"]),
  target_url: z.string(),
  decision: z.enum(["ALLOW", "WARN", "BLOCK"]),
  finding: z.object({
    verdict: z.enum(["safe", "suspicious", "malicious", "pending", "unknown"]),
    confidence: z.number().nullable(),
    reason: z.string(),
    evidence: z.array(z.string()),
  }),
  telegraph: z.object({
    miner_id: z.string().nullable(),
    miner_name: z.string().nullable(),
    intent: z.string().nullable(),
    signal_hash: z.string().nullable(),
    cost_usd: z.number().nullable(),
    duration_ms: z.number().nullable(),
    settlement: z.unknown().nullable(),
  }),
  execution: z
    .object({
      attempted: z.boolean(),
      status: z.number().nullable(),
      content_type: z.string().nullable(),
      bytes: z.number().int().nonnegative(),
      final_url: z.string().nullable(),
      redirect_location: z.string().nullable(),
      preview: z.string().nullable(),
      payment_settlement: z.unknown().nullable(),
      error: z.string().nullable(),
    })
    .nullable(),
  previous_hash: z.string(),
  record_hash: z.string().regex(/^[0-9a-f]{64}$/),
});

export interface AuditEvent {
  event: "SCAN" | "ACTION";
  target_url: string;
  decision: GateDecision;
  finding: NormalizedFinding;
  telegraph: {
    miner_id: string | null;
    miner_name: string | null;
    intent: string | null;
    signal_hash: string | null;
    cost_usd: number | null;
    duration_ms: number | null;
    settlement: unknown | null;
  };
  execution: {
    attempted: boolean;
    status: number | null;
    content_type: string | null;
    bytes: number;
    final_url: string | null;
    redirect_location: string | null;
    preview: string | null;
    payment_settlement: unknown | null;
    error: string | null;
  } | null;
}

export type AuditRecord = z.infer<typeof auditRecordSchema>;

export interface AuditLedger {
  records: AuditRecord[];
  integrity: {
    valid: boolean;
    checked: number;
    broken_at: string | null;
  };
}

export interface AuditStore {
  append(event: AuditEvent): Promise<AuditRecord>;
  assertReady(): Promise<void>;
  list(limit?: number): Promise<AuditLedger>;
}

export class AuditConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuditConfigurationError";
  }
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }

  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(",")}}`;
  }

  return JSON.stringify(value);
}

function hashRecord(record: Omit<AuditRecord, "record_hash">): string {
  return createHash("sha256").update(canonicalJson(record)).digest("hex");
}

function createRecord(event: AuditEvent, previousHash: string): AuditRecord {
  const withoutHash: Omit<AuditRecord, "record_hash"> = {
    id: randomUUID(),
    created_at: new Date().toISOString(),
    ...event,
    previous_hash: previousHash,
  };
  return auditRecordSchema.parse({
    ...withoutHash,
    record_hash: hashRecord(withoutHash),
  });
}

function defaultAuditPath(): string {
  return (
    process.env.PROOFGATE_AUDIT_FILE ??
    path.join(process.cwd(), "data", "proofgate-audit.jsonl")
  );
}

async function readRecords(filePath: string): Promise<AuditRecord[]> {
  let contents: string;
  try {
    contents = await readFile(filePath, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }

  return contents
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => auditRecordSchema.parse(JSON.parse(line)));
}

export function verifyAuditChain(records: AuditRecord[]): AuditLedger["integrity"] {
  let previousHash = GENESIS_HASH;

  for (const record of records) {
    const { record_hash: recordHash, ...withoutHash } = record;
    const valid =
      record.previous_hash === previousHash && hashRecord(withoutHash) === recordHash;
    if (!valid) {
      return { valid: false, checked: records.length, broken_at: record.id };
    }
    previousHash = record.record_hash;
  }

  return { valid: true, checked: records.length, broken_at: null };
}

export class JsonlAuditStore implements AuditStore {
  readonly filePath: string;
  private writeQueue: Promise<unknown> = Promise.resolve();

  constructor(filePath = defaultAuditPath()) {
    this.filePath = filePath;
  }

  async assertReady(): Promise<void> {
    const integrity = verifyAuditChain(await readRecords(this.filePath));
    if (!integrity.valid) {
      throw new Error(`Audit ledger integrity failed at ${integrity.broken_at}.`);
    }
  }

  append(event: AuditEvent): Promise<AuditRecord> {
    const operation = this.writeQueue.then(async () => {
      const records = await readRecords(this.filePath);
      const integrity = verifyAuditChain(records);
      if (!integrity.valid) {
        throw new Error(`Audit ledger integrity failed at ${integrity.broken_at}.`);
      }

      const record = createRecord(
        event,
        records.at(-1)?.record_hash ?? GENESIS_HASH,
      );

      await mkdir(path.dirname(this.filePath), { recursive: true });
      await appendFile(this.filePath, `${JSON.stringify(record)}\n`, "utf8");
      return record;
    });

    this.writeQueue = operation.catch(() => undefined);
    return operation;
  }

  async list(limit = 50): Promise<AuditLedger> {
    await this.writeQueue;
    const records = await readRecords(this.filePath);
    return {
      records: records.slice(-Math.max(1, Math.min(limit, 500))).reverse(),
      integrity: verifyAuditChain(records),
    };
  }
}

const COMPARE_AND_APPEND = `
local last = redis.call("LINDEX", KEYS[1], -1)
local current = "GENESIS"
if last then
  current = cjson.decode(last)["record_hash"]
end
if current ~= ARGV[1] then
  return 0
end
redis.call("RPUSH", KEYS[1], ARGV[2])
return 1
`;

export class RedisAuditStore implements AuditStore {
  readonly key: string;
  private writeQueue: Promise<unknown> = Promise.resolve();

  constructor(key = process.env.PROOFGATE_AUDIT_REDIS_KEY ?? "proofgate:audit:v1") {
    this.key = key;
  }

  private async records(): Promise<AuditRecord[]> {
    const serialized = await redisCommand<string[]>([
      "LRANGE",
      this.key,
      "0",
      "-1",
    ]);
    return serialized.map((record) => auditRecordSchema.parse(JSON.parse(record)));
  }

  async assertReady(): Promise<void> {
    const integrity = verifyAuditChain(await this.records());
    if (!integrity.valid) {
      throw new Error(`Audit ledger integrity failed at ${integrity.broken_at}.`);
    }
  }

  append(event: AuditEvent): Promise<AuditRecord> {
    const operation = this.writeQueue.then(async () => {
      for (let attempt = 0; attempt < 4; attempt += 1) {
        const records = await this.records();
        const integrity = verifyAuditChain(records);
        if (!integrity.valid) {
          throw new Error(`Audit ledger integrity failed at ${integrity.broken_at}.`);
        }

        const previousHash = records.at(-1)?.record_hash ?? GENESIS_HASH;
        const record = createRecord(event, previousHash);
        const appended = await redisCommand<number>([
          "EVAL",
          COMPARE_AND_APPEND,
          1,
          this.key,
          previousHash,
          JSON.stringify(record),
        ]);
        if (appended === 1) return record;
      }

      throw new Error("Audit ledger changed concurrently; retry the request.");
    });

    this.writeQueue = operation.catch(() => undefined);
    return operation;
  }

  async list(limit = 50): Promise<AuditLedger> {
    await this.writeQueue;
    const records = await this.records();
    return {
      records: records.slice(-Math.max(1, Math.min(limit, 500))).reverse(),
      integrity: verifyAuditChain(records),
    };
  }
}

const stores = new Map<string, AuditStore>();

export function auditStore(): AuditStore {
  const redis = redisConfiguration();
  if (redis) {
    const key = process.env.PROOFGATE_AUDIT_REDIS_KEY ?? "proofgate:audit:v1";
    const storeKey = `redis:${redis.url}:${key}`;
    const existing = stores.get(storeKey);
    if (existing) return existing;

    const store = new RedisAuditStore(key);
    stores.set(storeKey, store);
    return store;
  }

  if (process.env.VERCEL === "1") {
    throw new AuditConfigurationError(
      "Persistent audit storage is required on Vercel. Configure Upstash Redis.",
    );
  }

  const filePath = defaultAuditPath();
  const existing = stores.get(filePath);
  if (existing) return existing;

  const store = new JsonlAuditStore(filePath);
  stores.set(filePath, store);
  return store;
}