import { describe, expect, it, vi } from "vitest";

import type { AuditEvent, AuditRecord } from "./audit";
import { guardUrl } from "./guard";
import type { TelegraphScanResult } from "./telegraph";

function scan(decision: "ALLOW" | "WARN" | "BLOCK"): TelegraphScanResult {
  return {
    target_url: "https://example.com/",
    decision,
    finding: {
      verdict: decision === "BLOCK" ? "malicious" : decision === "WARN" ? "suspicious" : "safe",
      confidence: 0.95,
      reason: "Test decision",
      evidence: ["test"],
    },
    miner_id: "223",
    miner_name: "urlscan",
    intent: "URL_SCAN",
    routing_reason: "Test route",
    signal_hash: "0xabc",
    cost_usd: 0.01,
    duration_ms: 20,
    timestamp: "2026-08-18T00:00:00.000Z",
    settlement: null,
    raw_result: {},
  };
}

function fakeRecord(event: AuditEvent): AuditRecord {
  return {
    id: "1b4354db-e2ea-44db-841c-099badc71234",
    created_at: "2026-08-18T00:00:00.000Z",
    ...event,
    previous_hash: "GENESIS",
    record_hash: "a".repeat(64),
  };
}

describe("guarded action orchestration", () => {
  const ready = vi.fn(async () => undefined);

  it("executes only after an ALLOW decision and audits the action", async () => {
    const execute = vi.fn(async () => ({
      attempted: true as const,
      status: 200,
      content_type: "application/json",
      bytes: 12,
      final_url: "https://example.com/",
      redirect_location: null,
      preview: '{"ok":true}',
      payment_settlement: null,
      error: null,
    }));
    const append = vi.fn(async (event: AuditEvent) => fakeRecord(event));

    const result = await guardUrl(
      { url: "https://example.com", execute: true },
      { scan: async () => scan("ALLOW"), execute, store: { append, assertReady: ready } },
    );

    expect(execute).toHaveBeenCalledOnce();
    expect(result.execution).toMatchObject({ attempted: true, status: 200 });
    expect(append).toHaveBeenCalledWith(
      expect.objectContaining({ event: "ACTION", decision: "ALLOW" }),
    );
  });

  it.each(["WARN", "BLOCK"] as const)(
    "withholds execution after a %s decision",
    async (decision) => {
      const execute = vi.fn();
      const append = vi.fn(async (event: AuditEvent) => fakeRecord(event));

      const result = await guardUrl(
        { url: "https://example.com", execute: true },
        { scan: async () => scan(decision), execute, store: { append, assertReady: ready } },
      );

      expect(execute).not.toHaveBeenCalled();
      expect(result.execution).toMatchObject({ attempted: false });
      expect(append).toHaveBeenCalledWith(
        expect.objectContaining({ event: "ACTION", decision }),
      );
    },
  );

  it("records a scan without constructing an execution result", async () => {
    const append = vi.fn(async (event: AuditEvent) => fakeRecord(event));
    const result = await guardUrl(
      { url: "https://example.com" },
      { scan: async () => scan("ALLOW"), store: { append, assertReady: ready } },
    );

    expect(result.execution).toBeNull();
    expect(append).toHaveBeenCalledWith(
      expect.objectContaining({ event: "SCAN", execution: null }),
    );
  });

  it("does not scan or spend when audit storage is unavailable", async () => {
    const scanRequest = vi.fn(async () => scan("ALLOW"));
    const append = vi.fn();
    const assertReady = vi.fn(async () => {
      throw new Error("audit unavailable");
    });

    await expect(
      guardUrl(
        { url: "https://example.com" },
        { scan: scanRequest, store: { append, assertReady } },
      ),
    ).rejects.toThrow("audit unavailable");
    expect(scanRequest).not.toHaveBeenCalled();
    expect(append).not.toHaveBeenCalled();
  });
});