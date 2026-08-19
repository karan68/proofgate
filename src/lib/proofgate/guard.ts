import type { AuditStore, AuditRecord } from "./audit";
import { auditStore } from "./audit";
import {
  executeGuardedTarget,
  type GuardedExecutionResult,
} from "./execute";
import {
  askTelegraphUrlSafety,
  type TelegraphScanResult,
} from "./telegraph";

export interface GuardInput {
  url: string;
  execute?: boolean;
  method?: "GET" | "HEAD";
}

export interface GuardResult {
  scan: TelegraphScanResult;
  execution:
    | GuardedExecutionResult
    | {
        attempted: false;
        status: null;
        content_type: null;
        bytes: 0;
        final_url: null;
        redirect_location: null;
        preview: null;
        payment_settlement: null;
        error: string;
      }
    | null;
  audit: AuditRecord;
}

interface GuardDependencies {
  scan?: (url: string) => Promise<TelegraphScanResult>;
  execute?: (
    url: string,
    options: { method: "GET" | "HEAD" },
  ) => Promise<GuardedExecutionResult>;
  store?: Pick<AuditStore, "append" | "assertReady">;
}

export async function guardUrl(
  input: GuardInput,
  dependencies: GuardDependencies = {},
): Promise<GuardResult> {
  const store = dependencies.store ?? auditStore();
  await store.assertReady();
  const scan = await (dependencies.scan ?? askTelegraphUrlSafety)(input.url);
  const executeRequested = input.execute ?? false;
  const method = input.method ?? "GET";
  let execution: GuardResult["execution"] = null;

  if (executeRequested && scan.decision === "ALLOW") {
    execution = await (dependencies.execute ?? executeGuardedTarget)(scan.target_url, {
      method,
    });
  } else if (executeRequested) {
    execution = {
      attempted: false,
      status: null,
      content_type: null,
      bytes: 0,
      final_url: null,
      redirect_location: null,
      preview: null,
      payment_settlement: null,
      error: `Execution withheld because the policy decision was ${scan.decision}.`,
    };
  }

  const audit = await store.append({
    event: executeRequested ? "ACTION" : "SCAN",
    target_url: scan.target_url,
    decision: scan.decision,
    finding: scan.finding,
    telegraph: {
      miner_id: scan.miner_id,
      miner_name: scan.miner_name,
      intent: scan.intent,
      signal_hash: scan.signal_hash,
      cost_usd: scan.cost_usd,
      duration_ms: scan.duration_ms,
      settlement: scan.settlement,
    },
    execution,
  });

  return { scan, execution, audit };
}