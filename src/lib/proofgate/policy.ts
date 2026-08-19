export type GateDecision = "ALLOW" | "WARN" | "BLOCK";

export type FindingVerdict =
  | "safe"
  | "suspicious"
  | "malicious"
  | "pending"
  | "unknown";

export interface NormalizedFinding {
  verdict: FindingVerdict;
  confidence: number | null;
  reason: string;
  evidence: string[];
}

export interface PolicyResult {
  decision: GateDecision;
  finding: NormalizedFinding;
}

export interface PolicyOptions {
  minConfidence?: number;
  minHarmlessEngines?: number;
}

function policyOptions(options: PolicyOptions): Required<PolicyOptions> {
  const minConfidence = options.minConfidence ?? 0.8;
  const minHarmlessEngines = options.minHarmlessEngines ?? 10;

  if (!Number.isFinite(minConfidence) || minConfidence < 0 || minConfidence > 1) {
    throw new RangeError("minConfidence must be a finite number between 0 and 1.");
  }
  if (!Number.isSafeInteger(minHarmlessEngines) || minHarmlessEngines < 0) {
    throw new RangeError("minHarmlessEngines must be a non-negative safe integer.");
  }

  return { minConfidence, minHarmlessEngines };
}

const MALICIOUS_LABELS = new Set([
  "block",
  "blocked",
  "malicious",
  "phishing",
  "unsafe",
]);

const SUSPICIOUS_LABELS = new Set(["suspicious", "warn", "warning"]);
const SAFE_LABELS = new Set(["allow", "allowed", "benign", "clean", "safe"]);

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function asNumber(value: unknown): number | null {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return null;
  }

  return value;
}

function asBoolean(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function clampConfidence(value: unknown): number | null {
  const parsed = asNumber(value);
  return parsed === null ? null : Math.min(1, Math.max(0, parsed));
}

function normalizeLabel(value: unknown): FindingVerdict | null {
  if (typeof value !== "string") {
    return null;
  }

  const label = value.trim().toLowerCase();
  if (MALICIOUS_LABELS.has(label)) return "malicious";
  if (SUSPICIOUS_LABELS.has(label)) return "suspicious";
  if (SAFE_LABELS.has(label)) return "safe";
  if (label === "pending" || label === "queued" || label === "processing") {
    return "pending";
  }

  return null;
}

function textReason(record: Record<string, unknown>, fallback: string): string {
  for (const key of ["reason", "reasoning", "summary", "message", "status"]) {
    if (typeof record[key] === "string" && record[key].trim()) {
      return record[key].trim();
    }
  }

  return fallback;
}

function normalizeVirusTotal(
  record: Record<string, unknown>,
  minHarmlessEngines: number,
): NormalizedFinding | null {
  const data = asRecord(record.data);
  const attributes = asRecord(data?.attributes);
  const stats = asRecord(attributes?.last_analysis_stats);
  if (!stats) return null;

  const malicious = asNumber(stats.malicious) ?? 0;
  const suspicious = asNumber(stats.suspicious) ?? 0;
  const harmless = asNumber(stats.harmless) ?? 0;
  const undetected = asNumber(stats.undetected) ?? 0;
  const total = malicious + suspicious + harmless + undetected;
  const evidence = [
    `VirusTotal malicious engines: ${malicious}`,
    `VirusTotal suspicious engines: ${suspicious}`,
    `VirusTotal harmless engines: ${harmless}`,
  ];

  if (malicious >= 2) {
    return {
      verdict: "malicious",
      confidence: total > 0 ? malicious / total : null,
      reason: `${malicious} engines classified the target as malicious.`,
      evidence,
    };
  }

  if (malicious === 1 || suspicious > 0) {
    return {
      verdict: "suspicious",
      confidence: total > 0 ? (malicious + suspicious) / total : null,
      reason: "Threat engines returned a non-clean result.",
      evidence,
    };
  }

  if (harmless >= minHarmlessEngines) {
    return {
      verdict: "safe",
      confidence: total > 0 ? harmless / total : null,
      reason: `${harmless} engines classified the target as harmless.`,
      evidence,
    };
  }

  return {
    verdict: "unknown",
    confidence: total > 0 ? harmless / total : null,
    reason: "Too few threat engines returned an affirmative clean result.",
    evidence,
  };
}

function normalizeUrlScan(record: Record<string, unknown>): NormalizedFinding | null {
  const verdicts = asRecord(record.verdicts);
  const overall = asRecord(verdicts?.overall);
  const malicious = asBoolean(overall?.malicious);
  if (malicious !== null) {
    const score = asNumber(overall?.score);
    const normalizedScore =
      score === null ? null : Math.min(1, Math.abs(score) / 100);
    return {
      verdict: malicious ? "malicious" : "safe",
      confidence:
        normalizedScore === null
          ? null
          : malicious
            ? normalizedScore
            : 1 - normalizedScore,
      reason: malicious
        ? "URLScan.io marked the rendered page as malicious."
        : "URLScan.io completed its browser analysis without a malicious verdict.",
      evidence: score === null ? [] : [`URLScan.io score: ${score}`],
    };
  }

  if (typeof record.uuid === "string" || typeof record.api === "string") {
    return {
      verdict: "pending",
      confidence: null,
      reason: "URLScan.io accepted the scan, but the final verdict is not ready.",
      evidence: typeof record.uuid === "string" ? [`Scan UUID: ${record.uuid}`] : [],
    };
  }

  return null;
}

function normalizePhishTank(record: Record<string, unknown>): NormalizedFinding | null {
  const inDatabase = asBoolean(record.in_database);
  if (inDatabase === null) return null;

  const verified = asBoolean(record.verified);
  if (inDatabase && verified) {
    return {
      verdict: "malicious",
      confidence: 1,
      reason: "PhishTank lists the URL as verified phishing.",
      evidence: typeof record.phish_id === "string" ? [`PhishTank ID: ${record.phish_id}`] : [],
    };
  }

  return {
    verdict: inDatabase ? "suspicious" : "unknown",
    confidence: null,
    reason: inDatabase
      ? "The URL is listed by PhishTank but is not yet verified."
      : "The URL is absent from PhishTank; absence is not proof of safety.",
    evidence: [],
  };
}

export function normalizeMinerResult(
  value: unknown,
  options: PolicyOptions = {},
): NormalizedFinding {
  const { minHarmlessEngines } = policyOptions(options);
  const outer = asRecord(value);
  const record = asRecord(outer?.result) ?? outer;
  if (!record) {
    return {
      verdict: "unknown",
      confidence: null,
      reason: "The Miner returned an unsupported response shape.",
      evidence: [],
    };
  }

  const normalized = asRecord(record.result) ?? record;
  const malicious = asBoolean(normalized.malicious);
  const label = normalizeLabel(normalized.verdict) ?? normalizeLabel(normalized.label);
  if (malicious !== null || label) {
    const evidence = Array.isArray(normalized.evidence)
      ? normalized.evidence.flatMap((item) => {
          if (typeof item === "string") return [item];
          const record = asRecord(item);
          if (!record || typeof record.detail !== "string") return [];
          const source = typeof record.source === "string" ? `${record.source}: ` : "";
          return [`${source}${record.detail}`];
        })
      : [];
    return {
      verdict: malicious === true ? "malicious" : label ?? "safe",
      confidence: clampConfidence(normalized.confidence),
      reason: textReason(normalized, "The Miner returned a normalized verdict."),
      evidence,
    };
  }

  return (
    normalizeVirusTotal(normalized, minHarmlessEngines) ??
    normalizeUrlScan(normalized) ??
    normalizePhishTank(normalized) ?? {
      verdict: "unknown",
      confidence: null,
      reason: "The Miner response did not contain an actionable final verdict.",
      evidence: [],
    }
  );
}

export function evaluatePolicy(
  value: unknown,
  options: PolicyOptions = {},
): PolicyResult {
  const { minConfidence } = policyOptions(options);
  const finding = normalizeMinerResult(value, options);

  if (finding.verdict === "malicious") {
    return { decision: "BLOCK", finding };
  }

  if (finding.verdict !== "safe") {
    return { decision: "WARN", finding };
  }

  if (finding.confidence === null) {
    return {
      decision: "WARN",
      finding: {
        ...finding,
        reason: `${finding.reason} The Miner did not provide confidence required by policy.`,
      },
    };
  }

  if (finding.confidence < minConfidence) {
    return {
      decision: "WARN",
      finding: {
        ...finding,
        reason: `${finding.reason} Confidence is below the ${(minConfidence * 100).toFixed(0)}% policy threshold.`,
      },
    };
  }

  return { decision: "ALLOW", finding };
}