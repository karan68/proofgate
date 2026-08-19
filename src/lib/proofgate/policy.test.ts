import { describe, expect, it } from "vitest";

import { evaluatePolicy, normalizeMinerResult } from "./policy";

describe("ProofGate policy", () => {
  it("blocks a normalized malicious response nested in an Engine result", () => {
    const result = evaluatePolicy({
      result: {
        verdict: "malicious",
        malicious: true,
        confidence: 0.98,
        reason: "Two independent feeds matched.",
        evidence: ["urlhaus", "phishtank"],
      },
    });

    expect(result).toMatchObject({
      decision: "BLOCK",
      finding: { verdict: "malicious", confidence: 0.98 },
    });
  });

  it("allows a completed clean URLScan.io result", () => {
    expect(
      evaluatePolicy({ verdicts: { overall: { malicious: false, score: 0 } } }),
    ).toMatchObject({ decision: "ALLOW", finding: { verdict: "safe" } });
  });

  it("warns while an asynchronous URLScan.io scan is pending", () => {
    expect(
      evaluatePolicy({ uuid: "scan-123", api: "https://urlscan.io/api/v1/result/scan-123" }),
    ).toMatchObject({ decision: "WARN", finding: { verdict: "pending" } });
  });

  it("blocks a verified PhishTank match", () => {
    expect(
      evaluatePolicy({ in_database: true, verified: true, phish_id: "42" }),
    ).toMatchObject({ decision: "BLOCK", finding: { verdict: "malicious" } });
  });

  it("does not treat absence from PhishTank as proof of safety", () => {
    expect(evaluatePolicy({ in_database: false, verified: false })).toMatchObject({
      decision: "WARN",
      finding: { verdict: "unknown" },
    });
  });

  it("blocks a VirusTotal result confirmed by multiple engines", () => {
    const response = {
      data: {
        attributes: {
          last_analysis_stats: {
            malicious: 3,
            suspicious: 0,
            harmless: 62,
            undetected: 5,
          },
        },
      },
    };

    expect(evaluatePolicy(response)).toMatchObject({
      decision: "BLOCK",
      finding: { verdict: "malicious" },
    });
  });

  it("allows a strongly clean VirusTotal result", () => {
    const response = {
      data: {
        attributes: {
          last_analysis_stats: {
            malicious: 0,
            suspicious: 0,
            harmless: 68,
            undetected: 2,
          },
        },
      },
    };

    expect(evaluatePolicy(response)).toMatchObject({
      decision: "ALLOW",
      finding: { verdict: "safe" },
    });
  });

  it("fails closed on unsupported or empty responses", () => {
    expect(evaluatePolicy({ choices: [] }).decision).toBe("WARN");
    expect(normalizeMinerResult(null).verdict).toBe("unknown");
  });

  it("warns when an affirmative safe confidence is below policy", () => {
    const result = evaluatePolicy(
      { verdict: "safe", malicious: false, confidence: 0.6 },
      { minConfidence: 0.8 },
    );

    expect(result).toMatchObject({ decision: "WARN", finding: { verdict: "safe" } });
  });

  it("fails closed when a safe verdict omits confidence", () => {
    const result = evaluatePolicy({ verdict: "safe", malicious: false });

    expect(result).toMatchObject({
      decision: "WARN",
      finding: { verdict: "safe", confidence: null },
    });
    expect(result.finding.reason).toContain("did not provide confidence");
  });

  it("rejects invalid policy thresholds", () => {
    expect(() => evaluatePolicy({}, { minConfidence: -0.1 })).toThrow(RangeError);
    expect(() => evaluatePolicy({}, { minConfidence: 1.1 })).toThrow(RangeError);
    expect(() => normalizeMinerResult({}, { minHarmlessEngines: -1 })).toThrow(
      RangeError,
    );
    expect(() => normalizeMinerResult({}, { minHarmlessEngines: 1.5 })).toThrow(
      RangeError,
    );
  });

  it("preserves structured Miner evidence as readable audit text", () => {
    const result = normalizeMinerResult({
      verdict: "safe",
      confidence: 0.9,
      evidence: [{ source: "rdap", status: "clean", detail: "Domain age is 1200 days." }],
    });

    expect(result.evidence).toEqual(["rdap: Domain age is 1200 days."]);
  });
});