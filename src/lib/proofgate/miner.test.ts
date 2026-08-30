import { describe, expect, it } from "vitest";

import {
  aggregateEvidence,
  scanUrlWithEvidence,
  type SourceEvidence,
} from "./miner";

const checkedAt = new Date("2026-08-18T00:00:00.000Z");

function evidence(
  source: SourceEvidence["source"],
  status: SourceEvidence["status"],
  detail = `${source} ${status}`,
): SourceEvidence {
  return { source, status, detail };
}

describe("Miner evidence aggregation", () => {
  it("lets one authoritative threat match override clean votes", () => {
    const result = aggregateEvidence(
      "https://example.com/",
      [
        evidence("dns", "clean"),
        evidence("rdap", "clean"),
        evidence("phishtank", "clean"),
        evidence("google", "malicious", "Safe Browsing matched SOCIAL_ENGINEERING."),
      ],
      checkedAt,
    );

    expect(result).toMatchObject({ verdict: "malicious", malicious: true, confidence: 0.97 });
    expect(result.reason).toContain("SOCIAL_ENGINEERING");
  });

  it("raises confidence when independent threat providers agree", () => {
    expect(
      aggregateEvidence(
        "https://example.com/",
        [evidence("google", "malicious"), evidence("urlhaus", "malicious")],
        checkedAt,
      ).confidence,
    ).toBe(0.995);
  });

  it("does not let clean sources erase a structural warning", () => {
    expect(
      aggregateEvidence(
        "http://example.com/file.exe",
        [evidence("structure", "suspicious"), evidence("phishtank", "clean")],
        checkedAt,
      ),
    ).toMatchObject({ verdict: "suspicious", malicious: false, confidence: 0.72 });
  });

  it("requires a reputation source for an allow-grade confidence", () => {
    const noReputation = aggregateEvidence(
      "https://example.com/",
      [evidence("dns", "clean"), evidence("rdap", "clean")],
      checkedAt,
    );
    const oneReputation = aggregateEvidence(
      "https://example.com/",
      [evidence("dns", "clean"), evidence("rdap", "clean"), evidence("phishtank", "clean")],
      checkedAt,
    );

    expect(noReputation).toMatchObject({ verdict: "safe", confidence: 0.65 });
    expect(oneReputation).toMatchObject({ verdict: "safe", confidence: 0.86 });
  });
});

describe("Miner provider contracts", () => {
  it.each([
    ["https://example.com/download%2Eexe", "executable download path"],
    ["https://example.com/download.exe%00.txt", "null byte encoding"],
    ["https://free-prize-claim.info/win", "credential or reward lure hostname"],
    ["https://example.com/bad%encoding", "malformed URL encoding"],
  ])("flags deterministic structural risk for %s", async (url, detail) => {
    const result = await scanUrlWithEvidence(url, {
      fetcher: async (input) => {
        if (String(input).startsWith("https://rdap.org/")) {
          return Response.json({
            events: [{ eventAction: "registration", eventDate: "2020-01-01T00:00:00Z" }],
          });
        }
        throw new Error(`Unexpected request ${String(input)}`);
      },
      lookup: async () => ["93.184.216.34"],
      now: checkedAt,
    });

    expect(result).toMatchObject({ verdict: "suspicious", malicious: false });
    expect(result.reason).toContain(detail);
  });

  it("classifies a dead lure domain instead of failing before structural analysis", async () => {
    const result = await scanUrlWithEvidence("https://free-prize-claim.info/win", {
      fetcher: async (input) => {
        if (String(input).startsWith("https://rdap.org/")) {
          return new Response("", { status: 404 });
        }
        throw new Error(`Unexpected request ${String(input)}`);
      },
      lookup: async () => {
        throw new Error("ENOTFOUND");
      },
      now: checkedAt,
    });

    expect(result).toMatchObject({ verdict: "suspicious", malicious: false, confidence: 0.62 });
    expect(result.evidence.find((item) => item.source === "dns")).toMatchObject({
      status: "unavailable",
    });
  });

  it.each([
    "https://accounts.google.com/signin",
    "https://secure-login.microsoft.com/account",
  ])("does not flag an ordinary first-party login URL as structural risk: %s", async (url) => {
    const result = await scanUrlWithEvidence(url, {
      fetcher: async (input) => {
        if (String(input).startsWith("https://rdap.org/")) {
          return Response.json({
            events: [{ eventAction: "registration", eventDate: "1997-09-15T00:00:00Z" }],
          });
        }
        throw new Error(`Unexpected request ${String(input)}`);
      },
      lookup: async () => ["8.8.8.8"],
      now: checkedAt,
    });

    expect(result.evidence.find((item) => item.source === "structure")).toMatchObject({
      status: "clean",
    });
  });

  it("maps a verified PhishTank response to malicious without visiting the target", async () => {
    const requested: string[] = [];
    const fetcher = async (input: RequestInfo | URL) => {
      const url = String(input);
      requested.push(url);
      if (url.startsWith("https://rdap.org/")) {
        return new Response(
          JSON.stringify({
            events: [{ eventAction: "registration", eventDate: "1995-08-14T00:00:00Z" }],
          }),
        );
      }
      if (url.includes("phishtank")) {
        return new Response(
          JSON.stringify({
            results: {
              url: "https://example.com/",
              in_database: true,
              phish_id: 42,
              phish_detail_page: "https://phishtank.org/phish_detail.php?phish_id=42",
              verified: "y",
              valid: "y",
            },
          }),
        );
      }
      throw new Error(`Unexpected request ${url}`);
    };

    const result = await scanUrlWithEvidence("https://example.com", {
      fetcher: fetcher as typeof fetch,
      lookup: async () => ["93.184.216.34"],
      now: checkedAt,
      phishTankAppKey: "phish-key",
    });

    expect(result).toMatchObject({ verdict: "malicious", malicious: true });
    expect(requested).not.toContain("https://example.com/");
  });

  it("uses the documented Google and URLhaus contracts when keys are configured", async () => {
    const requests: Array<{ url: string; init?: RequestInit }> = [];
    const fetcher = async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      requests.push({ url, init });
      if (url.startsWith("https://rdap.org/")) {
        return new Response(
          JSON.stringify({
            events: [{ eventAction: "registration", eventDate: "1995-08-14T00:00:00Z" }],
          }),
        );
      }
      if (url.includes("phishtank")) {
        return new Response(JSON.stringify({ results: { in_database: false } }));
      }
      if (url.includes("safebrowsing")) return new Response("{}");
      if (url.includes("urlhaus")) return new Response(JSON.stringify({ query_status: "no_results" }));
      if (url.includes("virustotal")) {
        return new Response(
          JSON.stringify({
            data: {
              attributes: {
                last_analysis_stats: {
                  malicious: 0,
                  suspicious: 0,
                  harmless: 65,
                  undetected: 5,
                },
              },
            },
          }),
        );
      }
      throw new Error(`Unexpected request ${url}`);
    };

    const result = await scanUrlWithEvidence("https://example.com", {
      fetcher: fetcher as typeof fetch,
      lookup: async () => ["93.184.216.34"],
      now: checkedAt,
      googleSafeBrowsingKey: "google-key",
      urlHausAuthKey: "urlhaus-key",
      virusTotalApiKey: "vt-key",
    });

    expect(result).toMatchObject({ verdict: "safe", malicious: false, confidence: 0.96 });
    expect(
      requests.find((request) => request.url.startsWith("https://rdap.org/"))?.init?.headers,
    ).toMatchObject({
      "User-Agent": "ProofGate/0.1 (+https://proofgate-six.vercel.app)",
    });
    expect(requests.find((request) => request.url.includes("urlhaus"))?.init?.headers).toMatchObject({
      "Auth-Key": "urlhaus-key",
    });
    expect(requests.find((request) => request.url.includes("virustotal"))?.init?.headers).toMatchObject({
      "x-apikey": "vt-key",
    });
    const googleBody = JSON.parse(
      String(requests.find((request) => request.url.includes("safebrowsing"))?.init?.body),
    );
    expect(googleBody.threatInfo.threatEntries).toEqual([{ url: "https://example.com/" }]);
  });
});