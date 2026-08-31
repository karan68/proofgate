import { describe, expect, it } from "vitest";

import {
  answerHistoricalUrlQuestion,
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
  it("lets one authoritative threat match override no-signal votes", () => {
    const result = aggregateEvidence(
      "https://example.com/",
      [
        evidence("dns", "ok"),
        evidence("rdap", "ok"),
        evidence("phishtank", "ok"),
        evidence("google", "malicious", "Safe Browsing matched SOCIAL_ENGINEERING."),
      ],
      checkedAt,
    );

    expect(result).toMatchObject({ verdict: "malicious", confidence: 0.97 });
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

  it("does not let no-signal sources erase a structural warning", () => {
    const result = aggregateEvidence(
      "http://example.com/file.exe",
      [evidence("structure", "suspicious"), evidence("phishtank", "ok")],
      checkedAt,
    );
    expect(result).toMatchObject({ verdict: "suspicious", confidence: 0.72 });
  });

  it("requires a reputation source for an allow-grade confidence", () => {
    const noReputation = aggregateEvidence(
      "https://example.com/",
      [evidence("dns", "ok"), evidence("rdap", "ok")],
      checkedAt,
    );
    const oneReputation = aggregateEvidence(
      "https://example.com/",
      [evidence("dns", "ok"), evidence("rdap", "ok"), evidence("phishtank", "ok")],
      checkedAt,
    );

    expect(noReputation).toMatchObject({ verdict: "no_threat_signal", confidence: 0.65 });
    expect(oneReputation).toMatchObject({ verdict: "no_threat_signal", confidence: 0.86 });
  });

  it("never emits a benign claim word or a bare boolean that the Telegraph scorer reads as a contradiction", () => {
    const results = [
      aggregateEvidence("https://example.com/", [evidence("dns", "ok")], checkedAt),
      aggregateEvidence(
        "https://example.com/",
        [evidence("structure", "suspicious")],
        checkedAt,
      ),
      aggregateEvidence("https://example.com/", [evidence("google", "malicious")], checkedAt),
      answerHistoricalUrlQuestion("What is documented about Necurs?", checkedAt),
      answerHistoricalUrlQuestion("What domains did the Example Nebula campaign use?", checkedAt),
    ];

    for (const result of results) {
      const body = JSON.stringify(result);
      expect(body).not.toMatch(/\b(safe|clean|benign|legitimate|harmless)\b/i);
      expect(body).not.toMatch(/:false\b/);
      const booleans = body.match(/"(\w+)":true\b/g) ?? [];
      expect(booleans).toEqual(result.verdict === "malicious" ? ['"malicious":true'] : []);
    }
  });

  it("reports unqueried reputation providers as a plain list instead of prose evidence", async () => {
    const result = await scanUrlWithEvidence("https://example.com", {
      fetcher: async (input) => {
        if (String(input).startsWith("https://rdap.org/")) {
          return Response.json({
            events: [{ eventAction: "registration", eventDate: "1995-08-14T00:00:00Z" }],
          });
        }
        throw new Error(`Unexpected request ${String(input)}`);
      },
      lookup: async () => ["93.184.216.34"],
      now: checkedAt,
    });

    expect(result.providers_not_queried).toEqual([
      "phishtank",
      "google",
      "urlhaus",
      "virustotal",
    ]);
    expect(result.evidence.some((item) => item.status === "not_queried")).toBe(false);
  });
});

describe("Miner provider contracts", () => {
  it.each([
    ["https://example.com/download%2Eexe", "malware-style executable download path"],
    ["https://example.com/download.exe%00.txt", "null byte encoding"],
    ["https://free-prize-claim.info/win", "credential-phishing or reward lure hostname"],
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

    expect(result).toMatchObject({ verdict: "suspicious" });
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

    expect(result).toMatchObject({ verdict: "suspicious", confidence: 0.62 });
    expect(result.not_observed).toContain("dns");
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
      status: "ok",
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

    expect(result).toMatchObject({ verdict: "malicious" });
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

    expect(result).toMatchObject({ verdict: "no_threat_signal", confidence: 0.96 });
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

describe("Miner historical answers", () => {
  it("answers a known no-URL campaign question without claiming a live scan", () => {
    const result = answerHistoricalUrlQuestion(
      "What is documented about Microsoft's 2020 takedown of Necurs?",
      checkedAt,
    );

    expect(result).toMatchObject({
      verdict: "malicious",
      live_reason: null,
      historical_context: { id: "necurs", matched_by: "question" },
    });
    expect(result.answer).toContain("more than nine million computers");
    expect(result.answer).toContain("more than six million unique domains");
  });

  it("abstains from an unknown no-URL campaign question", () => {
    const result = answerHistoricalUrlQuestion(
      "What domains did the Example Nebula campaign use?",
      checkedAt,
    );

    expect(result).toMatchObject({
      confidence: 0,
      historical_context: null,
    });
    expect(result.answer).toContain("No URL or campaign verdict is claimed");
  });

  it("keeps a legitimate publisher verdict separate from Mirai context", async () => {
    const result = await scanUrlWithEvidence("https://github.com/example/mirai-source-code", {
      fetcher: async (input) => {
        if (String(input).startsWith("https://rdap.org/")) {
          return Response.json({
            events: [{ eventAction: "registration", eventDate: "2007-10-09T00:00:00Z" }],
          });
        }
        throw new Error(`Unexpected request ${String(input)}`);
      },
      lookup: async () => ["140.82.112.4"],
      now: checkedAt,
      question: "What domains were documented after the Mirai source code release?",
    });

    expect(result).toMatchObject({
      verdict: "no_threat_signal",
      historical_context: { id: "mirai", matched_by: "question" },
    });
    expect(result.answer).toContain("Anna-senpai");
    expect(result.answer).not.toMatch(/\bsafe\b/i);
  });

  it("does not let historical context erase a live structural warning", async () => {
    const result = await scanUrlWithEvidence("http://example.com/file.exe", {
      fetcher: async (input) => {
        if (String(input).startsWith("https://rdap.org/")) {
          return Response.json({
            events: [{ eventAction: "registration", eventDate: "1995-01-01T00:00:00Z" }],
          });
        }
        throw new Error(`Unexpected request ${String(input)}`);
      },
      lookup: async () => ["93.184.216.34"],
      now: checkedAt,
      question: "What is documented about Emotet infrastructure?",
    });

    expect(result).toMatchObject({
      verdict: "suspicious",
      historical_context: { id: "emotet", matched_by: "question" },
    });
    expect(result.live_reason).toContain("malware-style executable download path");
  });
});