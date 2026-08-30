import { Buffer } from "node:buffer";

import { z } from "zod";

import {
  findHistoricalUrlIncident,
  type HistoricalUrlMatch,
} from "./historical-url-intel";
import {
  assertPublicTarget,
  type AddressLookup,
  type ValidatedTarget,
} from "./target";

export type EvidenceStatus =
  | "malicious"
  | "suspicious"
  | "clean"
  | "unavailable"
  | "error";

export interface SourceEvidence {
  source: "structure" | "dns" | "rdap" | "phishtank" | "google" | "urlhaus" | "virustotal" | "history";
  status: EvidenceStatus;
  detail: string;
  reference?: string;
}

export interface HistoricalContext {
  id: string;
  name: string;
  disposition: "malicious" | "defensive" | "demonstration";
  matched_by: "hostname" | "question";
  facts: readonly string[];
  sources: readonly { name: string; url: string }[];
}

export interface MinerScanResult {
  schema_version: "1.0";
  intent: "URL_SCAN";
  url: string;
  verdict: "safe" | "suspicious" | "malicious";
  malicious: boolean;
  confidence: number;
  answer: string;
  reason: string;
  live_reason: string | null;
  live_scan_performed: boolean;
  historical_context: HistoricalContext | null;
  evidence: SourceEvidence[];
  checked_at: string;
  policy_version: "proofgate-2";
}

export interface MinerScanOptions {
  fetcher?: typeof fetch;
  lookup?: AddressLookup;
  now?: Date;
  phishTankAppKey?: string;
  googleSafeBrowsingKey?: string;
  urlHausAuthKey?: string;
  virusTotalApiKey?: string;
  question?: string;
}

const phishTankSchema = z.object({
  results: z
    .object({
      url: z.string().optional(),
      in_database: z.union([z.boolean(), z.string()]),
      phish_id: z.union([z.string(), z.number()]).optional(),
      phish_detail_page: z.string().optional(),
      verified: z.union([z.boolean(), z.string()]).optional(),
      valid: z.union([z.boolean(), z.string()]).optional(),
    })
    .passthrough(),
});

const urlHausSchema = z
  .object({
    query_status: z.string(),
    urlhaus_reference: z.string().optional(),
    threat: z.string().optional(),
    url_status: z.string().optional(),
    url_count: z.union([z.string(), z.number()]).optional(),
  })
  .passthrough();

const googleSchema = z
  .object({
    matches: z
      .array(
        z.object({
          threatType: z.string(),
          platformType: z.string().optional(),
          cacheDuration: z.string().optional(),
        }),
      )
      .optional(),
  })
  .passthrough();

const virusTotalSchema = z.object({
  data: z.object({
    attributes: z.object({
      last_analysis_stats: z.object({
        malicious: z.number().int().nonnegative().default(0),
        suspicious: z.number().int().nonnegative().default(0),
        harmless: z.number().int().nonnegative().default(0),
        undetected: z.number().int().nonnegative().default(0),
      }),
    }),
  }),
});

const rdapSchema = z.object({
  events: z
    .array(
      z.object({
        eventAction: z.string(),
        eventDate: z.string(),
      }),
    )
    .optional(),
});

const URL_SHORTENERS = new Set([
  "bit.ly",
  "cutt.ly",
  "is.gd",
  "rebrand.ly",
  "shorturl.at",
  "t.co",
  "tinyurl.com",
]);
const LURE_WORDS = new Set([
  "account",
  "bonus",
  "claim",
  "free",
  "gift",
  "login",
  "password",
  "prize",
  "secure",
  "signin",
  "update",
  "verify",
  "wallet",
]);

function truthy(value: boolean | string | undefined): boolean {
  if (typeof value === "boolean") return value;
  return typeof value === "string" && ["1", "true", "y", "yes"].includes(value.toLowerCase());
}

async function parseJson(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return {};
  return JSON.parse(text);
}

function structureEvidence(target: ValidatedTarget): SourceEvidence {
  const parsed = new URL(target.url);
  const risks: string[] = [];
  const domainWords = (target.registrableDomain ?? target.hostname)
    .split(/[.-]+/)
    .filter(Boolean);

  if (target.protocol !== "https:") risks.push("unencrypted HTTP");
  if (target.hostname.includes("xn--")) risks.push("internationalized hostname");
  if (target.registrableDomain === null) risks.push("literal IP address");
  if (URL_SHORTENERS.has(target.registrableDomain ?? target.hostname)) {
    risks.push("URL shortener");
  }
  let decodedPath = parsed.pathname;
  try {
    decodedPath = decodeURIComponent(parsed.pathname);
  } catch {
    risks.push("malformed URL encoding");
  }
  if (decodedPath.includes("\0")) risks.push("null byte encoding");
  if (/\.(?:apk|bat|cmd|com|exe|hta|jar|js|msi|ps1|scr|vbs)$/i.test(decodedPath)) {
    risks.push("executable download path");
  }
  if (domainWords.filter((word) => LURE_WORDS.has(word)).length >= 2) {
    risks.push("credential or reward lure hostname");
  }

  return risks.length > 0
    ? {
        source: "structure",
        status: "suspicious",
        detail: `Structural risk: ${risks.join(", ")}.`,
      }
    : {
        source: "structure",
        status: "clean",
        detail: "No high-risk URL structure indicators were found.",
      };
}

async function rdapEvidence(
  target: ValidatedTarget,
  fetcher: typeof fetch,
  now: Date,
): Promise<SourceEvidence> {
  if (!target.registrableDomain) {
    return {
      source: "rdap",
      status: "unavailable",
      detail: "Domain age is unavailable for literal IP targets.",
    };
  }

  try {
    const response = await fetcher(
      `https://rdap.org/domain/${encodeURIComponent(target.registrableDomain)}`,
      {
        headers: {
          Accept: "application/rdap+json, application/json",
          "User-Agent": "ProofGate/0.1 (+https://proofgate-six.vercel.app)",
        },
        signal: AbortSignal.timeout(4_000),
      },
    );
    if (response.status === 404) {
      return {
        source: "rdap",
        status: "unavailable",
        detail: "No authoritative RDAP registration record was found.",
      };
    }
    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const body = rdapSchema.parse(await parseJson(response));
    const registration = body.events?.find((event) =>
      ["registration", "registered"].includes(event.eventAction.toLowerCase()),
    );
    if (!registration) {
      return {
        source: "rdap",
        status: "unavailable",
        detail: "The RDAP record does not disclose a registration date.",
      };
    }

    const registeredAt = new Date(registration.eventDate);
    const ageDays = Math.floor((now.getTime() - registeredAt.getTime()) / 86_400_000);
    if (!Number.isFinite(ageDays) || ageDays < 0) throw new Error("invalid registration date");

    return ageDays < 30
      ? {
          source: "rdap",
          status: "suspicious",
          detail: `Domain was registered ${ageDays} day${ageDays === 1 ? "" : "s"} ago.`,
        }
      : {
          source: "rdap",
          status: "clean",
          detail: `Domain age is ${ageDays} days.`,
        };
  } catch (error) {
    return {
      source: "rdap",
      status: "error",
      detail: `RDAP lookup failed: ${(error as Error).message}`,
    };
  }
}

async function phishTankEvidence(
  target: ValidatedTarget,
  fetcher: typeof fetch,
  appKey?: string,
): Promise<SourceEvidence> {
  if (!appKey) {
    return {
      source: "phishtank",
      status: "unavailable",
      detail: "PHISHTANK_APP_KEY is not configured; keyless HTTPS returned 403 in live verification.",
    };
  }

  try {
    const form = new URLSearchParams({
      url: target.url,
      format: "json",
      app_key: appKey,
    });

    const response = await fetcher("https://checkurl.phishtank.com/checkurl/", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "proofgate/1.0 (Telegraph URL_SCAN Miner)",
      },
      body: form,
      signal: AbortSignal.timeout(8_000),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const result = phishTankSchema.parse(await parseJson(response)).results;
    if (truthy(result.in_database) && truthy(result.verified) && truthy(result.valid)) {
      return {
        source: "phishtank",
        status: "malicious",
        detail: "PhishTank lists this URL as verified phishing.",
        reference: result.phish_detail_page,
      };
    }
    if (truthy(result.in_database)) {
      return {
        source: "phishtank",
        status: "suspicious",
        detail: "The URL is present in PhishTank but lacks a verified-valid verdict.",
        reference: result.phish_detail_page,
      };
    }

    return {
      source: "phishtank",
      status: "clean",
      detail: "The URL is absent from PhishTank's submitted URL database.",
    };
  } catch (error) {
    return {
      source: "phishtank",
      status: "error",
      detail: `PhishTank lookup failed: ${(error as Error).message}`,
    };
  }
}

async function googleEvidence(
  target: ValidatedTarget,
  fetcher: typeof fetch,
  apiKey?: string,
): Promise<SourceEvidence> {
  if (!apiKey) {
    return {
      source: "google",
      status: "unavailable",
      detail: "GOOGLE_SAFE_BROWSING_API_KEY is not configured.",
    };
  }

  try {
    const response = await fetcher(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "proofgate", clientVersion: "1.0.0" },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url: target.url }],
          },
        }),
        signal: AbortSignal.timeout(8_000),
      },
    );
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const body = googleSchema.parse(await parseJson(response));
    const threats = body.matches?.map((match) => match.threatType) ?? [];

    return threats.length > 0
      ? {
          source: "google",
          status: "malicious",
          detail: `Google Safe Browsing matched: ${[...new Set(threats)].join(", ")}.`,
        }
      : {
          source: "google",
          status: "clean",
          detail: "Google Safe Browsing returned no threat-list matches.",
        };
  } catch (error) {
    return {
      source: "google",
      status: "error",
      detail: `Google Safe Browsing lookup failed: ${(error as Error).message}`,
    };
  }
}

async function urlHausEvidence(
  target: ValidatedTarget,
  fetcher: typeof fetch,
  authKey?: string,
): Promise<SourceEvidence> {
  if (!authKey) {
    return {
      source: "urlhaus",
      status: "unavailable",
      detail: "URLHAUS_AUTH_KEY is not configured.",
    };
  }

  try {
    const response = await fetcher("https://urlhaus-api.abuse.ch/v1/url/", {
      method: "POST",
      headers: {
        "Auth-Key": authKey,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ url: target.url }),
      signal: AbortSignal.timeout(8_000),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const body = urlHausSchema.parse(await parseJson(response));

    if (body.query_status === "ok") {
      return {
        source: "urlhaus",
        status: "malicious",
        detail: `URLhaus matched ${body.threat ?? "a malware distribution URL"} (${body.url_status ?? "status unknown"}).`,
        reference: body.urlhaus_reference,
      };
    }
    if (body.query_status === "no_results") {
      return {
        source: "urlhaus",
        status: "clean",
        detail: "URLhaus returned no exact malware URL match.",
      };
    }
    throw new Error(`query_status ${body.query_status}`);
  } catch (error) {
    return {
      source: "urlhaus",
      status: "error",
      detail: `URLhaus lookup failed: ${(error as Error).message}`,
    };
  }
}

async function virusTotalEvidence(
  target: ValidatedTarget,
  fetcher: typeof fetch,
  apiKey?: string,
): Promise<SourceEvidence> {
  if (!apiKey) {
    return {
      source: "virustotal",
      status: "unavailable",
      detail: "VIRUSTOTAL_API_KEY is not configured.",
    };
  }

  try {
    const identifier = Buffer.from(target.url).toString("base64url");
    const response = await fetcher(`https://www.virustotal.com/api/v3/urls/${identifier}`, {
      headers: { Accept: "application/json", "x-apikey": apiKey },
      signal: AbortSignal.timeout(8_000),
    });
    if (response.status === 404) {
      return {
        source: "virustotal",
        status: "unavailable",
        detail: "VirusTotal has no existing report for this exact URL.",
      };
    }
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const stats = virusTotalSchema.parse(await parseJson(response)).data.attributes
      .last_analysis_stats;

    if (stats.malicious >= 2) {
      return {
        source: "virustotal",
        status: "malicious",
        detail: `${stats.malicious} VirusTotal engines classified the URL as malicious.`,
      };
    }
    if (stats.malicious === 1 || stats.suspicious > 0) {
      return {
        source: "virustotal",
        status: "suspicious",
        detail: `VirusTotal returned ${stats.malicious} malicious and ${stats.suspicious} suspicious verdicts.`,
      };
    }
    if (stats.harmless >= 10) {
      return {
        source: "virustotal",
        status: "clean",
        detail: `${stats.harmless} VirusTotal engines classified the URL as harmless.`,
      };
    }

    return {
      source: "virustotal",
      status: "unavailable",
      detail: "VirusTotal has too few affirmative verdicts for a decision.",
    };
  } catch (error) {
    return {
      source: "virustotal",
      status: "error",
      detail: `VirusTotal lookup failed: ${(error as Error).message}`,
    };
  }
}

const REPUTATION_SOURCES = new Set(["phishtank", "google", "urlhaus", "virustotal"]);

export function aggregateEvidence(
  targetUrl: string,
  evidence: SourceEvidence[],
  checkedAt = new Date(),
): MinerScanResult {
  const malicious = evidence.filter((item) => item.status === "malicious");
  const suspicious = evidence.filter((item) => item.status === "suspicious");
  const cleanReputation = evidence.filter(
    (item) => item.status === "clean" && REPUTATION_SOURCES.has(item.source),
  );

  if (malicious.length > 0) {
    const reason = `malicious: ${malicious.map((item) => item.detail).join(" ")}`;
    return {
      schema_version: "1.0",
      intent: "URL_SCAN",
      url: targetUrl,
      verdict: "malicious",
      malicious: true,
      confidence: malicious.length > 1 ? 0.995 : 0.97,
      answer: reason,
      reason,
      live_reason: reason,
      live_scan_performed: true,
      historical_context: null,
      evidence,
      checked_at: checkedAt.toISOString(),
      policy_version: "proofgate-2",
    };
  }

  if (suspicious.length > 0) {
    const reason = `suspicious: ${suspicious.map((item) => item.detail).join(" ")}`;
    return {
      schema_version: "1.0",
      intent: "URL_SCAN",
      url: targetUrl,
      verdict: "suspicious",
      malicious: false,
      confidence: cleanReputation.length > 0 ? 0.72 : 0.62,
      answer: reason,
      reason,
      live_reason: reason,
      live_scan_performed: true,
      historical_context: null,
      evidence,
      checked_at: checkedAt.toISOString(),
      policy_version: "proofgate-2",
    };
  }

  const confidence = cleanReputation.length >= 2 ? 0.96 : cleanReputation.length === 1 ? 0.86 : 0.65;
  const cleanNames = cleanReputation.map((item) => item.source).join(", ");
  const reason =
    cleanReputation.length > 0
      ? `safe: no threat match from ${cleanNames}; public DNS and URL policy checks completed.`
      : "safe with limited confidence: public DNS and URL policy checks passed, but no reputation provider returned a clean verdict.";
  return {
    schema_version: "1.0",
    intent: "URL_SCAN",
    url: targetUrl,
    verdict: "safe",
    malicious: false,
    confidence,
    answer: reason,
    reason,
    live_reason: reason,
    live_scan_performed: true,
    historical_context: null,
    evidence,
    checked_at: checkedAt.toISOString(),
    policy_version: "proofgate-2",
  };
}

function historicalContext(match: HistoricalUrlMatch): HistoricalContext {
  return {
    id: match.incident.id,
    name: match.incident.name,
    disposition: match.incident.disposition,
    matched_by: match.matched_by,
    facts: match.incident.facts,
    sources: match.incident.sources,
  };
}

export function addHistoricalContext(
  result: MinerScanResult,
  question?: string,
): MinerScanResult {
  const match = findHistoricalUrlIncident({ url: result.url, question });
  if (!match) return result;

  const historicalAnswer = match.incident.facts.join(" ");
  const answer =
    match.matched_by === "hostname"
      ? historicalAnswer
      : `Live URL assessment: ${result.live_reason} Historical context: ${historicalAnswer}`;
  return {
    ...result,
    answer,
    reason: answer,
    historical_context: historicalContext(match),
  };
}

export function answerHistoricalUrlQuestion(
  question: string | undefined,
  checkedAt = new Date(),
): MinerScanResult {
  const match = findHistoricalUrlIncident({ question });
  if (match) {
    const answer = match.incident.facts.join(" ");
    const historicalStatus = match.incident.disposition === "malicious" ? "malicious" : "clean";
    return {
      schema_version: "1.0",
      intent: "URL_SCAN",
      url: "",
      verdict: match.incident.disposition === "malicious" ? "malicious" : "safe",
      malicious: match.incident.disposition === "malicious",
      confidence: 1,
      answer,
      reason: answer,
      live_reason: null,
      live_scan_performed: false,
      historical_context: historicalContext(match),
      evidence: [
        {
          source: "history",
          status: historicalStatus,
          detail: `Matched the bounded historical record for ${match.incident.name}.`,
          reference: match.incident.sources[0]?.url,
        },
      ],
      checked_at: checkedAt.toISOString(),
      policy_version: "proofgate-2",
    };
  }

  const answer =
    "No complete HTTP or HTTPS URL was provided, and the question did not match ProofGate's bounded historical incident catalog. No URL or campaign verdict is claimed.";
  return {
    schema_version: "1.0",
    intent: "URL_SCAN",
    url: "",
    verdict: "suspicious",
    malicious: false,
    confidence: 0,
    answer,
    reason: answer,
    live_reason: null,
    live_scan_performed: false,
    historical_context: null,
    evidence: [{ source: "history", status: "unavailable", detail: answer }],
    checked_at: checkedAt.toISOString(),
    policy_version: "proofgate-2",
  };
}

export async function scanUrlWithEvidence(
  input: string,
  options: MinerScanOptions = {},
): Promise<MinerScanResult> {
  const fetcher = options.fetcher ?? fetch;
  const now = options.now ?? new Date();
  const target = await assertPublicTarget(input, {
    lookup: options.lookup,
    allowNonStandardPorts: false,
    allowUnresolved: true,
  });

  const evidence: SourceEvidence[] = [
    structureEvidence(target),
    {
      source: "dns",
      status: target.addresses.length > 0 ? "clean" : "unavailable",
      detail:
        target.addresses.length > 0
          ? `Resolved only to public addresses: ${target.addresses.join(", ")}.`
          : "The hostname did not resolve during this scan.",
    },
  ];

  const remoteEvidence = await Promise.all([
    rdapEvidence(target, fetcher, now),
    phishTankEvidence(
      target,
      fetcher,
      options.phishTankAppKey ?? process.env.PHISHTANK_APP_KEY,
    ),
    googleEvidence(
      target,
      fetcher,
      options.googleSafeBrowsingKey ?? process.env.GOOGLE_SAFE_BROWSING_API_KEY,
    ),
    urlHausEvidence(
      target,
      fetcher,
      options.urlHausAuthKey ?? process.env.URLHAUS_AUTH_KEY,
    ),
    virusTotalEvidence(
      target,
      fetcher,
      options.virusTotalApiKey ?? process.env.VIRUSTOTAL_API_KEY,
    ),
  ]);

  return addHistoricalContext(
    aggregateEvidence(target.url, [...evidence, ...remoteEvidence], now),
    options.question,
  );
}