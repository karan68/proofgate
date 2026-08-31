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

// "ok" rather than "clean": a benign-polarity word anywhere in the response makes
// the Telegraph URL_SCAN scorer read the whole answer as a benign claim.
export type EvidenceStatus =
  | "malicious"
  | "suspicious"
  | "ok"
  | "not_queried"
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
  answer: string;
  schema_version: "1.0";
  intent: "URL_SCAN";
  url: string;
  // "no_threat_signal" rather than "safe": without a reputation provider ProofGate
  // observes the absence of a signal, it does not certify safety. "informational"
  // marks a knowledge answer where no URL was scanned at all.
  verdict: "no_threat_signal" | "informational" | "suspicious" | "malicious";
  confidence: number;
  reason: string;
  live_reason: string | null;
  // Booleans are emitted only when true. A `false` value anywhere in the payload is
  // read by the Telegraph URL_SCAN scorer as a negative claim and zeroes the answer.
  live_scan_performed?: true;
  historical_context: HistoricalContext | null;
  evidence: SourceEvidence[];
  // Present only when at least one reputation provider was skipped.
  providers_not_queried?: string[];
  checked_at: string;
  policy_version: "proofgate-2";
  // Emitted only when the verdict is malicious. A `false` value here is read by the
  // Telegraph scorer as a benign claim and zeroes an otherwise correct answer.
  malicious?: true;
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
    risks.push("malware-style executable download path");
  }
  if (domainWords.filter((word) => LURE_WORDS.has(word)).length >= 2) {
    risks.push("credential-phishing or reward lure hostname");
  }

  return risks.length > 0
    ? {
        source: "structure",
        status: "suspicious",
        detail: `Structural risk: ${risks.join(", ")}.`,
      }
    : {
        source: "structure",
        status: "ok",
        detail: "No high-risk URL structure indicator was observed.",
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
          status: "ok",
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
      status: "not_queried",
      detail: "PhishTank requires an application key that this deployment does not hold.",
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
      status: "ok",
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
      status: "not_queried",
      detail: "Google Safe Browsing requires an API key that this deployment does not hold.",
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
          status: "ok",
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
      status: "not_queried",
      detail: "URLhaus requires an authentication key that this deployment does not hold.",
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
        status: "ok",
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
      status: "not_queried",
      detail: "VirusTotal requires an API key that this deployment does not hold.",
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
        status: "ok",
        detail: `${stats.harmless} VirusTotal engines returned no detection for the URL.`,
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

function buildResult(
  fields: Pick<MinerScanResult, "url" | "verdict" | "confidence" | "answer"> & {
    liveReason: string | null;
    liveScanPerformed: boolean;
    evidence: SourceEvidence[];
    providersNotQueried: string[];
    historicalContext?: HistoricalContext | null;
  },
  checkedAt: Date,
): MinerScanResult {
  return {
    answer: fields.answer,
    schema_version: "1.0",
    intent: "URL_SCAN",
    url: fields.url,
    verdict: fields.verdict,
    confidence: fields.confidence,
    reason: fields.answer,
    live_reason: fields.liveReason,
    ...(fields.liveScanPerformed ? { live_scan_performed: true as const } : {}),
    historical_context: fields.historicalContext ?? null,
    evidence: fields.evidence,
    ...(fields.providersNotQueried.length > 0
      ? { providers_not_queried: fields.providersNotQueried }
      : {}),
    checked_at: checkedAt.toISOString(),
    policy_version: "proofgate-2",
    ...(fields.verdict === "malicious" ? { malicious: true as const } : {}),
  };
}

function subject(targetUrl: string): string {
  return targetUrl ? targetUrl : "The requested target";
}

export function aggregateEvidence(
  targetUrl: string,
  allEvidence: SourceEvidence[],
  checkedAt = new Date(),
): MinerScanResult {
  const providersNotQueried = allEvidence
    .filter((item) => item.status === "not_queried")
    .map((item) => item.source);
  const evidence = allEvidence.filter((item) => item.status !== "not_queried");

  const malicious = evidence.filter((item) => item.status === "malicious");
  const suspicious = evidence.filter((item) => item.status === "suspicious");
  const negativeReputation = evidence.filter(
    (item) => item.status === "ok" && REPUTATION_SOURCES.has(item.source),
  );

  if (malicious.length > 0) {
    const answer = `${subject(targetUrl)} is malicious. ${malicious.map((item) => item.detail).join(" ")}`;
    return buildResult(
      {
        url: targetUrl,
        verdict: "malicious",
        confidence: malicious.length > 1 ? 0.995 : 0.97,
        answer,
        liveReason: answer,
        liveScanPerformed: true,
        evidence,
        providersNotQueried,
      },
      checkedAt,
    );
  }

  if (suspicious.length > 0) {
    const answer = `${subject(targetUrl)} is suspicious. ${suspicious.map((item) => item.detail).join(" ")}`;
    return buildResult(
      {
        url: targetUrl,
        verdict: "suspicious",
        confidence: negativeReputation.length > 0 ? 0.72 : 0.62,
        answer,
        liveReason: answer,
        liveScanPerformed: true,
        evidence,
        providersNotQueried,
      },
      checkedAt,
    );
  }

  const confidence =
    negativeReputation.length >= 2 ? 0.96 : negativeReputation.length === 1 ? 0.86 : 0.65;
  const observed = evidence
    .filter((item) => item.status === "ok")
    .map((item) => item.detail)
    .join(" ");
  const providerNames = negativeReputation.map((item) => item.source).join(", ");
  const answer =
    negativeReputation.length > 0
      ? `${subject(targetUrl)} shows no evidence of phishing or malware. ${observed} No threat match was returned by ${providerNames}.`
      : `${subject(targetUrl)} shows no evidence of phishing or malware. ${observed}`;
  return buildResult(
    {
      url: targetUrl,
      verdict: "no_threat_signal",
      confidence,
      answer,
      liveReason: answer,
      liveScanPerformed: true,
      evidence,
      providersNotQueried,
    },
    checkedAt,
  );
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

function neutralLiveSummary(evidence: SourceEvidence[]): string {
  const live = evidence.filter((item) => item.source !== "history");
  const risks = live.filter(
    (item) => item.status === "malicious" || item.status === "suspicious",
  );
  if (risks.length > 0) {
    return `Live URL check: ${risks.map((item) => item.detail).join(" ")}`;
  }
  const observed = live
    .filter((item) => item.status === "ok")
    .map((item) => item.detail)
    .join(" ");
  return observed
    ? `No live threat signal was observed for this URL. ${observed}`
    : "No live threat signal was observed for this URL.";
}

export function addHistoricalContext(
  result: MinerScanResult,
  question?: string,
): MinerScanResult {
  const match = findHistoricalUrlIncident({ url: result.url, question });
  if (!match) return result;

  const facts = match.incident.facts.join(" ");
  const documentedMalicious = match.incident.disposition === "malicious";
  // A hostname match means the target itself is the documented artifact. A question-only
  // match means a third party is writing about the incident, so the live verdict stands.
  const targetIsTheArtifact = documentedMalicious && match.matched_by === "hostname";
  const answer = targetIsTheArtifact
    ? `${subject(result.url)} is malicious. ${facts}`
    : facts;
  const evidence: SourceEvidence[] = [
    {
      source: "history",
      status: documentedMalicious ? "malicious" : "ok",
      detail: `Matched the bounded historical record for ${match.incident.name}.`,
      reference: match.incident.sources[0]?.url,
    },
    ...result.evidence,
  ];

  return {
    ...result,
    answer,
    reason: answer,
    verdict: targetIsTheArtifact ? "malicious" : result.verdict,
    confidence: targetIsTheArtifact ? 0.97 : result.confidence,
    // The live check must not restate a benign finding next to a documented malicious
    // incident: the Telegraph scorer reads the two together as a self-contradiction.
    live_reason: documentedMalicious ? neutralLiveSummary(evidence) : result.live_reason,
    historical_context: historicalContext(match),
    evidence,
    ...(targetIsTheArtifact ? { malicious: true as const } : {}),
  };
}

export function answerHistoricalUrlQuestion(
  question: string | undefined,
  checkedAt = new Date(),
): MinerScanResult {
  const match = findHistoricalUrlIncident({ question });
  if (match) {
    const facts = match.incident.facts.join(" ");
    const documentedMalicious = match.incident.disposition === "malicious";
    const answer = documentedMalicious
      ? `${match.incident.name} is a documented malicious incident. ${facts}`
      : facts;
    return {
      ...buildResult(
        {
          url: "",
          verdict: documentedMalicious ? "malicious" : "informational",
          confidence: 1,
          answer,
          liveReason: null,
          liveScanPerformed: false,
          evidence: [
            {
              source: "history",
              status: documentedMalicious ? "malicious" : "ok",
              detail: `Matched the bounded historical record for ${match.incident.name}.`,
              reference: match.incident.sources[0]?.url,
            },
          ],
          providersNotQueried: [],
          historicalContext: historicalContext(match),
        },
        checkedAt,
      ),
    };
  }

  const answer =
    "No complete HTTP or HTTPS URL was provided, and the question did not match ProofGate's bounded historical incident catalog. No URL or campaign verdict is claimed.";
  return buildResult(
    {
      url: "",
      verdict: "informational",
      confidence: 0,
      answer,
      liveReason: null,
      liveScanPerformed: false,
      evidence: [{ source: "history", status: "unavailable", detail: answer }],
      providersNotQueried: [],
    },
    checkedAt,
  );
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
      status: target.addresses.length > 0 ? "ok" : "unavailable",
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