import type { NextRequest } from "next/server";
import { stringify } from "yaml";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

function minerId(): number {
  const parsed = Number(process.env.PROOFGATE_MINER_ID ?? "7402");
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error("PROOFGATE_MINER_ID must be a non-negative safe integer.");
  }
  return parsed;
}

function publicBaseUrl(request: NextRequest): string {
  const configured = process.env.PROOFGATE_PUBLIC_URL?.replace(/\/$/, "");
  if (configured) {
    const url = new URL(configured);
    const local = ["localhost", "127.0.0.1"].includes(url.hostname);
    if (url.protocol !== "https:" && !(local && url.protocol === "http:")) {
      throw new Error(
        "PROOFGATE_PUBLIC_URL must use HTTPS unless it points to localhost.",
      );
    }
    if (url.username || url.password) {
      throw new Error("PROOFGATE_PUBLIC_URL must not contain credentials.");
    }
    return url.toString().replace(/\/$/, "");
  }

  if (["localhost", "127.0.0.1"].includes(request.nextUrl.hostname)) {
    return request.nextUrl.origin;
  }

  throw new Error("Set PROOFGATE_PUBLIC_URL before publishing miner.yaml.");
}

export async function GET(request: NextRequest) {
  try {
    const baseUrl = publicBaseUrl(request);
    const repository = process.env.PROOFGATE_REPOSITORY_URL;
    const config = {
      version: "1",
      kind: "miner",
      id: minerId(),
      slug: "proofgate-url-intelligence",
      protocol: "generic",
      name: "ProofGate URL Intelligence",
      description:
        "Deterministic pre-execution URL intelligence for autonomous agents. Aggregates phishing, malware, DNS, domain-age, URL-structure, and bounded sourced historical-incident evidence, plus one bounded HEAD reachability probe sent to the already-validated public address, pinned to that address, with redirects unfollowed and no response body read.",
      base_url: baseUrl,
      rate_limit_per_sec: 5,
      cache_ttl_sec: 60,
      circuit_threshold: 5,
      circuit_cooldown_seconds: 30,
      endpoints: [
        {
          path: "/scan",
          external_path: "/api/miner/scan",
          method: "POST",
          description:
            "Return a normalized live URL verdict and a scorer-readable answer, including the HTTP status, scheme and declared redirect from one bounded HEAD probe, with sourced historical context when the request names a documented incident.",
          intents: ["URL_SCAN"],
          params: {
            body: {
              required: [
                {
                  name: "url",
                  type: "string",
                  intents: ["URL_SCAN"],
                  description:
                    "Complete public http:// or https:// URL to evaluate, up to 2,048 characters.",
                },
              ],
            },
          },
        },
      ],
      input_schema: {
        type: "object",
        additionalProperties: false,
        required: ["url"],
        properties: {
          url: {
            type: "string",
            format: "uri",
            maxLength: 2048,
            description: "The public HTTP or HTTPS URL to evaluate.",
          },
          question: {
            type: "string",
            maxLength: 4096,
            description:
              "Optional original URL_SCAN question, retained to distinguish live URL safety from documented historical incident context.",
          },
        },
      },
      output_schema: {
        type: "object",
        required: [
          "schema_version",
          "intent",
          "url",
          "verdict",
          "confidence",
          "answer",
          "reason",
          "live_reason",
          "historical_context",
          "evidence",
          "checked_at",
          "policy_version",
        ],
        properties: {
          schema_version: { type: "string" },
          intent: { type: "string", enum: ["URL_SCAN"] },
          url: { type: "string" },
          verdict: {
            type: "string",
            enum: ["no_threat_signal", "informational", "suspicious", "malicious"],
            description:
              "no_threat_signal means no threat evidence was found; it is not a certification that the URL is safe.",
          },
          malicious: {
            type: "boolean",
            enum: [true],
            description: "Present only when the verdict is malicious; never emitted as false.",
          },
          confidence: { type: "number", minimum: 0, maximum: 1 },
          answer: { type: "string" },
          reason: { type: "string" },
          live_reason: { type: ["string", "null"] },
          historical_context: { type: ["object", "null"] },
          evidence: {
            type: "array",
            items: { type: "object" },
            description:
              "Findings that produced a reading, from structure, dns, rdap, reachability, history and any reputation provider that answered.",
          },
          providers_not_queried: {
            type: "array",
            items: { type: "string" },
            description: "Reputation providers skipped because no credential is configured.",
          },
          not_observed: {
            type: "array",
            items: { type: "string" },
            description: "Checks that ran but produced no reading.",
          },
          checked_at: { type: "string", format: "date-time" },
          policy_version: { type: "string" },
        },
      },
      semantics: {
        signal_mapping: {
          confidence_field: "confidence",
          label_field: "verdict",
          reason_field: "answer",
        },
        supported_intents: ["URL_SCAN"],
      },
      on_chain: {
        transform: "direct",
        min_price_usdc: 0.01,
        fields: {
          strings: [
            {
              index: 0,
              name: "verdict",
              description:
                "Normalized no_threat_signal, informational, suspicious, or malicious verdict.",
              source_path: "verdict",
            },
            {
              index: 1,
              name: "reason",
              description: "Human-readable explanation for the safety verdict.",
              source_path: "reason",
            },
          ],
          integers: [
            {
              index: 0,
              name: "confidence_x10000",
              description: "Confidence score scaled to an integer from 0 to 10,000.",
              source_path: "confidence",
              multiplier: 10000,
            },
          ],
          bools: [
            {
              index: 0,
              name: "malicious",
              description: "True when the submitted URL is classified as malicious.",
              source_path: "malicious",
            },
          ],
        },
        request: [
          {
            endpoint: "scan",
            method: "POST",
            body: { url: { source: "strings.0" } },
          },
        ],
      },
      docs: {
        website: baseUrl,
        ...(repository ? { repository } : {}),
      },
      limitations: [
        {
          code: "MAX_PARAM_VALUE",
          message: "URL input is limited to 2,048 characters.",
          param: "url",
          property: "length",
          value_num: 2048,
          operator: "lte",
        },
        {
          code: "MAX_PARAM_VALUE",
          message: "Question context is limited to 4,096 characters.",
          param: "question",
          property: "length",
          value_num: 4096,
          operator: "lte",
        },
        {
          code: "NO_CERTIFICATION",
          message:
            "A no_threat_signal verdict reports the absence of threat evidence. ProofGate does not certify that a URL is safe.",
        },
        {
          code: "BOUNDED_PROBE",
          message:
            "The reachability probe sends one HEAD request to the validated public address, pinned to that address, with redirects unfollowed, no response body read, and a 5 second timeout. ProofGate never renders or executes the target.",
        },
      ],
    };

    return new Response(stringify(config, { lineWidth: 0 }), {
      headers: {
        "Cache-Control": "public, max-age=300",
        "Content-Type": "application/yaml; charset=utf-8",
      },
    });
  } catch (error) {
    return Response.json(
      { error: "miner_config_unavailable", message: (error as Error).message },
      { status: 503 },
    );
  }
}