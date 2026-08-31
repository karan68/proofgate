import { rateLimitError } from "../../../../lib/proofgate/access";
import { apiError, publicCorsHeaders } from "../../../../lib/proofgate/api";
import {
  answerHistoricalUrlQuestion,
  scanUrlWithEvidence,
} from "../../../../lib/proofgate/miner";
import { scanRequestFromBody } from "../../../../lib/proofgate/miner-request";

export const dynamic = "force-dynamic";
export const maxDuration = 30;
export const runtime = "nodejs";

export async function GET() {
  return Response.json(
    {
      status: "ok",
      miner: "proofgate-url-intelligence",
      intent: "URL_SCAN",
      providers: {
        phishtank: Boolean(process.env.PHISHTANK_APP_KEY),
        google_safe_browsing: Boolean(process.env.GOOGLE_SAFE_BROWSING_API_KEY),
        urlhaus: Boolean(process.env.URLHAUS_AUTH_KEY),
        virustotal: Boolean(process.env.VIRUSTOTAL_API_KEY),
      },
    },
    { headers: publicCorsHeaders },
  );
}

export async function POST(request: Request) {
  try {
    const limitError = await rateLimitError(request, {
      scope: "miner",
      limit: 120,
      windowMs: 60_000,
    });
    if (limitError) {
      for (const [key, value] of Object.entries(publicCorsHeaders)) {
        limitError.headers.set(key, value);
      }
      return limitError;
    }

    const rawBody = await request.text();
    // The Telegraph node never discloses the question it graded, so record it here.
    console.log(
      JSON.stringify({
        event: "miner_scan_request",
        at: new Date().toISOString(),
        user_agent: request.headers.get("user-agent")?.slice(0, 200) ?? null,
        body: rawBody.slice(0, 4_096),
      }),
    );

    const scanRequest = scanRequestFromBody(JSON.parse(rawBody));
    const result = scanRequest.url
      ? await scanUrlWithEvidence(scanRequest.url, { question: scanRequest.question })
      : answerHistoricalUrlQuestion(scanRequest.question);
    console.log(
      JSON.stringify({
        event: "miner_scan_answer",
        verdict: result.verdict,
        matched: result.historical_context?.id ?? null,
        answer: result.answer.slice(0, 1_024),
      }),
    );
    return Response.json(result, {
      headers: publicCorsHeaders,
    });
  } catch (error) {
    const response = apiError(error);
    for (const [key, value] of Object.entries(publicCorsHeaders)) {
      response.headers.set(key, value);
    }
    return response;
  }
}

export async function OPTIONS() {
  return new Response(null, { status: 204, headers: publicCorsHeaders });
}