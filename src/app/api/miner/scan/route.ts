import { rateLimitError } from "@/lib/proofgate/access";
import { apiError, publicCorsHeaders } from "@/lib/proofgate/api";
import { scanUrlWithEvidence } from "@/lib/proofgate/miner";
import { scanUrlFromBody } from "@/lib/proofgate/miner-request";

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

    const url = scanUrlFromBody(await request.json());
    return Response.json(await scanUrlWithEvidence(url), {
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