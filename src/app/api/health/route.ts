import { telegraphRuntimeStatus } from "@/lib/proofgate/telegraph";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET() {
  return Response.json({
    status: "ok",
    service: "proofgate",
    version: "0.1.0",
    time: new Date().toISOString(),
    telegraph: telegraphRuntimeStatus(),
    providers: {
      phishtank: Boolean(process.env.PHISHTANK_APP_KEY),
      google_safe_browsing: Boolean(process.env.GOOGLE_SAFE_BROWSING_API_KEY),
      urlhaus: Boolean(process.env.URLHAUS_AUTH_KEY),
      virustotal: Boolean(process.env.VIRUSTOTAL_API_KEY),
    },
  });
}