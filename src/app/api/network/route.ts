import { apiError } from "@/lib/proofgate/api";
import {
  discoverUrlScanMiners,
  telegraphRuntimeStatus,
} from "@/lib/proofgate/telegraph";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET() {
  try {
    const discovery = await discoverUrlScanMiners();
    return Response.json({ discovery, runtime: telegraphRuntimeStatus() });
  } catch (error) {
    return apiError(error);
  }
}