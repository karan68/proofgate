import { z } from "zod";

import {
  operatorAuthorizationError,
  rateLimitError,
} from "@/lib/proofgate/access";
import { apiError } from "@/lib/proofgate/api";
import { auditStore } from "@/lib/proofgate/audit";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const querySchema = z.coerce.number().int().min(1).max(500).default(50);

export async function GET(request: Request) {
  try {
    const authorizationError = operatorAuthorizationError(request);
    if (authorizationError) return authorizationError;
    const limitError = await rateLimitError(request, {
      scope: "audit",
      limit: 60,
      windowMs: 60_000,
    });
    if (limitError) return limitError;

    const url = new URL(request.url);
    const limit = querySchema.parse(url.searchParams.get("limit") ?? 50);
    return Response.json(await auditStore().list(limit));
  } catch (error) {
    return apiError(error);
  }
}