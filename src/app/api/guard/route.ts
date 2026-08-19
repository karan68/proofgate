import { z } from "zod";

import {
  operatorAuthorizationError,
  rateLimitError,
} from "@/lib/proofgate/access";
import { apiError } from "@/lib/proofgate/api";
import { guardUrl } from "@/lib/proofgate/guard";

export const dynamic = "force-dynamic";
export const maxDuration = 60;
export const runtime = "nodejs";

const requestSchema = z
  .object({
    url: z.string().trim().min(1).max(2_048),
    execute: z.boolean().optional().default(false),
    method: z.enum(["GET", "HEAD"]).optional().default("GET"),
  })
  .strict();

export async function POST(request: Request) {
  try {
    const authorizationError = operatorAuthorizationError(request);
    if (authorizationError) return authorizationError;
    const limitError = await rateLimitError(request, {
      scope: "guard",
      limit: 10,
      windowMs: 60_000,
    });
    if (limitError) return limitError;

    const input = requestSchema.parse(await request.json());
    return Response.json(await guardUrl(input));
  } catch (error) {
    return apiError(error);
  }
}