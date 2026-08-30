import { z } from "zod";

import { TargetValidationError } from "./target";

const requestSchema = z
  .object({
    url: z.string().trim().min(1).max(4_096).optional(),
    question: z.string().trim().min(1).max(4_096).optional(),
    query: z.string().trim().min(1).max(4_096).optional(),
    input: z.string().trim().min(1).max(4_096).optional(),
  })
  .passthrough();

export function scanUrlFromBody(body: unknown): string {
  const parsed = requestSchema.parse(body);
  for (const candidate of [parsed.url, parsed.question, parsed.query, parsed.input]) {
    if (!candidate) continue;
    const match = candidate.match(/https?:\/\/[^\s<>"'`]+/i);
    if (match) return match[0].replace(/[),.;!?\]}]+$/, "");
  }
  throw new TargetValidationError("Provide one complete http:// or https:// URL.");
}