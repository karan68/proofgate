import { z } from "zod";

import { TargetValidationError } from "./target";

const requestSchema = z
  .object({
    url: z.string().trim().min(1).max(2_048).optional(),
    question: z.string().trim().min(1).max(4_096).optional(),
    query: z.string().trim().min(1).max(4_096).optional(),
    input: z.string().trim().min(1).max(4_096).optional(),
    payload: z.unknown().optional(),
    params: z.unknown().optional(),
    arguments: z.unknown().optional(),
    data: z.unknown().optional(),
  })
  .passthrough();

function trimProsePunctuation(value: string): string {
  let end = value.length;
  while (end > 0 && /[.,;!?]/.test(value[end - 1])) end -= 1;
  for (const [opening, closing] of [
    ["(", ")"],
    ["[", "]"],
    ["{", "}"],
  ]) {
    while (
      end > 0 &&
      value[end - 1] === closing &&
      value.slice(0, end).split(closing).length > value.slice(0, end).split(opening).length
    ) {
      end -= 1;
    }
  }
  return value.slice(0, end);
}

function stringsFromContainer(value: unknown): string[] {
  if (!value || typeof value !== "object" || Array.isArray(value)) return [];
  const record = value as Record<string, unknown>;
  return [record.url, record.question, record.query, record.input].filter(
    (candidate): candidate is string => typeof candidate === "string",
  );
}

export function scanUrlFromBody(body: unknown): string {
  const parsed = requestSchema.parse(body);
  if (parsed.url) return parsed.url;

  const candidates = [
    parsed.question,
    parsed.query,
    parsed.input,
    ...stringsFromContainer(parsed.payload),
    ...stringsFromContainer(parsed.params),
    ...stringsFromContainer(parsed.arguments),
    ...stringsFromContainer(parsed.data),
  ];
  for (const candidate of candidates) {
    if (!candidate) continue;
    const match = candidate.match(/https?:\/\/[^\s<>"'`]+/i);
    if (match) return trimProsePunctuation(match[0]);
  }
  throw new TargetValidationError("Provide one complete http:// or https:// URL.");
}