import { ZodError } from "zod";

import { AuditConfigurationError } from "./audit";
import { TargetExecutionError } from "./execute";
import { RedisConfigurationError } from "./redis";
import { TargetValidationError } from "./target";
import {
  TelegraphConfigurationError,
  TelegraphRequestError,
} from "./telegraph";

export function apiError(error: unknown): Response {
  if (error instanceof ZodError) {
    return Response.json(
      {
        error: "invalid_request",
        message: "The request did not match the required contract.",
        issues: error.issues.map((issue) => ({
          path: issue.path.join("."),
          message: issue.message,
        })),
      },
      { status: 400 },
    );
  }

  if (error instanceof SyntaxError) {
    return Response.json(
      { error: "invalid_json", message: "The request body must be valid JSON." },
      { status: 400 },
    );
  }

  if (error instanceof TargetValidationError) {
    return Response.json(
      { error: "unsafe_target", message: error.message },
      { status: 400 },
    );
  }

  if (error instanceof TelegraphConfigurationError) {
    return Response.json(
      { error: "payment_not_configured", message: error.message },
      { status: 503 },
    );
  }

  if (error instanceof TelegraphRequestError) {
    return Response.json(
      {
        error: "telegraph_request_failed",
        message: error.message,
        upstream_status: error.status,
      },
      { status: 502 },
    );
  }

  if (error instanceof TargetExecutionError) {
    return Response.json(
      { error: "target_execution_failed", message: error.message },
      { status: 502 },
    );
  }

  if (
    error instanceof AuditConfigurationError ||
    error instanceof RedisConfigurationError
  ) {
    return Response.json(
      { error: "storage_not_configured", message: error.message },
      { status: 503 },
    );
  }

  console.error("[proofgate] Unhandled API error", error);
  return Response.json(
    { error: "internal_error", message: "ProofGate could not complete the request." },
    { status: 500 },
  );
}

export const publicCorsHeaders = {
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Origin": "*",
} as const;