#!/usr/bin/env node

import { config } from "dotenv";
import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import * as z from "zod/v4";

import { auditStore } from "../src/lib/proofgate/audit";
import { guardUrl } from "../src/lib/proofgate/guard";
import {
  discoverUrlScanMiners,
  telegraphRuntimeStatus,
} from "../src/lib/proofgate/telegraph";

config({ path: [".env.local", ".env"], quiet: true });

function text(value: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }],
  };
}

function toolError(error: unknown) {
  const message = error instanceof Error ? error.message : "Unknown ProofGate error";
  return {
    content: [{ type: "text" as const, text: message }],
    isError: true,
  };
}

export function createProofGateServer(): McpServer {
  const server = new McpServer({ name: "proofgate", version: "0.1.0" });

  server.registerTool(
    "proofgate_network_status",
    {
      description:
        "Check ProofGate payment readiness and discover the live Telegraph URL_SCAN Miner pool. This tool is free and performs no inference or target request.",
      inputSchema: z.object({}),
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async () => {
      try {
        return text({
          runtime: telegraphRuntimeStatus(),
          discovery: await discoverUrlScanMiners(),
        });
      } catch (error) {
        return toolError(error);
      }
    },
  );

  server.registerTool(
    "proofgate_scan",
    {
      description:
        "Select a compatible Miner from Telegraph's live URL_SCAN catalog, pay for one x402 inference, apply ProofGate policy, and append a tamper-evident audit record. Does not visit the target URL.",
      inputSchema: z.object({
        url: z.string().url().max(2_048).describe("Public HTTP or HTTPS URL to scan"),
      }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        openWorldHint: true,
      },
    },
    async ({ url }) => {
      try {
        return text(await guardUrl({ url, execute: false }));
      } catch (error) {
        return toolError(error);
      }
    },
  );

  server.registerTool(
    "proofgate_guarded_fetch",
    {
      description:
        "Scan a public URL through the live Telegraph URL_SCAN network, then issue a DNS-pinned GET or HEAD only when policy returns ALLOW. Redirects are not followed, bodies are capped, and x402 payments are limited by server policy.",
      inputSchema: z.object({
        url: z.string().url().max(2_048).describe("Public HTTP or HTTPS URL to guard"),
        method: z.enum(["GET", "HEAD"]).default("GET"),
      }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        openWorldHint: true,
      },
    },
    async ({ url, method }) => {
      try {
        return text(await guardUrl({ url, method, execute: true }));
      } catch (error) {
        return toolError(error);
      }
    },
  );

  server.registerTool(
    "proofgate_audit_tail",
    {
      description:
        "Read recent local ProofGate decisions and verify the SHA-256 audit chain. No payment or target request is made.",
      inputSchema: z.object({
        limit: z.number().int().min(1).max(100).default(20),
      }),
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ limit }) => {
      try {
        return text(await auditStore().list(limit));
      } catch (error) {
        return toolError(error);
      }
    },
  );

  return server;
}

void serveStdio(createProofGateServer, {
  onerror: (error) => console.error("[proofgate-mcp]", error.message),
});
console.error("[proofgate-mcp] v0.1.0 ready on stdio");