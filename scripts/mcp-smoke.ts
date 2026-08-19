import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import path from "node:path";

const expectedTools = [
  "proofgate_audit_tail",
  "proofgate_guarded_fetch",
  "proofgate_network_status",
  "proofgate_scan",
];

const environment = Object.fromEntries(
  Object.entries(process.env).filter((entry): entry is [string, string] => {
    return typeof entry[1] === "string";
  }),
);

const client = new Client({ name: "proofgate-smoke", version: "0.1.0" });
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [path.resolve("dist/mcp/server.js")],
  cwd: process.cwd(),
  env: environment,
  stderr: "pipe",
});

transport.stderr?.on("data", (chunk) => process.stderr.write(chunk));

try {
  await client.connect(transport);
  const { tools } = await client.listTools();
  const names = tools.map((tool) => tool.name).sort();
  if (JSON.stringify(names) !== JSON.stringify(expectedTools)) {
    throw new Error(`Unexpected MCP tools: ${names.join(", ")}`);
  }

  const status = await client.callTool({
    name: "proofgate_network_status",
    arguments: {},
  });
  if (status.isError) {
    throw new Error("proofgate_network_status returned an MCP error result");
  }

  const textBlock = status.content.find((block) => block.type === "text");
  if (!textBlock || textBlock.type !== "text") {
    throw new Error("Network status did not return text content");
  }
  const body = JSON.parse(textBlock.text);
  if (body.discovery?.intent_id !== "URL_SCAN" || body.discovery?.count < 1) {
    throw new Error("Live Telegraph URL_SCAN discovery was missing or empty");
  }

  const audit = await client.callTool({
    name: "proofgate_audit_tail",
    arguments: { limit: 1 },
  });
  if (audit.isError) {
    throw new Error("proofgate_audit_tail returned an MCP error result");
  }
  const auditText = audit.content.find((block) => block.type === "text");
  if (!auditText || auditText.type !== "text") {
    throw new Error("Audit tail did not return text content");
  }
  const auditBody = JSON.parse(auditText.text);
  if (auditBody.integrity?.valid !== true) {
    throw new Error("MCP audit-tail chain verification failed");
  }

  const invalidLimit = await client.callTool({
    name: "proofgate_audit_tail",
    arguments: { limit: 0 },
  });
  if (!invalidLimit.isError) {
    throw new Error("MCP accepted an audit limit below its schema minimum");
  }

  const privateTarget = await client.callTool({
    name: "proofgate_scan",
    arguments: { url: "http://127.0.0.1" },
  });
  if (!privateTarget.isError) {
    throw new Error("MCP accepted a private scan target");
  }

  const invalidMethod = await client.callTool({
    name: "proofgate_guarded_fetch",
    arguments: { url: "https://example.com", method: "POST" },
  });
  if (!invalidMethod.isError) {
    throw new Error("MCP accepted an unsupported guarded-fetch method");
  }

  console.log(
    JSON.stringify(
      {
        protocol: "MCP stdio",
        tools: names,
        live_intent: body.discovery.intent_id,
        live_miners: body.discovery.miners.map((miner: { slug: string }) => miner.slug),
        payment_ready: body.runtime.payment_ready,
        audit_integrity: auditBody.integrity.valid,
        invalid_inputs_rejected: 3,
      },
      null,
      2,
    ),
  );
} finally {
  await client.close();
}