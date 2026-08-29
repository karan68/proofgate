import { readFile } from "node:fs/promises";

import { config } from "dotenv";
import {
  createPublicClient,
  createWalletClient,
  decodeEventLog,
  fallback,
  formatEther,
  http,
  keccak256,
  parseAbi,
  toHex,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { baseSepolia } from "viem/chains";

config({ path: [".env.local", ".env"], quiet: true });

const DIAMOND = "0x5a2324aA18613FAD4e44bDF0d6c73Ec1f6D87ff8";
const INTENT = "URL_SCAN";
const LOCAL_ARTIFACT = "public/wasm/proofgate-url-scorer.wasm";
const MAX_BYTES = 32 * 1024 * 1024;
const BLOCKED_REGISTRATION_ADDRESSES = new Set([
  "0xd286eba99581da0950d1bb036e4fa9306424e851",
]);

const registryAbi = parseAbi([
  "function registerWasm(bytes32 wasmHash, string wasmUrl, string intent) returns (uint256 registrationId)",
  "function getCanonicalIntents() view returns (string[])",
  "event IntentRegistered(uint256 indexed registrationId, address indexed registrant, uint8 entityType, bytes32 intentId, string contentUrl, bytes32 contentHash)",
]);

function privateKey(): Hex {
  const value = process.env.TELEGRAPH_EVM_PRIVATE_KEY;
  if (!value || !/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error("TELEGRAPH_EVM_PRIVATE_KEY is missing or malformed.");
  }
  return value as Hex;
}

function wasmUrl(): string {
  const value = process.env.PROOFGATE_WASM_URL;
  if (!value) {
    throw new Error(
      "Set PROOFGATE_WASM_URL to the immutable raw GitHub URL for the committed artifact.",
    );
  }
  const parsed = new URL(value);
  if (parsed.protocol !== "https:") {
    throw new Error("WASM registration requires a public HTTPS artifact URL.");
  }
  if (parsed.hostname !== "raw.githubusercontent.com") {
    throw new Error("Use a commit-pinned raw.githubusercontent.com artifact URL.");
  }
  if (!/^\/[\w.-]+\/[\w.-]+\/[0-9a-f]{40}\//i.test(parsed.pathname)) {
    throw new Error("WASM artifact URL must contain a full 40-character commit SHA.");
  }
  return parsed.toString();
}

async function main() {
  const submit = process.argv.includes("--submit");
  const artifactUrl = wasmUrl();
  const [localBytes, response] = await Promise.all([
    readFile(LOCAL_ARTIFACT),
    fetch(artifactUrl, {
      headers: { Accept: "application/wasm" },
      signal: AbortSignal.timeout(20_000),
    }),
  ]);
  if (!response.ok) {
    throw new Error(`Committed WASM artifact returned HTTP ${response.status}.`);
  }
  const remoteBytes = Buffer.from(await response.arrayBuffer());
  if (!localBytes.equals(remoteBytes)) {
    throw new Error("Committed WASM bytes differ from the local artifact.");
  }
  if (remoteBytes.byteLength > MAX_BYTES) {
    throw new Error(`WASM artifact exceeds 32 MiB: ${remoteBytes.byteLength} bytes.`);
  }

  const wasmModule = await WebAssembly.compile(remoteBytes);
  const imports = WebAssembly.Module.imports(wasmModule);
  const exports = new Set(
    WebAssembly.Module.exports(wasmModule).map((item) => item.name),
  );
  const requiredExports = ["memory", "alloc", "dealloc", "rank_answer"];
  const exportChecks = Object.fromEntries(
    requiredExports.map((name) => [name, exports.has(name)]),
  );
  const wasmHash = keccak256(toHex(remoteBytes));

  const account = privateKeyToAccount(privateKey());
  const rpcUrl =
    process.env.BASE_SEPOLIA_RPC_URL ??
    "https://base-sepolia-rpc.publicnode.com";
  const publicClient = createPublicClient({
    chain: baseSepolia,
    transport: fallback([http(rpcUrl), http("https://base-sepolia.drpc.org")]),
  });
  const [ethBalance, canonicalIntents] = await Promise.all([
    publicClient.getBalance({ address: account.address }),
    publicClient.readContract({
      address: DIAMOND,
      abi: registryAbi,
      functionName: "getCanonicalIntents",
    }),
  ]);
  const blockedWallet = BLOCKED_REGISTRATION_ADDRESSES.has(
    account.address.toLowerCase(),
  );
  const ready =
    !blockedWallet &&
    ethBalance > 0n &&
    imports.length === 0 &&
    Object.values(exportChecks).every(Boolean) &&
    canonicalIntents.includes(INTENT);

  const simulation = ready
    ? await publicClient.simulateContract({
        account,
        address: DIAMOND,
        abi: registryAbi,
        functionName: "registerWasm",
        args: [wasmHash, artifactUrl, INTENT],
      })
    : null;

  console.log(
    JSON.stringify(
      {
        mode: submit ? "submit" : "check",
        chain: "Base Sepolia",
        chain_id: baseSepolia.id,
        diamond: DIAMOND,
        wallet: account.address,
        blocked_wallet: blockedWallet,
        eth: formatEther(ethBalance),
        intent: INTENT,
        canonical_intent: canonicalIntents.includes(INTENT),
        artifact_url: artifactUrl,
        artifact_bytes: remoteBytes.byteLength,
        artifact_keccak256: wasmHash,
        zero_imports: imports.length === 0,
        required_exports: exportChecks,
        simulated_registration_id:
          simulation?.result?.toString() ?? null,
        ready_to_register: ready && simulation !== null,
      },
      null,
      2,
    ),
  );

  if (!submit) {
    if (!ready || simulation === null) process.exitCode = 2;
    return;
  }
  if (!ready || simulation === null) {
    throw new Error("WASM registration preconditions failed; no transaction was sent.");
  }

  const walletClient = createWalletClient({
    account,
    chain: baseSepolia,
    transport: http(rpcUrl),
  });
  const transactionHash = await walletClient.writeContract(simulation.request);
  const receipt = await publicClient.waitForTransactionReceipt({
    hash: transactionHash,
    confirmations: 1,
    timeout: 120_000,
  });
  let registrationId: bigint | null = null;
  for (const log of receipt.logs) {
    try {
      const event = decodeEventLog({ abi: registryAbi, ...log });
      if (
        event.eventName === "IntentRegistered" &&
        event.args.entityType === 2
      ) {
        registrationId = event.args.registrationId;
        break;
      }
    } catch {
      // Ignore unrelated Diamond and token logs.
    }
  }
  if (registrationId === null) {
    throw new Error("Registration transaction did not emit a WASM IntentRegistered event.");
  }

  console.log(
    JSON.stringify(
      {
        registered: true,
        registration_id: registrationId.toString(),
        transaction_hash: transactionHash,
        explorer: `https://sepolia.basescan.org/tx/${transactionHash}`,
        intent: INTENT,
        artifact_url: artifactUrl,
        artifact_keccak256: wasmHash,
      },
      null,
      2,
    ),
  );
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});