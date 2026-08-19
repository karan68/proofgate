import { createHash } from "node:crypto";

import { config } from "dotenv";
import {
  createPublicClient,
  createWalletClient,
  decodeEventLog,
  fallback,
  formatEther,
  formatUnits,
  http,
  parseAbi,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { baseSepolia } from "viem/chains";
import { parse } from "yaml";

config({ path: [".env.local", ".env"], quiet: true });

const DIAMOND = "0x5a2324aA18613FAD4e44bDF0d6c73Ec1f6D87ff8";
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const INTENTS = ["URL_SCAN"] as const;
const MIN_PRICE_ATOMIC = 10_000n;
const BLOCKED_REGISTRATION_ADDRESSES = new Set([
  "0xd286eba99581da0950d1bb036e4fa9306424e851",
]);

const registryAbi = parseAbi([
  "function registerMiner(string yamlUrl, bytes32 yamlHash, address feeAddress, uint256 minPriceUsdc, string[] supportedIntents) returns (uint256)",
  "function getMiner(uint256 registrationId) view returns (address miner, string yamlUrl, bytes32 yamlHash, bool active, bytes32 intentId, address feeAddress, uint256 minPriceUsdc, string[] supportedIntents)",
  "event MinerRegistered(uint256 indexed registrationId, address indexed miner, string yamlUrl, bytes32 yamlHash, address feeAddress, uint256 minPriceUsdc, string[] supportedIntents)",
]);
const usdcAbi = parseAbi([
  "function balanceOf(address account) view returns (uint256)",
]);

interface MinerDescriptor {
  base_url?: string;
  docs?: { repository?: string };
  endpoints?: Array<{ external_path?: string }>;
  semantics?: { supported_intents?: string[] };
  slug?: string;
}

function minerYamlUrl(): string {
  const explicit = process.env.PROOFGATE_MINER_YAML_URL;
  if (explicit) return new URL(explicit).toString();

  const origin = process.env.PROOFGATE_PUBLIC_URL?.replace(/\/$/, "");
  if (!origin) {
    throw new Error(
      "Set PROOFGATE_MINER_YAML_URL or PROOFGATE_PUBLIC_URL to the deployed HTTPS origin.",
    );
  }
  return new URL(`${origin}/miner.yaml`).toString();
}

function privateKey(): Hex {
  const value = process.env.TELEGRAPH_EVM_PRIVATE_KEY;
  if (!value || !/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error("TELEGRAPH_EVM_PRIVATE_KEY is missing or malformed.");
  }
  return value as Hex;
}

async function main() {
  const submit = process.argv.includes("--submit");
  const yamlUrl = minerYamlUrl();
  if (!yamlUrl.startsWith("https://")) {
    throw new Error("Miner registration requires a public HTTPS YAML URL.");
  }

  const response = await fetch(yamlUrl, {
    headers: { Accept: "application/yaml" },
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) {
    throw new Error(`Miner YAML returned HTTP ${response.status}.`);
  }
  const yamlBytes = Buffer.from(await response.arrayBuffer());
  const descriptor = parse(yamlBytes.toString("utf8")) as MinerDescriptor;
  const yamlHash = `0x${createHash("sha256").update(yamlBytes).digest("hex")}` as Hex;
  const origin = new URL(yamlUrl).origin;
  const descriptorChecks = {
    slug: descriptor.slug === "proofgate-url-intelligence",
    base_url: descriptor.base_url === origin,
    endpoint:
      descriptor.endpoints?.some(
        (endpoint) => endpoint.external_path === "/api/miner/scan",
      ) === true,
    intent:
      descriptor.semantics?.supported_intents?.includes("URL_SCAN") === true,
    repository:
      descriptor.docs?.repository === "https://github.com/karan68/proofgate",
  };
  if (!Object.values(descriptorChecks).every(Boolean)) {
    throw new Error(
      `Published Miner YAML failed checks: ${JSON.stringify(descriptorChecks)}`,
    );
  }

  const account = privateKeyToAccount(privateKey());
  const rpcUrl =
    process.env.BASE_SEPOLIA_RPC_URL ??
    "https://base-sepolia-rpc.publicnode.com";
  const publicClient = createPublicClient({
    chain: baseSepolia,
    transport: fallback([http(rpcUrl), http("https://base-sepolia.drpc.org")]),
  });
  const [ethBalance, usdcBalance] = await Promise.all([
    publicClient.getBalance({ address: account.address }),
    publicClient.readContract({
      address: USDC,
      abi: usdcAbi,
      functionName: "balanceOf",
      args: [account.address],
    }),
  ]);
  const blockedWallet = BLOCKED_REGISTRATION_ADDRESSES.has(
    account.address.toLowerCase(),
  );
  const ready =
    !blockedWallet && ethBalance > 0n && usdcBalance >= MIN_PRICE_ATOMIC;

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
        usdc: formatUnits(usdcBalance, 6),
        yaml_url: yamlUrl,
        yaml_sha256: yamlHash,
        yaml_bytes: yamlBytes.byteLength,
        descriptor_checks: descriptorChecks,
        intents: INTENTS,
        min_price_atomic: MIN_PRICE_ATOMIC.toString(),
        ready_to_register: ready,
      },
      null,
      2,
    ),
  );

  if (!submit) {
    if (!ready) process.exitCode = 2;
    return;
  }
  if (!ready) {
    throw new Error("Registration preconditions failed; no transaction was sent.");
  }

  const { request } = await publicClient.simulateContract({
    account,
    address: DIAMOND,
    abi: registryAbi,
    functionName: "registerMiner",
    args: [
      yamlUrl,
      yamlHash,
      account.address,
      MIN_PRICE_ATOMIC,
      [...INTENTS],
    ],
  });
  const walletClient = createWalletClient({
    account,
    chain: baseSepolia,
    transport: http(rpcUrl),
  });
  const transactionHash = await walletClient.writeContract(request);
  const receipt = await publicClient.waitForTransactionReceipt({
    hash: transactionHash,
    confirmations: 1,
    timeout: 120_000,
  });
  let registrationId: bigint | null = null;
  for (const log of receipt.logs) {
    try {
      const event = decodeEventLog({ abi: registryAbi, ...log });
      if (event.eventName === "MinerRegistered") {
        registrationId = event.args.registrationId;
        break;
      }
    } catch {
      // Ignore logs from other contracts in the transaction.
    }
  }
  if (registrationId === null) {
    throw new Error("Registration transaction did not emit MinerRegistered.");
  }

  const record = await publicClient.readContract({
    address: DIAMOND,
    abi: registryAbi,
    functionName: "getMiner",
    args: [registrationId],
  });
  console.log(
    JSON.stringify(
      {
        registered: true,
        registration_id: registrationId.toString(),
        transaction_hash: transactionHash,
        explorer: `https://sepolia.basescan.org/tx/${transactionHash}`,
        on_chain: {
          miner: record[0],
          yaml_url: record[1],
          yaml_hash: record[2],
          active: record[3],
          fee_address: record[5],
          min_price_atomic: record[6].toString(),
          intents: record[7],
        },
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
