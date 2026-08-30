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
const DEFAULT_REGISTRATION_ID = 384n;
const BLOCKED_REGISTRATION_ADDRESSES = new Set([
  "0xd286eba99581da0950d1bb036e4fa9306424e851",
]);

const registryAbi = parseAbi([
  "function registerMiner(string yamlUrl, bytes32 yamlHash, address feeAddress, uint256 minPriceUsdc, string[] supportedIntents) returns (uint256)",
  "function updateMiner(uint256 registrationId, string yamlUrl, bytes32 yamlHash, address feeAddress, uint256 minPriceUsdc, string[] supportedIntents)",
  "function getMiner(uint256 registrationId) view returns (address miner, string yamlUrl, bytes32 yamlHash, bool active, bytes32 intentId, address feeAddress, uint256 minPriceUsdc, string[] supportedIntents)",
  "event MinerRegistered(uint256 indexed registrationId, address indexed miner, string yamlUrl, bytes32 yamlHash, address feeAddress, uint256 minPriceUsdc, string[] supportedIntents)",
]);
const usdcAbi = parseAbi([
  "function balanceOf(address account) view returns (uint256)",
]);

interface MinerDescriptor {
  base_url?: string;
  docs?: { repository?: string };
  endpoints?: Array<{
    external_path?: string;
    intents?: string[];
    params?: { body?: { required?: Array<{ name?: string; intents?: string[] }> } };
  }>;
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
  const update = process.argv.includes("--update");
  const registrationId = BigInt(
    process.env.PROOFGATE_MINER_REGISTRATION_ID ?? DEFAULT_REGISTRATION_ID,
  );
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
        (endpoint) =>
          endpoint.external_path === "/api/miner/scan" &&
          endpoint.intents?.includes("URL_SCAN") === true &&
          endpoint.params?.body?.required?.some(
            (parameter) =>
              parameter.name === "url" && parameter.intents?.includes("URL_SCAN") === true,
          ) === true,
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
  const [ethBalance, usdcBalance, currentRecord] = await Promise.all([
    publicClient.getBalance({ address: account.address }),
    publicClient.readContract({
      address: USDC,
      abi: usdcAbi,
      functionName: "balanceOf",
      args: [account.address],
    }),
    update
      ? publicClient.readContract({
          address: DIAMOND,
          abi: registryAbi,
          functionName: "getMiner",
          args: [registrationId],
        })
      : Promise.resolve(null),
  ]);
  const blockedWallet = BLOCKED_REGISTRATION_ADDRESSES.has(
    account.address.toLowerCase(),
  );
  const currentRecordValid =
    !update ||
    (currentRecord !== null &&
      currentRecord[0].toLowerCase() === account.address.toLowerCase() &&
      currentRecord[1] === yamlUrl &&
      currentRecord[3] === true &&
      currentRecord[5].toLowerCase() === account.address.toLowerCase() &&
      currentRecord[6] === MIN_PRICE_ATOMIC &&
      currentRecord[7].length === INTENTS.length &&
      INTENTS.every((intent) => currentRecord[7].includes(intent)));
  const ready =
    !blockedWallet &&
    ethBalance > 0n &&
    usdcBalance >= MIN_PRICE_ATOMIC &&
    currentRecordValid &&
    (!update || currentRecord?.[2].toLowerCase() !== yamlHash.toLowerCase());

  const simulation = ready
    ? await publicClient.simulateContract({
        account,
        address: DIAMOND,
        abi: registryAbi,
        functionName: update ? "updateMiner" : "registerMiner",
        args: update
          ? [
              registrationId,
              yamlUrl,
              yamlHash,
              account.address,
              MIN_PRICE_ATOMIC,
              [...INTENTS],
            ]
          : [yamlUrl, yamlHash, account.address, MIN_PRICE_ATOMIC, [...INTENTS]],
      })
    : null;

  console.log(
    JSON.stringify(
      {
        mode: `${update ? "update" : "register"}-${submit ? "submit" : "check"}`,
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
        registration_id: update ? registrationId.toString() : null,
        current_record_valid: currentRecordValid,
        current_yaml_sha256: currentRecord?.[2] ?? null,
        simulation_ready: simulation !== null,
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
    throw new Error("Registration preconditions failed; no transaction was sent.");
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
  let emittedRegistrationId: bigint | null = null;
  for (const log of receipt.logs) {
    try {
      const event = decodeEventLog({ abi: registryAbi, ...log });
      if (event.eventName === "MinerRegistered") {
        emittedRegistrationId = event.args.registrationId;
        break;
      }
    } catch {
      // Ignore logs from other contracts in the transaction.
    }
  }
  if (emittedRegistrationId === null) {
    throw new Error("Registration transaction did not emit MinerRegistered.");
  }

  const record = await publicClient.readContract({
    address: DIAMOND,
    abi: registryAbi,
    functionName: "getMiner",
    args: [emittedRegistrationId],
  });
  console.log(
    JSON.stringify(
      {
        registered: true,
        registration_id: emittedRegistrationId.toString(),
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
