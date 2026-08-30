import { createHash } from "node:crypto";

import { privateKeyToAccount } from "viem/accounts";
import type { Hex } from "viem";

const PORTAL_API = "https://submissions.telegraphprotocol.com/api/api";
const NODE_API = "https://devnode.telegraphprotocol.com/api";
const PUBLIC_YAML = "https://proofgate-six.vercel.app/miner.yaml";
const SUBMISSION_ID = "6a930a4aae9ddfbc70a760d9";
const PREVIOUS_ITEM_ID = "384";
const ITEM_ID = "386";
const EXPECTED_YAML_SHA256 = "a7783891544380f745c860cf704d25b8ee9c8b935b9cb90cea62964a368be5a1";
const TWITTER_USERNAME = "karanyadav38450";

interface Challenge {
  message: string;
  nonce: string;
  issuedAt: string;
}

interface SubmissionItem {
  id: string;
  verified: boolean;
}

interface Submission {
  _id: string;
  track: string;
  walletAddress: string;
  items: SubmissionItem[];
  status: string;
  twitterUsername: string;
}

async function checkedFetch(url: string, init?: RequestInit): Promise<Response> {
  const response = await fetch(url, { ...init, signal: AbortSignal.timeout(20_000) });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`${init?.method ?? "GET"} ${url} returned HTTP ${response.status}: ${detail.slice(0, 500)}`);
  }
  return response;
}

function privateKey(): Hex {
  const value = process.env.TELEGRAPH_EVM_PRIVATE_KEY;
  if (!value || !/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error("TELEGRAPH_EVM_PRIVATE_KEY is missing or malformed.");
  }
  return value as Hex;
}

const account = privateKeyToAccount(privateKey());
const address = account.address;
const [nodeResponse, yamlResponse, submissionsResponse] = await Promise.all([
  checkedFetch(`${NODE_API}/miners/${ITEM_ID}`),
  checkedFetch(PUBLIC_YAML),
  checkedFetch(`${PORTAL_API}/submissions/mine/${address}?track=miner`),
]);
const node = (await nodeResponse.json()) as {
  miner?: { activation_status?: string; rejection_reason?: string | null; yaml_hash?: string };
};
if (
  node.miner?.activation_status !== "active" ||
  node.miner?.rejection_reason !== null ||
  node.miner?.yaml_hash !== EXPECTED_YAML_SHA256
) {
  throw new Error(`registration ${ITEM_ID} is not active with the expected YAML hash`);
}

const yamlBytes = new Uint8Array(await yamlResponse.arrayBuffer());
const yamlDigest = createHash("sha256").update(yamlBytes).digest("hex");
if (yamlDigest !== EXPECTED_YAML_SHA256) {
  throw new Error(`published YAML digest mismatch: expected ${EXPECTED_YAML_SHA256}, received ${yamlDigest}`);
}

const submissions = ((await submissionsResponse.json()) as { submissions?: Submission[] }).submissions ?? [];
const current = submissions.find((submission) => submission._id === SUBMISSION_ID);
if (
  !current ||
  current.track !== "miner" ||
  current.walletAddress.toLowerCase() !== address.toLowerCase() ||
  current.status !== "verified" ||
  current.twitterUsername !== TWITTER_USERNAME ||
  current.items.length !== 1 ||
  current.items[0].id !== PREVIOUS_ITEM_ID ||
  current.items[0].verified !== true
) {
  throw new Error("existing portal submission does not match the expected verified item");
}

const challenge = (await (
  await checkedFetch(`${PORTAL_API}/challenge`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      address,
      track: "miner",
      items: [ITEM_ID],
      action: "edit",
      submissionId: SUBMISSION_ID,
    }),
  })
).json()) as Challenge;
const signature = await account.signMessage({ message: challenge.message });
const form = new FormData();
form.append("address", address);
form.append("signature", signature);
form.append("nonce", challenge.nonce);
form.append("issuedAt", challenge.issuedAt);
form.append("itemIds", JSON.stringify([ITEM_ID]));
form.append("twitterUsername", TWITTER_USERNAME);
form.append("files", new Blob([yamlBytes], { type: "application/yaml" }), "proofgate-miner.yaml");

const update = (await (
  await checkedFetch(`${PORTAL_API}/submissions/miner/${SUBMISSION_ID}`, {
    method: "PUT",
    body: form,
  })
).json()) as { saved?: boolean; status?: string };
const verifiedSubmissions = ((await (
  await checkedFetch(`${PORTAL_API}/submissions/mine/${address}?track=miner`)
).json()) as { submissions?: Submission[] }).submissions ?? [];
const verified = verifiedSubmissions.find((submission) => submission._id === SUBMISSION_ID);
if (
  update.saved !== true ||
  update.status !== "verified" ||
  verified?.status !== "verified" ||
  verified.items.length !== 1 ||
  verified.items[0].id !== ITEM_ID ||
  verified.items[0].verified !== true
) {
  throw new Error("portal did not persist a verified replacement item");
}

console.log(
  JSON.stringify(
    {
      saved: update.saved,
      status: verified.status,
      submission_id: verified._id,
      item_id: verified.items[0].id,
      item_verified: verified.items[0].verified,
      wallet: address,
      yaml_sha256: yamlDigest,
    },
    null,
    2,
  ),
);