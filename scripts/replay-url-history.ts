import { createHash } from "node:crypto";

import { answerHistoricalUrlQuestion } from "../src/lib/proofgate/miner";

const CORPUS_COMMIT = "e9cf33d5aaa24ba5c620b12dc076abc29de53ac0";
const CORPUS_URL =
  `https://raw.githubusercontent.com/shreshth006/Preflight/${CORPUS_COMMIT}` +
  "/fixtures/live/scored-receipts.json";
const CHAMPION_URL =
  "https://raw.githubusercontent.com/zkasuran/telegraph-salience-scorer/" +
  "0174a85639c398a0e898dcb11b54367eb2723b2b/dist/xfmr/url_c3.wasm";
const CHAMPION_DECLARED_HASH =
  "71581b142ca88090e795ffaaa95442e7403c49018f94e7c0b41ce938cef97c6a";
const CHAMPION_BINARY_SHA256 =
  "ee85db4661b262a6133f71f0b8f228e663d213cefdaf73c43c293c082bb00d0b";
const OLD_PROOFGATE_ANSWER =
  "safe with limited confidence: public DNS and URL policy checks passed, but no reputation provider returned a clean verdict.";

interface Receipt {
  intent: string;
  question: string;
  ground_truth: string;
  converted_answer?: string;
  score?: number;
}

interface Scorer {
  score(question: string, groundTruth: string, answer: string): number;
}

async function checkedFetch(url: string): Promise<Response> {
  const response = await fetch(url, { signal: AbortSignal.timeout(20_000) });
  if (!response.ok) throw new Error(`GET ${url} returned HTTP ${response.status}`);
  return response;
}

async function loadChampion(): Promise<Scorer> {
  const bytes = new Uint8Array(await (await checkedFetch(CHAMPION_URL)).arrayBuffer());
  const digest = createHash("sha256").update(bytes).digest("hex");
  if (digest !== CHAMPION_BINARY_SHA256) {
    throw new Error(`champion binary digest mismatch: expected ${CHAMPION_BINARY_SHA256}, received ${digest}`);
  }

  const wasmModule = await WebAssembly.compile(bytes);
  if (WebAssembly.Module.imports(wasmModule).length > 0) {
    throw new Error("champion scorer unexpectedly requires imports");
  }
  const { exports } = await WebAssembly.instantiate(wasmModule, {});
  const memory = exports.memory as WebAssembly.Memory;
  const alloc = exports.alloc as (length: number) => number;
  const rankAnswer = exports.rank_answer as (...arguments_: number[]) => number;
  if (!memory || !alloc || !rankAnswer) throw new Error("champion scorer ABI is incomplete");

  const encoder = new TextEncoder();
  function write(value: string): [number, number] {
    const encoded = encoder.encode(value);
    if (encoded.length === 0) return [0, 0];
    const pointer = alloc(encoded.length);
    new Uint8Array(memory.buffer, pointer, encoded.length).set(encoded);
    return [pointer, encoded.length];
  }

  return {
    score(question, groundTruth, answer) {
      const score = rankAnswer(...write(question), ...write(groundTruth), ...write(answer));
      if (!Number.isFinite(score) || score < 0 || score > 1) {
        throw new Error(`champion returned invalid score ${score}`);
      }
      return score;
    },
  };
}

function average(values: number[]): number {
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function ranks(values: number[]): number[] {
  const sorted = [...values].map((value, index) => ({ value, index })).sort((a, b) => a.value - b.value);
  const result = new Array<number>(values.length);
  for (let start = 0; start < sorted.length; ) {
    let end = start + 1;
    while (end < sorted.length && sorted[end].value === sorted[start].value) end += 1;
    const rank = (start + end - 1) / 2;
    for (let index = start; index < end; index += 1) result[sorted[index].index] = rank;
    start = end;
  }
  return result;
}

function spearman(left: number[], right: number[]): number {
  if (left.length !== right.length || left.length < 2) return 0;
  const leftRanks = ranks(left);
  const rightRanks = ranks(right);
  const leftMean = average(leftRanks);
  const rightMean = average(rightRanks);
  let numerator = 0;
  let leftSquare = 0;
  let rightSquare = 0;
  for (let index = 0; index < left.length; index += 1) {
    const leftDelta = leftRanks[index] - leftMean;
    const rightDelta = rightRanks[index] - rightMean;
    numerator += leftDelta * rightDelta;
    leftSquare += leftDelta ** 2;
    rightSquare += rightDelta ** 2;
  }
  return leftSquare && rightSquare ? numerator / Math.sqrt(leftSquare * rightSquare) : 0;
}

const [scorer, corpus] = await Promise.all([
  loadChampion(),
  checkedFetch(CORPUS_URL).then((response) => response.json() as Promise<Receipt[]>),
]);
const receipts = corpus.filter(
  (receipt) =>
    receipt.intent === "URL_SCAN" &&
    typeof receipt.question === "string" &&
    typeof receipt.ground_truth === "string",
);
if (receipts.length !== 180) throw new Error(`expected 180 URL_SCAN receipts, received ${receipts.length}`);

const replayable = receipts.filter(
  (receipt) => typeof receipt.converted_answer === "string" && typeof receipt.score === "number",
);
const predicted = replayable.map((receipt) =>
  scorer.score(receipt.question, receipt.ground_truth, receipt.converted_answer as string),
);
const recorded = replayable.map((receipt) => receipt.score as number);
const fidelity = spearman(predicted, recorded);

const pairs = new Map<string, Receipt[]>();
for (const receipt of receipts) {
  const key = JSON.stringify([receipt.question, receipt.ground_truth]);
  const group = pairs.get(key) ?? [];
  group.push(receipt);
  pairs.set(key, group);
}
if (pairs.size !== 10) throw new Error(`expected 10 unique URL_SCAN pairs, received ${pairs.size}`);

const rows = [...pairs.values()].map((group) => {
  const { question, ground_truth: groundTruth } = group[0];
  const candidateAnswer = answerHistoricalUrlQuestion(question).answer;
  const candidate = scorer.score(question, groundTruth, candidateAnswer);
  const baseline = scorer.score(question, groundTruth, OLD_PROOFGATE_ANSWER);
  const field = Math.max(...group.map((receipt) => receipt.score ?? 0));
  return { question, candidate, baseline, field };
});

for (const row of rows) {
  console.log(
    `${row.candidate.toFixed(6)} baseline=${row.baseline.toFixed(6)} field=${row.field.toFixed(6)} ${row.question}`,
  );
}
const candidateMean = average(rows.map((row) => row.candidate));
const baselineMean = average(rows.map((row) => row.baseline));
const fieldMean = average(rows.map((row) => row.field));
const wins = rows.filter((row) => row.candidate > row.field).length;
const losses = rows.filter((row) => row.candidate < row.field).length;

console.log(`\nChampion API-declared hash: ${CHAMPION_DECLARED_HASH}`);
console.log(`Champion binary SHA-256: ${CHAMPION_BINARY_SHA256}`);
console.log(`Corpus commit: ${CORPUS_COMMIT}`);
console.log(
  `Replay fidelity across epochs 260-290: n=${replayable.length} Spearman=${fidelity.toFixed(6)} (${fidelity >= 0.9 ? "faithful" : fidelity >= 0.85 ? "usable, not exact" : "weak"})`,
);
console.log(`Candidate mean=${candidateMean.toFixed(6)} minimum=${Math.min(...rows.map((row) => row.candidate)).toFixed(6)}`);
console.log(`Old fallback mean=${baselineMean.toFixed(6)}`);
console.log(`Best recorded field mean=${fieldMean.toFixed(6)}`);
console.log(`Candidate vs best recorded field: ${wins} wins, ${rows.length - wins - losses} ties, ${losses} losses`);

if (
  fidelity < 0.85 ||
  candidateMean <= baselineMean ||
  candidateMean <= fieldMean ||
  Math.min(...rows.map((row) => row.candidate)) < 0.5 ||
  wins !== rows.length
) {
  process.exitCode = 1;
}