/**
 * Evaluates ProofGate's real answers against the public archive of scored
 * Telegraph URL_SCAN receipts, using the live champion scoring module.
 *
 *   npx tsx scripts/evaluate-url-corpus.ts
 *   npx tsx scripts/evaluate-url-corpus.ts --show-worst 15
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";

import { answerHistoricalUrlQuestion, scanUrlWithEvidence } from "../src/lib/proofgate/miner";

const CORPUS_URL =
  "https://raw.githubusercontent.com/shreshth006/Preflight/e9cf33d5aaa24ba5c620b12dc076abc29de53ac0/fixtures/live/scored-receipts.json";
const CHAMPION_URL =
  "https://raw.githubusercontent.com/zkasuran/telegraph-salience-scorer/0174a85639c398a0e898dcb11b54367eb2723b2b/dist/xfmr/url_c3.wasm";
const CACHE = "tmp-champion/url_c3.wasm";

interface Receipt {
  intent: string;
  question: string;
  ground_truth: string;
  converted_answer?: string;
  score?: number;
  miner?: string;
}

async function championScorer() {
  if (!existsSync(CACHE)) {
    await mkdir("tmp-champion", { recursive: true });
    const response = await fetch(CHAMPION_URL);
    if (!response.ok) throw new Error(`GET champion wasm returned ${response.status}`);
    await writeFile(CACHE, Buffer.from(await response.arrayBuffer()));
  }
  const wasmModule = await WebAssembly.compile(new Uint8Array(await readFile(CACHE)));
  const { exports } = (await WebAssembly.instantiate(wasmModule, {})) as {
    exports: {
      memory: WebAssembly.Memory;
      alloc(size: number): number;
      rank_answer(...args: number[]): number;
    };
  };
  const encoder = new TextEncoder();
  const write = (value: string): [number, number] => {
    const encoded = encoder.encode(value);
    if (encoded.length === 0) return [0, 0];
    const pointer = exports.alloc(encoded.length);
    new Uint8Array(exports.memory.buffer, pointer, encoded.length).set(encoded);
    return [pointer, encoded.length];
  };
  return (question: string, groundTruth: string, minerAnswer: string) =>
    exports.rank_answer(...write(question), ...write(groundTruth), ...write(minerAnswer));
}

function urlIn(text: string): string | null {
  const match = text.match(/https?:\/\/[^\s<>"'`]+/i);
  return match ? match[0].replace(/[.,;:!?)\]]+$/, "") : null;
}

const offlineScan = (url: string, question: string) =>
  scanUrlWithEvidence(url, {
    question,
    now: new Date("2026-08-31T00:00:00.000Z"),
    lookup: async () => ["93.184.216.34"],
    reachabilityProbe: async () => ({
      source: "reachability",
      status: "not_queried",
      detail: "The reachability probe was disabled for this run.",
    }),
    fetcher: (async (input: RequestInfo | URL) => {
      if (String(input).startsWith("https://rdap.org/")) {
        return Response.json({
          events: [{ eventAction: "registration", eventDate: "2005-01-01T00:00:00Z" }],
        });
      }
      throw new Error(`Unexpected request ${String(input)}`);
    }) as typeof fetch,
  });

const response = await fetch(CORPUS_URL);
if (!response.ok) throw new Error(`GET corpus returned ${response.status}`);
const raw = (await response.json()) as Receipt[] | { receipts: Receipt[] };
const receipts = (Array.isArray(raw) ? raw : raw.receipts).filter(
  (receipt) => receipt.intent === "URL_SCAN" && receipt.question && receipt.ground_truth,
);

const seen = new Map<string, Receipt>();
for (const receipt of receipts) seen.set(`${receipt.question}\u0000${receipt.ground_truth}`, receipt);
const unique = [...seen.values()];

const score = await championScorer();
const rows: {
  question: string;
  ground_truth: string;
  answer: string;
  score: number;
  matched: boolean;
  result: unknown;
}[] = [];

for (const receipt of unique) {
  const url = urlIn(receipt.question);
  let result;
  try {
    result = url
      ? await offlineScan(url, receipt.question)
      : answerHistoricalUrlQuestion(receipt.question, new Date("2026-08-31T00:00:00.000Z"));
  } catch {
    result = answerHistoricalUrlQuestion(receipt.question, new Date("2026-08-31T00:00:00.000Z"));
  }
  rows.push({
    question: receipt.question,
    ground_truth: receipt.ground_truth,
    answer: result.answer,
    score: score(receipt.question, receipt.ground_truth, JSON.stringify(result)),
    matched: result.historical_context !== null,
    result,
  });
}

const values = rows.map((row) => row.score).sort((a, b) => a - b);
const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
const median = values[Math.floor(values.length / 2)];
const zeros = values.filter((value) => value === 0).length;
const strong = values.filter((value) => value >= 0.9).length;

console.log(`unique URL_SCAN receipts : ${unique.length}`);
console.log(`catalogue matches        : ${rows.filter((row) => row.matched).length}`);
console.log(`mean score               : ${mean.toFixed(6)}`);
console.log(`median score             : ${median.toFixed(6)}`);
console.log(`hard zeros               : ${zeros}`);
console.log(`>= 0.9                   : ${strong} of ${rows.length}`);

const showWorst = process.argv.indexOf("--show-worst");
const limit = showWorst === -1 ? 10 : Number(process.argv[showWorst + 1] ?? 10);
const worst = [...rows].sort((a, b) => a.score - b.score).slice(0, limit);
console.log(`\nweakest ${limit}:`);
for (const row of worst) {
  console.log(`  ${row.score.toFixed(6)}  ${row.matched ? "matched " : "no-match"}  ${row.question.slice(0, 120)}`);
}

if (process.argv.includes("--detail")) {
  for (const row of worst) {
    console.log(`\n=== ${row.score.toFixed(6)} ${row.question}`);
    console.log(`GROUND TRUTH: ${row.ground_truth}`);
    console.log(`OUR ANSWER  : ${row.answer}`);
    console.log(`ANSWER ONLY SCORE: ${score(row.question, row.ground_truth, row.answer).toFixed(6)}`);
    const record = row.result as unknown as Record<string, unknown>;
    for (const key of Object.keys(record)) {
      if (key === "answer") continue;
      const clone = { ...record };
      delete clone[key];
      console.log(
        `   ${score(row.question, row.ground_truth, JSON.stringify(clone)).toFixed(6)}  without "${key}"`,
      );
    }
    let accumulated: Record<string, unknown> = { answer: record.answer };
    console.log("   cumulative:");
    for (const key of Object.keys(record)) {
      if (key === "answer") continue;
      accumulated = { ...accumulated, [key]: record[key] };
      console.log(
        `   ${score(row.question, row.ground_truth, JSON.stringify(accumulated)).toFixed(6)}  after adding "${key}"`,
      );
    }
  }
}
