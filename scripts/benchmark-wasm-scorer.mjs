import { readFile } from "node:fs/promises";

const FIXTURE_ROOT =
  "https://raw.githubusercontent.com/zkasuran/telegraph-salience-scorer/0174a85639c398a0e898dcb11b54367eb2723b2b";
const CHAMPION_URL = `${FIXTURE_ROOT}/dist/xfmr/url_c3.wasm`;
const VERDICTLOCK_ROOT =
  "https://raw.githubusercontent.com/sneg55/verdictlock/9f06db38f09bdeba8d85f14973db9eeffd414d05";
const DEFAULT_CANDIDATE =
  "wasm-scorer/target/wasm32-unknown-unknown/release/proofgate_url_scorer.wasm";

async function bytesFrom(source) {
  if (/^https?:\/\//.test(source)) {
    const response = await fetch(source);
    if (!response.ok) {
      throw new Error(`GET ${source} returned ${response.status}`);
    }
    return new Uint8Array(await response.arrayBuffer());
  }
  return new Uint8Array(await readFile(source));
}

async function jsonFrom(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`GET ${url} returned ${response.status}`);
  }
  return response.json();
}

async function loadScorer(source) {
  const bytes = await bytesFrom(source);
  const wasmModule = await WebAssembly.compile(bytes);
  const imports = WebAssembly.Module.imports(wasmModule);
  if (imports.length > 0) {
    throw new Error(`${source} has ${imports.length} imports`);
  }
  const { exports } = await WebAssembly.instantiate(wasmModule, {});
  for (const name of ["memory", "alloc", "dealloc", "rank_answer"]) {
    if (!(name in exports)) {
      throw new Error(`${source} does not export ${name}`);
    }
  }

  const encoder = new TextEncoder();
  function write(value) {
    const encoded = encoder.encode(value);
    if (encoded.length === 0) {
      return [0, 0];
    }
    const pointer = exports.alloc(encoded.length);
    new Uint8Array(exports.memory.buffer, pointer, encoded.length).set(encoded);
    return [pointer, encoded.length];
  }

  return {
    bytes: bytes.length,
    score(question, groundTruth, minerAnswer) {
      const result = exports.rank_answer(
        ...write(question),
        ...write(groundTruth),
        ...write(minerAnswer),
      );
      if (!Number.isFinite(result) || result < 0 || result > 1) {
        throw new Error(`${source} returned invalid score ${result}`);
      }
      return result;
    },
  };
}

function summarize(name, scorer, cases) {
  const rows = cases.map((testCase) => {
    const self = scorer.score(
      testCase.question,
      testCase.ground_truth,
      testCase.ground_truth,
    );
    const good = scorer.score(
      testCase.question,
      testCase.ground_truth,
      testCase.good,
    );
    const bad = scorer.score(
      testCase.question,
      testCase.ground_truth,
      testCase.bad,
    );
    return { id: testCase.id, intent: testCase.intent, self, good, bad };
  });
  const meanMargin =
    rows.reduce((sum, row) => sum + row.good - row.bad, 0) / rows.length;
  const wins = rows.filter((row) => row.good > row.bad).length;
  const worstSelf = Math.min(...rows.map((row) => row.self));
  return { name, bytes: scorer.bytes, meanMargin, wins, worstSelf, rows };
}

function printSummary(summary) {
  console.log(
    `${summary.name}: bytes=${summary.bytes} margin=${summary.meanMargin.toFixed(4)} wins=${summary.wins}/${summary.rows.length} worst_self=${summary.worstSelf.toFixed(4)}`,
  );
  const losses = summary.rows.filter((row) => row.good <= row.bad);
  for (const row of losses) {
    console.log(
      `  LOSS ${row.id}: good=${row.good.toFixed(4)} bad=${row.bad.toFixed(4)}`,
    );
  }
}

function attackResults(name, scorer, cases) {
  return {
    name,
    rows: cases.map((testCase) => {
      const honest = scorer.score(
        testCase.question,
        testCase.ground_truth,
        testCase.honest,
      );
      const attack = scorer.score(
        testCase.question,
        testCase.ground_truth,
        testCase.attack,
      );
      const passed =
        testCase.rule === "near_zero"
          ? attack <= 0.2
          : testCase.rule === "near_honest"
            ? attack >= honest - 0.2
            : attack < honest;
      return { test: testCase.name, rule: testCase.rule, honest, attack, passed };
    }),
  };
}

const candidatePath = process.argv[2] ?? DEFAULT_CANDIDATE;
const [
  candidate,
  champion,
  benchmark,
  attacks,
  urlScanBenchmark,
  gateStressBenchmark,
  urlScanAttacks,
] = await Promise.all([
  loadScorer(candidatePath),
  loadScorer(CHAMPION_URL),
  jsonFrom(`${FIXTURE_ROOT}/bench/benchmark.json`),
  jsonFrom(`${FIXTURE_ROOT}/bench/attacks.json`),
  jsonFrom(`${VERDICTLOCK_ROOT}/bench/url-scan.json`),
  jsonFrom(`${VERDICTLOCK_ROOT}/bench/gate-stress.json`),
  jsonFrom(`${VERDICTLOCK_ROOT}/bench/attacks.json`),
]);

const relevantCases = benchmark.cases.filter(
  (testCase) => testCase.intent === "URL_SCAN",
);
const summaries = [
  summarize("candidate/all", candidate, benchmark.cases),
  summarize("champion/all", champion, benchmark.cases),
  summarize("candidate/url_scan", candidate, relevantCases),
  summarize("champion/url_scan", champion, relevantCases),
  summarize("candidate/verdictlock_url", candidate, urlScanBenchmark.cases),
  summarize("champion/verdictlock_url", champion, urlScanBenchmark.cases),
  summarize("candidate/gate_stress", candidate, gateStressBenchmark.cases),
  summarize("champion/gate_stress", champion, gateStressBenchmark.cases),
];
const attackSuites = [
  attackResults("candidate", candidate, attacks.cases),
  attackResults("champion", champion, attacks.cases),
  attackResults("candidate/url", candidate, urlScanAttacks.cases),
  attackResults("champion/url", champion, urlScanAttacks.cases),
];

for (const summary of summaries) {
  printSummary(summary);
}

for (const suite of attackSuites) {
  const failed = suite.rows.filter((row) => !row.passed);
  console.log(
    `${suite.name}/attacks: ${suite.rows.length - failed.length}/${suite.rows.length} passed`,
  );
  for (const row of failed) {
    console.log(
      `  FAIL ${row.test}: honest=${row.honest.toFixed(4)} attack=${row.attack.toFixed(4)} rule=${row.rule}`,
    );
  }
}

const candidateUrl = summaries.find(
  (summary) => summary.name === "candidate/url_scan",
);
const championUrl = summaries.find(
  (summary) => summary.name === "champion/url_scan",
);
const candidateVerdictLock = summaries.find(
  (summary) => summary.name === "candidate/verdictlock_url",
);
const candidateUrlAttacks = attackSuites.find(
  (suite) => suite.name === "candidate/url",
);
if (
  candidateUrl.rows.length === 0 ||
  candidateUrl.wins < championUrl.wins ||
  candidateUrl.meanMargin < championUrl.meanMargin ||
  candidateUrl.worstSelf < 0.75 ||
  candidateVerdictLock.wins !== candidateVerdictLock.rows.length ||
  candidateUrlAttacks.rows.some((row) => !row.passed)
) {
  process.exitCode = 1;
}