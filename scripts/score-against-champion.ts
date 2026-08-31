/**
 * Scores ProofGate's real URL_SCAN responses with the live Telegraph champion
 * scoring module (registration 220) so answer regressions are caught locally.
 *
 *   npx tsx scripts/score-against-champion.ts
 *   npx tsx scripts/score-against-champion.ts --production
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";

import {
  answerHistoricalUrlQuestion,
  scanUrlWithEvidence,
  type MinerScanResult,
} from "../src/lib/proofgate/miner";

const CHAMPION_URL =
  "https://raw.githubusercontent.com/zkasuran/telegraph-salience-scorer/0174a85639c398a0e898dcb11b54367eb2723b2b/dist/xfmr/url_c3.wasm";
const CACHE = "tmp-champion/url_c3.wasm";
const MINIMUM = 0.9;

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

const stubbedScan = (url: string, question: string, registeredAt: string, address: string) =>
  scanUrlWithEvidence(url, {
    question,
    now: new Date("2026-08-31T00:00:00.000Z"),
    lookup: async () => [address],
    fetcher: (async (input: RequestInfo | URL) => {
      if (String(input).startsWith("https://rdap.org/")) {
        return Response.json({
          events: [{ eventAction: "registration", eventDate: registeredAt }],
        });
      }
      throw new Error(`Unexpected request ${String(input)}`);
    }) as typeof fetch,
  });

interface Case {
  id: string;
  question: string;
  ground_truth: string;
  /** Request body the Telegraph node would post to the deployed endpoint. */
  request: Record<string, string>;
  run(): Promise<MinerScanResult> | MinerScanResult;
}

const cases: Case[] = [
  {
    id: "mirai-url",
    question:
      "What is documented about the Mirai botnet source code release at https://github.com/mirai-botnet/mirai/releases/tag/v1.0.0 ?",
    ground_truth:
      "The Mirai botnet source code was publicly released on Hack Forums in late September 2016 by a user calling himself Anna-senpai. Mirai infected insecure IoT devices using default credentials and powered record-breaking DDoS attacks against KrebsOnSecurity, OVH and Dyn.",
    request: {
      url: "https://github.com/mirai-botnet/mirai/releases/tag/v1.0.0",
      question: "What is documented about the Mirai botnet source code release?",
    },
    run: () =>
      stubbedScan(
        "https://github.com/mirai-botnet/mirai/releases/tag/v1.0.0",
        "What is documented about the Mirai botnet source code release?",
        "2007-10-09T00:00:00Z",
        "140.82.114.3",
      ),
  },
  {
    id: "sunburst-hostname",
    question: "Is https://avsvmcloud.com malicious?",
    ground_truth:
      "Yes. avsvmcloud.com was the SUNBURST command-and-control domain used by the trojanized SolarWinds Orion updates that FireEye disclosed in December 2020.",
    request: { url: "https://avsvmcloud.com", question: "Is this domain malicious?" },
    run: () =>
      stubbedScan(
        "https://avsvmcloud.com",
        "Is this domain malicious?",
        "2018-07-25T00:00:00Z",
        "20.140.0.1",
      ),
  },
  {
    id: "necurs-legitimate-publisher",
    question:
      "https://www.microsoft.com/en-us/msrc/blog/2020/07/01/microsoft-takedown-of-necurs-botnet-domain-infrastructure/",
    ground_truth:
      "On March 10, 2020 Microsoft and partners in 35 countries took coordinated legal and technical action against Necurs, a botnet that had infected more than nine million computers. Microsoft predicted more than six million domains its generation algorithm would create so registries could block them in advance.",
    request: {
      url: "https://www.microsoft.com/en-us/msrc/blog/2020/07/01/microsoft-takedown-of-necurs-botnet-domain-infrastructure/",
      question: "What is documented about Microsoft's takedown of Necurs botnet domain infrastructure?",
    },
    run: () =>
      stubbedScan(
        "https://www.microsoft.com/en-us/msrc/blog/2020/07/01/microsoft-takedown-of-necurs-botnet-domain-infrastructure/",
        "What is documented about Microsoft's takedown of Necurs botnet domain infrastructure?",
        "1991-05-02T00:00:00Z",
        "23.62.61.28",
      ),
  },
  {
    id: "conficker-no-url",
    question: "What is documented about Conficker's use of algorithmically generated domains?",
    ground_truth:
      "Conficker generated pseudo-random command-and-control domains from the current date. The A and B variants produced 250 candidate domains per day across 110 top-level domains, and Conficker.C expanded that on April 1, 2009 to 50,000 candidate domains per day across 116 top-level domains.",
    request: {
      input: "What is documented about Conficker's use of algorithmically generated domains?",
    },
    run: () =>
      answerHistoricalUrlQuestion(
        "What is documented about Conficker's use of algorithmically generated domains?",
        new Date("2026-08-31T00:00:00.000Z"),
      ),
  },
  {
    id: "wannacry-killswitch",
    question:
      "What is documented about the WannaCry kill-switch domain iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com?",
    ground_truth:
      "It was the WannaCry kill-switch domain hardcoded into the ransomware. Marcus Hutchins registered and sinkholed it on May 12, 2017, which stopped the initial outbreak from spreading further.",
    request: { input: "What is documented about the WannaCry kill-switch domain?" },
    run: () =>
      answerHistoricalUrlQuestion(
        "What is documented about the WannaCry kill-switch domain?",
        new Date("2026-08-31T00:00:00.000Z"),
      ),
  },
  {
    id: "phishing-structure",
    question: "Is http://secure-login-verify.free-prize-claim.info/account a phishing site?",
    ground_truth:
      "Yes. It is a credential-phishing lure hostname with no legitimate service behind it.",
    request: {
      url: "http://secure-login-verify.free-prize-claim.info/account",
      question: "Is this a phishing site?",
    },
    run: () =>
      stubbedScan(
        "http://secure-login-verify.free-prize-claim.info/account",
        "Is this a phishing site?",
        "2026-08-20T00:00:00Z",
        "45.33.32.156",
      ),
  },
  {
    id: "ordinary-benign-url",
    question: "Is https://www.microsoft.com/en-us/security safe to visit?",
    ground_truth:
      "Yes. It is the legitimate Microsoft security portal, it is not associated with phishing or malware, and it is safe to visit.",
    request: {
      url: "https://www.microsoft.com/en-us/security",
      question: "Is this URL safe to visit?",
    },
    run: () =>
      stubbedScan(
        "https://www.microsoft.com/en-us/security",
        "Is this URL safe to visit?",
        "1991-05-02T00:00:00Z",
        "23.62.61.28",
      ),
  },
];

const score = await championScorer();
let failures = 0;
const bisect = process.argv.includes("--bisect");
const production = process.argv.includes("--production");
const endpoint = `${process.env.PROOFGATE_PUBLIC_URL ?? "https://proofgate-six.vercel.app"}/api/miner/scan`;

if (production) console.log(`Scoring live responses from ${endpoint}\n`);

for (const testCase of cases) {
  const result = production
    ? ((await (
        await fetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(testCase.request),
        })
      ).json()) as MinerScanResult)
    : await testCase.run();
  const body = JSON.stringify(result);
  const bodyScore = score(testCase.question, testCase.ground_truth, body);
  const answerScore = score(testCase.question, testCase.ground_truth, result.answer);
  const worst = Math.min(bodyScore, answerScore);
  if (worst < MINIMUM) failures += 1;
  console.log(
    `${worst >= MINIMUM ? "PASS" : "FAIL"}  body=${bodyScore.toFixed(6)}  answer=${answerScore.toFixed(6)}  verdict=${result.verdict.padEnd(17)} ${testCase.id}`,
  );
  if (bisect && bodyScore < MINIMUM) {
    const record = result as unknown as Record<string, unknown>;
    for (const key of Object.keys(record)) {
      if (key === "answer") continue;
      const clone = { ...record };
      delete clone[key];
      console.log(
        `        ${score(testCase.question, testCase.ground_truth, JSON.stringify(clone)).toFixed(6)}  without "${key}"`,
      );
    }
  }
}

console.log(
  failures === 0
    ? `\nAll ${cases.length} cases score at least ${MINIMUM} under the live champion scorer.`
    : `\n${failures} of ${cases.length} cases scored below ${MINIMUM}.`,
);
process.exit(failures === 0 ? 0 : 1);
