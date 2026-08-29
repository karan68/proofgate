import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import { keccak256, toHex } from "viem";

const source =
  "wasm-scorer/target/wasm32-unknown-unknown/release/proofgate_url_scorer.wasm";
const destination = "public/wasm/proofgate-url-scorer.wasm";

const bytes = await readFile(source);
if (bytes.byteLength > 32 * 1024 * 1024) {
  throw new Error(`WASM artifact exceeds 32 MiB: ${bytes.byteLength} bytes`);
}

const wasmModule = await WebAssembly.compile(bytes);
const imports = WebAssembly.Module.imports(wasmModule);
if (imports.length !== 0) {
  throw new Error(`WASM artifact has forbidden imports: ${JSON.stringify(imports)}`);
}

const exports = new Set(
  WebAssembly.Module.exports(wasmModule).map((item) => item.name),
);
for (const required of ["memory", "alloc", "dealloc", "rank_answer"]) {
  if (!exports.has(required)) {
    throw new Error(`WASM artifact is missing required export ${required}`);
  }
}

const { exports: runtime } = await WebAssembly.instantiate(wasmModule, {});
const encoder = new TextEncoder();
function write(value) {
  const bytes = encoder.encode(value);
  const pointer = runtime.alloc(bytes.length);
  new Uint8Array(runtime.memory.buffer, pointer, bytes.length).set(bytes);
  return [pointer, bytes.length];
}
function score(question, groundTruth, answer) {
  return runtime.rank_answer(
    ...write(question),
    ...write(groundTruth),
    ...write(answer),
  );
}
for (let iteration = 0; iteration < 10_000; iteration += 1) {
  if (score("Scan example.com", "safe", "safe") !== 1) {
    throw new Error(`WASM repeatability check failed at iteration ${iteration}`);
  }
}
let oversizedAllocationTrapped = false;
try {
  runtime.alloc(2 * 1024 * 1024 + 1);
} catch {
  oversizedAllocationTrapped = true;
}
if (!oversizedAllocationTrapped) {
  throw new Error("WASM allocator accepted an oversized input arena request");
}

await mkdir(dirname(destination), { recursive: true });
await writeFile(destination, bytes);

console.log(
  JSON.stringify(
    {
      source,
      destination,
      bytes: bytes.byteLength,
      imports: imports.length,
      keccak256: keccak256(toHex(bytes)),
      exports: [...exports].sort(),
    },
    null,
    2,
  ),
);