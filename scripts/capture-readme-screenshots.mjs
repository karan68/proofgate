import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

const APP_URL = "https://proofgate-six.vercel.app";
const OUTPUT = path.resolve("public/screenshots");
const CHROME =
  process.env.CHROME_PATH ??
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";

const miners = [
  { id: "203", name: "VirusTotal Threat Intelligence", slug: "virustotal" },
  { id: "5001", name: "URL Sentinel", slug: "url-sentinel" },
  { id: "222", name: "PhishTank URL Check", slug: "phishtank" },
  { id: "223", name: "URLScan.io", slug: "urlscan" },
];

const recordedWarn = {
  id: "46b73555-e725-4e5f-9e5a-89cea34c7ee9",
  created_at: "2026-08-19T08:25:57.886Z",
  event: "SCAN",
  target_url: "https://example.com/",
  decision: "WARN",
  telegraph: { miner_name: "LiteLLM Bedrock Proxy" },
  record_hash: "3f24bdf8b4059a8364335d54810980db6dbdca3922e6bf081246e18d3f486b2b",
};

const recordedAllow = {
  id: "ae087dca-31a5-4269-967c-0f6959731253",
  created_at: "2026-08-19T08:33:14.544Z",
  event: "ACTION",
  target_url: "https://example.com/",
  decision: "ALLOW",
  telegraph: { miner_name: "URL Sentinel" },
  record_hash: "2c7d71afc63007f3579afbd523074e375d3552c4d1faff7f8f7257ca132b7a27",
};

const networkResponse = {
  discovery: {
    count: miners.length,
    intent_id: "URL_SCAN",
    checked_at: "2026-08-19T08:33:10.000Z",
    miners,
  },
  runtime: {
    payment_ready: true,
    operator_access_required: false,
  },
};

const auditResponse = {
  records: [recordedAllow, recordedWarn],
  integrity: { valid: true, checked: 2, broken_at: null },
};

const cases = [
  {
    name: "verified-allow-execution",
    label: "VERIFIED RECEIPT REPLAY · BASE SEPOLIA TX 0xfb8e…6585",
    mode: "execute",
    target: "https://example.com",
    result: {
      scan: {
        decision: "ALLOW",
        finding: {
          verdict: "safe",
          confidence: 0.9,
          reason: "No malicious or suspicious signals across 4/4 responding sources.",
          evidence: [
            "URL Sentinel returned a synchronous verdict from four responding sources.",
            "Policy confidence 90% exceeded the 80% execution threshold.",
          ],
        },
        miner_id: "5001",
        miner_name: "URL Sentinel",
        signal_hash: "sha256:76869f9753075524d41f58498c24c97000095d08f342ff36261b1e178be12fba",
        cost_usd: 0.01,
        duration_ms: 3726,
      },
      execution: {
        attempted: true,
        status: 200,
        bytes: 559,
        preview: "Example Domain — This domain is for use in documentation examples without needing permission.",
      },
      audit: recordedAllow,
    },
  },
  {
    name: "fail-closed-warn",
    label: "DETERMINISTIC POLICY FIXTURE · NO PAYMENT · NO TARGET REQUEST",
    mode: "scan",
    target: "https://example.com",
    result: {
      scan: {
        decision: "WARN",
        finding: {
          verdict: "safe",
          confidence: 0.65,
          reason: "No reputation provider confirmed the result. Confidence is below the 80% policy threshold.",
          evidence: [
            "structure: URL structure checks completed without a suspicious signal.",
            "dns: Hostname resolved to public addresses.",
            "rdap: Domain registration metadata was available.",
            "reputation: Keyed providers were unavailable and did not count as clean.",
          ],
        },
        miner_id: null,
        miner_name: "ProofGate policy fixture",
        signal_hash: "sha256:fixture-low-confidence",
        cost_usd: null,
        duration_ms: 0,
      },
      execution: null,
      audit: recordedWarn,
    },
  },
  {
    name: "malicious-block",
    label: "DETERMINISTIC POLICY FIXTURE · NO PAYMENT · NO TARGET REQUEST",
    mode: "execute",
    target: "https://security-fixture.invalid/login",
    result: {
      scan: {
        decision: "BLOCK",
        finding: {
          verdict: "malicious",
          confidence: 0.99,
          reason: "Independent threat sources classified the fixture as malicious.",
          evidence: [
            "google: SOCIAL_ENGINEERING fixture match.",
            "urlhaus: Malware distribution fixture match.",
            "policy: One authoritative threat match overrides clean votes.",
          ],
        },
        miner_id: null,
        miner_name: "ProofGate policy fixture",
        signal_hash: "sha256:fixture-malicious",
        cost_usd: null,
        duration_ms: 0,
      },
      execution: {
        attempted: false,
        status: null,
        bytes: 0,
        preview: null,
      },
      audit: {
        ...recordedWarn,
        id: "00000000-0000-4000-8000-000000000003",
        target_url: "https://security-fixture.invalid/login",
        decision: "BLOCK",
        record_hash: "fixture-only-not-an-audit-receipt",
      },
    },
  },
];

class CdpClient {
  constructor(url) {
    this.url = url;
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = new Map();
  }

  async connect() {
    this.socket = new WebSocket(this.url);
    await new Promise((resolve, reject) => {
      this.socket.addEventListener("open", resolve, { once: true });
      this.socket.addEventListener("error", reject, { once: true });
    });
    this.socket.addEventListener("message", (event) => {
      const message = JSON.parse(String(event.data));
      if (message.id) {
        const pending = this.pending.get(message.id);
        if (!pending) return;
        this.pending.delete(message.id);
        if (message.error) pending.reject(new Error(message.error.message));
        else pending.resolve(message.result);
        return;
      }
      for (const listener of this.listeners.get(message.method) ?? []) {
        listener(message.params);
      }
    });
  }

  send(method, params = {}) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.socket.send(JSON.stringify({ id, method, params }));
    });
  }

  on(method, listener) {
    const listeners = this.listeners.get(method) ?? [];
    listeners.push(listener);
    this.listeners.set(method, listeners);
  }

  close() {
    this.socket?.close();
  }
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function waitForJson(url, attempts = 80) {
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      const response = await fetch(url);
      if (response.ok) return response.json();
    } catch {
      // Chrome has not opened its debugger yet.
    }
    await delay(100);
  }
  throw new Error(`Timed out waiting for ${url}`);
}

async function waitForSelector(client, selector, timeoutMs = 15_000) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    const result = await client.send("Runtime.evaluate", {
      expression: `Boolean(document.querySelector(${JSON.stringify(selector)}))`,
      returnByValue: true,
    });
    if (result.result.value) return;
    await delay(100);
  }
  throw new Error(`Timed out waiting for ${selector}`);
}

async function waitForExpression(client, expression, timeoutMs = 15_000) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    const result = await client.send("Runtime.evaluate", {
      expression,
      returnByValue: true,
    });
    if (result.result.value) return;
    await delay(100);
  }
  throw new Error(`Timed out waiting for expression: ${expression}`);
}

function fulfill(client, requestId, body) {
  return client.send("Fetch.fulfillRequest", {
    requestId,
    responseCode: 200,
    responseHeaders: [
      { name: "Content-Type", value: "application/json; charset=utf-8" },
      { name: "Cache-Control", value: "no-store" },
    ],
    body: Buffer.from(JSON.stringify(body)).toString("base64"),
  });
}

async function captureCase(fixture, index) {
  const port = 9400 + index;
  const userData = await mkdtemp(path.join(tmpdir(), "proofgate-capture-"));
  const chrome = spawn(
    CHROME,
    [
      "--headless=new",
      "--disable-gpu",
      "--hide-scrollbars",
      "--no-first-run",
      "--no-default-browser-check",
      "--remote-allow-origins=*",
      `--remote-debugging-port=${port}`,
      `--user-data-dir=${userData}`,
      "about:blank",
    ],
    { stdio: "ignore" },
  );

  let client;
  try {
    const targets = await waitForJson(`http://127.0.0.1:${port}/json`);
    const target = targets.find((candidate) => candidate.type === "page");
    if (!target?.webSocketDebuggerUrl) throw new Error("Chrome page target missing");
    client = new CdpClient(target.webSocketDebuggerUrl);
    await client.connect();
    await client.send("Page.enable");
    await client.send("Runtime.enable");
    await client.send("Emulation.setDeviceMetricsOverride", {
      width: 1440,
      height: 1100,
      deviceScaleFactor: 1,
      mobile: false,
    });
    await client.send("Emulation.setEmulatedMedia", {
      features: [{ name: "prefers-reduced-motion", value: "reduce" }],
    });
    await client.send("Fetch.enable", {
      patterns: [{ urlPattern: `${APP_URL}/api/*`, requestStage: "Request" }],
    });
    client.on("Fetch.requestPaused", async ({ requestId, request }) => {
      try {
        const url = new URL(request.url);
        if (url.pathname === "/api/network") {
          await fulfill(client, requestId, networkResponse);
        } else if (url.pathname === "/api/audit") {
          await fulfill(client, requestId, auditResponse);
        } else if (url.pathname === "/api/guard") {
          await fulfill(client, requestId, fixture.result);
        } else {
          await client.send("Fetch.continueRequest", { requestId });
        }
      } catch {
        await client.send("Fetch.failRequest", {
          requestId,
          errorReason: "Aborted",
        });
      }
    });

    await client.send("Page.navigate", { url: APP_URL });
    await waitForSelector(client, ".run-button");
    await waitForSelector(client, ".miner-row strong");
    await client.send("Runtime.evaluate", {
      expression: `(() => {
        const input = document.querySelector('#target-url');
        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
        setter.call(input, ${JSON.stringify(fixture.target)});
        input.dispatchEvent(new Event('input', { bubbles: true }));
        const mode = ${JSON.stringify(fixture.mode)};
        const label = mode === 'execute' ? 'Guard & execute' : 'Scan only';
        [...document.querySelectorAll('button')].find(button => button.textContent.trim() === label)?.click();
      })()`,
    });
    const selectedLabel = fixture.mode === "execute" ? "Guard & execute" : "Scan only";
    await waitForExpression(
      client,
      `[...document.querySelectorAll('button')].some(button => button.textContent.trim() === ${JSON.stringify(selectedLabel)} && button.classList.contains('selected'))`,
    );
    await waitForExpression(
      client,
      `document.querySelector('#target-url')?.value === ${JSON.stringify(fixture.target)}`,
    );
    await client.send("Runtime.evaluate", {
      expression: `document.querySelector('.run-button').click()`,
    });
    await waitForSelector(client, ".decision-view");
    await client.send("Runtime.evaluate", {
      expression: `(() => {
        const badge = document.createElement('div');
        badge.textContent = ${JSON.stringify(fixture.label)};
        Object.assign(badge.style, {
          position: 'fixed', top: '68px', left: '50%', transform: 'translateX(-50%)',
          zIndex: '99999', padding: '8px 12px', border: '1px solid #3b8059',
          borderRadius: '4px', color: '#54df90', background: '#09100c',
          font: '500 10px IBM Plex Mono, monospace', letterSpacing: '0'
        });
        document.body.appendChild(badge);
      })()`,
    });
    await delay(150);
    const screenshot = await client.send("Page.captureScreenshot", {
      format: "png",
      fromSurface: true,
      captureBeyondViewport: false,
    });
    await writeFile(
      path.join(OUTPUT, `${fixture.name}.png`),
      Buffer.from(screenshot.data, "base64"),
    );
  } finally {
    client?.close();
    chrome.kill();
    await delay(250);
    await rm(userData, {
      recursive: true,
      force: true,
      maxRetries: 5,
      retryDelay: 200,
    }).catch(() => undefined);
  }
}

const requested = process.argv.slice(2);
const selectedCases = requested.length
  ? cases.filter((fixture) => requested.includes(fixture.name))
  : cases;
if (selectedCases.length === 0) {
  throw new Error(`Unknown case. Available: ${cases.map((fixture) => fixture.name).join(", ")}`);
}

for (const fixture of selectedCases) {
  const index = cases.indexOf(fixture);
  await captureCase(fixture, index);
  console.log(`captured ${fixture.name}.png`);
}
