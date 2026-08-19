"use client";

import {
  Activity,
  ArrowUpRight,
  Check,
  CircleCheck,
  Clock3,
  Copy,
  Database,
  ExternalLink,
  FileJson,
  LockKeyhole,
  Network,
  OctagonX,
  Play,
  Radar,
  RefreshCw,
  Search,
  ShieldCheck,
  SquareTerminal,
  TriangleAlert,
} from "lucide-react";
import {
  startTransition,
  useDeferredValue,
  useEffect,
  useEffectEvent,
  useState,
  type FormEvent,
} from "react";

type Decision = "ALLOW" | "WARN" | "BLOCK";

interface NetworkPayload {
  discovery: {
    count: number;
    intent_id: "URL_SCAN";
    miners: Array<{ id: string; name: string; slug: string }>;
  };
  runtime: {
    payment_ready: boolean;
    operator_access_required: boolean;
  };
}

interface AuditRecord {
  id: string;
  created_at: string;
  event: "SCAN" | "ACTION";
  target_url: string;
  decision: Decision;
  telegraph: { miner_name: string | null };
  record_hash: string;
}

interface AuditPayload {
  records: AuditRecord[];
  integrity: { valid: boolean; checked: number };
}

interface GuardPayload {
  scan: {
    decision: Decision;
    finding: {
      confidence: number | null;
      reason: string;
      evidence: string[];
    };
    miner_id: string | null;
    miner_name: string | null;
    signal_hash: string | null;
    cost_usd: number | null;
    duration_ms: number | null;
  };
  execution: {
    attempted: boolean;
    status: number | null;
    bytes: number;
    preview: string | null;
  } | null;
}

function statusIcon(decision: Decision, size = 18) {
  if (decision === "ALLOW") return <CircleCheck size={size} aria-hidden="true" />;
  if (decision === "BLOCK") return <OctagonX size={size} aria-hidden="true" />;
  return <TriangleAlert size={size} aria-hidden="true" />;
}

function shortHash(value: string | null, width = 10) {
  if (!value) return "not issued";
  return value.length > width * 2
    ? `${value.slice(0, width)}...${value.slice(-width)}`
    : value;
}

function relativeTime(value: string) {
  const minutes = Math.floor(Math.max(0, Date.now() - new Date(value).getTime()) / 60_000);
  if (minutes < 1) return "now";
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  return hours < 24 ? `${hours}h` : `${Math.floor(hours / 24)}d`;
}

async function responseJson<T>(response: Response): Promise<T> {
  const body = await response.json();
  if (!response.ok) {
    throw new Error(body.message ?? body.error?.message ?? body.error ?? `HTTP ${response.status}`);
  }
  return body as T;
}

export function ProofGateConsole() {
  const [target, setTarget] = useState("https://example.com");
  const deferredTarget = useDeferredValue(target);
  const [mode, setMode] = useState<"scan" | "execute">("scan");
  const [method, setMethod] = useState<"GET" | "HEAD">("GET");
  const [network, setNetwork] = useState<NetworkPayload | null>(null);
  const [audit, setAudit] = useState<AuditPayload | null>(null);
  const [result, setResult] = useState<GuardPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [accessKey, setAccessKey] = useState("");
  const [auditLocked, setAuditLocked] = useState(false);

  async function refreshData() {
    const operatorHeaders = accessKey
      ? { Authorization: `Bearer ${accessKey}` }
      : undefined;
    const networkResponse = await Promise.resolve(
      fetch("/api/network", { cache: "no-store" }).then(responseJson<NetworkPayload>),
    );
    startTransition(() => setNetwork(networkResponse));

    if (networkResponse.runtime.operator_access_required && !accessKey) {
      startTransition(() => setAuditLocked(true));
      return;
    }

    const auditResponse = await fetch("/api/audit?limit=12", {
        cache: "no-store",
        headers: operatorHeaders,
      }).then(async (response) => {
      if (response.status === 401 || response.status === 503) {
        return { locked: true, payload: null };
      }
      return {
        locked: false,
        payload: await responseJson<AuditPayload>(response),
      };
    });

    startTransition(() => {
      setAuditLocked(auditResponse.locked);
      if (auditResponse.payload) setAudit(auditResponse.payload);
    });
  }

  const refreshOnMount = useEffectEvent(refreshData);

  useEffect(() => {
    void refreshOnMount();
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const response = await fetch("/api/guard", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(accessKey ? { Authorization: `Bearer ${accessKey}` } : {}),
        },
        body: JSON.stringify({ url: target, execute: mode === "execute", method }),
      });
      const body = await responseJson<GuardPayload>(response);
      startTransition(() => setResult(body));
      await refreshData();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Request failed");
    } finally {
      setLoading(false);
    }
  }

  async function copySignal() {
    if (!result?.scan.signal_hash) return;
    await navigator.clipboard.writeText(result.scan.signal_hash);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1_500);
  }

  let targetHost = "awaiting target";
  try {
    targetHost = new URL(deferredTarget).hostname || targetHost;
  } catch {
    // Keep the stable placeholder while the operator is typing.
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#main" aria-label="ProofGate console">
          <span className="brand-mark"><ShieldCheck size={18} /></span>
          <span>ProofGate</span>
          <span className="brand-edition">H1 / 2026</span>
        </a>
        <div className="topbar-status" aria-label="Runtime status">
          <span className={`status-dot ${network ? "online" : "pending"}`} />
          <span>{network ? `${network.discovery.count} live URL_SCAN Miners` : "Connecting to Telegraph"}</span>
        </div>
        <nav className="topbar-actions" aria-label="Project links">
          <a href="/miner.yaml" target="_blank" rel="noreferrer" title="Open Miner YAML"><FileJson size={16} /><span>Miner YAML</span></a>
          <a href="https://explorer.telegraphprotocol.com/miners/leaderboard" target="_blank" rel="noreferrer" title="Open Telegraph Explorer"><ExternalLink size={16} /><span>Explorer</span></a>
        </nav>
      </header>

      <main id="main" className="console-grid">
        <section className="workbench" aria-labelledby="gate-title">
          <div className="workbench-heading reveal-one">
            <div>
              <p className="eyebrow"><Radar size={14} /> Live policy surface</p>
              <h1 id="gate-title">Pre-execution gate</h1>
              <p className="operational-subtitle">URL_SCAN · confidence floor 80% · Base Sepolia</p>
            </div>
            <div className={`payment-state ${network?.runtime.payment_ready ? "ready" : "not-ready"}`}>
              <LockKeyhole size={15} />
              <span>{network?.runtime.payment_ready ? "Payer armed" : "Payer not configured"}</span>
            </div>
          </div>

          <div className="route-map reveal-two" aria-label="ProofGate request path">
            <div className="route-node active"><Search size={18} /><span>Intent</span><strong>URL_SCAN</strong></div>
            <div className="route-line"><span /></div>
            <div className="route-node"><Network size={18} /><span>Route</span><strong>Ranked Miner</strong></div>
            <div className="route-line"><span /></div>
            <div className="route-node"><ShieldCheck size={18} /><span>Policy</span><strong>Act / withhold</strong></div>
          </div>

          <form className="gate-form reveal-three" onSubmit={submit}>
            <label htmlFor="target-url">Target URL</label>
            <div className="target-row">
              <div className="target-input-wrap">
                <Search size={19} aria-hidden="true" />
                <input id="target-url" name="url" type="url" maxLength={2_048} required spellCheck={false} autoComplete="url" value={target} onChange={(event) => setTarget(event.target.value)} aria-describedby="target-host" />
                <span id="target-host" className="target-host">{targetHost}</span>
              </div>
              <button className="run-button" type="submit" disabled={loading}>
                {loading ? <RefreshCw className="spin" size={18} /> : mode === "execute" ? <Play size={18} /> : <Radar size={18} />}
                <span>{loading ? "Routing" : mode === "execute" ? "Guard action" : "Scan via Telegraph"}</span>
              </button>
            </div>
            <div className="control-row">
              <div className="segmented" aria-label="Gate mode">
                <button type="button" className={mode === "scan" ? "selected" : ""} onClick={() => setMode("scan")}>Scan only</button>
                <button type="button" className={mode === "execute" ? "selected" : ""} onClick={() => setMode("execute")}>Guard & execute</button>
              </div>
              <div className={`segmented method-control ${mode === "scan" ? "disabled" : ""}`} aria-label="HTTP method">
                <button type="button" disabled={mode === "scan"} className={method === "GET" ? "selected" : ""} onClick={() => setMethod("GET")}>GET</button>
                <button type="button" disabled={mode === "scan"} className={method === "HEAD" ? "selected" : ""} onClick={() => setMethod("HEAD")}>HEAD</button>
              </div>
              <span className="policy-note"><LockKeyhole size={13} /> redirects off · 256 KiB cap</span>
            </div>
            <label className="operator-key" htmlFor="operator-key">
              <LockKeyhole size={14} />
              <span>Operator key</span>
              <input
                id="operator-key"
                type="password"
                autoComplete="off"
                value={accessKey}
                onChange={(event) => setAccessKey(event.target.value)}
              />
            </label>
          </form>

          <div className="result-stage" aria-live="polite" aria-busy={loading}>
            {error ? <div className="error-banner"><TriangleAlert size={18} /><div><strong>Request stopped</strong><span>{error}</span></div></div> : null}
            {loading ? (
              <div className="scan-progress"><div className="scan-beam" /><Radar size={30} /><strong>Routing through Telegraph</strong><span>Waiting for a finalized Miner response</span></div>
            ) : result ? (
              <div className={`decision-view decision-${result.scan.decision.toLowerCase()}`}>
                <div className="decision-summary">
                  <div className="decision-badge">{statusIcon(result.scan.decision, 24)}<span>{result.scan.decision}</span></div>
                  <div className="confidence-block"><span>Confidence</span><strong>{result.scan.finding.confidence === null ? "n/a" : `${Math.round(result.scan.finding.confidence * 100)}%`}</strong></div>
                </div>
                <p className="decision-reason">{result.scan.finding.reason}</p>
                <div className="proof-grid">
                  <div><span>Miner</span><strong>{result.scan.miner_name ?? "unknown"}</strong><small>ID {result.scan.miner_id ?? "n/a"}</small></div>
                  <div><span>Signal</span><strong className="mono">{shortHash(result.scan.signal_hash)}</strong>{result.scan.signal_hash ? <button type="button" className="copy-button" title="Copy signal hash" onClick={copySignal}>{copied ? <Check size={14} /> : <Copy size={14} />}</button> : null}</div>
                  <div><span>Settlement</span><strong>{result.scan.cost_usd === null ? "n/a" : `$${result.scan.cost_usd.toFixed(2)}`}</strong><small>{result.scan.duration_ms === null ? "latency n/a" : `${result.scan.duration_ms} ms`}</small></div>
                  <div><span>Action</span><strong>{result.execution === null ? "not requested" : result.execution.attempted ? `HTTP ${result.execution.status}` : "withheld"}</strong><small>{result.execution?.bytes ? `${result.execution.bytes} bytes` : "policy enforced"}</small></div>
                </div>
                <div className="evidence-list">
                  <div className="section-label"><Database size={14} /> Evidence</div>
                  {result.scan.finding.evidence.length ? result.scan.finding.evidence.map((item, index) => <div className="evidence-row" key={`${item}-${index}`}><span>{String(index + 1).padStart(2, "0")}</span><p>{item}</p></div>) : <div className="evidence-row muted"><span>00</span><p>No normalized evidence was returned.</p></div>}
                </div>
                {result.execution?.preview ? <pre className="response-preview">{result.execution.preview}</pre> : null}
              </div>
            ) : (
              <div className="empty-result"><ShieldCheck size={34} /><div><strong>No decision yet</strong><span>Policy output will appear here after live routing.</span></div><div className="empty-rule"><span>ALLOW</span><span>WARN</span><span>BLOCK</span></div></div>
            )}
          </div>
        </section>

        <aside className="audit-rail" aria-labelledby="audit-title">
          <div className="rail-heading">
            <div><p className="eyebrow"><Activity size={14} /> Local evidence</p><h2 id="audit-title">Decision ledger</h2></div>
            <button className="icon-button" type="button" onClick={() => void refreshData()} title="Refresh network and ledger"><RefreshCw size={16} /></button>
          </div>
          <div className="rail-metrics">
            <div><span>Chain integrity</span><strong className={auditLocked ? "metric-warn" : audit?.integrity.valid ? "metric-good" : "metric-warn"}>{auditLocked ? "LOCKED" : audit ? (audit.integrity.valid ? "VERIFIED" : "BROKEN") : "CHECKING"}</strong></div>
            <div><span>Records checked</span><strong>{audit?.integrity.checked ?? 0}</strong></div>
          </div>
          <div className="miner-pool">
            <div className="section-label"><Network size={14} /> Live routing pool</div>
            <div className="miner-list">
              {network?.discovery.miners.map((miner, index) => <div className="miner-row" key={`${miner.id}-${miner.slug}`}><span className="miner-rank">{String(index + 1).padStart(2, "0")}</span><div><strong>{miner.name}</strong><small>{miner.slug}</small></div><span className="live-pill">LIVE</span></div>) ?? <div className="miner-row skeleton-row"><span /><div /><span /></div>}
            </div>
          </div>
          <div className="ledger-list">
            <div className="section-label"><Clock3 size={14} /> Recent decisions</div>
            <div className="ledger-scroll">
              {audit?.records.length ? audit.records.map((record) => <article className={`ledger-entry entry-${record.decision.toLowerCase()}`} key={record.id}><div className="ledger-entry-top"><span className="ledger-decision">{statusIcon(record.decision, 15)}{record.decision}</span><time dateTime={record.created_at}>{relativeTime(record.created_at)}</time></div><strong className="ledger-target">{record.target_url}</strong><div className="ledger-meta"><span>{record.telegraph.miner_name ?? "local"}</span><span>{record.event}</span><span className="mono">{shortHash(record.record_hash, 5)}</span></div></article>) : <div className="ledger-empty"><Database size={22} /><span>No local decisions recorded</span></div>}
            </div>
          </div>
          <div className="rail-footer">
            <a href="/api/audit" target="_blank" rel="noreferrer"><Database size={15} /> JSON ledger <ArrowUpRight size={14} /></a>
            <span><SquareTerminal size={15} /> MCP stdio ready</span>
          </div>
        </aside>
      </main>
    </div>
  );
}