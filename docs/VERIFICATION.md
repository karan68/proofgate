# ProofGate Verification Ledger

This document records what was tested, how it was tested, and which evidence is
live, historical, simulated, or still pending. It exists to prevent screenshots,
fixtures, mocks, and dry runs from being mistaken for production transactions.

Last updated: **2026-08-29**

## Evidence Classes

| Class | Meaning |
| --- | --- |
| Live production | Read directly from `https://proofgate-six.vercel.app` without request interception |
| Live historical integration | A real Telegraph/Base Sepolia call performed during development and independently verified |
| Deterministic fixture | A known local policy input; no payment and no target request |
| Automated test | Vitest with injected fetch/DNS/storage dependencies; no real payment |
| Dry check | Reads public chain/YAML/configuration state but submits no transaction |
| Public proxy benchmark | Pinned third-party corpus; useful evidence but not the private evaluator |

## Safety State

At the end of verification:

- Public production reports `payment_ready: false`.
- The production payer private key is not configured.
- Track 2 registrations used Base Sepolia gas only; no x402 or USDC payment was
  made.
- Replacement registration `384` is active for `URL_SCAN`; registration `310`
  was atomically deregistered by the update.
- Registration `384` pins YAML SHA-256
  `9ba61d88467c40d56cb4b301096842c9264c00a32c3f5801e37e4e1b50ab1328`
  and explicitly declares the endpoint intent plus required `url` body parameter.
- Track 1 submission `6a930a4aae9ddfbc70a760d9` is saved and verified
  with item `384`.
- Track 2 registrations `1810`, `1814`, and `1816` were each rejected at 12/15
  hidden ordering wins. There is no accepted ProofGate Track 2 registration.
- Track 2 portal submission `6a9320d4ae9ddfbc70a760db` is saved and verified,
  but still points to rejected registration `1814`.
- No payment or transaction was initiated while preparing README screenshots.

## Automated Baseline

Command:

```powershell
npm exec -- vitest run --coverage
```

Result:

```text
Test Files  10 passed (10)
Tests       74 passed (74)
Statements  83.49% (516/618)
Branches    76.19% (413/542)
Functions   91.34% (95/104)
Lines       85.96% (490/570)
```

Additional gates:

```powershell
npm run typecheck
npm run lint
npm run build
npm run mcp:build
npm run mcp:smoke
npm audit
```

Verified results:

| Gate | Result |
| --- | --- |
| `next typegen && tsc --noEmit` | passed |
| ESLint | passed, no warnings |
| Next.js 16 production build | passed |
| MCP ESM bundle | passed |
| MCP v2 initialization and tool listing | passed |
| npm audit | 0 vulnerabilities |
| GitHub Actions | [schema-fix run 33263101514: success](https://github.com/karan68/proofgate/actions/runs/33263101514) |

### Track 2 WASM scorer

Commands:

```powershell
npm run wasm:test
npm run wasm:verify
npm run wasm:build
npm run wasm:benchmark
```

Verified artifact:

| Field | Result |
| --- | --- |
| Intent | `URL_SCAN` |
| Rust tests | 18 passed, 0 failed |
| Arbitrary input | deterministic random bytes, NULs, non-ASCII, repeated calls, 200 KiB answer |
| WASM allocator | 10,000 repeated scores; oversized 2 MiB arena request traps |
| Compiled size | 817,538 bytes |
| Keccak-256 | `0xc04a107cdeab50dca4b0d06cd4f2a48c0fc64e3eef0767f7d82d6dc43e0147b7` |
| WASM imports | 0 |
| ABI exports | `memory`, `alloc`, `dealloc`, `rank_answer` present |
| Independent URL ordering | 26/26; mean margin 0.9599 |
| Independent URL attacks | 18/18 |
| Independent gate stress | 26/26; mean margin 0.8428 |

The URL and attack fixtures are pinned to VerdictLock commit
`9f06db38f09bdeba8d85f14973db9eeffd414d05`. The comparison champion is pinned
to `zkasuran/telegraph-salience-scorer` commit
`0174a85639c398a0e898dcb11b54367eb2723b2b`. These are public proxy results;
they do not expose or predict Telegraph's private evaluation with certainty.
The packed GloVe data source and licenses are recorded in
[`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md). Semantic credit is capped
and runs only after deterministic factual-conflict gates.

Historical private results:

| Registration | Source commit | Candidate | Champion | Result |
| --- | --- | ---: | ---: | --- |
| `1810` | `d1ad35af60df64b1026ec2af36b494903e1622ac` | 12/15 | 15/15 | rejected |
| `1814` | `97c659e7f8f962be37fb016447f61a5e77702832` | 12/15 | 15/15 | rejected |
| `1816` | `1307577453d2ee04abd0bf193615d6c62ebcb0e8` | 12/15 | 15/15 | rejected |

Registration `1816` used artifact hash
`0xc04a107cdeab50dca4b0d06cd4f2a48c0fc64e3eef0767f7d82d6dc43e0147b7`.
Its candidate margin was `0.7189615` versus champion margin `0.94808555`; worst
self-match was `1`, score standard deviation was `0.4541932`, and no historical
rows were evaluated. The confirmed gas-only transaction was
[`0xf8c307cff97d49d47f66c25acffe0d832e1dd182563c1d0ce7f788c1adc66344`](https://sepolia.basescan.org/tx/0xf8c307cff97d49d47f66c25acffe0d832e1dd182563c1d0ce7f788c1adc66344).

CI installs Rust 1.96.1 with `wasm32-unknown-unknown`, checks rustfmt, tests the
source, verifies the committed artifact against its registered Keccak, runs all
pinned URL ordering and attack gates against those exact bytes, and then builds
the source independently. Cross-host Rust builds are not claimed to be
byte-identical.

## Test Coverage by Module

### Access controls

- local development may run without a configured operator key
- production fails closed when no operator key exists
- missing and wrong bearer values return 401
- valid bearer value succeeds
- independent identities receive independent rate buckets
- quota exhaustion returns 429 and `Retry-After`
- invalid limiter settings are rejected

### Policy

- malicious -> `BLOCK`
- suspicious/pending/unknown -> `WARN`
- safe without confidence -> `WARN`
- safe below threshold -> `WARN`
- safe at/above threshold -> `ALLOW`
- confidence clamping and option validation
- VirusTotal, URLScan.io, PhishTank, and normalized ProofGate shapes
- structured evidence preserved as readable audit text

### Target validation

- HTTP/HTTPS normalization and fragment removal
- local/private hostname rejection
- embedded credential rejection
- private, loopback, reserved, CGNAT, IPv6 local address rejection
- public IPv4 classification
- mixed public/private DNS response rejection
- nonstandard execution port rejection

### Guarded execution

- Web `Request` to Undici adapter
- pinned dispatcher reaches the expected normalized URL
- GET and HEAD behavior
- manual redirect reporting
- exact response-size boundary
- declared and streamed body overflow cancellation
- text preview sanitization
- private DNS rejection before fetch
- executor only called after `ALLOW`
- WARN/BLOCK execution withholding
- audit storage readiness checked before a paid scan

### Audit

- concurrent local appends serialize correctly
- modified historical record is detected
- atomic Redis compare-and-append across independent store instances
- Vercel without persistent Redis fails closed

### Telegraph/x402

- live discovery response parsing
- contract-based `URL_SCAN` Miner selection
- exact dispatcher URL and request body
- no compatible Miner -> refusal before dispatch
- failed upstream response never becomes a verdict
- exact-cap x402 requirement is signed
- over-cap requirement is refused before signed retry
- wrong-network requirement is refused
- missing key and malformed cap are rejected
- discovery errors propagate

### ProofGate Miner

- authoritative malicious evidence overrides clean votes
- multiple malicious sources raise confidence
- structural warnings survive clean reputation evidence
- reputation evidence is required for allow-grade confidence
- PhishTank provider contract
- Google Safe Browsing provider contract
- URLhaus provider contract and auth header
- VirusTotal provider contract and auth header
- submitted target URL is not fetched

### Miner YAML and registration

- non-local HTTP origins rejected
- HTTPS public origin emitted
- localhost HTTP allowed for development
- deployed YAML fetched as exact bytes
- descriptor slug/base URL/endpoint/intent/repository checked
- SHA-256 computed
- fresh wallet public balances checked
- exposed historical wallet blocked
- no submit in check mode

## Live Production Matrix

Direct checks against `https://proofgate-six.vercel.app`:

| Surface | Expected | Observed |
| --- | --- | --- |
| `/` | responsive console | loaded, no horizontal overflow at 1440x900 or 390x844 |
| `/api/health` | 200 | 200 |
| `/api/network` | live `URL_SCAN` pool | 200, four Miners |
| Runtime payer | disabled | `payment_ready: false` |
| Runtime operator policy | required | `operator_access_required: true` |
| `/miner.yaml` | public HTTPS config | 200; canonical Vercel URL and GitHub repository |
| `/api/miner/scan` with `example.com` | free deterministic scan | 200; safe finding with limited `0.65` confidence when keyed providers are absent |
| `/api/audit` without bearer | reject | 401 |
| `/api/audit` with bearer | valid Redis chain | 200, `integrity.valid: true` |
| `/api/guard` with bearer but no payer | fail before payment | 503 `payment_not_configured` |
| Security headers | deny framing, nosniff | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` |

## API Parameter Matrix

A 28-case live local HTTP matrix passed all expected statuses. It covered:

- allowed and disallowed methods
- audit limits `1`, `500`, `0`, `501`, and non-numeric input
- Miner status and CORS preflight
- valid self-Miner scan
- missing, empty, extra, malformed, and oversized Miner payloads
- unsupported URL schemes
- URL credentials
- private targets
- missing, malformed, extra, oversized, and private guard inputs
- Miner YAML availability

No valid paid guard request was included in that matrix.

## Distributed Rate-Limit Proof

Production guard was called with an authenticated but schema-invalid body `{}`.
That body cannot reach Telegraph or authorize payment.

Observed sequence:

```text
10 responses: HTTP 400 invalid_request
 2 responses: HTTP 429 rate_limited
 0 responses: HTTP 500
```

This proved that the connected Redis limiter was active across the deployed
route while keeping the payment path unreachable.

## MCP Protocol Proof

The real smoke client:

1. spawns `dist/mcp/server.js`
2. performs MCP v2 initialization over stdio
3. lists exactly four tools
4. calls `proofgate_network_status`
5. confirms live `URL_SCAN` discovery
6. calls `proofgate_audit_tail`
7. verifies audit-chain integrity
8. verifies three invalid tool inputs return MCP error results
9. closes the child process

Observed tool list:

```text
proofgate_audit_tail
proofgate_guarded_fetch
proofgate_network_status
proofgate_scan
```

## Live Historical x402 and Action Proof

A development-only burner performed the integration run. That address was later
considered exposed and is hard-blocked from registration. The fresh wallet was
not used.

Recorded outcome:

| Field | Value |
| --- | --- |
| Target | `https://example.com/` |
| Telegraph intent | `URL_SCAN` |
| Miner | `URL Sentinel` (`5001`) |
| Finding | `safe` |
| Confidence | `0.90` |
| Policy | `ALLOW` |
| Cost | `0.01` USDC |
| Transaction | `0xfb8e49d1eee8d13e7b18707942bbd85f5a99f69dbe41e285ed8fbd21ee316585` |
| Block | `45,680,053` |
| Transfer | `0.01` Base Sepolia USDC from payer to Telegraph Diamond |
| Guarded method | `GET` |
| Action result | HTTP 200, 559 bytes |
| Audit event | `ACTION` |
| Audit record | `ae087dca-31a5-4269-967c-0f6959731253` |
| Record hash | `2c7d71afc63007f3579afbd523074e375d3552c4d1faff7f8f7257ca132b7a27` |

BaseScan:

https://sepolia.basescan.org/tx/0xfb8e49d1eee8d13e7b18707942bbd85f5a99f69dbe41e285ed8fbd21ee316585

The receipt was independently read through Base Sepolia RPC and the ERC-20
`Transfer` log decoded. It was not accepted solely because Telegraph returned a
settlement header.

## Registration and Track 1 Submission

Fresh wallet public address:

```text
0x2589cd4A7B7301A5973faf636b21166D0c21B67d
```

The read-only preflight initially reported:

```text
Base Sepolia ETH: 0.0001
Circle test USDC: 1
Outgoing transaction count: 0
```

`npm run registration:check` returned:

```text
blocked_wallet: false
descriptor_checks: all true
ready_to_register: true
```

The initial YAML hash observed by the dry check was:

```text
0x06a74048c626035b1a17966a625f53aa380eeabd07e1a74503d839cb2ed538d7
```

Registration `309` was then submitted in
[transaction `0x6524...4fcc`](https://sepolia.basescan.org/tx/0x6524ef379a6b92a491e859d39dc7b3578da45861a2e1340f67b30ec8e4624fcc).
Telegraph's current validator rejected that first descriptor because every
`on_chain.fields.*` mapping now requires a description. The emitted YAML was
corrected, tested, deployed, and re-hashed as:

```text
0x9841d385976c89586f4c80bee0cecfd8ded75cba605b9f921d779376460e01d4
```

The deployed Diamond confirmed the exact function
`updateMiner(uint256,string,bytes32,address,uint256,string[])`. The update
simulated successfully and was sent in
[transaction `0xd866...38a8`](https://sepolia.basescan.org/tx/0xd86632828b733200eb3ae3306df315d2be5e47eb8af0077f5fa690f538fa38a8).
It emitted `MinerDeregistered(309)`, `MinerRegistered(310)`,
`IntentRegistered(310)`, and `MinerUpdated(309,310)`. The replacement record
was independently read back with:

```text
registration ID: 310
activation status: active
intent: URL_SCAN
slug: proofgate-url-intelligence
YAML hash: 9841d385...460e01d4
rejection reason: null
```

The Track 1 portal then accepted a fresh EIP-191 challenge signature and the
exact 2,841-byte YAML file. The saved response was independently confirmed via
the portal's "My Submissions" API:

```text
submission ID: 6a930a4aae9ddfbc70a760d9
track: miner
item ID: 310
item verified: true
submission status: verified
saved: true
X username: karanyadav38450
created: 2026-08-29T16:35:22.708Z
```

The verified item also carried the informational string
`Ownership could not be determined` and `githubUrl: null`. Those fields are
recorded rather than interpreted: the portal independently returned
`item.verified: true`, overall `status: verified`, and `saved: true`.

The fresh wallet retained `1` testnet USDC. These registration transactions
used Base Sepolia test ETH gas only; production x402 payment remains disabled.

## Screenshot Provenance

| Artifact | Evidence class | Network/payment behavior |
| --- | --- | --- |
| `production-console-desktop.png` | live production | public page load only |
| `production-console-mobile.png` | live production | public page load only |
| `verified-allow-execution.png` | historical receipt replay | no new request; fields copied from the recorded audit receipt |
| `fail-closed-warn.png` | deterministic fixture | guard route intercepted before network; no payment, no target request |
| `malicious-block.png` | deterministic fixture | invalid fixture domain; guard route intercepted; no payment, no target request |

The outcome screenshots are generated by
[`scripts/capture-readme-screenshots.mjs`](../scripts/capture-readme-screenshots.mjs).
Chrome DevTools `Fetch` interception fulfills `/api/guard`, `/api/network`, and
`/api/audit` inside an isolated browser profile. Each non-live image is stamped
in-frame as either a verified receipt replay or deterministic fixture.

Recreate them:

```powershell
npm run docs:capture
```

Set `CHROME_PATH` if Chrome is installed elsewhere. The script requires no
wallet and must not be modified to pass through `/api/guard` when generating
documentation fixtures.

## Non-Claims

ProofGate does **not** claim that:

- the public Vercel deployment currently performs paid scans
- registration guarantees routing volume or leaderboard placement
- deterministic WARN/BLOCK screenshots are live network results
- every safe verdict guarantees a harmless destination
- missing provider keys count as clean evidence
- the hash chain encrypts records or externally witnesses its newest tail
- upstream Telegraph or reputation providers are always available

These boundaries are intentional and should remain visible in future releases.
