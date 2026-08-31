# ProofGate Security Model

ProofGate sits between an autonomous agent and an untrusted URL. Its primary
security property is simple: no target request is made unless a paid Telegraph
scan finishes and local policy returns `ALLOW`.

## Wallet and payment safety

- Use a dedicated Base Sepolia burner wallet with limited test funds.
- Keep `TELEGRAPH_EVM_PRIVATE_KEY` server-side in `.env.local` or the deployment
  platform's secret store.
- Never prefix the key with `NEXT_PUBLIC_`.
- Telegraph and target-origin payment caps are checked against x402 payment
  requirements before ProofGate signs them.
- ProofGate accepts only the configured Base Sepolia payment network.
- Payment caps reduce loss; they do not make an exposed private key safe.

Rotate and drain the burner wallet immediately if the key may have been
exposed.

## SSRF controls

Before execution, ProofGate:

- accepts only `http:` and `https:` URLs;
- rejects URL credentials, private hostnames, and nonstandard ports;
- resolves every returned address and rejects the target if any address is
  private, loopback, link-local, multicast, reserved, or otherwise non-public;
- pins a validated address into the Undici connection while preserving TLS SNI
  and the HTTP Host header;
- does not follow redirects;
- supports only `GET` and `HEAD`;
- caps the response body and stores only a bounded text preview.

The preflight scan does not itself authorize a redirect destination. A caller
must submit that new destination as a separate guarded action.

## Miner behavior

ProofGate's own Miner derives evidence from URL structure, DNS, RDAP, configured
reputation APIs, and one bounded reachability probe. Missing, rate-limited, or
failed providers are recorded and do not count as evidence of absence.

The reachability probe is the only contact the Miner makes with the submitted
target. It runs after the same public-address validation as the guarded
execution path, is pinned to the validated address so a second DNS answer cannot
redirect it inward, sends `HEAD` only, does not follow redirects, reads no
response body, and times out after 5 seconds. Nothing from the target is
rendered, executed, or stored beyond the status line and two response headers.

The benign verdict is `no_threat_signal`. ProofGate reports the absence of
threat evidence; it does not certify that a URL is safe.

Provider results are untrusted inputs. They are parsed into bounded normalized
records before aggregation.

## Audit ledger

The local JSONL ledger is append-only in normal operation. Serverless
deployments require Redis and use an atomic compare-and-append script so two
instances cannot silently fork the chain. ProofGate verifies storage before
starting a paid scan and verifies the complete chain before appending.

The chain detects edits, deletion from the middle, and reordering. It cannot
detect truncation of the newest records without an external witness, and it
does not encrypt target URLs or evidence. Protect the audit file with operating
system permissions and avoid storing sensitive query parameters in target
URLs.

## Deployment guidance

- Terminate TLS at a maintained reverse proxy or hosting platform.
- Configure `PROOFGATE_API_KEY`; production guard and audit routes fail closed
  without it and use constant-time bearer-key comparison.
- Configure Upstash Redis; Vercel guard/audit access fails closed without
  persistent storage.
- ProofGate applies per-identity request limits. Add platform-level firewall
  limits as a second layer before exposing a funded deployment.
- Apply platform-level request-size, concurrency, and rate limits.
- Keep provider keys and the wallet key out of build logs and client bundles.
- Monitor payment settlements and stop the service on unexplained spend.
- Back up audit records to append-only storage if they are used as evidence.

Development permits an unconfigured operator key for local use. Production
does not. The operator key entered in the console is held only in component
memory and is sent only to guard and audit routes.

## Reporting a vulnerability

Do not disclose wallet keys, provider keys, sensitive target URLs, or working
exploit details in a public issue. Once the repository is published, use its
private security-advisory channel. Until then, report the issue privately to
the project owner and include the affected route, impact, and a minimal
reproduction with secrets removed.