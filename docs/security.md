# Security model

Scope: v0.3.1 — bidirectional task exchange (outbound dialing + inbound
adapter + admission guard + operator-configurable relay). This document
states what is enforced, what is deferred, and what the operator must not
assume.

## Identity and trust chain

1. **Transport identity (Iroh).** Each endpoint holds a persistent Ed25519
   `SecretKey`; the public key is the `EndpointId`. Every QUIC connection is
   mutually authenticated by TLS 1.3 with key-anchored certificates, so a
   peer's `EndpointId` is cryptographically proven, not claimed.
2. **Pairing (v0.3).** A
   `hermes-iroh://pair?peer=<id>&secret=...&ts=...&nonce=...` ticket is
   validated *offline* by `security.validate_ticket` — scheme, host,
   peer-id charset, secret length, **expiry** (15 minutes) and **nonce
   shape** are enforced before anything is stored. The nonce is single-use
   (`NonceStore`, 0600); replays are refused after confirmation. The ticket
   secret is stored with the paired endpoint record and sent inside every task
   envelope; the receiving adapter compares it in constant time before
   dispatch. A forged ticket therefore cannot authenticate task traffic.
   Pairing additionally requires an explicit `confirm=true` tool argument; this
   is an application confirmation gate, not yet a desktop/operator approval
   prompt.
3. **Peer state.** Peers live in `<HERMES_HOME>/iroh-interconnect/peers.json`
   with mode `0600` (enforced on every write and repaired on open).

## What is enforced (fail-closed)

- **Frame bounds.** 4-byte big-endian length prefix; lengths above 4 MiB are
  rejected *before allocation* on both sides of the wire.
- **Envelope validation.** Protocol name, version, message type, and required
  fields are checked; malformed envelopes yield a structured `task.error`.
  Invalid framing, UTF-8, truncated reads, and read timeouts close the stream
  without dispatching input.
- **Unknown peers and forged task credentials.** `iroh_peer_call` refuses any peer not in the store;
  inbound tasks are authorized by the sender's **TLS-authenticated Iroh
  endpoint id** (captured at the QUIC connection, not taken from envelope
  content) mapped through the peer store — unpaired senders get a
  structured `rejected` reply and their task is never dispatched to the
  agent.
- **Missing sidecar.** Calls fail closed with an actionable message rather
  than silently degrading.
- **Bounded failures.** A peer that cannot be dialed produces a structured
  error after the configured timeout — no hang, no partial state, and
  `last_called` is not updated on failure.
- **Inbound admission guard.** Every inbound request passes a guard before
  reaching the task engine: `requestId` replay is rejected (dedupe window),
  total concurrent tasks are capped (8), and each peer is rate-limited
  (30 req/min sliding window). Rejected requests get a structured
  `task.error`; the agent is never invoked.
- **Outbound redaction.** Bearer tokens, `secret|token|password|api_key=...`
  shapes, and PEM private keys are masked before text leaves the process
  (outbound tool text and adapter replies).
- **Secrets in tool output.** `iroh_peer_list` and `iroh_peer_status` never
  return ticket secrets.
- **Persistent identity.** The endpoint key is 0600; a corrupt key file
  fails closed with recovery instructions instead of silently re-keying
  (which would strand paired peers).

## What is deferred (do not assume it exists yet)

- **Ring-based authorization (iroh-rings).** Deferred by plan §"conditional
  use": the pinned iroh-rings 0.7.0 gate would be enabled only behind a
  Hermes wrapper that fixes the `can_access` OR-bypass and `FsTransfer`
  range-count allocation. Not wired.
- **Pairing confirmation UX.** Landed in v0.3: tickets carry expiry +
  single-use nonces and pairing requires an explicit confirmation argument
  (`confirm=true`). This is an application-level gate; a dedicated
  desktop/operator approval prompt remains future work.
- **Relay policy (v0.3).** The relay set is now operator-configurable via
  `HERMES_IROH_RELAY` / the sidecar's `--relay` flag: `default` (n0 public
  relays), `off` (LAN-only, direct addrs required), or a self-hosted relay
  URL. Public relays observe connection metadata (never plaintext);
  LAN-only operation removes even that exposure.

## Known limitations

- The sidecar's inbound admission state (replay windows, rate counters) is
  in-memory and resets on restart. Authorization does not depend on it —
  the adapter's peer-store check and the bounded handoff remain the
  boundary — but a restart briefly resets rate limiting.
- `peers.json`, `endpoint.key`, and `pairing.secret` are plaintext at rest.
  Filesystem access is a separate trust boundary; files are 0600 but not
  encrypted.
- The confirmation gate is tool-arg based: the agent must re-invoke
  `iroh_peer_pair` with `confirm=true`. The ticket nonce is consumed only
  after confirmation. A desktop UI surface for the prompt is a future item.
- Automatic file fetching is disabled by default because it performs a local
  write selected by a peer-supplied destination. If enabled, configure
  `HERMES_IROH_AUTO_FETCH_DIR`; destinations outside that receiver-owned root
  are rejected.
- `HERMES_IROH_INSECURE_TLS` disables relay certificate verification and is
  for isolated development/testing only; production deployments must use a
  trusted certificate.
- The sidecar's serve process dies on stdin EOF (plugin-owned lifecycle).
  Operator-run instances should pass `--keep-alive`.
- The Rust dependency graph contains the transitive, unmaintained `paste`
  crate through Iroh's network-discovery stack. It is not directly used by
  this plugin; revisit it when the upstream dependency graph removes it and
  keep the lockfile vulnerability audit in CI.
