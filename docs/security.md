# Security model

Scope: v0.2 — bidirectional task exchange (outbound dialing + inbound
adapter). This document states what is enforced, what is deferred, and what
the operator must not assume.

## Identity and trust chain

1. **Transport identity (Iroh).** Each endpoint holds a persistent Ed25519
   `SecretKey`; the public key is the `EndpointId`. Every QUIC connection is
   mutually authenticated by TLS 1.3 with key-anchored certificates, so a
   peer's `EndpointId` is cryptographically proven, not claimed.
2. **Pairing (v0.1).** A `hermes-iroh://pair?peer=<id>&secret=<n>=16 chars`
   ticket is validated *offline* by `security.validate_ticket` — scheme,
   host, peer-id charset, and secret length are enforced before anything is
   stored. Pairing is currently operator-driven (the operator obtains the
   ticket out-of-band and pairs through the tool).
3. **Peer state.** Peers live in `<HERMES_HOME>/iroh-interconnect/peers.json`
   with mode `0600` (enforced on every write and repaired on open).

## What is enforced (fail-closed)

- **Frame bounds.** 4-byte big-endian length prefix; lengths above 4 MiB are
  rejected *before allocation* on both sides of the wire.
- **Envelope validation.** Protocol name, version, message type, and required
  fields are checked; malformed input yields a structured `task.error`, never
  a panic or a pass-through.
- **Unknown peers.** `iroh_peer_call` refuses any peer not in the store;
  inbound tasks from unpaired endpoint ids are rejected at the adapter.
- **Missing sidecar.** Calls fail closed with an actionable message rather
  than silently degrading.
- **Bounded failures.** A peer that cannot be dialed produces a structured
  error after the configured timeout — no hang, no partial state, and
  `last_called` is not updated on failure.
- **Outbound redaction.** Bearer tokens, `secret|token|password|api_key=...`
  shapes, and PEM private keys are masked before text leaves the process
  (outbound tool text and adapter replies).
- **Secrets in tool output.** `iroh_peer_list` and `iroh_peer_status` never
  return ticket secrets.
- **Persistent identity.** The endpoint key is 0600; a corrupt key file
  fails closed with recovery instructions instead of silently re-keying
  (which would strand paired peers).

## What is deferred (do not assume it exists yet)

- **Inbound peer authentication mapping.** The adapter routes tasks into the
  gateway, but the sidecar's inbound handler does not yet map the
  authenticated Iroh `EndpointId` to a paired peer record (tasks are tagged
  `unknown-peer` and rejected by the adapter's peer check until the mapping
  lands with pairing). The cryptographic transport authentication is real;
  the peer-registry lookup on inbound is the remaining seam.
- **Ring-based authorization (iroh-rings).** Deferred by plan §"conditional
  use": the pinned iroh-rings 0.7.0 gate would be enabled only behind a
  Hermes wrapper that fixes the `can_access` OR-bypass and `FsTransfer`
  range-count allocation. Not wired in v0.2.
- **Pairing confirmation UX.** v0.2 trusts the operator's ticket handling.
  Human-in-the-loop confirmation and ticket expiry/single-use nonces are
  staged follow-ups.
- **Relay policy.** The sidecar currently uses the default relay set. Public
  relays observe connection metadata (not plaintext); self-hosted relay
  configuration is a follow-up.

## Known limitations

- The sidecar spawns one serve process per `iroh_peer_call` in v0.2 (the
  session is closed after each tool call). A persistent shared session with
  reconnect guards is the next transport milestone.
- The `open` ring, `FsTransfer`, and stock `Transfer::can_access` must never
  be enabled without the wrapper fixes described in the feasibility plan.
- `peers.json` and `endpoint.key` are plaintext at rest. Filesystem access
  is a separate trust boundary; files are 0600 but not encrypted.
