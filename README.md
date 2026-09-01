# hermes-iroh-interconnect

> [!WARNING]
> **Alpha software.** This plugin is under active development. The wire
> protocol (`hermes-interconnect` v1) may change without migration, inbound
> peer authentication mapping is not yet wired (see `docs/security.md`),
> and it has not been hardened against adversarial peers outside the test
> suite. Do not connect it to untrusted agents. Pin the exact commit you
> install and re-read `docs/security.md` before enabling inbound use.

Agent interconnect for [Hermes Agent](https://github.com/NousResearch/hermes-agent)
over [Iroh](https://github.com/n0-computer/iroh): dial-by-key QUIC with NAT
traversal and relay fallback. Implements the interconnection model proven in
Codux on Hermes' native plugin surface.

> [!NOTE]
> **Unaffiliated community project.** This plugin is an independent,
> third-party extension — not an official Nous Research product, and not
> endorsed by or affiliated with Nous Research, n0-computer (Iroh), or
> duxweb (Codux). Hermes, Iroh, and Codux are the properties of their
> respective owners.

**Architecture** (per the feasibility plan, §2):

```
Hermes agent process
  └─ Python plugin (this repo)
      ├─ model-visible peer tools (iroh toolset)
      ├─ pairing / trust / redaction policy
      └─ one-shot sidecar control client
             │ localhost stdio
             ▼
        hermes-iroh-sidecar (Rust, sidecar/)
          ├─ Iroh Endpoint / SecretKey (pinned iroh 1.0.0)
          ├─ bounded 4-byte length-prefixed JSON frames (4 MiB cap)
          ├─ versioned envelope: hermes-interconnect v1
          └─ ALPN /hermes/interconnect/1
```

Status: **v0.3-alpha — bidirectional transport plus optional artifacts**.
Real QUIC peer dialing, persistent endpoint identity, serve-mode control
plane, inbound authorization, admission hardening, relay configuration, and
optional SendMe-backed file transfer are implemented and covered end-to-end:
a real QUIC peer → sidecar file handoff → adapter → reply back over QUIC
runs green in CI-style tests. File transfer is delegated to SendMe when
installed; without it, the task interconnect remains fully functional.
Ring-based authorization remains staged (see "Roadmap").

### Optional file transfer

The plugin exposes `iroh_send_file`, `iroh_fetch_file`, and
`iroh_transfer_status` through the `iroh` toolset. They use the installed
SendMe CLI (`sendme`) and are optional: if SendMe is unavailable, the tools
return an actionable install message and do not affect peer/task exchange.
Install and verify it with:

```bash
cargo install --locked sendme
sendme --version
```

A SendMe sender must remain running until the receiver completes. Treat its
ticket as a bearer capability and share it only with the intended peer.

## What's verified (v0.3-alpha)

- Two live sidecar processes dial each other over real QUIC and exchange
  tasks (Rust `serve_process` tests; Python `SidecarSession` tests).
- A full inbound chain: remote QUIC peer → file handoff → adapter reply →
  back over the wire (`full_chain_e2e.rs`).
- Persistent endpoint identity across sidecar restarts (0600 key file).
- Inbound tasks from unknown peers are rejected (fail closed).
- Outbound calls to unreachable peers fail bounded (no hang, structured
  error, no partial state).
- Optional SendMe-backed file transfer tools are registered without making
  SendMe a plugin dependency. If `sendme` is absent, they return an
  actionable install/verify message; all task interconnect functionality
  continues to work normally.

## Install

```bash
# 1. Build the sidecar (requires cargo)
cd sidecar && cargo build --release

# 2. Install the plugin into Hermes
mkdir -p ~/.hermes/plugins
ln -s "$(pwd)" ~/.hermes/plugins/hermes-iroh-interconnect

# 3. Enable it
hermes plugins enable hermes-iroh-interconnect
```

## Tools

| Tool | Purpose | Side effects |
|---|---|---|
| `iroh_peer_status` | Sidecar availability, state dir, peer count | Read-only |
| `iroh_peer_list` | Paired peers (id, endpoint, timestamps — no secrets) | Read-only |
| `iroh_peer_pair` | Record a peer from a `hermes-iroh://pair?...` ticket | Durable peer record |
| `iroh_peer_call` | One bounded task to one paired peer | Network request, audited |

## Testing

```bash
# Rust: framing, envelope, and real loopback QUIC round trip
cd sidecar && cargo test

# Python: security, tools, real Hermes PluginManager load, live sidecar
python -m pytest tests/
```

The Hermes integration tests load the plugin through the real
`PluginManager` against a temp `HERMES_HOME` (they are skipped when no
Hermes checkout exists at `~/.hermes/hermes-agent`).

## Security

See [docs/security.md](docs/security.md) for the trust model. Summary:

- Peer identity is the Iroh endpoint public key, authenticated by the QUIC
  TLS 1.3 handshake — never a peer-claimed name.
- Pairing tickets are validated offline; peer state is stored 0600 in the
  profile-scoped plugin data dir.
- Inbound text is framed as untrusted external input with provenance; slash
  commands embedded in peer text are neutralized.
- Outbound text is scrubbed of credential-shaped strings (defense in depth).
- Every frame is size-bounded before allocation; malformed input fails
  closed with a structured `task.error`.

## License

MIT. The Iroh dependency is dual MIT/Apache-2.0.
