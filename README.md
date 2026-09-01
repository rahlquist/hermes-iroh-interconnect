# hermes-iroh-interconnect

Connect your Hermes agents directly over the internet or across private networks. This plugin gives one Hermes agent a secure, authenticated way to send another agent a task, receive the result, and optionally exchange files through SendMe — without relying on a central message broker or cloud service. You gain persistent agent identities, explicit operator-approved pairing, encrypted QUIC transport with NAT traversal and relay fallback, inbound peer authorization, replay/rate/concurrency protection, and a native Hermes platform adapter. In practical terms: your agents can collaborate as peers, delegate work across machines, and pass artifact-transfer tickets while retaining control over who is trusted and what leaves each host.

> [!WARNING]
> **Alpha software.** This plugin is under active development. The wire
> protocol (`hermes-interconnect` v1) may change without migration, and it
> has not been hardened against adversarial peers outside the test suite.
> Do not connect it to untrusted agents. Pin the exact commit you install
> and re-read `docs/security.md` before enabling inbound use.

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

## How the connection works

You do not connect to a ticket. A ticket is used once to pair two agents and
approve trust. After pairing, the receiving agent remembers the peer's stable
EndpointId. When a task is sent, Iroh uses that EndpointId to discover a
current network path, tries a direct encrypted QUIC connection, and can use a
relay when the two machines cannot connect directly. The relay helps locate or
forward traffic; it does not become the agent's identity and cannot read the
encrypted task contents.

The connection has two layers of protection:

1. **Iroh authentication** proves that the remote machine owns the private key
   belonging to the expected EndpointId.
2. **Hermes authorization** checks that EndpointId against the locally paired
   peer store, then applies replay, rate, and concurrency limits before the
   task reaches the agent.

If the network briefly disappears, the current task can fail or time out. The
sidecar stays available and a later task makes a fresh dial attempt; pairing
does not need to be repeated. Automatic retries are intentionally limited so a
non-idempotent task is not silently run twice.

### Connection diagrams

- [Architecture: what runs on each machine](docs/diagrams/interconnect-architecture.html)
- [Sequence: how one task is located, authenticated, and returned](docs/diagrams/connection-sequence.html)

The diagrams are also available as editable Archify source files in
`docs/diagrams/`. GitHub does not render standalone HTML files inside the
repository view; open them locally or publish them with GitHub Pages.

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

The plugin is optional with respect to SendMe. The three artifact tools remain
registered even when `sendme` is absent; they return an actionable install
message instead of preventing the Iroh task tools from loading.

```bash
# Verify the optional dependency
command -v sendme && sendme --version

# Optional transfer operations
# iroh_send_file: path -> ticket + transfer id
# iroh_fetch_file: ticket + existing destination directory -> verified path
# iroh_transfer_status: list or stop a tracked sender by transfer id
```

For a sender, keep the `sendme send` provider running until the receiver
finishes. Tickets are bearer capabilities. Do not put them in public channels.

### Relay configuration

`HERMES_IROH_RELAY` applies to both the Iroh sidecar and SendMe transfers.
The SendMe transfer tools are available only when the `sendme` executable is
installed; otherwise they return the install/verify instructions without
affecting task exchange.

- unset, `default`, or `n0`: use the default n0 relay set;
- `off`, `none`, or `disabled`: disable relays (direct/LAN addresses required);
- a relay URL: use that self-hosted relay.

The sidecar also accepts `--relay <default|off|URL>` and operator-run peers
can use `--keep-alive` when stdin is not owned by the plugin.

### Operator pairing flow

1. Run `iroh_peer_make_ticket` on the receiving agent.
2. Send the ticket out-of-band to the intended peer.
3. Run `iroh_peer_pair` once without `confirm` to review the proposed trust.
4. Re-run it with `confirm=true` to authorize the peer.
5. Tickets expire after 15 minutes and are single-use.

### CI and local verification

GitHub Actions runs `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo test`, and the Python suite on every push and pull request. The Python
CI job does not require Hermes source or SendMe; those are optional runtime
integrations and have dedicated local/integration tests.


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
