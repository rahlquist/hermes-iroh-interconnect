# Hermes Iroh Interconnect — Visual Guide

This guide explains the plugin without assuming networking or Iroh experience. The diagrams are standalone **Archify** documents. Open the `.html` files in a browser to use the dark/light theme toggle and export controls. The source JSON beside each diagram is the editable source.

## The short version

Two or more Hermes agents can work together like this:

1. Each machine has a permanent cryptographic identity.
2. An operator pairs the machines once using a short-lived approval ticket.
3. A sender chooses a paired peer by its stable identity.
4. Iroh finds a network path: direct first, relay when necessary.
5. The sidecars establish encrypted QUIC and authenticate the remote identity.
6. The receiving plugin checks its local trust policy before handing text to Hermes.
7. For files, the task channel carries a short-lived `send_hermes` ticket; the file bytes travel through the separate file provider.

The relay is a traffic/path service. It is not the owner of either agent's identity and cannot read the encrypted task payload.

## Diagram index

| Diagram | Answers | Open |
|---|---|---|
| System architecture | What runs on each machine? What does the relay do? | [HTML](diagrams/01-system-architecture.html) · [source](diagrams/01-system-architecture.architecture.json) |
| Pairing workflow | How do I link two agents safely? | [HTML](diagrams/02-pairing.html) · [source](diagrams/02-pairing.workflow.json) |
| Task call sequence | What happens during `iroh_peer_call`? | [HTML](diagrams/03-task-call.html) · [source](diagrams/03-task-call.sequence.json) |
| File transfer dataflow | How does a file move without putting file bytes in the task channel? | [HTML](diagrams/04-file-transfer.html) · [source](diagrams/04-file-transfer.dataflow.json) |
| Inbound handoff lifecycle | What does the receiver do with an incoming task or file ticket? | [HTML](diagrams/05-inbound-handoff.html) · [source](diagrams/05-inbound-handoff.lifecycle.json) |
| Many-client topology | How does this work with three or more clients? | [HTML](diagrams/06-many-clients.html) · [source](diagrams/06-many-clients.architecture.json) |

## 1. System architecture: what runs where

![Hermes Iroh system architecture](diagrams/how-hermes-agents-connect.svg)

Each client has two important processes:

- **Python plugin:** exposes Hermes tools, stores paired peers, enforces policy, and connects inbound work to the Hermes session.
- **Rust sidecar:** owns the Iroh endpoint, private key, QUIC connections, ALPN, framing, and network path selection.

The two local processes communicate over standard input/output. Sidecars communicate over encrypted QUIC. The relay is outside both machines and is used for discovery or forwarding when a direct path is unavailable.

## 2. Pairing: linking two agents

Pairing is an approval operation, not a permanent network connection.

- The receiving agent creates a ticket and an SVG QR code containing the same pairing data.
- The operator passes the ticket privately or shows/scans the QR with the intended peer.
- The other operator reviews the endpoint identity and expiration.
- `confirm=true` records the peer locally.
- The ticket is then discarded. Future calls use the stored EndpointId.

A ticket is single-use and expires after 15 minutes. If the ticket names the wrong machine, is expired, or has already been consumed, the operation fails closed.

## 3. Task calls: text and results

`iroh_peer_call` sends a bounded text task. It does not send arbitrary shell commands or grant the other agent access to the machine.

The sender's sidecar finds a current network path, authenticates the receiver's EndpointId during QUIC/TLS, and sends a versioned, size-bounded JSON frame. The receiver's sidecar writes a queue handoff. The receiver's plugin checks the authenticated sender against its paired-peer registry, frames the text as **untrusted external input**, and delivers it to Hermes. The reply follows the same path in reverse.

If the network disappears, the current call fails with a bounded error. Pairing remains valid; the next call performs fresh discovery. The system deliberately does not blindly replay non-idempotent work.

## 4. File transfers: two channels, not one

A task and a file are different things:

- **Task channel:** encrypted Hermes/Iroh message carrying the provider ticket and transfer metadata.
- **File channel:** `send_hermes` provider streams the actual file bytes and verifies them with Iroh Blobs.

The sender must keep `send_hermes` running until the receiver finishes. The ticket is a bearer capability: anyone who obtains it may be able to fetch the file, so never post it publicly.

With a paired Hermes peer and `auto_fetch` explicitly enabled by the receiver:

1. `iroh_send_file` starts and tracks `send_hermes`.
2. The sender sends the ticket through the authenticated task channel.
3. The receiving adapter validates the peer and ticket.
4. The adapter runs `send_hermes receive` into the requested existing destination directory.
5. The receiver verifies the resulting file and the provider can finish.

Set `auto_fetch=false` when the receiving operator wants to review each incoming file before fetching it.

## 5. Inbound handoff: receiver decision points

Every inbound frame passes through bounded validation and authorization. Unknown peers, replayed request IDs, malformed envelopes, and oversized frames are rejected. A valid task is written to the sidecar queue and the adapter produces a reply file.

For a file ticket:

- **Auto-fetch enabled:** fetch automatically after peer and ticket validation.
- **Auto-fetch disabled:** surface the ticket to the agent so a human can decide.
- **No adapter reply:** the sidecar returns a bounded timeout instead of hanging forever.

Remote text is never treated as a trusted Hermes command. The adapter adds provenance and neutralizes leading slash commands.

## 6. Three or more clients

There is no central “mesh trust” switch. Every client has its own stable identity and local paired-peer registry. Pairing A with B does not automatically trust C or D.

A relay can serve many clients, but it does not replace per-peer authorization. Iroh attempts direct paths where possible; the relay is the fallback path when NAT, firewall, or network topology prevents direct connectivity.

## Operator checklist

Before testing:

- Install and enable the plugin on every participating Hermes host.
- Build or install the same `send_hermes` version on every host that transfers files.
- Pair only intended peers and verify the EndpointId before confirming.
- Configure the same trusted relay URL on all clients.
- For a self-hosted relay, expose HTTPS/WebSocket TCP 3443 (or trusted HTTPS 443) and QUIC UDP 7842. TCP 3340 is the relay HTTP/API port, not the Iroh WebSocket endpoint.
- Use a publicly trusted certificate in production. `HERMES_IROH_INSECURE_TLS=1` is for the current self-signed test deployment only.
- Keep provider processes alive until transfers complete.
- Verify the destination path and resulting file hash; ticket creation is not transfer completion.

## Troubleshooting map

| Symptom | First check |
|---|---|
| Pairing rejected | Ticket expiry, nonce reuse, exact EndpointId, and `confirm=true` |
| `No addressing information` | Relay URL inherited by the sidecar process |
| First call times out | Relay WebSocket/TLS reachability and UDP 7842; inspect sidecar trace logs |
| Relay receives but drops packets | Destination sidecar is not registered on the same relay; check HTTPS/WebSocket TCP port |
| File provider hangs | Sender is still running; both sides use the same `send_hermes` build |
| File ticket arrives but no fetch | Receiving plugin is installed/enabled and `auto_fetch` setting is what you expect |
| Remote text looks like a command | It should be displayed as untrusted framed text, not executed as a command |

## Implementation boundary

The plugin intentionally separates concerns:

```text
Hermes plugin  →  trust, policy, tools, adapter, file-ticket handoff
Rust sidecar   →  Iroh endpoint, identity, QUIC, ALPN, framing
send_hermes    →  file provider and verified byte transfer
Relay          →  discovery and encrypted packet forwarding
```

This separation makes a failure diagnosable: a task timeout, a relay registration problem, an adapter handoff problem, and a file-provider problem are different failure classes.
