"""Client tools for the hermes-iroh-interconnect plugin.

Registered in the ``iroh`` toolset via ``register_tools(ctx)`` (plan §4):

- ``iroh_peer_status`` — read-only sidecar/identity/state report.
- ``iroh_peer_list``   — read-only list of paired peers (no secrets).
- ``iroh_peer_pair``   — offline ticket validation + durable peer record.
- ``iroh_peer_call``   — one bounded task to one paired peer via the sidecar.

All handlers follow the Hermes tool convention: ``(args: dict, **kw) -> str``
where the string is JSON with at least ``{"success": bool}``.

Module name note: this file is deliberately NOT named ``tools.py`` — that
would shadow Hermes core's ``tools`` package on ``sys.path`` and break plugin
discovery (``from tools.registry import registry``).
"""

from __future__ import annotations

import json
import os
import secrets as _secrets
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from security import (
    TICKET_MAX_AGE_SECONDS,
    InvalidTicket,
    NonceStore,
    PeerStore,
    redact_outbound,
    validate_ticket,
)
from transfer_tools import iroh_fetch_file, iroh_send_file, iroh_transfer_status

__all__ = [
    "register_tools",
    "iroh_fetch_file",
    "iroh_peer_call",
    "iroh_peer_list",
    "iroh_peer_make_ticket",
    "iroh_peer_pair",
    "iroh_peer_status",
    "iroh_send_file",
    "iroh_transfer_status",
]

_TOOLSET = "iroh"
_MAX_TASK_TEXT = 64_000  # bounded task payload (plan §5 frame cap is 4 MiB)
_MAX_REPLY_TEXT = 256_000


def _state_dir() -> Path:
    override = os.environ.get("HERMES_IROH_STATE_DIR")
    if override:
        return Path(override)
    try:
        from hermes_constants import get_hermes_home

        return Path(get_hermes_home()) / "iroh-interconnect"
    except Exception:
        return Path.home() / ".hermes" / "iroh-interconnect"


def _sidecar_path() -> Optional[str]:
    """Locate the sidecar binary: env override, then repo-relative default."""
    override = os.environ.get("HERMES_IROH_SIDECAR")
    if override:
        return override if Path(override).exists() else None
    local = Path(__file__).resolve().parent / "sidecar" / "target" / "release" / "hermes-iroh-sidecar"
    if local.exists():
        return str(local)
    return None


def _store() -> PeerStore:
    return PeerStore(_state_dir())


def _endpoint_id() -> Optional[str]:
    """This agent's endpoint id, via the sidecar's offline ``id`` subcommand
    (derives the public key from the persistent key file; binds nothing).
    Returns None when no identity exists yet."""
    sidecar = _sidecar_path()
    if not sidecar:
        return None
    try:
        proc = subprocess.run(
            [sidecar, "id", "--state-dir", str(_state_dir())],
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        return str(json.loads(proc.stdout.decode("utf-8", "replace"))["endpointId"])
    except Exception:
        return None


def _pairing_secret() -> str:
    """The local pairing secret: a stable random token stored 0600 in the
    state dir. Shared only via pairing tickets."""
    path = _state_dir() / "pairing.secret"
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    token = _secrets.token_urlsafe(24)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(token)
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    return token


def _ok(payload: Dict[str, Any]) -> str:
    return json.dumps({"success": True, **payload})


def _err(message: str) -> str:
    return json.dumps({"success": False, "error": message})


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


def iroh_peer_status(args: dict, **_: Any) -> str:
    """Report sidecar availability, state path, and peer count (read-only)."""
    sidecar = _sidecar_path()
    store = _store()
    return _ok(
        {
            "sidecar_available": sidecar is not None,
            "sidecar_path": sidecar,
            "state_dir": str(store.dir),
            "peers": len(store.list_peers()),
        }
    )


def iroh_peer_list(args: dict, **_: Any) -> str:
    """List paired peers without any secret material."""
    peers = {}
    for peer_id, record in _store().list_peers().items():
        peers[peer_id] = {
            "endpoint_id": record.get("endpoint_id", ""),
            "added": record.get("added", ""),
            "last_called": record.get("last_called", ""),
        }
    return _ok({"peers": peers})


def iroh_peer_pair(args: dict, **_: Any) -> str:
    """Validate a pairing ticket offline and record the peer durably.

    v0.3 fail-closed additions:

    - ticket expiry (``ts`` + ``TICKET_MAX_AGE_SECONDS``) enforced by
      ``validate_ticket`` — expired tickets are refused
    - single-use nonce: replayed tickets are refused via ``NonceStore``
    - human-in-the-loop confirmation: pairing requires ``confirm: true`` in
      the tool args. The first call without it returns a pending decision
      describing exactly what would be trusted, so the operator approves
      consciously rather than by reflex.
    """
    raw_ticket = str(args.get("ticket") or "").strip()
    if not raw_ticket:
        return _err("'ticket' is required (a hermes-iroh://pair?... string)")
    try:
        parsed = validate_ticket(raw_ticket)
    except InvalidTicket as exc:
        return _err(f"invalid ticket: {exc}")

    peer_id = parsed["peer_id"]
    state_dir = _state_dir()

    # Single-use enforcement: a nonce that was already consumed means this
    # exact ticket is being replayed.
    nonces = NonceStore(state_dir)
    if not nonces.mark_used(parsed["nonce"]):
        return _err("ticket already used (nonce replay) — request a fresh ticket")

    if not bool(args.get("confirm")):
        # Human-in-the-loop gate: do NOT pair; surface the decision.
        return _err(
            "pairing requires operator confirmation. Review and re-invoke with "
            f"confirm=true to trust peer {peer_id!r} (endpoint {peer_id!r}) for "
            "bidirectional task exchange on this machine."
        )

    store = PeerStore(state_dir)
    store.add_peer(
        peer_id,
        {
            "endpoint_id": peer_id,
            "secret": parsed["secret"],
            "added": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "last_called": "",
            "paired_via": "ticket",
            "ticket_ts": parsed["ts"],
        },
    )
    return _ok({"peer_id": peer_id, "paired": True})


def iroh_peer_make_ticket(args: dict, **_: Any) -> str:
    """Issue a fresh pairing ticket for THIS agent's endpoint id.

    The ticket embeds the endpoint id (peer), the pairing secret, an
    issuance timestamp, and a random single-use nonce. Share it out-of-band
    with the peer agent; it expires after ``TICKET_MAX_AGE_SECONDS``.
    """
    endpoint_id = _endpoint_id()
    if not endpoint_id:
        return _err(
            "endpoint id unavailable: the sidecar must have run once to "
            "generate the persistent endpoint key"
        )
    secret = _pairing_secret()
    nonce = _secrets.token_hex(16)
    ts = int(time.time())
    ticket = (
        f"hermes-iroh://pair?peer={endpoint_id}&secret={secret}"
        f"&ts={ts}&nonce={nonce}"
    )
    return _ok(
        {
            "ticket": ticket,
            "peer_id": endpoint_id,
            "expires_in_seconds": TICKET_MAX_AGE_SECONDS,
        }
    )


def iroh_peer_call(args: dict, **_: Any) -> str:
    """Send one bounded task to one paired peer via the sidecar.

    Fail-closed: unknown peers, missing sidecar, and oversized payloads are
    rejected before any network I/O. The reply is bounded and redacted.
    """
    peer_id = str(args.get("peer") or args.get("peer_id") or "").strip()
    message = str(args.get("message") or args.get("task") or "").strip()
    context_id = str(args.get("context_id") or "").strip()
    if not peer_id or not message:
        return _err("both 'peer' and 'message' are required")

    if len(message) > _MAX_TASK_TEXT:
        return _err(f"message exceeds the {_MAX_TASK_TEXT}-character task limit")

    store = _store()
    record = store.get_peer(peer_id)
    if record is None:
        return _err(f"peer '{peer_id}' is not paired; use iroh_peer_pair first")

    sidecar = _sidecar_path()
    if sidecar is None:
        return _err(
            "iroh sidecar binary is not available; build it with "
            "'cargo build --release' in the plugin's sidecar/ directory "
            "or set HERMES_IROH_SIDECAR to its path"
        )

    # Outbound redaction is defense in depth (plan §7).
    safe_message = redact_outbound(message)

    from sidecar_client import (
        SidecarUnavailable,
        default_sidecar_path,
        get_shared_session,
    )

    try:
        binary = os.environ.get("HERMES_IROH_SIDECAR") or default_sidecar_path()
        if not binary or not Path(binary).exists():
            return _err("sidecar binary vanished; check HERMES_IROH_SIDECAR")
        state_dir = _state_dir()
        # Persistent shared session: one serve process per profile, reused
        # across calls. A dead process is detected and restarted with a
        # fresh bound endpoint (same persistent identity).
        session = get_shared_session(binary, state_dir)
        reply = session.dial(
            endpoint_id=record.get("endpoint_id", peer_id),
            addrs=record.get("addrs") or [],
            text=safe_message,
            timeout=int(os.environ.get("HERMES_IROH_TIMEOUT", "120")),
        )
    except SidecarUnavailable as exc:
        return _err(f"peer call to '{peer_id}' failed: {exc}")
    except Exception as exc:  # bounded: transport failures become errors
        return _err(f"peer call to '{peer_id}' failed: {exc}")

    reply_text = str(reply.get("text") or "")[:_MAX_REPLY_TEXT]
    status_str = str(reply.get("status") or "failed")

    record["last_called"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    store.add_peer(peer_id, record)

    return _ok(
        {
            "peer": peer_id,
            "status": status_str,
            "text": reply_text,
            "error": str(reply.get("error") or ""),
        }
    )


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_tools(ctx: Any) -> None:
    """Register the four client tools with the Hermes tool registry."""
    ctx.register_tool(
        name="iroh_peer_status",
        toolset=_TOOLSET,
        schema={
            "name": "iroh_peer_status",
            "description": (
                "Report the Iroh interconnect status: sidecar availability, "
                "state directory, and paired peer count. Read-only."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
        handler=iroh_peer_status,
    )
    ctx.register_tool(
        name="iroh_peer_list",
        toolset=_TOOLSET,
        schema={
            "name": "iroh_peer_list",
            "description": (
                "List paired Iroh interconnect peers (id, endpoint, timestamps; "
                "no secrets). Read-only."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
        handler=iroh_peer_list,
    )
    ctx.register_tool(
        name="iroh_peer_pair",
        toolset=_TOOLSET,
        schema={
            "name": "iroh_peer_pair",
            "description": (
                "Pair with a peer using a hermes-iroh://pair?peer=...&secret=...&ts=...&nonce=... "
                "ticket. The ticket is validated offline (expiry + single-use nonce "
                "enforced) and the peer is stored in profile-scoped state. Requires "
                "operator confirmation: pass confirm=true after reviewing the ticket."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ticket": {"type": "string", "description": "Pairing ticket URI"},
                    "confirm": {
                        "type": "boolean",
                        "description": (
                            "Operator confirmation. First call WITHOUT this to surface "
                            "the decision, then re-invoke with confirm=true."
                        ),
                    },
                },
                "required": ["ticket"],
            },
        },
        handler=iroh_peer_pair,
    )
    ctx.register_tool(
        name="iroh_peer_make_ticket",
        toolset=_TOOLSET,
        schema={
            "name": "iroh_peer_make_ticket",
            "description": (
                "Issue a fresh single-use pairing ticket for THIS agent so a remote "
                "peer can pair with it. Share the ticket out-of-band; it expires in "
                "15 minutes and can be used exactly once."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
        handler=iroh_peer_make_ticket,
    )
    ctx.register_tool(
        name="iroh_send_file",
        toolset=_TOOLSET,
        schema={
            "name": "iroh_send_file",
            "description": (
                "Share one file or directory with a peer over iroh-blobs "
                "(via the SendMe CLI, if installed) and get a transfer "
                "ticket. Optional feature: requires sendme on this machine; "
                "otherwise returns install instructions."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File or directory to share",
                    },
                    "allow_sensitive": {
                        "type": "boolean",
                        "description": (
                            "Explicitly authorize sharing a path that "
                            "matches sensitive-material patterns"
                        ),
                    },
                },
                "required": ["path"],
            },
        },
        handler=iroh_send_file,
    )
    ctx.register_tool(
        name="iroh_fetch_file",
        toolset=_TOOLSET,
        schema={
            "name": "iroh_fetch_file",
            "description": (
                "Fetch a SendMe ticket into an explicit destination "
                "directory and verify the result. Optional feature: "
                "requires sendme on this machine; otherwise returns "
                "install instructions."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "ticket": {
                        "type": "string",
                        "description": "The sendme receive ticket string",
                    },
                    "dest": {
                        "type": "string",
                        "description": "Existing destination directory",
                    },
                },
                "required": ["ticket", "dest"],
            },
        },
        handler=iroh_fetch_file,
    )
    ctx.register_tool(
        name="iroh_transfer_status",
        toolset=_TOOLSET,
        schema={
            "name": "iroh_transfer_status",
            "description": (
                "List tracked SendMe providers (from iroh_send_file) or "
                "stop one by transfer id. Optional feature: requires "
                "sendme; otherwise returns install instructions."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "stop": {
                        "type": "string",
                        "description": "Transfer id to stop (from listing)",
                    },
                },
                "required": [],
            },
        },
        handler=iroh_transfer_status,
    )
    ctx.register_tool(
        name="iroh_peer_call",
        toolset=_TOOLSET,
        schema={
            "name": "iroh_peer_call",
            "description": (
                "Send one task to a paired peer over the Iroh QUIC transport "
                "and return its bounded reply. Requires a previously paired peer."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "peer": {"type": "string", "description": "Paired peer id"},
                    "message": {"type": "string", "description": "Task text (bounded)"},
                    "context_id": {
                        "type": "string",
                        "description": "Optional context id to continue a conversation",
                    },
                },
                "required": ["peer", "message"],
            },
        },
        handler=iroh_peer_call,
    )
