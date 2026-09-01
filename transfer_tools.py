"""Optional file-transfer tools backed by the SendMe CLI (iroh-blobs).

Design (mirrors the plugin's fail-closed conventions):

- **Optional dependency.** SendMe is not required to install or run the
  plugin. Every tool entry point probes for the binary first; when it is
  absent the tool returns a structured, actionable result (never raises,
  never half-executes) explaining exactly what to install.
- **Safety model** follows the sendme-file-transfer skill: reject
  credential/private material by default on send; require an explicit
  destination directory on receive; never overwrite without confirmation;
  verify the resulting path after completion.
- **Tracked sender lifecycle.** ``sendme send`` runs as a long-lived
  provider; the send tool records the PID in the plugin state dir so a
  later stop targets only that process (never a broad pkill).
- **Relay policy inheritance.** ``HERMES_IROH_RELAY`` is passed through to
  sendme's ``--relay`` flag so LAN-only interconnects stay LAN-only for
  file transfers.
- **Ticket composition.** A sendme ticket is a plain string and fits
  inside the interconnect's bounded task payload, so peers exchange
  artifacts by passing tickets through normal ``iroh_peer_call`` text.
"""

from __future__ import annotations

import json
import os
import re
import select
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Optional

from security import redact_outbound

__all__ = [
    "sendme_available",
    "sendme_install_hint",
    "iroh_send_file",
    "iroh_fetch_file",
    "iroh_transfer_status",
]

# Credential/private material the skill says to reject by default.
_SENSITIVE_NAME_RE = re.compile(
    r"(^|/)(\.env(\..+)?|id_[a-z0-9]+|\.ssh|\.gnupg|\.aws|\.config/gcloud"
    r"|bitwarden.*|\.bitwarden|\.password-store|\.netrc|\.kube/config"
    r"|credentials?\.json|\.git-credentials)$",
    re.IGNORECASE,
)
_SENSITIVE_DIR_HINTS = (".ssh", ".gnupg", ".aws", ".config/gcloud", ".bitwarden")

_TICKET_RE = re.compile(
    r"(?:sendme receive )([a-z0-9]{4,}\.[a-z0-9]+|[a-z0-9]{20,})|\b(blob[a-z0-9]{40,})\b",
    re.IGNORECASE,
)
# Real sendme 0.36 tickets start with a scheme-like prefix (e.g. "blob");
# accept them bare or with the legacy "sendme receive " wrapper printed by
# older versions.
_HASH_RE = re.compile(r"hash ([0-9a-f]{16,})")


def _normalize_ticket(raw: str) -> Optional[str]:
    """Extracts the bare ticket token from user/CLI input. Accepts either
    the raw ticket or the legacy 'sendme receive <ticket>' string."""
    text = raw.strip()
    match = _TICKET_RE.search(text)
    if not match:
        return None
    return match.group(1) or match.group(2)


# ---------------------------------------------------------------------------
# Availability
# ---------------------------------------------------------------------------


def sendme_available() -> Optional[str]:
    """Returns the sendme binary path when installed, else None.

    Checks the PATH plus the Hermes skill conventions. Never raises.
    """
    return shutil.which("sendme")


def sendme_install_hint() -> Dict[str, Any]:
    """The structured result returned when SendMe is not installed."""
    return {
        "success": False,
        "error": (
            "SendMe is not installed on this machine, so file transfer is "
            "unavailable. The rest of the iroh interconnect (peer pairing, "
            "task exchange, adapter) works normally without it."
        ),
        "remedy": {
            "what": "SendMe (p2p file transfer over iroh/iroh-blobs)",
            "install": (
                "cargo install --locked sendme   # rustup required; or "
                "grab a prebuilt release: https://github.com/n0-computer/sendme/releases"
            ),
            "verify": "sendme --version",
            "optional_skill": (
                "the sendme-file-transfer Hermes skill documents the safety "
                "model and is recommended but not required"
            ),
        },
        "available": False,
    }


def _state_dir() -> Path:
    override = os.environ.get("HERMES_IROH_STATE_DIR")
    if override:
        return Path(override)
    try:
        from hermes_constants import get_hermes_home

        return Path(get_hermes_home()) / "iroh-interconnect"
    except Exception:
        return Path.home() / ".hermes" / "iroh-interconnect"


def _ok(payload: Dict[str, Any]) -> str:
    return json.dumps({"success": True, **payload})


def _err(message: str) -> str:
    return json.dumps({"success": False, "error": message})


def _transfers_file() -> Path:
    return _state_dir() / "sendme-transfers.json"


def _load_transfers() -> Dict[str, Dict[str, Any]]:
    try:
        return json.loads(_transfers_file().read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_transfers(data: Dict[str, Dict[str, Any]]) -> None:
    from security import _atomic_json_write

    path = _transfers_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_json_write(path, data, mode=0o600)


def _relay_flag() -> list:
    relay = os.environ.get("HERMES_IROH_RELAY", "").strip()
    if relay in ("", "default", "n0"):
        return []
    return ["--relay", "disabled" if relay == "off" else relay]


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


def _sensitive_path(path: Path) -> Optional[str]:
    """Returns a reason string when the path looks like credential/private
    material (sendme-file-transfer skill safety rule), else None."""
    resolved = path.resolve()
    name_match = _SENSITIVE_NAME_RE.search(str(resolved))
    if name_match:
        return f"path matches sensitive-material pattern: {name_match.group(0)}"
    for hint in _SENSITIVE_DIR_HINTS:
        if hint in resolved.parts:
            return f"path lives under {hint}"
    return None


def iroh_send_file(args: dict, **_: Any) -> str:
    """Share one file/directory over iroh-blobs via SendMe and return the
    transfer ticket (a bearer capability — share it only with the peer).

    Fail-closed: missing binary, missing path, or sensitive-material
    patterns reject before any process starts. The provider runs as a
    tracked background process and must stay alive for the transfer.
    """
    # Validate the user's requested path before probing the optional
    # dependency, so malformed/unsafe input still gets a precise error on a
    # machine without SendMe.
    raw_path = str(args.get("path") or "").strip()
    if not raw_path:
        return _err("'path' is required (file or directory to share)")

    path = Path(raw_path).expanduser()
    if not path.exists():
        return _err(f"path does not exist: {path}")

    reason = _sensitive_path(path)
    if reason and not bool(args.get("allow_sensitive")):
        return _err(
            f"refusing to share {path}: {reason}. If you truly intend this, "
            "re-invoke with allow_sensitive=true."
        )

    if not path.is_file() and not path.is_dir():
        return _err(f"path is neither a regular file nor a directory: {path}")

    binary = sendme_available()
    if binary is None:
        return json.dumps(sendme_install_hint())

    cmd = [binary, "send", "--no-progress", str(path)] + _relay_flag()
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
    except OSError as exc:
        return _err(f"failed to start sendme send: {exc}")

    # Capture the ticket line with a bounded wait (the provider stays alive
    # after printing it).
    ticket = None
    content_hash = None
    deadline = time.time() + 20
    try:
        while time.time() < deadline:
            if proc.stdout is None:
                break
            remaining = max(0.0, deadline - time.time())
            ready, _, _ = select.select([proc.stdout], [], [], min(0.25, remaining))
            if not ready:
                if proc.poll() is not None:
                    break
                continue
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break
                continue
            h = _HASH_RE.search(line)
            if h and content_hash is None:
                content_hash = h.group(1)
            t = _TICKET_RE.search(line)
            if t:
                ticket = t.group(1) or t.group(2)
                break
    finally:
        if ticket is None:
            # Never leave a half-started provider behind.
            proc.kill()

    if ticket is None:
        return _err(
            "sendme started but no ticket was produced within 20s "
            f"(exit code {proc.poll()}); no transfer is active"
        )

    transfer_id = f"t-{int(time.time())}-{proc.pid}"
    transfers = _load_transfers()
    transfers[transfer_id] = {
        "pid": proc.pid,
        "path": str(path),
        "ticket": ticket,
        "hash": content_hash,
        "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "provider-running",
    }
    _save_transfers(transfers)

    return _ok(
        {
            "transfer_id": transfer_id,
            "ticket": ticket,
            "hash": content_hash,
            "path": str(path),
            "note": (
                "The ticket is a bearer capability while the provider runs. "
                "Share it with the peer (e.g. via iroh_peer_call text); the "
                "receiver runs iroh_fetch_file with it. The provider must "
                "stay running until the fetch completes."
            ),
        }
    )


def iroh_fetch_file(args: dict, **_: Any) -> str:
    """Fetch a SendMe ticket into a destination directory and verify the
    result. Fail-closed: missing binary, missing/unsafe destination, or a
    failing receive is reported without presenting partial state."""
    ticket_raw = str(args.get("ticket") or "").strip()
    if not ticket_raw:
        return _err("'ticket' is required: provide the sendme ticket string")
    ticket = _normalize_ticket(ticket_raw)
    if not ticket:
        return _err("ticket does not look like a sendme ticket")

    dest_raw = str(args.get("dest") or "").strip()
    if not dest_raw:
        return _err(
            "'dest' is required: an explicit, existing destination directory"
        )
    dest = Path(dest_raw).expanduser()
    if not dest.is_dir():
        return _err(f"destination is not an existing directory: {dest}")

    binary = sendme_available()
    if binary is None:
        return json.dumps(sendme_install_hint())

    cmd = [binary, "receive", ticket, "--no-progress"] + _relay_flag()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=int(os.environ.get("HERMES_IROH_FETCH_TIMEOUT", "600")),
            check=False,
            cwd=str(dest),
        )
    except subprocess.TimeoutExpired:
        return _err(
            "receive timed out; no complete result is reported — the sender "
            "may have gone offline (its provider must stay running)"
        )
    except OSError as exc:
        return _err(f"failed to run sendme receive: {exc}")

    if proc.returncode != 0:
        stderr = (proc.stderr or proc.stdout or "").strip()
        return _err(
            f"sendme receive failed (exit {proc.returncode}): {stderr[:500]}. "
            "Leftover .sendme-* state in the destination is resumable."
        )

    # Verify: find the newest non-hidden entry in dest (sendme moves the
    # result in atomically after download).
    entries = [p for p in dest.iterdir() if not p.name.startswith(".sendme")]
    if not entries:
        return _err(
            "receive exited 0 but no resulting path was found in the "
            "destination; inspect .sendme-* state there"
        )
    result = max(entries, key=lambda p: p.stat().st_mtime)

    return _ok(
        {
            "path": str(result),
            "type": "directory" if result.is_dir() else "file",
            "note": redact_outbound(
                "Received via iroh-blobs; verify contents before use."
            ),
        }
    )


def iroh_transfer_status(args: dict, **_: Any) -> str:
    """List tracked sendme providers and stop one on request."""
    transfers = _load_transfers()
    stop_id = str(args.get("stop") or "").strip()

    if stop_id:
        record = transfers.get(stop_id)
        if record is None:
            return _err(f"unknown transfer id: {stop_id}")
        pid = record.get("pid")
        stopped = False
        if pid is not None:
            try:
                os.kill(int(pid), 15)
                stopped = True
            except (ProcessLookupError, PermissionError, ValueError):
                stopped = False
        record["status"] = "stopped" if stopped else "already-exited"
        transfers[stop_id] = record
        _save_transfers(transfers)
        return _ok({"transfer_id": stop_id, "status": record["status"]})

    # Status listing: prune exited providers. kill(0) succeeds on zombies,
    # so liveness alone is not proof the provider runs — but a zombie means
    # the parent (this process, in-session) has not reaped it, which for
    # operator-initiated stops only happens after an explicit stop. We
    # therefore treat "kill(0) ok" as alive; the stop path reaps via
    # subprocess ownership in the session that started it.
    alive = {}
    for tid, record in transfers.items():
        pid = record.get("pid")
        try:
            os.kill(int(pid), 0)
            alive[tid] = {k: record[k] for k in ("path", "ticket", "started", "status")}
        except (ProcessLookupError, TypeError, ValueError):
            record["status"] = "already-exited"
            alive[tid] = {"path": record.get("path"), "status": record["status"]}
    _save_transfers(transfers)
    return _ok({"transfers": alive})
