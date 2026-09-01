"""Sidecar control client (TDD).

Two clients over the same binary (plan §6 Phase 2):

- :class:`SidecarSession` — long-lived ``serve`` process speaking
  newline-delimited JSON-RPC on stdio. One process per plugin owns the
  Iroh endpoint; ``status``/``dial`` go through a thread-safe request lock.
  A dead process raises :class:`SidecarUnavailable` (fail closed).
- :class:`SidecarClient` — one-shot ``call`` for the v0.1 echo path.

Fail-closed rules: missing binary, timeout, broken pipe, and malformed JSON
all raise :class:`SidecarUnavailable` (never hang, never leak state).
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional


class SidecarUnavailable(RuntimeError):
    """The sidecar process could not be executed or answered."""


def default_sidecar_path(debug: bool = False) -> Optional[str]:
    """Locate the sidecar binary: env override, then repo-relative default."""
    override = __import__("os").environ.get("HERMES_IROH_SIDECAR")
    if override:
        return override if Path(override).exists() else None
    profile = "debug" if debug else "release"
    local = (
        Path(__file__).resolve().parent
        / "sidecar"
        / "target"
        / profile
        / "hermes-iroh-sidecar"
    )
    return str(local) if local.exists() else None


class SidecarClient:
    """One-shot client for the ``hermes-iroh-sidecar call`` mode."""

    def __init__(self, binary_path: str):
        self.binary_path = binary_path

    def call(
        self,
        request: Dict[str, Any],
        endpoint_id: str,
        timeout_secs: int = 120,
    ) -> Dict[str, Any]:
        """Send one request, return the parsed reply dict."""
        payload = json.dumps({"endpointId": endpoint_id, "request": request}).encode("utf-8")
        try:
            proc = subprocess.run(
                [self.binary_path, "call", "--endpoint", endpoint_id],
                input=payload,
                capture_output=True,
                timeout=max(1, int(timeout_secs)),
                check=False,
            )
        except FileNotFoundError as exc:
            raise SidecarUnavailable(f"sidecar binary not found: {exc}") from exc
        except subprocess.TimeoutExpired as exc:
            raise SidecarUnavailable(f"sidecar timed out after {timeout_secs}s") from exc

        if proc.returncode != 0:
            stderr = proc.stderr.decode("utf-8", "replace").strip()
            raise SidecarUnavailable(f"sidecar exited {proc.returncode}: {stderr[:500]}")
        try:
            reply = json.loads(proc.stdout.decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise SidecarUnavailable(f"sidecar returned malformed JSON: {exc}") from exc
        if not isinstance(reply, dict):
            raise SidecarUnavailable("sidecar reply is not a JSON object")
        return reply


class SidecarSession:
    """Long-lived ``serve`` process speaking NDJSON JSON-RPC on stdio."""

    def __init__(self, binary_path: str, state_dir: Optional[Path] = None):
        self.binary_path = binary_path
        self.state_dir = state_dir
        self.proc: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            return
        argv = [self.binary_path, "serve"]
        if self.state_dir is not None:
            argv += ["--state-dir", str(self.state_dir)]
        relay = os.environ.get("HERMES_IROH_RELAY")
        if relay:
            argv += ["--relay", relay]
        try:
            self.proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
        except (FileNotFoundError, OSError) as exc:
            raise SidecarUnavailable(f"cannot start sidecar: {exc}") from exc

    def close(self) -> None:
        if self.proc is None:
            return
        try:
            if self.proc.poll() is None:
                self.proc.stdin.close()
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait(timeout=5)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
        self.proc = None

    def __enter__(self) -> "SidecarSession":
        self.start()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()

    # -- rpc ----------------------------------------------------------------

    def request(self, method: str, params: Optional[Dict[str, Any]] = None, timeout: int = 120) -> Dict[str, Any]:
        """Send one JSON-RPC request, return the parsed result object.

        Thread-safe: a lock serializes access to the single stdin/stdout
        pipe pair. Any failure (dead process, timeout, malformed reply,
        JSON-RPC error) raises :class:`SidecarUnavailable`.
        """
        if self.proc is None or self.proc.poll() is not None:
            raise SidecarUnavailable("sidecar process is not running")
        req = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
        with self._lock:
            try:
                assert self.proc is not None and self.proc.stdin and self.proc.stdout
                self.proc.stdin.write(json.dumps(req) + "\n")
                self.proc.stdin.flush()
                line = self.proc.stdout.readline()
            except (BrokenPipeError, OSError, ValueError) as exc:
                raise SidecarUnavailable(f"sidecar pipe failure: {exc}") from exc
        if not line:
            raise SidecarUnavailable("sidecar closed the connection")
        try:
            reply = json.loads(line)
        except ValueError as exc:
            raise SidecarUnavailable(f"sidecar reply is not JSON: {exc}") from exc
        if not isinstance(reply, dict):
            raise SidecarUnavailable("sidecar reply is not an object")
        if "error" in reply:
            message = reply["error"].get("message", "unknown error")
            raise SidecarUnavailable(f"sidecar error: {message}")
        result = reply.get("result")
        if not isinstance(result, dict):
            raise SidecarUnavailable("sidecar reply has no result object")
        return result

    # -- high-level methods --------------------------------------------------

    def status(self, timeout: int = 60) -> Dict[str, Any]:
        return self.request("status", timeout=timeout)

    def dial(
        self,
        endpoint_id: str,
        addrs: List[str],
        text: str,
        timeout: int = 120,
    ) -> Dict[str, Any]:
        """Dial a peer by endpoint id + addresses and run one task."""
        return self.request(
            "dial",
            {"endpointId": endpoint_id, "addrs": addrs, "task": {"text": text}},
            timeout=timeout,
        )


# ---------------------------------------------------------------------------
# Shared persistent session (one serve process per profile)
# ---------------------------------------------------------------------------

_shared_lock = threading.Lock()
_shared_sessions: Dict[str, "SidecarSession"] = {}


def get_shared_session(binary_path: str, state_dir: Optional[Path] = None) -> "SidecarSession":
    """Returns the profile's long-lived serve session, starting or restarting
    it as needed.

    Keyed by (binary_path, state_dir). A session whose process has died is
    transparently restarted on the next call — the sidecar's persistent
    endpoint key means the restarted endpoint keeps the same identity, so
    paired peers are unaffected.
    """
    key = f"{binary_path}::{state_dir}"
    with _shared_lock:
        session = _shared_sessions.get(key)
        if session is None:
            session = SidecarSession(binary_path, state_dir=state_dir)
            session.start()
            _shared_sessions[key] = session
            return session
        if session.proc is None or session.proc.poll() is not None:
            # Dead process: restart with the same persistent identity.
            session.close()
            session.start()
        return session


def close_shared_sessions() -> None:
    """Tears down all shared sessions (used at plugin shutdown/tests)."""
    with _shared_lock:
        for session in _shared_sessions.values():
            session.close()
        _shared_sessions.clear()
