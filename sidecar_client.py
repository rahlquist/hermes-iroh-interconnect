"""Sidecar control client (TDD).

Contract (plan §6 Phase 2):
- Spawns the sidecar binary, performs one JSON request over stdio, reads one
  bounded JSON reply.
- Fails closed: missing binary, timeout, and malformed output all raise
  :class:`SidecarUnavailable` (never hang, never leak partial state).
- v0.1 uses one-shot process-per-call. A long-lived stdio session is a
  follow-up once inbound pairing lands.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any, Dict, Optional


class SidecarUnavailable(RuntimeError):
    """The sidecar binary could not be executed or answered."""


class SidecarClient:
    """One-shot client for the ``hermes-iroh-sidecar`` binary."""

    def __init__(self, binary_path: str):
        self.binary_path = binary_path

    def call(
        self,
        request: Dict[str, Any],
        endpoint_id: str,
        timeout_secs: int = 120,
    ) -> Dict[str, Any]:
        """Send one request, return the parsed reply dict.

        Raises :class:`SidecarUnavailable` on any failure (missing binary,
        nonzero exit, timeout, malformed JSON). Never returns partial state.
        """
        payload = json.dumps(
            {"endpointId": endpoint_id, "request": request}
        ).encode("utf-8")
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
            raise SidecarUnavailable(
                f"sidecar exited {proc.returncode}: {stderr[:500]}"
            )
        try:
            reply = json.loads(proc.stdout.decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise SidecarUnavailable(f"sidecar returned malformed JSON: {exc}") from exc
        if not isinstance(reply, dict):
            raise SidecarUnavailable("sidecar reply is not a JSON object")
        return reply
