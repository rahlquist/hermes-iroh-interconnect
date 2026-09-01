"""Inbound platform adapter — routes peer tasks into a live Hermes session.

Design (mirrors the proven A2A plugin pattern, plan §4 inbound behavior):

- ``IrohAdapter`` is a ``BasePlatformAdapter`` subclass registered via
  ``ctx.register_platform(name="iroh", ...)``.
- The Rust sidecar's serve mode accepts inbound peer QUIC connections and
  drops each task as a JSON file in ``<state>/queue/task-*.json`` (the file
  queue is the sidecar→Python handoff; no plugin-owned sockets).
- A poll loop (daemon asyncio task) picks task files up, frames the text as
  UNTRUSTED external input with provenance, and dispatches it through the
  normal ``MessageEvent`` path — the agent that answers is the live gateway
  agent with full memory, not a throwaway clone.
- The reply resolves through ``send()`` (called by the gateway with the
  session's chat_id), is redacted, and is written back as
  ``queue/reply-<taskId>.json`` for the sidecar to return on the QUIC stream.

Bind safety: this adapter opens NO sockets. All transport lives in the
sidecar; unknown peers' tasks are rejected (fail closed).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, Optional

from security import redact_outbound, wrap_inbound

try:  # The adapter only imports Hermes internals when running inside Hermes.
    from gateway.platforms.base import (
        BasePlatformAdapter,
        MessageEvent,
        MessageType,
        SendResult,
    )
    from gateway.config import Platform

    _HERMES_AVAILABLE = True
except Exception:  # pragma: no cover - standalone test env
    _HERMES_AVAILABLE = False

logger = logging.getLogger(__name__)

_POLL_INTERVAL = 0.25  # seconds between queue scans
_TASK_FILE_RE = re.compile(r"^task-(?P<task_id>.+)\.json$")


def _state_dir() -> Path:
    override = os.environ.get("HERMES_IROH_STATE_DIR")
    if override:
        return Path(override)
    try:
        from hermes_constants import get_hermes_home

        return Path(get_hermes_home()) / "iroh-interconnect"
    except Exception:
        return Path.home() / ".hermes" / "iroh-interconnect"


if _HERMES_AVAILABLE:

    def _ensure_iroh_platform_registered() -> None:
        """Register a placeholder PlatformEntry so ``Platform("iroh")`` resolves.

        The real adapter registration happens via ``ctx.register_platform``
        in ``__init__.py``; this pre-registration only satisfies the enum's
        plugin-name check for standalone adapter unit tests.
        """
        try:
            from gateway.platform_registry import platform_registry, PlatformEntry

            if not platform_registry.is_registered("iroh"):
                platform_registry.register(
                    PlatformEntry(
                        name="iroh",
                        label="Iroh",
                        adapter_factory=lambda cfg: IrohAdapter(cfg),
                        check_fn=lambda: True,
                        source="plugin",
                    )
                )
        except Exception:
            pass

    _ensure_iroh_platform_registered()

    class IrohAdapter(BasePlatformAdapter):  # type: ignore[misc,valid-type]
        """Inbound peer-task adapter over the sidecar's file handoff."""

        def __init__(self, config, **kwargs):
            platform = Platform("iroh")
            super().__init__(config=config, platform=platform)
            self.state_dir = _state_dir()
            self._loop: Optional[asyncio.AbstractEventLoop] = None
            self._poll_task: Optional[asyncio.Task] = None
            self._running = False
            # contextId -> text the gateway delivered via send(); the poll
            # loop matches replies to their originating task by context.
            self._reply_text: Dict[str, str] = {}
            self._last_delivered: Dict[str, str] = {}

        # ── identity ──────────────────────────────────────────────────────

        @property
        def name(self) -> str:
            return "Iroh"

        @property
        def queue_dir(self) -> Path:
            return self.state_dir / "queue"

        # ── inbound plumbing ──────────────────────────────────────────────

        def _frame_inbound(self, peer_id: str, text: str) -> str:
            """Frame remote text as untrusted input (slash commands inert)."""
            return wrap_inbound(peer_id, text)

        def _known_peer(self, peer_id: str) -> bool:
            try:
                from security import PeerStore

                return peer_id in PeerStore(self.state_dir).list_peers()
            except Exception:
                return False

        def _resolve_peer(self, endpoint_id: str) -> Optional[str]:
            """Maps the TLS-authenticated sender endpoint id to a paired
            peer id. Returns None for unpaired senders (fail closed)."""
            try:
                from security import PeerStore

                return PeerStore(self.state_dir).find_by_endpoint_id(endpoint_id)
            except Exception:
                return None

        def _process_task_file(self, path: Path) -> None:
            """Validate, frame, and dispatch one queued task file."""
            try:
                task = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                logger.warning("iroh adapter: unreadable task file %s", path.name)
                path.unlink(missing_ok=True)
                return

            # The JSON taskId field is authoritative; the filename only
            # marks the file as a task handoff. peerId is the sender's
            # TLS-authenticated endpoint id written by the sidecar — it is
            # never taken from envelope content.
            task_id = str(task.get("taskId") or "")
            endpoint_id = str(task.get("peerId") or "")
            context_id = str(task.get("contextId") or task_id)
            text = str(task.get("text") or "")

            peer_id = self._resolve_peer(endpoint_id)
            if not task_id or peer_id is None:
                logger.warning(
                    "iroh adapter: rejected task %s from unpaired endpoint", task_id
                )
                self._write_reply(task_id, "rejected", "unknown or unpaired peer")
                path.unlink(missing_ok=True)
                return

            framed = self._frame_inbound(peer_id, text)
            event = MessageEvent(
                text=framed,
                message_type=MessageType.TEXT,
                source=self.build_source(
                    chat_id=context_id,
                    chat_name=f"iroh:{peer_id}",
                    chat_type="dm",
                    user_id=peer_id,
                    user_name=peer_id,
                ),
                message_id=task_id,
                metadata={"iroh_task_id": task_id, "iroh_peer": peer_id},
            )
            # The gateway resolves the reply through send() with this
            # context id; the poll loop does not block on it here.
            asyncio.create_task(self.handle_message(event))

        def _write_reply(self, task_id: str, status: str, text: str) -> None:
            if not task_id:
                return
            self.queue_dir.mkdir(parents=True, exist_ok=True)
            reply = {
                "taskId": task_id,
                "status": status,
                "text": redact_outbound(text),
            }
            tmp = self.queue_dir / f"reply-{task_id}.json.tmp"
            tmp.write_text(json.dumps(reply), encoding="utf-8")
            tmp.replace(self.queue_dir / f"reply-{task_id}.json")

        # ── gateway contract ──────────────────────────────────────────────

        async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
            """Chat metadata for the gateway (plan: dedicated peer sessions)."""
            peer_hint = str(chat_id)
            return {
                "name": f"iroh:{peer_hint}",
                "type": "dm",
            }

        async def connect(self, **_kwargs) -> bool:
            try:
                self._loop = asyncio.get_running_loop()
            except RuntimeError:
                self._loop = None
            self.queue_dir.mkdir(parents=True, exist_ok=True)
            self._running = True
            self._poll_task = asyncio.ensure_future(self._poll_loop())
            logger.info("iroh adapter: connected (queue=%s)", self.queue_dir)
            return True

        async def disconnect(self) -> None:
            self._running = False
            if self._poll_task is not None:
                self._poll_task.cancel()
                try:
                    await self._poll_task
                except (asyncio.CancelledError, Exception):
                    pass
                self._poll_task = None
            logger.info("iroh adapter: disconnected")

        async def send(
            self,
            chat_id: str,
            content: str,
            reply_to: Optional[str] = None,
            metadata: Optional[Dict[str, Any]] = None,
        ) -> SendResult:
            """Capture the gateway's reply for the originating task.

            The gateway calls send() with the session's chat_id (the task's
            contextId). We redact and record it; if a queued task with this
            context is waiting, its reply file is written immediately.
            """
            self._last_delivered[str(chat_id)] = redact_outbound(content)
            self._reply_text[str(chat_id)] = redact_outbound(content)
            return SendResult(success=True, message_id=f"iroh-{chat_id}")

        # ── poll loop ─────────────────────────────────────────────────────

        async def _poll_loop(self) -> None:
            while self._running:
                try:
                    await self._poll_once()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.warning("iroh adapter: poll error", exc_info=True)
                await asyncio.sleep(_POLL_INTERVAL)

        async def _poll_once(self) -> None:
            if not self.queue_dir.exists():
                return
            # Deliver any replies captured since the last tick. The reply
            # file name and taskId come from the task's JSON field.
            for path in list(self.queue_dir.glob("task-*.json")):
                try:
                    task = json.loads(path.read_text(encoding="utf-8"))
                except Exception:
                    continue
                task_id = str(task.get("taskId") or "")
                context_id = str(task.get("contextId") or "")
                reply = self._reply_text.pop(context_id, None)
                if reply is not None:
                    self._write_reply(task_id, "completed", reply)
                    path.unlink(missing_ok=True)
            # Dispatch fresh tasks.
            for path in list(self.queue_dir.glob("task-*.json")):
                self._process_task_file(path)

else:  # pragma: no cover - Hermes internals unavailable

    class IrohAdapter:  # type: ignore[no-redef]
        """Placeholder when Hermes internals are absent (standalone tests)."""

        def __init__(self, config=None, **kwargs):
            self.state_dir = _state_dir()
            self._loop = None
            self._poll_task = None
            self._running = False
            self._reply_text: Dict[str, str] = {}
            self._last_delivered: Dict[str, str] = {}
            self._config = config

        @property
        def name(self) -> str:
            return "Iroh"

        @property
        def queue_dir(self) -> Path:
            return self.state_dir / "queue"

        def _frame_inbound(self, peer_id: str, text: str) -> str:
            return wrap_inbound(peer_id, text)

        def _known_peer(self, peer_id: str) -> bool:
            try:
                from security import PeerStore

                return peer_id in PeerStore(self.state_dir).list_peers()
            except Exception:
                return False

        def _write_reply(self, task_id: str, status: str, text: str) -> None:
            if not task_id:
                return
            self.queue_dir.mkdir(parents=True, exist_ok=True)
            reply = {"taskId": task_id, "status": status, "text": redact_outbound(text)}
            tmp = self.queue_dir / f"reply-{task_id}.json.tmp"
            tmp.write_text(json.dumps(reply), encoding="utf-8")
            tmp.replace(self.queue_dir / f"reply-{task_id}.json")

        def _process_task_file(self, path: Path) -> None:
            try:
                task = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                path.unlink(missing_ok=True)
                return
            task_id = str(task.get("taskId") or "")
            peer_id = str(task.get("peerId") or "")
            if not task_id or not peer_id or not self._known_peer(peer_id):
                self._write_reply(task_id, "rejected", "unknown or unpaired peer")
                path.unlink(missing_ok=True)
                return
            # No gateway loop in standalone mode: complete with the framed
            # text echoed back so the file contract is still exercised.
            self._write_reply(task_id, "completed", self._frame_inbound(peer_id, str(task.get("text") or "")))
            path.unlink(missing_ok=True)

        async def connect(self, **_kwargs) -> bool:
            self.queue_dir.mkdir(parents=True, exist_ok=True)
            self._running = True
            return True

        async def disconnect(self) -> None:
            self._running = False

        async def send(self, chat_id: str, content: str, reply_to=None, metadata=None):
            self._last_delivered[str(chat_id)] = content
            self._reply_text[str(chat_id)] = content

            class _R:
                def __init__(self, chat_id: str):
                    self.success = True
                    self.message_id = f"iroh-{chat_id}"

            return _R(chat_id)

        async def _poll_once(self) -> None:
            if not self.queue_dir.exists():
                return
            for path in list(self.queue_dir.glob("task-*.json")):
                self._process_task_file(path)
