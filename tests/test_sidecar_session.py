"""RED tests for the long-lived sidecar session client (TDD).

Contract:
- SidecarSession spawns `serve --state-dir` once, speaks NDJSON JSON-RPC,
  and survives many requests on one process.
- request() is thread-safe (a lock serializes the single stdin pipe).
- Dead process / broken pipe raises SidecarUnavailable (fail closed).
- status() reports endpoint id + addrs; dial() performs a real task call.
"""

import json
import subprocess
import threading

import pytest

import sidecar_client
from sidecar_client import SidecarSession, SidecarUnavailable


@pytest.fixture()
def sidecar_binary():
    path = sidecar_client.default_sidecar_path(debug=True)
    if path is None:
        pytest.fail("debug sidecar binary not built")
    return path


def test_status_roundtrip(sidecar_binary, tmp_path):
    with SidecarSession(sidecar_binary, state_dir=tmp_path) as session:
        status = session.status(timeout=60)
    assert status["ready"] is True
    assert len(status["endpointId"]) == 52
    assert status["alpn"] == "/hermes/interconnect/1"
    assert isinstance(status["addrs"], list)


def test_one_process_many_requests(sidecar_binary, tmp_path):
    with SidecarSession(sidecar_binary, state_dir=tmp_path) as session:
        for _ in range(5):
            status = session.status(timeout=30)
            assert status["ready"] is True


def test_unknown_method_raises(sidecar_binary, tmp_path):
    with SidecarSession(sidecar_binary, state_dir=tmp_path) as session:
        with pytest.raises(SidecarUnavailable):
            session.request("explode", {}, timeout=15)


def test_dead_process_fails_closed(sidecar_binary, tmp_path):
    session = SidecarSession(sidecar_binary, state_dir=tmp_path)
    session.start()
    session.proc.kill()
    session.proc.wait()
    with pytest.raises(SidecarUnavailable):
        session.status(timeout=15)


def test_thread_safe_requests(sidecar_binary, tmp_path):
    with SidecarSession(sidecar_binary, state_dir=tmp_path) as session:
        assert session.status(timeout=60)["ready"] is True
        errors = []

        def worker():
            try:
                for _ in range(3):
                    assert session.status(timeout=30)["ready"] is True
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors, errors


def test_dial_real_peer_to_peer(sidecar_binary, tmp_path):
    """Two sessions dial each other over real QUIC: B's inbound task goes
    through the file handoff, answered by a simulated adapter thread."""
    stop = threading.Event()

    def fake_adapter(queue_dir):
        while not stop.is_set():
            try:
                entries = list(queue_dir.glob("task-*.json"))
            except OSError:
                entries = []
            for entry in entries:
                try:
                    task = json.loads(entry.read_text())
                except Exception:
                    continue
                task_id = task.get("taskId")
                if task_id:
                    reply = {
                        "taskId": task_id,
                        "status": "completed",
                        "text": f"echo: {task.get('text', '')}",
                    }
                    (queue_dir / f"reply-{task_id}.json").write_text(
                        json.dumps(reply)
                    )
            stop.wait(0.05)

    with SidecarSession(sidecar_binary, state_dir=tmp_path / "a") as a, \
         SidecarSession(sidecar_binary, state_dir=tmp_path / "b") as b:
        status_b = b.status(timeout=60)
        worker = threading.Thread(
            target=fake_adapter, args=(tmp_path / "b" / "queue",), daemon=True
        )
        worker.start()
        try:
            reply = a.dial(
                endpoint_id=status_b["endpointId"],
                addrs=status_b["addrs"],
                text="hello from A",
                timeout=90,
            )
        finally:
            stop.set()
            worker.join(timeout=5)
    assert reply["status"] == "completed"
    assert "hello from A" in reply["text"]


def test_shared_session_reuses_one_process(sidecar_binary, tmp_path):
    """get_shared_session returns the same live session for the same key."""
    key_dir = tmp_path / "shared"
    s1 = sidecar_client.get_shared_session(sidecar_binary, key_dir)
    pid1 = s1.proc.pid
    s2 = sidecar_client.get_shared_session(sidecar_binary, key_dir)
    assert s2 is s1
    assert s2.proc.pid == pid1
    sidecar_client.close_shared_sessions()


def test_shared_session_restarts_dead_process(sidecar_binary, tmp_path):
    """A killed sidecar is transparently restarted with the same identity."""
    key_dir = tmp_path / "restart"
    session = sidecar_client.get_shared_session(sidecar_binary, key_dir)
    status1 = session.status(timeout=60)
    session.proc.kill()
    session.proc.wait(timeout=5)

    session2 = sidecar_client.get_shared_session(sidecar_binary, key_dir)
    status2 = session2.status(timeout=60)
    # Persistent identity: the restarted endpoint keeps the same endpoint id.
    assert status2["endpointId"] == status1["endpointId"]
    sidecar_client.close_shared_sessions()


def test_shared_sessions_teardown(sidecar_binary, tmp_path):
    sidecar_client.get_shared_session(sidecar_binary, tmp_path / "t1")
    sidecar_client.close_shared_sessions()
    assert sidecar_client._shared_sessions == {}


def test_unused_import_guard():
    # Keep the module's subprocess usage honest (used for kill on close).
    assert hasattr(sidecar_client, "subprocess")
