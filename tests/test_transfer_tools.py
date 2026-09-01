"""Tests for the optional SendMe-backed transfer tools (TDD).

Contract:
- Missing binary => structured install hint (success=false, remedy with
  install/verify commands), NEVER an exception and NEVER a partial run.
- send path validation: missing path rejected; sensitive-material paths
  rejected with allow_sensitive escape hatch.
- Provider lifecycle: send starts a tracked provider, records PID +
  ticket in 0600 state, stop targets only that PID.
- fetch: requires explicit existing dest; verifies result path.
- Relay flag inheritance from HERMES_IROH_RELAY.
"""

import json
import os
import signal
import subprocess
import time
from pathlib import Path

import pytest

import transfer_tools
from transfer_tools import (
    iroh_fetch_file,
    iroh_send_file,
    iroh_transfer_status,
    sendme_available,
    sendme_install_hint,
)


@pytest.fixture()
def transfer_env(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_IROH_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.delenv("HERMES_IROH_RELAY", raising=False)

    # Track and reap any provider children the tests start so pytest can
    # exit (a live child would otherwise hang the run).
    started = []

    real_popen = transfer_tools.subprocess.Popen

    def tracking_popen(*a, **kw):
        proc = real_popen(*a, **kw)
        started.append(proc)
        return proc

    monkeypatch.setattr(transfer_tools.subprocess, "Popen", tracking_popen)
    yield tmp_path
    for proc in started:
        if proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
    # Reap any children this test process still owns (zombies block exit).
    import time as _time

    deadline = _time.time() + 5
    while _time.time() < deadline and started:
        try:
            done_pid, _ = os.waitpid(-1, os.WNOHANG)
            if done_pid == 0:
                _time.sleep(0.1)
            else:
                started[:] = [p for p in started if p.pid != done_pid]
        except ChildProcessError:
            break
    for proc in started:
        try:
            proc.wait(timeout=1)
        except (subprocess.TimeoutExpired, ChildProcessError):
            pass


class TestAvailability:
    def test_install_hint_shape(self):
        hint = sendme_install_hint()
        assert hint["success"] is False
        assert "SendMe is not installed" in hint["error"]
        assert "cargo install" in hint["remedy"]["install"]
        assert hint["remedy"]["verify"] == "sendme --version"

    def test_missing_binary_returns_hint_not_exception(self, transfer_env, monkeypatch):
        monkeypatch.setenv("PATH", "/nonexistent-bin")
        # Force re-resolution.
        monkeypatch.setattr(transfer_tools.shutil, "which", lambda _: None)
        out = json.loads(iroh_send_file({"path": "/tmp"}, task_id=None))
        assert out["success"] is False
        assert "remedy" in out
        out = json.loads(iroh_fetch_file({"ticket": "sendme receive 4abcdtickeq1234567890abcdef1234567890abcd", "dest": "/tmp"}, task_id=None))
        assert out["success"] is False
        assert "remedy" in out


class TestSendFile:
    def test_requires_path(self, transfer_env):
        out = json.loads(iroh_send_file({}, task_id=None))
        assert out["success"] is False

    def test_rejects_missing_path(self, transfer_env):
        out = json.loads(iroh_send_file({"path": "/no/such/file"}, task_id=None))
        assert out["success"] is False
        assert "does not exist" in out["error"]

    def test_rejects_sensitive_paths(self, transfer_env, tmp_path):
        secret = tmp_path / "id_ed25519"
        secret.write_text("fake")
        out = json.loads(iroh_send_file({"path": str(secret)}, task_id=None))
        assert out["success"] is False
        assert "sensitive" in out["error"]

    def test_sensitive_override(self, transfer_env, tmp_path, monkeypatch):
        secret = tmp_path / "id_ed25519"
        secret.write_text("fake")
        self._with_fake_sendme(monkeypatch, tmp_path)
        out = json.loads(
            iroh_send_file(
                {"path": str(secret), "allow_sensitive": True}, task_id=None
            )
        )
        assert out["success"] is True, out

    @staticmethod
    def _with_fake_sendme(monkeypatch, tmp_path):
        """A fake sendme: prints the ticket, lingers ~30s (provider), exits.

        The provider-tracking test asserts liveness within that window; the
        fixture's teardown reaps the child either way, so nothing can hang
        the run.
        """
        fake = tmp_path / "fake-sendme.sh"
        fake.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "send" ]; then\n'
            '  printf \'imported file %s, 11 B, hash abcdef0123456789abcdef0123456789\\n\' "$4"\n'
            '  printf \'sendme receive 4abcdtickeq1234567890abcdef1234567890abcd\\n\'\n'
            "  sleep 2\n"
            'elif [ "$1" = "receive" ]; then\n'
            '  mkdir -p "$PWD/received-file" && echo data > "$PWD/received-file/data.txt"\n'
            "  exit 0\n"
            "fi\n"
        )
        fake.chmod(0o755)
        monkeypatch.setattr(transfer_tools, "sendme_available", lambda: str(fake))

    def test_send_starts_tracked_provider(self, transfer_env, tmp_path, monkeypatch):
        payload = tmp_path / "doc.txt"
        payload.write_text("hello")
        self._with_fake_sendme(monkeypatch, tmp_path)
        out = json.loads(iroh_send_file({"path": str(payload)}, task_id=None))
        assert out["success"] is True, out
        assert out["ticket"] == "4abcdtickeq1234567890abcdef1234567890abcd"
        assert out["hash"] == "abcdef0123456789abcdef0123456789"

        transfers = json.loads(iroh_transfer_status({}, task_id=None))
        tid = out["transfer_id"]
        assert transfers["transfers"][tid]["status"] == "provider-running"
        pid = transfers["transfers"][tid].get("pid") or _pid_from_state(transfer_env, tid)
        assert pid
        os.kill(int(pid), 0)  # provider alive

        # Stop targets exactly that provider. The fake provider is a child
        # of this test process, so after SIGTERM we must wait() to reap it
        # (kill(0) succeeds on zombies). The real plugin reaps when its
        # session polls the provider.
        stopped = json.loads(iroh_transfer_status({"stop": tid}, task_id=None))
        assert stopped["status"] == "stopped"
        pid_int = int(pid)
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                os.waitpid(pid_int, os.WNOHANG)
                os.kill(pid_int, 0)
                time.sleep(0.1)
            except (ProcessLookupError, ChildProcessError):
                break
        with pytest.raises((ProcessLookupError, ChildProcessError)):
            os.kill(pid_int, 0)

    def test_relay_flag_inherited(self, transfer_env, tmp_path, monkeypatch):
        payload = tmp_path / "r.txt"
        payload.write_text("x")
        seen = {}
        fake = tmp_path / "fake-sendme-relay.sh"
        fake.write_text(
            "#!/bin/sh\n"
            'echo "$@" > /tmp/sendme-args-captured\n'
            'echo "sendme receive 4abcdtickeq1234567890abcdef1234567890abcd"\n'
            "sleep 300\n"
        )
        fake.chmod(0o755)
        monkeypatch.setattr(transfer_tools, "sendme_available", lambda: str(fake))
        monkeypatch.setenv("HERMES_IROH_RELAY", "off")
        out = json.loads(iroh_send_file({"path": str(payload)}, task_id=None))
        assert out["success"] is True
        args = Path("/tmp/sendme-args-captured").read_text()
        assert "--relay disabled" in args
        _kill_provider(out)


def _pid_from_state(state_dir, transfer_id):
    data = json.loads((Path(state_dir) / "state" / "sendme-transfers.json").read_text())
    return data[transfer_id]["pid"]


def _kill_provider(send_out):
    tid = send_out["transfer_id"]
    iroh_transfer_status({"stop": tid}, task_id=None)


class TestFetchFile:
    def test_requires_dest(self, transfer_env):
        out = json.loads(
            iroh_fetch_file({"ticket": "sendme receive 4abcdtickeq1234567890abcdef1234567890abcd"}, task_id=None)
        )
        assert out["success"] is False
        assert "dest" in out["error"]

    def test_rejects_missing_dest(self, transfer_env):
        out = json.loads(
            iroh_fetch_file(
                {"ticket": "sendme receive abc", "dest": "/no/such/dir"}, task_id=None
            )
        )
        assert out["success"] is False

    def test_fetch_verifies_result(
        self, transfer_env, tmp_path, monkeypatch
    ):
        TestSendFile._with_fake_sendme(monkeypatch, tmp_path)
        dest = tmp_path / "downloads"
        dest.mkdir()
        out = json.loads(
            iroh_fetch_file(
                {
                    "ticket": "sendme receive 4abcdtickeq1234567890abcdef1234567890abcd",
                    "dest": str(dest),
                },
                task_id=None,
            )
        )
        assert out["success"] is True, out
        assert (Path(out["path"]) / "data.txt").exists()
