"""Tests for the iroh-interconnect tool layer (TDD).

Contract (plan §4 v1 tool surface):
- iroh_peer_status: read-only, reports sidecar availability + identity.
- iroh_peer_list:   read-only, lists paired peers (no secrets in output).
- iroh_peer_pair:   validates a ticket offline and records the peer.
- iroh_peer_call:   sends one bounded task; bounded response; fail-closed
                    on unknown peers.
- Secrets never appear in tool output.
"""

import json
from pathlib import Path

import pytest

import peer_tools as iroh_tools
from security import PeerStore


@pytest.fixture()
def peer_env(tmp_path, monkeypatch):
    """Isolated plugin state dir per test."""
    monkeypatch.setenv("HERMES_IROH_STATE_DIR", str(tmp_path / "state"))
    return tmp_path / "state"


class TestPeerStatus:
    def test_reports_unavailable_when_no_sidecar(self, peer_env, monkeypatch):
        monkeypatch.setenv("HERMES_IROH_SIDECAR", "/nonexistent/sidecar")
        out = json.loads(iroh_tools.iroh_peer_status({}, task_id=None))
        assert out["success"] is True
        assert out["sidecar_available"] is False

    def test_reports_state_dir(self, peer_env):
        out = json.loads(iroh_tools.iroh_peer_status({}, task_id=None))
        assert out["success"] is True
        assert "peers" in out


class TestPeerList:
    def test_empty_then_populated(self, peer_env):
        assert json.loads(iroh_tools.iroh_peer_list({}, task_id=None))["peers"] == {}
        store = PeerStore(peer_env)
        store.add_peer("p1", {"endpoint_id": "abc", "added": "now"})
        out = json.loads(iroh_tools.iroh_peer_list({}, task_id=None))
        assert "p1" in out["peers"]
        # No secret material in output.
        assert "secret" not in json.dumps(out)


class TestPeerPair:
    @staticmethod
    def _ticket(peer="bbbbbbbbbbbbbbbb", nonce=None):
        import time as _time

        ts = int(_time.time())
        nonce = nonce or "ab12cd34ef56ab12cd34ef56ab12cd34"
        return (
            f"hermes-iroh://pair?peer={peer}"
            f"&secret=longenoughsecretvalue1&ts={ts}&nonce={nonce}"
        )

    def test_requires_confirmation_before_pairing(self, peer_env):
        out = json.loads(
            iroh_tools.iroh_peer_pair({"ticket": self._ticket()}, task_id=None)
        )
        assert out["success"] is False
        assert "confirm" in out["error"].lower()
        # Nothing paired yet.
        assert PeerStore(peer_env).get_peer("bbbbbbbbbbbbbbbb") is None

    def test_pairs_with_valid_ticket_and_confirmation(self, peer_env):
        out = json.loads(
            iroh_tools.iroh_peer_pair(
                {"ticket": self._ticket(), "confirm": True}, task_id=None
            )
        )
        assert out["success"] is True, out
        assert PeerStore(peer_env).get_peer("bbbbbbbbbbbbbbbb") is not None

    def test_rejects_replayed_ticket(self, peer_env):
        ticket = self._ticket()
        first = json.loads(
            iroh_tools.iroh_peer_pair(
                {"ticket": ticket, "confirm": True}, task_id=None
            )
        )
        assert first["success"] is True
        replay = json.loads(
            iroh_tools.iroh_peer_pair(
                {"ticket": ticket, "confirm": True}, task_id=None
            )
        )
        assert replay["success"] is False
        assert "replay" in replay["error"].lower() or "already used" in replay["error"].lower()

    def test_rejects_expired_ticket(self, peer_env):
        import time as _time

        old_ts = int(_time.time()) - 3600
        ticket = (
            "hermes-iroh://pair?peer=bbbbbbbbbbbbbbbb"
            "&secret=longenoughsecretvalue1"
            f"&ts={old_ts}&nonce={'ab12cd34ef56ab12cd34ef56ab12cd34'}"
        )
        out = json.loads(
            iroh_tools.iroh_peer_pair({"ticket": ticket, "confirm": True}, task_id=None)
        )
        assert out["success"] is False
        assert "expired" in out["error"].lower()

    def test_rejects_invalid_ticket(self, peer_env):
        out = json.loads(iroh_tools.iroh_peer_pair({"ticket": "garbage"}, task_id=None))
        assert out["success"] is False
        assert "error" in out

    def test_requires_ticket_arg(self, peer_env):
        out = json.loads(iroh_tools.iroh_peer_pair({}, task_id=None))
        assert out["success"] is False


class TestMakeTicket:
    def test_issues_fresh_ticket(self, peer_env, monkeypatch):
        # A fake sidecar binary that answers `id` offline.
        Path(peer_env).mkdir(parents=True, exist_ok=True)
        fake = Path(peer_env) / "fake-sidecar.sh"
        fake.write_text(
            "#!/bin/sh\n"
            'echo \'{"endpointId": "ym1ba7mr7ezejfkrumg1ryxiauts1xdx5fzitwobrh9oxxuqahno"}\'\n'
        )
        fake.chmod(0o755)
        monkeypatch.setenv("HERMES_IROH_SIDECAR", str(fake))
        out = json.loads(iroh_tools.iroh_peer_make_ticket({}, task_id=None))
        assert out["success"] is True
        ticket = out["ticket"]
        assert ticket.startswith("hermes-iroh://pair?")
        assert "ts=" in ticket and "nonce=" in ticket
        assert out["expires_in_seconds"] == 900
        # The ticket it just issued validates and pairs end-to-end.
        parsed = json.loads(
            iroh_tools.iroh_peer_pair(
                {"ticket": ticket, "confirm": True}, task_id=None
            )
        )
        assert parsed["success"] is True

    def test_reports_missing_identity(self, peer_env, monkeypatch):
        monkeypatch.setenv("HERMES_IROH_SIDECAR", "/nonexistent/sidecar")
        out = json.loads(iroh_tools.iroh_peer_make_ticket({}, task_id=None))
        assert out["success"] is False
        assert "endpoint" in out["error"].lower()


class TestPeerCall:
    def test_fails_closed_on_unknown_peer(self, peer_env):
        out = json.loads(
            iroh_tools.iroh_peer_call({"peer": "ghost", "message": "hi"}, task_id=None)
        )
        assert out["success"] is False
        assert "unknown" in out["error"].lower() or "not paired" in out["error"].lower()

    def test_requires_peer_and_message(self, peer_env):
        out = json.loads(iroh_tools.iroh_peer_call({"peer": "x"}, task_id=None))
        assert out["success"] is False

    def test_reports_transport_unavailable_when_sidecar_missing(self, peer_env, monkeypatch):
        monkeypatch.setenv("HERMES_IROH_SIDECAR", "/nonexistent/sidecar")
        store = PeerStore(peer_env)
        store.add_peer("p9", {"endpoint_id": "zzz", "secret": "s"})
        out = json.loads(
            iroh_tools.iroh_peer_call({"peer": "p9", "message": "hello"}, task_id=None)
        )
        assert out["success"] is False
        assert "sidecar" in out["error"].lower()


class TestRegistration:
    def test_register_tools_via_ctx(self, peer_env, monkeypatch):
        registered = {}

        class FakeCtx:
            def register_tool(self, name, toolset, schema, handler, **kwargs):
                registered[name] = handler

        iroh_tools.register_tools(FakeCtx())
        assert set(registered) == {
            "iroh_peer_status",
            "iroh_peer_list",
            "iroh_peer_pair",
            "iroh_peer_make_ticket",
            "iroh_peer_call",
            "iroh_send_file",
            "iroh_fetch_file",
            "iroh_transfer_status",
        }
        # Handlers dispatch with the real registry's args-dict convention.
        out = json.loads(registered["iroh_peer_list"]({}, task_id=None))
        assert out["success"] is True
