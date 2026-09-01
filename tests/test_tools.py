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
    def test_pairs_with_valid_ticket(self, peer_env):
        ticket = (
            "hermes-iroh://pair?peer=bbbbbbbbbbbbbbbb&secret=longenoughsecretvalue1"
        )
        out = json.loads(iroh_tools.iroh_peer_pair({"ticket": ticket}, task_id=None))
        assert out["success"] is True
        assert PeerStore(peer_env).get_peer("bbbbbbbbbbbbbbbb") is not None

    def test_rejects_invalid_ticket(self, peer_env):
        out = json.loads(iroh_tools.iroh_peer_pair({"ticket": "garbage"}, task_id=None))
        assert out["success"] is False
        assert "error" in out

    def test_requires_ticket_arg(self, peer_env):
        out = json.loads(iroh_tools.iroh_peer_pair({}, task_id=None))
        assert out["success"] is False


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
            "iroh_peer_call",
        }
        # Handlers dispatch with the real registry's args-dict convention.
        out = json.loads(registered["iroh_peer_list"]({}, task_id=None))
        assert out["success"] is True
