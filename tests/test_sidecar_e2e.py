"""E2E: peer_tools.iroh_peer_call through the real release sidecar binary.

Proves the full Python -> binary -> JSON reply chain with the actual
artifact built from the Rust workspace (not a mock).
"""

import json
import os
import sys
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent
SIDECAR = PLUGIN_DIR / "sidecar" / "target" / "release" / "hermes-iroh-sidecar"

pytestmark = pytest.mark.skipif(
    not SIDECAR.exists(),
    reason="release sidecar not built (run: cargo build --release in sidecar/)",
)


@pytest.fixture()
def tool_env(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_IROH_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("HERMES_IROH_SIDECAR", str(SIDECAR))
    if str(PLUGIN_DIR) not in sys.path:
        sys.path.insert(0, str(PLUGIN_DIR))
    yield


def test_status_sees_release_sidecar(tool_env):
    import peer_tools as iroh_tools

    out = json.loads(iroh_tools.iroh_peer_status({}, task_id=None))
    assert out["success"] is True
    assert out["sidecar_available"] is True
    assert out["sidecar_path"] == str(SIDECAR)


def test_pair_then_call_through_real_sidecar(tool_env):
    import peer_tools as iroh_tools
    from security import PeerStore

    store = PeerStore(Path(os.environ["HERMES_IROH_STATE_DIR"]))
    store.add_peer("livepeer01", {"endpoint_id": "livepeer01", "secret": "x" * 20})

    out = json.loads(
        iroh_tools.iroh_peer_call(
            {"peer": "livepeer01", "message": "Summarize the README."},
            task_id=None,
        )
    )
    assert out["success"] is True, out
    assert out["status"] == "completed"
    assert "Summarize the README." in out["text"]

    # last_called timestamp was persisted.
    record = PeerStore(Path(os.environ["HERMES_IROH_STATE_DIR"])).get_peer("livepeer01")
    assert record["last_called"]


def test_call_rejects_oversized_message(tool_env):
    import peer_tools as iroh_tools
    from security import PeerStore

    store = PeerStore(Path(os.environ["HERMES_IROH_STATE_DIR"]))
    store.add_peer("bigpeer000", {"endpoint_id": "bigpeer000", "secret": "x" * 20})
    out = json.loads(
        iroh_tools.iroh_peer_call(
            {"peer": "bigpeer000", "message": "x" * 70_000}, task_id=None
        )
    )
    assert out["success"] is False
    assert "limit" in out["error"].lower()
