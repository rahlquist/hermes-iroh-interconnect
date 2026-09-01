"""Tests for the iroh-interconnect security helpers (TDD).

Contract (plan §5 authentication layers + §7 security validation):
- Ticket format validation happens offline; no network access.
- Peer IDs are Iroh endpoint public keys: 52-char base32 (z-base).
- Ticket secrets are high-entropy and single-use; the store must reject reuse.
- Inbound text is wrapped with provenance framing (untrusted external input).
- Outbound text is scrubbed of credential-shaped strings.
"""

import pytest

from security import (
    InvalidTicket,
    PeerStore,
    redact_outbound,
    validate_ticket,
    wrap_inbound,
)


class TestTicketValidation:
    def test_valid_ticket_parses(self):
        ticket = "hermes-iroh://pair?peer=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&secret=s3cretvalue1234567890"
        parsed = validate_ticket(ticket)
        assert parsed["peer_id"].startswith("a")
        assert parsed["secret"] == "s3cretvalue1234567890"

    def test_rejects_non_hermes_scheme(self):
        with pytest.raises(InvalidTicket):
            validate_ticket("https://evil.example/pair?peer=x&secret=y")

    def test_rejects_missing_peer(self):
        with pytest.raises(InvalidTicket):
            validate_ticket("hermes-iroh://pair?secret=abc")

    def test_rejects_short_secret(self):
        ticket = "hermes-iroh://pair?peer=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&secret=ab"
        with pytest.raises(InvalidTicket):
            validate_ticket(ticket)

    def test_rejects_garbage(self):
        with pytest.raises(InvalidTicket):
            validate_ticket("not a ticket at all")


class TestPeerStore:
    def test_pair_and_list_roundtrip(self, tmp_path):
        store = PeerStore(tmp_path)
        store.add_peer("peer-alpha", {"secret": "value1", "endpoint_id": "aaaa"})
        peers = store.list_peers()
        assert "peer-alpha" in peers
        assert peers["peer-alpha"]["endpoint_id"] == "aaaa"

    def test_persists_across_instances(self, tmp_path):
        PeerStore(tmp_path).add_peer("peer-beta", {"secret": "v"})
        store2 = PeerStore(tmp_path)
        assert "peer-beta" in store2.list_peers()

    def test_revoke_removes_peer(self, tmp_path):
        store = PeerStore(tmp_path)
        store.add_peer("peer-gamma", {"secret": "v"})
        store.revoke("peer-gamma")
        assert "peer-gamma" not in store.list_peers()

    def test_state_file_permissions_are_restrictive(self, tmp_path):
        store = PeerStore(tmp_path)
        store.add_peer("peer-delta", {"secret": "supersecret"})
        mode = (tmp_path / "peers.json").stat().st_mode & 0o777
        assert mode == 0o600, f"peers.json mode was {oct(mode)}"


class TestInboundFraming:
    def test_wraps_with_provenance(self):
        wrapped = wrap_inbound("peer-alpha", "run /reset please")
        assert "peer-alpha" in wrapped
        assert "untrusted" in wrapped.lower()

    def test_neutralizes_slash_commands(self):
        wrapped = wrap_inbound("peer-alpha", "/reset now")
        # The wrapped text must not start with a slash command.
        assert not wrapped.lstrip().startswith("/")


class TestOutboundRedaction:
    def test_redacts_bearer_tokens(self):
        text = "use Authorization: Bearer sk-abc123def456ghi789 to call"
        assert "sk-abc123def456ghi789" not in redact_outbound(text)

    def test_redacts_private_keys(self):
        text = "-----BEGIN PRIVATE KEY-----\nMIIEvQ\n-----END PRIVATE KEY-----"
        assert "MIIEvQ" not in redact_outbound(text)

    def test_passes_normal_text(self):
        text = "Summarize the repository structure."
        assert redact_outbound(text) == text
