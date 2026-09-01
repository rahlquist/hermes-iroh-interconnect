"""Tests for the iroh-interconnect security helpers (TDD).

Contract (plan §5 authentication layers + §7 security validation):
- Ticket format validation happens offline; no network access.
- Peer IDs are Iroh endpoint public keys: 52-char base32 (z-base).
- Ticket secrets are high-entropy and single-use; the store must reject reuse.
- Tickets expire (ts + TICKET_MAX_AGE_SECONDS); expired tickets are refused.
- Tickets carry a single-use nonce; NonceStore enforces one-time use.
- Inbound text is wrapped with provenance framing (untrusted external input).
- Outbound text is scrubbed of credential-shaped strings.
"""

import time

import pytest

from security import (
    TICKET_MAX_AGE_SECONDS,
    InvalidTicket,
    NonceStore,
    PeerStore,
    redact_outbound,
    validate_ticket,
    wrap_inbound,
)

_PEER = "a" * 52
_SECRET = "s3cretvalue1234567890"


def _ticket(ts=None, nonce=None, peer=_PEER, secret=_SECRET):
    ts = int(time.time()) if ts is None else ts
    nonce = nonce or ("ab12cd34ef56ab12cd34ef56ab12cd34")
    return (
        f"hermes-iroh://pair?peer={peer}&secret={secret}&ts={ts}&nonce={nonce}"
    )


class TestTicketValidation:
    def test_valid_ticket_parses(self):
        parsed = validate_ticket(_ticket())
        assert parsed["peer_id"].startswith("a")
        assert parsed["secret"] == _SECRET
        assert isinstance(parsed["ts"], int)
        assert parsed["nonce"]

    def test_rejects_non_hermes_scheme(self):
        with pytest.raises(InvalidTicket):
            validate_ticket("https://evil.example/pair?peer=x&secret=y")

    def test_rejects_missing_peer(self):
        with pytest.raises(InvalidTicket):
            validate_ticket("hermes-iroh://pair?secret=abc")

    def test_rejects_short_secret(self):
        with pytest.raises(InvalidTicket):
            validate_ticket(_ticket(secret="ab"))

    def test_rejects_garbage(self):
        with pytest.raises(InvalidTicket):
            validate_ticket("not a ticket at all")

    def test_rejects_legacy_ticket_without_expiry_fields(self):
        legacy = (
            f"hermes-iroh://pair?peer={_PEER}&secret={_SECRET}"
        )
        with pytest.raises(InvalidTicket, match="expiry fields"):
            validate_ticket(legacy)

    def test_rejects_expired_ticket(self):
        old = int(time.time()) - TICKET_MAX_AGE_SECONDS - 10
        with pytest.raises(InvalidTicket, match="expired"):
            validate_ticket(_ticket(ts=old))

    def test_rejects_future_ticket(self):
        future = int(time.time()) + 3600
        with pytest.raises(InvalidTicket, match="future"):
            validate_ticket(_ticket(ts=future))

    def test_rejects_malformed_nonce(self):
        with pytest.raises(InvalidTicket, match="nonce"):
            validate_ticket(_ticket(nonce="ZZZZ-not-hex-9999"))


class TestNonceStore:
    def test_first_use_accepted_second_rejected(self, tmp_path):
        store = NonceStore(tmp_path)
        nonce = "ab12cd34ef56ab12cd34ef56ab12cd34"
        assert store.mark_used(nonce) is True
        assert store.mark_used(nonce) is False

    def test_distinct_nonces_both_accepted(self, tmp_path):
        store = NonceStore(tmp_path)
        assert store.mark_used("ab12cd34ef56ab12cd34ef56ab12cd34") is True
        assert store.mark_used("ff12cd34ef56ab12cd34ef56ab12cd34") is True

    def test_rejects_empty_nonce(self, tmp_path):
        assert NonceStore(tmp_path).mark_used("") is False

    def test_prunes_expired_nonces(self, tmp_path):
        store = NonceStore(tmp_path)
        old = int(time.time()) - 2 * TICKET_MAX_AGE_SECONDS - 60
        store.mark_used("ab12cd34ef56ab12cd34ef56ab12cd34", now=old)
        # The stale nonce is pruned; the same string is usable again as a
        # fresh nonce (only relevant for IDs colliding after expiry).
        assert store.mark_used("ab12cd34ef56ab12cd34ef56ab12cd34") is True

    def test_store_is_0600(self, tmp_path):
        import os

        store = NonceStore(tmp_path)
        store.mark_used("ab12cd34ef56ab12cd34ef56ab12cd34")
        mode = os.stat(store.path).st_mode & 0o777
        assert mode == 0o600


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

    def test_find_by_endpoint_id(self, tmp_path):
        store = PeerStore(tmp_path)
        store.add_peer("peer-a", {"endpoint_id": "endpointid111", "secret": "v"})
        assert store.find_by_endpoint_id("endpointid111") == "peer-a"
        assert store.find_by_endpoint_id("endpointid111") is not None
        assert store.find_by_endpoint_id("unknown") is None
        assert store.find_by_endpoint_id("") is None

    def test_find_by_endpoint_id_matches_primary_key(self, tmp_path):
        store = PeerStore(tmp_path)
        store.add_peer("zzz-endpoint-id", {"secret": "v"})
        assert store.find_by_endpoint_id("zzz-endpoint-id") == "zzz-endpoint-id"


class TestInboundFraming:
    def test_wrap_inbound_marks_provenance(self):
        framed = wrap_inbound("peer-x", "hello")
        assert "peer-x" in framed
        assert "hello" in framed
        assert "UNTRUSTED" in framed

    def test_wrap_inbound_neutralizes_slash_commands(self):
        framed = wrap_inbound("peer-x", "/reset and more")
        assert "/reset" not in framed


class TestOutboundRedaction:
    def test_bearer_token_redacted(self):
        out = redact_outbound("Authorization: Bearer abcdef123456")
        assert "abcdef123456" not in out

    def test_plain_secret_redacted(self):
        out = redact_outbound("password=hunter2value")
        assert "hunter2value" not in out