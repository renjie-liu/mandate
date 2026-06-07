"""Tests for the policy engine: rule matching and first-match-wins → execution mode."""

from mandate.model import Decision, OrgPolicy
from mandate.kernel.policy_engine import PolicyEngine


def engine(rules):
    return PolicyEngine.from_org_policy(OrgPolicy.from_dict({"rules": rules}))


def test_default_is_allow_when_no_rule_matches():
    assert engine([]).decide("github.repo.read") is Decision.ALLOW


def test_exact_action_match():
    e = engine([{"match": {"action": "github.repo.write"}, "decision": "allow_draft_only"}])
    assert e.decide("github.repo.write") is Decision.ALLOW_DRAFT_ONLY
    assert e.decide("github.repo.read") is Decision.ALLOW


def test_action_wildcard_match():
    e = engine([{"match": {"action": "payment.*"}, "decision": "require_manager_approval"}])
    assert e.decide("payment.send") is Decision.REQUIRE_MANAGER_APPROVAL
    assert e.decide("payment") is Decision.REQUIRE_MANAGER_APPROVAL
    assert e.decide("paymentx") is Decision.ALLOW


def test_first_match_wins_for_branch_then_catchall():
    e = engine([
        {"match": {"action": "github.repo.write", "resource.branch": "main"},
         "decision": "require_code_owner_approval"},
        {"match": {"action": "github.repo.write"}, "decision": "allow_draft_only"},
    ])
    main = e.decide("github.repo.write", {"resource": {"branch": "main"}})
    feature = e.decide("github.repo.write", {"resource": {"branch": "feature/x"}})
    assert main is Decision.REQUIRE_CODE_OWNER_APPROVAL
    assert feature is Decision.ALLOW_DRAFT_ONLY


def test_data_labels_membership():
    e = engine([
        {"match": {"data.labels": ["pii"], "destination.external": True}, "decision": "deny"},
    ])
    ctx = {"data": {"labels": ["pii", "internal"]}, "destination": {"external": True}}
    assert e.decide("email.send", ctx) is Decision.DENY
    # No external destination → rule does not fire.
    ctx2 = {"data": {"labels": ["pii"]}, "destination": {"external": False}}
    assert e.decide("email.send", ctx2) is Decision.ALLOW


def test_recipient_domain_not_in():
    e = engine([
        {"match": {"action": "email.send", "recipient.domain_not_in": ["acme.com"]},
         "decision": "allow_draft_only"},
    ])
    external = e.decide("email.send", {"recipient": {"domain": "gmail.com"}})
    internal = e.decide("email.send", {"recipient": {"domain": "acme.com"}})
    assert external is Decision.ALLOW_DRAFT_ONLY
    assert internal is Decision.ALLOW


def test_decision_semantics_helpers():
    assert Decision.ALLOW_DRAFT_ONLY.is_draft
    assert Decision.ALLOW_DRAFT_ONLY.executes
    assert Decision.DENY.is_deny
    assert Decision.REQUIRE_CODE_OWNER_APPROVAL.requires_approval
    assert not Decision.ALLOW.requires_approval
