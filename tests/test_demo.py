"""End-to-end test of the P0 demo: the six scenarios produce the contract's outcomes."""

from mandate.demo import DEMO_SECRET_VALUE, run


def test_demo_walks_all_six_scenarios():
    out = run()
    r = out.results

    # 1) read → allowed + charged
    assert r["read"].status == "ok" and r["read"].cost_usd > 0

    # 2) write → draft on a feature branch; approval on main; nothing ships
    assert r["write_draft"].status == "draft"
    assert r["write_draft"].result["shipped"] is False
    assert r["write_main"].status == "pending_approval"

    # 3) secret tool runs; key stays server-side
    assert r["secret"].status == "ok"

    # 4) the adversarial proof: allowed egress works, exfil is blocked
    assert r["egress_ok"].status == "ok"
    assert r["egress_blocked"].status == "blocked"
    assert r["egress_blocked"].detail.get("egress_blocked") is True

    # 5) memory: provenance enforced; low-trust held; trusted committed
    assert r["mem_rejected"].status == "rejected"
    assert r["mem_held"].status == "held_for_review"
    assert r["mem_ok"].status == "ok"

    # 6) budget kill switch fires and refuses further work
    assert r["killed"].status == "killed"
    assert r["post_kill"].status == "killed"
    assert out.killed_at_step is not None


def test_demo_never_leaks_the_secret_anywhere_agent_visible():
    out = run()
    # Not in any audit log...
    assert DEMO_SECRET_VALUE not in out.gateway.audit.to_jsonl()
    assert DEMO_SECRET_VALUE not in out.budget_gateway.audit.to_jsonl()
    # ...nor in any result the agent received.
    for _label, res in out.narrative:
        assert DEMO_SECRET_VALUE not in repr(res.result)


def test_demo_audit_chain_verifies():
    out = run()
    assert out.gateway.audit.verify()
    assert out.budget_gateway.audit.verify()
