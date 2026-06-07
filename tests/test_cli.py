"""Tests for the ``mandate`` CLI entry point."""

from pathlib import Path

import pytest

from mandate.cli import main

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "research-assistant"


def test_compile_prints_a_bundle(capsys):
    rc = main([
        "compile",
        str(EXAMPLE / "agent.yaml"),
        str(EXAMPLE / "agent-compose.yaml"),
        "--org-policy", str(EXAMPLE / "org-policy.yaml"),
    ])
    out = capsys.readouterr().out
    assert rc == 0
    assert "capabilities" in out
    assert "github.repo.read" in out
    assert "deny_by_default" in out


def test_compile_reports_error_for_bad_grant(tmp_path, capsys):
    # A deployment that grants a capability the image never requested.
    bad = tmp_path / "bad-compose.yaml"
    bad.write_text(
        "apiVersion: mandate/v1\n"
        "kind: AgentDeployment\n"
        "agents:\n"
        "  scout:\n"
        "    image: research-assistant:1@sha256:x\n"
        "    tenant: acme\n"
        "    grants:\n"
        "      - capability: payment.send\n"
        "    identity:\n"
        "      principal: agent://acme/scout\n"
        "      bindings: { secrets: { SEMANTIC_SCHOLAR_KEY: vault://acme/k } }\n"
        "    budget: { usd_per_day: 1, max_steps_per_run: 1, on_exceed: kill }\n"
    )
    rc = main(["compile", str(EXAMPLE / "agent.yaml"), str(bad)])
    err = capsys.readouterr().err
    assert rc == 1
    assert "compile error" in err


def test_demo_runs_quietly(capsys):
    rc = main(["demo", "--quiet"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "capability-decision audit" in out
    assert "hash chain VERIFIED" in out


def test_requires_a_subcommand():
    with pytest.raises(SystemExit):
        main([])
