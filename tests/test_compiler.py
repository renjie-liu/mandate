"""Tests for the compiler: requests ∩ grants, subset/loosening rejection, secret checks."""

import pytest

from mandate.compiler import compile_bundle
from mandate.errors import CompileError, SubsetViolation
from mandate.model import AgentDeployment, AgentImage, OrgPolicy


def image(**overrides):
    base = {
        "apiVersion": "mandate/v1",
        "kind": "AgentImage",
        "metadata": {"name": "t", "version": "1", "publisher": "did:key:zX"},
        "loop": {"constraints": {"max_steps": 80}},
        "harness": {
            "egress": {"allow": ["arxiv.org"]},
            "tools": [
                {"ref": "mcp:github", "requests": [
                    {"capability": "github.repo.read", "resources": {"repos": ["acme/research"]}},
                ]},
            ],
        },
        "identity": {"asks": {"secrets": [
            {"name": "K", "purpose": "p", "required": True},
        ]}},
        "memory": {"writes": {"require_provenance": True, "require_fields": ["source"]}},
    }
    base.update(overrides)
    return AgentImage.from_dict(base)


def deployment(grants, *, secrets=None, max_steps=40):
    return AgentDeployment.from_dict({
        "apiVersion": "mandate/v1",
        "kind": "AgentDeployment",
        "agents": {"scout": {
            "image": "t:1@sha256:deadbeef",
            "tenant": "acme",
            "grants": grants,
            "identity": {
                "principal": "agent://acme/scout",
                "invoked_by": ["user:alice@acme"],
                "bindings": {"secrets": secrets if secrets is not None else {"K": "vault://acme/k"}},
            },
            "budget": {"usd_per_day": 50, "max_steps_per_run": max_steps, "on_exceed": "kill"},
        }},
    })


def compile_ok(img, dep, org=None):
    return compile_bundle(img, dep, org, session="s", run="r")


def test_happy_path_intersects_to_the_grant():
    b = compile_ok(image(), deployment([
        {"capability": "github.repo.read", "resources": {"repos": ["acme/research"]}, "expires": "30d"},
    ]))
    assert len(b.capabilities) == 1
    assert b.capabilities[0].action == "github.repo.read"
    assert b.budget.max_steps_per_run == 40
    assert b.egress_allow == ["arxiv.org"]
    assert b.deny_external_egress is True


def test_grant_not_subset_is_rejected():
    with pytest.raises(SubsetViolation):
        compile_ok(image(), deployment([
            {"capability": "github.repo.read", "resources": {"repos": ["acme/secret"]}},
        ]))


def test_grant_for_unrequested_capability_is_rejected():
    with pytest.raises(CompileError):
        compile_ok(image(), deployment([
            {"capability": "payment.send"},
        ]))


def test_deployment_cannot_loosen_image_step_ceiling():
    with pytest.raises(SubsetViolation):
        compile_ok(
            image(),
            deployment([
                {"capability": "github.repo.read", "resources": {"repos": ["acme/research"]}},
            ], max_steps=200),  # > image ceiling of 80
        )


def test_required_secret_must_be_bound():
    with pytest.raises(CompileError):
        compile_ok(image(), deployment([
            {"capability": "github.repo.read", "resources": {"repos": ["acme/research"]}},
        ], secrets={}))


def test_secret_must_be_a_broker_reference_under_org_policy():
    org = OrgPolicy.from_dict({"defaults": {"require_secret_broker": True}})
    with pytest.raises(CompileError):
        compile_ok(image(), deployment([
            {"capability": "github.repo.read", "resources": {"repos": ["acme/research"]}},
        ], secrets={"K": "literal-secret-value"}), org)


def test_org_policy_can_require_capability_expiry():
    org = OrgPolicy.from_dict({"defaults": {"require_capability_expiry": True}})
    with pytest.raises(CompileError):
        compile_ok(image(), deployment([
            {"capability": "github.repo.read", "resources": {"repos": ["acme/research"]}},
        ]), org)  # grant has no expires


def test_usd_budget_takes_min_of_deployment_and_org():
    org = OrgPolicy.from_dict({"defaults": {"max_agent_usd_per_day": 10}})
    b = compile_ok(image(), deployment([
        {"capability": "github.repo.read", "resources": {"repos": ["acme/research"]}},
    ]), org)
    assert b.budget.usd_per_day == 10


def test_empty_org_policy_is_accepted():
    b = compile_ok(image(), deployment([
        {"capability": "github.repo.read", "resources": {"repos": ["acme/research"]}},
    ]), OrgPolicy.empty())
    assert b.org_policy.rules == []
