"""Tests for the capability algebra (subset, meet, authorizes) and sensitivity order."""

import pytest

from mandate.model import Capability
from mandate.model.sensitivity import sensitivity_at_most, sensitivity_level


def cap(action, **kw):
    return Capability.from_dict({"capability": action, **kw})


# -- subset rule --------------------------------------------------------------


def test_grant_omitting_scope_is_subset_of_request():
    request = cap("github.repo.read", resources={"repos": ["acme/research", "acme/x"]},
                  scope={"include_private": False})
    grant = cap("github.repo.read", resources={"repos": ["acme/research"]}, expires="30d")
    assert grant.is_subset_of(request)


def test_grant_with_extra_resource_is_not_subset():
    request = cap("github.repo.read", resources={"repos": ["acme/research"]})
    grant = cap("github.repo.read", resources={"repos": ["acme/research", "acme/secret"]})
    assert not grant.is_subset_of(request)


def test_grant_widening_boolean_scope_is_not_subset():
    request = cap("github.repo.read", scope={"include_private": False})
    grant = cap("github.repo.read", scope={"include_private": True})
    assert not grant.is_subset_of(request)


def test_grant_narrowing_boolean_scope_is_subset():
    request = cap("github.repo.read", scope={"include_private": True})
    grant = cap("github.repo.read", scope={"include_private": False})
    assert grant.is_subset_of(request)


def test_different_actions_never_subset():
    assert not cap("github.repo.write").is_subset_of(cap("github.repo.read"))


def test_request_unconstrained_dimension_accepts_any_grant():
    request = cap("github.repo.read")  # no resources at all → universe
    grant = cap("github.repo.read", resources={"repos": ["acme/research"]})
    assert grant.is_subset_of(request)


def test_higher_sensitivity_grant_is_not_subset():
    request = cap("x.y.z", data={"max_sensitivity": "internal"})
    grant = cap("x.y.z", data={"max_sensitivity": "restricted"})
    assert not grant.is_subset_of(request)


# -- meet ---------------------------------------------------------------------


def test_meet_intersects_resources_and_takes_min_sensitivity():
    a = cap("github.repo.read", resources={"repos": ["acme/research", "acme/x"]},
            data={"max_sensitivity": "restricted"})
    b = cap("github.repo.read", resources={"repos": ["acme/research"]},
            data={"max_sensitivity": "internal"}, expires="30d")
    m = a.meet(b)
    assert m.resources["repos"] == ["acme/research"]
    assert m.max_sensitivity == "internal"
    assert m.expires == "30d"


def test_meet_requires_same_action():
    with pytest.raises(ValueError):
        cap("a.b.c").meet(cap("a.b.d"))


# -- authorizes ---------------------------------------------------------------


def test_authorizes_requires_resource_to_be_named_and_in_set():
    c = cap("github.repo.read", resources={"repos": ["acme/research"]})
    assert c.authorizes("github.repo.read", {"repos": ["acme/research"]})
    assert not c.authorizes("github.repo.read", {"repos": ["acme/other"]})
    # The caller must name the constrained resource; the kernel won't guess.
    assert not c.authorizes("github.repo.read", {})


def test_authorizes_scope_ceiling_only_checked_when_asserted():
    c = cap("github.repo.read", resources={"repos": ["acme/research"]},
            scope={"include_private": False})
    # Not asserting privacy → stays on the safe side → authorized.
    assert c.authorizes("github.repo.read", {"repos": ["acme/research"]})
    # Explicitly requesting private access exceeds the ceiling → refused.
    assert not c.authorizes(
        "github.repo.read", {"repos": ["acme/research"], "include_private": True}
    )


def test_authorizes_open_dimension_allows_any_value():
    # An unscoped write authorizes any branch — policy, not capability, gates main.
    c = cap("github.repo.write", resources={"repos": ["acme/research"]})
    assert c.authorizes("github.repo.write", {"repos": ["acme/research"], "branch": "main"})


def test_branch_scope_is_enforced_against_a_singular_branch_key():
    # Regression: a capability scoped to branches=[main] must NOT authorize a call that
    # names branch="feature/x" just because the runtime key is singular.
    c = cap("github.repo.write", resources={"repos": ["acme/research"]},
            scope={"branches": ["main"]})
    assert c.authorizes("github.repo.write", {"repos": ["acme/research"], "branch": "main"})
    assert not c.authorizes(
        "github.repo.write", {"repos": ["acme/research"], "branch": "feature/x"}
    )


def test_resource_identity_matches_singular_or_plural_key():
    c = cap("github.repo.read", resources={"repos": ["acme/research"]})
    assert c.authorizes("github.repo.read", {"repo": "acme/research"})  # singular key
    assert not c.authorizes("github.repo.read", {"repo": "acme/other"})


# -- sensitivity --------------------------------------------------------------


def test_sensitivity_ordering():
    assert sensitivity_level("public") < sensitivity_level("secret")
    assert sensitivity_at_most("internal", "restricted")
    assert not sensitivity_at_most("restricted", "internal")
