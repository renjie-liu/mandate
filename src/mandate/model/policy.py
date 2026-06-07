"""The policy model: execution-mode enum, rules, and ``OrgPolicy`` (contract §6, §10).

The kernel's policy decision is an **execution mode, not a boolean**. That return type
is the spine of the system, so the full enum is fixed early even though P0 only
exercises a few arms. A rule is ``match → decision``; the engine that evaluates rules
against a live syscall context lives in :mod:`mandate.kernel.policy_engine`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Decision(StrEnum):
    """The execution mode returned for a syscall (contract §6)."""

    ALLOW = "allow"
    DENY = "deny"
    ALLOW_READONLY = "allow_readonly"
    ALLOW_DRAFT_ONLY = "allow_draft_only"
    ALLOW_WITH_REDACTION = "allow_with_redaction"
    ALLOW_IN_SANDBOX = "allow_in_sandbox"
    REQUIRE_HUMAN_APPROVAL = "require_human_approval"
    REQUIRE_2FA = "require_2fa"
    REQUIRE_MANAGER_APPROVAL = "require_manager_approval"
    # The contract's §6/§10 examples and the shipped org-policy use a code-owner approval
    # mode; it joins the canonical require_* family as a more specific human approver.
    REQUIRE_CODE_OWNER_APPROVAL = "require_code_owner_approval"
    REQUIRE_SIMULATION_FIRST = "require_simulation_first"
    REQUIRE_BUDGET_INCREASE = "require_budget_increase"

    # -- semantics: how the gateway should treat each mode ---------------------

    @property
    def is_deny(self) -> bool:
        return self is Decision.DENY

    @property
    def requires_approval(self) -> bool:
        """Modes that block the effect pending an out-of-band human/control action."""
        return self in {
            Decision.REQUIRE_HUMAN_APPROVAL,
            Decision.REQUIRE_2FA,
            Decision.REQUIRE_MANAGER_APPROVAL,
            Decision.REQUIRE_CODE_OWNER_APPROVAL,
            Decision.REQUIRE_SIMULATION_FIRST,
            Decision.REQUIRE_BUDGET_INCREASE,
        }

    @property
    def is_draft(self) -> bool:
        return self is Decision.ALLOW_DRAFT_ONLY

    @property
    def executes(self) -> bool:
        """True if the kernel should actually run the tool (live or draft)."""
        return self in {
            Decision.ALLOW,
            Decision.ALLOW_READONLY,
            Decision.ALLOW_IN_SANDBOX,
            Decision.ALLOW_DRAFT_ONLY,
            Decision.ALLOW_WITH_REDACTION,
        }


@dataclass(frozen=True)
class PolicyRule:
    """One ``match → decision`` guardrail.

    ``match`` is a dict of conditions ANDed together. Supported condition keys (P0):

    * ``action`` — exact, or ``provider.resource.*`` / ``*`` wildcard.
    * ``resource.<dim>`` — the syscall's resource dimension equals / contains the value.
    * ``data.labels`` — true if any listed label is present on the syscall.
    * ``destination.external`` — boolean match.
    * ``recipient.domain_not_in`` — true if the recipient domain is absent from the list.
    """

    match: dict[str, Any]
    decision: Decision

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "PolicyRule":
        return cls(match=dict(raw.get("match") or {}), decision=Decision(raw["decision"]))


@dataclass(frozen=True)
class OrgPolicy:
    """Tenant-wide guardrails (contract §10). P0 accepts an empty one as a first-class
    meet input so the third file can be added later without recompiling the model."""

    defaults: dict[str, Any] = field(default_factory=dict)
    rules: list[PolicyRule] = field(default_factory=list)

    @classmethod
    def empty(cls) -> "OrgPolicy":
        return cls(defaults={}, rules=[])

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> "OrgPolicy":
        if not raw:
            return cls.empty()
        rules = [PolicyRule.from_dict(r) for r in (raw.get("rules") or [])]
        return cls(defaults=dict(raw.get("defaults") or {}), rules=rules)

    # -- meet inputs the compiler reads ---------------------------------------

    @property
    def deny_external_egress(self) -> bool:
        return bool(self.defaults.get("deny_external_egress", True))

    @property
    def require_secret_broker(self) -> bool:
        return bool(self.defaults.get("require_secret_broker", True))

    @property
    def max_agent_usd_per_day(self) -> float | None:
        return self.defaults.get("max_agent_usd_per_day")

    @property
    def require_capability_expiry(self) -> bool:
        return bool(self.defaults.get("require_capability_expiry", False))
