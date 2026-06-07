"""The effective capability bundle — the compiled "binary" the kernel enforces."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..model import AgentDeployment, AgentImage, Capability, OrgPolicy
from ..model.subject import AgentKernelSubject


@dataclass(frozen=True)
class EffectiveBudget:
    """Metered ceilings after the meet (``min`` of every layer's limit)."""

    usd_per_day: float | None
    tokens_per_day: int | None
    max_steps_per_run: int | None
    on_exceed: str  # kill | pause | escalate


@dataclass(frozen=True)
class MemoryPolicy:
    """The effective contract every ``memory.write`` must satisfy."""

    require_provenance: bool
    require_fields: list[str]
    low_trust_source: str


@dataclass(frozen=True)
class CapabilityBundle:
    """Everything the kernel needs to enforce one agent run.

    This is the join point: a single :class:`AgentKernelSubject`, the effective
    capabilities, the deny-by-default egress allow-list, the metered budget, the
    secret bindings (broker refs, never values), the memory-write contract, and the
    org policy the engine evaluates per syscall.
    """

    subject: AgentKernelSubject
    capabilities: list[Capability]
    egress_allow: list[str]
    deny_external_egress: bool
    budget: EffectiveBudget
    secret_bindings: dict[str, str]
    memory_policy: MemoryPolicy
    org_policy: OrgPolicy
    image: AgentImage = field(repr=False)
    deployment: AgentDeployment = field(repr=False)

    # -- capability lookup the gateway uses ------------------------------------

    def authorizing_capability(
        self, action: str, resource: dict[str, Any] | None = None
    ) -> Capability | None:
        """Return the effective capability authorizing ``(action, resource)``, if any."""
        for cap in self.capabilities:
            if cap.authorizes(action, resource):
                return cap
        return None

    def to_dict(self) -> dict[str, Any]:
        """Render the bundle as plain data (for ``mandate compile`` output)."""
        return {
            "subject": self.subject.as_dict(),
            "capabilities": [c.to_dict() for c in self.capabilities],
            "egress": {
                "deny_by_default": self.deny_external_egress,
                "allow": list(self.egress_allow),
            },
            "budget": {
                "usd_per_day": self.budget.usd_per_day,
                "tokens_per_day": self.budget.tokens_per_day,
                "max_steps_per_run": self.budget.max_steps_per_run,
                "on_exceed": self.budget.on_exceed,
            },
            "secret_bindings": dict(self.secret_bindings),
            "memory_policy": {
                "require_provenance": self.memory_policy.require_provenance,
                "require_fields": list(self.memory_policy.require_fields),
                "low_trust_source": self.memory_policy.low_trust_source,
            },
        }
