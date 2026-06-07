"""``AgentDeployment`` — file 2, private (contract §9).

Binds an image to *your* identity, secrets, budget, volumes, and concrete model.
**Installing is granting** — this is the consent ceremony, so the grants here are the
authority half of the meet. This parser targets the single-agent P0 shape; a named
agent can be selected when a compose file holds several.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .capability import Capability


@dataclass(frozen=True)
class Budget:
    """The seatbelt (contract §9 budget)."""

    tokens_per_day: int | None = None
    usd_per_day: float | None = None
    max_steps_per_run: int | None = None
    on_exceed: str = "kill"  # kill | pause | escalate

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> "Budget":
        raw = raw or {}
        return cls(
            tokens_per_day=raw.get("tokens_per_day"),
            usd_per_day=raw.get("usd_per_day"),
            max_steps_per_run=raw.get("max_steps_per_run"),
            on_exceed=str(raw.get("on_exceed", "kill")),
        )


@dataclass(frozen=True)
class AgentDeployment:
    """Parsed deployment for a single agent."""

    agent_name: str
    image_ref: str
    image_digest: str | None
    tenant: str
    grants: list[Capability]
    principal: str
    invoked_by: list[str]
    secret_bindings: dict[str, str]
    inbox: dict[str, Any]
    budget: Budget
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, raw: dict[str, Any], agent: str | None = None) -> "AgentDeployment":
        if raw.get("kind") != "AgentDeployment":
            raise ValueError(f"expected kind: AgentDeployment, got {raw.get('kind')!r}")
        agents = raw.get("agents") or {}
        if not agents:
            raise ValueError("deployment has no agents")
        if agent is None:
            if len(agents) > 1:
                raise ValueError(
                    f"deployment defines {len(agents)} agents "
                    f"({', '.join(agents)}); specify which one"
                )
            agent = next(iter(agents))
        if agent not in agents:
            raise ValueError(f"no agent named {agent!r} in deployment")
        spec = agents[agent]

        image_ref = str(spec.get("image", ""))
        image_digest = _digest_of(image_ref)
        grants = [Capability.from_dict(g) for g in spec.get("grants") or []]

        identity = spec.get("identity") or {}
        bindings = identity.get("bindings") or {}
        secret_bindings = dict(bindings.get("secrets") or {})

        return cls(
            agent_name=agent,
            image_ref=image_ref,
            image_digest=image_digest,
            tenant=str(spec.get("tenant", "")),
            grants=grants,
            principal=str(identity.get("principal", f"agent://{spec.get('tenant', '')}/{agent}")),
            invoked_by=list(identity.get("invoked_by") or []),
            secret_bindings=secret_bindings,
            inbox=dict(bindings.get("inbox") or {}),
            budget=Budget.from_dict(spec.get("budget")),
            raw=raw,
        )


def _digest_of(image_ref: str) -> str | None:
    """Extract the ``@sha256:...`` digest from an image reference, if present."""
    if "@" in image_ref:
        return image_ref.split("@", 1)[1]
    return None
