"""``AgentImage`` — file 1, author-declared (contract §8).

Publishable, signable, content-addressed. No secrets, no real identity, no budgets —
only requirements, *requests*, constraints, and character. This parser pulls out the
fields P0 enforces (capability requests, the egress allow-list, image-declared
ceilings, the memory-write provenance contract) and keeps the rest as ``raw``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .capability import Capability


@dataclass(frozen=True)
class ToolRequest:
    """One tool the image wires in, with the capabilities it requests."""

    ref: str  # e.g. mcp:github
    requests: list[Capability] = field(default_factory=list)


@dataclass(frozen=True)
class MemoryWriteContract:
    """The image's rules for what a valid ``memory.write`` looks like (§8 memory)."""

    require_provenance: bool = True
    require_fields: list[str] = field(default_factory=list)
    low_trust_source: str = "review"  # untrusted-origin long-term writes are held


@dataclass(frozen=True)
class AgentImage:
    """Parsed author-declared image."""

    name: str
    version: str
    publisher: str | None
    max_steps: int | None
    subagent_max_depth: int | None
    egress_allow: list[str]
    tools: list[ToolRequest]
    secret_asks: list[dict[str, Any]]
    memory_writes: MemoryWriteContract
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def requested_capabilities(self) -> list[Capability]:
        """Every capability the image requests, flattened across tools."""
        return [cap for tool in self.tools for cap in tool.requests]

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "AgentImage":
        if raw.get("kind") != "AgentImage":
            raise ValueError(f"expected kind: AgentImage, got {raw.get('kind')!r}")
        meta = raw.get("metadata") or {}

        loop_constraints = ((raw.get("loop") or {}).get("constraints")) or {}
        harness = raw.get("harness") or {}
        egress = ((harness.get("egress") or {}).get("allow")) or []

        tools: list[ToolRequest] = []
        for tool in harness.get("tools") or []:
            requests = [Capability.from_dict(_as_cap_dict(r)) for r in tool.get("requests") or []]
            tools.append(ToolRequest(ref=str(tool.get("ref", "")), requests=requests))

        asks = ((raw.get("identity") or {}).get("asks")) or {}
        secret_asks = list(asks.get("secrets") or [])

        mem = raw.get("memory") or {}
        writes = mem.get("writes") or {}
        long_term = writes.get("long_term") or {}
        memory_writes = MemoryWriteContract(
            require_provenance=bool(writes.get("require_provenance", True)),
            require_fields=list(writes.get("require_fields") or []),
            low_trust_source=str(long_term.get("low_trust_source", "review")),
        )

        return cls(
            name=str(meta.get("name", "")),
            version=str(meta.get("version", "")),
            publisher=meta.get("publisher"),
            max_steps=loop_constraints.get("max_steps"),
            subagent_max_depth=loop_constraints.get("subagent_max_depth"),
            egress_allow=list(egress),
            tools=tools,
            secret_asks=secret_asks,
            memory_writes=memory_writes,
            raw=raw,
        )


def _as_cap_dict(entry: Any) -> dict[str, Any]:
    """Accept either an object form or the bare ``capability:`` string shorthand."""
    if isinstance(entry, str):
        return {"capability": entry}
    return entry
