"""Provenance-checked memory (contract §7 ``memory.write``, §8 memory).

Memory is not a free scratchpad: every write must carry provenance, and a long-term
write whose origin is untrusted is a memory-poisoning vector. The store enforces the
image's write contract:

* missing any required provenance field → **rejected**.
* a long-term write from a low-trust source → **held for consolidation review**, not
  committed directly.
* otherwise → committed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..compiler.bundle import MemoryPolicy
from ..errors import ProvenanceRejected

# Source-trust values treated as untrusted for long-term consolidation.
LOW_TRUST = {"low", "untrusted", "injected", "web", "scraped"}


@dataclass(frozen=True)
class MemoryRecord:
    """A committed or held memory object."""

    scope: str
    obj: dict[str, Any]
    provenance: dict[str, Any]
    long_term: bool
    status: str  # committed | held_for_review
    detail: dict[str, Any] = field(default_factory=dict)


class MemoryStore:
    """A scoped, provenance-enforcing memory backend (P0: in-process)."""

    def __init__(self, policy: MemoryPolicy) -> None:
        self._policy = policy
        self._committed: list[MemoryRecord] = []
        self._held: list[MemoryRecord] = []

    @property
    def committed(self) -> tuple[MemoryRecord, ...]:
        return tuple(self._committed)

    @property
    def held(self) -> tuple[MemoryRecord, ...]:
        return tuple(self._held)

    def write(
        self,
        scope: str,
        obj: dict[str, Any],
        provenance: dict[str, Any] | None,
        *,
        long_term: bool = False,
    ) -> MemoryRecord:
        """Validate and apply one write; raise :class:`ProvenanceRejected` if invalid."""
        provenance = provenance or {}

        if self._policy.require_provenance:
            missing = [f for f in self._policy.require_fields if f not in provenance]
            if missing:
                raise ProvenanceRejected(
                    f"memory.write to {scope!r} rejected: missing required provenance "
                    f"field(s) {missing}"
                )

        source_trust = str(provenance.get("source_trust", "")).lower()
        if long_term and self._policy.low_trust_source == "review" and source_trust in LOW_TRUST:
            record = MemoryRecord(
                scope=scope,
                obj=dict(obj),
                provenance=dict(provenance),
                long_term=True,
                status="held_for_review",
                detail={"reason": f"low-trust source {source_trust!r} held for review"},
            )
            self._held.append(record)
            return record

        record = MemoryRecord(
            scope=scope,
            obj=dict(obj),
            provenance=dict(provenance),
            long_term=long_term,
            status="committed",
        )
        self._committed.append(record)
        return record

    def read(self, scope: str) -> list[MemoryRecord]:
        return [r for r in self._committed if r.scope == scope]
