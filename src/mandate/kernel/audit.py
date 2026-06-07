"""The append-only audit log (contract §7 ``audit.append``).

Every syscall and every decision is recorded. The log is **append-only**: there is no
update or delete, and each entry carries the hash of the previous one, so any tampering
with history is detectable by :meth:`AuditLog.verify`. The audit must be able to
*explain* each capability decision, not merely trace that a call happened — so entries
carry the subject, capability, resource, decision, and cost.

Crucially, nothing secret is ever written here: callers pass already-safe summaries and
broker *references*, never plaintext.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Iterator

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class AuditEvent:
    """One immutable entry in the chain."""

    seq: int
    ts: float
    syscall: str
    principal: str
    action: str
    decision: str | None
    status: str
    cost_usd: float
    resource: dict[str, Any] = field(default_factory=dict)
    data_labels: list[str] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = GENESIS_HASH
    hash: str = ""

    def payload(self) -> dict[str, Any]:
        """The hashed content (everything except the hash itself)."""
        d = asdict(self)
        d.pop("hash", None)
        return d


def _hash_event(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


class AuditLog:
    """An append-only, hash-chained sequence of :class:`AuditEvent`."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def append(
        self,
        *,
        syscall: str,
        principal: str,
        action: str,
        status: str,
        decision: str | None = None,
        cost_usd: float = 0.0,
        resource: dict[str, Any] | None = None,
        data_labels: list[str] | None = None,
        detail: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Append one event and return it. The only mutator on this class."""
        prev_hash = self._events[-1].hash if self._events else GENESIS_HASH
        seq = len(self._events)
        base = AuditEvent(
            seq=seq,
            ts=time.time(),
            syscall=syscall,
            principal=principal,
            action=action,
            decision=decision,
            status=status,
            cost_usd=round(float(cost_usd), 6),
            resource=dict(resource or {}),
            data_labels=list(data_labels or []),
            detail=dict(detail or {}),
            prev_hash=prev_hash,
        )
        event = AuditEvent(**{**asdict(base), "hash": _hash_event(base.payload())})
        self._events.append(event)
        return event

    # -- read-only views -------------------------------------------------------

    def __iter__(self) -> Iterator[AuditEvent]:
        return iter(tuple(self._events))

    def __len__(self) -> int:
        return len(self._events)

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    def verify(self) -> bool:
        """Recompute the chain; return True iff no entry has been altered or reordered."""
        prev = GENESIS_HASH
        for event in self._events:
            if event.prev_hash != prev:
                return False
            if event.hash != _hash_event(event.payload()):
                return False
            prev = event.hash
        return True

    def to_jsonl(self) -> str:
        """Serialize the whole log as JSON lines (for export / a dashboard)."""
        return "\n".join(
            json.dumps(asdict(e), sort_keys=True, default=str) for e in self._events
        )
