"""The result type every agent-facing syscall returns.

A syscall never returns a raw effect; it returns a :class:`SyscallResult` that records
the execution mode policy chose, what actually happened (``status``), the budget cost,
and the audit sequence number that pins it in the append-only log. The agent sees this
— never the kernel's internal machinery.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..model import Decision


@dataclass(frozen=True)
class SyscallResult:
    """The outcome of one syscall, as the agent observes it."""

    syscall: str  # e.g. "tool.call", "memory.write", "approval.request"
    status: str  # ok | draft | denied | blocked | rejected | held_for_review |
    #              pending_approval | killed
    decision: Decision | None = None
    result: Any = None  # tool/memory payload — never a secret
    cost_usd: float = 0.0
    audit_seq: int | None = None
    message: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        """True when the effect was actually carried out (live or as a draft)."""
        return self.status in {"ok", "draft"}

    @property
    def blocked(self) -> bool:
        """True when the kernel refused or gated the effect."""
        return self.status in {"denied", "blocked", "rejected", "killed"}

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        mode = f" [{self.decision}]" if self.decision else ""
        msg = f" — {self.message}" if self.message else ""
        return f"{self.syscall}: {self.status}{mode}{msg}"
