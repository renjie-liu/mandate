"""The budget meter and kill switch (contract §9 budget, ROADMAP P0).

``budget.charge`` is a kernel-internal accounting side effect of ``tool.call`` / llm /
``memory.write``. The meter accumulates spend against the compiled ceilings; when a
charge would cross a ceiling it reports ``exceeded`` and names the breached limit. What
*happens* on exceed (kill / pause / escalate) is the gateway's call — the meter only
measures.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..compiler.bundle import EffectiveBudget


@dataclass(frozen=True)
class ChargeResult:
    """The outcome of a single charge."""

    exceeded: bool
    breached: tuple[str, ...] = ()  # which limits were crossed
    usd_spent: float = 0.0
    tokens_spent: int = 0
    steps: int = 0


class BudgetMeter:
    """Accumulating counter for usd / tokens / steps against compiled ceilings."""

    def __init__(self, budget: EffectiveBudget) -> None:
        self._budget = budget
        self.usd_spent: float = 0.0
        self.tokens_spent: int = 0
        self.steps: int = 0

    @property
    def on_exceed(self) -> str:
        return self._budget.on_exceed

    def snapshot(self) -> dict[str, float | int | None]:
        return {
            "usd_spent": round(self.usd_spent, 6),
            "usd_per_day": self._budget.usd_per_day,
            "tokens_spent": self.tokens_spent,
            "tokens_per_day": self._budget.tokens_per_day,
            "steps": self.steps,
            "max_steps_per_run": self._budget.max_steps_per_run,
        }

    def charge(self, *, usd: float = 0.0, tokens: int = 0, steps: int = 0) -> ChargeResult:
        """Apply a charge, then report whether any ceiling is now breached.

        The charge always lands (the resource was consumed); the gateway decides what to
        do about a breach. Charges are monotonic — the meter never refunds.
        """
        self.usd_spent += usd
        self.tokens_spent += tokens
        self.steps += steps

        breached: list[str] = []
        if self._budget.usd_per_day is not None and self.usd_spent > self._budget.usd_per_day:
            breached.append("usd_per_day")
        if (
            self._budget.tokens_per_day is not None
            and self.tokens_spent > self._budget.tokens_per_day
        ):
            breached.append("tokens_per_day")
        if (
            self._budget.max_steps_per_run is not None
            and self.steps > self._budget.max_steps_per_run
        ):
            breached.append("max_steps_per_run")

        return ChargeResult(
            exceeded=bool(breached),
            breached=tuple(breached),
            usd_spent=round(self.usd_spent, 6),
            tokens_spent=self.tokens_spent,
            steps=self.steps,
        )
