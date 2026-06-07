"""A minimal audit dashboard (ROADMAP P0: "append-only audit log + minimal dashboard").

Renders the append-only log as a terminal table: every syscall, the decision, the
cost, and the running budget — plus the subject it all ran under and whether the hash
chain still verifies. Deliberately plain text so it works anywhere.
"""

from __future__ import annotations

from .compiler.bundle import CapabilityBundle
from .kernel.audit import AuditLog
from .kernel.gateway import SyscallGateway

# How each terminal status reads in the dashboard.
_STATUS_GLYPH = {
    "ok": "allowed",
    "draft": "draft",
    "denied": "DENIED",
    "blocked": "BLOCKED",
    "rejected": "REJECTED",
    "held_for_review": "held",
    "pending_approval": "approval",
    "killed": "KILLED",
}


def render_dashboard(
    audit: AuditLog,
    *,
    bundle: CapabilityBundle | None = None,
    budget_snapshot: dict | None = None,
) -> str:
    """Return the dashboard as a string."""
    lines: list[str] = []
    rule = "─" * 92
    lines.append(rule)
    lines.append("  MANDATE — capability-decision audit")
    lines.append(rule)

    if bundle is not None:
        s = bundle.subject
        lines.append(f"  subject   : {s.principal}  (tenant={s.tenant})")
        lines.append(f"  session   : {s.session}   run={s.run}")
        if s.image_digest:
            lines.append(f"  image     : {s.image_digest}")
        lines.append("")

    header = f"  {'#':>2}  {'syscall':<16} {'action':<24} {'decision':<22} {'status':<9} {'$cost':>7}"
    lines.append(header)
    lines.append("  " + "-" * (len(header) - 2))

    for e in audit.events:
        decision = e.decision or "-"
        status = _STATUS_GLYPH.get(e.status, e.status)
        lines.append(
            f"  {e.seq:>2}  {e.syscall:<16} {_clip(e.action, 24):<24} "
            f"{_clip(decision, 22):<22} {status:<9} {e.cost_usd:>7.4f}"
        )
        note = e.detail.get("reason") or (e.detail.get("egress_blocked") and "egress blocked")
        if note:
            lines.append(f"      └─ {note}")

    lines.append("  " + "-" * (len(header) - 2))
    total = sum(e.cost_usd for e in audit.events)
    lines.append(f"  {'':>2}  {'TOTAL':<16} {'':<24} {'':<22} {'':<9} {total:>7.4f}")

    if budget_snapshot is not None:
        lines.append("")
        lines.append(
            f"  budget    : ${budget_snapshot['usd_spent']:.4f} / "
            f"${budget_snapshot['usd_per_day']}  ·  "
            f"steps {budget_snapshot['steps']}/{budget_snapshot['max_steps_per_run']}  ·  "
            f"tokens {budget_snapshot['tokens_spent']}/{budget_snapshot['tokens_per_day']}"
        )

    lines.append(f"  integrity : hash chain {'VERIFIED' if audit.verify() else 'BROKEN'}")
    lines.append(rule)
    return "\n".join(lines)


def render_for_gateway(gateway: SyscallGateway, bundle: CapabilityBundle | None = None) -> str:
    """Convenience: render the dashboard for a gateway's audit log + budget."""
    return render_dashboard(
        gateway.audit, bundle=bundle or gateway.bundle, budget_snapshot=gateway.budget.snapshot()
    )


def _clip(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"
