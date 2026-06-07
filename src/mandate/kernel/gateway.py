"""The syscall gateway — the kernel (contract §2, §7).

This is the single mediated boundary. Every agent-facing syscall (`tool.call`,
`memory.write`, `approval.request`) enters here and, in one place, is:

1. **authorized** against the effective capability bundle,
2. **decided** by policy into an execution mode,
3. **charged** to the budget (with the kill switch on a breach),
4. **executed** — if the mode permits — with secrets broker-injected and any egress
   confined to the deny-by-default sandbox, and
5. **audited** to the append-only log.

The agent is handed an SDK client bound to this gateway and *nothing else*: it has no
reference to the broker, the budget, the egress guard, or the memory store. There is no
second path. That is INV-1.
"""

from __future__ import annotations

from typing import Any, Callable

from ..compiler.bundle import CapabilityBundle
from ..errors import EgressDenied, MandateError, ProvenanceRejected
from ..model import Decision
from ..model.subject import AgentKernelSubject
from .audit import AuditEvent, AuditLog
from .broker import SecretBroker
from .budget import BudgetMeter, ChargeResult
from .egress import EgressGuard, Sandbox
from .memory import MemoryStore
from .policy_engine import PolicyEngine
from .syscalls import SyscallResult
from .tools import Tool, ToolRegistry


class SyscallGateway:
    """The mediated boundary between an agent and every external effect."""

    def __init__(
        self,
        bundle: CapabilityBundle,
        *,
        tools: ToolRegistry | None = None,
        audit: AuditLog | None = None,
        vault: dict[str, str] | None = None,
        broker: SecretBroker | None = None,
        fetcher: Callable[[str], str] | None = None,
    ) -> None:
        self.bundle = bundle
        self.subject: AgentKernelSubject = bundle.subject
        self.audit = audit or AuditLog()
        self.budget = BudgetMeter(bundle.budget)
        self.policy = PolicyEngine.from_org_policy(bundle.org_policy)
        self.broker = broker or SecretBroker(bundle.secret_bindings, vault=vault)
        self.memory = MemoryStore(bundle.memory_policy)
        self.tools = tools or ToolRegistry()
        # Egress is deny-by-default: only the compiled allow-list passes.
        self.egress = EgressGuard(bundle.egress_allow)
        self._sandbox = Sandbox(self.egress, fetcher=fetcher)

        self.killed = False
        self.kill_reason: str | None = None
        self.pending_approvals: list[dict[str, Any]] = []

    # =====================================================================
    # Agent-facing syscalls
    # =====================================================================

    def tool_call(
        self,
        capability: str,
        name: str,
        args: dict[str, Any] | None = None,
        *,
        resource: dict[str, Any] | None = None,
        data_labels: list[str] | None = None,
    ) -> SyscallResult:
        """`tool.call` — the workhorse syscall. Authorize → decide → charge → act."""
        args = dict(args or {})
        resource = dict(resource or {})
        data_labels = list(data_labels or [])

        if self.killed:
            return self._killed_result("tool.call", capability, resource, data_labels)

        # 1. Authority: is there an effective capability for this (action, resource)?
        cap = self.bundle.authorizing_capability(capability, resource)
        if cap is None:
            return self._deny(
                "tool.call",
                capability,
                resource,
                data_labels,
                message=f"no effective capability authorizes {capability!r} on {resource}",
                detail={"reason": "no_capability"},
            )

        tool = self.tools.get(name)
        if tool is None or tool.action != capability:
            return self._deny(
                "tool.call",
                capability,
                resource,
                data_labels,
                message=(
                    f"no tool {name!r} bound to capability {capability!r}"
                    if tool is None
                    else f"tool {name!r} performs {tool.action!r}, not {capability!r}"
                ),
                detail={"reason": "tool_mismatch"},
            )

        # 2. Policy: turn the call's context into an execution mode.
        context = self._policy_context(resource, data_labels, tool)
        decision = self.policy.decide(capability, context)

        # 3. Budget: a step is always consumed; tool cost only if it will execute.
        will_execute = decision.executes
        charge = self.budget.charge(
            usd=tool.cost_usd if will_execute else 0.0,
            tokens=tool.cost_tokens if will_execute else 0,
            steps=1,
        )
        if charge.exceeded:
            return self._budget_exceeded("tool.call", capability, resource, data_labels, charge)

        # 4. Act on the decision.
        if decision.is_deny:
            return self._finish(
                "tool.call", capability, decision, "denied", None, 0.0, resource,
                data_labels, message="blocked by policy", detail={"tool": name},
            )
        if decision.requires_approval:
            self.pending_approvals.append(
                {"action": capability, "decision": str(decision), "context": context}
            )
            return self._finish(
                "tool.call", capability, decision, "pending_approval", None, 0.0, resource,
                data_labels, message=f"gated: {decision} required before this can land",
                detail={"tool": name},
            )

        # The mode permits execution (live, or draft for allow_draft_only).
        mode = "draft" if decision.is_draft else "live"
        try:
            result = self._execute_tool(tool, args, mode=mode)
        except EgressDenied as exc:
            # The no-bypass invariant firing: code ran, but its egress was refused.
            return self._finish(
                "tool.call", capability, decision, "blocked", None, tool.cost_usd, resource,
                data_labels, message=str(exc), detail={"tool": name, "egress_blocked": True},
            )

        status = "draft" if decision.is_draft else "ok"
        message = "drafted; nothing shipped" if decision.is_draft else "executed"
        return self._finish(
            "tool.call", capability, decision, status, result, tool.cost_usd, resource,
            data_labels, message=message, detail={"tool": name},
        )

    def memory_write(
        self,
        scope: str,
        obj: dict[str, Any],
        provenance: dict[str, Any] | None = None,
        *,
        long_term: bool = False,
        data_labels: list[str] | None = None,
    ) -> SyscallResult:
        """`memory.write` — provenance-checked; long-term low-trust writes are held."""
        data_labels = list(data_labels or [])
        resource = {"scope": scope, "long_term": long_term}

        if self.killed:
            return self._killed_result("memory.write", "memory.write", resource, data_labels)

        context = {
            "resource": resource,
            "data": {"labels": data_labels},
            "destination": {"external": False},
        }
        decision = self.policy.decide("memory.write", context)

        charge = self.budget.charge(steps=1)
        if charge.exceeded:
            return self._budget_exceeded(
                "memory.write", "memory.write", resource, data_labels, charge
            )

        if decision.is_deny:
            return self._finish(
                "memory.write", "memory.write", decision, "denied", None, 0.0, resource,
                data_labels, message="blocked by policy",
            )
        if decision.requires_approval:
            self.pending_approvals.append(
                {"action": "memory.write", "decision": str(decision), "context": context}
            )
            return self._finish(
                "memory.write", "memory.write", decision, "pending_approval", None, 0.0,
                resource, data_labels, message=f"gated: {decision} required",
            )

        try:
            record = self.memory.write(scope, obj, provenance, long_term=long_term)
        except ProvenanceRejected as exc:
            return self._finish(
                "memory.write", "memory.write", decision, "rejected", None, 0.0, resource,
                data_labels, message=str(exc), detail={"reason": "missing_provenance"},
            )

        if record.status == "held_for_review":
            return self._finish(
                "memory.write", "memory.write", decision, "held_for_review",
                {"status": record.status}, 0.0, resource, data_labels,
                message="low-trust source held for consolidation review",
                detail=record.detail,
            )
        return self._finish(
            "memory.write", "memory.write", decision, "ok", {"status": record.status},
            0.0, resource, data_labels, message="committed",
        )

    def approval_request(
        self, action: str, context: dict[str, Any] | None = None
    ) -> SyscallResult:
        """`approval.request` — record a pending human decision for an action."""
        if self.killed:
            return self._killed_result("approval.request", action, {}, [])
        charge = self.budget.charge(steps=1)
        if charge.exceeded:
            return self._budget_exceeded("approval.request", action, {}, [], charge)
        self.pending_approvals.append({"action": action, "context": dict(context or {})})
        return self._finish(
            "approval.request", action, Decision.REQUIRE_HUMAN_APPROVAL,
            "pending_approval", None, 0.0, {}, [], message="awaiting human approval",
        )

    # =====================================================================
    # Control-plane (operator only; never agent-callable)
    # =====================================================================

    def run_kill(self, reason: str = "control-plane kill") -> SyscallResult:
        """`run.kill` — stop the run. Further agent syscalls are refused."""
        self.killed = True
        self.kill_reason = reason
        return self._finish(
            "run.kill", "run.kill", None, "killed", None, 0.0, {}, [], message=reason,
            detail={"budget": self.budget.snapshot()},
        )

    # =====================================================================
    # Internals
    # =====================================================================

    def _execute_tool(self, tool: Tool, args: dict[str, Any], *, mode: str) -> Any:
        """Run a tool server-side, injecting its secret and/or sandbox as needed."""
        sandbox = self._sandbox if tool.external else None
        if tool.secret is not None:
            if not self.broker.is_bound(tool.secret):
                raise MandateError(f"tool {tool.name!r} needs unbound secret {tool.secret!r}")
            return self.broker.inject(
                tool.secret,
                lambda value: tool.execute(
                    args, mode=mode, secret_value=value, sandbox=sandbox, subject=self.subject
                ),
            )
        return tool.execute(args, mode=mode, sandbox=sandbox, subject=self.subject)

    def _policy_context(
        self, resource: dict[str, Any], data_labels: list[str], tool: Tool
    ) -> dict[str, Any]:
        return {
            "resource": resource,
            "data": {"labels": data_labels},
            "destination": {"external": bool(tool.external)},
            "recipient": resource.get("recipient") or {},
            "cost_usd": tool.cost_usd,
        }

    def _budget_exceeded(
        self,
        syscall: str,
        action: str,
        resource: dict[str, Any],
        data_labels: list[str],
        charge: ChargeResult,
    ) -> SyscallResult:
        """Apply the configured ``on_exceed`` policy: kill / pause / escalate."""
        on_exceed = self.budget.on_exceed
        detail = {"breached": list(charge.breached), "budget": self.budget.snapshot()}
        if on_exceed == "escalate":
            self.pending_approvals.append(
                {"action": action, "decision": str(Decision.REQUIRE_BUDGET_INCREASE)}
            )
            return self._finish(
                syscall, action, Decision.REQUIRE_BUDGET_INCREASE, "pending_approval",
                None, 0.0, resource, data_labels,
                message=f"budget exceeded ({', '.join(charge.breached)}); escalated",
                detail=detail,
            )
        # kill (default) and pause both stop the run; pause is a resumable kill.
        self.killed = True
        self.kill_reason = f"budget exceeded: {', '.join(charge.breached)}"
        kill_detail = {**detail, "trigger": syscall}
        # Audit the control-plane kill as a run.kill; the agent still sees *their*
        # syscall come back killed.
        event = self.audit.append(
            syscall="run.kill",
            principal=self.subject.principal,
            action="run.kill",
            status="killed",
            decision=None,
            cost_usd=0.0,
            resource=resource,
            data_labels=data_labels,
            detail=kill_detail,
        )
        return SyscallResult(
            syscall=syscall,
            status="killed",
            decision=None,
            result=None,
            cost_usd=0.0,
            audit_seq=event.seq,
            message=f"run killed — {self.kill_reason}",
            detail=kill_detail,
        )

    def _deny(
        self,
        syscall: str,
        action: str,
        resource: dict[str, Any],
        data_labels: list[str],
        *,
        message: str,
        detail: dict[str, Any] | None = None,
    ) -> SyscallResult:
        """Refuse a call that lacks authority (charges the step it consumed).

        Even an unauthorized call consumes a metered step, so if that step trips the
        budget the kill switch fires here too — denied calls cannot be used to spam the
        syscall boundary indefinitely under a step ceiling.
        """
        charge = self.budget.charge(steps=1)
        if charge.exceeded:
            return self._budget_exceeded(syscall, action, resource, data_labels, charge)
        return self._finish(
            syscall, action, Decision.DENY, "denied", None, 0.0, resource, data_labels,
            message=message, detail=detail,
        )

    def _killed_result(
        self, syscall: str, action: str, resource: dict[str, Any], data_labels: list[str]
    ) -> SyscallResult:
        return self._finish(
            syscall, action, None, "killed", None, 0.0, resource, data_labels,
            message=f"run is killed: {self.kill_reason}",
        )

    def _finish(
        self,
        syscall: str,
        action: str,
        decision: Decision | None,
        status: str,
        result: Any,
        cost_usd: float,
        resource: dict[str, Any],
        data_labels: list[str],
        *,
        message: str = "",
        detail: dict[str, Any] | None = None,
    ) -> SyscallResult:
        """Append the audit event for a completed syscall and return its result."""
        event: AuditEvent = self.audit.append(
            syscall=syscall,
            principal=self.subject.principal,
            action=action,
            status=status,
            decision=str(decision) if decision is not None else None,
            cost_usd=cost_usd,
            resource=resource,
            data_labels=data_labels,
            detail=detail or {},
        )
        return SyscallResult(
            syscall=syscall,
            status=status,
            decision=decision,
            result=result,
            cost_usd=cost_usd,
            audit_seq=event.seq,
            message=message,
            detail=detail or {},
        )
