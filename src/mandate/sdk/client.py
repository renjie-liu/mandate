"""The agent-facing syscall client (contract §7, agent-facing set)."""

from __future__ import annotations

from typing import Any

from ..kernel.syscalls import SyscallResult
from ..kernel.transport import AgentEndpoint
from ..model.subject import AgentKernelSubject


class AgentClient:
    """What the agent harness holds. Every method crosses the kernel.

    It holds an :class:`~mandate.kernel.transport.AgentEndpoint` (the agent end of a
    data-only message channel) and the run's subject — and **nothing else**. There is no
    reference, direct or transitive, from this object to the gateway, the broker, the
    budget, the audit log, or the secret vault, and the endpoint has no response store or
    response-posting method, so a call's result comes only from the kernel.

    This makes the no-bypass claim hold at the reference-graph level, and makes the result
    the agent observes come only from the gateway (see the no-bypass tests). It does *not*
    claim to defeat whole-interpreter introspection (``gc.get_objects()``) or the fact that
    the agent can fabricate inert data objects in a shared process — that residue is the
    sandbox/process boundary's job (contract §2), which the in-process P0 only simulates.
    """

    def __init__(self, channel: AgentEndpoint, subject: AgentKernelSubject) -> None:
        self._channel = channel
        # A frozen value with no back-reference to the kernel — safe for the agent to hold.
        self._subject = subject

    @property
    def subject(self) -> AgentKernelSubject:
        """Read-only view of the identity every call runs under."""
        return self._subject

    def tool_call(
        self,
        capability: str,
        name: str,
        args: dict[str, Any] | None = None,
        *,
        resource: dict[str, Any] | None = None,
        data_labels: list[str] | None = None,
    ) -> SyscallResult:
        """Invoke a tool by name under a named capability."""
        return self._channel.send(
            "tool.call",
            {
                "capability": capability,
                "name": name,
                "args": args,
                "resource": resource,
                "data_labels": data_labels,
            },
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
        """Write to memory; the kernel enforces the provenance contract."""
        return self._channel.send(
            "memory.write",
            {
                "scope": scope,
                "obj": obj,
                "provenance": provenance,
                "long_term": long_term,
                "data_labels": data_labels,
            },
        )

    def approval_request(
        self, action: str, context: dict[str, Any] | None = None
    ) -> SyscallResult:
        """Ask for human approval for an action the agent cannot self-authorize."""
        return self._channel.send(
            "approval.request", {"action": action, "context": context}
        )
