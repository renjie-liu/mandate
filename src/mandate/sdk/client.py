"""The agent-facing syscall client (contract §7, agent-facing set)."""

from __future__ import annotations

from typing import Any

from ..kernel.gateway import SyscallGateway
from ..kernel.syscalls import SyscallResult


class AgentClient:
    """What the agent harness holds. Every method crosses the kernel.

    The constructor takes the gateway, but the agent is only ever given the *client*,
    not the gateway — so the only verbs available are the three below. This is the SDK
    half of the no-bypass invariant: the attack surface is exactly this small.
    """

    def __init__(self, gateway: SyscallGateway) -> None:
        self._gateway = gateway

    @property
    def subject(self):
        """Read-only view of the identity every call runs under."""
        return self._gateway.subject

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
        return self._gateway.tool_call(
            capability, name, args, resource=resource, data_labels=data_labels
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
        return self._gateway.memory_write(
            scope, obj, provenance, long_term=long_term, data_labels=data_labels
        )

    def approval_request(
        self, action: str, context: dict[str, Any] | None = None
    ) -> SyscallResult:
        """Ask for human approval for an action the agent cannot self-authorize."""
        return self._gateway.approval_request(action, context)
