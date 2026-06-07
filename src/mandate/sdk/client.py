"""The agent-facing syscall client (contract §7, agent-facing set)."""

from __future__ import annotations

from typing import Any

from ..kernel.gateway import SyscallGateway
from ..kernel.syscalls import SyscallResult
from ..model.subject import AgentKernelSubject


class AgentClient:
    """What the agent harness holds. Every method crosses the kernel.

    The three syscalls are bound as closures over the gateway rather than stored as an
    attribute, so there is no ``agent._gateway`` (hence no ``agent._gateway.broker._vault``)
    path from agent-reachable state into the kernel's subsystems.

    This is hygiene, **not** the security boundary. CPython offers no true privacy — a
    closure cell is still reachable via ``__closure__`` / ``gc`` — so the no-bypass
    guarantee (INV-1) does not rest on it. It rests on the sandbox/process boundary
    (contract §2): in production the agent runs *inside* the sandbox and reaches the
    kernel only by sending syscalls across it, so it never holds this object at all. The
    egress and broker behaviour — exercised by the no-bypass tests — is the real boundary;
    this surface just keeps the in-process simulation from handing the keys over for free.
    """

    def __init__(self, gateway: SyscallGateway) -> None:
        subject = gateway.subject

        def tool_call(
            capability: str,
            name: str,
            args: dict[str, Any] | None = None,
            *,
            resource: dict[str, Any] | None = None,
            data_labels: list[str] | None = None,
        ) -> SyscallResult:
            """Invoke a tool by name under a named capability."""
            return gateway.tool_call(
                capability, name, args, resource=resource, data_labels=data_labels
            )

        def memory_write(
            scope: str,
            obj: dict[str, Any],
            provenance: dict[str, Any] | None = None,
            *,
            long_term: bool = False,
            data_labels: list[str] | None = None,
        ) -> SyscallResult:
            """Write to memory; the kernel enforces the provenance contract."""
            return gateway.memory_write(
                scope, obj, provenance, long_term=long_term, data_labels=data_labels
            )

        def approval_request(
            action: str, context: dict[str, Any] | None = None
        ) -> SyscallResult:
            """Ask for human approval for an action the agent cannot self-authorize."""
            return gateway.approval_request(action, context)

        self.tool_call = tool_call
        self.memory_write = memory_write
        self.approval_request = approval_request
        # The subject is a frozen value with no back-reference to the kernel — safe to hold.
        self._subject: AgentKernelSubject = subject

    @property
    def subject(self) -> AgentKernelSubject:
        """Read-only view of the identity every call runs under."""
        return self._subject
