"""The agent-facing syscall client (contract §7, agent-facing set)."""

from __future__ import annotations

from typing import Any

from ..kernel.syscalls import SyscallResult
from ..kernel.transport import AgentEndpoint
from ..model.subject import AgentKernelSubject


class AgentClient:
    """What the agent harness holds. Every method crosses the kernel.

    It holds a channel endpoint (the agent end of a data-only message channel) and the
    run's subject — and **nothing else**. Across both transports, there is no reference,
    direct or transitive, from this object to the gateway, the broker, the budget, the
    audit log, or the secret vault.

    How strong "no bypass" is depends on the transport behind the channel:

    * :class:`~mandate.kernel.transport.KernelService` (in-process) — a convenience for
      tests and single-process use. It keeps the gateway/secret unreachable, but it is
      **not an isolation boundary**: a determined in-process agent can reach the transport's
      request queue and forge the result it *observes*, or just fabricate a ``SyscallResult``.
      That is inert — every real effect is still kernel-mediated — but the observed result
      is not guaranteed kernel-sourced.
    * :class:`~mandate.kernel.process_transport.ProcessKernelService` — the real boundary
      (contract §2/§13). The kernel runs in a separate process; the agent holds only a
      pipe, so there is nothing to reach or pre-seed and a result can only be what the
      kernel sent back. This is what P1 hardens into a full sandbox (E2B/Firecracker).
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
