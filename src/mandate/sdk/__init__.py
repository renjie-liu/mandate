"""The agent-facing SDK — the only way an agent acts.

An :class:`AgentClient` is a thin, deliberately small surface bound to one
:class:`~mandate.kernel.gateway.SyscallGateway`. It exposes exactly the agent-facing
syscalls and nothing else: no network primitive, no filesystem handle, no secret
accessor, no budget or audit object. If it isn't a method here, the agent cannot do it.
"""

from .client import AgentClient

__all__ = ["AgentClient"]
