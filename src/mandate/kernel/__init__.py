"""The Mandate kernel: the syscall gateway and the subsystems it mediates.

The gateway is the one place agent-controlled execution turns into a side effect.
Every agent-facing syscall passes through it, is decided by policy, charged to the
budget, and appended to the audit log — and the agent holds no reference that lets it
reach a subsystem directly. That is the no-bypass invariant (INV-1) in code.
"""

from .audit import AuditEvent, AuditLog
from .broker import SecretBroker
from .budget import BudgetMeter, ChargeResult
from .egress import EgressGuard, Sandbox
from .gateway import SyscallGateway
from .memory import MemoryRecord, MemoryStore
from .policy_engine import PolicyEngine
from .syscalls import SyscallResult
from .tools import Tool, ToolRegistry
from .transport import KernelService, KernelWorker, SyscallChannel

__all__ = [
    "SyscallGateway",
    "SyscallResult",
    "KernelService",
    "KernelWorker",
    "SyscallChannel",
    "PolicyEngine",
    "BudgetMeter",
    "ChargeResult",
    "AuditLog",
    "AuditEvent",
    "SecretBroker",
    "EgressGuard",
    "Sandbox",
    "MemoryStore",
    "MemoryRecord",
    "Tool",
    "ToolRegistry",
]
