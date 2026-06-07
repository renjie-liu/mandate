"""Mandate — a capability microkernel for AI agents.

This package is the P0 vertical slice of the kernel contract (v0.2). It compiles
author-declared agent images, private deployment grants, and organization policy
into an effective capability bundle, then enforces every side effect at a single
syscall boundary under one agent identity.

The layering mirrors ``docs/mandate-kernel-contract-v0.2.md``:

* :mod:`mandate.model`    — the manifest data model + capability algebra
* :mod:`mandate.compiler` — manifests → effective capability bundle (the "binary")
* :mod:`mandate.kernel`   — the syscall gateway + enforcement subsystems
* :mod:`mandate.sdk`      — the agent-facing syscall client (the only way to act)
"""

from .errors import (
    BudgetExceeded,
    CapabilityDenied,
    CompileError,
    EgressDenied,
    MandateError,
    ProvenanceRejected,
    RunKilled,
    SubsetViolation,
)

__version__ = "0.2.0"

__all__ = [
    "__version__",
    "MandateError",
    "CompileError",
    "SubsetViolation",
    "CapabilityDenied",
    "EgressDenied",
    "ProvenanceRejected",
    "BudgetExceeded",
    "RunKilled",
]
