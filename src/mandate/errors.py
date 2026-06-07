"""Exception hierarchy for Mandate.

These split into two families:

* **Compile-time** (:class:`CompileError`, :class:`SubsetViolation`) — raised by the
  compiler when a manifest set is inconsistent. The contract is explicit that these
  are rejected at *build* time, not runtime (§4).
* **Runtime** (the rest) — raised inside the kernel when an agent-controlled action
  is refused at the syscall boundary. Most agent-facing syscalls turn these into a
  ``SyscallResult`` rather than propagating them, but the kernel raises internally so
  no refusal can be silently swallowed.
"""


class MandateError(Exception):
    """Base class for every Mandate error."""


class CompileError(MandateError):
    """A manifest set could not be compiled into an effective bundle."""


class SubsetViolation(CompileError):
    """A grant (or binding) is not a subset of / loosens the corresponding request.

    Installing is granting, and a grant may only ever *narrow* a request. A grant
    that authorizes more than the image asked for is a configuration bug, caught
    here before the agent ever runs.
    """


class CapabilityDenied(MandateError):
    """No effective capability authorizes the attempted action."""


class EgressDenied(MandateError):
    """A sandbox tried to reach a host outside the deny-by-default allow-list.

    This is the no-bypass invariant (INV-1) firing: agent-controlled code can
    *request* an external side effect, but the only route out of the sandbox is the
    kernel gateway, and unapproved hosts never pass.
    """


class ProvenanceRejected(MandateError):
    """A memory write was missing required provenance fields."""


class BudgetExceeded(MandateError):
    """A charge pushed a metered resource past its compiled ceiling."""


class RunKilled(MandateError):
    """The run has been killed (budget kill-switch or control-plane ``run.kill``)."""
