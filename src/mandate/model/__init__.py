"""The Mandate manifest data model and capability algebra.

Pure data + pure functions: no I/O, no enforcement. The compiler and kernel build
on these types. Keeping the algebra (subset, meet, sensitivity ordering) here — and
testable in isolation — is deliberate: it is the part of the wedge that decides what
authority an agent actually holds.
"""

from .capability import Capability
from .deployment import AgentDeployment, Budget
from .image import AgentImage, ToolRequest
from .policy import Decision, OrgPolicy, PolicyRule
from .sensitivity import SENSITIVITY_ORDER, sensitivity_at_most, sensitivity_level
from .subject import AgentKernelSubject

__all__ = [
    "Capability",
    "AgentImage",
    "ToolRequest",
    "AgentDeployment",
    "Budget",
    "OrgPolicy",
    "PolicyRule",
    "Decision",
    "AgentKernelSubject",
    "SENSITIVITY_ORDER",
    "sensitivity_level",
    "sensitivity_at_most",
]
