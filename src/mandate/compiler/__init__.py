"""The Mandate compiler: manifests → effective capability bundle (the "binary").

``effective = image.constraints ⊓ deployment.grants ⊓ org.policy ⊓ runtime.quota``

P0 implements the ``requests ∩ grants`` half and accepts an (optional, possibly empty)
org-policy as a first-class meet input. The compiler rejects at *build* time — never
at runtime — a grant that is not a subset of a request, a binding that loosens an image
ceiling, or a grant missing an ``expires`` that org policy requires.
"""

from .bundle import CapabilityBundle, EffectiveBudget, MemoryPolicy
from .compile import compile_bundle
from .loader import load_deployment, load_image, load_manifest, load_org_policy

__all__ = [
    "compile_bundle",
    "CapabilityBundle",
    "EffectiveBudget",
    "MemoryPolicy",
    "load_manifest",
    "load_image",
    "load_deployment",
    "load_org_policy",
]
