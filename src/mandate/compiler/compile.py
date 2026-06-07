"""The compilation pass: lattice meet of image, deployment, and org policy (§4)."""

from __future__ import annotations

import hashlib

from ..errors import CompileError, SubsetViolation
from ..model import AgentDeployment, AgentImage, Capability, OrgPolicy
from ..model.subject import AgentKernelSubject
from .bundle import CapabilityBundle, EffectiveBudget, MemoryPolicy


def compile_bundle(
    image: AgentImage,
    deployment: AgentDeployment,
    org_policy: OrgPolicy | None = None,
    *,
    session: str,
    run: str,
    owner: str | None = None,
) -> CapabilityBundle:
    """Compile the three manifests into an effective :class:`CapabilityBundle`.

    Raises :class:`CompileError` / :class:`SubsetViolation` at build time for any
    inconsistency, so an agent never starts on an unsound bundle.
    """
    org_policy = org_policy or OrgPolicy.empty()

    capabilities = _compile_capabilities(image, deployment, org_policy)
    budget = _compile_budget(image, deployment, org_policy)
    egress_allow, deny_external = _compile_egress(image, deployment, org_policy)
    _check_secret_bindings(image, deployment, org_policy)

    subject = AgentKernelSubject(
        principal=deployment.principal,
        tenant=deployment.tenant,
        session=session,
        run=run,
        image_digest=deployment.image_digest,
        deployment_id=_deployment_id(deployment),
        owner=owner or _first_user(deployment.invoked_by),
        publisher=image.publisher,
    )

    memory_policy = MemoryPolicy(
        require_provenance=image.memory_writes.require_provenance,
        require_fields=list(image.memory_writes.require_fields),
        low_trust_source=image.memory_writes.low_trust_source,
    )

    return CapabilityBundle(
        subject=subject,
        capabilities=capabilities,
        egress_allow=egress_allow,
        deny_external_egress=deny_external,
        budget=budget,
        secret_bindings=dict(deployment.secret_bindings),
        memory_policy=memory_policy,
        org_policy=org_policy,
        image=image,
        deployment=deployment,
    )


def _compile_capabilities(
    image: AgentImage, deployment: AgentDeployment, org_policy: OrgPolicy
) -> list[Capability]:
    """``requests ∩ grants``: each grant must match and be a subset of a request."""
    requests = image.requested_capabilities
    effective: list[Capability] = []

    for grant in deployment.grants:
        request = _matching_request(requests, grant)
        if request is None:
            raise CompileError(
                f"deployment grants {grant.action!r} but the image never requests it; "
                f"a grant must answer a request"
            )
        if not grant.is_subset_of(request):
            raise SubsetViolation(
                f"grant for {grant.action!r} is not a subset of the image request "
                f"(installing may only narrow authority, never widen it): "
                f"grant={grant.to_dict()} request={request.to_dict()}"
            )
        if org_policy.require_capability_expiry and not grant.expires:
            raise CompileError(
                f"org policy requires an 'expires' on every granted capability, "
                f"but the grant for {grant.action!r} has none"
            )
        effective.append(request.meet(grant))

    return effective


def _matching_request(
    requests: list[Capability], grant: Capability
) -> Capability | None:
    """Find the image request a grant answers (same action)."""
    for req in requests:
        if req.action == grant.action:
            return req
    return None


def _compile_budget(
    image: AgentImage, deployment: AgentDeployment, org_policy: OrgPolicy
) -> EffectiveBudget:
    """Scalar limits meet by ``min``; an image ceiling may not be loosened."""
    max_steps = _meet_ceiling(
        "max_steps",
        image_ceiling=image.max_steps,
        deployment_value=deployment.budget.max_steps_per_run,
    )
    usd = _min_optional(deployment.budget.usd_per_day, org_policy.max_agent_usd_per_day)
    return EffectiveBudget(
        usd_per_day=usd,
        tokens_per_day=deployment.budget.tokens_per_day,
        max_steps_per_run=max_steps,
        on_exceed=deployment.budget.on_exceed,
    )


def _meet_ceiling(
    name: str, *, image_ceiling: int | None, deployment_value: int | None
) -> int | None:
    """Meet an image-declared ceiling with a deployment value.

    The image ceiling cannot be loosened (§8: image constraints "cannot be loosened
    later"). A deployment value above the ceiling is a misconfiguration, rejected here;
    a value at or below it is taken as-is (which is also the ``min``).
    """
    if image_ceiling is None:
        return deployment_value
    if deployment_value is None:
        return image_ceiling
    if deployment_value > image_ceiling:
        raise SubsetViolation(
            f"deployment sets {name}={deployment_value}, which loosens the image "
            f"ceiling of {image_ceiling}; a binding may not widen an image constraint"
        )
    return deployment_value


def _min_optional(*values: float | None) -> float | None:
    present = [v for v in values if v is not None]
    return min(present) if present else None


def _compile_egress(
    image: AgentImage, deployment: AgentDeployment, org_policy: OrgPolicy
) -> tuple[list[str], bool]:
    """Egress is deny-by-default; the effective allow-list is the image's request.

    Most-restrictive wins: org policy's ``deny_external_egress`` cannot be relaxed, and
    in P0 the deployment does not widen the image allow-list.
    """
    deny_external = org_policy.deny_external_egress
    allow = list(dict.fromkeys(image.egress_allow))  # de-dup, preserve order
    return allow, deny_external


def _check_secret_bindings(
    image: AgentImage, deployment: AgentDeployment, org_policy: OrgPolicy
) -> None:
    """Every *required* secret the image asks for must be bound to a broker ref."""
    for ask in image.secret_asks:
        name = ask.get("name")
        if ask.get("required") and name not in deployment.secret_bindings:
            raise CompileError(
                f"image requires secret {name!r} but the deployment binds no broker "
                f"reference for it"
            )
    for name, ref in deployment.secret_bindings.items():
        if org_policy.require_secret_broker and not _is_broker_ref(ref):
            raise CompileError(
                f"org policy requires broker-managed secrets, but {name!r} is bound to "
                f"a literal value instead of a broker reference (e.g. vault://...)"
            )


def _is_broker_ref(ref: str) -> bool:
    return isinstance(ref, str) and "://" in ref


def _deployment_id(deployment: AgentDeployment) -> str:
    digest = hashlib.sha1(
        f"{deployment.principal}|{deployment.image_ref}".encode()
    ).hexdigest()[:10]
    return f"dep_{digest}"


def _first_user(invoked_by: list[str]) -> str | None:
    for entry in invoked_by:
        if entry.startswith("user:"):
            return entry
    return invoked_by[0] if invoked_by else None
