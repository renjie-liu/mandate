"""The capability object and its algebra (contract §5).

A capability expresses **static authority only**: resource + action + static scope +
expiry. Nothing conditional. Anything that depends on the runtime context of a
specific call (``cost_usd > 0``, ``recipient external``, a risk score) is *policy*
(§6), never a field here. Keeping the two grammars apart is load-bearing.

The two operations that matter:

* :meth:`Capability.is_subset_of` — the rule the compiler enforces when checking that a
  grant ⊆ a request. Granting *more* than was requested is rejected.
* :meth:`Capability.meet` — the lattice meet (∧) of two capabilities with the same
  action: per-dimension intersection. Compilation takes the meet of request and grant.

A capability also answers the runtime question :meth:`authorizes`: does this static
grant cover a concrete ``(action, resource)`` a syscall is attempting?
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .sensitivity import sensitivity_at_most, sensitivity_level

# The default sensitivity ceiling when a capability omits ``data.max_sensitivity``.
DEFAULT_MAX_SENSITIVITY = "internal"


def _as_set(value: Any) -> set:
    """Normalize a scalar-or-list dimension value into a set for subset comparison."""
    if isinstance(value, (list, tuple, set)):
        return set(value)
    return {value}


def _dimension_subset(grant_value: Any, request_value: Any) -> bool:
    """True if a single resource/scope dimension of a grant ⊆ that of a request.

    The request is the ceiling; the grant narrows it. A dimension the grant omits is
    *inherited* from the request (the deployment narrows only what it explicitly
    states), so omission can never exceed the request:

    * request unconstrained (``None``) → any grant value is a subset (True).
    * grant silent (``None``) → inherits the request's ceiling → subset (True).
    * both booleans → grant may only narrow (``include_private: true`` ⊄ ``false``).
    * both list/scalar → ordinary set-subset.

    The only way to fail is for the grant to *explicitly* state a value broader than a
    value the request explicitly constrained.
    """
    if request_value is None or grant_value is None:
        return True
    if isinstance(request_value, bool) or isinstance(grant_value, bool):
        # A truthy grant (e.g. include_private) requires a truthy request.
        return (not grant_value) or bool(request_value)
    return _as_set(grant_value) <= _as_set(request_value)


def _dimension_meet(a_value: Any, b_value: Any) -> Any:
    """Per-dimension lattice meet (the narrower of two dimension values)."""
    if a_value is None:
        return b_value
    if b_value is None:
        return a_value
    if isinstance(a_value, bool) or isinstance(b_value, bool):
        return bool(a_value) and bool(b_value)
    return sorted(_as_set(a_value) & _as_set(b_value))


_MISSING = object()


def _candidate_keys(dim: str) -> list[str]:
    """Morphological variants of a dimension key (``branches`` ↔ ``branch``, etc.).

    Capability dimensions are typically plural (``repos``, ``branches``) while a syscall
    usually names a single resource (``repo``, ``branch``). We try the exact key, common
    singular forms, and the plural forms so the two always meet.
    """
    keys: list[str] = []

    def add(key: str) -> None:
        if key and key not in keys:
            keys.append(key)

    add(dim)
    if dim.endswith("ies"):
        add(dim[:-3] + "y")  # categories -> category
    if dim.endswith("es"):
        add(dim[:-2])  # branches -> branch
    if dim.endswith("s"):
        add(dim[:-1])  # repos -> repo
    add(dim + "s")
    add(dim + "es")
    return keys


def _resource_value(resource: dict[str, Any], dim: str) -> Any:
    """Find the runtime value for a capability dimension, tolerating singular/plural.

    Returns ``_MISSING`` when the caller specified nothing for this dimension, so a
    branch-scoped capability is actually enforced against a call that passes ``branch``
    rather than silently skipping the check because the key form didn't match.
    """
    for key in _candidate_keys(dim):
        if key in resource:
            return resource[key]
    return _MISSING


@dataclass(frozen=True)
class Capability:
    """A static grant of authority: ``provider.resource.action`` + scope + expiry."""

    action: str
    resources: dict[str, Any] = field(default_factory=dict)
    scope: dict[str, Any] = field(default_factory=dict)
    max_sensitivity: str = DEFAULT_MAX_SENSITIVITY
    expires: str | None = None

    # -- construction ----------------------------------------------------------

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Capability":
        """Parse one capability object (request or grant) from manifest YAML.

        Accepts both the long form and the bare ``{capability: fs.workspace.rw}``
        shorthand (no resources/scope).
        """
        if "capability" not in raw:
            raise ValueError(f"capability object missing 'capability' key: {raw!r}")
        data = raw.get("data") or {}
        return cls(
            action=str(raw["capability"]),
            resources=dict(raw.get("resources") or {}),
            scope=dict(raw.get("scope") or {}),
            max_sensitivity=str(data.get("max_sensitivity", DEFAULT_MAX_SENSITIVITY)),
            expires=raw.get("expires"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize back to the manifest object form (used by the CLI)."""
        out: dict[str, Any] = {"capability": self.action}
        if self.resources:
            out["resources"] = dict(self.resources)
        if self.scope:
            out["scope"] = dict(self.scope)
        if self.max_sensitivity != DEFAULT_MAX_SENSITIVITY:
            out["data"] = {"max_sensitivity": self.max_sensitivity}
        if self.expires is not None:
            out["expires"] = self.expires
        return out

    # -- algebra ---------------------------------------------------------------

    def is_subset_of(self, other: "Capability") -> bool:
        """True if ``self`` ⊆ ``other`` per the contract §5 subset rule.

        Equal action; every resource and scope dimension narrower-or-equal; sensitivity
        ceiling no higher. ``self`` is the grant, ``other`` the request.
        """
        if self.action != other.action:
            return False
        for dim in self.resources.keys() | other.resources.keys():
            if not _dimension_subset(self.resources.get(dim), other.resources.get(dim)):
                return False
        for dim in self.scope.keys() | other.scope.keys():
            if not _dimension_subset(self.scope.get(dim), other.scope.get(dim)):
                return False
        return sensitivity_at_most(self.max_sensitivity, other.max_sensitivity)

    def meet(self, other: "Capability") -> "Capability":
        """The lattice meet (∧) with another capability of the *same* action.

        Per-dimension intersection; sensitivity ceiling is the ``min`` of the two;
        expiry is the sooner of the two. Used by the compiler to fold a request and a
        (subset) grant into the single effective capability.
        """
        if self.action != other.action:
            raise ValueError(
                f"cannot meet capabilities of different actions: "
                f"{self.action!r} ∧ {other.action!r}"
            )
        dims = self.resources.keys() | other.resources.keys()
        resources = {
            d: _dimension_meet(self.resources.get(d), other.resources.get(d)) for d in dims
        }
        sdims = self.scope.keys() | other.scope.keys()
        scope = {d: _dimension_meet(self.scope.get(d), other.scope.get(d)) for d in sdims}
        sensitivity = min(
            (self.max_sensitivity, other.max_sensitivity), key=sensitivity_level
        )
        return Capability(
            action=self.action,
            resources={k: v for k, v in resources.items() if v is not None},
            scope={k: v for k, v in scope.items() if v is not None},
            max_sensitivity=sensitivity,
            expires=_sooner_expiry(self.expires, other.expires),
        )

    # -- runtime authorization -------------------------------------------------

    def authorizes(self, action: str, resource: dict[str, Any] | None = None) -> bool:
        """True if this capability covers a concrete ``(action, resource)`` request.

        Two kinds of dimension are treated differently:

        * **resource identity** (``resources`` — e.g. ``repos``) — the caller *must*
          name which resource it is touching, and it must fall inside the grant. The
          kernel will not guess a resource on the agent's behalf.
        * **scope qualifiers** (``scope`` — e.g. ``include_private``, ``branches``) —
          static ceilings. They are checked only when the caller asserts them; absence
          means the call stays on the safe side of the ceiling. A capability leaves a
          dimension fully open by omitting it (an unscoped ``github.repo.write``
          authorizes any branch — it is *policy*, not the capability, that then gates
          writes to ``main``).
        """
        if self.action != action:
            return False
        resource = resource or {}
        for dim, allowed in self.resources.items():
            if allowed is None:
                continue
            value = _resource_value(resource, dim)
            if value is _MISSING:
                return False
            if not _dimension_subset(value, allowed):
                return False
        for dim, allowed in self.scope.items():
            if allowed is None:
                continue
            value = _resource_value(resource, dim)
            if value is not _MISSING and not _dimension_subset(value, allowed):
                return False
        return True

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        bits = [self.action]
        if self.resources:
            bits.append(f"resources={self.resources}")
        if self.scope:
            bits.append(f"scope={self.scope}")
        if self.expires:
            bits.append(f"expires={self.expires}")
        return " ".join(bits)


def _sooner_expiry(a: str | None, b: str | None) -> str | None:
    """Pick the sooner of two coarse ``"30d"``-style expiries (None = no expiry)."""
    if a is None:
        return b
    if b is None:
        return a
    return min((a, b), key=_expiry_seconds)


_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def _expiry_seconds(value: str) -> int:
    """Parse a coarse duration like ``"30d"`` / ``"24h"`` into seconds (best effort)."""
    value = value.strip()
    if not value:
        return 0
    unit = value[-1].lower()
    if unit in _UNIT_SECONDS:
        try:
            return int(float(value[:-1]) * _UNIT_SECONDS[unit])
        except ValueError:
            return 0
    try:
        return int(value)
    except ValueError:
        return 0
