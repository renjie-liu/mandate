"""The policy engine: decide an execution mode for a syscall in context (§6).

``policy.decide`` is consulted before any agent-facing syscall completes. It returns an
**execution mode**, never a boolean. Rules are evaluated in order; the first whose
``match`` holds wins; if none match, the default is :attr:`Decision.ALLOW` (authority was
already proven by the capability check — policy only *narrows*).
"""

from __future__ import annotations

from typing import Any

from ..model import Decision, OrgPolicy, PolicyRule


class PolicyEngine:
    """Evaluates ordered :class:`PolicyRule` guardrails against a syscall context."""

    def __init__(
        self, rules: list[PolicyRule], *, default: Decision = Decision.ALLOW
    ) -> None:
        self._rules = list(rules)
        self._default = default

    @classmethod
    def from_org_policy(cls, org_policy: OrgPolicy) -> "PolicyEngine":
        return cls(list(org_policy.rules))

    @property
    def rules(self) -> tuple[PolicyRule, ...]:
        return tuple(self._rules)

    def decide(self, action: str, context: dict[str, Any] | None = None) -> Decision:
        """Return the execution mode for ``action`` in ``context`` (first match wins)."""
        ctx = dict(context or {})
        ctx["action"] = action
        for rule in self._rules:
            if _matches(rule.match, ctx):
                return rule.decision
        return self._default


def _matches(match: dict[str, Any], ctx: dict[str, Any]) -> bool:
    """True if every condition in ``match`` holds against ``ctx`` (conditions ANDed)."""
    for key, expected in match.items():
        if key == "action":
            if not _match_action(expected, str(ctx.get("action", ""))):
                return False
        elif key.endswith("_not_in"):
            # e.g. recipient.domain_not_in: [acme.com] — true when the value is absent.
            actual = _dig(ctx, key[: -len("_not_in")])
            if actual in set(_as_list(expected)):
                return False
        elif key == "data.labels":
            present = set(_as_list(_dig(ctx, "data.labels")))
            if not (set(_as_list(expected)) & present):
                return False
        else:
            if not _match_value(expected, _dig(ctx, key)):
                return False
    return True


def _match_action(pattern: str, action: str) -> bool:
    if pattern == "*":
        return True
    if pattern.endswith(".*"):
        return action == pattern[:-2] or action.startswith(pattern[:-1])
    return action == pattern


def _match_value(expected: Any, actual: Any) -> bool:
    if isinstance(expected, list):
        actual_set = set(_as_list(actual))
        return bool(actual_set & set(expected)) if actual_set else actual in expected
    return actual == expected


def _dig(ctx: dict[str, Any], dotted: str) -> Any:
    """Walk a dotted path like ``resource.branch`` through nested dicts."""
    node: Any = ctx
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]
