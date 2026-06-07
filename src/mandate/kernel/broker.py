"""The secret broker (contract §2, §7 ``secret.inject``).

No tool or MCP server holds a usable credential. Secrets are broker-injected at the
gateway *during* a tool call, and the agent — and the tool code — never see plaintext.
This broker models that: it resolves a binding name to a broker reference, leases the
value to a server-side callback for the duration of one call, and returns only the
callback's (sanitized) result. There is deliberately **no method that returns a secret
value to the agent**; ``inject`` is the only way to use one, and it keeps the value on
the kernel side of the boundary.
"""

from __future__ import annotations

from typing import Callable, TypeVar

from ..errors import MandateError

T = TypeVar("T")


class SecretBroker:
    """Maps binding names → broker refs → values, and injects them server-side."""

    def __init__(
        self,
        bindings: dict[str, str],
        vault: dict[str, str] | None = None,
    ) -> None:
        # name -> "vault://acme/ss-key"
        self._bindings = dict(bindings)
        # "vault://acme/ss-key" -> actual secret value (a real broker would fetch this).
        self._vault = dict(vault or {})

    def is_bound(self, name: str) -> bool:
        return name in self._bindings

    def reference(self, name: str) -> str | None:
        """The broker *reference* for a name — safe to log; never the value."""
        return self._bindings.get(name)

    def inject(self, name: str, use: Callable[[str], T]) -> T:
        """Lease the secret named *name* to ``use`` for one call and return its result.

        The plaintext value exists only inside ``use`` (kernel-side tool code) and is
        never returned to the caller. This is the injection point: the tool receives a
        live credential, the agent receives only the sanitized outcome.
        """
        ref = self._bindings.get(name)
        if ref is None:
            raise MandateError(f"no secret binding for {name!r}")
        if ref not in self._vault:
            raise MandateError(
                f"broker reference {ref!r} for {name!r} does not resolve to a value"
            )
        value = self._vault[ref]
        return use(value)
