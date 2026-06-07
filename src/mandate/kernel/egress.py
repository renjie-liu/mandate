"""Sandbox egress enforcement — the no-bypass invariant in code (contract §2).

> INV-1 (No bypass): there is no path from agent-controlled execution to an external
> side effect that does not cross the kernel.

The agent's code-execution tool runs *inside* a :class:`Sandbox`. The sandbox has no raw
network primitive of its own — its only way out is :meth:`Sandbox.fetch`, which consults
the :class:`EgressGuard`. Egress is **deny-by-default**: a host is reachable only if it is
on the compiled allow-list. A prompt-injected agent can write code that *tries* to
``curl`` an attacker domain (or exfiltrate a key), but the attempt dies at this boundary
— and is audited. This is the difference between a kernel and a cooperative SDK wrapper.
"""

from __future__ import annotations

from typing import Callable
from urllib.parse import urlparse

from ..errors import EgressDenied


class EgressGuard:
    """A deny-by-default host allow-list."""

    def __init__(self, allow: list[str]) -> None:
        self._allow = {h.lower() for h in allow}

    @property
    def allowed_hosts(self) -> frozenset[str]:
        return frozenset(self._allow)

    def is_allowed(self, host: str) -> bool:
        return host.lower() in self._allow

    def check(self, url: str) -> str:
        """Return the host if reachable; raise :class:`EgressDenied` otherwise."""
        host = urlparse(url).hostname or ""
        if not self.is_allowed(host):
            raise EgressDenied(
                f"egress to {host or url!r} blocked: not on the deny-by-default "
                f"allow-list {sorted(self._allow)}"
            )
        return host


class Sandbox:
    """The isolated execution context the agent's code tool runs in.

    Network is reachable *only* through :meth:`fetch`; there is no other egress
    primitive. An optional ``on_egress`` callback lets the kernel audit every attempt —
    allowed or denied — so even blocked exfiltration leaves a trace.
    """

    def __init__(
        self,
        egress: EgressGuard,
        on_egress: Callable[[str, str, bool], None] | None = None,
        fetcher: Callable[[str], str] | None = None,
    ) -> None:
        self._egress = egress
        self._on_egress = on_egress
        # The simulated network. A real sandbox would make the actual request here,
        # but only *after* the guard has approved the host.
        self._fetcher = fetcher or (lambda url: f"<{url}>")

    def fetch(self, url: str) -> str:
        """Attempt an outbound request. Allowed hosts pass; everything else is denied."""
        host = urlparse(url).hostname or ""
        try:
            self._egress.check(url)
        except EgressDenied:
            if self._on_egress is not None:
                self._on_egress(url, host, False)
            raise
        if self._on_egress is not None:
            self._on_egress(url, host, True)
        return self._fetcher(url)
