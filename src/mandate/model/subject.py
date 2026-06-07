"""``AgentKernelSubject`` — the join key (contract §3).

The runtime identity that policy, audit, memory, secrets, and budget all reference.
Every syscall carries it. ``principal`` is simultaneously the memory namespace, the
credential scope, the policy subject, and the audit subject — one value, four jobs.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class AgentKernelSubject:
    """Stable identity threaded through every subsystem and every syscall."""

    principal: str  # e.g. agent://acme/scout
    tenant: str  # isolation domain
    session: str
    run: str
    image_digest: str | None = None
    deployment_id: str | None = None
    owner: str | None = None
    publisher: str | None = None

    def as_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return f"{self.principal} (tenant={self.tenant}, run={self.run})"
