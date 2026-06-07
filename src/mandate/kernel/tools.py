"""Tools as kernel-side drivers (contract §13: MCP servers are drivers, not the boundary).

A :class:`Tool` is server-side code the gateway invokes *after* a call is authorized and
decided. The agent never holds the tool; it asks the kernel to run one by name. A tool
declares the capability ``action`` it performs, its cost, whether it needs a sandbox for
egress, and which secret (if any) the broker must inject. Its ``fn`` receives the
injected secret value and/or a sandbox — both kernel-side — and returns a sanitized
result the agent may see.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

# fn(args, *, mode, secret_value=None, sandbox=None, subject=None) -> result
ToolFn = Callable[..., Any]


@dataclass(frozen=True)
class Tool:
    """A registered, capability-bound tool driver."""

    name: str
    action: str
    cost_usd: float = 0.0
    cost_tokens: int = 0
    external: bool = False  # performs outbound egress; runs inside the sandbox
    secret: str | None = None  # binding name the broker must inject
    fn: ToolFn | None = None

    def execute(
        self,
        args: dict[str, Any],
        *,
        mode: str = "live",
        secret_value: str | None = None,
        sandbox: Any = None,
        subject: Any = None,
    ) -> Any:
        if self.fn is None:
            # A trivial default so tests/demos can register a no-op tool.
            return {"tool": self.name, "mode": mode, "args": dict(args)}
        return self.fn(
            args,
            mode=mode,
            secret_value=secret_value,
            sandbox=sandbox,
            subject=subject,
        )


class ToolRegistry:
    """A name → :class:`Tool` map the gateway looks tools up in."""

    def __init__(self, tools: list[Tool] | None = None) -> None:
        self._tools: dict[str, Tool] = {}
        for tool in tools or []:
            self.register(tool)

    def register(self, tool: Tool) -> Tool:
        if tool.name in self._tools:
            raise ValueError(f"tool {tool.name!r} already registered")
        self._tools[tool.name] = tool
        return tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def __contains__(self, name: str) -> bool:
        return name in self._tools
