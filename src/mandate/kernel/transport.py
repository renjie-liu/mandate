"""The syscall transport — the agent/kernel boundary made concrete (contract §2).

The agent must reach the kernel only by sending plain-data syscall *messages* and
receiving a result the **kernel** produced. Two things follow, and this module enforces
both with the *shape* of what each side holds:

1. **No reference to the kernel.** The agent end holds only a request queue, never the
   gateway/broker/budget/vault — so no walk of the agent's object graph reaches a
   subsystem. (Whole-interpreter introspection — ``gc.get_objects()`` — can still
   enumerate anything in one process; removing *that* is the sandbox's job, which P0
   simulates with a worker thread standing in for the process boundary.)

2. **No way to forge a response.** The channel is split into an :class:`AgentEndpoint`
   and a :class:`KernelEndpoint`. The agent end can submit a request and block for *its
   own* reply, delivered through a fresh per-call reply box; there is **no shared response
   store and no response-posting method on the agent's object**, so it cannot pre-seed or
   overwrite what a call returns. (A clean-ABI guarantee, not a hard boundary: in one
   interpreter the agent can always fabricate a ``SyscallResult`` value — but that is not a
   syscall and causes nothing, because every real effect happens on the kernel side.)
"""

from __future__ import annotations

import queue
import threading
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ..errors import MandateError
from .syscalls import SyscallResult

if TYPE_CHECKING:  # keep the gateway type out of this module's runtime globals
    from .gateway import SyscallGateway

_DEFAULT_TIMEOUT = 15.0
_STOP = object()


@dataclass
class _Request:
    """One in-flight syscall: plain-data message + a private box for its reply."""

    syscall: str
    payload: dict[str, Any]
    reply: "queue.Queue[SyscallResult]"


class AgentEndpoint:
    """The agent-held end of the channel: submit a request, await your own reply.

    Holds only the shared request queue. Each :meth:`send` creates a *local* one-shot
    reply box (not an attribute, not a shared map) that the kernel fills; there is no
    ``_responses`` store and no ``respond`` method here, so a denied call cannot be turned
    into a forged ``ok`` by anything reachable on this object.
    """

    def __init__(self, requests: "queue.Queue[Any]", timeout: float = _DEFAULT_TIMEOUT) -> None:
        self._requests = requests
        self._timeout = timeout

    def send(self, syscall: str, payload: dict[str, Any]) -> SyscallResult:
        reply: "queue.Queue[SyscallResult]" = queue.Queue(maxsize=1)
        self._requests.put(_Request(syscall, dict(payload), reply))
        try:
            return reply.get(timeout=self._timeout)
        except queue.Empty as exc:
            raise MandateError("syscall channel timed out waiting for the kernel") from exc


class KernelEndpoint:
    """The kernel-held end: receive requests, and a stop signal for shutdown."""

    def __init__(self, requests: "queue.Queue[Any]") -> None:
        self._requests = requests

    def receive(self) -> Any:
        return self._requests.get()

    def stop(self) -> None:
        self._requests.put(_STOP)


def make_channel(
    timeout: float = _DEFAULT_TIMEOUT,
) -> tuple[AgentEndpoint, KernelEndpoint]:
    """Create a connected (agent, kernel) endpoint pair over one request queue."""
    requests: "queue.Queue[Any]" = queue.Queue()
    return AgentEndpoint(requests, timeout=timeout), KernelEndpoint(requests)


class KernelWorker:
    """Drains the kernel endpoint and dispatches each message to the gateway, on a thread.

    The worker references the gateway and replies through each request's private box; the
    agent endpoint references neither, so the gateway is reachable from the kernel side
    alone and responses originate only here.
    """

    def __init__(self, gateway: "SyscallGateway", endpoint: KernelEndpoint) -> None:
        self._gateway = gateway
        self._endpoint = endpoint
        self._thread = threading.Thread(target=self._loop, name="mandate-kernel", daemon=True)

    def start(self) -> "KernelWorker":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._endpoint.stop()
        self._thread.join(timeout=2.0)

    def _loop(self) -> None:
        while True:
            req = self._endpoint.receive()
            if req is _STOP:
                return
            try:
                result = self._dispatch(req)
            except Exception as exc:  # never leave the agent blocked on a dead worker
                result = SyscallResult(
                    syscall=req.syscall, status="denied", message=f"kernel error: {exc}"
                )
            req.reply.put(result)

    def _dispatch(self, req: _Request) -> SyscallResult:
        g, p = self._gateway, req.payload
        if req.syscall == "tool.call":
            return g.tool_call(
                p["capability"], p["name"], p.get("args"),
                resource=p.get("resource"), data_labels=p.get("data_labels"),
            )
        if req.syscall == "memory.write":
            return g.memory_write(
                p["scope"], p["obj"], p.get("provenance"),
                long_term=p.get("long_term", False), data_labels=p.get("data_labels"),
            )
        if req.syscall == "approval.request":
            return g.approval_request(p["action"], p.get("context"))
        return SyscallResult(
            syscall=req.syscall, status="denied", message=f"unknown syscall {req.syscall!r}"
        )


class KernelService:
    """Runs a gateway behind a channel and hands out agent clients.

    The *operator* holds the service (and through it the gateway, audit log, budget); the
    *agent* is handed only a client bound to the agent endpoint. Use as a context manager,
    or call :meth:`shutdown` to stop the worker.
    """

    def __init__(self, gateway: "SyscallGateway", *, timeout: float = _DEFAULT_TIMEOUT) -> None:
        self._gateway = gateway
        self._agent_endpoint, kernel_endpoint = make_channel(timeout=timeout)
        self._worker = KernelWorker(gateway, kernel_endpoint).start()

    @property
    def gateway(self) -> "SyscallGateway":
        return self._gateway

    def client(self):
        """Return a fresh agent client that can reach the kernel only via the channel."""
        from ..sdk.client import AgentClient  # lazy: avoids a kernel↔sdk import cycle

        return AgentClient(self._agent_endpoint, self._gateway.subject)

    def shutdown(self) -> None:
        self._worker.stop()

    def __enter__(self) -> "KernelService":
        return self

    def __exit__(self, *exc: Any) -> bool:
        self.shutdown()
        return False
