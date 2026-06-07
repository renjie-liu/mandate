"""The syscall transport — the agent/kernel boundary made concrete (contract §2).

The agent-facing client must not merely *avoid an attribute* that points at the kernel;
it must hold **no reference to the gateway at all**, or the no-bypass claim is only as
strong as Python's (non-existent) privacy. So the agent talks to the kernel the way it
will in production: by putting plain-data syscall *messages* on a channel and reading
plain-data results back. The gateway lives on the far side.

In production the two sides are different processes (the agent inside the sandbox); here
a worker thread stands in for that boundary. Either way, walking the agent's object
graph never reaches the gateway, the broker, or the secret vault — only queues of data.

(Whole-heap introspection — ``gc.get_objects()`` — can still enumerate any object in a
shared interpreter. That is exactly what process/sandbox isolation removes, and is out of
scope for the in-process P0 simulation; it is the sandbox's job, not the SDK's.)
"""

from __future__ import annotations

import itertools
import queue
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..errors import MandateError
from .syscalls import SyscallResult

if TYPE_CHECKING:  # keep the gateway type out of this module's runtime globals
    from .gateway import SyscallGateway

_DEFAULT_TIMEOUT = 15.0


@dataclass
class _Request:
    rid: int
    syscall: str
    payload: dict[str, Any] = field(default_factory=dict)


_STOP = object()


class SyscallChannel:
    """A data-only transport. The agent end references queues of messages, never a kernel.

    All state here is plain data: an inbound request queue, an outbound response map, a
    condition variable, and an id counter. Nothing on this object refers to the gateway,
    so an agent that holds (only) this cannot walk its way to a subsystem.
    """

    def __init__(self, timeout: float = _DEFAULT_TIMEOUT) -> None:
        self._timeout = timeout
        self._requests: "queue.Queue[Any]" = queue.Queue()
        self._responses: dict[int, SyscallResult] = {}
        self._cond = threading.Condition()
        self._ids = itertools.count()

    # -- agent side ------------------------------------------------------------

    def send(self, syscall: str, payload: dict[str, Any]) -> SyscallResult:
        """Submit one syscall message and block for its result."""
        rid = next(self._ids)
        self._requests.put(_Request(rid, syscall, payload))
        with self._cond:
            ready = self._cond.wait_for(
                lambda: rid in self._responses, timeout=self._timeout
            )
            if not ready:
                raise MandateError("syscall channel timed out waiting for the kernel")
            return self._responses.pop(rid)

    # -- kernel side (used only by the worker, never by the agent) -------------

    def _next_request(self) -> Any:
        return self._requests.get()

    def _put_response(self, rid: int, response: SyscallResult) -> None:
        with self._cond:
            self._responses[rid] = response
            self._cond.notify_all()

    def _stop(self) -> None:
        self._requests.put(_STOP)


class KernelWorker:
    """Drains the channel and dispatches each message to the gateway, on its own thread.

    The worker references the gateway; the channel does not, and the agent references
    only the channel — so the gateway is reachable from the kernel side alone.
    """

    def __init__(self, gateway: "SyscallGateway", channel: SyscallChannel) -> None:
        self._gateway = gateway
        self._channel = channel
        self._thread = threading.Thread(target=self._loop, name="mandate-kernel", daemon=True)

    def start(self) -> "KernelWorker":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._channel._stop()
        self._thread.join(timeout=2.0)

    def _loop(self) -> None:
        while True:
            req = self._channel._next_request()
            if req is _STOP:
                return
            try:
                response = self._dispatch(req)
            except Exception as exc:  # never leave the agent blocked on a dead worker
                response = SyscallResult(
                    syscall=req.syscall, status="denied", message=f"kernel error: {exc}"
                )
            self._channel._put_response(req.rid, response)

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
    """Runs a gateway behind a :class:`SyscallChannel` and hands out agent clients.

    The *operator* holds the service (and through it the gateway, audit log, budget); the
    *agent* is handed only a client bound to the channel. Use as a context manager, or
    call :meth:`shutdown` to stop the worker.
    """

    def __init__(self, gateway: "SyscallGateway", *, timeout: float = _DEFAULT_TIMEOUT) -> None:
        self._gateway = gateway
        self._channel = SyscallChannel(timeout=timeout)
        self._worker = KernelWorker(gateway, self._channel).start()

    @property
    def gateway(self) -> "SyscallGateway":
        return self._gateway

    def client(self):
        """Return a fresh agent client that can reach the kernel only via the channel."""
        from ..sdk.client import AgentClient  # lazy: avoids a kernel↔sdk import cycle

        return AgentClient(self._channel, self._gateway.subject)

    def shutdown(self) -> None:
        self._worker.stop()

    def __enter__(self) -> "KernelService":
        return self

    def __exit__(self, *exc: Any) -> bool:
        self.shutdown()
        return False
