"""A process-isolated kernel — the real boundary the in-process channel only models.

Three reviews established a theorem: in a *shared interpreter* the agent can always
reach the transport's internals (an attribute, then a queue, then a reply box, then via
``gc``) and forge the result it *observes*, or simply fabricate a ``SyscallResult`` value.
None of that breaks INV-1 — every real effect is still kernel-mediated — but it means the
in-process channel cannot, even in principle, guarantee that the observed result came from
the kernel.

The contract is explicit that isolation is the sandbox/process layer's job (§2, §13:
*use* E2B / Firecracker / gVisor), not the SDK's. This module is the minimal realization
of that line: the kernel runs in a **separate process**, and the agent holds only a pipe.
The gateway, the broker, the secret vault, and the per-call reply state live in another
address space — so there is nothing for agent code to reach or pre-seed (not via
attributes, not via ``gc.get_objects()``), and a result can only be what the kernel sent
back over the pipe. A denied call is observed as denied, full stop.

The agent connection accepts *only* syscalls; operator inspection (audit, budget) flows on
a separate control connection the agent never holds.
"""

from __future__ import annotations

import multiprocessing as mp
import threading
from typing import TYPE_CHECKING, Any, Callable

from ..errors import MandateError
from .syscalls import SyscallResult

if TYPE_CHECKING:
    from .gateway import SyscallGateway

GatewayFactory = Callable[..., "SyscallGateway"]


# ---------------------------------------------------------------------------
# Child process: build the gateway here so it never exists in the agent's heap.
# ---------------------------------------------------------------------------


def _dispatch(gateway: "SyscallGateway", syscall: str, payload: dict[str, Any]) -> SyscallResult:
    p = payload
    if syscall == "tool.call":
        return gateway.tool_call(
            p["capability"], p["name"], p.get("args"),
            resource=p.get("resource"), data_labels=p.get("data_labels"),
        )
    if syscall == "memory.write":
        return gateway.memory_write(
            p["scope"], p["obj"], p.get("provenance"),
            long_term=p.get("long_term", False), data_labels=p.get("data_labels"),
        )
    if syscall == "approval.request":
        return gateway.approval_request(p["action"], p.get("context"))
    return SyscallResult(syscall=syscall, status="denied", message=f"unknown syscall {syscall!r}")


def _inspect(gateway: "SyscallGateway", what: str) -> Any:
    if what == "subject":
        return gateway.subject
    if what == "audit":
        return list(gateway.audit.events)
    if what == "budget":
        return gateway.budget.snapshot()
    if what == "killed":
        return gateway.killed
    if what == "dashboard":
        from ..dashboard import render_for_gateway

        return render_for_gateway(gateway)
    raise MandateError(f"unknown inspection {what!r}")


def _serve(agent_conn, control_conn, factory: GatewayFactory, args: tuple) -> None:
    from multiprocessing.connection import wait

    gateway = factory(*args)  # privileged objects are created here, in the child only
    open_conns = {agent_conn, control_conn}
    while open_conns:
        for conn in wait(list(open_conns)):
            try:
                message = conn.recv()
            except EOFError:
                open_conns.discard(conn)
                continue
            kind = message[0]
            if kind == "stop":
                open_conns.discard(conn)
                continue
            if conn is agent_conn and kind == "syscall":
                _, syscall, payload = message
                conn.send(_dispatch(gateway, syscall, payload))
            elif conn is control_conn and kind == "inspect":
                try:
                    conn.send(("ok", _inspect(gateway, message[1])))
                except Exception as exc:  # pragma: no cover - defensive
                    conn.send(("err", str(exc)))
            else:
                # The agent connection may ONLY issue syscalls; nothing else is honoured.
                conn.send(
                    SyscallResult(syscall="?", status="denied", message="channel not permitted")
                )


# ---------------------------------------------------------------------------
# Parent process: the agent end is a pipe; it holds no kernel state at all.
# ---------------------------------------------------------------------------


class _ProcessChannel:
    """Agent end of a cross-process syscall channel. Holds only a pipe + a lock."""

    def __init__(self, conn, lock: threading.Lock, timeout: float) -> None:
        self._conn = conn
        self._lock = lock
        self._timeout = timeout

    def send(self, syscall: str, payload: dict[str, Any]) -> SyscallResult:
        with self._lock:
            self._conn.send(("syscall", syscall, payload))
            if not self._conn.poll(self._timeout):
                raise MandateError("syscall channel timed out waiting for the kernel")
            result = self._conn.recv()
        if not isinstance(result, SyscallResult):
            raise MandateError("malformed kernel response")
        return result


class ProcessKernelService:
    """Runs a gateway in a separate process; hands the agent a pipe-bound client.

    ``factory`` (with ``args``) is called *inside the child* to build the gateway, so no
    privileged object is ever constructed in — or pickled into — the agent's process.
    Operators use the inspection methods (over a private control pipe); the agent gets only
    :meth:`client`.
    """

    def __init__(self, factory: GatewayFactory, args: tuple = (), *, timeout: float = 15.0) -> None:
        ctx = mp.get_context("fork")
        self._timeout = timeout
        self._agent_conn, child_agent = ctx.Pipe()
        self._control_conn, child_control = ctx.Pipe()
        self._proc = ctx.Process(
            target=_serve, args=(child_agent, child_control, factory, args), daemon=True
        )
        self._proc.start()
        child_agent.close()
        child_control.close()
        self._agent_lock = threading.Lock()
        self._control_lock = threading.Lock()
        self._subject = self._inspect("subject")

    # -- operator-side inspection (never reachable by the agent) ----------------

    def _inspect(self, what: str) -> Any:
        with self._control_lock:
            self._control_conn.send(("inspect", what))
            if not self._control_conn.poll(self._timeout):
                raise MandateError("kernel control channel timed out")
            status, value = self._control_conn.recv()
        if status != "ok":
            raise MandateError(f"kernel inspection failed: {value}")
        return value

    @property
    def subject(self):
        return self._subject

    @property
    def pid(self) -> int | None:
        return self._proc.pid

    def audit_events(self) -> list:
        return self._inspect("audit")

    def budget_snapshot(self) -> dict:
        return self._inspect("budget")

    def killed(self) -> bool:
        return self._inspect("killed")

    def dashboard(self) -> str:
        return self._inspect("dashboard")

    # -- agent-side -------------------------------------------------------------

    def client(self):
        from ..sdk.client import AgentClient

        channel = _ProcessChannel(self._agent_conn, self._agent_lock, self._timeout)
        return AgentClient(channel, self._subject)

    # -- lifecycle --------------------------------------------------------------

    def shutdown(self) -> None:
        for conn in (self._agent_conn, self._control_conn):
            try:
                conn.send(("stop",))
            except (OSError, BrokenPipeError, ValueError):
                pass
        self._proc.join(timeout=2.0)
        if self._proc.is_alive():  # pragma: no cover - defensive
            self._proc.terminate()
            self._proc.join(timeout=2.0)

    def __enter__(self) -> "ProcessKernelService":
        return self

    def __exit__(self, *exc: Any) -> bool:
        self.shutdown()
        return False
