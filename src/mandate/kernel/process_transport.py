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
a separate control connection the agent never holds. And because the agent owns its end of
the pipe, every frame it sends is treated as **untrusted**: a malformed or non-syscall
message comes back as a denied result, never an exception that could crash the kernel.
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
    """Dispatch one (untrusted) agent frame. Never raises — malformed input → denied.

    The payload arrives over the agent pipe and is not to be trusted: a missing field or a
    tool/gateway error must come back as a denied result, never crash the kernel process.
    """
    try:
        if syscall == "tool.call":
            return gateway.tool_call(
                payload["capability"], payload["name"], payload.get("args"),
                resource=payload.get("resource"), data_labels=payload.get("data_labels"),
            )
        if syscall == "memory.write":
            return gateway.memory_write(
                payload["scope"], payload["obj"], payload.get("provenance"),
                long_term=payload.get("long_term", False), data_labels=payload.get("data_labels"),
            )
        if syscall == "approval.request":
            return gateway.approval_request(payload["action"], payload.get("context"))
        return SyscallResult(syscall=syscall, status="denied", message=f"unknown syscall {syscall!r}")
    except KeyError as exc:
        return SyscallResult(
            syscall=syscall, status="denied", message=f"malformed payload: missing {exc}"
        )
    except Exception as exc:  # a tool/gateway bug must not take down the kernel process
        return SyscallResult(syscall=syscall, status="denied", message=f"kernel error: {exc}")


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
            keep, reply = _serve_one(gateway, conn, conn is agent_conn)
            if reply is not None:
                try:
                    conn.send(reply)
                except (OSError, ValueError):  # peer went away mid-reply
                    keep = False
            if not keep:
                open_conns.discard(conn)
                try:
                    conn.close()
                except OSError:  # pragma: no cover - defensive
                    pass


def _serve_one(gateway: "SyscallGateway", conn, is_agent: bool):
    """Read and handle one **untrusted** frame. Returns ``(keep_open, reply_or_None)``.

    Agent-pipe input is adversarial: any malformed frame yields a denied result (or, on the
    operator control pipe, an error tuple) — never an exception that escapes and crashes the
    kernel process. Corrupt framing drops just that one connection; the process keeps
    serving the other.
    """
    try:
        message = conn.recv()
    except EOFError:
        return False, None
    except Exception:  # corrupt framing on this pipe — drop it, keep the process alive
        return False, None
    try:
        if not isinstance(message, tuple) or not message:
            raise ValueError("frame is not a non-empty tuple")
        kind = message[0]
        if kind == "stop":
            return False, None
        if is_agent:
            # The agent connection may ONLY issue well-formed syscalls.
            if kind != "syscall" or len(message) != 3 or not isinstance(message[2], dict):
                return True, SyscallResult(
                    syscall="?", status="denied", message="malformed syscall frame"
                )
            return True, _dispatch(gateway, str(message[1]), message[2])
        if kind != "inspect" or len(message) != 2:
            return True, ("err", "malformed control frame")
        try:
            return True, ("ok", _inspect(gateway, message[1]))
        except Exception as exc:
            return True, ("err", str(exc))
    except Exception as exc:  # last-resort guard: a bad frame must never crash the loop
        if is_agent:
            return True, SyscallResult(
                syscall="?", status="denied", message=f"kernel rejected frame: {exc}"
            )
        return True, ("err", f"kernel rejected frame: {exc}")


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
