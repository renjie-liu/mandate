"""A process-isolated kernel — the real boundary the in-process channel only models.

Three reviews established a theorem: in a *shared interpreter* the agent can always
reach the transport's internals and forge the result it *observes* (inert — effects stay
kernel-mediated). The contract assigns isolation to the sandbox/process layer (§2, §13:
*use* E2B / Firecracker / gVisor), not the SDK. This module is the minimal realization of
that line: the kernel runs in a **separate process**, and the agent holds only a pipe.

Because the agent owns its end of the pipe, **everything it sends is untrusted** — bytes
chosen by a possibly-compromised agent. Two rules make that safe:

* **A safe wire format.** The agent pipe carries length-bounded **JSON**, never pickle.
  ``multiprocessing``'s default ``recv()`` would *unpickle* — i.e. run ``__reduce__`` —
  before any validation, which is remote code execution inside the privileged process.
  We use ``recv_bytes`` + ``json.loads`` instead, so agent bytes can only ever decode to
  primitive data; no object is constructed and no code runs in the kernel.
* **Validate, then dispatch.** Every decoded frame is schema- and type-checked at the
  boundary; the gateway only ever sees well-typed primitives. A malformed frame, an
  oversized frame, or a tool error becomes a denied/error result — never a crash.

The operator's control pipe (audit, budget) is a separate connection. It carries the
**same safe JSON wire** — never pickle — because in a *co-located* deployment (agent and
operator sharing one process, as in the demo/tests) agent code can ``gc``-reach it; treating
its bytes as untrusted means even that cannot become code execution. Inspection only ever
exposes audit / budget / subject — never the vault, which lives only in the kernel process.
Full agent-process isolation (the agent in its *own* process, holding only the syscall pipe)
is the P1 sandbox; this module makes every reachable pipe safe regardless.
"""

from __future__ import annotations

import json
import multiprocessing as mp
import threading
from dataclasses import asdict
from typing import TYPE_CHECKING, Any, Callable

from ..errors import MandateError
from ..model import Decision
from ..model.subject import AgentKernelSubject
from .audit import AuditEvent
from .syscalls import SyscallResult

if TYPE_CHECKING:
    from .gateway import SyscallGateway

GatewayFactory = Callable[..., "SyscallGateway"]

# Largest agent frame we will read. Generous for syscall args; caps a memory-exhaustion DoS.
_MAX_FRAME = 1 << 20  # 1 MiB


# ---------------------------------------------------------------------------
# Child process: build the gateway here so it never exists in the agent's heap.
# ---------------------------------------------------------------------------


def _denied(syscall: str, message: str) -> SyscallResult:
    return SyscallResult(syscall=syscall, status="denied", message=message)


def _dispatch(gateway: "SyscallGateway", syscall: str, payload: dict[str, Any]) -> SyscallResult:
    """Dispatch one validated agent frame. Never raises — bad input/driver error → denied.

    Field *types* are checked here (the wire format already guarantees primitives), so the
    gateway is only ever handed well-typed values and a malformed call can't crash it.
    """
    args = payload.get("args")
    resource = payload.get("resource")
    data_labels = payload.get("data_labels")
    if args is not None and not isinstance(args, dict):
        return _denied(syscall, "args must be an object")
    if resource is not None and not isinstance(resource, dict):
        return _denied(syscall, "resource must be an object")
    if data_labels is not None and (
        not isinstance(data_labels, list) or not all(isinstance(x, str) for x in data_labels)
    ):
        return _denied(syscall, "data_labels must be a list of strings")

    try:
        if syscall == "tool.call":
            capability, name = payload.get("capability"), payload.get("name")
            if not isinstance(capability, str) or not isinstance(name, str):
                return _denied(syscall, "capability and name must be strings")
            return gateway.tool_call(
                capability, name, args, resource=resource, data_labels=data_labels
            )
        if syscall == "memory.write":
            scope, obj = payload.get("scope"), payload.get("obj")
            if not isinstance(scope, str) or not isinstance(obj, dict):
                return _denied(syscall, "scope must be a string and obj an object")
            provenance = payload.get("provenance")
            if provenance is not None and not isinstance(provenance, dict):
                return _denied(syscall, "provenance must be an object")
            return gateway.memory_write(
                scope, obj, provenance,
                long_term=bool(payload.get("long_term", False)), data_labels=data_labels,
            )
        if syscall == "approval.request":
            action = payload.get("action")
            if not isinstance(action, str):
                return _denied(syscall, "action must be a string")
            context = payload.get("context")
            if context is not None and not isinstance(context, dict):
                return _denied(syscall, "context must be an object")
            return gateway.approval_request(action, context)
        return _denied(syscall, f"unknown syscall {syscall!r}")
    except Exception as exc:  # a gateway/tool bug must not take down the kernel process
        return _denied(syscall, f"kernel error: {exc}")


def _handle_agent_frame(gateway: "SyscallGateway", raw: bytes) -> SyscallResult:
    """Decode and validate one **untrusted** agent frame (JSON bytes), then dispatch."""
    try:
        frame = json.loads(raw.decode("utf-8"))
    except Exception:
        return _denied("?", "unparseable agent frame (expected JSON)")
    if not isinstance(frame, dict) or frame.get("op") != "syscall":
        return _denied("?", "malformed agent frame")
    syscall, payload = frame.get("syscall"), frame.get("payload")
    if not isinstance(syscall, str) or not isinstance(payload, dict):
        return _denied("?", "malformed agent frame")
    return _dispatch(gateway, syscall, payload)


def _inspect_json(gateway: "SyscallGateway", what: str) -> Any:
    """Operator inspection, returned as JSON-able data (never live objects)."""
    if what == "subject":
        return gateway.subject.as_dict()
    if what == "audit":
        return [asdict(event) for event in gateway.audit.events]
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
    live = {agent_conn, control_conn}
    while control_conn in live:
        try:
            ready = wait(list(live))
        except Exception:  # pragma: no cover - defensive
            return
        for conn in ready:
            if conn is control_conn:
                if _serve_control(gateway, control_conn):
                    return
            elif not _serve_agent(gateway, agent_conn):
                live.discard(agent_conn)
                _safe_close(agent_conn)


def _serve_agent(gateway: "SyscallGateway", conn) -> bool:
    """Handle one untrusted agent frame over the JSON wire. Returns keep-open."""
    try:
        raw = conn.recv_bytes(_MAX_FRAME)
    except EOFError:
        return False
    except Exception:
        return False  # oversized or corrupt framing → drop the agent connection
    result = _handle_agent_frame(gateway, raw)
    try:
        conn.send_bytes(_encode_result(result))
    except (OSError, ValueError):
        return False
    return True


def _serve_control(gateway: "SyscallGateway", conn) -> bool:
    """Operator control channel. Returns True to stop the kernel process.

    Uses the *same safe JSON wire as the agent pipe* — never pickle. The control pipe is
    meant for the operator, but in a co-located deployment (agent + operator in one process)
    agent code can reach it; treating its bytes as untrusted means even that can't be turned
    into code execution. Inspection only ever exposes audit/budget/subject — never the vault.
    """
    try:
        raw = conn.recv_bytes(_MAX_FRAME)
    except (EOFError, OSError):
        return True  # operator gone → shut down
    except Exception:
        return True
    try:
        message = json.loads(raw.decode("utf-8"))
    except Exception:
        _safe_send(conn, {"status": "err", "message": "unparseable control frame"})
        return False
    if isinstance(message, dict):
        if message.get("op") == "stop":
            return True
        if message.get("op") == "inspect":
            try:
                payload = {"status": "ok", "value": _inspect_json(gateway, message.get("what"))}
            except Exception as exc:
                payload = {"status": "err", "message": str(exc)}
            _safe_send(conn, payload)
            return False
    _safe_send(conn, {"status": "err", "message": "unknown control frame"})
    return False


def _safe_send(conn, payload: dict[str, Any]) -> None:
    try:
        conn.send_bytes(json.dumps(payload).encode("utf-8"))
    except (OSError, ValueError, TypeError):  # pragma: no cover - defensive
        pass


def _safe_close(conn) -> None:
    try:
        conn.close()
    except OSError:  # pragma: no cover - defensive
        pass


# -- JSON codec for SyscallResult (the only thing that crosses back to the agent) --------


def _result_to_dict(result: SyscallResult) -> dict[str, Any]:
    return {
        "syscall": result.syscall,
        "status": result.status,
        "decision": str(result.decision) if result.decision is not None else None,
        "result": result.result,
        "cost_usd": result.cost_usd,
        "audit_seq": result.audit_seq,
        "message": result.message,
        "detail": result.detail,
    }


def _encode_result(result: SyscallResult) -> bytes:
    # The gateway already normalized the result to JSON-safe data before auditing, so this
    # should always succeed. The fallback keeps the *audited status* intact (it does not
    # invent an "error") and merely drops an unexpectedly-unserializable result.
    try:
        return json.dumps(_result_to_dict(result)).encode("utf-8")
    except (TypeError, ValueError):  # pragma: no cover - gateway normalizes results
        safe = _result_to_dict(result)
        safe.update(result=None, detail={"result_unserializable": True})
        return json.dumps(safe).encode("utf-8")


def _result_from_dict(data: Any) -> SyscallResult:
    if not isinstance(data, dict):
        raise MandateError("malformed kernel response")
    decision = data.get("decision")
    return SyscallResult(
        syscall=str(data.get("syscall", "")),
        status=str(data.get("status", "")),
        decision=Decision(decision) if decision else None,
        result=data.get("result"),
        cost_usd=float(data.get("cost_usd") or 0.0),
        audit_seq=data.get("audit_seq"),
        message=str(data.get("message") or ""),
        detail=data.get("detail") if isinstance(data.get("detail"), dict) else {},
    )


def _decode_inspect(what: str, value: Any) -> Any:
    """Reconstruct operator-side objects from a JSON control response."""
    if what == "subject" and isinstance(value, dict):
        return AgentKernelSubject(**value)
    if what == "audit" and isinstance(value, list):
        return [AuditEvent(**event) for event in value]
    return value  # budget (dict), killed (bool), dashboard (str)


# ---------------------------------------------------------------------------
# Parent process: the agent end is a pipe; it holds no kernel state at all.
# ---------------------------------------------------------------------------


class _ProcessChannel:
    """Agent end of a cross-process syscall channel. Holds only a pipe + a lock.

    Sends JSON bytes and reads JSON bytes — no pickle in either direction on this pipe, so
    nothing the agent emits can construct an object in the kernel, and nothing the kernel
    returns is unpickled here.
    """

    def __init__(self, conn, lock: threading.Lock, timeout: float) -> None:
        self._conn = conn
        self._lock = lock
        self._timeout = timeout

    def send(self, syscall: str, payload: dict[str, Any]) -> SyscallResult:
        try:
            frame = json.dumps({"op": "syscall", "syscall": syscall, "payload": payload})
        except (TypeError, ValueError) as exc:
            # Non-primitive args never cross the boundary — fail fast in the agent process.
            raise MandateError(
                f"syscall payload must be JSON-serializable primitives "
                f"(objects do not cross the process boundary): {exc}"
            ) from exc
        try:
            with self._lock:
                self._conn.send_bytes(frame.encode("utf-8"))
                if not self._conn.poll(self._timeout):
                    raise MandateError("syscall channel timed out waiting for the kernel")
                raw = self._conn.recv_bytes(_MAX_FRAME)
        except (OSError, EOFError) as exc:
            raise MandateError("syscall channel is closed") from exc
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise MandateError("malformed kernel response") from exc
        return _result_from_dict(data)


class ProcessKernelService:
    """Runs a gateway in a separate process; hands the agent a pipe-bound client.

    ``factory`` (with ``args``) is called *inside the child* to build the gateway, so no
    privileged object is ever constructed in — or sent to — the agent's process. Operators
    use the inspection methods (over a control pipe); the agent gets only :meth:`client`,
    which reaches the kernel solely by sending JSON syscall frames. Both pipes use the same
    safe JSON wire, so neither can be turned into code execution by agent-reachable code.
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

    # -- operator-side inspection (control pipe; same safe JSON wire) ------------

    def _inspect(self, what: str) -> Any:
        with self._control_lock:
            self._control_conn.send_bytes(
                json.dumps({"op": "inspect", "what": what}).encode("utf-8")
            )
            if not self._control_conn.poll(self._timeout):
                raise MandateError("kernel control channel timed out")
            raw = self._control_conn.recv_bytes(_MAX_FRAME)
        message = json.loads(raw.decode("utf-8"))
        if not isinstance(message, dict) or message.get("status") != "ok":
            detail = message.get("message") if isinstance(message, dict) else "malformed"
            raise MandateError(f"kernel inspection failed: {detail}")
        return _decode_inspect(what, message.get("value"))

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
        try:
            with self._control_lock:
                self._control_conn.send_bytes(json.dumps({"op": "stop"}).encode("utf-8"))
        except (OSError, ValueError):
            pass
        self._proc.join(timeout=2.0)
        if self._proc.is_alive():  # pragma: no cover - defensive
            self._proc.terminate()
            self._proc.join(timeout=2.0)
        for conn in (self._agent_conn, self._control_conn):
            _safe_close(conn)

    def __enter__(self) -> "ProcessKernelService":
        return self

    def __exit__(self, *exc: Any) -> bool:
        self.shutdown()
        return False
