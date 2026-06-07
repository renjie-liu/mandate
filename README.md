# Mandate

**A capability microkernel for AI agents.**

A *mandate* is delegated authority to act on someone's behalf — bounded, revocable,
auditable. That is exactly what an autonomous agent needs and what this project compiles
and enforces. Mandate turns author-declared agent images, private deployment grants, and
organization policy into an effective runtime **capability bundle**. Every tool call,
memory operation, credential use, IPC message, and budget charge crosses the same
**syscall boundary** and is enforced under one agent identity.

> **Status: P0 implemented.** The kernel contract (`v0.2`) is defined and the P0 vertical
> slice is built and tested — the compiler, the syscall gateway, policy execution-modes,
> the budget kill-switch, the append-only audit log, broker-injected secrets, and
> deny-by-default egress. Run the adversarial demo with `mandate demo` (see
> [Quickstart](#quickstart)). See [`ROADMAP.md`](./ROADMAP.md) for what's next. Expect the
> contract to keep changing.

---

## Why

Most projects in this space define *what an agent is* — a framework: prompt + tools + a
loop. Mandate is the layer underneath: the **control plane for an agent _workload_** —
its install, identity, capabilities, secrets, memory, budget, audit, and isolation.

The wedge is **not** the YAML. Docker `cagent`, AgentSpec, and Agent Format already make
agents declarative. The wedge is that the manifest **compiles into capabilities the
kernel enforces at the syscall boundary** — and that the agent has no way to act outside
them.

```
A better manifest for agents          ← what others are building
The compiler + kernel that turn        ← what this is
manifests into enforceable capabilities
```

## The one invariant that makes it a kernel

> **No bypass.** There is no path from agent-controlled execution to an external side
> effect that does not cross a mediated syscall.

A policy engine on its own is advice an agent can route around. Mandate enforces at the
boundary: sandbox egress is deny-by-default, secrets are broker-injected (the agent never
sees plaintext), and every side-effecting path is a syscall. A prompt-injected agent can
*request* anything; it can only *act* through the kernel. This is the difference between
Mandate and a cooperative SDK wrapper, and it is what the P0 demo proves adversarially.

The agent talks to the kernel over a **data-only syscall channel** with split
agent/kernel endpoints: the agent end holds no reference to the gateway, broker, budget,
or secret vault (so no reference-graph path reaches a subsystem), and it has no response
store to pre-seed — a call's result comes only from the kernel. The hard isolation
boundary is the sandbox/process line (in production the agent runs *inside* the sandbox);
P0 runs in one process and simulates that line, so it does not claim to defeat
whole-interpreter introspection (`gc.get_objects()`) or the fact that the agent can
fabricate inert data objects — that residue is precisely the sandbox's job, not the SDK's.

## How it compiles

```
agent.yaml (image)  +  agent-compose.yaml (deployment)  +  org-policy.yaml
        │                          │                            │
        └──────────────────────────┴─────────────┬──────────────┘
                                                  ▼
                                        Mandate Compiler
                                                  ▼
                              effective capability bundle  (the "binary")
                                                  ▼
                              microkernel enforces at every syscall

effective = image.constraints ⊓ deployment.grants ⊓ org.policy ⊓ runtime.quota
            (capabilities by intersection · scalar limits by min · modes by most-restrictive)
```

## The three files

| File | Kind | Who writes it | Holds |
|------|------|---------------|-------|
| [`agent.yaml`](./examples/research-assistant/agent.yaml) | `AgentImage` | author | requirements, requests, constraints, persona. **No secrets, no identity, no budgets.** Publishable & signable. |
| [`agent-compose.yaml`](./examples/research-assistant/agent-compose.yaml) | `AgentDeployment` | installer | grants, identity bindings, budget, memory volume, concrete model. **Private. Installing = granting.** |
| [`org-policy.yaml`](./examples/research-assistant/org-policy.yaml) | `OrgPolicy` | org admin | tenant-wide guardrails (deny/approval/limits). |

## What we build vs reuse

Reuse, don't reinvent: **durable execution** (Temporal / Restate) as scheduler + journal,
**sandbox** (E2B / Firecracker, gVisor) for isolation, **credential broker**
(Infisical Agent Vault) so the agent never sees secrets, **memory backend** (mem0 / Letta)
behind our permission layer.

Build (the wedge): the **manifest compiler**, the **capability runtime + syscall gateway**,
**capability-decision audit/replay**, and — later — the **identity-as-citizen wallet** and
**cross-layer fork**. Full mapping in the [contract](./docs/mandate-kernel-contract-v0.2.md#13-build-vs-buy-corrected).

## Quickstart

```bash
pip install -e ".[dev]"   # runtime dep is just PyYAML; [dev] adds pytest

mandate demo              # run the six adversarial scenarios + audit dashboard
mandate compile examples/research-assistant/agent.yaml \
                examples/research-assistant/agent-compose.yaml \
                --org-policy examples/research-assistant/org-policy.yaml

pytest                    # compiler · kernel · no-bypass · end-to-end demo
```

`mandate demo` walks the contract's §14 demo. Each step is a syscall crossing the kernel:

1. read `acme/research` → **allowed**, charged, audited
2. write to a branch → **draft-only**; write to `main` → **code-owner approval**; nothing ships
3. semantic-scholar search → API key **broker-injected server-side**, never in the result
4. under simulated injection, the code tool tries to `curl` an unapproved host → **blocked by egress**
5. memory write with no provenance → **rejected**; low-trust long-term → **held for review**
6. over budget → **killed**; every later syscall is refused

The whole run prints as an append-only, hash-chained audit table.

## Repo structure

```
.
├── README.md · ROADMAP.md · pyproject.toml
├── docs/
│   └── mandate-kernel-contract-v0.2.md   # the spec / contract
├── examples/
│   └── research-assistant/               # the P0 demo agent
│       ├── agent.yaml                    # AgentImage     (author)
│       ├── agent-compose.yaml            # AgentDeployment (installer)
│       ├── org-policy.yaml               # OrgPolicy       (org admin)
│       ├── prompts/researcher.md         # persona (!= principal)
│       └── demo.py                       # thin runner for the six scenarios
├── src/mandate/
│   ├── model/                            # capability algebra + manifest model
│   ├── compiler/                         # manifests → effective capability bundle
│   ├── kernel/                           # syscall gateway + enforcement subsystems
│   ├── sdk/                              # agent-facing syscall client (the only way to act)
│   ├── demo.py · dashboard.py · cli.py   # reference demo, audit view, `mandate` CLI
│   └── errors.py
└── tests/                                # pytest suite incl. an explicit no-bypass test
```

## License

Apache-2.0 (add via GitHub's license template, or `gh repo create --license apache-2.0`).
