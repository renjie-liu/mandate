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

## Vision

Agents should be long-running delegated actors, not stateless chat loops. A real agent is
an LLM plus a harness, identity, and memory: it can use tools, receive messages, hold
credentials through a broker, remember across sessions, and act on behalf of a user or
organization.

Mandate makes that actor installable like infrastructure: publish an agent image, bind it
to private identity and grants at deployment time, then run it under one auditable trust
boundary.

## Goal

Build the runtime trust layer underneath agent manifests. Mandate should compile
author-declared requirements, installer grants, organization policy, and runtime quota
into one effective authority bundle, then enforce it at every side-effect boundary.

The first goal is deliberately small: prove that a prompt-injected, non-cooperative agent
cannot bypass the kernel to reach tools, memory, credentials, network egress, IPC, or
budgeted spend.

## What Mandate Provides

Mandate is the operating substrate an agent workload needs before it can safely run for
hours, days, or weeks:

- **Multi-tenant isolation:** tenant-scoped identity, policy, memory, secrets, budget,
  and audit.
- **Multi-session runtime:** durable sessions that can pause, resume, snapshot, fork, and
  be killed under quota.
- **Agent-native memory:** short-term, long-term, and recallable memory with provenance,
  permissions, retention, and deletion semantics.
- **Keychain for agents:** credential handles and broker injection, so agents and tools
  never hold plaintext secrets.
- **Capability permissions:** static authority compiled from manifests, grants, org
  policy, and runtime quota, checked at every syscall.
- **Sandboxed execution:** deny-by-default egress and mediated tool/code execution so
  prompt injection cannot route around the kernel.
- **Auditable behavior:** every tool call, memory operation, credential use, IPC message,
  approval, and budget charge is traceable and replayable.

## Architecture

![Mandate high-level architecture](./docs/mandate-architecture.svg)

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

The agent talks to the kernel over a **data-only syscall channel**, and Mandate ships two
transports behind it:

- **In-process** (`KernelService`) — convenient for tests/demos. The agent holds no
  reference to the gateway, broker, budget, or secret vault, so no reference-graph path
  reaches a subsystem. It is **not** an isolation boundary, though: sharing one interpreter,
  the agent can forge the result it *observes* (or fabricate a `SyscallResult`). That is
  **inert** — every real effect is still kernel-mediated and audited, so INV-1 holds — but
  the observed result isn't guaranteed kernel-sourced.
- **Process-isolated** (`ProcessKernelService`) — the real boundary (contract §2, §13). The
  kernel runs in a **separate process**; the agent holds only a pipe, so there is nothing
  to reach or pre-seed and a result can only be what the kernel sent back. A denied call is
  observed as denied. **Every** pipe (syscall *and* operator control) carries length-bounded
  JSON, never pickle, and every frame is schema- and type-validated — so bytes from
  agent-reachable code can only ever decode to primitive data, never construct an object or
  run code in the kernel, and a malformed frame returns denied rather than crashing it.
  Inspection exposes audit/budget/subject only — never the secret vault, which lives solely
  in the kernel process. Try it with `mandate demo --isolated`; running the agent in its own
  process (so it can't even reach the control pipe) and a full sandbox (E2B / Firecracker /
  gVisor) are the P1 hardening.

In short: the SDK shape keeps the kernel unreachable; **isolation is the process/sandbox
layer's job, not the SDK's** — exactly what the build-vs-buy table says to *use*, not build.

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

## Existing Building Blocks

Most of the substrate exists. The missing piece is not another agent framework; it is the
shared identity, authority, and audit boundary that ties these blocks together. Mandate
should treat existing projects as drivers or substrates, then own the compiler and
no-bypass syscall gateway.

| Layer | Use / wrap | Why | Mandate owns |
|---|---|---|---|
| Manifest authoring | [Docker Agent](https://docs.docker.com/ai/cagent/), [Agent Format](https://agentformat.org/), Agent Spec-style schemas | Agent definitions are already converging on declarative manifests. | The compile step from manifest source into enforceable capability bundles. |
| Tool ecosystem | [MCP](https://modelcontextprotocol.io/docs/learn/server-concepts), Docker MCP catalog/gateway | MCP is the driver model for tools, resources, and prompts. | Tool admission, capability binding, and syscall mediation. MCP servers are packages, not the security boundary. |
| Durable execution | [Temporal](https://temporal.io/), [Restate](https://docs.restate.dev/concepts/durable_execution/), [DBOS](https://docs.dbos.dev/) | Long-running agents need scheduler, journal, retries, pause/resume, and human waits. | The agent syscall journal, replay semantics, budget kill switch, and fork/snapshot contract. |
| Agent loop / graph | [LangGraph](https://langgraphjs.guide/persistence/) or similar graph runtimes | Useful for planning graphs, node checkpointing, and local agent control flow. | The kernel remains outside the loop; graph state is not the source of authority. |
| Sandbox / isolation | [E2B](https://www.e2b.dev/docs), [Firecracker](https://github.com/firecracker-microvm/firecracker), gVisor-style isolation | Code tools and untrusted execution need a real boundary, not SDK cooperation. | Deny-by-default egress, subject-scoped mounts, and the proof that side effects cannot bypass syscalls. |
| Credential broker / keychain | [Infisical Agent Vault](https://docs.agent-vault.dev/), [Vault](https://developer.hashicorp.com/vault/docs), [Auth0 Token Vault](https://auth0.com/features/token-vault) | Agents and tool servers should receive credential handles or brokered injection, not plaintext secrets. | Capability-scoped secret leases, server-side injection, revocation, and audit. |
| Memory backend | [Letta / MemGPT-style memory](https://docs.letta.com/concepts/memory-management), [mem0](https://docs.mem0.ai/) | Existing systems cover long-term memory, recall, and context management patterns. | Per-agent memory namespaces, permissioned reads/writes, provenance, source-trust, retention, deletion, and snapshot/fork semantics. |
| Policy engine | [Cedar](https://docs.cedarpolicy.com/), [OPA/Rego](https://www.openpolicyagent.org/docs/latest), [Microsoft Agent Governance Toolkit](https://microsoft.github.io/agent-governance-toolkit/packages/), [ACS](https://microsoft.github.io/agent-governance-toolkit/packages/agent-control-specification/) | Good engines exist for evaluating policy over structured input and returning normalized verdicts. | Capability grammar, policy-to-execution-mode decisions, and enforcement at the no-bypass runtime boundary. |
| Observability | [OpenTelemetry](https://opentelemetry.io/docs/) plus durable workflow history | Traces, logs, and metrics are commodity plumbing. | Capability-decision audit, explainability, replay, and incident reconstruction under one `AgentKernelSubject`. |
| Identity-as-citizen resources | [Twilio](https://www.twilio.com/docs/sms), [SendGrid](https://sendgrid.com/en-us/solutions/email-api), [Stripe Issuing](https://stripe.com/issuing), [Lithic](https://docs.lithic.com/docs) | Email, phone, and spend can be built from existing APIs. | Agent-scoped inboxes, contact channels, virtual cards, spend limits, approvals, and revocation. Build later, not P0. |

The near-term wedge is therefore small and sharp: build the **manifest compiler**,
**capability runtime + syscall gateway**, and **capability-decision audit/replay**; reuse
the rest behind that boundary. Full mapping in the [contract](./docs/mandate-kernel-contract-v0.2.md#13-build-vs-buy-corrected).

## Market Difference

Mandate is not trying to replace every adjacent agent project. It is the common authority
boundary those projects need when an agent becomes long-running, delegated, and
side-effecting.

| Category | What exists | Mandate difference |
|---|---|---|
| Agent frameworks | LangGraph, CrewAI, AutoGen, OpenAI Agents SDK, and similar runtimes build loops, graphs, tools, and planning flows. | Mandate sits under the loop. Framework state is useful execution state, but it is not the source of authority. |
| Agent manifests | Docker Agent, Agent Format, and Agent Spec-style schemas make agents portable and declarative. | Mandate compiles manifest source, deployment grants, org policy, and runtime quota into an effective capability bundle. |
| MCP and tool gateways | MCP standardizes tool servers, resources, prompts, and client/server transport. Tool platforms such as Composio or Arcade help connect SaaS APIs. | Mandate treats tools as drivers. Admission, permission, secret injection, budget, egress, and audit still happen at the syscall boundary. |
| Governance middleware | Microsoft AGT Agent OS and ACS validate the market: policy verdicts, adapters, lifecycle controls, telemetry, approvals, and compliance mapping all matter. | Mandate can use AGT/ACS-style verdicts, but does not stop at app-level middleware. The kernel owns the host boundary that actually enforces verdicts. |
| Sandboxes and durable engines | E2B, Firecracker, gVisor-style isolation, Temporal, Restate, and DBOS can run code and keep workflows alive. | Mandate binds those substrates to one `AgentKernelSubject`, one capability bundle, one budget kill switch, and one replayable syscall journal. |
| Memory and secret systems | Letta/mem0-style memory systems recall context; Vault-style systems store credentials. | Mandate makes memory and secrets agent-native resources: scoped, permissioned, revocable, provenance-aware, and audited per tenant/session. |

The sharp positioning is: **Mandate is the no-bypass capability kernel underneath agent
manifests, frameworks, MCP servers, policy engines, sandboxes, memory systems, and
vaults.** Existing systems can be reused as engines or adapters; Mandate owns the
authority boundary, capability compiler, and audit subject.

The closest adjacent market signal is Microsoft AGT: it shows demand for agent
governance, policy verdicts, framework adapters, runtime controls, and compliance
evidence. Mandate's bet is lower in the stack. Policy verdicts are necessary, but the
hard part is making every side effect pass through the same enforced subject boundary.
That is the part Mandate should own.

## Quickstart

```bash
pip install -e ".[dev]"   # runtime dep is just PyYAML; [dev] adds pytest

mandate demo              # run the six adversarial scenarios + audit dashboard
mandate demo --isolated   # also run the kernel in a separate process (the real boundary)
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
