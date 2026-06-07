# Mandate — Capability Microkernel Contract v0.2

> **Mandate is a capability microkernel for AI agents.** It compiles author-declared
> agent images, private deployment grants, and organization policy into an effective
> runtime capability bundle. Every tool call, memory operation, credential use, IPC
> message, and budget charge crosses the same syscall boundary and is enforced under
> one agent identity.

The value is not the YAML. The value is that the YAML compiles into a capability
bundle the kernel enforces at the syscall boundary — and that **there is no other way
for the agent to act**.

Field provenance is tagged throughout:
`[A]` author-declared (image) · `[I]` install-injected (deployment) · `[O]` org-policy ·
`[R]` runtime binding · `[K]` compiles to a kernel-enforced capability/limit.
`[P0]` marks what the first vertical slice implements; everything else is contract-now /
build-later.

---

## 1. Thesis: source → binary

```
agent.yaml (image)  +  agent-compose.yaml (deployment)  +  org-policy.yaml
        │                         │                              │
        └─────────────────────────┴──────────────┬───────────────┘
                                                  ▼
                                    Mandate Compiler
                                                  ▼
                              effective capability bundle  (the "binary")
                                                  ▼
                              microkernel enforces at every syscall
```

The manifest is *source code*. The capability bundle is its *compiled binary*. The
kernel is the CPU that will not execute anything outside the bundle.

---

## 2. The no-bypass invariant (the chapter that makes this a kernel)

A precise syscall ABI is worthless if the agent has a side-effect path that skips it.
A policy engine on its own is not a security boundary — it is advice the agent can route
around. The kernel claim rests on one runtime invariant:

> **INV-1 (No bypass).** There exists no path from agent-controlled execution to an
> external side effect that does not cross an agent-facing syscall.

Side effect = outbound network, filesystem writes outside scratch, credential use,
subprocess spawn, message to another agent.

**How INV-1 is enforced (not by the SDK — by the boundary):**
- **`[P0]` Sandbox egress is deny-by-default.** The only route out of the sandbox is the
  kernel gateway. The agent's code-execution tool runs *inside* this sandbox and is
  subject to the same egress rules — it cannot `curl` an unapproved host.
- **`[P0]` No tool or MCP server holds a usable credential.** Secrets are broker-injected
  at the gateway during `tool.call`; the agent and the tool code never see plaintext.
- **`[K]` Filesystem reach is a syscall.** Anything beyond ephemeral scratch is a
  `memory.*` or artifact volume operation, hence mediated.

**Corollary.** A prompt-injected LLM can *request* anything, but can only *act* through
mediated syscalls. The compromise is contained to requests, never to unmediated effects.
This is the difference between Mandate and a cooperative SDK wrapper, and it is the
single thing the P0 demo must prove adversarially (see §14).

---

## 3. `AgentKernelSubject` — the join key

The runtime object that policy, audit, memory, secrets, and budget all reference. Every
syscall carries it. Without it, "one identity across subsystems" stays a slogan.

```yaml
subject:                              # [P0] (minimal fields starred)
  principal: agent://acme/scout       # * stable identity; threads through everything
  tenant: acme-corp                   # * isolation domain
  session: sess_123                   # * 
  run: run_456                        # *
  image_digest: sha256:...            #   provenance of the running image
  deployment_id: dep_...
  owner: user:alice@acme
  publisher: did:key:z6Mk...          #   who signed the image
```

`principal` is simultaneously the memory namespace, the credential scope, the policy
subject, and the audit subject. One value, four jobs.

---

## 4. Compilation: lattice meet

```
effective = image.constraints  ⊓  deployment.grants  ⊓  org.policy  ⊓  runtime.quota
```

`⊓` is the lattice meet, applied per field type:
- **capabilities** → set intersection
- **scalar limits** (tokens, $, steps, memory) → `min`
- **modes** (isolation, sensitivity ceilings) → most-restrictive

The compiler **rejects** at build time, not runtime: a grant that is not a subset of a
request; a deployment/runtime binding that *loosens* an image constraint; a granted
capability missing an `expires` when org policy requires one. `[P0]` implements the
`requests ∩ grants` half; it accepts an (optional, possibly empty) org-policy input from
day one so the third file can be added later without recompiling the model.

---

## 5. Capability grammar (static authority only)

Capabilities are objects, with a string shorthand. They express **what resource + action
+ static scope + expiry** — nothing conditional.

```yaml
- capability: github.repo.read        # provider.resource.action   [K]
  resources:
    repos: [acme/research]
  scope:                              # static scope, NOT runtime conditions
    branches: [main, dev]
    include_private: false
  data:
    max_sensitivity: internal         # ceiling this cap may touch
  expires: 30d
```

**Subset rule (enforced by compiler):** a grant ⊆ a request iff the action is equal,
`resources` ⊆, `scope` ⊆, and `data.max_sensitivity` ≤. Granting *more* than requested is
rejected.

**Capability vs policy — the hard line.** Capability = static grant of authority. Policy
(§6) = dynamic decision over a specific syscall in context. `when cost_usd > 0` /
`recipient external` / `current risk score` belong to policy, never inside a capability
object. Keep them apart or the two grammars merge into mud.

---

## 6. Policy returns an execution mode, not a boolean

The kernel's `policy.decide` return type is the spine of the system. Changing it from
`allow|deny` to an enum ripples through gateway, consent screen, and audit — so it is
frozen early.

```yaml
policies:                             # [O] mostly; [A] may add stricter, never looser
  - match: { action: github.repo.write, resource.branch: main }
    decision: require_code_owner_approval
  - match: { action: email.send, recipient.domain_not_in: [acme.com] }
    decision: allow_draft_only
  - match: { data.labels: [pii], destination.external: true }
    decision: deny
```

`decision ∈ { allow, deny, allow_readonly, allow_draft_only, allow_with_redaction,
allow_in_sandbox, require_human_approval, require_2fa, require_manager_approval,
require_simulation_first, require_budget_increase }`

`[P0]` ships three rules (repo.write→draft_only, external-egress→deny, over-budget→kill)
and the full enum as the return type, even if most arms are unused at first.

---

## 7. Syscall ABI (partitioned by caller)

Every agent-facing syscall is an attack surface, so the set is kept small and the other
two layers are unreachable by the agent.

**Agent-facing** (the only calls the harness can make; each crosses the kernel):
```
tool.call(capability, name, args, data_labels)
memory.read(scope, query)
memory.write(scope, object, provenance)
agent.spawn(image, grants)            # grants ⊆ caller's effective caps
ipc.send(to, channel, message, data_labels)
approval.request(action, context)
```

**Kernel-internal** (effects the kernel triggers; never agent-callable):
```
secret.inject   # during tool.call; broker-only, no plaintext return
budget.charge   # accounting side effect of tool.call / llm / memory.write
audit.append    # append-only, every syscall + decision
policy.decide   # consulted before any agent-facing syscall completes
```

**Control-plane** (operator / budget-enforcer / scheduler):
```
run.pause   run.resume   run.kill   snapshot.take   fork.create
```

Each agent-facing syscall carries the `subject`, a `capability` ref, `resource`, `args`,
`data_labels`; the kernel attaches `policy_decision`, `budget_cost`, and `audit_event`
before completing. `[P0]`: `tool.call`, `memory.write`, `approval.request` (agent-facing);
`secret.inject`, `budget.charge`, `audit.append` (internal); `run.kill` (control-plane).

---

## 8. File 1 — `AgentImage` (`agent.yaml`)

Author-declared. Publishable, signable, content-addressed. No secrets, no real identity,
no budgets — only requirements, requests, constraints, and character.

```yaml
apiVersion: mandate/v1
kind: AgentImage
metadata:
  name: research-assistant
  version: 1.4.2
  publisher: did:key:z6Mk...          # [A]

llm:                                   # [A] capability requirement, NOT a hard model pin
  capability_class:
    reasoning: high
    tool_calling: required
    structured_output: required
    min_context_tokens: 128000
    vision: optional
  tested_on: [anthropic/claude-opus-4-x, openai/gpt-x]

loop:
  strategy: react                      # [A]
  constraints:                         # [K] image-declared ceilings; cannot be loosened
    max_steps: 80
    subagent_max_depth: 2
    inherit: attenuate                 # child caps ⊆ parent caps

harness:
  requires: { isolation: microvm, min_cpu: 1, min_memory: 2Gi }   # [A]
  recommends: { cpu: 2, memory: 4Gi }
  execution:                           # replaces `timeout: unlimited`
    mode: durable
    persistence: pause_resume
    active_runtime_limit: bounded
  egress:                              # [K] requested allow-list; deny-by-default
    allow: [api.semanticscholar.org, arxiv.org]
  tools:
    - ref: mcp:github
      requests:
        - capability: github.repo.read
          resources: { repos: [acme/research] }
          scope: { include_private: false }
    - ref: mcp:filesystem
      requests: [ { capability: fs.workspace.rw } ]

identity:
  persona: { system_prompt: ./prompts/researcher.md }   # [A] persona != principal
  invocation: { default_acl: { invokable_by: [owner, owner-delegates] } }
  asks:                                # citizen resources REQUESTED (bound at deploy)
    secrets:
      - { name: SEMANTIC_SCHOLAR_KEY, purpose: semantic_scholar_api, required: true }
    inbox:   { required: false, purpose: async_results }
    payment: { required: false }

memory:
  volumes:                             # mounts, like a filesystem — authorized, not assumed
    - name: project
      mount: /memory/project
      requested_access: { read: true, write: true }
      scopes: [project.research, project.literature]
      data_policy: { max_sensitivity: internal }
    - name: user
      mount: /memory/user
      requested_access: { read: true, write: false }
      scopes: [user.preferences]
  writes:
    require_provenance: true           # [K]
    require_fields: [source, source_trust, confidence, observed_at, owner, expiry]
    long_term:
      low_trust_source: review         # injected/untrusted-origin writes can't go LT directly
  retention:
    default_ttl: 30d
    pii: { long_term_write: approval, hard_delete_on_owner_request: true }
  consistency: { mode: mvcc, conflict: escalate }
  snapshots: { logical: true }
```

Note `source_trust` in memory writes: a long-term write whose origin is untrusted
(e.g. scraped web content) is a memory-poisoning vector and is held for consolidation
review rather than committed directly.

---

## 9. File 2 — `AgentDeployment` (`agent-compose.yaml`)

Private. Binds an image to *your* identity, secrets, budget, volumes, and concrete model.
**Installing is granting** — this is the consent ceremony.

```yaml
apiVersion: mandate/v1
kind: AgentDeployment
agents:
  scout:
    image: research-assistant:1.4.2@sha256:...   # [I] pinned by digest
    tenant: acme-corp

    grants:                                       # [K] each ⊆ a request; rejected otherwise
      - capability: github.repo.read
        resources: { repos: [acme/research] }
        expires: 30d

    llm_binding:                                  # [R] image declared class; deploy picks model
      primary: anthropic/claude-opus-4-x
      fallback: { strategy: same_or_higher_capability, allow_local: false }

    resources: { cpu: 2, memory: 4Gi }            # [R] within image.requires/recommends

    identity:                                     # [I]
      principal: agent://acme/scout
      invoked_by: [user:alice@acme, service:ci-bot]
      bindings:
        secrets: { SEMANTIC_SCHOLAR_KEY: vault://acme/ss-key }   # broker ref, never a value
        inbox: { email: scout@agents.acme.com }

    budget:                                       # [K] the seatbelt
      tokens_per_day: 5000000
      usd_per_day: 50
      max_steps_per_run: 40
      on_exceed: kill                             # kill | pause | escalate

    timeouts:                                     # [R] explicit; no "unlimited"
      max_active_wall_time: 2h
      max_session_duration: 7d
      idle_timeout: 30m
      approval_timeout: 24h

    memory: { volume: vol://acme/scout-mem, snapshot: { schedule: daily, retain: 7 } }
```

---

## 10. File 3 — `OrgPolicy` (`org-policy.yaml`)

Global guardrails the tenant applies to *every* agent. The enterprise buy-in. `[P0]`
ships an empty/trivial one, but the compiler treats it as a first-class meet input.

```yaml
apiVersion: mandate/v1
kind: OrgPolicy
defaults:
  deny_external_egress: true
  require_secret_broker: true
  max_agent_usd_per_day: 50
rules:
  - match: { action: payment.* }
    decision: require_manager_approval
  - match: { data.labels: [pii], destination.external: true }
    decision: deny
  - match: { action: github.repo.write, resource.branch: main }
    decision: require_code_owner_approval
```

---

## 11. Multi-agent IPC (capability-ized)

Links are not just wires; agent-to-agent messaging is mediated or a swarm becomes a
permission-bypass.

```yaml
topology:
  links:
    - from: scout
      to: writer
      channel: messages
      policy:
        data_labels_allowed: [public, internal]
        allow_tool_result_forwarding: false
        allow_secret_reference_forwarding: false   # secret refs cannot be serialized over IPC
        require_provenance: true
```

Formalized rules: `child_effective_caps = parent_effective_caps ∩ child_requested_caps ∩
spawn_grants`; message caps do **not** imply tool caps; a memory write arriving via IPC
still passes through `memory.write`; secret references are non-serializable across IPC.

---

## 12. Fork: logical first, physical later

```yaml
fork:                                  # P1
  mode: logical
  includes: [memory_snapshot, workflow_checkpoint, artifact_store]
  excludes: [active_network_connections, secret_leases, pending_external_side_effects]
```

`logical` fork is nearly free on a durable engine (the journal already records, not
re-executes, completed side effects). `physical` fork (atomic memory + workflow journal +
sandbox VM + browser profile) is P2 — the hard part is side-effecting tool idempotency,
which constrains *any* replay, not just VM snapshots.

---

## 13. Build vs Buy (corrected)

USE = adopt · WRAP = adopt engine, own integration · BUILD = the wedge.

| Subsystem | OSS | Verdict | Note |
|---|---|---|---|
| LLM routing | LiteLLM / provider gateway | USE | Commodity; not the moat. |
| Manifest authoring shape | Docker cagent, AgentSpec, Agent Format | WRAP | Extend; don't invent a new YAML standard. |
| Sandbox / isolation | E2B (Firecracker), Modal (gVisor), Kata, Northflank | USE | **Benchmark restore latency per workload — never hardcode.** Session caps (E2B Pro 24h / Base 1h) are real; long-running leans on pause/resume. |
| Durable execution | Temporal, Restate, DBOS | USE | Kernel scheduler + journal; gives logical fork. |
| Policy engine | MS Agent Governance Toolkit (Cedar/Rego), seL4-style caps | WRAP | AGT claims **deterministic enforcement <1ms** and is **application-level, not kernel isolation** — its own docs say combine with container isolation. That caveat *is* the case for §2. |
| Tool ecosystem | MCP + Docker MCP Catalog/Gateway | USE/WRAP | **MCP servers are packages/drivers, not the security boundary. MCP OAuth authorizes access to a tool server; it does not unify your memory/budget/secret/audit/tenant isolation. All MCP calls must cross syscall mediation.** |
| Credential broker | Infisical Agent Vault, Vault, Auth0 Token Vault | USE/WRAP | Broker-injection; agent never sees plaintext. Wire to capability model. |
| Memory backend | mem0, Letta, Zep/Graphiti | WRAP | Backend swappable; **the permission/provenance/scope/snapshot layer is the value.** |
| Manifest compiler | — | BUILD | Core wedge. |
| Capability runtime + syscall gateway | — | BUILD | Core wedge. |
| Audit / replay | on Temporal | BUILD | Must explain every capability decision, not just trace. |
| Identity-as-citizen wallet | Stripe Issuing / Lithic | BUILD later | Differentiator; compliance swamp if rushed. |
| Cross-layer physical fork | — | BUILD later | Heavy; logical fork first. |

---

## 14. P0 — the frozen vertical slice

Prove one thing: **every real action an agent takes can be intercepted, explained,
approved, denied, charged, and audited — and the agent cannot bypass it.**

Scope (and nothing more):
- `AgentKernelSubject` (principal/tenant/session/run)
- Compiler: `requests ∩ grants` (org-policy input accepted but may be empty)
- Capability grammar: object form, only `github.repo.*`, `fs.workspace.rw`, one secret-bound tool
- Syscalls: `tool.call`, `memory.write`, `approval.request` + internal `secret.inject`,
  `budget.charge`, `audit.append` + control-plane `run.kill`
- Policy → execution mode, 3 rules
- **No-bypass**: sandbox egress deny-by-default + broker injection
- Budget counter + kill switch
- Append-only audit log + minimal dashboard (every syscall + decision)
- One demo agent: GitHub research assistant

**The demo (the adversarial version is the point):**
1. Agent reads `acme/research` → **allowed**, charged, audited.
2. Agent opens a write/issue → policy returns **draft_only**; nothing ships without approval.
3. Agent uses `SEMANTIC_SCHOLAR_KEY` → secret **injected server-side**, never enters context.
4. **Under simulated injection**, agent's code tool tries to `curl` an unapproved domain
   and to exfiltrate the key → **blocked by egress**. *(This is the proof it's a kernel, not a library.)*
5. Agent writes long-term memory → **rejected without provenance**; low-trust source held for review.
6. Agent exceeds budget → **killed / escalated**.

If step 4 holds against a non-cooperative agent, the thesis is demonstrated and the rest
is subsystem growth.
