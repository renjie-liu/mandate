# Roadmap

Priorities follow the kernel contract. The rule: **don't build the whole OS first.**
Prove the wedge — that every real action is intercepted, explained, approved, denied,
charged, and audited, and that the agent cannot bypass it — then grow subsystems.

## P0 — the frozen vertical slice ✅ implemented

Prove the kernel, nothing more.

- [x] `AgentKernelSubject` (principal / tenant / session / run) — `model/subject.py`
- [x] Compiler: `requests ∩ grants` + subset validation (org-policy input accepted, may be empty) — `compiler/`
- [x] Capability grammar: object form, scoped to `github.repo.*`, `fs.workspace.rw`, one secret-bound tool — `model/capability.py`
- [x] Syscalls: `tool.call`, `memory.write`, `approval.request` (agent-facing); `secret.inject`, `budget.charge`, `audit.append` (kernel-internal); `run.kill` (control-plane) — `kernel/gateway.py`
- [x] Policy returns an **execution mode** (not a boolean); 3 rules — `kernel/policy_engine.py`, full enum in `model/policy.py`
- [x] **No-bypass**: sandbox egress deny-by-default + broker injection — `kernel/egress.py`, `kernel/broker.py`
- [x] Budget counter + kill switch — `kernel/budget.py`
- [x] Append-only audit log + minimal dashboard — `kernel/audit.py` (hash-chained), `dashboard.py`
- [x] Demo agent: GitHub research assistant — `demo.py`, `examples/research-assistant/`

> **What's real vs. simulated.** The compiler, capability algebra, gateway mediation,
> policy/budget/audit, and the no-bypass *enforcement model* are real and tested
> (`pytest`, incl. an explicit no-bypass test that walks the agent's reference graph).
> The agent reaches the kernel only over a data-only syscall channel (a worker thread
> standing in for the process boundary), so it holds no reference to any subsystem. The
> sandbox/egress boundary and the credential broker are in-process simulations that prove
> the model end-to-end; P1+ swaps the thread for a real process/sandbox and the broker for
> Infisical/Vault per the contract's build-vs-buy table, behind the same syscall surface.
> (In one process, `gc.get_objects()` can still enumerate anything — that residue is the
> sandbox's job to remove, not the SDK's.)

**The demo (adversarial step 4 is the point):**
1. read repo → allowed, charged, audited
2. write/issue → policy returns `draft_only`
3. use API key → injected server-side, never in context
4. **under simulated injection, agent tries to `curl` an unapproved domain / exfil the key → blocked by egress** ← proves kernel, not library
5. long-term memory write without provenance → rejected
6. over budget → killed / escalated

## P1 — system feel

Memory volume manager · memory read/write permissions · provenance-required long-term
memory · logical fork · multi-agent IPC policy · approval workflow.

## P2 — differentiation

Identity-as-citizen wallet (spend-limited virtual card, inbox) · physical cross-layer
fork · agent registry · richer org-policy DSL · replay + simulation.

## P3 — enterprise platform

Compliance exports · tenant risk dashboard · policy diff / rollout · incident replay ·
agent SRE console.

See [`docs/kernel-contract-v0.2.md`](./docs/kernel-contract-v0.2.md) for the full contract.
