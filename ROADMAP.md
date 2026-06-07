# Roadmap

Priorities follow the kernel contract. The rule: **don't build the whole OS first.**
Prove the wedge — that every real action is intercepted, explained, approved, denied,
charged, and audited, and that the agent cannot bypass it — then grow subsystems.

## P0 — the frozen vertical slice

Prove the kernel, nothing more.

- [ ] `AgentKernelSubject` (principal / tenant / session / run)
- [ ] Compiler: `requests ∩ grants` + subset validation (org-policy input accepted, may be empty)
- [ ] Capability grammar: object form, scoped to `github.repo.*`, `fs.workspace.rw`, one secret-bound tool
- [ ] Syscalls: `tool.call`, `memory.write`, `approval.request` (agent-facing); `secret.inject`, `budget.charge`, `audit.append` (kernel-internal); `run.kill` (control-plane)
- [ ] Policy returns an **execution mode** (not a boolean); 3 rules
- [ ] **No-bypass**: sandbox egress deny-by-default + broker injection
- [ ] Budget counter + kill switch
- [ ] Append-only audit log + minimal dashboard
- [ ] Demo agent: GitHub research assistant

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
