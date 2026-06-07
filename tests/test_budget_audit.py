"""Tests for the budget meter and the append-only, hash-chained audit log."""

from dataclasses import replace

from mandate.compiler.bundle import EffectiveBudget
from mandate.kernel.audit import AuditLog
from mandate.kernel.budget import BudgetMeter


def budget(**kw):
    base = dict(usd_per_day=1.0, tokens_per_day=1000, max_steps_per_run=3, on_exceed="kill")
    base.update(kw)
    return EffectiveBudget(**base)


# -- budget -------------------------------------------------------------------


def test_budget_accumulates_and_does_not_exceed_under_limit():
    m = BudgetMeter(budget())
    r = m.charge(usd=0.5, tokens=100, steps=1)
    assert not r.exceeded
    assert m.usd_spent == 0.5


def test_budget_exceeds_on_steps():
    m = BudgetMeter(budget(max_steps_per_run=2))
    m.charge(steps=1)
    r = m.charge(steps=1)
    assert not r.exceeded
    r = m.charge(steps=1)
    assert r.exceeded
    assert "max_steps_per_run" in r.breached


def test_budget_exceeds_on_usd_and_names_the_limit():
    m = BudgetMeter(budget(usd_per_day=0.05))
    r = m.charge(usd=0.06)
    assert r.exceeded and r.breached == ("usd_per_day",)


# -- audit --------------------------------------------------------------------


def test_audit_is_appendable_and_chain_verifies():
    log = AuditLog()
    log.append(syscall="tool.call", principal="p", action="a", status="ok", cost_usd=0.1)
    log.append(syscall="memory.write", principal="p", action="memory.write", status="ok")
    assert len(log) == 2
    assert log.verify()
    assert log.events[0].prev_hash == "0" * 64
    assert log.events[1].prev_hash == log.events[0].hash


def test_audit_tamper_is_detected():
    log = AuditLog()
    log.append(syscall="tool.call", principal="p", action="a", status="ok", cost_usd=0.1)
    log.append(syscall="tool.call", principal="p", action="b", status="ok", cost_usd=0.2)
    # Forge history: swap a status on the first (frozen) event in place.
    log._events[0] = replace(log._events[0], status="denied")
    assert not log.verify()


def test_audit_exposes_only_append_as_mutator():
    log = AuditLog()
    # No public update/delete method exists on the log surface.
    public = {n for n in dir(log) if not n.startswith("_")}
    assert "append" in public
    assert not (public & {"update", "delete", "remove", "pop", "clear", "insert"})
