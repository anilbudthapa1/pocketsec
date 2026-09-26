"""G5.13: the assurance table, checked by running the behaviour each row names.

**Why this module exists (finding F2).** G5.13 used to run one in-process "mutation" per
PROVEN_BY_CONSTRUCTION row, and each probe read exactly the surface its own patch changed:
P5 patched an O7 entry into ``CATALOG`` and then asked whether ``CATALOG`` held an O7; P6
added a fourth ``__init__`` keyword and then counted the keywords; P7 replaced
``Lease.expired`` and then called ``Lease.expired``. None of those probes could report a
surviving mutation, and a verifier deleted the executor's entry guard and gave SENTINEL a
module flag that switched it off without G5.13 noticing. The gate and the findings
presented the run as mutation evidence.

**What it does now.** Each probe exercises the *behaviour* the row claims through the
real code path — a real executor refusing impostors, the 182-case SENTINEL matrix, an
evidence-destroying action at a real executor, a lease that is never shown to a
registry — so a breakage anywhere on that path, not only the one patched here, turns the
probe false. G5.13 passes only if every probe holds on today's code and fails under a
behaviour-level break (``held and not held_mutated``). This is a behavioural
self-consistency check. The source-level mutation evidence is the out-of-package test
``tests/test_stage5_gate.py::test_every_mutation_edit_breaks_its_named_test``, which
applies :data:`assurance.MUTATION_EDITS` and :data:`assurance.SENSITIVITY_EDITS` to a
scratch copy and runs each row's named test; P2 forbids a process launcher here, so the
gate cannot run it.

P1 is TESTED (F5-honesty), but its probe runs here too: a gate that cannot see the entry
guard deleted is the defect this module replaced.
"""

from __future__ import annotations

import copy
import inspect
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import fields, replace
from types import MappingProxyType, SimpleNamespace
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.gate import REPO_ROOT, GateCheck
from pocketsec.stage5.assurance import properties as assurance
from pocketsec.stage5.labs import adversarial_load as fixtures

__all__ = ["FINDINGS_PATH", "PROBED_ROWS", "check_assurance_table", "mutation_results"]

FINDINGS_PATH = REPO_ROOT / "docs" / "stage-5-findings.md"

#: Rows G5.13 probes: every PROVEN_BY_CONSTRUCTION row plus P1, whose downgrade must not
#: take the entry guard out of the gate's sight.
PROBED_ROWS: tuple[str, ...] = ("P1", "P4", "P5", "P6", "P7", "P8", "P9")


@contextmanager
def _patched(owner: Any, name: str, value: Any) -> Iterator[None]:
    original = getattr(owner, name)
    setattr(owner, name, value)
    try:
        yield
    finally:
        setattr(owner, name, original)


def _holds(probe: Callable[[], bool]) -> bool:
    """A probe that raises has not shown the property holds."""
    try:
        return bool(probe())
    except Exception:
        return False


def _executor_module() -> Any:
    from pocketsec.stage5.gate import TransactionalExecutor

    return inspect.getmodule(TransactionalExecutor)


# --- P1 (TESTED): the entry guard -------------------------------------------------------


def _entry_refuses_impostors() -> bool:
    """Five impostors at a real executor: each refused BY ``_refuse_untyped``, 0 applies."""
    from pocketsec.stage5.gate_runtime import lab_operator, lab_rig
    from pocketsec.stage5.host.simulated import FaultProfile

    rig = lab_rig(FaultProfile(seed=61))
    operator = lab_operator("SUSPEND_PROCESS")
    token = fixtures.mint_token(rig.tokens, operator, action_id="act.g513.p1")
    resolution = fixtures.build_resolution(incident_id=operator.incident_id)
    impostors = (
        operator.spec.operator_id, {"operator_id": operator.spec.operator_id},
        SimpleNamespace(spec=operator.spec, target=operator.target,
                        incident_id=operator.incident_id, ttl_seconds=operator.ttl_seconds,
                        evidence_refs=(), argv=lambda: ("sh", "-c", "id")),
        copy.deepcopy(operator),
    )
    before = rig.host.apply_calls
    for forged in impostors:
        try:
            rig.executor.execute(forged, token, resolution=resolution)
        except (ContractError, TypeError) as refusal:
            trace = refusal.__traceback__
            frames = inspect.getinnerframes(trace) if trace is not None else []
            if not frames or frames[-1].function != "_refuse_untyped":
                return False
            continue
        return False
    return bool(rig.host.apply_calls == before)


def _p1() -> tuple[bool, bool]:
    held = _holds(_entry_refuses_impostors)
    with _patched(_executor_module(), "_refuse_untyped", lambda operator, token: None):
        return held, _holds(_entry_refuses_impostors)


# --- P4 and P6: through a real SENTINEL ---------------------------------------------------


def _matrix_failures() -> list[str]:
    from pocketsec.stage5.gate_construction import sentinel_matrix_denials

    _passes, denials, cases, failures = sentinel_matrix_denials()
    return failures if denials == cases else [*failures, "denials short"]


def _authority_holds() -> bool:
    """Every catalog operator resolves one authority equal to its spec's, no MODEL grant
    source exists, and a real kernel denies a token of any other class (AUTHORITY)."""
    from pocketsec.stage5.authority import capability
    from pocketsec.stage5.operators.catalog import CATALOG

    total = all(capability.required_authority(spec) is spec.authority for spec in CATALOG.values())
    no_model = not {"MODEL", "LLM"} & set(capability.GrantSource.__members__)
    return total and no_model and not [f for f in _matrix_failures() if "AUTHORITY" in f]


def _p4() -> tuple[bool, bool]:
    from pocketsec.stage5.authority import capability
    from pocketsec.stage5.operators.algebra import OperatorClass

    held = _holds(_authority_holds)
    table = capability.AUTHORITY_BY_OPERATOR_CLASS
    narrowed = MappingProxyType({key: value for key, value in table.items()
                                 if key is not OperatorClass.O3_SUSPEND})
    with _patched(capability, "AUTHORITY_BY_OPERATOR_CLASS", narrowed):
        return held, _holds(_authority_holds)


def _p6() -> tuple[bool, bool]:
    """The 182-case matrix under a switch that returns PASS before any check (F2/F4)."""
    from pocketsec.stage5.sentinel import kernel

    held = _holds(lambda: not _matrix_failures())

    def switched_off(self: Any, request: Any, operator_id: str, target_digest: str) -> Any:
        return kernel.SentinelVerdict(kernel.Decision.PASS, (), "off", operator_id,
                                      target_digest, kernel.CHECK_ORDER)

    with _patched(kernel.SentinelKernel, "_run", switched_off):
        return held, _holds(lambda: not _matrix_failures())


# --- P5: no O7 operator can be built ------------------------------------------------------


def _no_o7_operator_constructible() -> bool:
    """Try every O7 route — a catalog entry and a forged spec — and build none."""
    from pocketsec.stage5.constitution.invariants import AuthorityClass
    from pocketsec.stage5.gate_runtime import lab_operator
    from pocketsec.stage5.operators import catalog
    from pocketsec.stage5.operators.algebra import DefensiveOperator, OperatorClass

    target = lab_operator("TERMINATE_PROCESS").target
    forged = replace(catalog.CATALOG["TERMINATE_PROCESS"], operator_id="WIPE_HOST",
                     operator_class=OperatorClass.O7_DESTRUCTIVE, authority=AuthorityClass.AX)
    routes = [spec for spec in catalog.CATALOG.values()
              if spec.operator_class is OperatorClass.O7_DESTRUCTIVE] + [forged]
    for spec in routes:
        try:
            DefensiveOperator(spec=spec, target=target, incident_id="inc.g513.p5",
                              ttl_seconds=60, evidence_refs=())
        except (ContractError, TypeError):
            continue
        return False
    return True


def _p5() -> tuple[bool, bool]:
    from pocketsec.stage5.constitution.invariants import AuthorityClass
    from pocketsec.stage5.operators import catalog
    from pocketsec.stage5.operators.algebra import OperatorClass

    held = _holds(_no_o7_operator_constructible)
    wipe = replace(catalog.CATALOG["TERMINATE_PROCESS"], operator_id="WIPE_HOST",
                   operator_class=OperatorClass.O7_DESTRUCTIVE, authority=AuthorityClass.AX)
    with _patched(catalog, "CATALOG", MappingProxyType({**catalog.CATALOG, "WIPE_HOST": wipe})):
        return held, _holds(_no_o7_operator_constructible)


# --- P7: expiry by data, under a clock nothing else moves ----------------------------------


def _expiry_is_data() -> bool:
    """A lease no registry has seen expires exactly when its fields say, and a registry
    under a :class:`ManualClock` lists a lease as expired with no call but the clock's."""
    from pocketsec.stage5.executor.identity import ManualClock
    from pocketsec.stage5.executor.lease import Lease, LeaseRegistry
    from pocketsec.stage5.gate_runtime import lab_operator

    lease = Lease(lease_id="lease.p7", action_id="act.p7", incident_id="inc.p7",
                  operator_id="SUSPEND_PROCESS", target_digest="sha256:" + "a" * 64,
                  granted_at=100, ttl_seconds=60, maximum_lifetime_seconds=90, renewals=0,
                  rollback_operator_id="RESUME_PROCESS")
    by_fields = all(lease.expired(t) == (t >= 160) for t in range(90, 200, 7))
    clock = ManualClock(at=1_000)
    registry = LeaseRegistry(clock=clock)
    granted = registry.grant(operator=lab_operator("SUSPEND_PROCESS"), action_id="act.g513.p7",
                             ttl_seconds=60, resolution=fixtures.build_resolution())
    clock.advance(60)
    listed = isinstance(granted, Lease) and granted in registry.expired(clock.now())
    return by_fields and listed


def _p7() -> tuple[bool, bool]:
    from pocketsec.stage5.executor.lease import Lease

    held = _holds(_expiry_is_data)

    def waits_for_a_registry(self: Any, now: int) -> bool:
        return bool(getattr(self, "_swept_by_registry", False)) and (
            now >= self.expires_at() or now >= self.hard_deadline())

    with _patched(Lease, "expired", waits_for_a_registry):
        return held, _holds(_expiry_is_data)


# --- P8: no COMMIT without an evidence bundle ---------------------------------------------


def _evidence_refusal_precedes_the_host() -> bool:
    """An evidence-destroying suspension at a real executor: REFUSED_EVIDENCE, recorded in
    the receipt, no COMMIT phase and no host call; and ``_commit`` demands a bundle."""
    from pocketsec.stage5.gate import executor_for_rig
    from pocketsec.stage5.gate_runtime import _target_operator
    from pocketsec.stage5.labs.baselines import build_rig
    from pocketsec.stage5.labs.response_corpus import build_evidence_destroying_cases

    tx = _executor_module()
    case = build_evidence_destroying_cases(count=1, seed=37)[0]
    rig = build_rig(case)
    operator = _target_operator(rig, "SUSPEND_PROCESS")
    token = fixtures.mint_token(rig.tokens, operator, action_id="act.g513.p8")
    executor = executor_for_rig(rig)
    before = rig.host.apply_calls
    receipt = executor.execute(operator, token, resolution=case.resolution)
    no_commit = all(record.phase is not tx.Phase.COMMIT for record in receipt.phases)
    refused = receipt.outcome is tx.Outcome.REFUSED_EVIDENCE and no_commit
    try:
        executor._commit(operator)  # type: ignore[call-arg]  # must not bind: bundle required
    except TypeError:
        return refused and rig.host.apply_calls == before
    return False


def _p8() -> tuple[bool, bool]:
    tx = _executor_module()
    held = _holds(_evidence_refusal_precedes_the_host)
    original = tx.TransactionalExecutor._prepare

    def prepare_ignoring_evidence(self: Any, operator: Any, token: Any, *, resolution: Any) -> Any:
        try:
            return original(self, operator, token, resolution=resolution)
        except tx._Refusal as refusal:
            if refusal.outcome is not tx.Outcome.REFUSED_EVIDENCE:
                raise
            return None, None

    with _patched(tx.TransactionalExecutor, "_prepare", prepare_ignoring_evidence):
        return held, _holds(_evidence_refusal_precedes_the_host)


# --- P9: a receipt cannot omit or contradict whether its host was simulated ----------------


def _receipt_states_simulation(receipt: Any) -> bool:
    receipt_type = type(receipt)
    kwargs = {f.name: getattr(receipt, f.name) for f in fields(receipt) if f.name != "simulated"}
    try:
        receipt_type(**kwargs)
    except TypeError:
        omitted_refused = True
    else:
        omitted_refused = False
    try:
        receipt_type(**kwargs, simulated=not receipt.simulated)
    except ContractError:
        contradiction_refused = True
    else:
        contradiction_refused = False
    return receipt.simulated is True and omitted_refused and contradiction_refused


def _p9(receipt: Any) -> tuple[bool, bool]:
    receipt_type = type(receipt)
    held = _holds(lambda: _receipt_states_simulation(receipt))
    original = receipt_type.__init__

    def defaulted(self: Any, *args: Any, **named: Any) -> None:
        original(self, *args, **{"simulated": True, **named})

    with _patched(receipt_type, "__init__", defaulted):
        return held, _holds(lambda: _receipt_states_simulation(receipt))


# --- the check --------------------------------------------------------------------------


def mutation_results(receipt: Any) -> Mapping[str, tuple[bool, bool]]:
    """``property_id -> (holds, holds_under_a_behaviour_level_break)``.

    A proven row with no probe reads ``(False, True)``, so it can never count as killed.
    """
    probes: dict[str, Callable[[], tuple[bool, bool]]] = {
        "P1": _p1, "P4": _p4, "P5": _p5, "P6": _p6, "P7": _p7, "P8": _p8,
        "P9": lambda: _p9(receipt),
    }
    wanted = sorted({*PROBED_ROWS, *(row.property_id for row in assurance.proven())})
    return {pid: probes[pid]() if pid in probes else (False, True) for pid in wanted}


def _anchors_apply() -> list[str]:
    """Every text edit's anchor still occurs exactly once in today's source."""
    stale: list[str] = []
    edits = {**assurance.SENSITIVITY_EDITS, **assurance.MUTATION_EDITS}
    for property_id, (path, _anchor, _replacement) in edits.items():
        try:
            assurance.mutated_source(property_id, (REPO_ROOT / path).read_text(encoding="utf-8"))
        except ContractError:
            stale.append(property_id)
    return stale


def _any_receipt() -> Any:
    """One real receipt, for P9's probe: it rebuilds a receipt from this one's fields."""
    from pocketsec.stage5.gate_runtime import lab_rig, lab_run
    from pocketsec.stage5.host.simulated import FaultProfile

    return lab_run(lab_rig(FaultProfile(seed=53)), "OBSERVE_PROCESS_METADATA")


def check_assurance_table() -> GateCheck:
    """G5.13 — executor properties proven by construction, or downgraded to empirical."""
    results = mutation_results(_any_receipt())
    broken = sorted(pid for pid, (held, _mutated) in results.items() if not held)
    blind = sorted(pid for pid, (held, mutated) in results.items() if held and mutated)
    stale = _anchors_apply()
    unresolved = assurance.unresolvable_constructions()
    no_why = [row.property_id for row in assurance.unmeasured() if not row.why_not.strip()]
    findings = FINDINGS_PATH.read_text(encoding="utf-8") if FINDINGS_PATH.is_file() else None
    unearned = () if findings is None else assurance.unearned_verification_language(findings)
    passed = (not broken and not blind and not stale and not unresolved and not no_why
              and findings is not None and not unearned)
    return GateCheck(
        "G5.13",
        "Executor properties PROVEN_BY_CONSTRUCTION or explicitly downgraded to empirical",
        passed,
        f"counts {dict(assurance.counts())}; behavioural probes (a self-consistency check, "
        f"not source mutation — that is tests/test_stage5_gate.py, which P2 keeps outside "
        f"the package) over {sorted(results)}: behaviour broken on today's code {broken}; "
        f"probes blind to their behaviour-level break {blind}; stale edit anchors {stale}; "
        f"unresolvable constructions {list(unresolved)}; UNMEASURED rows without why_not "
        f"{no_why}; downgraded {sorted(assurance.DOWNGRADED)}; findings document present "
        f"{findings is not None}, unearned verification language at lines "
        f"{[row.split(':')[0] for row in unearned][:8]}",
    )
