"""G5.9, G5.12, G5.13, G5.14, G5.15: comparisons, bounds, assurance and novelty discipline.

Three of these compare arms, and all three run every arm through the real SENTINEL, the
real executor and the same ``SimulatedHost`` in one process (spec §7's three rules), with
``saturation_check`` first so a split every arm solves records nothing. What they measure
is a *within-model* fact: the harm tables that define "collateral" share an author with
the planner (§9.2), so a win here is not evidence that the machinery helps on a Linux host,
and a loss here is a real, falsifiable negative result about the machinery inside the
model. Both sentences go in the findings.

G5.13 lives in ``gate_assurance.py`` and is re-exported here. Its earlier in-process
"mutation" run was circular — each probe read the surface its own patch edited — and a
gate with the executor entry guard deleted and SENTINEL switched off still passed it
(finding F2). It now probes each row's behaviour through the real code path; the
source-level mutation evidence is ``tests/test_stage5_gate.py``, outside the package,
because trust rule P2 forbids a process launcher here.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Callable, Mapping
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.experiments.registry import ExperimentRegistry
from pocketsec.stage0.gate import REPO_ROOT, GateCheck
from pocketsec.stage0.hypotheses import HYPOTHESES
from pocketsec.stage0.prior_art import PriorArtLedger
from pocketsec.stage5.core_ids import ABLATION_FLAGS, OPTIONAL_IDS
from pocketsec.stage5.governor import STAGE5_BUDGET, BudgetExhausted, ResourceGovernor
from pocketsec.stage5.labs import adversarial_load
from pocketsec.stage5.labs.baselines import (
    REFERENCE_ARM_ID,
    always_isolate,
    no_automated_response,
    no_hysteresis,
    pareto_frontier_of,
    reference_arm,
    run_arm,
    single_scalar_utility,
    single_world_planner,
)
from pocketsec.stage5.labs.fifty_experiments import (
    AblationRow,
    record_ablation,
    run_ablation,
    saturation_check,
)
from pocketsec.stage5.labs.response_corpus import build_action_flood, build_ambiguous_pairs
from pocketsec.stage5.operators.d3fend import load_snapshot, mapped_fraction
from pocketsec.stage5.resources import loadavg, measure_stage5_resources

if TYPE_CHECKING:  # pragma: no cover - annotations only; gate.py imports this module
    from pocketsec.stage5.gate import Stage5GateContext

__all__ = [
    "FINDINGS_PATH",
    "HONESTY_HEADINGS",
    "NOVELTY_TOKENS",
    "RESEARCH_CONSTRUCTS",
    "cells_consulted",
    "check_ablation_survival",
    "check_assurance_table",
    "check_bounded_under_load",
    "check_multi_world_collateral",
    "check_no_novelty_claim",
    "mutation_results",
    "novelty_offenders",
    "unread_ablation_flags",
]

FINDINGS_PATH = REPO_ROOT / "docs" / "stage-5-findings.md"
STAGE5_ROOT = REPO_ROOT / "pocketsec" / "stage5"

#: §11's six honesty-ledger headings. G5.15 needs the five the integration plan fixes;
#: Stage 5's sixth, PARAMETERS, is checked too because §4.9's chosen thresholds are the
#: thing in this stage most likely to be misread as a finding.
HONESTY_HEADINGS: tuple[str, ...] = (
    "### MEASURED", "### UNMEASURED", "### REJECTED", "### RETRACTED",
    "### NOT A DETECTION RESULT", "### PARAMETERS",
)
NOVELTY_TOKENS: tuple[str, ...] = (
    "novel", "novelty", "first", "unprecedented", "patent", "breakthrough", "state-of-the-art",
)
RESEARCH_CONSTRUCTS: tuple[str, ...] = (
    "SAFE", "AEGIS", "SENTINEL", "Action Shadow", "Intervention Cone",
    "Response Identifiability", "Safe-State Manifold", "Intervention Residual",
)
_NOVELTY_WINDOW = 3
_AMBIGUOUS_PAIRS = 30
_FLOOD_CASES = 40


def _factory() -> Callable[[Any], Any]:
    from pocketsec.stage5.gate import executor_for_rig

    return executor_for_rig


# --- G5.9 -----------------------------------------------------------------------------


def check_multi_world_collateral(ctx: Stage5GateContext) -> GateCheck:
    """G5.9 — multi-world evaluation demonstrably reduces collateral in ambiguous incidents."""
    pairs = build_ambiguous_pairs(count=_AMBIGUOUS_PAIRS, seed=17)
    cases = tuple(member for pair in pairs for member in pair)
    arms = {
        "B1": no_automated_response, "B4": always_isolate,
        "B7": single_world_planner, REFERENCE_ARM_ID: reference_arm,
    }
    outcomes = {
        arm: run_arm(policy, cases, baseline_id=arm, build_executor=_factory())
        for arm, policy in arms.items()
    }
    load = loadavg()
    degenerate, reason = saturation_check(outcomes)
    full, single = outcomes[REFERENCE_ARM_ID], outcomes["B7"]
    lower = (
        full.collateral_per_1000() is not None and single.collateral_per_1000() is not None
        and full.collateral_per_1000() < single.collateral_per_1000()  # type: ignore[operator]
    )
    no_worse = full.incidents_contained >= single.incidents_contained
    passed = not degenerate and lower and no_worse
    return GateCheck(
        "G5.9",
        "Multi-world evaluation reduces collateral in ambiguous incidents",
        passed,
        f"{len(pairs)} ambiguous pairs ({len(cases)} cases); saturation: {reason}; full "
        f"planner contained {full.incidents_contained} at collateral_per_1000 "
        f"{full.collateral_per_1000()} over {full.actions_taken} actions; B7 single-world "
        f"contained {single.incidents_contained} at {single.collateral_per_1000()} over "
        f"{single.actions_taken} actions; strictly lower collateral {lower}, containment no "
        f"worse {no_worse}. Within-model only: 'collateral' is defined by harm tables that "
        f"share an author with the planner (§6.1). loadavg {load}",
    )


# --- G5.12 ----------------------------------------------------------------------------


def _flood_bounds() -> dict[str, int]:
    """Drive the field, twin and cone with every case's full process table as targets."""
    from pocketsec.stage5.aegis.cone import MAX_CONE_DEPTH, MAX_CONE_NODES, build_intervention_cone
    from pocketsec.stage5.aegis.pareto import world_ids_of
    from pocketsec.stage5.aegis.planner import _adaptation_model
    from pocketsec.stage5.cells.response_cells import ResponseCellField
    from pocketsec.stage5.constitution.invariants import FROZEN_CONSTITUTION
    from pocketsec.stage5.memory.effectiveness import EffectivenessMemory
    from pocketsec.stage5.safe.action_field import MAX_CANDIDATES, generate_action_field
    from pocketsec.stage5.twin.response_twin import MAX_TWIN_NODES, ResponseTwin

    seen = dict.fromkeys(("candidates", "cone_depth", "cone_nodes", "twin_nodes", "work_units",
                          "fields_truncated", "cases", "budget_escalations", "over_bound"), 0)
    for case in build_action_flood(count=_FLOOD_CASES, seed=23):
        governor, snapshot = ResourceGovernor(), case.host.snapshot()
        twin = ResponseTwin(snapshot=snapshot, governor=governor)
        field = generate_action_field(
            case.resolution, snapshot, constitution=FROZEN_CONSTITUTION,
            invariants=case.invariants, governor=governor, memory=EffectivenessMemory(),
            cells=ResponseCellField(), twin=twin,
        )
        seen["cases"] += 1
        seen["candidates"] = max(seen["candidates"], len(field.candidates))
        # Only a row that names a bound counts: every field also carries the unrelated
        # response-cell-lookup row, and counting that would make this clause vacuous.
        seen["fields_truncated"] += any(
            "budget" in row.reason or "MAX_CANDIDATES" in row.reason for row in field.truncations
        )
        world = world_ids_of(case.resolution)[0]
        for candidate in field.candidates:
            try:
                cone = build_intervention_cone(candidate, world_id=world, twin=twin,
                                               adaptations=_adaptation_model(snapshot),
                                               governor=governor)
                twin_nodes = len(twin.predict(candidate, world_id=world).predicted.nodes)
            except BudgetExhausted:
                seen["budget_escalations"] += 1
                break
            seen["cone_depth"] = max(seen["cone_depth"], max(n.depth for n in cone.nodes))
            seen["cone_nodes"] = max(seen["cone_nodes"], len(cone.nodes))
            seen["twin_nodes"] = max(seen["twin_nodes"], twin_nodes)
        seen["work_units"] = max(seen["work_units"], governor.spend_report()["TOTAL"])
        seen["over_bound"] += (len(field.candidates) > MAX_CANDIDATES
                               or seen["cone_depth"] > MAX_CONE_DEPTH
                               or seen["cone_nodes"] > MAX_CONE_NODES
                               or seen["twin_nodes"] > MAX_TWIN_NODES)
    return seen


def _executor_state_bounds(ctx: Stage5GateContext) -> dict[str, int]:
    from pocketsec.stage5.executor.journal import MAX_JOURNAL_BYTES
    from pocketsec.stage5.executor.lease import MAX_CONCURRENT_LEASES

    journal = max((a.rig.journal.bytes_used() for a in ctx.actions), default=0)
    leases = max((len(a.rig.leases.active(a.rig.clock.now())) for a in ctx.actions), default=0)
    return {
        "journal_bytes": journal, "journal_over": int(journal > MAX_JOURNAL_BYTES),
        "leases": leases, "leases_over": int(leases > MAX_CONCURRENT_LEASES),
    }


def check_bounded_under_load(ctx: Stage5GateContext) -> GateCheck:
    """G5.12 — resource and action fan-out remain bounded under adversarial load."""
    suites = adversarial_load.run_all()
    flood = _flood_bounds()
    state = _executor_state_bounds(ctx)
    report = measure_stage5_resources(ctx.corpus, build_executor=_factory())
    incremental_ok = (report.incremental_rss_bytes is not None
                      and report.incremental_rss_bytes <= 50 * 1024 * 1024)
    bounds_ok = (all(s.within_bound for s in suites) and flood["over_bound"] == 0
                 and flood["work_units"] <= STAGE5_BUDGET.max_work_units
                 and flood["fields_truncated"] == flood["cases"] and not state["journal_over"]
                 and not state["leases_over"])
    passed = bounds_ok and report.within_target is True
    unmeasured = sorted(name for name, value in report.component_bytes.items() if value is None)
    return GateCheck(
        "G5.12",
        "Resource and action fan-out remain bounded under adversarial load",
        passed,
        f"fan-out bounds held: {bounds_ok} — adversarial suites within bound "
        f"{sum(s.within_bound for s in suites)}/{len(suites)} "
        f"({', '.join(f'{s.suite}={s.observed_value}/{s.bound}' for s in suites)}); action "
        f"flood of {flood['cases']} cases: max candidates {flood['candidates']}, max cone "
        f"depth {flood['cone_depth']} / nodes {flood['cone_nodes']}, max twin nodes "
        f"{flood['twin_nodes']}, max work units {flood['work_units']} of "
        f"{STAGE5_BUDGET.max_work_units}, {flood['fields_truncated']}/{flood['cases']} fields "
        f"recorded the bound that cut them (budget/MAX_CANDIDATES truncation row), "
        f"{flood['budget_escalations']} BudgetExhausted escalations; max "
        f"journal {state['journal_bytes']} B, max active leases {state['leases']}. Resource "
        f"envelope: incremental RSS {report.incremental_rss_bytes} B (<= 50 MiB: "
        f"{incremental_ok}), process peak {report.peak_rss_bytes} B, within_target="
        f"{report.within_target} — UNMEASURED rows {unmeasured}, so this criterion reports "
        f"UNMEASURED and does not pass (§6). loadavg {report.loadavg}",
    )


# --- G5.13 ----------------------------------------------------------------------------

# Moved to ``gate_assurance.py`` (finding F2): the probes that lived here each read the
# surface their own patch changed and could not report a surviving mutation. The names
# stay importable from this module for ``gate.py``, ``cli.py`` and the tests.
from pocketsec.stage5.gate_assurance import (  # noqa: E402 - re-export
    check_assurance_table,
    mutation_results,
)

# --- G5.14 ----------------------------------------------------------------------------


def ablation_rows(ctx: Stage5GateContext) -> dict[str, AblationRow]:
    """One measured row per OPTIONAL core id, keyed by the id (§4.9 Rule A's join)."""
    by_flag: dict[str, AblationRow] = {}
    rows: dict[str, AblationRow] = {}
    for core_id in OPTIONAL_IDS:
        flag = ABLATION_FLAGS[core_id]
        if flag not in by_flag:
            by_flag[flag] = run_ablation(ctx.corpus, flag=flag, core_id=core_id,
                                         build_executor=_factory())
        rows[core_id] = replace(by_flag[flag], core_id=core_id)
    return rows


def _register(ctx: Stage5GateContext, rows: Mapping[str, AblationRow]) -> dict[str, str | None]:
    registry = ExperimentRegistry(ctx.scratch / "registry.jsonl")
    registered: dict[str, str | None] = {}
    for sequence, (core_id, row) in enumerate(sorted(rows.items()), start=1):
        try:
            registered[core_id] = record_ablation(
                registry, row, sequence=sequence, seeds={"corpus": 11},
                dataset_sha256=ctx.corpus_sha256.removeprefix("sha256:"))
        except ContractError:
            registered[core_id] = None
    return registered


def primed_sensitivity(ctx: Stage5GateContext) -> dict[str, Any]:
    """The full planner and B7 again, with effectiveness memory primed in-simulator.

    Informational, not a pass condition. Cold, the planner can take no autonomous leased
    action (``rollback_reliability`` is ``None`` below eight samples), so a cold-start loss
    to the playbook could be an artefact of priming rather than of the machinery. This
    removes that excuse and records what then decides the outcome.
    """
    from pocketsec.stage5.gate_runtime import prime_memory

    def primed(policy: Callable[[Any], Any]) -> Callable[[Any], Any]:
        def run(rig: Any) -> Any:
            prime_memory(rig)
            return policy(rig)
        return run

    return {
        arm: run_arm(primed(policy), ctx.corpus, baseline_id=f"{arm}+primed",
                     build_executor=_factory())
        for arm, policy in (
            (REFERENCE_ARM_ID, reference_arm), ("B6", single_scalar_utility),
            ("B7", single_world_planner), ("B8", no_hysteresis),
        )
    }


#: Files that set or name the ablation flags without being the mechanism they switch.
_FLAG_DECLARERS = ("core_ids.py", "cli.py")


def unread_ablation_flags() -> tuple[str, ...]:
    """Ablation flags no package code reads as an attribute (finding R7).

    ``PlannerConfig`` declares all eleven and validates them with ``getattr``; a flag that
    nothing else reads switches nothing, so its ablation delta is 0.0 by construction, not
    by measurement. The gate, the labs and ``core_ids`` only set or name flags and are not
    readers.
    """
    flags = set(ABLATION_FLAGS.values())
    read: set[str] = set()
    for path in STAGE5_ROOT.rglob("*.py"):
        if path.name.startswith("gate") or path.name in _FLAG_DECLARERS or "labs" in path.parts:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
                read.add(node.attr)
    return tuple(sorted(flags - read))


class _Tripwire:
    """A stand-in whose every attribute read raises: handing it to a consumer shows
    whether the consumer reads the object at all, rather than whether a flag exists."""

    def __getattribute__(self, name: str) -> Any:
        raise LookupError(f"consulted .{name}")


def cells_consulted(ctx: Stage5GateContext) -> bool:
    """Whether field generation reads the response-cell field on any gate case (R7).

    ``enable_response_cells`` has a reader — the planner swaps the field for an empty one
    — but the generator it hands the field to uses only its type name in a truncation
    message, so SAFE-F21/F22's delta is 0.0 by construction. Measured by passing a
    tripwire and seeing whether generation ever touches it.
    """
    from pocketsec.stage5.constitution.invariants import FROZEN_CONSTITUTION
    from pocketsec.stage5.labs.baselines import build_rig
    from pocketsec.stage5.memory.effectiveness import EffectivenessMemory
    from pocketsec.stage5.safe.action_field import generate_action_field
    from pocketsec.stage5.twin.response_twin import ResponseTwin

    for case in ctx.corpus:
        rig = build_rig(case)
        try:
            generate_action_field(
                case.resolution, rig.before, constitution=FROZEN_CONSTITUTION,
                invariants=case.invariants, governor=ResourceGovernor(),
                memory=EffectivenessMemory(), cells=_Tripwire(),  # type: ignore[arg-type]
                twin=ResponseTwin(snapshot=rig.before, governor=ResourceGovernor()),
            )
        except LookupError:
            return True
    return False


def _inert_ids(ctx: Stage5GateContext, rows: Mapping[str, AblationRow]) -> list[str]:
    """OPTIONAL ids whose flag switches nothing the run can observe: unmeasured, not 0.0."""
    unread = set(unread_ablation_flags())
    cells_inert = not cells_consulted(ctx)
    return sorted(core for core, row in rows.items()
                  if row.flag in unread or (row.flag == "enable_response_cells" and cells_inert))


def check_ablation_survival(ctx: Stage5GateContext) -> GateCheck:
    """G5.14 — advanced mechanisms survive ablation against simpler playbooks/controllers."""
    degenerate, reason = saturation_check(ctx.outcomes)
    frontier = pareto_frontier_of(ctx.outcomes)
    rows = ablation_rows(ctx)
    registered = _register(ctx, rows)
    inert = _inert_ids(ctx, rows)
    unmeasured = sorted({*inert, *(core for core, row in rows.items() if row.delta is None)})
    unregistered = sorted(core for core, eid in registered.items() if eid is None)
    verdicts = {core: f"{row.flag}:{row.verdict.value}({row.delta})" for core, row in rows.items()}
    on_frontier = REFERENCE_ARM_ID in frontier
    passed = not degenerate and on_frontier and not unmeasured and not unregistered
    summary = ", ".join(
        f"{arm} {o.incidents_contained}c/{o.collateral_per_1000()}/{o.work_units}wu"
        for arm, o in sorted(ctx.outcomes.items()))
    primed = ", ".join(
        f"{arm} {o.incidents_contained}c/{o.collateral_per_1000()}/{o.work_units}wu/"
        f"{o.human_escalations}esc" for arm, o in primed_sensitivity(ctx).items())
    return GateCheck(
        "G5.14",
        "Advanced mechanisms survive ablation against simpler playbooks/controllers",
        passed,
        f"saturation: {reason}; Pareto frontier on (contained, collateral_per_1000, work "
        f"units) = {list(frontier)}, full planner on it: {on_frontier}; arms [{summary}]; "
        f"{len(rows) - len(unmeasured)}/{len(OPTIONAL_IDS)} OPTIONAL ids carry a measured "
        f"delta; inert (flag unread, or its consumer never reads what it switches — delta "
        f"0.0 by construction, counted unmeasured) {inert}; "
        f"{len(rows) - len(unregistered)} registered in a temporary ledger; verdicts "
        f"{verdicts}. Sensitivity, memory primed by in-simulator LAB_SANDBOX drills (not a "
        f"pass condition): [{primed}]. In-simulator comparison only (§6.1). loadavg "
        f"{ctx.loadavg_at_build}",
    )


# --- G5.15 ----------------------------------------------------------------------------


def novelty_offenders(text: str) -> list[str]:
    """Novelty words within three lines of a §49 construct, unless the paragraph disclaims."""
    lines = text.splitlines()
    token_re = re.compile(r"\b(" + "|".join(re.escape(t) for t in NOVELTY_TOKENS) + r")\b", re.I)
    construct_re = re.compile("|".join(re.escape(name) for name in RESEARCH_CONSTRUCTS))
    offenders: list[str] = []
    for number, line in enumerate(lines):
        match = token_re.search(line)
        if match is None:
            continue
        low, high = max(0, number - _NOVELTY_WINDOW), min(len(lines), number + _NOVELTY_WINDOW + 1)
        if not construct_re.search("\n".join(lines[low:high])):
            continue
        if "no novelty claim" in _paragraph(lines, number):
            continue
        offenders.append(f"{number + 1}:{match.group(1)}")
    return offenders


def _paragraph(lines: list[str], number: int) -> str:
    start = number
    while start > 0 and lines[start - 1].strip():
        start -= 1
    end = number
    while end < len(lines) - 1 and lines[end + 1].strip():
        end += 1
    return "\n".join(lines[start:end + 1])


def check_no_novelty_claim(ctx: Stage5GateContext) -> GateCheck:
    """G5.15 — no external novelty claim is made before literature/patent review."""
    from pocketsec.stage5.gate import registry_digest

    hypotheses_ok = set(HYPOTHESES) == {f"H{index}" for index in range(9)}
    ledger_ok = set(PriorArtLedger.load().entries) == set(HYPOTHESES)
    text = FINDINGS_PATH.read_text(encoding="utf-8") if FINDINGS_PATH.is_file() else None
    missing = [] if text is None else [h for h in HONESTY_HEADINGS if h not in text]
    offenders = [] if text is None else novelty_offenders(text)
    fraction = mapped_fraction()
    d3fend_ok = fraction == 0.0 or load_snapshot() is not None
    registry_ok = registry_digest() == ctx.registry_before
    passed = (hypotheses_ok and ledger_ok and text is not None and not missing
              and not offenders and d3fend_ok and registry_ok)
    return GateCheck(
        "G5.15",
        "No external novelty claim before literature/patent review",
        passed,
        f"HYPOTHESES == H0..H8 {hypotheses_ok}; prior-art ledger keys == HYPOTHESES "
        f"{ledger_ok} (Stage 5 appended to neither); docs/stage-5-findings.md present "
        f"{text is not None}, missing honesty headings {missing}, novelty words near a §49 "
        f"construct without 'no novelty claim' {offenders[:4]}; D3FEND mapped_fraction "
        f"{fraction} (0.0 = every operator UNMAPPED, ADR-0047); experiments/registry.jsonl "
        f"byte-identical before and after the gate {registry_ok}",
    )
