"""The Stage 8 gate's evidence criteria: G8.4 to G8.9, read off the gate's own runs.

These checks audit the discovery runs ``Stage8GateContext.build`` performed: the verdicts the
identifiability gate recorded, the REPLICATION batch, the novelty audit, every FORGE
tournament, every package's lineage, and what Stage 6 was handed and said. Each also builds
the one worked case the spec names (PM1 against its CO_OCCURS twin, the 5-episode candidate,
the PM3 rediscovery control, the PM2 expressibility refusal) with the real subsystem. A check
that inspects zero objects is VACUOUS and FAILS; a figure read from a corpus whose
preconditions failed is DEGENERATE and FAILS.

Nothing here is a detection result: the corpus, its planted truth and the lab oracle share an
author with the engine, and every detection gain is ``counterfactual_at_boundary``.
"""

from __future__ import annotations

import copy
import random
import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage0.gate import GateCheck
from pocketsec.stage0.prior_art import PriorArtLedger, ReviewStatus
from pocketsec.stage1.epoch.model import EpochModel, SystemIdentity
from pocketsec.stage6.provenance.ledger import ProvenanceLedger
from pocketsec.stage8.adapters.stage6 import Stage6Adapter
from pocketsec.stage8.ecology.lineage import NodeKind
from pocketsec.stage8.episode import Episode, Split
from pocketsec.stage8.forge.compiler import compile_all
from pocketsec.stage8.forge.package import (
    DiscoveryPackageV1,
    IdentifiabilityClass,
    NoveltyClass,
    RepresentationKind,
    ReproducibilityStatus,
    TournamentResult,
    verify_package,
)
from pocketsec.stage8.forge.tournament import (
    ENDPOINT_ARTIFACT_MAX_BYTES,
    FORGE_AGREEMENT_MIN,
    FORGE_FPR_TOLERANCE,
    FORGE_PRECISION_TOLERANCE,
    FORGE_RECALL_TOLERANCE,
    FORGE_WALL_RATIO_MAX,
    SECURITY_FIELDS,
    reselect,
)
from pocketsec.stage8.gate_boundary import rule_offenders
from pocketsec.stage8.gate_construction import PM1, control_genome
from pocketsec.stage8.governor.budget import ResearchBudget, ResearchGovernor
from pocketsec.stage8.identifiability.gate import IdentifiabilityGate
from pocketsec.stage8.laboratory.counterfactual import TransformKind, TransformSpec, apply_transform
from pocketsec.stage8.labs.discovery_corpus import (
    PLANTED_MECHANISMS,
    DiscoveryCorpus,
    Family,
    LabOracle,
)
from pocketsec.stage8.labs.discovery_run import DiscoveryRunReport, lab_gateway
from pocketsec.stage8.ledger.theory import LedgerEventKind, TheoryLedger
from pocketsec.stage8.novelty.prior_art_audit import audit, known_library
from pocketsec.stage8.oracle.planner import StopReason
from pocketsec.stage8.residual.observatory import (
    PhiOracleExplainer,
    ResidualKind,
    ResidualObservatory,
)
from pocketsec.stage8.sandbox.integrity import run_key, sign_record, verify_record

if TYPE_CHECKING:
    from pocketsec.stage8.gate import Stage8GateContext

__all__ = [
    "check_g8_4",
    "check_g8_5",
    "check_g8_6",
    "check_g8_7",
    "check_g8_8",
    "check_g8_9",
    "degenerate",
    "packages_of",
]

CO1 = "CO_OCCURS(EXECUTE+TEMP_LOCATION,CONNECT+EXTERNAL_ENDPOINT)"
#: G8.4(b)'s rival on the DROPOUT arm (the falsification package's worked case): a theory the
#: sensor loss makes indistinguishable from PM1 except on incompletely observed sessions.
DROPOUT_RIVAL = "PRECEDES(WRITE+TEMP_LOCATION,CONNECT+EXTERNAL_ENDPOINT)"
_LOCAL_ID = re.compile(r"^stage\d+:[A-Z0-9_]+$")


def degenerate(ctx: Stage8GateContext, arm: str) -> tuple[str, ...]:
    """The arm's failed preconditions (spec §4.19): a figure read from it is DEGENERATE."""
    report = ctx.preconditions.get(arm)
    return ("preconditions not computed",) if report is None else report.problems


def packages_of(ctx: Stage8GateContext) -> list[tuple[DiscoveryRunReport, DiscoveryPackageV1]]:
    """Every package of the PLANTED runs (lab oracle off and on), with the run it came from."""
    return [(r, p) for r in (ctx.main, ctx.lab_on) if r is not None for p in r.packages]


def _observed(corpus: DiscoveryCorpus) -> tuple[Episode, ...]:
    return corpus.episodes(Split.LAB_POOL) + corpus.episodes(Split.TRAIN)


# --- G8.4 -------------------------------------------------------------------------------------


def _reordered(corpus: DiscoveryCorpus) -> list[Episode]:
    """REORDER interventions on PM1's matches, labelled by the lab oracle (lab_oracle_authored)."""
    pm1 = control_genome(PM1)
    target = pm1.necessary_conditions[1]
    oracle = LabOracle(governor=ResearchGovernor(ResearchBudget()))
    rng = random.Random(0)
    made = [apply_transform(e, TransformSpec(TransformKind.REORDER, 0, target), rng=rng)
            for e in _observed(corpus) if pm1.decides(e)]
    return [e.with_split(Split.CHALLENGE, label=oracle.label(e)) for e in made if e is not None]


def _worked_cases(ctx: Stage8GateContext) -> tuple[bool, list[str]]:
    planted, dropout = ctx.planted, ctx.dropout
    if planted is None or dropout is None:
        return False, ["corpora missing"]
    pm1, co1 = control_genome(PM1), control_genome(CO1)
    observed = _observed(planted)
    off = IdentifiabilityGate(interventions_permitted=False).assess(pm1, [co1], observed)
    worlds = _reordered(planted)
    on = IdentifiabilityGate(interventions_permitted=True).assess(pm1, [co1], observed, worlds)
    lossy = IdentifiabilityGate(interventions_permitted=False).assess(
        pm1, [control_genome(DROPOUT_RIVAL)], _observed(dropout))
    hits = [e for e in observed if pm1.decides(e)][:5]
    few = IdentifiabilityGate(interventions_permitted=True).assess(
        pm1, [co1], hits + [e for e in observed if not pm1.decides(e)])
    ok = (off.klass is IdentifiabilityClass.EQUIVALENCE_CLASS
          and on.klass is IdentifiabilityClass.IDENTIFIED
          and (lossy.klass, lossy.reason) == (IdentifiabilityClass.UNIDENTIFIABLE,
                                              "ONLY_UNDER_INCOMPLETE_OBSERVATION")
          and few.verdict is Verdict.INSUFFICIENT_EVIDENCE)
    return ok, [f"(a) PM1 vs CO_OCCURS twin, interventions off: {off.klass.value}; with "
                f"{len(worlds)} REORDER worlds + lab oracle: {on.klass.value} "
                f"(lab_oracle_authored)",
                f"(b) DROPOUT PM1 vs {DROPOUT_RIVAL}: {lossy.klass.value}/{lossy.reason}",
                f"(c) 5-match candidate: {few.reason} -> "
                f"{None if few.verdict is None else few.verdict.value}"]


def _telemetry_stop(ctx: Stage8GateContext) -> tuple[bool, str]:
    run = ctx.dropout_run
    if run is None:
        return False, "DROPOUT run missing"
    stops = [(o.stop.value, o.visibility_share) for o in run.oracle]
    hit = any(o.stop is StopReason.TELEMETRY_FAILURE and (o.visibility_share or 0.0) >= 0.5
              for o in run.oracle)
    return hit, f"ORACLE stops on DROPOUT (stop, visibility share): {stops}"


def _run_verdicts(ctx: Stage8GateContext) -> tuple[list[str], int, int]:
    """(d): every non-IDENTIFIED verdict is UNKNOWN-typed, in the ledger, and in its package."""
    problems: list[str] = []
    verdicts = non_identified = 0
    allowed = {Verdict.UNIDENTIFIABLE, Verdict.INSUFFICIENT_EVIDENCE}
    for run in ctx.reports():
        by_package = {p.hypothesis_id: p for p in run.packages}
        for verdict in run.identifiability:
            verdicts += 1
            recorded = None if run.ledger is None else \
                run.ledger.record(verdict.hypothesis_id).identifiability
            if recorded is not verdict.klass:
                problems.append(f"{verdict.hypothesis_id} ledger has {recorded}")
            package = by_package.get(verdict.hypothesis_id)
            if package is not None and package.identifiability is not verdict.klass:
                problems.append(f"{verdict.hypothesis_id} package changed its class")
            if verdict.klass is not IdentifiabilityClass.IDENTIFIED:
                non_identified += 1
                if verdict.verdict not in allowed:
                    problems.append(f"{verdict.hypothesis_id} forced to {verdict.verdict}")
    return problems, verdicts, non_identified


def _open_world(ctx: Stage8GateContext) -> tuple[bool, str]:
    planted = ctx.planted
    if planted is None:
        return False, "(e) no corpus"
    pool = tuple(e.with_split(Split.LAB_POOL, label=None) for e in planted.episodes(Split.LAB_POOL))
    train = planted.episodes(Split.TRAIN)
    field = ResidualObservatory([PhiOracleExplainer.fit(train)],
                                governor=ResearchGovernor(ResearchBudget())).observe(pool)
    kinds = Counter(r.kind.value for r in field.residuals)
    ok = bool(field.residuals) and set(kinds) == {ResidualKind.UNEXPLAINED_ESCALATION.value}
    return ok, (f"(e) unlabelled LAB_POOL ({len(pool)} episodes): residual kinds "
                f"{dict(kinds)}; none assigned a known class: {ok}")


def check_g8_4(ctx: Stage8GateContext) -> GateCheck:
    """Unknown/unidentifiable outcomes are preserved rather than forced (spec §6 G8.4)."""
    title = "Unknown/unidentifiable outcomes are preserved rather than forced into conclusions"
    worked, texts = _worked_cases(ctx)
    stop_ok, stop_text = _telemetry_stop(ctx)
    problems, verdicts, non_identified = _run_verdicts(ctx)
    open_ok, open_text = _open_world(ctx)
    passed = worked and stop_ok and not problems and verdicts > 0 and open_ok
    return GateCheck("G8.4", title, passed, "; ".join(texts) + (
        f"; {stop_text}: TELEMETRY_FAILURE fired {stop_ok}; (d) run verdicts {verdicts}, "
        f"non-IDENTIFIED {non_identified}, problems {len(problems)}"
        f"{' ' + str(problems[:3]) if problems else ''}{' (VACUOUS)' if not verdicts else ''}; "
        f"{open_text}. Met as mechanism; value on real sensor loss is UNMEASURED"))


# --- G8.5 -------------------------------------------------------------------------------------


def _replication_batch(run: DiscoveryRunReport) -> tuple[int, set[int], int, bool]:
    """(registrations, batch sizes, results, every result registered first) on REPLICATION."""
    ledger = run.ledger
    if ledger is None:
        return 0, set(), 0, False
    regs = [dict(e.payload) for e in ledger.entries() if e.kind is LedgerEventKind.PREREGISTER
            and dict(e.payload).get("split") == Split.REPLICATION.value]
    results = [e.hypothesis_id for e in ledger.entries()
               if e.kind is LedgerEventKind.TEST_RESULT
               and dict(e.payload).get("split") == Split.REPLICATION.value]
    first = all(ledger.registered_before_tested(h) for h in results)
    return len(regs), {int(r["batch_size"]) for r in regs}, len(results), first


def check_g8_5(ctx: Stage8GateContext) -> GateCheck:
    """Validated discoveries reproduce across predefined independent splits (spec §6 G8.5)."""
    title = "Validated discoveries reproduce across predefined independent splits"
    run, problems = ctx.main, degenerate(ctx, "PLANTED")
    if run is None:
        return GateCheck("G8.5", title, False, "the PLANTED run did not complete")
    regs, sizes, results, first = _replication_batch(run)
    one_batch = regs == len(run.survived) and sizes <= {regs} and results == regs and first
    statuses = Counter(p.reproducibility.status.value for p in run.packages)
    bad = [p.package_id for p in run.packages
           if p.reproducibility.status is not ReproducibilityStatus.REPRODUCED
           or p.hypothesis_id not in run.reproduced]
    independent = sorted({p.reproducibility.independent_positives_available for p in run.packages})
    fps = [p.reproducibility.independent_false_positive_rate for p in run.packages]
    passed = not problems and one_batch and bool(run.packages) and not bad
    return GateCheck("G8.5", title, passed, (
        f"PLANTED preconditions {'OK' if not problems else 'DEGENERATE ' + str(problems)}; "
        f"SURVIVED {len(run.survived)}; REPLICATION preregistrations {regs} in one batch "
        f"(batch sizes {sorted(sizes)}), results {results}, all registered first: {first}; "
        f"REPRODUCED {len(run.reproduced)}; packages {len(run.packages)} by status "
        f"{dict(statuses)}{' (VACUOUS)' if not run.packages else ''}; built from a "
        f"non-REPRODUCED theory {len(bad)}; independent_positives_available {independent}; "
        f"INDEPENDENT FP rates {fps}. Predefined synthetic splits (hosts h09-h12, epoch 2, "
        f"family variants); independence from the corpus author is UNMEASURED"))


# --- G8.6 -------------------------------------------------------------------------------------


def _values(node: Any) -> list[str]:
    """Every string VALUE of a nested payload (keys are field names, not claims)."""
    if isinstance(node, dict):
        return [v for item in node.values() for v in _values(item)]
    if isinstance(node, (list, tuple)):
        return [v for item in node for v in _values(item)]
    return [node] if isinstance(node, str) else []


def _novel_words(package: DiscoveryPackageV1) -> int:
    """(c): 'novel' in a payload value other than the enum value POTENTIALLY_NOVEL."""
    return sum(v.lower().count("novel") for v in _values(package.to_dict())
               if v != NoveltyClass.POTENTIALLY_NOVEL.value)


def check_g8_6(ctx: Stage8GateContext) -> GateCheck:
    """Novelty is classified conservatively and not claimed without review (spec §6 G8.6)."""
    title = "Novelty is classified conservatively and not claimed without prior-art review"
    pairs = packages_of(ctx)
    claims = [p.package_id for _, p in pairs if p.novelty_claim_permitted]
    foreign = [m for _, p in pairs for m in p.known_technique_mappings if not _LOCAL_ID.match(m)]
    words = sum(_novel_words(p) for _, p in pairs)
    prior_art = PriorArtLedger.load()
    pm3 = control_genome(PLANTED_MECHANISMS[Family.CREDENTIAL_EGRESS].to_dsl())
    control = audit(pm3, known_library(), prior_art=prior_art)
    rediscovered = (control.classification is NoveltyClass.KNOWN
                    and "stage1:ATTACK_EXFIL" in control.matched_known)
    reviews = {h: (e.literature_status.value, e.patent_status.value)
               for h, e in prior_art.entries.items() if h in ("H4", "H8")}
    unreviewed = (set(reviews) == {"H4", "H8"} and all(
        s == ReviewStatus.NOT_REVIEWED.value for pair in reviews.values() for s in pair))
    classes = Counter(p.novelty_classification.value for _, p in pairs)
    passed = bool(pairs) and not claims and not foreign and not words and rediscovered \
        and unreviewed and not control.novelty_claim_permitted
    return GateCheck("G8.6", title, passed, (
        f"(a) packages {len(pairs)}{' (VACUOUS)' if not pairs else ''}, novelty classes "
        f"{dict(classes)}, claims permitted {len(claims)}, non-local technique ids "
        f"{len(foreign)}; (b) rediscovery control PM3 -> {control.classification.value}, "
        f"matched {list(control.matched_known)}; (c) 'novel' outside POTENTIALLY_NOVEL {words}; "
        f"(d) prior-art reviews {reviews}. ATT&CK/Sigma/YARA/literature indexes are NOT BUILT: "
        f"novelty against them is UNMEASURED"))


# --- G8.7 -------------------------------------------------------------------------------------


def _entrant_problems(result: TournamentResult) -> list[str]:
    problems = []
    for m in result.entrants:
        values = [getattr(m, name) for name in SECURITY_FIELDS]
        if not m.expressible and not m.refusal:
            problems.append(f"{m.kind.value} refused without a code")
        if m.expressible and any(v is None for v in values):
            problems.append(f"{m.kind.value} has a None security field")
    if reselect(result) != (result.selected, result.pareto_front):
        problems.append("reselect does not reproduce the selection")
    return problems


def _deployable_problem(result: TournamentResult) -> str | None:
    """(d) deployable only if the SELECTED entrant keeps quality within tolerance AND costs less."""
    if not result.deployable:
        return None
    ref = next(m for m in result.entrants if m.kind is RepresentationKind.TYPED_RULE)
    m = next((e for e in result.entrants if e.kind is result.selected), None)
    if m is None or None in (m.recall, m.precision, m.false_positive_rate, m.decision_agreement,
                             m.work_units_per_event, m.artifact_bytes, ref.recall, ref.precision,
                             ref.false_positive_rate, ref.work_units_per_event, ref.artifact_bytes):
        return "deployable with an unmeasured selected entrant"
    keeps = (m.recall >= ref.recall - FORGE_RECALL_TOLERANCE
             and m.precision >= ref.precision - FORGE_PRECISION_TOLERANCE
             and m.false_positive_rate <= ref.false_positive_rate + FORGE_FPR_TOLERANCE
             and m.decision_agreement >= FORGE_AGREEMENT_MIN
             and m.artifact_bytes <= ENDPOINT_ARTIFACT_MAX_BYTES)
    # F2 (honesty): work units are self-charged, so "cheaper" also needs the measured
    # within-run wall ratio to TYPED_RULE to be at most FORGE_WALL_RATIO_MAX.
    cheaper = (m.wall_ratio_to_reference is not None
               and m.wall_ratio_to_reference <= FORGE_WALL_RATIO_MAX
               and m.work_units_per_event <= ref.work_units_per_event
               and m.artifact_bytes <= ref.artifact_bytes
               and (m.work_units_per_event < ref.work_units_per_event
                    or m.artifact_bytes < ref.artifact_bytes))
    return None if keeps and cheaper else f"{m.kind.value} deployable but keeps={keeps} " \
        f"cheaper={cheaper}"


def _pm2_refusal(ctx: Stage8GateContext) -> str | None:
    planted = ctx.planted
    if planted is None:
        return None
    pm2 = control_genome(PLANTED_MECHANISMS[Family.REPEATED_EGRESS].to_dsl())
    compiled = compile_all(pm2, planted.episodes(Split.TRAIN),
                           governor=ResearchGovernor(ResearchBudget()))
    motif = next(c for c in compiled if c.kind is RepresentationKind.MOTIF)
    return motif.refusal


def check_g8_7(ctx: Stage8GateContext) -> GateCheck:
    """FORGE selects by measured security/resource Pareto performance (spec §6 G8.7)."""
    title = "FORGE selects by measured security/resource Pareto performance"
    results = [p.detector_candidates for _, p in packages_of(ctx)]
    problems = [f"{r.tournament_id}: {x}" for r in results for x in _entrant_problems(r)]
    deploy = [x for r in results if (x := _deployable_problem(r))]
    refusals = Counter(m.refusal for r in results for m in r.entrants if not m.expressible)
    pm2 = _pm2_refusal(ctx)
    fired = sum(refusals.values()) > 0 or pm2 == "MOTIF_CANNOT_EXPRESS_REPEATED"
    selected = Counter(str(r.selected.value if r.selected else None) for r in results)
    direct = ctx.direct
    dcr = [r.compression_ratio for r in results]
    passed = bool(results) and not problems and not deploy and fired and \
        pm2 == "MOTIF_CANNOT_EXPRESS_REPEATED"
    return GateCheck("G8.7", title, passed, (
        f"tournaments {len(results)}{' (VACUOUS)' if not results else ''}; (a)+(b) entrant/"
        f"reselection problems {len(problems)}{' ' + str(problems[:2]) if problems else ''}; "
        f"(c) refusals in tournaments {dict(refusals)}, PM2 compiled directly -> MOTIF refusal "
        f"{pm2}; (d) deployable {sum(r.deployable for r in results)}/{len(results)}, "
        f"selected {dict(selected)}, deployability violations {len(deploy)}; (e) DCR {dcr}; "
        f"direct model (LOGISTIC on TRAIN + HOLDOUT labels, F8) REPLICATION recall "
        f"{None if direct is None else direct.replication_recall} FPR "
        f"{None if direct is None else direct.replication_false_positive_rate} "
        f"wu/event {None if direct is None else direct.work_units_per_event}"))


# --- G8.8 -------------------------------------------------------------------------------------


def _lineage_problems(run: DiscoveryRunReport, package: DiscoveryPackageV1) -> list[str]:
    lineage, ledger = run.lineage, run.ledger
    if lineage is None or ledger is None:
        return ["run carries no lineage/ledger"]
    nodes = [lineage.node(n) for n in package.evidence_lineage]
    if any(n is None for n in nodes):
        return ["a lineage id is not in the DAG"]
    kinds = [n.kind for n in nodes if n is not None]
    problems = []
    if not kinds or kinds[0] is not NodeKind.RESIDUAL:
        problems.append("lineage does not start at a RESIDUAL")
    missing = {NodeKind.HYPOTHESIS, NodeKind.DISCOVERY, NodeKind.FORGE_CANDIDATE} - set(kinds)
    if missing:
        problems.append(f"lineage misses {sorted(k.value for k in missing)}")
    regs = [r.registration_id for r in package.falsification_results if r.registration_id]
    problems += [f"{r} is not a PREREGISTER" for r in regs if ledger.preregistration(r) is None]
    if not package.failure_conditions:
        problems.append("no failure conditions")
    if any(not d.startswith("sha256:") for d in package.evidence_digests):
        problems.append("a non-sha256 evidence digest")
    return problems + [f"verify_package: {p}" for p in verify_package(package)]


def _flip(value: Any) -> tuple[Any, bool]:
    """One changed byte in the first string or int of a nested artifact copy."""
    if isinstance(value, dict):
        for key in sorted(value):
            flipped, done = _flip(value[key])
            if done:
                return {**value, key: flipped}, True
    if isinstance(value, list):
        for index, item in enumerate(value):
            flipped, done = _flip(item)
            if done:
                return [*value[:index], flipped, *value[index + 1:]], True
    if isinstance(value, bool):
        return value, False
    if isinstance(value, int):
        return value ^ 1, True
    if isinstance(value, str) and value:
        return chr(ord(value[0]) ^ 1) + value[1:], True
    return value, False


def _tamper(run: DiscoveryRunReport, package: DiscoveryPackageV1) -> tuple[bool, bool, bool]:
    """(signature round-trips, artifact flip detected, edited ledger entry detected)."""
    key, payload = run_key(0), package.to_dict()
    signature = sign_record(payload, key=key)
    round_trip = verify_record(payload, signature, key=key)
    artifact = payload.get("compiled_artifact")
    detected = False
    if artifact is not None:
        flipped, done = _flip(copy.deepcopy(artifact))
        tampered = {**payload, "compiled_artifact": flipped}
        try:
            loaded_ok = verify_package(DiscoveryPackageV1.from_dict(tampered)) == ()
        except ContractError:
            loaded_ok = False
        detected = done and not verify_record(tampered, signature, key=key) and not loaded_ok
    entries = () if run.ledger is None else run.ledger.entries()
    ledger_detected = bool(entries) and all(
        replace(e, payload={**dict(e.payload), "tampered": True}).recomputed_digest()
        != e.entry_digest for e in entries[:1])
    return round_trip, detected, ledger_detected


def check_g8_8(ctx: Stage8GateContext) -> GateCheck:
    """Every DiscoveryPackage has complete lineage and failure conditions (spec §6 G8.8)."""
    title = "Every DiscoveryPackage has complete lineage and failure conditions"
    pairs = packages_of(ctx)
    problems = [f"{p.package_id}: {x}" for r, p in pairs for x in _lineage_problems(r, p)]
    tampers = [_tamper(r, p) for r, p in pairs]
    signed = sum(t[0] for t in tampers)
    artifact_caught = sum(t[1] for t in tampers)
    with_artifact = sum(p.compiled_artifact is not None for _, p in pairs)
    ledger_caught = sum(t[2] for t in tampers)
    passed = (bool(pairs) and not problems and signed == len(pairs)
              and artifact_caught == with_artifact and with_artifact > 0
              and ledger_caught == len(pairs))
    return GateCheck("G8.8", title, passed, (
        f"packages {len(pairs)}{' (VACUOUS)' if not pairs else ''}; lineage/ledger/verify "
        f"problems {len(problems)}{' ' + str(problems[:3]) if problems else ''}; "
        f"sign_record/verify_record round-trips {signed}/{len(pairs)} (HMAC: local integrity, "
        f"not identity, ADR-0064 precedent); one flipped artifact byte detected "
        f"{artifact_caught}/{with_artifact} packages with an artifact; one edited ledger entry "
        f"detected {ledger_caught}/{len(pairs)}"))


# --- G8.9 -------------------------------------------------------------------------------------


def _adapter_refuses_non_packages(pairs: Sequence[tuple[DiscoveryRunReport, DiscoveryPackageV1]]
                                  ) -> tuple[int, int]:
    """Rule 16's in-gate half: the one door refuses anything but a verified package."""
    adapter = Stage6Adapter(gateway=lab_gateway(provenance=ProvenanceLedger()),
                            ledger=TheoryLedger(),
                            epoch=EpochModel(identity=SystemIdentity()).current,
                            run_id="gate-refusal", host_id="lab-gate", synthetic=True)
    foreign: list[Any] = [p.to_dict() for _, p in pairs[:1]] + [p.mechanism for _, p in pairs[:1]]
    refused = 0
    for item in foreign:
        try:
            adapter.hand_over(item, evidence={}, sequence=0)
        except ContractError:
            refused += 1
    return refused, len(foreign)


def _capsule_problems(ctx: Stage8GateContext, run: DiscoveryRunReport) -> tuple[list[str], int]:
    ids = [c for r in run.receipts for c in r.capsule_ids]
    problems = []
    delta = ctx.offered[1] - ctx.offered[0]
    if not run.adapter_created == run.adapter_admitted == delta == len(ids):
        problems.append(f"created {run.adapter_created} admitted {run.adapter_admitted} "
                        f"offered +{delta} capsules {len(ids)}")
    kinds = {k for r in run.receipts for k in r.capsule_kinds}
    if ids and kinds != {"TRANSITION_EPISODE"}:
        problems.append(f"capsule kinds {sorted(kinds)}")
    if sum(r.simulated_records for r in run.receipts) != len(ids):
        problems.append("a capsule without SIMULATED_RECORD")
    records = () if ctx.provenance is None else ctx.provenance.records_for(ids)
    if len(records) != len(ids):
        problems.append(f"Stage 6 trust records {len(records)} for {len(ids)} capsules")
    if {r.source_class.value for r in records} - {"DERIVED_INFERENCE"}:
        problems.append("a capsule not DERIVED_INFERENCE")
    if {r.label_origin.value for r in records} - {"INFERENCE"}:
        problems.append("a label not by INFERENCE")
    if len({r.independence_group for r in records}) > 1:
        problems.append("more than one independence group")
    return problems, len(ids)


def check_g8_9(ctx: Stage8GateContext) -> GateCheck:
    """All endpoint adoption passes Stage 6 (spec §6 G8.9)."""
    title = "All endpoint adoption passes Stage 6"
    rules = {r: rule_offenders(r) for r in (5, 6, 7, 10, 11)}
    run = ctx.main
    if run is None:
        return GateCheck("G8.9", title, False, "the PLANTED run did not complete")
    refused, attempted = _adapter_refuses_non_packages(packages_of(ctx))
    problems, capsules = _capsule_problems(ctx, run)
    buckets = Counter(b for r in run.receipts for b in r.stage6_buckets)
    scores = sorted({s for r in run.receipts for s in r.predicted_provenance_scores})
    trusted = sum(r.trusted_candidates for r in run.receipts)
    passed = (not any(rules.values()) and capsules > 0 and not problems
              and refused == attempted > 0)
    return GateCheck("G8.9", title, passed, (
        f"(a) boundary rules 5, 6, 7, 10, 11 offenders {sum(len(o) for o in rules.values())}; "
        f"rule 16 in-gate: the adapter refused {refused}/{attempted} non-package objects (the "
        f"gateway/Stage 5 type refusals are tests/test_stage8_boundary.py::test_rule16_*: "
        f"calling admit or importing Stage 5 here would itself break rules 3 and 7); "
        f"(b) capsules {capsules}{' (VACUOUS)' if not capsules else ''}, problems "
        f"{problems or 'none'}; (c) Stage 6 buckets verbatim {dict(buckets)}, predicted "
        f"provenance scores {scores}. Realised adoption (TRUSTED_CANDIDATE) = {trusted}: B8-1, "
        f"ADR-0076 — met as a path only"))
