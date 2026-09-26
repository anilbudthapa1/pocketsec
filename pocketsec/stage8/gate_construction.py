"""The Stage 8 gate's construction criteria: G8.1, G8.2, G8.3 and G8.10.

Each of these asks whether a property holds *by construction* — a malformed hypothesis cannot
be built, free text cannot become state, an emulation cannot be authorised, no module can
reach Stage 5 — so each check tries to break the property with a real object and reads the
refusal, then audits the real discovery runs the gate built for the same property. Nothing is
decided by reading a document. A check that inspects zero objects is VACUOUS and FAILS.
"""

from __future__ import annotations

import ast
import copy
from collections.abc import Callable, Sequence
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError, digest_of_bytes
from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS
from pocketsec.stage0.gate import GateCheck
from pocketsec.stage8.challenger.adversarial import ChallengeKind
from pocketsec.stage8.constitution.discovery import (
    OFFENSIVE_TOKENS,
    SAFE_EXPERIMENT_CLASSES,
    verify_discovery_constitution,
)
from pocketsec.stage8.episode import Split
from pocketsec.stage8.forge.package import DiscoveryPackageV1, RepresentationKind
from pocketsec.stage8.gate_boundary import STAGE8_ROOT, rule_offenders
from pocketsec.stage8.genome.grammar import parse_mechanism
from pocketsec.stage8.genome.hypothesis import (
    DEFAULT_FALSIFIERS,
    MANDATORY_FALSIFIERS,
    Direction,
    ExperimentClass,
    Falsifier,
    FalsifierKind,
    GeneratorKind,
    GenomeProvenance,
    HypothesisGenome,
    ObservationScope,
    ResidualType,
    genome_for,
)
from pocketsec.stage8.governor.budget import ResearchBudget, ResearchGovernor
from pocketsec.stage8.laboratory.counterfactual import TransformKind
from pocketsec.stage8.ledger.theory import (
    LedgerEventKind,
    PreRegistration,
    TheoryLedger,
)
from pocketsec.stage8.prometheus.generators import (
    INJECTION_SUITE,
    ExternalProposalGenerator,
    GenerationContext,
)
from pocketsec.stage8.residual.observatory import (
    PhiOracleExplainer,
    ResidualObservatory,
    cluster_members,
)
from pocketsec.stage8.sandbox.boundary import LabClearance, ResearchSandbox, SandboxOutcome
from pocketsec.stage8.sandbox.integrity import HoldoutVault

if TYPE_CHECKING:
    from pocketsec.stage8.gate import Stage8GateContext

__all__ = [
    "DECLARED_STRING_FIELDS",
    "check_g8_1",
    "check_g8_2",
    "check_g8_3",
    "check_g8_10",
    "control_genome",
    "free_text_fields",
    "malformed_genomes",
]

PM1 = "PRECEDES(EXECUTE+TEMP_LOCATION,CONNECT+EXTERNAL_ENDPOINT)"
_SCOPE = ObservationScope((), frozenset({ResidualType.OBSERVATION}), ())
_DIGEST = "sha256:" + "0" * 64
#: G8.2(c): the modules whose dataclasses ARE the canonical scientific state.
STATE_MODULES = ("genome/hypothesis.py", "genome/grammar.py", "ledger/theory.py",
                 "ledger/negative_results.py", "forge/package.py", "episode.py")
#: Every string-typed dataclass field of those modules, with what it holds. A field not on
#: this list is an undeclared free-text field and fails G8.2(c). "code" = fixed vocabulary,
#: validated at construction; "rendering" = FailureCondition.detail, a bounded fixed-vocabulary
#: rendering the spec permits (§4 D8.16); "payload" = the ledger's typed event payload.
DECLARED_STRING_FIELDS: dict[str, str] = {
    "ObservationScope.residual_cluster_ids": "id", "ObservationScope.episode_ids": "id",
    "GenomeProvenance.source_digest": "digest", "HypothesisGenome.hypothesis_id": "id",
    "HypothesisGenome.competing_explanations": "id", "HypothesisGenome.parent_hypotheses": "id",
    "HypothesisGenome.schema_version": "version", "PreRegistration.registration_id": "id",
    "PreRegistration.hypothesis_id": "id", "PreRegistration.genome_digest": "digest",
    "PreRegistration.split_digest": "digest", "TestOutcome.registration_id": "id",
    "TestOutcome.hypothesis_id": "id", "TestOutcome.reasons": "code",
    "LedgerEntry.hypothesis_id": "id", "LedgerEntry.payload": "payload",
    "LedgerEntry.previous_digest": "digest", "LedgerEntry.entry_digest": "digest",
    "TheoryRecord.experiments": "id", "TheoryRecord.failed_predictions": "code",
    "TheoryRecord.counterexamples": "id", "TheoryRecord.revisions": "id",
    "NegativeResult.mechanism_digest": "digest", "NegativeResult.hypothesis_id": "id",
    "NegativeResult.reason": "code", "NegativeResult.counterexample_ids": "id",
    "FalsificationRecord.registration_id": "id", "FailureCondition.context": "code",
    "FailureCondition.detail": "rendering", "ReproducibilityRecord.reasons": "code",
    "RepresentationMeasurement.refusal": "code", "TournamentResult.tournament_id": "id",
    "TournamentResult.hypothesis_id": "id", "TournamentResult.reasons": "code",
    "RobustnessProfile.recall_retained": "code", "RobustnessProfile.doppelganger_matched_share":
    "code", "DiscoveryPackageV1.package_id": "id", "DiscoveryPackageV1.hypothesis_id": "id",
    "DiscoveryPackageV1.required_features": "code", "DiscoveryPackageV1.compiled_artifact":
    "payload", "DiscoveryPackageV1.evidence_lineage": "id", "DiscoveryPackageV1.evidence_digests":
    "digest", "DiscoveryPackageV1.evidence_episode_ids": "id",
    "DiscoveryPackageV1.known_technique_mappings": "code", "DiscoveryPackageV1.artifact_hashes":
    "digest", "DiscoveryPackageV1.schema_version": "version", "EpisodeContext.host_id": "id",
    "EpisodeContext.family": "code", "EpisodeContext.corpus": "version", "Episode.episode_id": "id",
}
_PRODUCTION_WORDS = ("PRODUCTION", "INTERVEN", "LIVE", "RESPONSE", "CONTAIN", "ENFORCE")


def control_genome(dsl: str, *, falsifiers: tuple[Falsifier, ...] = DEFAULT_FALSIFIERS
            ) -> HypothesisGenome:
    provenance = GenomeProvenance(GeneratorKind.SYMBOLIC_ENUMERATOR, _DIGEST, False, 0)
    return genome_for(parse_mechanism(dsl), direction=Direction.MALICIOUS, scope=_SCOPE,
                      provenance=provenance, falsifiers=falsifiers)


def _without(kind: FalsifierKind) -> Callable[[], tuple[Falsifier, ...]]:
    return lambda: tuple(f for f in DEFAULT_FALSIFIERS if f.kind is not kind)


def _replacing(kind: FalsifierKind, **changes: Any) -> Callable[[], tuple[Falsifier, ...]]:
    return lambda: tuple(replace(f, **changes) if f.kind is kind else f
                         for f in DEFAULT_FALSIFIERS)


def malformed_genomes() -> tuple[tuple[str, Callable[[], tuple[Falsifier, ...]]], ...]:
    """G8.1(a): six falsifier sets a genome must refuse (spec §6, in its order)."""
    missing = tuple((f"missing {k.value}", _without(k))
                    for k in sorted(MANDATORY_FALSIFIERS, key=lambda k: k.value))
    return (("no falsifiers", lambda: ()), *missing,
            ("threshold 1.5", _replacing(FalsifierKind.HOLDOUT_RECALL, threshold=1.5)),
            ("alpha 0", _replacing(FalsifierKind.HOLDOUT_ENRICHMENT, threshold=0.0, alpha=0.0)))


def _refused(build: Callable[[], object]) -> bool:
    try:
        build()
    except ContractError:
        return True
    return False


def _edit_after_test(ctx: Stage8GateContext) -> tuple[list[str], int]:
    """G8.1(c): a real vault test, then three edits that must each be refused."""
    planted = ctx.planted
    if planted is None:
        return ["no PLANTED corpus"], 0
    genome = control_genome(PM1)
    ledger = TheoryLedger()
    ledger.record_birth(genome)
    vault = HoldoutVault(planted.episodes(Split.HOLDOUT), split=Split.HOLDOUT, ledger=ledger,
                         governor=ResearchGovernor(ResearchBudget()))
    prediction = next(p for p in genome.predicted_observations if p.split is Split.HOLDOUT)
    registration = PreRegistration("", genome.hypothesis_id, genome.digest(), Split.HOLDOUT,
                                   vault.split_digest(), 1, 0.05, prediction)
    ledger.preregister(registration)
    (outcome,) = vault.evaluate(vault.seal_batch([registration]))
    edits = {
        "second PREREGISTER": lambda: ledger.preregister(registration),
        "second TEST_RESULT": lambda: ledger.record_result(outcome),
        "re-registration of a tested id": lambda: ledger.preregister(
            replace(registration, registration_id="", batch_size=2)),
    }
    accepted = [name for name, edit in edits.items() if not _refused(edit)]
    return accepted, len(edits) - len(accepted)


def _born_and_tested(ctx: Stage8GateContext) -> tuple[list[str], int, int, int]:
    """G8.1(b): over every run ledger the gate holds."""
    problems: list[str] = []
    born = registered = tested = 0
    for report in ctx.reports():
        ledger = report.ledger
        if ledger is None:
            problems.append("a run report carries no ledger")
            continue
        problems += [f"chain: {p}" for p in ledger.verify_chain()]
        for hid in ledger.hypothesis_ids():
            born += 1
            kinds = {f.kind for f in ledger.genome(hid).falsification_tests}
            if not kinds >= MANDATORY_FALSIFIERS:
                problems.append(f"{hid} lacks a mandatory falsifier")
        results = {e.hypothesis_id for e in ledger.entries()
                   if e.kind is LedgerEventKind.TEST_RESULT}
        registered += len({e.hypothesis_id for e in ledger.entries()
                           if e.kind is LedgerEventKind.PREREGISTER})
        tested += len(results)
        problems += [f"{hid} tested before registration" for hid in sorted(results)
                     if not ledger.registered_before_tested(hid)]
    return problems, born, registered, tested


def check_g8_1(ctx: Stage8GateContext) -> GateCheck:
    """Every hypothesis has explicit falsification conditions (spec §6 G8.1)."""
    title = "Every hypothesis has explicit falsification conditions"
    accepted = [name for name, build in malformed_genomes()
                if not _refused(lambda b=build: control_genome(PM1, falsifiers=b()))]
    problems, born, registered, tested = _born_and_tested(ctx)
    edits, refused_edits = _edit_after_test(ctx)
    main, probe = ctx.main, ctx.trap_probe
    trap = None if main is None else main.trap
    trap_ok = trap is not None and trap.generated and trap.registered and trap.refuted
    passed = (not accepted and not problems and not edits and registered >= 1
              and trap_ok and born > 0)
    probe_text = ("not run" if probe is None else
                  f"registered={probe.registered} refuted={probe.refuted} at {probe.refuted_at}")
    trap_text = ("no main run" if trap is None else
                 f"generated={trap.generated} registered={trap.registered} "
                 f"refuted={trap.refuted} at {trap.refuted_at}")
    return GateCheck("G8.1", title, passed, (
        f"(a) malformed genomes refused {6 - len(accepted)}/6{_list(accepted, 'accepted')}; "
        f"(b) {born} genomes born over {len(ctx.reports())} runs, {registered} registered, "
        f"{tested} tested, problems {len(problems)}{_list(problems[:3], 'e.g.')}; "
        f"(c) edits after test refused {refused_edits}/3{_list(edits, 'ACCEPTED')}; "
        f"(d) trap in run_discovery: {trap_text}. The spec requires generated AND registered "
        f"AND refuted in the loop; a pre-holdout screen refuting it before registration does "
        f"NOT meet the literal clause (reported, not re-worded). Isolated vault probe "
        f"(probe_trap_at_holdout): {probe_text}. F2 (trap survives HOLDOUT) "
        f"{'did not fire' if probe is not None and probe.refuted else 'UNDECIDED'}"))


def _list(items: Sequence[str], label: str) -> str:
    return f" ({label}: {', '.join(items)})" if items else ""


# --- G8.2 -------------------------------------------------------------------------------------


def _injection_context(ctx: Stage8GateContext) -> GenerationContext | None:
    planted = ctx.planted
    if planted is None:
        return None
    train = planted.episodes(Split.TRAIN)
    governor = ResearchGovernor(ResearchBudget())
    field = ResidualObservatory([PhiOracleExplainer.fit(train)], governor=governor).observe(train)
    if not field.clusters:
        return None
    cluster = field.clusters[0]
    return GenerationContext(train=train, cluster=cluster,
                             residual_episodes=cluster_members(cluster, field, train),
                             known=(), seed=0)


def _parses(text: str) -> bool:
    return not _refused(lambda: parse_mechanism(text))


def _injection(ctx: Stage8GateContext) -> tuple[bool, str]:
    context = _injection_context(ctx)
    if context is None:
        return False, "(a) VACUOUS: no residual cluster to propose against"
    generator = ExternalProposalGenerator(INJECTION_SUITE)
    out = [m for m, _ in generator.propose(context, ResearchGovernor(ResearchBudget()))]
    valid = [t for t in INJECTION_SUITE if _parses(t)]
    exact = out == [parse_mechanism(t) for t in valid]
    digests = all(generator.source_digest(context, parse_mechanism(t))
                  == digest_of_bytes(t.encode("ascii")) for t in valid)
    ok = (len(INJECTION_SUITE) == 24 and len(valid) == 8 and generator.refusals() == 16
          and exact and digests)
    return ok, (f"(a) injection suite {len(INJECTION_SUITE)} texts: {len(out)} parsed "
                f"(exactly their mechanisms: {exact}), {generator.refusals()} refused, "
                f"source_digest = sha256(text): {digests}")


def _canary(ctx: Stage8GateContext) -> tuple[bool, str]:
    run = ctx.injected
    if run is None or run.ledger is None:
        return False, "(b) VACUOUS: the injection run did not complete"
    blobs = [repr(dict(e.payload)) for e in run.ledger.entries()]
    blobs += [repr(run.ledger.genome(h).to_dict()) for h in run.ledger.hypothesis_ids()]
    blobs += [repr(p.to_dict()) for p in run.packages]
    # The empty text of §6.2 is a substring of everything, so it cannot be a canary.
    canaries = [t for t in INJECTION_SUITE if t]
    hits = sorted({t for t in canaries if any(t in blob for blob in blobs)})
    external = [h for h in run.ledger.hypothesis_ids()
                if run.ledger.genome(h).provenance.generator is GeneratorKind.EXTERNAL_PROPOSAL]
    return not hits and bool(blobs), (
        f"(b) canary scan over {len(blobs)} ledger/genome/package payloads of the injection "
        f"run: {len(hits)} of {len(canaries)} non-empty raw proposal strings found; "
        f"{len(external)} external-proposal "
        f"genomes born, each carrying only a sha256 source digest")


def free_text_fields() -> list[str]:
    """G8.2(c): string-typed dataclass fields of the state modules not on the declared list."""
    found: list[str] = []
    for relative in STATE_MODULES:
        tree = ast.parse((STAGE8_ROOT / relative).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for statement in node.body:
                if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
                    key = f"{node.name}.{statement.target.id}"
                    if "str" in ast.unparse(statement.annotation) and \
                            key not in DECLARED_STRING_FIELDS:
                        found.append(f"{relative}:{key}")
    return found


def _render_is_not_state(ctx: Stage8GateContext) -> tuple[bool, str]:
    first, second = control_genome(PM1), control_genome(PM1)
    rendered = first.render()
    same = first.hypothesis_id == second.hypothesis_id == control_genome(PM1).hypothesis_id
    round_trip = HypothesisGenome.from_dict(first.to_dict()) == first
    absent = rendered not in repr(first.to_dict())
    return same and round_trip and absent, (
        f"(d) equal content -> equal id: {same}; render() absent from the stored form: "
        f"{absent}; from_dict(to_dict()) round-trips: {round_trip}")


_TERMINAL = frozenset({"SURVIVED", "REPRODUCED", "NOT_REPRODUCED", "INSUFFICIENT_EVIDENCE"})


def _f14(ctx: Stage8GateContext) -> str:
    """Spec §8 F14, REPORTED (it is a falsifier of the design, not a clause of G8.2): does the
    injection suite change any SURVIVED/REPRODUCED outcome of a theory it did not propose?"""
    base, injected = ctx.main, ctx.injected
    if base is None or injected is None or injected.ledger is None:
        return "F14 UNMEASURED (a run is missing)"
    ledger = injected.ledger
    external = {ledger.genome(h).proposed_mechanism.to_dsl() for h in ledger.hypothesis_ids()
                if ledger.genome(h).provenance.generator is GeneratorKind.EXTERNAL_PROPOSAL}

    def terminal(outcomes: Sequence[tuple[str, str]]) -> set[tuple[str, str]]:
        return {o for o in outcomes if o[1] in _TERMINAL and o[0].split(":", 1)[1] not in external}

    lost = terminal(base.outcomes) - terminal(injected.outcomes)
    gained = terminal(injected.outcomes) - terminal(base.outcomes)
    fired = "FIRED" if lost or gained else "did not fire"
    return (f"F14 {fired}: with the suite, {len(lost)} held-out outcomes of non-injected theories "
            f"disappeared and {len(gained)} appeared (REPRODUCED {len(base.reproduced)} -> "
            f"{len(injected.reproduced)}; planted families recovered "
            f"{sum(ok for _, ok in base.planted_recovered)} -> "
            f"{sum(ok for _, ok in injected.planted_recovered)}): injected theories displace "
            f"others in the bounded population and registration batch")


def check_g8_2(ctx: Stage8GateContext) -> GateCheck:
    """Free-form LLM text is never the canonical scientific state (spec §6 G8.2)."""
    title = "Free-form LLM text is never the canonical scientific state"
    parts = [_injection(ctx), _canary(ctx)]
    undeclared = free_text_fields()
    parts.append((not undeclared, f"(c) undeclared string fields in the state modules: "
                  f"{len(undeclared)}{_list(undeclared, 'found')} "
                  f"(declared: {len(DECLARED_STRING_FIELDS)} ids/digests/codes)"))
    parts.append(_render_is_not_state(ctx))
    return GateCheck("G8.2", title, all(ok for ok, _ in parts),
                     "; ".join(text for _, text in parts) + f". Reported beside the criterion: "
                     f"{_f14(ctx)}. No LLM is built (ADR-0074).")


# --- G8.3 -------------------------------------------------------------------------------------


def _clearance(scope: str, *, expires: int, cls: ExperimentClass) -> LabClearance:
    return LabClearance("clr-gate", cls, scope, expires, "lab-gate")


def _sandbox_refusals() -> tuple[list[str], int, int]:
    sandbox, scope = ResearchSandbox(), "sha256:" + "a" * 64
    other, emulation = "sha256:" + "b" * 64, ExperimentClass.ISOLATED_EMULATION
    cases = (
        (None, 1, SandboxOutcome.REFUSED_NO_CLEARANCE),
        (_clearance(scope, expires=1, cls=emulation), 5, SandboxOutcome.REFUSED_EXPIRED),
        (_clearance(other, expires=100, cls=emulation), 2, SandboxOutcome.REFUSED_SCOPE),
        (_clearance(scope, expires=100, cls=emulation), 3, SandboxOutcome.REFUSED_NO_EMULATOR),
    )
    wrong = []
    for clearance, sequence, expected in cases:
        decision = sandbox.decide(emulation, clearance=clearance, scope_digest=scope,
                                  sequence=sequence)
        if decision.outcome is not expected:
            wrong.append(f"{expected.value}->{decision.outcome.value}")
    refusals = sum(1 for d in sandbox.audit() if not d.allowed)
    return wrong, refusals, len(sandbox.audit())


def check_g8_3(ctx: Stage8GateContext) -> GateCheck:
    """All active emulation is isolated and authorised (spec §6 G8.3)."""
    title = "All active emulation is isolated and authorised"
    members = set(ExperimentClass)
    vocabulary_ok = (members == set(SAFE_EXPERIMENT_CLASSES) | {ExperimentClass.ISOLATED_EMULATION}
                     and not [m for m in members
                              if any(w in m.value for w in _PRODUCTION_WORDS)])
    wrong, refusals, audited = _sandbox_refusals()
    records = [r for report in ctx.reports() for o in report.oracle for r in o.experiments]
    unsafe = [r.design.design_id for r in records
              if not r.sandbox.allowed or r.design.experiment_class not in SAFE_EXPERIMENT_CLASSES]
    execution = rule_offenders(8)
    passed = (vocabulary_ok and not wrong and refusals >= 4 and audited == 4 and records
              and not unsafe and not execution)
    return GateCheck("G8.3", title, bool(passed), (
        f"(a) ExperimentClass = the 6 safe classes + ISOLATED_EMULATION, no production-"
        f"intervention member: {vocabulary_ok}; (b) emulation refusals {refusals} "
        f"(no clearance, expired, wrong scope, valid clearance -> REFUSED_NO_EMULATOR), "
        f"wrong outcomes {len(wrong)}{_list(wrong, 'got')}, audited {audited}/4; "
        f"(c) ORACLE experiment records in the gate's runs: {len(records)}, not ALLOWED-and-safe "
        f"{len(unsafe)}{'' if records else ' (VACUOUS)'}; (d) boundary rule 8 offenders "
        f"{len(execution)}. There is no emulator (ADR-0075): isolation of a real emulation is "
        f"UNMEASURED; this criterion holds by construction only"))


# --- G8.10 ------------------------------------------------------------------------------------


def _inject(payload: Any, path: tuple[Any, ...], key: str) -> Any:
    tampered = copy.deepcopy(payload)
    node = tampered
    for step in path:
        node = node[step]
    node[key] = 1
    return tampered


_PACKAGE_DEPTHS: tuple[tuple[Any, ...], ...] = (
    (), ("detector_candidates",), ("detector_candidates", "entrants", 0), ("reproducibility",),
    ("resource_profile",), ("falsification_results", 0))
_GENOME_DEPTHS: tuple[tuple[Any, ...], ...] = ((), ("provenance",), ("observation_scope",))


def _authority_words(package: DiscoveryPackageV1 | None, genome: HypothesisGenome
                     ) -> tuple[int, int]:
    """(refusals, attempts) over the 12 words at every probed depth of both from_dicts."""
    refused = attempts = 0
    targets: list[tuple[Callable[[Any], object], Any, tuple[tuple[Any, ...], ...]]] = [
        (HypothesisGenome.from_dict, genome.to_dict(), _GENOME_DEPTHS)]
    if package is not None:
        targets.append((DiscoveryPackageV1.from_dict, package.to_dict(), _PACKAGE_DEPTHS))
    for loader, payload, depths in targets:
        for word in sorted(FORBIDDEN_AUTHORITY_FIELDS):
            for path in depths:
                attempts += 1
                refused += _refused(lambda f=loader, d=payload, p=path, w=word:
                                    f(_inject(d, p, w)))
    return refused, attempts


def check_g8_10(ctx: Stage8GateContext) -> GateCheck:
    """Stage 8 does not create a new direct path to Stage 5 authority (spec §6 G8.10)."""
    title = "Stage 8 does not create a new direct path to Stage 5 authority"
    rules = {r: rule_offenders(r) for r in (3, 8, 9, 12, 13)}
    constitution = verify_discovery_constitution()
    main = ctx.main
    package = main.packages[0] if main is not None and main.packages else None
    refused, attempts = _authority_words(package, control_genome(PM1))
    vocabularies = (RepresentationKind, ExperimentClass, ChallengeKind, TransformKind,
                    GeneratorKind, FalsifierKind)
    offensive = [m.value for v in vocabularies for m in v
                 if OFFENSIVE_TOKENS.search(m.value) or OFFENSIVE_TOKENS.search(m.name)]
    passed = (not any(rules.values()) and not constitution and refused == attempts
              and package is not None and not offensive)
    offenders = "; ".join(f"rule {r}: {o[:2]}" for r, o in rules.items() if o)
    return GateCheck("G8.10", title, passed, (
        f"boundary rules 3, 8, 9, 12, 13 offenders "
        f"{sum(len(o) for o in rules.values())}{' (' + offenders + ')' if offenders else ''}; "
        f"verify_discovery_constitution() problems {len(constitution)}; authority words refused "
        f"{refused}/{attempts} at every probed depth of HypothesisGenome.from_dict and "
        f"DiscoveryPackageV1.from_dict{'' if package else ' (no package: package half VACUOUS)'}; "
        f"closed-vocabulary members matching OFFENSIVE_TOKENS {len(offensive)}. No Stage 8 "
        f"module imports Stage 5; the Stage 5 entry-guard refusal of a package is tested in "
        f"tests/test_stage8_boundary.py (the gate may not import Stage 5)"))
