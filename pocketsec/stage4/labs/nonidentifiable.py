"""Constructed non-identifiable world pairs (architecture §39, last two rows).

A "non-identifiable" case that one observation separates is not a non-identifiability
test, it is a bug dressed as a corpus. So the construction here is **asserted, not
intended**:

* the two cases of a pair carry *byte-identical* Stage 1 semantic keys under every
  ``SensorPath`` — same observations, differently explained;
* their two worlds have *equal* expected and forbidden evidence sets over the whole
  closed signal vocabulary **and** over every ``SensorAction``'s reachable signal set,
  so ``simulate_sensor_value`` returns exactly ``0.0`` for all six actions;
* their consequences deliberately *differ*, so that "the system must not pick the more
  alarming world" is a test with something to fail on rather than a tautology.

``build_resolvable_after_one_observation`` is the contrast case and it is what stops the
above from being satisfied by a broken planner: those cases are separable by exactly one
targeted observation, must come back ``INSUFFICIENT_EVIDENCE`` rather than
``UNIDENTIFIABLE``, and must reach ``IDENTIFIED`` once that one observation is granted.

Identity handling matters here more than anywhere. The two cases of a pair share their
*semantics* and must not share their *identities*: Stage 1 carries lineage state across
scenarios on a shared pipeline, and a corpus that reuses process identities between
sessions silently erases its own signal (`MEMORY.md` — it retracted a published result).
Each case therefore gets its own identity namespace via
``incident_corpus.identity_namespace``, which is safe precisely because Stage 1's
``semantic_key()`` excludes pids.
"""

from __future__ import annotations

import hashlib
import random
from collections.abc import Iterable, Sequence
from dataclasses import replace
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.labs.corpus import Behaviour, Scenario
from pocketsec.stage1.observation.policy import MANDATORY_SIGNALS
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage1.state.security_state import (
    Privilege,
    SecurityStateV1,
    Trust,
)
from pocketsec.stage1.state.potential import phi
from pocketsec.stage1.telemetry.raw_event_v1 import SensorPath
from pocketsec.stage4.labs.incident_corpus import (
    GroundTruthWorld,
    IncidentCase,
    identity_namespace,
    reidentify,
)
from pocketsec.stage4.sensing.active_plan import ACTION_SIGNALS, SensorAction
from pocketsec.stage4.visibility.model import VisibilityModel, VisibilityObservation, fit_visibility_model
from pocketsec.stage4.worlds.field import CausalBeliefField
from pocketsec.stage4.worlds.world import (
    BeliefGeometry,
    LatentSecurityState,
    SecurityWorldV1,
    WorldSupport,
    WorldSupportState,
)

__all__ = [
    "CONFIRMED_SUPPORT_LOG_ODDS",
    "CONTRADICTED_SUPPORT_LOG_ODDS",
    "CORPUS_VISIBILITY_OCCURRENCES",
    "NONIDENTIFIABLE_EXPECTED",
    "NONIDENTIFIABLE_FORBIDDEN",
    "NONIDENTIFIABLE_VERSION",
    "RESOLVING_SIGNAL",
    "SIGNAL_VOCABULARY",
    "apply_granted_observation",
    "build_corpus_visibility_model",
    "build_nonidentifiable_pairs",
    "build_resolvable_after_one_observation",
    "field_for_nonidentifiable_pair",
    "field_for_resolvable_case",
    "reachable_signal_union",
    "semantic_key_digest",
]

NONIDENTIFIABLE_VERSION: str = "stage4-nonidentifiable-v0.1.0"

#: The closed signal vocabulary these corpora are defined over. Equal to the union of
#: every ``SensorAction``'s reachable set, asserted in ``reachable_signal_union``.
SIGNAL_VOCABULARY: frozenset[str] = frozenset(
    {
        "authentication",
        "privilege_change",
        "credential_access",
        "persistence_write",
        "module_load",
        "boundary_crossing",
        "file_staging",
        "session_teardown",
    }
)

#: Both worlds of a non-identifiable pair predict exactly these, and forbid exactly
#: ``NONIDENTIFIABLE_FORBIDDEN``. Equality over the whole vocabulary is what makes the
#: pair non-identifiable; the two sets are disjoint because a world that both expects
#: and forbids a signal is refused by ``SecurityWorldV1``.
NONIDENTIFIABLE_EXPECTED: frozenset[str] = frozenset(
    {"authentication", "privilege_change", "credential_access"}
)
NONIDENTIFIABLE_FORBIDDEN: frozenset[str] = frozenset({"module_load", "boundary_crossing"})

#: The one signal that separates a resolvable case's two worlds. Chosen because it is
#: **not** in ``MANDATORY_SIGNALS``: a mandatory signal is always collected, so a case
#: that hinged on one would already be resolved and would test nothing about planning.
RESOLVING_SIGNAL: str = "file_staging"

#: Support a world is moved to when an observation confirms what it predicted, and when
#: an observation contradicts what it forbade. Log-odds, so the field's geometry stays
#: uniform. Declared parameters of the lab update, not measurements.
CONFIRMED_SUPPORT_LOG_ODDS: float = 1.0
CONTRADICTED_SUPPORT_LOG_ODDS: float = -6.0

#: Occurrence count used by the CONSTRUCTED visibility model below. This is a corpus
#: parameter, not a measurement of any sensor: see ``build_corpus_visibility_model``.
CORPUS_VISIBILITY_OCCURRENCES: int = 40


# --- the shared observation sequence ----------------------------------------

#: One privileged-maintenance-looking sequence. It is what BOTH worlds of a pair claim
#: to explain, which is the whole construction: an authenticated session that elevates
#: privilege and reads a credential-classified object is exactly as consistent with an
#: approved administrator as with a compromised session, and no endpoint signal in the
#: vocabulary tells them apart.
_SHARED_SEQUENCE: tuple[tuple[str, dict[str, str]], ...] = (
    ("authenticate", {"user": "ops"}),
    ("execve", {"path": "/usr/bin/sudo"}),
    ("setuid", {"user": "root"}),
    ("read", {"path": "/etc/shadow"}),
    ("read", {"path": "/var/lib/db/shard-1.dat"}),
    ("write", {"path": "/var/tmp/stage.bin"}),
)


def _scenario(name: str, *, label: int, rng: random.Random) -> Scenario:
    """Build the shared sequence with deterministic inter-event gaps.

    Gaps vary; operations and object classes do not. Timing is excluded from
    ``semantic_key()``, so varying it keeps the corpus from pinning every ``time_bucket``
    to one value without touching the semantics the pair must share.
    """
    behaviours: list[Behaviour] = []
    for index, (operation, fields) in enumerate(_SHARED_SEQUENCE):
        gap = 1_000_000_000 * rng.randint(3, 40)
        behaviours.append(
            Behaviour(
                operation,
                {**fields, "pid": str(index), "start_time": str(index), "_gap_ns": str(gap)},
            )
        )
    return Scenario(name=name, behaviours=tuple(behaviours), label=label)


# --- D4.18: the non-identifiable pairs --------------------------------------


def build_nonidentifiable_pairs(
    *, count: int, seed: int
) -> tuple[tuple[IncidentCase, IncidentCase], ...]:
    """Two worlds explaining IDENTICAL observations, with NO discriminating observable.

    Both cases of a pair carry the same behaviour semantics and different ground-truth
    world labels. The pair is deterministic under ``seed`` and every case gets a unique
    identity namespace.
    """
    if not isinstance(count, int) or count < 1:
        raise ContractError(f"build_nonidentifiable_pairs.count must be >= 1, got {count!r}")
    rng = random.Random(seed)
    pairs: list[tuple[IncidentCase, IncidentCase]] = []
    for ordinal in range(count):
        base = _scenario(f"nonident-{ordinal:04d}", label=0, rng=rng)
        benign = _case(
            incident_id=f"s4-nonident-{seed:04d}-{ordinal:04d}-a",
            scenario=reidentify(
                replace(base, name=f"{base.name}-a", label=0),
                namespace=identity_namespace("nonidentifiable", 2 * ordinal),
            ),
            world_label="approved_admin",
            mechanism_id="approved_administration",
            alternatives=("compromised_admin_session",),
            expected_state="UNIDENTIFIABLE",
        )
        malicious = _case(
            incident_id=f"s4-nonident-{seed:04d}-{ordinal:04d}-b",
            scenario=reidentify(
                replace(base, name=f"{base.name}-b", label=1),
                namespace=identity_namespace("nonidentifiable", 2 * ordinal + 1),
            ),
            world_label="compromised_session",
            mechanism_id="compromised_admin_session",
            alternatives=("approved_administration",),
            expected_state="UNIDENTIFIABLE",
        )
        pairs.append((benign, malicious))
    return tuple(pairs)


def build_resolvable_after_one_observation(*, count: int, seed: int) -> tuple[IncidentCase, ...]:
    """§39's last row: non-identifiable at low telemetry, identifiable after ONE observation.

    The truth is the *malicious* world here on purpose. A resolvable corpus whose answer
    was always the benign world would let a planner that never collects anything score
    perfectly, which is the failure mode this row exists to catch.
    """
    if not isinstance(count, int) or count < 1:
        raise ContractError(
            f"build_resolvable_after_one_observation.count must be >= 1, got {count!r}"
        )
    rng = random.Random(seed ^ 0x5EED)
    cases: list[IncidentCase] = []
    for ordinal in range(count):
        base = _scenario(f"resolvable-{ordinal:04d}", label=1, rng=rng)
        cases.append(
            _case(
                incident_id=f"s4-resolvable-{seed:04d}-{ordinal:04d}",
                scenario=reidentify(
                    base, namespace=identity_namespace("resolvable", ordinal)
                ),
                world_label="compromised_session",
                mechanism_id="compromised_admin_session",
                alternatives=("approved_administration",),
                expected_state="INSUFFICIENT_EVIDENCE",
                discriminating_signal=RESOLVING_SIGNAL,
            )
        )
    return tuple(cases)


def _case(
    *,
    incident_id: str,
    scenario: Scenario,
    world_label: str,
    mechanism_id: str,
    alternatives: tuple[str, ...],
    expected_state: str,
    discriminating_signal: str | None = None,
) -> IncidentCase:
    """Wrap a scenario as an ``IncidentCase``.

    ``discriminating_signal=None`` is the corpus declaring, on the record, that it built
    this case to be non-identifiable. The corpus knows; the reasoner must not be told.
    """
    truth = GroundTruthWorld(
        world_label=world_label,
        mechanism_id=mechanism_id,
        raises_dimensions=frozenset({"privilege", "trust"}),
        discriminating_signal=discriminating_signal,
    )
    return IncidentCase(
        incident_id=incident_id,
        scenario=scenario,
        truth=truth,
        material_alternatives=alternatives,
        expected_state=expected_state,
    )


# --- the assertion machinery ------------------------------------------------


def reachable_signal_union() -> frozenset[str]:
    """Union of every ``SensorAction``'s reachable signals.

    Compared against ``SIGNAL_VOCABULARY`` in the tests. If an action ever reaches a
    signal outside the vocabulary, "no action discriminates these worlds" would stop
    being a statement about the whole observable space.
    """
    union: set[str] = set()
    for signals in ACTION_SIGNALS.values():
        union.update(signals)
    return frozenset(union)


def _canonical_semantic_keys(pipeline: Stage1Pipeline, case: IncidentCase, sensor: SensorPath) -> str:
    result = pipeline.run_scenario(case.scenario, sensor=sensor)
    rows: list[str] = []
    for key in result.semantic_keys:
        parts: list[str] = []
        for element in key:
            if isinstance(element, frozenset):
                parts.append("{" + ",".join(sorted(str(x) for x in element)) + "}")
            else:
                parts.append(str(element))
        rows.append("|".join(parts))
    return "\n".join(rows)


def semantic_key_digest(case: IncidentCase, *, sensor: SensorPath) -> str:
    """``sha256:`` digest of the case's Stage 1 semantic keys under one sensor path.

    A **fresh** pipeline per call, deliberately. A shared pipeline carries lineage state
    across scenarios, so digesting two cases through one pipeline would compare the
    second case against the first case's accumulated privilege rather than against
    itself. Frozensets inside a semantic key are sorted before hashing because
    ``frozenset`` iteration order is not a stable byte sequence.
    """
    pipeline = Stage1Pipeline(host_id="stage4-nonidentifiable")
    payload = _canonical_semantic_keys(pipeline, case, sensor)
    return f"sha256:{hashlib.sha256(payload.encode('utf-8')).hexdigest()}"


def build_corpus_visibility_model(
    *,
    signals: Iterable[str] = SIGNAL_VOCABULARY,
    sensors: Sequence[SensorPath] = (SensorPath.EBPF, SensorPath.AUDITD),
    epoch_id: int = 1,
) -> VisibilityModel:
    """A CONSTRUCTED visibility model over the corpus vocabulary.

    **Not a measurement.** Every row asserts full observability with
    ``CORPUS_VISIBILITY_OCCURRENCES`` declared occurrences. It exists so that a
    non-identifiability test is about *discrimination* rather than about a blind sensor:
    if the resolving signal were invisible, every case would come back
    ``INSUFFICIENT_EVIDENCE`` for the wrong reason and the corpus would prove nothing.
    Real visibility is fitted from replay by ``visibility/model.py`` and reported under
    G4.1, where the telemetry-source clause is declared UNMEASURED.

    Mandatory signals are excluded from the rows: ``VisibilityModel`` refuses a fitted
    row for one, because ``probability()`` already answers 1.0 for them from
    ``policy.py:47`` and a row would be silently ignored.
    """
    observations = tuple(
        VisibilityObservation(
            signal=signal,
            sensor=sensor,
            occurrences=CORPUS_VISIBILITY_OCCURRENCES,
            observations=CORPUS_VISIBILITY_OCCURRENCES,
            epoch_id=epoch_id,
        )
        for signal in sorted(set(signals) - MANDATORY_SIGNALS)
        for sensor in sensors
    )
    return fit_visibility_model(observations)


# --- fields the identifiability engine can be run against -------------------


_BENIGN_STATE = SecurityStateV1(privilege=Privilege.ELEVATED, trust=Trust.UNCERTAIN)
_MALICIOUS_STATE = SecurityStateV1(privilege=Privilege.ROOT, trust=Trust.UNTRUSTED)


def _world(
    *,
    world_id: str,
    mechanism_id: str,
    state: SecurityStateV1,
    expected: frozenset[str],
    forbidden: frozenset[str],
    log_odds: float = 0.0,
) -> SecurityWorldV1:
    latent = LatentSecurityState(
        state=state,
        asserted_dimensions=frozenset({"privilege", "trust"}),
        consequence=phi(state).total,
    )
    return SecurityWorldV1(
        world_id=world_id,
        mechanism_id=mechanism_id,
        latent_state=latent,
        support=WorldSupport(BeliefGeometry.LOG_ODDS, log_odds),
        support_state=WorldSupportState.PROVISIONAL,
        expected_evidence=expected,
        forbidden_evidence=forbidden,
        contradictions=(),
        tension=None,
        uncertainty=0.9,
        visibility_requirements=expected,
        spine_signatures=(),
        evidence_refs=(),
        born_at_sequence=0,
    )


def field_for_nonidentifiable_pair(
    pair: tuple[IncidentCase, IncidentCase], *, epoch_id: int = 1
) -> CausalBeliefField:
    """Two worlds with identical predictions, equal support and DIFFERENT consequence.

    The consequence gap is the point: with supports level, a system that ranked by alarm
    would name the compromised world, and the identifiability engine's tie-break has to
    refuse to.
    """
    benign, malicious = pair
    return CausalBeliefField(
        incident_id=benign.incident_id,
        epoch_id=epoch_id,
        worlds=(
            _world(
                world_id=f"{benign.incident_id}-w-approved",
                mechanism_id=benign.truth.mechanism_id,
                state=_BENIGN_STATE,
                expected=NONIDENTIFIABLE_EXPECTED,
                forbidden=NONIDENTIFIABLE_FORBIDDEN,
            ),
            _world(
                world_id=f"{benign.incident_id}-w-compromised",
                mechanism_id=malicious.truth.mechanism_id,
                state=_MALICIOUS_STATE,
                expected=NONIDENTIFIABLE_EXPECTED,
                forbidden=NONIDENTIFIABLE_FORBIDDEN,
            ),
        ),
    )


def field_for_resolvable_case(case: IncidentCase, *, epoch_id: int = 1) -> CausalBeliefField:
    """Two worlds differing on exactly one non-mandatory signal.

    The truth world expects ``RESOLVING_SIGNAL``; the alternative forbids it. Everything
    else — expected set, forbidden set, asserted dimensions — is shared, so exactly one
    ``SensorAction`` can separate them and the rest must be refused.
    """
    return CausalBeliefField(
        incident_id=case.incident_id,
        epoch_id=epoch_id,
        worlds=(
            _world(
                world_id=f"{case.incident_id}-w-compromised",
                mechanism_id="compromised_admin_session",
                state=_MALICIOUS_STATE,
                expected=NONIDENTIFIABLE_EXPECTED | {RESOLVING_SIGNAL},
                forbidden=NONIDENTIFIABLE_FORBIDDEN,
            ),
            _world(
                world_id=f"{case.incident_id}-w-approved",
                mechanism_id="approved_administration",
                state=_BENIGN_STATE,
                expected=NONIDENTIFIABLE_EXPECTED,
                forbidden=NONIDENTIFIABLE_FORBIDDEN | {RESOLVING_SIGNAL},
            ),
        ),
    )


def apply_granted_observation(
    field: CausalBeliefField, signal: str, *, observed: bool
) -> CausalBeliefField:
    """Apply one granted observation to a field. A LAB helper, not the runtime update.

    LUCID owns the real belief update; this exists so a test can check that a resolvable
    case actually resolves after one observation instead of asserting that it would. The
    rule is deliberately the crudest one that is still honest: a world contradicted by
    what was seen loses its support, a world that predicted it gains, and a world that
    said nothing is left exactly where it was — silence is not evidence.
    """
    if signal not in SIGNAL_VOCABULARY:
        raise ContractError(
            f"{signal!r} is outside the corpus vocabulary; the lab update refuses to "
            "score a signal the worlds never spoke about"
        )
    updated: list[SecurityWorldV1] = []
    for world in field.worlds:
        contradicted = world.forbids(signal) if observed else world.predicts(signal)
        confirmed = world.predicts(signal) if observed else world.forbids(signal)
        if contradicted:
            log_odds = CONTRADICTED_SUPPORT_LOG_ODDS
        elif confirmed:
            log_odds = CONFIRMED_SUPPORT_LOG_ODDS
        else:
            log_odds = world.support.value
        updated.append(
            replace(world, support=WorldSupport(BeliefGeometry.LOG_ODDS, log_odds))
        )
    return field.with_worlds(updated)


def corpus_report(
    pairs: Sequence[tuple[IncidentCase, IncidentCase]],
    resolvable: Sequence[IncidentCase],
) -> dict[str, Any]:
    """Provenance a ``BenchmarkResult`` records for these corpora (integration plan §5.4)."""
    return {
        "version": NONIDENTIFIABLE_VERSION,
        "nonidentifiable_pairs": len(pairs),
        "resolvable_cases": len(resolvable),
        "vocabulary": sorted(SIGNAL_VOCABULARY),
        "resolving_signal": RESOLVING_SIGNAL,
        "sensor_actions": sorted(action.value for action in SensorAction),
    }
