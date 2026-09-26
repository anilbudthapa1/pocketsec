"""D8.12 / PROM-F16 — the Reproducibility Gate: does a surviving theory hold somewhere else?

Surviving HOLDOUT means one held-out split, drawn from the same hosts' era, did not refute
the theory. That is not yet a discovery. This gate asks the question again on the
**REPLICATION** split (host-, time- and family-separated, spec §4.19) and adds three checks
the HOLDOUT test does not make. A theory is ``REPRODUCED`` iff all of these hold:

1. its REPLICATION test survived: every survivor is preregistered on REPLICATION in **one**
   batch (the Bonferroni family is m = the number of survivors), the vault is sealed and
   evaluated **once**, and the refutation rules registered at birth are re-run there;
2. it honours its own semantics on LAB_POOL: every ``INVARIANT`` metamorphic relation of
   ``DEFAULT_RELATIONS`` holds, and deleting a necessary step makes the support fall;
3. it would still be useful at realistic imbalance: precision at 20 negatives per positive,
   ``TPR·π / (TPR·π + FPR'·(1−π))`` with π = 1/21 and the smoothed ``FPR' = (fp + 0.5) /
   (negatives + 1)`` (so a zero observed FPR is never read as a perfect one), is ≥ 0.5;
4. it matches at most 1 % of the INDEPENDENT benign sessions (Stage 1 corpora it never saw).

Fewer than ``MIN_EVIDENCE_EPISODES`` REPLICATION true matches is ``INSUFFICIENT_EVIDENCE``,
whatever else holds: a handful of hits reproduces nothing.

What it refuses to do:

- It never evaluates a split twice and never sees a held-out episode: it talks to the
  :class:`HoldoutVault` only through preregistrations, one sealed ticket and the returned
  ``TestOutcome`` values.
- It never reads an unmeasured check as a pass. A metamorphic relation that applied to
  nothing (``holds is None``), an undefined replication recall, or an INDEPENDENT rate with no
  denominator each block ``REPRODUCED``. In particular a BENIGN-direction theory cannot be
  reproduced here: the INDEPENDENT sessions are all benign, so nothing there can show such
  a theory wrong, and an untestable check is not a passed one.
- It documents where the theory fails whether or not it passes (spec §24): the caller's
  challenger / doppelgänger / dropout contexts plus its own ``independent:fp`` observation.
- ``independent_positives_available`` is reported, never assumed: it is False whenever the
  INDEPENDENT sessions carry no positive (true for every planted mechanism), which is why
  independent *recall* is UNMEASURED.

It writes exactly one status per survivor (REPRODUCED / NOT_REPRODUCED /
INSUFFICIENT_EVIDENCE) through the ledger, which refuses REPRODUCED without a surviving
REPLICATION result.
"""

from __future__ import annotations

import random
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage8.episode import Episode, FitCounts, Split
from pocketsec.stage8.forge.package import (
    MAX_FAILURE_CONDITIONS,
    FailureCondition,
    ReproducibilityRecord,
    ReproducibilityStatus,
)
from pocketsec.stage8.genome.grammar import FEATURE_NAMES, Mechanism
from pocketsec.stage8.genome.hypothesis import Direction, FalsifierKind, HypothesisGenome
from pocketsec.stage8.governor.budget import ResearchGovernor
from pocketsec.stage8.identifiability.gate import MIN_EVIDENCE_EPISODES
from pocketsec.stage8.laboratory.metamorphic import (
    DEFAULT_RELATIONS,
    Expectation,
    MetamorphicResult,
    run_metamorphic,
)
from pocketsec.stage8.ledger.theory import PreRegistration, TestOutcome, TheoryLedger, TheoryStatus
from pocketsec.stage8.sandbox.integrity import HoldoutVault

__all__ = [
    "IMBALANCE_MIN_PRECISION",
    "IMBALANCE_RATIO",
    "INDEPENDENT_FP_MAX",
    "REPRODUCIBILITY_COMPONENT",
    "ReproducibilityGate",
    "ReproducibilityVerdict",
    "imbalance_precision",
    "telemetry_requirements",
]

#: Spec §4.21. Chosen, not measured.
IMBALANCE_RATIO: int = 20
IMBALANCE_MIN_PRECISION: float = 0.5
INDEPENDENT_FP_MAX: float = 0.01
REPRODUCIBILITY_COMPONENT: str = "reproducibility"

_STATUS: Mapping[ReproducibilityStatus, TheoryStatus] = MappingProxyType({
    ReproducibilityStatus.REPRODUCED: TheoryStatus.REPRODUCED,
    ReproducibilityStatus.NOT_REPRODUCED: TheoryStatus.NOT_REPRODUCED,
    ReproducibilityStatus.INSUFFICIENT_EVIDENCE: TheoryStatus.INSUFFICIENT_EVIDENCE,
})
_TARGET_LABEL: Mapping[Direction, int] = MappingProxyType(
    {Direction.MALICIOUS: 1, Direction.BENIGN: 0})


@dataclass(frozen=True, slots=True)
class ReproducibilityVerdict:
    """The gate's answer for one survivor, with everything it was decided on."""

    hypothesis_id: str
    record: ReproducibilityRecord
    invariance: tuple[MetamorphicResult, ...]
    telemetry_requirements: tuple[str, ...]  # feature_names() slots the predicates read
    failing_contexts: tuple[FailureCondition, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.record, ReproducibilityRecord):
            raise ContractError("ReproducibilityVerdict.record must be a ReproducibilityRecord")
        if len(self.failing_contexts) > MAX_FAILURE_CONDITIONS:
            raise ContractError(f"at most {MAX_FAILURE_CONDITIONS} failing contexts")
        unknown = set(self.telemetry_requirements) - set(FEATURE_NAMES)
        if unknown:
            raise ContractError(f"telemetry requirements name unknown slots {sorted(unknown)}")


def imbalance_precision(counts: FitCounts, *, ratio: int = IMBALANCE_RATIO) -> float | None:
    """Precision at ``ratio`` negatives per positive, from direction-relative counts.

    ``None`` when recall is undefined (no positives). The FPR is smoothed so a split with no
    observed false match still pays for the negatives it did not contain.
    """
    recall = counts.recall
    if recall is None:
        return None
    prior = 1.0 / (1.0 + ratio)
    fpr = (counts.false_matches + 0.5) / (counts.negatives + 1)
    hits = recall * prior
    return hits / (hits + fpr * (1.0 - prior))


#: The encoder's slot names per group, in bit order (the grammar's masks use the same order).
_RELATION_SLOTS = tuple(name for name in FEATURE_NAMES if name.startswith("relation="))
_OBJECT_SLOTS = tuple(name for name in FEATURE_NAMES if name.startswith("object."))
_RAISED_SLOTS = tuple(name for name in FEATURE_NAMES if name.startswith("raised."))


def _bits(mask: int) -> tuple[int, ...]:
    return tuple(bit for bit in range(mask.bit_length()) if mask >> bit & 1)


def telemetry_requirements(genome: HypothesisGenome) -> tuple[str, ...]:
    """The encoder slots every predicate of the theory reads (forbidden ones too), in feature order.

    This is what an endpoint must still observe for the theory to mean anything: lose the
    sensor behind one of these slots and the theory is blind, not refuted.
    """
    mechanism: Mechanism = genome.proposed_mechanism
    names: set[str] = set()
    for predicate in (*mechanism.steps, *genome.forbidden_observations):
        names.add(_RELATION_SLOTS[predicate.relation])
        names.update(_OBJECT_SLOTS[bit] for bit in
                     _bits(predicate.require_properties | predicate.forbid_properties))
        names.update(_RAISED_SLOTS[bit] for bit in _bits(predicate.require_raised))
    return tuple(sorted(names, key=FEATURE_NAMES.index))


class ReproducibilityGate:
    """Preregister, seal once, evaluate once, then judge each survivor on four checks."""

    __slots__ = ("_governor", "_independent", "_lab_pool", "_ledger", "_n", "_rng", "_vault")

    def __init__(
        self,
        *,
        vault: HoldoutVault,
        ledger: TheoryLedger,
        independent: Sequence[Episode],
        lab_pool: Sequence[Episode],
        governor: ResearchGovernor,
        rng: random.Random,
    ) -> None:
        if not isinstance(vault, HoldoutVault) or vault.split is not Split.REPLICATION:
            raise ContractError("the reproducibility gate needs the REPLICATION HoldoutVault")
        if not isinstance(ledger, TheoryLedger):
            raise ContractError("the reproducibility gate writes through a TheoryLedger")
        if not isinstance(governor, ResearchGovernor):
            raise ContractError("the reproducibility gate needs the run's ResearchGovernor")
        if not isinstance(rng, random.Random):
            raise ContractError("the reproducibility gate needs an explicit random.Random")
        self._independent = self._require_split(independent, Split.INDEPENDENT, "independent")
        self._lab_pool = self._require_split(lab_pool, Split.LAB_POOL, "lab_pool")
        self._vault, self._ledger, self._governor, self._rng = vault, ledger, governor, rng
        self._n: Counter[str] = Counter()

    def run(
        self,
        survivors: Sequence[HypothesisGenome],
        *,
        failing_contexts: Mapping[str, tuple[FailureCondition, ...]],
    ) -> tuple[ReproducibilityVerdict, ...]:
        """One verdict per survivor, in input order. ``()`` seals nothing."""
        survivors = self._check_survivors(survivors)
        if not survivors:
            return ()
        outcomes = self._evaluate_once(survivors)
        verdicts = tuple(
            self._judge(genome, outcomes[genome.hypothesis_id],
                        tuple(failing_contexts.get(genome.hypothesis_id, ())))
            for genome in survivors
        )
        return verdicts

    def stats(self) -> Mapping[str, int]:
        """Firing counts: batches, and one counter per status and failed check."""
        return MappingProxyType(dict(self._n))

    # --- the one batch ---------------------------------------------------------------------

    def _check_survivors(
        self, survivors: Sequence[HypothesisGenome]
    ) -> tuple[HypothesisGenome, ...]:
        genomes = tuple(survivors)
        if len({g.hypothesis_id for g in genomes}) != len(genomes):
            raise ContractError("a survivor appears twice; the batch would count it twice")
        # Everything is checked before anything is written, so a bad survivor cannot leave
        # half a batch preregistered and never evaluated.
        for genome in genomes:
            if not isinstance(genome, HypothesisGenome):
                raise ContractError(
                    f"survivors must be HypothesisGenomes, got {type(genome).__name__}")
            if self._ledger.genome(genome.hypothesis_id) != genome:
                raise ContractError(f"{genome.hypothesis_id} is not the genome the ledger holds")
            status = self._ledger.status(genome.hypothesis_id)
            if status is not TheoryStatus.SURVIVED:
                raise ContractError(
                    f"{genome.hypothesis_id} is {status}; only SURVIVED theories replicate")
        return genomes

    def _registration(self, genome: HypothesisGenome, batch_size: int) -> PreRegistration:
        prediction = next(p for p in genome.predicted_observations if p.split is Split.REPLICATION)
        alpha = next(f.alpha for f in genome.falsification_tests
                     if f.kind is FalsifierKind.REPLICATION and f.alpha is not None)
        return PreRegistration(
            registration_id="", hypothesis_id=genome.hypothesis_id,
            genome_digest=genome.digest(), split=Split.REPLICATION,
            split_digest=self._vault.split_digest(), batch_size=batch_size,
            alpha=alpha, prediction=prediction,
        )

    def _evaluate_once(self, survivors: tuple[HypothesisGenome, ...]) -> dict[str, TestOutcome]:
        registrations = [self._registration(g, len(survivors)) for g in survivors]
        for registration in registrations:
            self._ledger.preregister(registration)
        ticket = self._vault.seal_batch(registrations)
        outcomes = self._vault.evaluate(ticket)
        self._n["batches"] += 1
        self._n["registered"] += len(registrations)
        return {outcome.hypothesis_id: outcome for outcome in outcomes}

    # --- judging one survivor --------------------------------------------------------------

    def _judge(
        self, genome: HypothesisGenome, outcome: TestOutcome, contexts: tuple[FailureCondition, ...]
    ) -> ReproducibilityVerdict:
        # F1: decoys that perform a step this theory names are not harmless decoys for it.
        avoid = genome.proposed_mechanism.steps + genome.forbidden_observations
        invariance = run_metamorphic(genome.decides, self._lab_pool, DEFAULT_RELATIONS,
                                     rng=self._rng, governor=self._governor, decoy_avoid=avoid)
        independent_rate = self._independent_rate(genome)
        counts = outcome.counts
        precision_20 = imbalance_precision(counts)
        reasons = list(outcome.reasons)
        reasons += self._invariance_reasons(invariance)
        if precision_20 is None or precision_20 < IMBALANCE_MIN_PRECISION:
            reasons.append("imbalance_precision")
        if independent_rate is None:
            reasons.append("independent_fp_unmeasured")
        elif independent_rate > INDEPENDENT_FP_MAX:
            reasons.append("independent_fp")
        if counts.true_matches < MIN_EVIDENCE_EPISODES:
            status = ReproducibilityStatus.INSUFFICIENT_EVIDENCE
            reasons.insert(0, "insufficient_evidence")
        else:
            status = (ReproducibilityStatus.NOT_REPRODUCED if reasons
                      else ReproducibilityStatus.REPRODUCED)
        record = ReproducibilityRecord(
            status=status,
            replication_precision=counts.precision,
            replication_recall=counts.recall,
            replication_false_positive_rate=counts.false_positive_rate,
            imbalance_precision=precision_20,
            independent_false_positive_rate=independent_rate,
            independent_positives_available=any(ep.label == 1 for ep in self._independent),
            reasons=tuple(dict.fromkeys(reasons)),
        )
        self._ledger.set_status(genome.hypothesis_id, _STATUS[status],
                                reason=f"reproducibility:{status.value.lower()}")
        self._n[status.value] += 1
        for reason in record.reasons:
            self._n[f"reason:{reason}"] += 1
        return ReproducibilityVerdict(
            hypothesis_id=genome.hypothesis_id, record=record, invariance=invariance,
            telemetry_requirements=telemetry_requirements(genome),
            failing_contexts=self._contexts(contexts, independent_rate),
        )

    @staticmethod
    def _invariance_reasons(results: Sequence[MetamorphicResult]) -> list[str]:
        """Every relation that failed *or could not be measured*; None is never a pass."""
        expectations = {relation.relation_id: relation.expectation
                        for relation in DEFAULT_RELATIONS}
        reasons: list[str] = []
        for result in results:
            if result.holds is True:
                continue
            falls = expectations[result.relation_id] is Expectation.SUPPORT_FALLS
            kind = "support" if falls else "invariance"
            state = "unmeasured" if result.holds is None else "failed"
            reasons.append(f"{kind}_{state}:{result.relation_id}")
        return reasons

    def _independent_rate(self, genome: HypothesisGenome) -> float | None:
        """False matches / non-target INDEPENDENT episodes; None when there are none."""
        target = _TARGET_LABEL[genome.direction]
        meter = self._governor.meter
        before = meter.spent
        wrong = others = 0
        for episode in self._independent:
            if episode.label is None or episode.label == target:
                continue
            others += 1
            wrong += genome.decides(episode, meter=meter)
        self._governor.account(REPRODUCIBILITY_COMPONENT, meter.spent - before)
        return None if others == 0 else wrong / others

    def _contexts(
        self, given: tuple[FailureCondition, ...], independent_rate: float | None
    ) -> tuple[FailureCondition, ...]:
        if any(not isinstance(item, FailureCondition) for item in given):
            raise ContractError("failing_contexts must hold FailureCondition values")
        contexts = list(given)
        if independent_rate:  # observed matches on benign sessions it never saw: a known failure
            contexts.append(FailureCondition(
                context="independent:fp", observed_rate=independent_rate,
                detail="matches benign INDEPENDENT sessions",
            ))
        if len(contexts) > MAX_FAILURE_CONDITIONS:
            # Keep the first ones and say so: a silent cut would read as "fails nowhere else".
            self._n["failing_contexts_truncated"] += len(contexts) - MAX_FAILURE_CONDITIONS
            contexts = contexts[:MAX_FAILURE_CONDITIONS]
        return tuple(contexts)

    @staticmethod
    def _require_split(episodes: Sequence[Episode], split: Split, name: str) -> tuple[Episode, ...]:
        held = tuple(episodes)
        if not held:
            raise ContractError(f"{name} is empty: a check over nothing passes nothing")
        for episode in held:
            if not isinstance(episode, Episode) or episode.split is not split:
                raise ContractError(f"{name} must hold {split.value} Episodes only")
        return held
