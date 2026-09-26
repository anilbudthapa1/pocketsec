"""D8.11 / PROM-F15 — the Theory Ledger: append-only, digest-chained, preregistration first.

Falsification is only real if every test and refutation rule is recorded **before** the
held-out data is looked at, and if a hypothesis cannot be edited after its test runs. The
genome half is structural (a ``HypothesisGenome`` is immutable and content-addressed, so an
"edit" is a new id). This module is the other half: the one place a theory's lifecycle is
written down, in an order that can be checked.

**Append-only.** No update or delete method exists (Stage 0 registry precedent). Each
:class:`LedgerEntry` digest covers its sequence, kind, id, payload and the previous digest,
from :data:`GENESIS_DIGEST`; editing a retained entry breaks :meth:`TheoryLedger.verify_chain`.

**Order is enforced, not hoped for.** Each refusal raises :class:`LedgerError` and is counted:
a duplicate birth; any event for an unborn id; a ``CHALLENGE_RESULT`` for an undeclared
falsifier or for a *held-out* one (only the vault decides those); ``preregister`` with a
foreign genome digest, a prediction or alpha other than the one registered at birth, a second
registration for (id, split), or the wrong status (HOLDOUT needs PROPOSED, REPLICATION needs
SURVIVED); ``record_result`` without its PREREGISTER, or twice; an illegal transition (legal:
PROPOSED → CHALLENGED_OUT | REGISTERED | FOSSILIZED; REGISTERED → SURVIVED | FALSIFIED;
SURVIVED → REPRODUCED | NOT_REPRODUCED | INSUFFICIENT_EVIDENCE). Four transitions also need
evidence already in the ledger: REGISTERED only through :meth:`TheoryLedger.preregister`;
SURVIVED/FALSIFIED only with an agreeing HOLDOUT result; REPRODUCED only with a surviving
REPLICATION result; CHALLENGED_OUT only after a failed challenge. A status is never a
caller's assertion the ledger cannot back.

**Bounded, with recorded eviction.** The chain is a window of ``capacity`` entries: when full,
the oldest quarter is dropped and a ``CHECKPOINT`` records ``{dropped, first_sequence,
last_sequence, anchor_digest}``; every retained digest is re-derived from the anchor. At most
``max_theories`` records are kept outside the window; when full, terminal non-REPRODUCED
records fold oldest-first (their :class:`NegativeResult` was written to negative memory when
they became terminal), REPRODUCED and open records never fold, and if nothing can fold the
birth is refused (``births_refused_full``). A folded id leaves a **tombstone** (id -> terminal
status, at most :data:`MAX_TOMBSTONES`, oldest evicted and counted): the ledger, not the
negative memory's per-mechanism slot, remembers that the id was born and how it ended, so a
refuted hypothesis id can never be born again and re-tested (F5), and ``status`` still answers
for an id folded mid-run (S8-RES-1). A tombstone evicted past its cap is counted
(``tombstones_evicted``); only then could that id be born again.

In memory only; never writes the experiment registry file (spec §2.5). It holds genomes,
ids, digests and counts — never an episode, a step, a label or a raw proposal string.
"""

from __future__ import annotations

import math
import re
import sys
from collections import Counter, OrderedDict, deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, NoReturn

from pocketsec.stage0.contracts.common import (
    ContractError,
    digest_of_bytes,
    require_non_negative_int,
)
from pocketsec.stage8.episode import FitCounts, Split
from pocketsec.stage8.forge.package import IdentifiabilityClass, ReproducibilityStatus
from pocketsec.stage8.genome.hypothesis import FalsifierKind, HypothesisGenome, Prediction
from pocketsec.stage8.ledger.negative_results import (
    EPISODE_ID,
    REASON_CODE,
    NegativeResult,
    NegativeResultMemory,
    canonical_bytes,
    freeze_plain,
    plain_data,
)

if TYPE_CHECKING:
    from pocketsec.stage8.identifiability.gate import IdentifiabilityVerdict

__all__ = [
    "GENESIS_DIGEST",
    "HELD_OUT_SPLITS",
    "MAX_LEDGER_ENTRIES",
    "MAX_RECORD_ITEMS",
    "MAX_THEORIES",
    "MAX_TOMBSTONES",
    "LedgerEntry",
    "LedgerError",
    "LedgerEventKind",
    "PreRegistration",
    "TestOutcome",
    "TheoryLedger",
    "TheoryRecord",
    "TheoryStatus",
    "canonical_bytes",
]

#: Spec §4.21. Chosen, not measured.
MAX_LEDGER_ENTRIES: int = 16384
MAX_THEORIES: int = 2048
#: Folded-id tombstones kept (id -> terminal status). Chosen, not measured: eight ledgers' worth
#: of folds (ids only, never a genome); an eviction is counted, never silent.
MAX_TOMBSTONES: int = 8 * MAX_THEORIES
#: Per-record cap on each list a :class:`TheoryRecord` view carries (experiments, revisions,
#: failed predictions, counterexamples). Overflow is counted, never silent.
MAX_RECORD_ITEMS: int = 8
GENESIS_DIGEST: str = "sha256:" + "0" * 64
HELD_OUT_SPLITS: frozenset[Split] = frozenset({Split.HOLDOUT, Split.REPLICATION})

_MIN_CAPACITY = 8
_REGISTRATION_PREFIX = "reg-"
_DIGEST_HEX = 64
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


class TheoryStatus(StrEnum):
    PROPOSED = "PROPOSED"
    CHALLENGED_OUT = "CHALLENGED_OUT"
    REGISTERED = "REGISTERED"
    SURVIVED = "SURVIVED"
    FALSIFIED = "FALSIFIED"
    REPRODUCED = "REPRODUCED"
    NOT_REPRODUCED = "NOT_REPRODUCED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    FOSSILIZED = "FOSSILIZED"


class LedgerEventKind(StrEnum):
    BIRTH = "BIRTH"
    CHALLENGE_RESULT = "CHALLENGE_RESULT"
    PREREGISTER = "PREREGISTER"
    TEST_RESULT = "TEST_RESULT"
    STATUS = "STATUS"
    IDENTIFIABILITY = "IDENTIFIABILITY"
    CHECKPOINT = "CHECKPOINT"


class LedgerError(ContractError):
    """An event the ledger refuses: out of order, duplicated, unbacked or unknown."""


_S = TheoryStatus
_LEGAL: Mapping[TheoryStatus, frozenset[TheoryStatus]] = MappingProxyType({
    _S.PROPOSED: frozenset({_S.CHALLENGED_OUT, _S.REGISTERED, _S.FOSSILIZED}),
    _S.REGISTERED: frozenset({_S.SURVIVED, _S.FALSIFIED}),
    _S.SURVIVED: frozenset({_S.REPRODUCED, _S.NOT_REPRODUCED, _S.INSUFFICIENT_EVIDENCE}),
})
_OPEN: frozenset[TheoryStatus] = frozenset(
    {TheoryStatus.PROPOSED, TheoryStatus.REGISTERED, TheoryStatus.SURVIVED}
)
_FOLDABLE: frozenset[TheoryStatus] = frozenset(TheoryStatus) - _OPEN - {TheoryStatus.REPRODUCED}
_REPRODUCIBILITY: frozenset[TheoryStatus] = frozenset(_LEGAL[TheoryStatus.SURVIVED])
_REQUIRED_ENRICHMENT: Mapping[Split, FalsifierKind] = MappingProxyType({
    Split.HOLDOUT: FalsifierKind.HOLDOUT_ENRICHMENT,
    Split.REPLICATION: FalsifierKind.REPLICATION,
})


def _require_int(value: object, field: str, floor: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < floor:
        raise ContractError(f"{field} must be an int >= {floor}, got {value!r}")
    return value


def _require_sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ContractError(f"{field} must be 'sha256:' + 64 hex, got {value!r}")
    return value


def _require_reason(value: object) -> str:
    if not isinstance(value, str) or not REASON_CODE.fullmatch(value):
        raise ContractError(f"a ledger reason is a fixed-vocabulary code, got {value!r}")
    return value


def _require_unit(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractError(f"{field} must be a number, got {value!r}")
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise ContractError(f"{field} must be within [0, 1], got {value!r}")
    return float(value)


def _prediction_plain(prediction: Prediction) -> dict[str, Any]:
    return {
        "split": prediction.split.value,
        "min_precision": prediction.min_precision,
        "min_recall": prediction.min_recall,
        "max_false_positive_rate": prediction.max_false_positive_rate,
    }


def _counts_plain(counts: FitCounts) -> dict[str, int]:
    return {
        "matched": counts.matched, "true_matches": counts.true_matches,
        "false_matches": counts.false_matches, "positives": counts.positives,
        "negatives": counts.negatives,
    }


# --- value types ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PreRegistration:
    """A test fixed before its split is evaluated: which data, which family, which prediction.

    ``registration_id`` is derived from every other field ("" derives it; a mismatch is
    refused), so two registrations that differ in anything have different ids.
    """

    registration_id: str
    hypothesis_id: str
    genome_digest: str
    split: Split
    split_digest: str
    batch_size: int
    alpha: float
    prediction: Prediction

    def __post_init__(self) -> None:
        if not isinstance(self.hypothesis_id, str) or not self.hypothesis_id.startswith("hyp-"):
            raise ContractError(f"not a hypothesis id: {self.hypothesis_id!r}")
        if not isinstance(self.genome_digest, str) or not self.genome_digest:
            raise ContractError("genome_digest must be a non-empty digest string")
        if not isinstance(self.split, Split) or self.split not in HELD_OUT_SPLITS:
            raise ContractError(f"a preregistration is for a held-out split, got {self.split!r}")
        _require_sha256(self.split_digest, "PreRegistration.split_digest")
        _require_int(self.batch_size, "batch_size", 1)
        if isinstance(self.alpha, bool) or not isinstance(self.alpha, (int, float)) or not (
            math.isfinite(self.alpha) and 0.0 < self.alpha <= 0.5
        ):
            raise ContractError(f"alpha must be within (0, 0.5], got {self.alpha!r}")
        object.__setattr__(self, "alpha", float(self.alpha))
        if not isinstance(self.prediction, Prediction) or self.prediction.split is not self.split:
            raise ContractError("the prediction must be a Prediction for the registration's split")
        derived = _REGISTRATION_PREFIX + digest_of_bytes(canonical_bytes(self._content()))[7:31]
        if self.registration_id == "":
            object.__setattr__(self, "registration_id", derived)
        elif self.registration_id != derived:
            raise ContractError(
                f"registration_id {self.registration_id!r} does not match its content ({derived})"
            )

    def _content(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id, "genome_digest": self.genome_digest,
            "split": self.split.value, "split_digest": self.split_digest,
            "batch_size": self.batch_size, "alpha": self.alpha,
            "prediction": _prediction_plain(self.prediction),
        }

    def to_payload(self) -> dict[str, Any]:
        return {"registration_id": self.registration_id, **self._content()}


@dataclass(frozen=True, slots=True)
class TestOutcome:
    """One registration's held-out result. ``survived`` iff no refutation rule fired."""

    __test__ = False  # not a pytest class, despite the name

    registration_id: str
    hypothesis_id: str
    split: Split
    counts: FitCounts
    p_value: float | None
    survived: bool
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        rid = self.registration_id
        if not isinstance(rid, str) or not rid.startswith(_REGISTRATION_PREFIX):
            raise ContractError(f"not a registration id: {rid!r}")
        if not isinstance(self.split, Split) or self.split not in HELD_OUT_SPLITS:
            raise ContractError(f"a test outcome is on HOLDOUT or REPLICATION, got {self.split!r}")
        if not isinstance(self.counts, FitCounts):
            raise ContractError("counts must be FitCounts")
        if self.p_value is not None:
            object.__setattr__(self, "p_value", _require_unit(self.p_value, "p_value"))
        if not isinstance(self.survived, bool):
            raise ContractError("survived must be a bool")
        object.__setattr__(self, "reasons", tuple(_require_reason(r) for r in self.reasons))
        # The invariant a lenient caller would most like to weaken: a theory whose rule fired
        # did not survive, and one that "failed" must say which rule.
        if self.survived == bool(self.reasons):
            raise ContractError("survived must be True exactly when no refutation rule fired")


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    sequence: int
    kind: LedgerEventKind
    hypothesis_id: str
    payload: Mapping[str, Any]
    previous_digest: str
    entry_digest: str

    def recomputed_digest(self) -> str:
        """The digest this entry's content chains to; ≠ ``entry_digest`` means tampering."""
        return _entry_digest(
            self.sequence, self.kind, self.hypothesis_id, self.payload, self.previous_digest
        )


def _entry_digest(
    sequence: int, kind: LedgerEventKind, hypothesis_id: str, payload: Mapping[str, Any],
    previous: str,
) -> str:
    return digest_of_bytes(canonical_bytes({
        "sequence": sequence, "kind": kind.value, "hypothesis_id": hypothesis_id,
        "payload": payload, "previous_digest": previous,
    }))


@dataclass(frozen=True, slots=True)
class TheoryRecord:
    """Architecture §22's theory record: a read-only view assembled from the ledger."""

    genome: HypothesisGenome
    status: TheoryStatus
    evidence_for: int
    evidence_against: int
    experiments: tuple[str, ...]
    predictions: tuple[Prediction, ...]
    failed_predictions: tuple[str, ...]
    counterexamples: tuple[str, ...]
    revisions: tuple[str, ...]
    resource_cost: int
    identifiability: IdentifiabilityClass | None
    reproducibility: ReproducibilityStatus | None


class _Theory:
    """Mutable per-id bookkeeping behind a :class:`TheoryRecord`. Never handed out."""

    __slots__ = (
        "born", "challenges_failed", "counterexamples", "evidence_against", "evidence_for",
        "experiments", "failed_predictions", "genome", "identifiability", "overflow",
        "refutation", "refutation_reason", "registrations", "reproducibility", "resource_cost",
        "results", "revisions", "status",
    )

    def __init__(self, genome: HypothesisGenome, born: int) -> None:
        self.genome = genome
        self.born = born
        self.status = TheoryStatus.PROPOSED
        self.registrations: dict[Split, tuple[PreRegistration, int]] = {}
        self.results: dict[str, tuple[TestOutcome, int]] = {}
        self.challenges_failed = 0
        self.evidence_for = 0
        self.evidence_against = 0
        self.experiments: list[str] = []
        self.failed_predictions: list[str] = []
        self.counterexamples: list[str] = []
        self.revisions: list[str] = []
        self.overflow = 0
        self.resource_cost = 0
        self.identifiability: IdentifiabilityClass | None = None
        self.reproducibility: ReproducibilityStatus | None = None
        self.refutation: FalsifierKind | None = None
        self.refutation_reason = ""

    def add(self, items: list[str], value: str) -> None:
        if value in items:
            return
        if len(items) < MAX_RECORD_ITEMS:
            items.append(value)
        else:
            self.overflow += 1

    def registration(self, registration_id: str) -> tuple[PreRegistration, int] | None:
        for registration, sequence in self.registrations.values():
            if registration.registration_id == registration_id:
                return registration, sequence
        return None

    def result_on(self, split: Split) -> TestOutcome | None:
        for outcome, _ in self.results.values():
            if outcome.split is split:
                return outcome
        return None

    def view(self) -> TheoryRecord:
        return TheoryRecord(
            genome=self.genome, status=self.status, evidence_for=self.evidence_for,
            evidence_against=self.evidence_against, experiments=tuple(self.experiments),
            predictions=tuple(self.genome.predicted_observations),
            failed_predictions=tuple(self.failed_predictions),
            counterexamples=tuple(self.counterexamples), revisions=tuple(self.revisions),
            resource_cost=self.resource_cost, identifiability=self.identifiability,
            reproducibility=self.reproducibility,
        )


def _failed_predictions(prediction: Prediction, counts: FitCounts) -> list[str]:
    """Which recorded predictions the counts contradict. Undefined rates count as failed."""
    split = prediction.split.value
    failed = []
    if counts.precision is None or counts.precision < prediction.min_precision:
        failed.append(f"{split}:precision")
    if counts.recall is None or counts.recall < prediction.min_recall:
        failed.append(f"{split}:recall")
    fpr = counts.false_positive_rate
    if fpr is None or fpr > prediction.max_false_positive_rate:
        failed.append(f"{split}:false_positive_rate")
    return failed


def _refutation_kind(reason: str) -> FalsifierKind | None:
    """Map a vault / challenge reason code back to the falsifier that produced it."""
    token = reason.rsplit(":", 1)[-1]
    for kind in FalsifierKind:
        if token in (kind.value, kind.name):
            return kind
    return None


# --- the ledger -------------------------------------------------------------------------------


class TheoryLedger:
    """The append-only, digest-chained record of every theory in one research run."""

    def __init__(
        self,
        *,
        capacity: int = MAX_LEDGER_ENTRIES,
        max_theories: int = MAX_THEORIES,
        negative_memory: NegativeResultMemory | None = None,
    ) -> None:
        _require_int(capacity, "ledger capacity", _MIN_CAPACITY)
        _require_int(max_theories, "max_theories", 1)
        if negative_memory is not None and not isinstance(negative_memory, NegativeResultMemory):
            raise ContractError("negative_memory must be a NegativeResultMemory or None")
        self._capacity = capacity
        self._max_theories = max_theories
        self._memory = negative_memory
        self._entries: deque[LedgerEntry] = deque()
        self._anchor = GENESIS_DIGEST
        self._head_sequence = 0
        self._next_sequence = 0
        self._theories: dict[str, _Theory] = {}
        self._registration_owner: dict[str, str] = {}
        self._tombstones: OrderedDict[str, TheoryStatus] = OrderedDict()
        # (split digest, mechanism digest, direction) already tested: a reading killed on a split
        # cannot be re-born under a new id (say, with a looser kill criterion) and tested on the
        # same split again (F1, medium lens). Bounded like the tombstones, evictions counted.
        self._tested_on_split: OrderedDict[tuple[str, str, str], str] = OrderedDict()
        self._n: Counter[str] = Counter()

    # --- events ---------------------------------------------------------------------------

    def record_birth(self, genome: HypothesisGenome) -> LedgerEntry:
        if not isinstance(genome, HypothesisGenome):
            raise ContractError(f"record_birth takes a genome, got {type(genome).__name__}")
        hid = genome.hypothesis_id
        if hid in self._theories or hid in self._tombstones or (
            self._memory is not None and self._memory.result_for_hypothesis(hid) is not None
        ):
            self._refuse("refused_duplicate_birth", f"{hid} was already born")
        if len(self._theories) >= self._max_theories and not self._fold_one():
            self._refuse(
                "births_refused_full",
                f"{self._max_theories} theory records are all open or REPRODUCED; nothing can fold",
            )
        payload = {
            "genome_digest": genome.digest(),
            "mechanism_digest": genome.proposed_mechanism.digest(),
            "direction": genome.direction.value,
            "generator": genome.provenance.generator.value,
            "foreign": genome.provenance.foreign,
            "parents": list(genome.parent_hypotheses),
            "falsifiers": [
                [f.kind.value, f.split.value, f.threshold, f.alpha]
                for f in genome.falsification_tests
            ],
            "predictions": [_prediction_plain(p) for p in genome.predicted_observations],
        }
        entry = self._append(LedgerEventKind.BIRTH, hid, payload)
        self._theories[hid] = _Theory(genome, entry.sequence)
        for parent in genome.parent_hypotheses:
            parent_theory = self._theories.get(parent)
            if parent_theory is not None:
                parent_theory.add(parent_theory.revisions, hid)
        self._n["births"] += 1
        return entry

    def record_challenge(
        self,
        hypothesis_id: str,
        *,
        kind: FalsifierKind,
        passed: bool,
        statistic: float | None,
        work_units: int = 0,
        counterexample_ids: Sequence[str] = (),
    ) -> LedgerEntry:
        """A pre-holdout screen's result (LAB_POOL / CHALLENGE). Held-out kinds are refused."""
        theory = self._born(hypothesis_id)
        declared = [f for f in theory.genome.falsification_tests if f.kind is kind]
        if not declared:
            self._refuse("refused_undeclared_falsifier", f"{hypothesis_id} lacks {kind.value}")
        if any(f.split in HELD_OUT_SPLITS for f in declared):
            self._refuse(
                "refused_heldout_challenge",
                f"{kind!r} is decided on a held-out split by the vault, not by a challenge",
            )
        if not isinstance(passed, bool):
            raise ContractError("passed must be a bool")
        if statistic is not None and (
            isinstance(statistic, bool) or not isinstance(statistic, (int, float))
            or not math.isfinite(statistic)
        ):
            raise ContractError(f"statistic must be finite or None, got {statistic!r}")
        require_non_negative_int(work_units, "work_units")
        examples = list(counterexample_ids)
        if any(not isinstance(e, str) or not EPISODE_ID.fullmatch(e) for e in examples):
            raise ContractError("counterexample_ids must be episode ids")
        entry = self._append(LedgerEventKind.CHALLENGE_RESULT, hypothesis_id, {
            "kind": kind.value, "passed": passed,
            "statistic": None if statistic is None else float(statistic),
            "work_units": work_units, "counterexamples": examples[:MAX_RECORD_ITEMS],
        })
        theory.add(theory.experiments, f"challenge:{kind.value}")
        theory.resource_cost += work_units
        for example in examples:
            theory.add(theory.counterexamples, example)
        if not passed:
            theory.challenges_failed += 1
            theory.refutation, theory.refutation_reason = kind, f"challenge:{kind.value}"
        self._n["challenges"] += 1
        return entry

    def preregister(self, registration: PreRegistration) -> LedgerEntry:
        if not isinstance(registration, PreRegistration):
            raise ContractError("preregister takes a PreRegistration")
        hid, split = registration.hypothesis_id, registration.split
        theory = self._born(hid)
        genome = theory.genome
        if registration.genome_digest != genome.digest():
            self._refuse("refused_digest_mismatch", f"{hid}: registration names a different genome")
        if split in theory.registrations or theory.result_on(split) is not None:
            self._refuse("refused_reregistration", f"{hid} is already registered on {split.value}")
        needed = TheoryStatus.PROPOSED if split is Split.HOLDOUT else TheoryStatus.SURVIVED
        if theory.status is not needed:
            self._refuse(
                "refused_status_for_registration",
                f"{hid} is {theory.status.value}; {split.value} registration needs {needed.value}",
            )
        if registration.prediction not in genome.predicted_observations:
            self._refuse("refused_prediction_mismatch", f"{hid}: not the birth prediction")
        earlier = self._tested_on_split.get(self._reading_key(genome, registration.split_digest))
        if earlier is not None and earlier != hid:
            self._refuse("refused_retest_on_split",
                         f"{hid}: this reading was already tested on this split as {earlier}")
        declared_alpha = [
            f.alpha for f in genome.falsification_tests
            if f.kind is _REQUIRED_ENRICHMENT[split] and f.alpha is not None
        ]
        if declared_alpha and registration.alpha not in declared_alpha:
            self._refuse("refused_alpha_mismatch", f"{hid}: alpha differs from the birth one")
        entry = self._append(LedgerEventKind.PREREGISTER, hid, registration.to_payload())
        theory.registrations[split] = (registration, entry.sequence)
        self._registration_owner[registration.registration_id] = hid
        theory.add(theory.experiments, registration.registration_id)
        self._n["preregistrations"] += 1
        if split is Split.HOLDOUT:
            self._transition(theory, TheoryStatus.REGISTERED, "preregistered")
        return entry

    def record_result(self, outcome: TestOutcome, *, work_units: int = 0) -> LedgerEntry:
        if not isinstance(outcome, TestOutcome):
            raise ContractError("record_result takes a TestOutcome")
        theory = self._born(outcome.hypothesis_id)
        found = theory.registration(outcome.registration_id)
        if found is None or found[0].split is not outcome.split:
            self._refuse(
                "refused_result_unregistered",
                f"{outcome.registration_id} is not a PREREGISTER of {outcome.hypothesis_id} "
                f"on {outcome.split.value}",
            )
        if outcome.registration_id in theory.results:
            self._refuse("refused_second_result", f"{outcome.registration_id} already has a result")
        require_non_negative_int(work_units, "work_units")
        entry = self._append(LedgerEventKind.TEST_RESULT, outcome.hypothesis_id, {
            "registration_id": outcome.registration_id, "split": outcome.split.value,
            **_counts_plain(outcome.counts), "p_value": outcome.p_value,
            "survived": outcome.survived, "reasons": list(outcome.reasons),
            "work_units": work_units,
        })
        theory.results[outcome.registration_id] = (outcome, entry.sequence)
        self._remember_tested(theory.genome, found[0].split_digest)
        theory.evidence_for += outcome.counts.true_matches
        theory.evidence_against += outcome.counts.false_matches
        theory.resource_cost += work_units
        for failed in _failed_predictions(found[0].prediction, outcome.counts):
            theory.add(theory.failed_predictions, failed)
        if not outcome.survived:
            theory.refutation = _refutation_kind(outcome.reasons[0])
            theory.refutation_reason = outcome.reasons[0]
        self._n["results"] += 1
        return entry

    def record_identifiability(self, verdict: IdentifiabilityVerdict) -> LedgerEntry:
        theory = self._born(verdict.hypothesis_id)
        if not isinstance(verdict.klass, IdentifiabilityClass):
            raise ContractError(f"verdict.klass is not an IdentifiabilityClass: {verdict.klass!r}")
        entry = self._append(LedgerEventKind.IDENTIFIABILITY, verdict.hypothesis_id, {
            "klass": verdict.klass.value, "members": list(verdict.members),
            "distinguishing_episodes": int(verdict.distinguishing_episodes),
            "reason": _require_reason(verdict.reason),
            "verdict": None if verdict.verdict is None else verdict.verdict.value,
        })
        theory.identifiability = verdict.klass
        self._n["identifiability"] += 1
        return entry

    def set_status(self, hypothesis_id: str, status: TheoryStatus, *, reason: str) -> LedgerEntry:
        theory = self._born(hypothesis_id)
        if not isinstance(status, TheoryStatus):
            raise ContractError(f"status must be a TheoryStatus, got {status!r}")
        _require_reason(reason)
        if status is TheoryStatus.REGISTERED:
            self._refuse("refused_illegal_transition", "REGISTERED is reached only by preregister")
        self._require_evidence(theory, status)
        return self._transition(theory, status, reason)

    # --- queries --------------------------------------------------------------------------

    def status(self, hypothesis_id: str) -> TheoryStatus:
        theory = self._theories.get(hypothesis_id)
        if theory is not None:
            return theory.status
        tombstone = self._tombstones.get(hypothesis_id)
        if tombstone is not None:
            return tombstone
        folded = None if self._memory is None else self._memory.result_for_hypothesis(hypothesis_id)
        if folded is not None:
            return folded.status
        raise LedgerError(f"{hypothesis_id} is not in the ledger")

    def genome(self, hypothesis_id: str) -> HypothesisGenome:
        return self._known(hypothesis_id).genome

    def record(self, hypothesis_id: str) -> TheoryRecord:
        return self._known(hypothesis_id).view()

    def hypothesis_ids(self, status: TheoryStatus | None = None) -> tuple[str, ...]:
        """Retained ids in birth order, optionally only those with ``status``."""
        return tuple(
            hid for hid, theory in self._theories.items()
            if status is None or theory.status is status
        )

    def preregistration(self, registration_id: str) -> PreRegistration | None:
        """The PREREGISTER behind ``registration_id``, or ``None`` if there is none."""
        owner = self._registration_owner.get(registration_id)
        found = None if owner is None else self._theories[owner].registration(registration_id)
        return None if found is None else found[0]

    def outcome(self, registration_id: str) -> TestOutcome | None:
        owner = self._registration_owner.get(registration_id)
        if owner is None:
            return None
        found = self._theories[owner].results.get(registration_id)
        return None if found is None else found[0]

    def registered_before_tested(self, hypothesis_id: str) -> bool:
        """True iff the id has ≥ 1 test result and each came after its own PREREGISTER.

        An untested id answers False: there is nothing to vouch for, and a vacuous True is
        exactly the kind of pass this project has learned not to trust.
        """
        theory = self._known(hypothesis_id)
        if not theory.results:
            return False
        for registration_id, (_, result_sequence) in theory.results.items():
            found = theory.registration(registration_id)
            if found is None or not found[1] < result_sequence:
                return False
        return True

    def entries(self) -> tuple[LedgerEntry, ...]:
        return tuple(self._entries)

    def verify_chain(self) -> tuple[str, ...]:
        """Re-derive every retained digest from the anchor. ``()`` is the only pass."""
        problems: list[str] = []
        previous, expected = self._anchor, self._head_sequence
        for entry in self._entries:
            if entry.sequence != expected:
                problems.append(f"sequence {entry.sequence} where {expected} was expected")
            if entry.previous_digest != previous:
                problems.append(f"entry {entry.sequence} does not chain to its predecessor")
            if entry.recomputed_digest() != entry.entry_digest:
                problems.append(f"entry {entry.sequence} content does not match its digest")
            previous, expected = entry.entry_digest, entry.sequence + 1
        checkpoints = [e for e in self._entries if e.kind is LedgerEventKind.CHECKPOINT]
        if checkpoints:
            latest = checkpoints[-1].payload
            if latest.get("last_sequence") == self._head_sequence - 1 and latest.get(
                "anchor_digest"
            ) != self._anchor:
                problems.append("the latest checkpoint's anchor is not the chain's anchor")
        elif self._head_sequence != 0 or self._anchor != GENESIS_DIGEST:
            problems.append("entries were dropped but no checkpoint records it")
        return tuple(problems)

    def stats(self) -> Mapping[str, int]:
        counters = dict(self._n)
        counters["entries"] = len(self._entries)
        counters["theories"] = len(self._theories)
        counters["tombstones"] = len(self._tombstones)
        counters["capacity"] = self._capacity
        counters["record_items_overflow"] = sum(t.overflow for t in self._theories.values())
        return MappingProxyType(counters)

    def memory_bytes(self) -> int:
        entries = sum(
            sys.getsizeof(e) + len(canonical_bytes(e.payload)) + 2 * (7 + _DIGEST_HEX)
            for e in self._entries
        )
        theories = sum(
            sys.getsizeof(t) + len(t.genome.canonical_bytes())
            + 64 * (len(t.registrations) + len(t.results))
            + sum(sys.getsizeof(s) for s in (
                *t.experiments, *t.failed_predictions, *t.counterexamples, *t.revisions
            ))
            for t in self._theories.values()
        )
        return (
            entries + theories + sys.getsizeof(self._entries) + sys.getsizeof(self._theories)
            + sys.getsizeof(self._registration_owner) + 80 * len(self._registration_owner)
            + sys.getsizeof(self._tombstones) + 96 * len(self._tombstones)
            + sys.getsizeof(self._tested_on_split) + 200 * len(self._tested_on_split)
        )

    # --- internals ------------------------------------------------------------------------

    def _refuse(self, counter: str, message: str) -> NoReturn:
        self._n[counter] += 1
        raise LedgerError(message)

    def _born(self, hypothesis_id: str) -> _Theory:
        theory = self._theories.get(hypothesis_id) if isinstance(hypothesis_id, str) else None
        if theory is None:
            self._refuse("refused_unborn", f"{hypothesis_id!r} is not born here (or was folded)")
        return theory

    def _known(self, hypothesis_id: str) -> _Theory:
        theory = self._theories.get(hypothesis_id)
        if theory is None:
            raise LedgerError(f"{hypothesis_id!r} has no retained record in this ledger")
        return theory

    def _require_evidence(self, theory: _Theory, status: TheoryStatus) -> None:
        """A status the ledger's own entries do not back is refused as an illegal transition."""
        hid = theory.genome.hypothesis_id
        if status in (TheoryStatus.SURVIVED, TheoryStatus.FALSIFIED):
            outcome = theory.result_on(Split.HOLDOUT)
            if outcome is None or outcome.survived != (status is TheoryStatus.SURVIVED):
                self._refuse(
                    "refused_illegal_transition",
                    f"{hid}: {status.value} needs a HOLDOUT test result that agrees",
                )
        elif status is TheoryStatus.REPRODUCED:
            outcome = theory.result_on(Split.REPLICATION)
            if outcome is None or not outcome.survived:
                self._refuse(
                    "refused_illegal_transition",
                    f"{hid}: REPRODUCED needs a surviving REPLICATION test result",
                )
        elif status is TheoryStatus.CHALLENGED_OUT and theory.challenges_failed == 0:
            self._refuse(
                "refused_illegal_transition", f"{hid}: CHALLENGED_OUT needs a failed challenge"
            )

    def _transition(self, theory: _Theory, status: TheoryStatus, reason: str) -> LedgerEntry:
        current = theory.status
        if status not in _LEGAL.get(current, frozenset()):
            self._refuse(
                "refused_illegal_transition",
                f"{theory.genome.hypothesis_id}: {current.value} -> {status.value} is not legal",
            )
        entry = self._append(LedgerEventKind.STATUS, theory.genome.hypothesis_id, {
            "from": current.value, "to": status.value, "reason": reason,
        })
        theory.status = status
        if status in _REPRODUCIBILITY:
            theory.reproducibility = ReproducibilityStatus[status.name]
        if status in _FOLDABLE and theory.refutation_reason == "":
            theory.refutation_reason = reason
        if status in _FOLDABLE and self._memory is not None:
            self._memory.remember(self._negative(theory, entry.sequence))
            self._n["negative_results_written"] += 1
        self._n["status_changes"] += 1
        return entry

    def _negative(self, theory: _Theory, sequence: int) -> NegativeResult:
        return NegativeResult(
            mechanism_digest=theory.genome.proposed_mechanism.digest(),
            hypothesis_id=theory.genome.hypothesis_id,
            status=theory.status,
            refutation=theory.refutation,
            reason=theory.refutation_reason or theory.status.value,
            counterexample_ids=tuple(theory.counterexamples[:4]),
            recorded_sequence=sequence,
            direction=theory.genome.direction,
        )

    def _fold_one(self) -> bool:
        """Drop the oldest foldable record. Its negative result was written when it ended."""
        for hid, theory in self._theories.items():
            if theory.status in _FOLDABLE:
                del self._theories[hid]
                for registration, _ in theory.registrations.values():
                    self._registration_owner.pop(registration.registration_id, None)
                self._entomb(hid, theory.status)
                self._n["theories_folded"] += 1
                return True
        return False

    @staticmethod
    def _reading_key(genome: HypothesisGenome, split_digest: str) -> tuple[str, str, str]:
        return split_digest, genome.proposed_mechanism.digest(), genome.direction.value

    def _remember_tested(self, genome: HypothesisGenome, split_digest: str) -> None:
        key = self._reading_key(genome, split_digest)
        self._tested_on_split[key] = genome.hypothesis_id
        if len(self._tested_on_split) > MAX_TOMBSTONES:
            self._tested_on_split.popitem(last=False)
            self._n["tested_on_split_evicted"] += 1

    def _entomb(self, hypothesis_id: str, status: TheoryStatus) -> None:
        """Remember that a folded id existed and how it ended (bounded, eviction counted)."""
        if len(self._tombstones) >= MAX_TOMBSTONES:
            self._tombstones.popitem(last=False)
            self._n["tombstones_evicted"] += 1
        self._tombstones[hypothesis_id] = status

    def _append(
        self, kind: LedgerEventKind, hypothesis_id: str, payload: Mapping[str, Any]
    ) -> LedgerEntry:
        if len(self._entries) >= self._capacity - 1:
            self._drop_head()
        return self._push(kind, hypothesis_id, payload)

    def _push(
        self, kind: LedgerEventKind, hypothesis_id: str, payload: Mapping[str, Any]
    ) -> LedgerEntry:
        frozen = freeze_plain(plain_data(payload))
        previous = self._entries[-1].entry_digest if self._entries else self._anchor
        sequence = self._next_sequence
        entry = LedgerEntry(
            sequence=sequence, kind=kind, hypothesis_id=hypothesis_id, payload=frozen,
            previous_digest=previous,
            entry_digest=_entry_digest(sequence, kind, hypothesis_id, frozen, previous),
        )
        self._entries.append(entry)
        self._next_sequence += 1
        return entry

    def _drop_head(self) -> None:
        """Drop the oldest quarter of the window and record the drop in a CHECKPOINT."""
        count = max(2, self._capacity // 4)
        dropped = [self._entries.popleft() for _ in range(min(count, len(self._entries)))]
        self._anchor = dropped[-1].entry_digest
        self._head_sequence = dropped[-1].sequence + 1
        self._n["entries_dropped"] += len(dropped)
        self._n["checkpoints"] += 1
        self._push(LedgerEventKind.CHECKPOINT, "", {
            "dropped": len(dropped), "first_sequence": dropped[0].sequence,
            "last_sequence": dropped[-1].sequence, "anchor_digest": self._anchor,
        })
