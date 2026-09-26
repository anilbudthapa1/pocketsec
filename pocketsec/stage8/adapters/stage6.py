"""D8.17 / PROM-F20 — the ONE module that hands anything from Stage 8 to Stage 6.

Research has no production authority. A Stage 8 discovery may reach an endpoint only as a
candidate that Stage 6's own gates judge, and Stage 6 has no capsule kind that carries a
detector (ADR-0056: candidate kinds are exactly those with an executor). So this adapter
hands over **evidence, never the discovery**: for a verified, REPRODUCED
``DiscoveryPackageV1`` it builds one ``TRANSITION_EPISODE`` capsule per supporting
REPLICATION session (at most :data:`MAX_CAPSULES_PER_PACKAGE`) with Stage 6's own
``capsule_from_scenario``, labelled **by inference** under one declared source, and passes
each to ``QuarantineGateway.admit`` — Stage 6's single admission function — and to nothing
else. Whatever Stage 6 decides is recorded verbatim beside the provenance score Stage 6's
``score_provenance`` predicts. ``TRUSTED_CANDIDATE`` is counted, never acted on.

What the adapter refuses, each a ``ContractError`` and a counter:

* a package that is not a ``DiscoveryPackageV1``, or has any ``verify_package`` problem;
* a theory that is not ``REPRODUCED`` (a SURVIVED-only or INSUFFICIENT_EVIDENCE theory has
  not earned even a candidacy);
* a theory whose REPRODUCED status is only the package's own claim: the adapter holds the run's
  ``TheoryLedger`` and refuses a package whose hypothesis the ledger does not hold as
  ``REPRODUCED``, or whose genome, mechanism or direction is not the ledger's (S8-AUTH-01; a
  hand-built package, or one for a theory the vault killed, never reaches the door);
* a package whose evidence ids are empty, absent from ``evidence``, or do not re-derive from
  the raw ``ScenarioResult`` they name (the lineage check: the steps Stage 6 will see must
  be the steps Stage 8 measured);
* an evidence session the package's mechanism does not match, whose lab label disagrees with
  the package's direction, or whose evidence digests the package does not list (S8-AUTH-01:
  a MALICIOUS vote is only ever cast on a session Stage 8 measured as a malicious match);
* an evidence session another Stage 8 run (another independence group) already handed to the
  same gateway: two runs voting on one session would manufacture Stage 6's label quorum from
  Stage 8 alone (S8-AUTH-01). Bounded per gateway, evictions counted;
* synthetic data handed to an adapter not declared synthetic (``SIMULATED_RECORD`` would be
  missing, and the provenance score would overstate the evidence).

What never enters Stage 6: the mechanism, the compiled artifact, the tournament, the genome.
``capsule_from_scenario`` never reads ``result.scenario``, so the lab label cannot ride in
by the side door either; the only label is an explicit ``LabelAssertion`` of origin
``INFERENCE``, which agrees with the ``DERIVED_INFERENCE`` provenance.

**One independence group per run** (``"stage8:" + run_id``). Stage 8 never mints groups to
manufacture a label quorum: that would be a second promotion gate built by the sender
(ADR-0067 option B, ADR-0071). Measured before this was written (spec §0 M0.2): Stage 6 puts
such capsules in ``UNCERTAIN`` (``awaiting_label_quorum``), and with ``SIMULATED_RECORD`` the
provenance score falls to 0.4 < 0.5. Realised adoption of a Stage 8 discovery is therefore 0
by construction under Stage 6's current parameters (blocker B8-1, ADR-0076).

Every capsule is built before any is admitted, so a build failure admits nothing, and
``created() == admitted()`` holds after every completed hand-over. If Stage 6 raises part-way
through the admits, the capsules already admitted keep their lineage: a partial receipt is
recorded (``partial_hand_overs``), ``created`` counts only what was offered, and the error is
re-raised (S8-LIN-06). Receipts are a bounded ring with evictions counted.
"""

from __future__ import annotations

from collections import Counter, OrderedDict, deque
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from weakref import WeakKeyDictionary

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage1.epoch.model import Epoch
from pocketsec.stage1.pipeline import ScenarioResult
from pocketsec.stage6.capsule.experience_capsule import (
    ContaminationFlag,
    ExperienceCapsuleV1,
    LabelAssertion,
    LabelOrigin,
    SourceClass,
    SourceProvenance,
    capsule_from_scenario,
    reseal_capsule,
)
from pocketsec.stage6.capsule.quarantine import (
    QuarantineBucket,
    QuarantineGateway,
    QuarantineVerdict,
)
from pocketsec.stage6.provenance.trust import score_provenance
from pocketsec.stage8.episode import EpisodeContext, Split, episode_from_result
from pocketsec.stage8.forge.package import (
    DiscoveryPackageV1,
    ReproducibilityStatus,
    verify_package,
)
from pocketsec.stage8.genome.hypothesis import Direction
from pocketsec.stage8.ledger.theory import LedgerError, TheoryLedger, TheoryStatus

__all__ = [
    "MAX_ADAPTER_RECEIPTS",
    "MAX_CAPSULES_PER_PACKAGE",
    "MAX_HANDED_EVIDENCE",
    "STAGE8_CORPUS_TAG",
    "STAGE8_SOURCE_ID",
    "AdapterReceipt",
    "Stage6Adapter",
]

#: §4.21 — chosen parameters, not measurements.
MAX_CAPSULES_PER_PACKAGE: int = 8
MAX_ADAPTER_RECEIPTS: int = 1024
STAGE8_SOURCE_ID = "stage8-prometheus"
#: The corpus tag of the episodes this adapter re-derives for the lineage check only.
STAGE8_CORPUS_TAG = "stage8-adapter"

#: Evidence sessions remembered per gateway for the cross-run duplicate refusal. Chosen.
MAX_HANDED_EVIDENCE: int = 65536

_VERDICT: Mapping[Direction, Verdict] = MappingProxyType(
    {Direction.MALICIOUS: Verdict.MALICIOUS, Direction.BENIGN: Verdict.BENIGN})
_LAB_LABEL: Mapping[Direction, int] = MappingProxyType({Direction.MALICIOUS: 1,
                                                        Direction.BENIGN: 0})

#: Per gateway: evidence episode id -> the independence group that handed it over. Keyed weakly
#: by the gateway so a gateway's record dies with it; one gateway, one record, whichever run's
#: adapter holds it (S8-AUTH-01: a second group voting on one session is refused).
_HANDED: WeakKeyDictionary[QuarantineGateway, OrderedDict[str, str]] = WeakKeyDictionary()


@dataclass(frozen=True, slots=True)
class AdapterReceipt:
    """What was handed to Stage 6 for one package, and what Stage 6 said — verbatim."""

    package_id: str
    capsule_ids: tuple[str, ...]
    verdict_ids: tuple[str, ...]
    stage6_buckets: tuple[str, ...]  # QuarantineBucket values as returned; never reinterpreted
    predicted_provenance_scores: tuple[float, ...]  # score_provenance, beside the bucket
    trusted_candidates: int  # how many Stage 6 put in TRUSTED_CANDIDATE: counted, never acted on
    # Appended (integrator): capsules sealed with SIMULATED_RECORD, so the gate reads the flag
    # off the capsules actually admitted rather than off the adapter's constructor argument.
    simulated_records: int = 0
    capsule_kinds: tuple[str, ...] = ()  # each admitted capsule's CapsuleKind value, verbatim


class Stage6Adapter:
    """PROM-F20. The only caller of ``QuarantineGateway.admit`` in Stage 8."""

    def __init__(
        self,
        *,
        gateway: QuarantineGateway,
        ledger: TheoryLedger,
        epoch: Epoch,
        run_id: str,
        host_id: str,
        synthetic: bool,
        capacity: int = MAX_ADAPTER_RECEIPTS,
    ) -> None:
        # The gateway arrives already bound to the host's trusted view by whoever owns it;
        # Stage 8 never constructs a controller and never binds anything.
        if not isinstance(gateway, QuarantineGateway):
            raise ContractError("the adapter hands capsules to a Stage 6 QuarantineGateway only")
        if not isinstance(ledger, TheoryLedger):
            raise ContractError("the adapter needs the run's TheoryLedger: REPRODUCED is the "
                                "ledger's status, never the package's claim")
        if not isinstance(epoch, Epoch):
            raise ContractError("epoch must be the LOCAL Stage 1 Epoch")
        require_identifier(run_id, "run_id")
        require_identifier(host_id, "host_id")
        if not isinstance(synthetic, bool):
            raise ContractError("synthetic must be a bool")
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 1:
            raise ContractError("capacity must be a positive int")
        self._gateway = gateway
        self._ledger = ledger
        self._epoch = epoch
        self._group = "stage8:" + run_id
        require_identifier(self._group, "independence_group")
        self._host_id = host_id
        self._synthetic = synthetic
        self._receipts: deque[AdapterReceipt] = deque(maxlen=capacity)
        self._n: Counter[str] = Counter()
        self._buckets: Counter[str] = Counter()

    @property
    def independence_group(self) -> str:
        """The one group every capsule of this run carries (never minted per package)."""
        return self._group

    # --- the hand-over ----------------------------------------------------------------

    def hand_over(self, package: DiscoveryPackageV1, *, evidence: Mapping[str, ScenarioResult],
                  sequence: int) -> AdapterReceipt:
        """Refuse, or build every capsule and then admit each. See the module docstring."""
        require_non_negative_int(sequence, "sequence")
        self._check_package(package)
        self._check_ledger(package)
        ids = package.evidence_episode_ids[:MAX_CAPSULES_PER_PACKAGE]
        results = [self._evidence_for(episode_id, evidence, package) for episode_id in ids]
        self._check_not_handed(ids)
        capsules = self._build(package, results, sequence)
        verdicts: list[QuarantineVerdict] = []
        try:
            for capsule in capsules:
                self._n["created"] += 1
                verdicts.append(self._gateway.admit(capsule))
                self._n["admitted"] += 1
        except Exception:
            # S8-LIN-06: what Stage 6 already admitted keeps a receipt (and so its lineage).
            self._n["partial_hand_overs"] += 1
            self._record(package, capsules[:len(verdicts)], verdicts, ids[:len(verdicts)])
            raise
        return self._record(package, capsules, verdicts, ids)

    def _record(self, package: DiscoveryPackageV1, capsules: tuple[ExperienceCapsuleV1, ...],
                verdicts: list[QuarantineVerdict], ids: tuple[str, ...]) -> AdapterReceipt:
        handed = _HANDED.setdefault(self._gateway, OrderedDict())
        for episode_id in ids:
            handed[episode_id] = self._group
            if len(handed) > MAX_HANDED_EVIDENCE:
                handed.popitem(last=False)
                self._n["handed_evidence_evicted"] += 1
        buckets = tuple(verdict.bucket.value for verdict in verdicts)
        self._buckets.update(buckets)
        receipt = AdapterReceipt(
            package_id=package.package_id,
            capsule_ids=tuple(capsule.capsule_id for capsule in capsules),
            verdict_ids=tuple(verdict.verdict_id for verdict in verdicts),
            stage6_buckets=buckets,
            predicted_provenance_scores=tuple(score_provenance(c).score for c in capsules),
            trusted_candidates=sum(
                1 for verdict in verdicts if verdict.bucket is QuarantineBucket.TRUSTED_CANDIDATE),
            simulated_records=sum(1 for c in capsules
                                  if ContaminationFlag.SIMULATED_RECORD in c.contamination_flags),
            capsule_kinds=tuple(capsule.kind.value for capsule in capsules),
        )
        self._n["handed_over"] += 1
        self._n["trusted_candidates"] += receipt.trusted_candidates
        if len(self._receipts) == self._receipts.maxlen:
            self._n["receipts_evicted"] += 1
        self._receipts.append(receipt)
        return receipt

    def _refuse(self, counter: str, message: str) -> ContractError:
        self._n[counter] += 1
        return ContractError(message)

    def _check_package(self, package: DiscoveryPackageV1) -> None:
        if not isinstance(package, DiscoveryPackageV1):
            raise self._refuse("refused_type", f"hand_over takes a DiscoveryPackageV1, not "
                               f"{type(package).__name__}")
        problems = verify_package(package)
        if problems:
            raise self._refuse("refused_unverified", f"package fails verification: {problems[0]}")
        status = package.reproducibility.status
        if status is not ReproducibilityStatus.REPRODUCED:
            raise self._refuse("refused_not_reproduced",
                               f"only a REPRODUCED theory is handed to Stage 6, not {status}")
        if package.synthetic_data and not self._synthetic:
            raise self._refuse("refused_synthetic_unflagged",
                               "synthetic evidence needs an adapter declared synthetic "
                               "(SIMULATED_RECORD must be set)")
        if not package.evidence_episode_ids:
            raise self._refuse("refused_unevidenced", "the package names no evidence episode")

    def _check_ledger(self, package: DiscoveryPackageV1) -> None:
        """REPRODUCED, genome, mechanism and direction are the LEDGER's, not the package's."""
        hid = package.hypothesis_id
        try:
            status = self._ledger.status(hid)
            genome = self._ledger.genome(hid)
        except LedgerError as exc:
            raise self._refuse("refused_not_in_ledger",
                               f"{hid} has no retained record in the run's ledger") from exc
        if status is not TheoryStatus.REPRODUCED:
            raise self._refuse("refused_ledger_not_reproduced",
                               f"the ledger holds {hid} as {status.value}, not REPRODUCED")
        if (dict(package.artifact_hashes).get("genome") != genome.digest()
                or package.mechanism.digest() != genome.proposed_mechanism.digest()
                or package.direction is not genome.direction):
            raise self._refuse("refused_ledger_mismatch",
                               f"the package for {hid} is not the ledger's genome")

    def _check_not_handed(self, ids: tuple[str, ...]) -> None:
        handed = _HANDED.get(self._gateway, {})
        other = [i for i in ids if handed.get(i, self._group) != self._group]
        if other:
            raise self._refuse("refused_evidence_other_run",
                               f"{other[0]} was already handed to this gateway by "
                               f"{handed[other[0]]}: a second group would manufacture a quorum")

    def _evidence_for(self, episode_id: str, evidence: Mapping[str, ScenarioResult],
                      package: DiscoveryPackageV1) -> ScenarioResult:
        """The raw result for one evidence id, re-derived to prove it is that episode, that the
        package's mechanism matches it, that its lab label is the package's direction, and
        that its evidence digests are the package's (S8-AUTH-01)."""
        result = evidence.get(episode_id) if isinstance(evidence, Mapping) else None
        if not isinstance(result, ScenarioResult):
            raise self._refuse("refused_missing_evidence",
                               f"evidence episode {episode_id} has no raw ScenarioResult")
        context = EpisodeContext(self._host_id, 0, "", STAGE8_CORPUS_TAG, self._synthetic)
        derived = episode_from_result(result, split=Split.REPLICATION, context=context,
                                      label=None)
        if derived.episode_id != episode_id:
            raise self._refuse("refused_lineage_mismatch",
                               f"the result given for {episode_id} re-derives to "
                               f"{derived.episode_id}")
        if not package.mechanism.matches(derived.steps):
            raise self._refuse("refused_evidence_not_matched",
                               f"the package's mechanism does not match evidence {episode_id}")
        if result.scenario.label != _LAB_LABEL[package.direction]:
            raise self._refuse("refused_evidence_label",
                               f"evidence {episode_id} is labelled {result.scenario.label}, not "
                               f"{package.direction.value}")
        if not set(derived.evidence_digests()) <= set(package.evidence_digests):
            raise self._refuse("refused_evidence_digest",
                               f"evidence {episode_id} carries digests the package does not list")
        return result

    def _build(self, package: DiscoveryPackageV1, results: list[ScenarioResult],
               sequence: int) -> tuple[ExperienceCapsuleV1, ...]:
        """Every capsule BEFORE any admit, so a failure here admits nothing."""
        provenance = SourceProvenance(
            source_class=SourceClass.DERIVED_INFERENCE,
            source_id=STAGE8_SOURCE_ID,
            independence_group=self._group,
            label_origin=LabelOrigin.INFERENCE,
            transformation_lineage=("stage8", package.package_id[:24]),
            host_id=self._host_id,
        )
        label = LabelAssertion(verdict=_VERDICT[package.direction], origin=LabelOrigin.INFERENCE,
                               asserted_by=self._group, target_capsule_id="")
        built: list[ExperienceCapsuleV1] = []
        for offset, result in enumerate(results):
            capsule = capsule_from_scenario(result, epoch=self._epoch, provenance=provenance,
                                            sequence=sequence + offset, label=label)
            if self._synthetic:
                capsule = reseal_capsule(capsule, contamination_flags=(
                    capsule.contamination_flags | {ContaminationFlag.SIMULATED_RECORD}))
            built.append(capsule)
        return tuple(built)

    # --- reporting --------------------------------------------------------------------

    def created(self) -> int:
        return self._n["created"]

    def admitted(self) -> int:
        return self._n["admitted"]

    def receipts(self) -> tuple[AdapterReceipt, ...]:
        return tuple(self._receipts)

    def buckets(self) -> Mapping[str, int]:
        """Stage 6's bucket values as returned, counted; every bucket named, zeros included."""
        return MappingProxyType({bucket.value: self._buckets[bucket.value]
                                 for bucket in QuarantineBucket})

    def stats(self) -> Mapping[str, int]:
        counters = dict(self._n)
        counters.setdefault("created", 0)
        counters.setdefault("admitted", 0)
        counters["receipts"] = len(self._receipts)
        counters["refused"] = sum(v for k, v in self._n.items() if k.startswith("refused_"))
        return MappingProxyType(counters)
