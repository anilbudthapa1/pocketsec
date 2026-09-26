"""D9.17 — the Proof-Carrying Successor Package: a candidate that carries its own evidence.

Stage 9 searches; it never deploys (MEMORY.md: research components have no production
authority). What a search produces is therefore a *candidate* that a later gate can check
without trusting Stage 9: the genome, the static contract it satisfies, the held-out
metrics, the counterexamples, the invariance results, and the parent genome to roll back
to. Architecture §53 (ComputationContract) and §54 (SuccessorPackage) name every field;
each is bound here.

What construction refuses (``ProofCarryingSuccessorV1.__post_init__``):

* a payload that is not strict JSON (``NaN`` included), because a digest over a value two
  readers serialise differently certifies nothing;
* any key that :func:`forbidden_authority_keys` flags, anywhere in the package. A successor
  that says ``suggested_action`` is a model output reaching for authority (ADR-0003);
* a ``genome_digest`` that is not the genome's recomputed digest, a contract the genome
  violates, a rollback parent whose digest does not match, and a signature that is not the
  content digest.

**Integrity, not authenticity (ADR-0088).** The signature is ``sha256`` over the canonical
content. It detects an edit that was not re-signed. It cannot detect an edit whose author
recomputed the digest, because no key is involved: :func:`tampered_successor` says so in its
finding, and the test suite proves the re-signed edit is accepted. A later gate that needs
authenticity must add it; this module does not pretend to.

**Rollback lives in Stage 9's own lab registry.** :class:`CandidateRegistry` holds genomes
for experiments only. Stage 6 has no candidate kind that can execute a genome (ADR-0056,
blocker B9-2), so nothing here installs anything anywhere that matters. The one exit to
Stage 6 is ``successor/stage6_exit.py`` (ADR-0081), which this module never imports:
importing Stage 6's capsule package loads 27 Stage 5 modules (M0.9).
"""

from __future__ import annotations

import copy
import dataclasses
import json
import math
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Protocol

from pocketsec.stage0.contracts.common import ContractError, digest_of_bytes, register_schema
from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS
from pocketsec.stage0.experiments.ids import parse_experiment_id
from pocketsec.stage2.compile_candidates.candidate import forbidden_authority_keys
from pocketsec.stage9.argus.adversary import ArgusFinding, ArgusSurface
from pocketsec.stage9.chemistry.typed_ir import MAX_SESSION_EVENTS
from pocketsec.stage9.daedalus.synthesizer import SynthesizedSystem
from pocketsec.stage9.foundry.primitives import SEED_ALPHABET
from pocketsec.stage9.genome.computational import (
    ComputationalGenomeV1,
    EvidenceSemantics,
    LearningLaw,
    build_genome,
)
from pocketsec.stage9.ontogenesis.fitness import FitnessRecord

__all__ = [
    "CONTENT_SIGNATURE_ALGORITHM",
    "FAILURE_BEHAVIOR_ABSTAIN",
    "MAX_COUNTEREXAMPLES",
    "MAX_REGISTRY",
    "PROOF_CARRYING_SUCCESSOR_V1_ID",
    "PROOF_CARRYING_SUCCESSOR_V1_VERSION",
    "SUCCESSOR_KEYS",
    "CandidateRegistry",
    "ComputationContract",
    "InstallReceipt",
    "ProofCarryingSuccessorV1",
    "RegistryEvent",
    "RollbackArtifact",
    "build_successor",
    "content_digest",
    "tampered_successor",
]

PROOF_CARRYING_SUCCESSOR_V1_ID = "pocketsec.proof_carrying_successor.v1"
PROOF_CARRYING_SUCCESSOR_V1_VERSION = register_schema(PROOF_CARRYING_SUCCESSOR_V1_ID, "1.0.0")

MAX_COUNTEREXAMPLES = 64
MAX_REGISTRY = 64
CONTENT_SIGNATURE_ALGORITHM = "sha256-content"
#: The only failure behaviour a phenotype has: fewer events than it needs -> no score.
FAILURE_BEHAVIOR_ABSTAIN = "ABSTAIN_UNKNOWN"
_METRIC_KEYS = ("heldout_worst_case_ap", "heldout_clean_ap", "train_worst_case_ap", "gap",
                "base_rate")
SUCCESSOR_KEYS = frozenset({
    "schema", "schema_version", "computational_genome", "genome_digest", "parent_lineage",
    "mutation_set", "executable_artifacts", "contracts", "measured_resources",
    "security_metrics", "counterexample_suite", "invariance_suite", "uncertainty_profile",
    "failure_domains", "rollback_artifact", "signatures", "synthetic_data", "experiment_id",
})


class _Measurement(Protocol):
    """What a successor needs from ``harness.hardware_in_loop.HardwareMeasurement``."""

    def to_dict(self) -> dict[str, Any]: ...


# --- JSON normalisation and freezing -----------------------------------------------------------


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, allow_nan=False,
                          separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ContractError(f"successor payload is not strict JSON: {exc}") from exc


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _thaw(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw(v) for v in value]
    return value


def _freeze(value: Any) -> Any:
    """Deep read-only copy: a frozen dataclass holding a live dict is not frozen."""
    if isinstance(value, Mapping):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(v) for v in value)
    return value


def _json_mapping(value: Any, what: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractError(f"{what} must be a mapping, got {type(value).__name__}")
    normal = json.loads(_canonical(_thaw(value)))
    return _freeze(normal)  # type: ignore[no-any-return]


# --- the contract ------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ComputationContract:
    """Architecture §53: what a phenotype promises, every figure static or UNMEASURED."""

    max_rss: int                          # = session_state_bytes_max (phenotype bytes)
    max_cpu_window: int                   # = session_wu_max (work units, not seconds)
    max_event_latency_us: float | None    # None = UNMEASURED; never a guess
    max_queue: int                        # = MAX_SESSION_EVENTS
    required_sensors: tuple[str, ...]     # InputSource names the genome reads
    failure_behavior: str                 # "ABSTAIN_UNKNOWN"
    evidence_guarantee: str               # "WINNING_LINEAGE_LOCATORS"
    offline_guarantee: bool               # no file/network/process primitive exists
    forbidden_authority_edges: tuple[str, ...]   # sorted(FORBIDDEN_AUTHORITY_FIELDS)

    def __post_init__(self) -> None:
        for name in ("max_rss", "max_cpu_window", "max_queue"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ContractError(f"ComputationContract.{name} must be an int >= 0")
        latency = self.max_event_latency_us
        if latency is not None and (not isinstance(latency, float) or not math.isfinite(latency)
                                    or latency <= 0.0):
            raise ContractError("max_event_latency_us must be None (UNMEASURED) or > 0")
        object.__setattr__(self, "required_sensors", tuple(self.required_sensors))
        object.__setattr__(self, "forbidden_authority_edges",
                           tuple(self.forbidden_authority_edges))

    @classmethod
    def for_genome(cls, genome: ComputationalGenomeV1) -> ComputationContract:
        """The tightest contract a genome's static bounds support. Latency stays None:
        a host-contended wall-clock figure is not a device bound (spec §2.7)."""
        bounds = genome.bounds
        return cls(
            max_rss=bounds.session_state_bytes_max,
            max_cpu_window=bounds.session_wu_max,
            max_event_latency_us=None,
            max_queue=MAX_SESSION_EVENTS,
            required_sensors=tuple(sorted({s.value for s, _ in genome.observation_map})),
            failure_behavior=FAILURE_BEHAVIOR_ABSTAIN,
            evidence_guarantee=EvidenceSemantics.WINNING_LINEAGE_LOCATORS.value,
            offline_guarantee=True,
            forbidden_authority_edges=tuple(sorted(FORBIDDEN_AUTHORITY_FIELDS)),
        )

    def check(self, genome: ComputationalGenomeV1) -> tuple[str, ...]:
        """Static violations of this contract by ``genome``; ``()`` is the only pass."""
        bounds = genome.bounds
        found: list[str] = []
        if bounds.session_state_bytes_max > self.max_rss:
            found.append(f"max_rss: static {bounds.session_state_bytes_max} > {self.max_rss}")
        if bounds.session_wu_max > self.max_cpu_window:
            found.append(f"max_cpu_window: static {bounds.session_wu_max} WU > "
                         f"{self.max_cpu_window}")
        if self.max_queue < MAX_SESSION_EVENTS:
            found.append(f"max_queue {self.max_queue} < MAX_SESSION_EVENTS "
                         f"{MAX_SESSION_EVENTS}: the phenotype would read past the contract")
        undeclared = sorted({s.value for s, _ in genome.observation_map}
                            - set(self.required_sensors))
        if undeclared:
            found.append(f"required_sensors: undeclared inputs {undeclared}")
        found += self._semantic_violations(genome)
        return tuple(found)

    def _semantic_violations(self, genome: ComputationalGenomeV1) -> list[str]:
        found: list[str] = []
        if self.failure_behavior != FAILURE_BEHAVIOR_ABSTAIN:
            found.append(f"failure_behavior {self.failure_behavior!r}: the phenotype can only "
                         f"abstain ({FAILURE_BEHAVIOR_ABSTAIN})")
        if self.evidence_guarantee != genome.evidence_semantics.value:
            found.append(f"evidence_guarantee {self.evidence_guarantee!r} != genome "
                         f"{genome.evidence_semantics.value!r}")
        if not self.offline_guarantee:
            found.append("offline_guarantee is False, but the IR has no I/O primitive: the "
                         "contract misdescribes the genome")
        if genome.learning_law is not LearningLaw.NONE:
            found.append(f"learning_law {genome.learning_law.value}: no online learning")
        unknown = sorted(_primitives_used(genome) - set(SEED_ALPHABET.names()))
        if unknown:
            found.append(f"primitives outside the seed alphabet: {unknown}")
        if tuple(sorted(self.forbidden_authority_edges)) != tuple(
                sorted(FORBIDDEN_AUTHORITY_FIELDS)):
            found.append("forbidden_authority_edges is not FORBIDDEN_AUTHORITY_FIELDS: a "
                         "shortened list is a weakened contract")
        return found

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_rss": self.max_rss, "max_cpu_window": self.max_cpu_window,
            "max_event_latency_us": self.max_event_latency_us, "max_queue": self.max_queue,
            "required_sensors": list(self.required_sensors),
            "failure_behavior": self.failure_behavior,
            "evidence_guarantee": self.evidence_guarantee,
            "offline_guarantee": self.offline_guarantee,
            "forbidden_authority_edges": list(self.forbidden_authority_edges),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ComputationContract:
        expected = {f.name for f in dataclasses.fields(cls)}
        if set(payload) != expected:
            differ = sorted(set(payload) ^ expected)
            raise ContractError(f"ComputationContract keys differ: {differ}")
        return cls(**{k: payload[k] for k in expected})


def _primitives_used(genome: ComputationalGenomeV1) -> set[str]:
    return {n.primitive for p in (genome.update, genome.readout) for n in p.nodes if n.primitive}


# --- the package -------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RollbackArtifact:
    """The parent genome, whole, and the digest of its scores on the held-out split."""

    parent_genome: Mapping[str, Any]
    parent_digest: str
    parent_scores_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {"parent_genome": _thaw(self.parent_genome), "parent_digest": self.parent_digest,
                "parent_scores_digest": self.parent_scores_digest}


@dataclass(frozen=True, slots=True)
class ProofCarryingSuccessorV1:
    """Architecture §54. Construction IS verification: an instance that exists passed."""

    computational_genome: Mapping[str, Any]
    genome_digest: str
    parent_lineage: tuple[str, ...]
    mutation_set: tuple[str, ...]
    executable_artifacts: tuple[tuple[str, str], ...]     # ("phenotype", digest)
    contracts: ComputationContract
    measured_resources: Mapping[str, Any] | None           # HardwareMeasurement.to_dict()
    security_metrics: Mapping[str, float | None]
    counterexample_suite: tuple[str, ...]                  # sample_ids, <= MAX_COUNTEREXAMPLES
    invariance_suite: tuple[Mapping[str, Any], ...]
    uncertainty_profile: Mapping[str, Any]
    failure_domains: tuple[str, ...]
    rollback_artifact: RollbackArtifact
    signatures: tuple[tuple[str, str], ...]                # integrity, not authenticity
    synthetic_data: bool = True
    experiment_id: str | None = None
    schema_version: str = PROOF_CARRYING_SUCCESSOR_V1_VERSION

    def __post_init__(self) -> None:
        self._normalise()
        payload = self.to_dict()
        _canonical(payload)
        smuggled = forbidden_authority_keys(payload, prefix="successor")
        if smuggled:
            raise ContractError(f"successor carries authority-named keys: {list(smuggled)}")
        genome = self.genome()
        if genome.digest != self.genome_digest:
            raise ContractError(f"genome_digest {self.genome_digest} != recomputed "
                                f"{genome.digest}")
        violations = self.contracts.check(genome)
        if violations:
            raise ContractError(f"genome violates its own contract: {list(violations)}")
        self._check_rollback()
        self._check_signature(payload)

    def _normalise(self) -> None:
        if self.schema_version != PROOF_CARRYING_SUCCESSOR_V1_VERSION:
            raise ContractError(f"unknown successor schema_version {self.schema_version!r}")
        if not isinstance(self.contracts, ComputationContract):
            raise ContractError("contracts must be a ComputationContract")
        if not isinstance(self.rollback_artifact, RollbackArtifact):
            raise ContractError("rollback_artifact must be a RollbackArtifact")
        if not isinstance(self.synthetic_data, bool):
            raise ContractError("synthetic_data must be a bool")
        if self.experiment_id is not None:
            try:
                parse_experiment_id(self.experiment_id)
            except ValueError as exc:
                raise ContractError(f"experiment_id is not a PocketSec id: {exc}") from exc
        _set = object.__setattr__
        _set(self, "computational_genome",
             _json_mapping(self.computational_genome, "computational_genome"))
        _set(self, "security_metrics", _metrics(self.security_metrics))
        _set(self, "measured_resources", None if self.measured_resources is None
             else _json_mapping(self.measured_resources, "measured_resources"))
        _set(self, "uncertainty_profile",
             _json_mapping(self.uncertainty_profile, "uncertainty_profile"))
        _set(self, "invariance_suite", tuple(_json_mapping(entry, "invariance entry")
                                             for entry in self.invariance_suite))
        for name in ("parent_lineage", "mutation_set", "counterexample_suite", "failure_domains"):
            _set(self, name, tuple(str(v) for v in getattr(self, name)))
        _set(self, "executable_artifacts", _pairs(self.executable_artifacts))
        _set(self, "signatures", _pairs(self.signatures))
        if len(self.counterexample_suite) > MAX_COUNTEREXAMPLES:
            raise ContractError(f"{len(self.counterexample_suite)} counterexamples > "
                                f"MAX_COUNTEREXAMPLES={MAX_COUNTEREXAMPLES}")
        _set(self, "rollback_artifact", RollbackArtifact(
            _json_mapping(self.rollback_artifact.parent_genome, "parent_genome"),
            self.rollback_artifact.parent_digest, self.rollback_artifact.parent_scores_digest))

    def _check_rollback(self) -> None:
        parent = ComputationalGenomeV1.from_dict(_thaw(self.rollback_artifact.parent_genome))
        if parent.digest != self.rollback_artifact.parent_digest:
            raise ContractError(f"rollback parent_digest {self.rollback_artifact.parent_digest} "
                                f"!= the parent genome's {parent.digest}")

    def _check_signature(self, payload: Mapping[str, Any]) -> None:
        if len(self.signatures) != 1 or self.signatures[0][0] != CONTENT_SIGNATURE_ALGORITHM:
            raise ContractError(f"signatures must be exactly (({CONTENT_SIGNATURE_ALGORITHM!r}, "
                                f"digest),); got {self.signatures}")
        expected = content_digest(payload)
        if self.signatures[0][1] != expected:
            raise ContractError(f"signature {self.signatures[0][1]} != content digest {expected}")

    @property
    def content_digest(self) -> str:
        """The digest the signature certifies (also the successor's identity)."""
        return self.signatures[0][1]

    def genome(self) -> ComputationalGenomeV1:
        return ComputationalGenomeV1.from_dict(_thaw(self.computational_genome))

    def to_dict(self) -> dict[str, Any]:
        return _payload({f.name: getattr(self, f.name) for f in dataclasses.fields(self)})

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ProofCarryingSuccessorV1:
        """Rebuild AND re-verify; exact keys, so an extra field cannot ride along."""
        if set(payload) != SUCCESSOR_KEYS:
            raise ContractError(f"successor keys differ: {sorted(set(payload) ^ SUCCESSOR_KEYS)}")
        if payload["schema"] != PROOF_CARRYING_SUCCESSOR_V1_ID:
            raise ContractError(f"not a successor payload: {payload['schema']!r}")
        rollback = payload["rollback_artifact"]
        if not isinstance(rollback, Mapping) or set(rollback) != {
                "parent_genome", "parent_digest", "parent_scores_digest"}:
            raise ContractError("rollback_artifact keys differ")
        return cls(
            computational_genome=payload["computational_genome"],
            genome_digest=payload["genome_digest"],
            parent_lineage=tuple(payload["parent_lineage"]),
            mutation_set=tuple(payload["mutation_set"]),
            executable_artifacts=tuple(tuple(p) for p in payload["executable_artifacts"]),
            contracts=ComputationContract.from_dict(payload["contracts"]),
            measured_resources=payload["measured_resources"],
            security_metrics=payload["security_metrics"],
            counterexample_suite=tuple(payload["counterexample_suite"]),
            invariance_suite=tuple(payload["invariance_suite"]),
            uncertainty_profile=payload["uncertainty_profile"],
            failure_domains=tuple(payload["failure_domains"]),
            rollback_artifact=RollbackArtifact(**rollback),
            signatures=tuple(tuple(p) for p in payload["signatures"]),
            synthetic_data=payload["synthetic_data"],
            experiment_id=payload["experiment_id"],
            schema_version=payload["schema_version"],
        )


def _metrics(value: Any) -> Mapping[str, float | None]:
    if not isinstance(value, Mapping) or set(value) != set(_METRIC_KEYS):
        raise ContractError(f"security_metrics must have exactly {list(_METRIC_KEYS)}")
    out: dict[str, float | None] = {}
    for key in _METRIC_KEYS:
        metric = value[key]
        if metric is not None and (isinstance(metric, bool) or not isinstance(metric, (int, float))
                                   or not math.isfinite(metric)):
            raise ContractError(f"security_metrics.{key} must be a finite number or None")
        out[key] = None if metric is None else float(metric)
    return MappingProxyType(out)


def _pairs(value: Any) -> tuple[tuple[str, str], ...]:
    pairs = tuple(tuple(p) for p in value)
    if any(len(p) != 2 or not all(isinstance(x, str) for x in p) for p in pairs):
        raise ContractError(f"expected (str, str) pairs, got {value!r}")
    return pairs


def content_digest(payload: Mapping[str, Any]) -> str:
    """sha256 over the canonical payload without its signatures."""
    unsigned = {k: v for k, v in payload.items() if k != "signatures"}
    return digest_of_bytes(_canonical(_thaw(unsigned)))


# --- building a successor ----------------------------------------------------------------------


def _security_metrics(train: FitnessRecord, heldout: FitnessRecord,
                      base_rate: float | None) -> dict[str, float | None]:
    gap = None
    if train.worst_case_ap is not None and heldout.worst_case_ap is not None:
        gap = train.worst_case_ap - heldout.worst_case_ap
    return {"heldout_worst_case_ap": heldout.worst_case_ap, "heldout_clean_ap": heldout.clean_ap,
            "train_worst_case_ap": train.worst_case_ap, "gap": gap, "base_rate": base_rate}


def _invariance(tests: Sequence[Any], synth: SynthesizedSystem) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for test in tests:
        if not dataclasses.is_dataclass(test) or isinstance(test, type):
            raise ContractError(f"invariance entries must be SymmetryTest records, got {test!r}")
        entries.append(dataclasses.asdict(test))
    report = synth.metamorphic
    entries.append({"transformation": "daedalus:actor_slot_reversal", "sessions": report.sessions,
                    "score_changed": report.permutation_score_changes, "max_abs_delta": None,
                    "invariant": report.actor_slot_permutation_invariant,
                    "reason": "DAEDALUS metamorphic check (synthesize)"})
    entries.append({"transformation": "daedalus:determinism", "sessions": report.sessions,
                    "score_changed": None, "max_abs_delta": None,
                    "invariant": report.deterministic,
                    "reason": "two fresh phenotypes, same sessions, identical runs"})
    return entries


def _failure_domains(synth: SynthesizedSystem, heldout: FitnessRecord,
                     dropped: int) -> list[str]:
    genome = synth.specialized
    domains = [
        f"sessions with fewer than {genome.min_events_for_score} event(s) abstain (UNKNOWN)",
        f"more than 16 concurrent lineages evict state ({genome.lineage_eviction_policy})",
        f"sessions longer than MAX_SESSION_EVENTS={MAX_SESSION_EVENTS} abstain (UNKNOWN), "
        "overflow counted: padding a session past the bound buys UNKNOWN, not a benign score",
        f"worst held-out variant: {heldout.worst_variant}",
        "calibration UNMEASURED: scores are rankings, not probabilities",
        "evaluated on synthetic, project-authored corpora only",
    ]
    if not synth.pcb.expressible:
        domains.append("not expressible in Stage 3 PCB (M0.10)")
    if synth.metamorphic.actor_slot_permutation_invariant is False:
        domains.append("actor-slot relabelling changes scores")
    if dropped:
        domains.append(f"{dropped} counterexample(s) beyond MAX_COUNTEREXAMPLES were dropped")
    return domains


def _checked_records(synth: SynthesizedSystem, train: FitnessRecord,
                     heldout: FitnessRecord) -> None:
    allowed = {synth.genome_digest, synth.specialized.digest}
    for name, record in (("train", train), ("heldout", heldout)):
        if record.genome_digest not in allowed:
            raise ContractError(f"{name} record is for {record.genome_digest}, not this genome")
    if synth.genome_digest != synth.specialized.digest and \
            not synth.metamorphic.specialization_preserves_scores:
        raise ContractError("specialisation changed scores, so the metrics do not transfer")
    if not synth.unit_checks_passed:
        failed = [name for name, ok in synth.unit_checks if not ok]
        raise ContractError(f"DAEDALUS unit checks failed: {failed}")


def build_successor(synth: SynthesizedSystem, *, train: FitnessRecord, heldout: FitnessRecord,
                    parent: ComputationalGenomeV1, parent_scores_digest: str,
                    counterexamples: Sequence[str], invariance: Sequence[Any],
                    measured: _Measurement | None, experiment_id: str | None,
                    base_rate: float | None = None) -> ProofCarryingSuccessorV1:
    """Assemble and sign a successor from DAEDALUS output and its fitness evidence.

    ``base_rate`` is an addition to the §4.18 signature (the spec lists ``base_rate`` among
    the metrics but gives no parameter for it); None means UNMEASURED.
    """
    _checked_records(synth, train, heldout)
    genome = synth.specialized
    kept = tuple(sorted(dict.fromkeys(counterexamples)))
    lineage = dict.fromkeys((*genome.parent_digests, synth.genome_digest, parent.digest))
    lineage.pop(genome.digest, None)
    fields: dict[str, Any] = {
        "computational_genome": genome.to_dict(), "genome_digest": genome.digest,
        "parent_lineage": tuple(lineage),
        "mutation_set": tuple(m for m in genome.mutation.split("+") if m),
        "executable_artifacts": (("phenotype", synth.phenotype_digest),),
        "contracts": ComputationContract.for_genome(genome),
        "measured_resources": None if measured is None else measured.to_dict(),
        "security_metrics": _security_metrics(train, heldout, base_rate),
        "counterexample_suite": kept[:MAX_COUNTEREXAMPLES],
        "invariance_suite": tuple(_invariance(invariance, synth)),
        "uncertainty_profile": {"min_events_for_score": genome.min_events_for_score,
                                "calibration": None,
                                "heldout_abstained_sessions": heldout.abstained_sessions},
        "failure_domains": tuple(_failure_domains(synth, heldout,
                                                  max(0, len(kept) - MAX_COUNTEREXAMPLES))),
        "rollback_artifact": RollbackArtifact(parent.to_dict(), parent.digest,
                                              parent_scores_digest),
        "experiment_id": experiment_id,
    }
    return _signed(fields)


def _signed(fields: Mapping[str, Any]) -> ProofCarryingSuccessorV1:
    signature = ((CONTENT_SIGNATURE_ALGORITHM, content_digest(_payload(fields))),)
    return ProofCarryingSuccessorV1(**fields, signatures=signature)


def _payload(values: Mapping[str, Any]) -> dict[str, Any]:
    """The ONE serialiser: ``to_dict`` and signing both use it, so they cannot drift."""
    contract: ComputationContract = values["contracts"]
    rollback: RollbackArtifact = values["rollback_artifact"]
    payload = {
        "schema": PROOF_CARRYING_SUCCESSOR_V1_ID,
        "schema_version": values.get("schema_version", PROOF_CARRYING_SUCCESSOR_V1_VERSION),
        "computational_genome": _thaw(values["computational_genome"]),
        "genome_digest": values["genome_digest"],
        "parent_lineage": list(values["parent_lineage"]),
        "mutation_set": list(values["mutation_set"]),
        "executable_artifacts": [list(p) for p in values["executable_artifacts"]],
        "contracts": contract.to_dict(),
        "measured_resources": _thaw(values["measured_resources"]),
        "security_metrics": dict(values["security_metrics"]),
        "counterexample_suite": list(values["counterexample_suite"]),
        "invariance_suite": [_thaw(e) for e in values["invariance_suite"]],
        "uncertainty_profile": _thaw(values["uncertainty_profile"]),
        "failure_domains": list(values["failure_domains"]),
        "rollback_artifact": rollback.to_dict(),
        "signatures": [list(p) for p in values.get("signatures", ())],
        "synthetic_data": values.get("synthetic_data", True),
        "experiment_id": values["experiment_id"],
    }
    return payload


# --- Stage 9's own lab registry ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class InstallReceipt:
    slot: int
    installed_digest: str
    previous_digest: str | None


@dataclass(frozen=True, slots=True)
class RegistryEvent:
    kind: str                # "INSTALL" | "ROLLBACK" | "EVICT"
    slot: int
    genome_digest: str


class CandidateRegistry:
    """Stage 9's OWN lab registry. It holds genomes for experiments and no production state.

    Bounded at ``capacity`` install records (oldest evicted and counted); the event log is
    bounded the same way. Only the ACTIVE install can be rolled back, once: rolling back a
    superseded or evicted install is refused rather than guessed at.
    """

    def __init__(self, capacity: int = MAX_REGISTRY) -> None:
        if not 1 <= capacity <= MAX_REGISTRY:
            raise ContractError(f"capacity must be in [1, {MAX_REGISTRY}]")
        self._capacity = capacity
        self._records: OrderedDict[int, RollbackArtifact] = OrderedDict()
        self._installed: dict[int, str] = {}
        self._events: list[RegistryEvent] = []
        self._active: ComputationalGenomeV1 | None = None
        # The SLOT, not the digest: the same genome installed twice is two installs, and
        # only the later one is active.
        self._active_slot: int | None = None
        self._next_slot = 0
        self._evictions = 0

    def install(self, successor: ProofCarryingSuccessorV1) -> InstallReceipt:
        # Re-verify from bytes: object.__setattr__ can edit a frozen instance in memory.
        verified = ProofCarryingSuccessorV1.from_dict(successor.to_dict())
        genome = verified.genome()
        previous = None if self._active is None else self._active.digest
        slot = self._next_slot
        self._next_slot += 1
        self._records[slot] = verified.rollback_artifact
        self._installed[slot] = genome.digest
        self._active, self._active_slot = genome, slot
        self._log(RegistryEvent("INSTALL", slot, genome.digest))
        while len(self._records) > self._capacity:
            old, _ = self._records.popitem(last=False)
            self._evictions += 1
            self._log(RegistryEvent("EVICT", old, self._installed.pop(old)))
        return InstallReceipt(slot=slot, installed_digest=genome.digest, previous_digest=previous)

    def active(self) -> ComputationalGenomeV1 | None:
        return self._active

    def rollback(self, receipt: InstallReceipt) -> ComputationalGenomeV1:
        """Re-install the parent genome carried by ``receipt``'s successor."""
        artifact = self._records.get(receipt.slot)
        if artifact is None or self._installed.get(receipt.slot) != receipt.installed_digest:
            raise ContractError(f"install slot {receipt.slot} is unknown, evicted or already "
                                "rolled back")
        if self._active_slot != receipt.slot:
            raise ContractError("only the active install can be rolled back")
        parent = ComputationalGenomeV1.from_dict(_thaw(artifact.parent_genome))
        if parent.digest != artifact.parent_digest:
            raise ContractError("rollback parent does not match its recorded digest")
        del self._records[receipt.slot]
        del self._installed[receipt.slot]
        self._active, self._active_slot = parent, None
        self._log(RegistryEvent("ROLLBACK", receipt.slot, parent.digest))
        return parent

    def _log(self, event: RegistryEvent) -> None:
        self._events.append(event)
        del self._events[: max(0, len(self._events) - 4 * self._capacity)]

    def history(self) -> tuple[RegistryEvent, ...]:
        return tuple(self._events)

    @property
    def evictions(self) -> int:
        return self._evictions

    def __len__(self) -> int:
        return len(self._records)


# --- ARGUS: tampered successor -----------------------------------------------------------------


def _edited_genome_dict(payload: Mapping[str, Any]) -> dict[str, Any]:
    """A VALID genome differing from ``payload`` (one more event before scoring), with its
    own correct digest: an attacker who re-digests the genome, not a clumsy one."""
    genome = ComputationalGenomeV1.from_dict(payload)
    return build_genome(
        registers=genome.registers, update=genome.update, readout=genome.readout,
        aggregation=genome.aggregation, lookup_table=genome.lookup_table,
        min_events_for_score=genome.min_events_for_score + 1,
    ).to_dict()


def _tamperings(successor: ProofCarryingSuccessorV1) -> list[tuple[str, dict[str, Any]]]:
    base = successor.to_dict()
    metric = copy.deepcopy(base)
    value = metric["security_metrics"]["heldout_worst_case_ap"]
    metric["security_metrics"]["heldout_worst_case_ap"] = 1.0 if value is None \
        else min(1.0, value + 0.1) if value < 1.0 else 0.5
    parent = copy.deepcopy(base)
    parent["rollback_artifact"]["parent_genome"] = _edited_genome_dict(
        base["rollback_artifact"]["parent_genome"])
    genome = copy.deepcopy(base)
    genome["computational_genome"] = _edited_genome_dict(base["computational_genome"])
    signature = copy.deepcopy(base)
    signature["signatures"] = [[CONTENT_SIGNATURE_ALGORITHM, "sha256:" + "0" * 64]]
    return [("metric_edit", metric), ("rollback_parent_edit", parent),
            ("genome_edit", genome), ("signature_edit", signature)]


def tampered_successor(successor: ProofCarryingSuccessorV1) -> ArgusFinding:
    """[SUPPLY_CHAIN] Four tamperings; a DEFENCE finding that must refuse all four.

    Each tampered payload goes through ``from_dict``. ``fired`` counts ``ContractError``
    refusals; any other outcome (acceptance, or a different exception) is a failure.
    """
    outcomes: list[str] = []
    fired = 0
    tamperings = _tamperings(successor)
    for name, payload in tamperings:
        try:
            ProofCarryingSuccessorV1.from_dict(payload)
            outcomes.append(f"{name}: ACCEPTED")
        except ContractError as exc:
            fired += 1
            outcomes.append(f"{name}: refused ({str(exc)[:80]})")
        except Exception as exc:  # any other failure is NOT a refusal, and is reported
            outcomes.append(f"{name}: {type(exc).__name__} (not a contract refusal)")
    limit = ("limit: an edit re-signed with a recomputed content digest is accepted; "
             "sha256-content is integrity, not authenticity (ADR-0088)")
    return ArgusFinding(
        attack_id="tampered_successor", surface=ArgusSurface.SUPPLY_CHAIN, kind="DEFENCE",
        fired=fired, total=len(tamperings), inert=fired == 0, metric_before=None,
        metric_after=None, detail="; ".join([*outcomes, limit]),
        measured_by="pocketsec.stage9.successor.proof_carrying:tampered_successor",
    )
