"""Stage 2 D2.10/D2.11 — counterfactual twin, credit ledger, value of information.

These tests exist to make three claims false if they are false:

1. A probe cannot leak into the live model. The quantizer and lattice stand-ins
   here raise :class:`AssertionError` from their mutating entry points, so if the
   read-only guard were removed *and* the probe learned from its own
   counterfactual, the suite fails loudly instead of producing plausible numbers.
2. An unmeasured probe cannot earn credit. A budget-refused probe reports a real
   0.0 divergence; the ledger must refuse it rather than read that zero as
   "this transition was innocent".
3. A quality number that was not measured is ``None``, never 0.0.

The final test is the G2.7 measurement: four attribution mechanisms on a fixed
split, all four reported, with no assertion that ours wins.

D2.6 (lattice), D2.8 (future cone) and D2.9 (uncertainty) are being written in
parallel and were absent when this suite was authored, so the quantizer, lattice,
cone and uncertainty estimate are local stand-ins matching the documented shapes.
Every number below therefore describes *this package's* behaviour given a
hash-bucket quantizer and a bigram lattice — the spec's own simple controls —
and must be re-measured against the real D2.6/D2.8 once they land.
"""

from __future__ import annotations

import copy
import functools
import itertools
import math
import random
from dataclasses import dataclass, field
from typing import Any

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.causal.memory import CausalMemory, CausalNode
from pocketsec.stage1.labs.corpus import Behaviour, Scenario
from pocketsec.stage1.observation.policy import (
    AOPBudget,
    AdaptiveObservationPolicy,
    EscalationDecision,
    MANDATORY_SIGNALS,
    ObservationLevel,
)
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage1.state.security_state import DIMENSIONS, SecurityStateV1
from pocketsec.stage2.counterfactual.twin import (
    DELAY_NOOP_EVIDENCE,
    MAX_PROBES_PER_EVENT,
    MAX_PROBE_DEPTH,
    LATTICE_READS,
    PROBE_REFUSED_EVIDENCE,
    PROBE_TRUNCATED_EVIDENCE,
    QUANTIZER_READS,
    CounterfactualProbe,
    Intervention,
    ProbeBudget,
    ReadOnlyGuard,
    counterfactual_probe,
    jensen_shannon,
    label_distribution,
    phi_only_probe,
    probe_event,
)
from pocketsec.stage2.counterfactual.value_of_information import (
    MIN_VALUE_OF_INFORMATION,
    InformationNeedTracker,
    assert_mandatory_signals_intact,
    estimate_information_need,
    request_observation_escalation,
    uncertainty_only_requests,
)
from pocketsec.stage2.credit.ledger import (
    MAX_LEDGER_ENTRIES,
    AttributionReport,
    CausalCreditLedger,
    chain_recall,
    naive_ancestry,
    top_k_by_delta_phi,
)
from pocketsec.stage2.encoder.ssir_encoder import (
    EncodedTransition,
    encode_ssir_transition,
)
from pocketsec.stage2.lattice.quantizer import BehaviourQuantizer
from pocketsec.stage2.lattice.transitions import TransitionLattice
from pocketsec.stage2.predictors.future_cone import predict_future_cone
from pocketsec.stage2.router.accounting import WorkKind, WorkLedger
from pocketsec.stage2.uncertainty.abstention import (
    EpistemicQuadrant,
    UncertaintyEstimate,
)

# --- stand-ins for the concurrently-written packages -------------------------


@dataclass(frozen=True, slots=True)
class _Branch:
    label: str
    probability: float
    delta_phi: float
    atom_path: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class _Cone:
    branches: tuple[_Branch, ...]
    unresolved_mass: float
    depth: int = 1
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class _Atom:
    """Stands in for D2.6's ``BehaviourAtom`` (the fields a probe reads)."""

    atom_id: int
    prototype: tuple[float, ...]
    label_hint: str

    def distance(self, features: Any) -> float:
        return sum((a - b) ** 2 for a, b in zip(self.prototype, features, strict=True))


class _BucketQuantizer:
    """The spec's ``HashBucketQuantizer`` control, as a probe-visible stand-in.

    ``learn`` is the fixture-only mutator. ``quantize_behaviour_atom`` — the name
    D2.6 exposes and the one the read-only guard forbids — raises, so a probe
    that ever reached it would fail this suite rather than silently train.
    """

    def __init__(self) -> None:
        self._atoms: dict[int, _Atom] = {}
        self._next = 0

    def learn(self, step: EncodedTransition) -> int:
        key = (step.relation_family, step.state_delta_mask, step.object_property_mask)
        atom_id = self._key_to_id(key)
        if atom_id not in self._atoms:
            self._atoms[atom_id] = _Atom(
                atom_id=atom_id,
                prototype=step.features,
                label_hint=f"fam{step.relation_family}m{step.state_delta_mask}",
            )
        return atom_id

    @staticmethod
    def _key_to_id(key: tuple[int, int, int]) -> int:
        family, mask, properties = key
        return (family * 1_000_003 + mask * 1_009 + properties) % 251

    def quantize_behaviour_atom(self, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError("D2.6 mutator reached from a counterfactual probe")

    def atoms(self) -> tuple[_Atom, ...]:
        return tuple(self._atoms[key] for key in sorted(self._atoms))

    def get(self, atom_id: int) -> _Atom | None:
        return self._atoms.get(atom_id)

    def snapshot(self) -> str:
        return repr([(a.atom_id, a.prototype, a.label_hint) for a in self.atoms()])


class _BigramLattice:
    """Stands in for D2.6's ``TransitionLattice``; Laplace-smoothed bigrams."""

    def __init__(self, *, alpha: float = 1.0) -> None:
        self.alpha = alpha
        self._counts: dict[tuple[int, int], int] = {}
        self._out: dict[int, int] = {}

    def learn(self, source: int, target: int) -> None:
        self._counts[(source, target)] = self._counts.get((source, target), 0) + 1
        self._out[source] = self._out.get(source, 0) + 1

    def observe(self, *args: Any, **kwargs: Any) -> None:
        raise AssertionError("D2.6 lattice mutator reached from a counterfactual probe")

    def successors(
        self, source: int, *, epoch_id: int | None = None, limit: int = 8
    ) -> tuple[tuple[int, float], ...]:
        edges = [
            (target, count)
            for (src, target), count in self._counts.items()
            if src == source
        ]
        if not edges:
            return ()
        total = self._out.get(source, 0) + self.alpha * max(1, len(edges))
        ranked = sorted(edges, key=lambda pair: (-pair[1], pair[0]))[:limit]
        return tuple(
            (target, (count + self.alpha) / total) for target, count in ranked
        )

    def probability(
        self, source: int, target: int, *, epoch_id: int | None = None
    ) -> float:
        total = self._out.get(source, 0) + self.alpha
        return (self._counts.get((source, target), 0) + self.alpha) / total

    def snapshot(self) -> str:
        return repr(sorted(self._counts.items()))


@dataclass(frozen=True, slots=True)
class _Window:
    """Stands in for D2.3's ``LineageWindow`` (the fields a probe reads)."""

    lineage_key: str
    steps: tuple[EncodedTransition, ...]
    truncated: bool = False
    last_sequence: int = 0


@dataclass(frozen=True, slots=True)
class _Estimate:
    """Stands in for D2.9's ``UncertaintyEstimate``."""

    value: float
    sources: dict[str, float] = field(default_factory=dict)
    calibration_id: str | None = None
    quadrant: str = "ESCALATE"
    abstain: bool = False
    detail: str = ""


class _WorkLedger:
    """Stands in for D2.4's ``WorkLedger``: records only what it is told ran."""

    def __init__(self) -> None:
        self.records: list[tuple[Any, bool, float, str]] = []

    def record(self, kind: Any, *, performed: bool, units: float, detail: str = "") -> None:
        self.records.append((kind, performed, units, detail))

    def performed_units(self) -> float:
        return sum(units for _, performed, units, _ in self.records if performed)


def _state_label(state: SecurityStateV1) -> str:
    """A security-meaning label, so divergence tracks futures, not atom names."""
    held = [name for name in DIMENSIONS if state.level(name) > 0]
    return "+".join(held) if held else "routine"


def _state_weight(state: SecurityStateV1) -> float:
    return float(sum(state.level(name) for name in DIMENSIONS))


def _make_expander(*, relabel: bool = False) -> Any:
    """A stand-in for D2.8 ``predict_future_cone``.

    With ``relabel=True`` every call invents fresh atom-path ids while keeping
    the labels identical — the semantic-vs-syntactic test.
    """
    counter = itertools.count(9_000)

    def expander(
        lattice: Any,
        quantizer: Any,
        *,
        from_atom: int,
        state: SecurityStateV1,
        epoch_id: int,
    ) -> _Cone:
        prefix = _state_label(state)
        weight = _state_weight(state)
        branches = []
        for atom_id, probability in lattice.successors(
            from_atom, epoch_id=epoch_id, limit=4
        ):
            atom = quantizer.get(atom_id)
            hint = atom.label_hint if atom is not None else "unknown"
            path = (next(counter),) if relabel else (atom_id,)
            branches.append(
                _Branch(f"{prefix}->{hint}", probability, weight, path)
            )
        mass = sum(branch.probability for branch in branches)
        return _Cone(tuple(branches), max(0.0, 1.0 - mass))

    return expander


# --- the attribution fixture -------------------------------------------------

_BACKGROUND: tuple[tuple[str, dict[str, str]], ...] = (
    ("read", {"path": "/var/log/syslog"}),
    ("execve", {"path": "/usr/bin/grep"}),
    ("write", {"path": "/home/dev/build/out.o"}),
    ("read", {"path": "/proc/stat"}),
    ("connect", {"raddr": "10.0.0.20", "rport": "5432"}),
    ("send", {"raddr": "10.0.0.20", "rport": "5432"}),
    ("read", {"path": "/etc/hosts"}),
    ("execve", {"path": "/usr/bin/awk"}),
)
#: Legitimate privileged administration. Present so that raw ΔΦ cannot separate
#: the chain by itself — which is the only version of this task worth measuring.
_BENIGN_ADMIN: tuple[tuple[str, dict[str, str]], ...] = (
    ("setuid", {"target_uid": "0"}),
    ("install", {"path": "nginx"}),
    ("write", {"path": "/etc/systemd/system/nginx.service"}),
)
_BENIGN_BACKUP: tuple[tuple[str, dict[str, str]], ...] = (
    ("execve", {"path": "/usr/bin/tar"}),
    ("read", {"path": "/home/dev/documents/notes.txt"}),
    ("write", {"path": "/backup/archive.tar"}),
)
_CHAIN: tuple[tuple[str, dict[str, str]], ...] = (
    ("execve", {"path": "/usr/bin/perl"}),
    ("read", {"path": "/root/.ssh/id_rsa"}),
    ("write", {"path": "/etc/cron.d/sysupdate"}),
    ("connect", {"raddr": "198.51.100.61", "rport": "443"}),
    ("send", {"raddr": "198.51.100.61", "rport": "443"}),
)
_SECOND_NS = 1_000_000_000
#: Fixed split for the G2.7 measurement. A result quoted without these is void.
FIXTURE_SEEDS: tuple[int, ...] = (11, 17, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61)


def _build_attribution_scenario(seed: int) -> tuple[Scenario, tuple[str, ...]]:
    """One single-lineage session: background, benign privileged work, a chain.

    The seed varies *structure*, not only timing: chain length, whether the
    legitimate privileged burst lands before or after the chain, whether the
    backup job runs, and the spacing between chain stages. Varying only the
    background would produce twelve copies of one measurement, and a zero spread
    across seeds is exactly the degeneracy this wave's own guard exists to catch.
    """
    rng = random.Random(seed)
    steps: list[Behaviour] = []
    kinds: list[str] = []

    def add(operation: str, fields: dict[str, str], kind: str) -> None:
        gap = str(rng.randrange(1, 120) * _SECOND_NS)
        steps.append(Behaviour(operation, {**fields, "_gap_ns": gap}))
        kinds.append(kind)

    def background(count: int, offset: int) -> None:
        for index in range(count):
            add(*_BACKGROUND[(index + offset) % len(_BACKGROUND)], "background")

    def burst(pattern: tuple[tuple[str, dict[str, str]], ...], kind: str) -> None:
        for operation, fields in pattern:
            add(operation, fields, kind)

    chain = _CHAIN[: rng.choice((2, 3, 4, 5))]
    admin_first = rng.random() < 0.5
    spacing = rng.choice((1, 2, 3, 4))

    background(rng.randrange(4, 10), 0)
    if admin_first:
        burst(_BENIGN_ADMIN, "benign_admin")
        background(rng.randrange(4, 10), 3)
    if rng.random() < 0.7:
        burst(_BENIGN_BACKUP, "benign_backup")
    background(rng.randrange(3, 8), 5)
    for operation, fields in chain:
        add(operation, fields, "chain")
        background(spacing, rng.randrange(len(_BACKGROUND)))
    if not admin_first:
        burst(_BENIGN_ADMIN, "benign_admin")
    background(rng.randrange(4, 10), 2)

    scenario = Scenario(
        name=f"attribution-{seed:04d}",
        behaviours=tuple(steps),
        label=1,
        technique="fixture-escalation-chain",
    )
    return scenario, tuple(kinds)


@dataclass(frozen=True, slots=True)
class _Session:
    seed: int
    memory: CausalMemory
    encoded: tuple[EncodedTransition, ...]
    signatures: tuple[str, ...]
    kinds: tuple[str, ...]

    @property
    def ground_truth(self) -> frozenset[str]:
        return frozenset(
            signature
            for signature, kind in zip(self.signatures, self.kinds, strict=True)
            if kind == "chain"
        )

    def window(self) -> _Window:
        return _Window(lineage_key=f"lineage-{self.seed}", steps=self.encoded)

    def model(self) -> tuple[_BucketQuantizer, _BigramLattice]:
        quantizer = _BucketQuantizer()
        lattice = _BigramLattice()
        previous: int | None = None
        for step in self.encoded:
            atom_id = quantizer.learn(step)
            if previous is not None:
                lattice.learn(previous, atom_id)
            previous = atom_id
        return quantizer, lattice


@functools.cache
def _session(seed: int) -> _Session:
    """A real Stage 1 session. A fresh pipeline per session, always.

    Sharing a pipeline carries lineage state across sessions and silently erases
    the signal (``planning/MEMORY.md`` corpus trap).
    """
    scenario, kinds = _build_attribution_scenario(seed)
    pipeline = Stage1Pipeline()
    result = pipeline.run_scenario(scenario, offset=0)
    assert len(result.transitions) == len(scenario.behaviours)
    return _Session(
        seed=seed,
        memory=pipeline.causal,
        encoded=tuple(encode_ssir_transition(t) for t in result.transitions),
        signatures=tuple(t.causal_signature for t in result.transitions),
        kinds=kinds,
    )


def _index_of(session: _Session, *, noop: bool) -> int:
    """First mid-window step that either changed nothing or changed a lot."""
    candidates = range(1, len(session.encoded) - 1)
    for index in candidates:
        step = session.encoded[index]
        quiet = step.state_delta_mask == 0 and step.delta_phi == 0.0
        if quiet is noop:
            return index
    raise AssertionError(f"fixture has no {'no-op' if noop else 'consequential'} step")


def _credential_chain_index(session: _Session) -> int:
    """The chain's credential read: high ΔΦ, and no earlier step raised it."""
    credential_bit = 1 << tuple(DIMENSIONS).index("credential")
    for index, (step, kind) in enumerate(
        zip(session.encoded, session.kinds, strict=True)
    ):
        if kind == "chain" and step.state_delta_mask & credential_bit:
            return index
    raise AssertionError("fixture has no credential-raising chain step")


# --- divergence algebra ------------------------------------------------------


def test_label_distribution_carries_unresolved_mass_as_its_own_label():
    cone = _Cone((_Branch("routine", 0.4, 0.0),), unresolved_mass=0.6)
    distribution = label_distribution(cone)
    assert math.isclose(sum(distribution.values()), 1.0)
    assert distribution["__unresolved__"] == pytest.approx(0.6)


def test_label_distribution_of_a_wholly_unknown_future_is_unknown():
    assert label_distribution(_Cone((), unresolved_mass=0.0)) == {"__unresolved__": 1.0}
    assert label_distribution(None) == {"__unresolved__": 1.0}


def test_label_distribution_rejects_a_negative_probability():
    with pytest.raises(ContractError):
        label_distribution(_Cone((_Branch("bad", -0.1, 0.0),), unresolved_mass=0.0))


def test_jensen_shannon_is_symmetric_bounded_and_zero_on_agreement():
    left = {"a": 0.7, "b": 0.3}
    right = {"a": 0.2, "b": 0.8}
    forward = jensen_shannon(left, right)
    assert forward == pytest.approx(jensen_shannon(right, left))
    assert 0.0 < forward < 1.0
    assert jensen_shannon(left, dict(left)) == 0.0
    assert jensen_shannon({"a": 1.0}, {"b": 1.0}) == pytest.approx(1.0)


# --- isolation: a probe may never train on its own counterfactual ------------


def test_read_only_guard_refuses_every_named_mutator():
    quantizer = _BucketQuantizer()
    guard = ReadOnlyGuard(quantizer, readable=QUANTIZER_READS)
    assert guard.atoms() == ()
    with pytest.raises(ContractError):
        guard.quantize_behaviour_atom()
    with pytest.raises(ContractError):
        guard.anything = 1


def test_read_only_guard_is_an_allowlist_not_a_one_name_blocklist():
    """Pins S2-AUTH-04.

    The guard used to be constructed with ``forbidden=("observe",)`` for the
    lattice and ``forbidden=("quantize_behaviour_atom",)`` for the quantizer,
    while ``set_status``, ``remove_edge``, ``reinsert`` and ``fission_atom``
    forwarded straight through to the live object. ``reinsert`` accepts a whole
    ``LatticeTransition``, so counts, epoch histories and ``CompileStatus`` —
    including ``EXECUTABLE``, which ADR-0003 says Stage 2 never promotes itself
    to — could be fabricated during a probe. Deny-by-default is the fix, so this
    test asserts on the *real* Stage 2 objects that every mutator they expose is
    refused, and that the reads the probe actually performs still work.
    """
    from pocketsec.stage2.lattice.quantizer import BehaviourQuantizer
    from pocketsec.stage2.lattice.transitions import TransitionLattice

    lattice = ReadOnlyGuard(TransitionLattice(), readable=LATTICE_READS)
    for mutator in ("observe", "set_status", "remove_edge", "reinsert"):
        with pytest.raises(ContractError):
            getattr(lattice, mutator)
    assert lattice.successors(0, epoch_id=0) == ()

    quantizer = ReadOnlyGuard(BehaviourQuantizer(), readable=QUANTIZER_READS)
    for mutator in ("quantize_behaviour_atom", "fission_atom"):
        with pytest.raises(ContractError):
            getattr(quantizer, mutator)
    assert quantizer.atoms() == ()


def test_probe_does_not_mutate_the_live_quantizer_or_lattice():
    """Full-state comparison, not a spot check.

    The stand-ins also raise from ``quantize_behaviour_atom``/``observe``, so a
    probe that learned from its counterfactual would fail here even if the
    read-only guard were deleted.
    """
    session = _session(11)
    quantizer, lattice = session.model()
    before = (quantizer.snapshot(), lattice.snapshot())
    deep_before = (copy.deepcopy(quantizer.atoms()), copy.deepcopy(lattice._counts))

    for intervention in Intervention:
        counterfactual_probe(
            session.window(),
            quantizer,
            lattice,
            target_index=_credential_chain_index(session),
            intervention=intervention,
            cone_expander=_make_expander(),
        )

    assert (quantizer.snapshot(), lattice.snapshot()) == before
    assert quantizer.atoms() == deep_before[0]
    assert lattice._counts == deep_before[1]


def test_probe_reads_the_lattice_and_never_writes_to_it():
    session = _session(11)
    quantizer, lattice = session.model()
    ledger = _WorkLedger()
    probe = counterfactual_probe(
        session.window(),
        quantizer,
        lattice,
        target_index=_credential_chain_index(session),
        ledger=ledger,
        cone_expander=_make_expander(),
    )
    assert probe.measured
    assert ledger.performed_units() > 0.0
    assert all(performed for _, performed, _, _ in ledger.records)


# --- compute budget ---------------------------------------------------------


def test_probes_per_event_never_exceed_the_cap_and_exhaustion_is_reported():
    session = _session(11)
    quantizer, lattice = session.model()
    targets = list(range(1, MAX_PROBES_PER_EVENT + 3))
    probes = probe_event(
        session.window(),
        quantizer,
        lattice,
        target_indices=targets,
        event_key="event-1",
        budget=ProbeBudget(),
        cone_expander=_make_expander(),
    )
    assert len(probes) == len(targets)
    measured = [probe for probe in probes if probe.measured]
    assert len(measured) == MAX_PROBES_PER_EVENT
    refused = [probe for probe in probes if not probe.measured]
    assert refused, "the cap must actually refuse something"
    for probe in refused:
        assert probe.budget_exhausted is True
        assert PROBE_REFUSED_EVIDENCE in probe.evidence
        assert probe.divergence == 0.0


def test_a_refused_probe_records_unperformed_work_on_the_ledger():
    """Pins S2-01: the budget-refusal path must survive the REAL WorkLedger.

    This used to inject a validation-free local stub, so it passed while the
    refusal branch was unreachable against the ledger it documents: it recorded
    ``performed=False`` with ``units=PROBE_COST_UNITS`` (200.0), which
    ``WorkRecord.__post_init__`` refuses outright, so ``_refused_probe`` was
    never returned and the fifth probe of any real caller crashed with
    ContractError. A stub ledger cannot test a contract the real ledger enforces,
    so the real one is used here and closed, which is what runs the contract.
    """
    session = _session(11)
    quantizer, lattice = session.model()
    ledger = WorkLedger()
    ledger.begin("event-1")
    budget = ProbeBudget(max_per_event=1)
    probes = probe_event(
        session.window(),
        quantizer,
        lattice,
        target_indices=(1, 2),
        budget=budget,
        ledger=ledger,
        cone_expander=_make_expander(),
    )
    account = ledger.close()
    ledger.assert_no_phantom_savings()

    assert len(probes) == 2
    assert probes[0].measured
    assert probes[1].budget_exhausted is True
    assert PROBE_REFUSED_EVIDENCE in probes[1].evidence

    # Two observed cones genuinely ran (one per probe) and are charged. The
    # refused probe writes NO record at all: a probe that did not run is not
    # work, and a 0.0-unit skipped COUNTERFACTUAL beside the performed one would
    # trip `assert_no_phantom_savings()` on any event that probes more than once.
    assert [record.kind for record in account.work] == [
        WorkKind.CONE_EXPANSION,
        WorkKind.COUNTERFACTUAL,
        WorkKind.CONE_EXPANSION,
    ]
    assert all(record.performed for record in account.work)


def test_probe_event_exceeding_its_budget_against_a_real_ledger_does_not_raise():
    """Pins S2-01's failure scenario verbatim.

    ``probe_event`` with a real ``WorkLedger`` and more targets than
    ``MAX_PROBES_PER_EVENT`` used to raise ContractError on the fifth probe
    instead of returning four measured probes plus refusals.
    """
    session = _session(11)
    quantizer, lattice = session.model()
    ledger = WorkLedger()
    ledger.begin("event-1")
    probes = probe_event(
        session.window(),
        quantizer,
        lattice,
        target_indices=range(1, MAX_PROBES_PER_EVENT + 3),
        event_key="event-1",
        budget=ProbeBudget(),
        ledger=ledger,
        cone_expander=_make_expander(),
    )
    ledger.close()
    ledger.assert_no_phantom_savings()
    assert sum(1 for probe in probes if probe.measured) == MAX_PROBES_PER_EVENT
    refused = [probe for probe in probes if not probe.measured]
    assert len(refused) == 2
    assert all(PROBE_REFUSED_EVIDENCE in probe.evidence for probe in refused)


def test_probe_depth_truncation_is_reported_not_silently_exceeded():
    session = _session(11)
    quantizer, lattice = session.model()
    assert len(session.encoded) > MAX_PROBE_DEPTH + 2
    probe = counterfactual_probe(
        session.window(),
        quantizer,
        lattice,
        target_index=1,
        cone_expander=_make_expander(),
    )
    assert probe.budget_exhausted is True
    assert PROBE_TRUNCATED_EVIDENCE in probe.evidence


def test_probe_budget_rejects_a_nonsense_budget():
    with pytest.raises(ContractError):
        ProbeBudget(max_per_event=0)
    with pytest.raises(ContractError):
        ProbeBudget(max_total=0)


def test_probe_rejects_an_out_of_range_target_and_an_empty_window():
    session = _session(11)
    quantizer, lattice = session.model()
    with pytest.raises(ContractError):
        counterfactual_probe(
            session.window(),
            quantizer,
            lattice,
            target_index=len(session.encoded),
            cone_expander=_make_expander(),
        )
    with pytest.raises(ContractError):
        counterfactual_probe(
            _Window("empty", ()),
            quantizer,
            lattice,
            target_index=0,
            cone_expander=_make_expander(),
        )
    with pytest.raises(ContractError):
        phi_only_probe(_Window("empty", ()), target_index=0)


# --- intervention semantics -------------------------------------------------


def test_masking_a_no_op_transition_registers_exactly_zero_divergence():
    session = _session(11)
    quantizer, lattice = session.model()
    probe = counterfactual_probe(
        session.window(),
        quantizer,
        lattice,
        target_index=_index_of(session, noop=True),
        cone_expander=_make_expander(),
    )
    assert probe.divergence == 0.0
    assert probe.delta_phi_shift == pytest.approx(0.0)


def test_masking_a_high_delta_phi_transition_diverges_more_than_a_no_op():
    session = _session(11)
    quantizer, lattice = session.model()
    expander = _make_expander()
    window = session.window()
    consequential = counterfactual_probe(
        window,
        quantizer,
        lattice,
        target_index=_credential_chain_index(session),
        cone_expander=expander,
    )
    quiet = counterfactual_probe(
        window,
        quantizer,
        lattice,
        target_index=_index_of(session, noop=True),
        cone_expander=expander,
    )
    assert consequential.divergence > quiet.divergence
    assert consequential.divergence > 0.0


def test_a_relabelled_but_equivalent_future_registers_near_zero_divergence():
    """Semantic, not syntactic: fresh atom ids, identical security futures."""
    session = _session(11)
    quantizer, lattice = session.model()
    probe = counterfactual_probe(
        session.window(),
        quantizer,
        lattice,
        target_index=_index_of(session, noop=True),
        cone_expander=_make_expander(relabel=True),
    )
    assert probe.observed_cone.branches[0].atom_path != (
        probe.counterfactual_cone.branches[0].atom_path
    )
    assert probe.divergence == pytest.approx(0.0, abs=1e-12)


def test_substitute_benign_strips_consequence_without_removing_the_step():
    session = _session(11)
    quantizer, lattice = session.model()
    target = _credential_chain_index(session)
    masked = counterfactual_probe(
        session.window(),
        quantizer,
        lattice,
        target_index=target,
        intervention=Intervention.MASK,
        cone_expander=_make_expander(),
    )
    substituted = counterfactual_probe(
        session.window(),
        quantizer,
        lattice,
        target_index=target,
        intervention=Intervention.SUBSTITUTE_BENIGN,
        cone_expander=_make_expander(),
    )
    assert substituted.divergence > 0.0
    assert label_distribution(substituted.counterfactual_cone) == label_distribution(
        masked.counterfactual_cone
    )


def test_delaying_the_last_transition_in_the_horizon_is_reported_as_a_no_op():
    session = _session(11)
    quantizer, lattice = session.model()
    last = len(session.encoded) - 1
    probe = counterfactual_probe(
        session.window(),
        quantizer,
        lattice,
        target_index=last,
        intervention=Intervention.DELAY,
        cone_expander=_make_expander(),
    )
    assert DELAY_NOOP_EVIDENCE in probe.evidence
    assert probe.divergence == 0.0


def test_phi_only_probe_uses_zero_parameters_and_tracks_masked_delta_phi():
    session = _session(11)
    target = _credential_chain_index(session)
    probe = phi_only_probe(session.window(), target_index=target)
    assert probe.divergence > 0.0
    assert probe.delta_phi_shift < 0.0, "removing a Φ-raising step must lower the future"
    quiet = phi_only_probe(session.window(), target_index=_index_of(session, noop=True))
    assert quiet.divergence <= probe.divergence


# --- credit ledger ----------------------------------------------------------


def _node(signature: str, *, sequence: int, delta_phi: float) -> CausalNode:
    return CausalNode(
        signature=signature,
        parent_signature="0" * 16,
        sequence=sequence,
        relation=1,
        state_delta_mask=4,
        delta_phi=delta_phi,
        evidence_locators=(f"ev:{signature}",),
    )


def _probe(
    divergence: float, *, shift: float = 0.0, refused: bool = False
) -> CounterfactualProbe:
    cone = _Cone((_Branch("routine", 1.0, 0.0),), unresolved_mass=0.0)
    return CounterfactualProbe(
        target_signature="probe-target",
        intervention=Intervention.MASK,
        observed_cone=cone,
        counterfactual_cone=cone,
        divergence=divergence,
        delta_phi_shift=shift,
        budget_exhausted=refused,
        evidence=(PROBE_REFUSED_EVIDENCE,) if refused else ("ev:probe",),
    )


def test_immaterial_probe_earns_no_credit():
    ledger = CausalCreditLedger()
    exact = ledger.assign_causal_credit(_probe(0.0), _node("a", sequence=1, delta_phi=0.0))
    tiny = ledger.assign_causal_credit(_probe(0.0001), _node("b", sequence=2, delta_phi=0.0))
    assert exact is None and tiny is None
    assert ledger.entries() == ()
    assert ledger.probes_spent() == 2


def test_a_budget_refused_probe_can_never_earn_credit():
    """The invariant that would be silently weakened by trusting a 0.0.

    A refused probe carries a genuine 0.0 divergence for a comparison that never
    ran. If the ledger ever credits one, an exhausted budget starts exonerating
    attack steps, so this must fail loudly.
    """
    ledger = CausalCreditLedger()
    entry = ledger.assign_causal_credit(
        _probe(0.99, shift=-5.0, refused=True), _node("a", sequence=1, delta_phi=9.0)
    )
    assert entry is None
    assert ledger.entries() == ()
    assert ledger.probes_spent() == 0, "a refused probe must not consume ledger budget"
    assert ledger.probes_refused() == 1


def test_material_probe_is_recorded_and_re_probing_does_not_inflate_credit():
    ledger = CausalCreditLedger()
    node = _node("a", sequence=3, delta_phi=4.0)
    first = ledger.assign_causal_credit(_probe(0.4), node)
    second = ledger.assign_causal_credit(_probe(0.6), node)
    assert first is not None and second is not None
    assert second.credit == pytest.approx(0.6)
    assert second.probes_spent == 2
    assert len(ledger.entries()) == 1
    third = ledger.assign_causal_credit(_probe(0.2), node)
    assert third is not None
    assert third.credit == pytest.approx(0.6), "credit is a divergence, not a running sum"


def test_a_probe_with_only_a_delta_phi_shift_is_still_material():
    ledger = CausalCreditLedger()
    entry = ledger.assign_causal_credit(
        _probe(0.0, shift=-2.0), _node("a", sequence=1, delta_phi=2.0)
    )
    assert entry is not None


def test_ledger_never_exceeds_capacity_and_counts_every_eviction():
    ledger = CausalCreditLedger(capacity=MAX_LEDGER_ENTRIES, probe_budget=600)
    total = MAX_LEDGER_ENTRIES + 64
    for index in range(total):
        ledger.assign_causal_credit(
            _probe(0.05 + index / 10_000.0),
            _node(f"sig-{index:04d}", sequence=index, delta_phi=float(index)),
        )
    assert len(ledger.entries()) == MAX_LEDGER_ENTRIES
    assert ledger.evictions() == total - MAX_LEDGER_ENTRIES
    # The survivors are the most-credited, not the most recent.
    assert min(entry.credit for entry in ledger.entries()) > 0.05


def test_ledger_memory_is_bounded_and_measured():
    ledger = CausalCreditLedger(probe_budget=600)
    for index in range(MAX_LEDGER_ENTRIES + 32):
        ledger.assign_causal_credit(
            _probe(0.5),
            _node(f"sig-{index:04d}", sequence=index, delta_phi=1.0),
        )
    measured = ledger.memory_bytes()
    assert 0 < measured <= MAX_LEDGER_ENTRIES * 256
    assert ledger.to_dict()["memory_bytes"] == measured


def test_ledger_refuses_probes_beyond_its_session_budget():
    ledger = CausalCreditLedger(probe_budget=3)
    for index in range(5):
        ledger.assign_causal_credit(
            _probe(0.5), _node(f"sig-{index}", sequence=index, delta_phi=1.0)
        )
    assert ledger.probes_spent() == 3
    assert ledger.probes_refused() == 2
    assert len(ledger.entries()) == 3


def test_ledger_rejects_nonsense_construction():
    with pytest.raises(ContractError):
        CausalCreditLedger(capacity=0)
    with pytest.raises(ContractError):
        CausalCreditLedger(probe_budget=0)
    with pytest.raises(ContractError):
        top_k_by_delta_phi(_session(11).memory, k=-1)


def test_quality_numbers_are_none_without_ground_truth_and_never_zero():
    session = _session(11)
    ledger = CausalCreditLedger()
    ledger.assign_causal_credit(
        _probe(0.5), _node("sig-0", sequence=1, delta_phi=1.0)
    )
    report = ledger.report(session.memory)
    assert isinstance(report, AttributionReport)
    assert report.chain_recall is None
    assert report.conciseness_gain is None
    assert report.to_dict()["chain_recall"] is None
    assert chain_recall(frozenset({"a"}), ground_truth=None) is None
    assert chain_recall(frozenset({"a"}), ground_truth=frozenset()) is None


def test_conciseness_gain_is_none_when_recall_is_worse_than_naive():
    session = _session(11)
    ledger = CausalCreditLedger()
    # One credited node that is not in the chain: strictly worse recall than the
    # full ancestry, so a conciseness figure would be meaningless.
    ledger.assign_causal_credit(
        _probe(0.5), _node("not-in-chain", sequence=1, delta_phi=1.0)
    )
    report = ledger.report(session.memory, ground_truth=session.ground_truth)
    assert report.chain_recall == 0.0
    assert report.conciseness_gain is None
    assert report.naive_ancestry_nodes == len(naive_ancestry(session.memory))


def test_conciseness_gain_is_reported_when_recall_matches_naive():
    session = _session(11)
    ledger = CausalCreditLedger(probe_budget=600)
    for sequence, signature in enumerate(sorted(session.ground_truth), start=1):
        ledger.assign_causal_credit(
            _probe(0.5), _node(signature, sequence=sequence, delta_phi=1.0)
        )
    report = ledger.report(session.memory, ground_truth=session.ground_truth)
    assert report.chain_recall == pytest.approx(1.0)
    assert report.conciseness_gain is not None
    assert report.conciseness_gain == pytest.approx(
        report.naive_ancestry_nodes / report.nodes_inspected
    )


# --- value of information ---------------------------------------------------


class _CountingPolicy(AdaptiveObservationPolicy):
    """Real AOP behaviour, with the number of consultations visible."""

    def __init__(self, budget: AOPBudget | None = None) -> None:
        super().__init__(budget)
        self.considered = 0

    def consider(self, **kwargs: Any) -> EscalationDecision:
        self.considered += 1
        return super().consider(**kwargs)


class _SignalDroppingPolicy:
    """A policy that stops collecting a mandatory signal. Must be refused."""

    budget = AOPBudget()

    def collects(self, signal: str, target: str) -> bool:
        return signal != sorted(MANDATORY_SIGNALS)[0]


def _reducible(value: float) -> _Estimate:
    return _Estimate(
        value=value,
        sources={"EVIDENCE_INCOMPLETE": 0.7, "CONE_AMBIGUITY": 0.3},
    )


def _ambiguous_cone() -> _Cone:
    return _Cone(
        (_Branch("escalation", 0.3, 6.0), _Branch("routine", 0.3, 0.0)),
        unresolved_mass=0.4,
    )


def test_mandatory_signals_are_never_disabled_and_a_drop_is_refused():
    policy = _CountingPolicy()
    assert_mandatory_signals_intact(policy, target="lineage-a")
    with pytest.raises(ContractError):
        assert_mandatory_signals_intact(_SignalDroppingPolicy(), target="lineage-a")
    with pytest.raises(ContractError):
        request_observation_escalation(
            _reducible(0.9),
            _ambiguous_cone(),
            _SignalDroppingPolicy(),  # type: ignore[arg-type]
            target="lineage-a",
            now_ns=1,
        )


def test_no_expected_reduction_is_claimed_when_no_source_breakdown_exists():
    policy = _CountingPolicy()
    need = estimate_information_need(
        _Estimate(value=0.95), None, policy, target="lineage-a"
    )
    assert need.expected_uncertainty_reduction == 0.0
    assert need.worth_collecting is False
    assert "reducible share unknown" in need.detail


def test_irreducible_uncertainty_does_not_buy_telemetry():
    """Entropy and prototype distance are model limits, not missing evidence."""
    policy = _CountingPolicy()
    need, decision = request_observation_escalation(
        _Estimate(value=0.99, sources={"ENTROPY": 1.0}),
        _ambiguous_cone(),
        policy,
        target="lineage-a",
        now_ns=1,
    )
    assert need.value_of_information < MIN_VALUE_OF_INFORMATION
    assert decision.escalated is False
    assert policy.considered == 0, "a worthless request must not reach AOP at all"


def test_a_worthwhile_request_reaches_aop_and_can_be_granted():
    policy = _CountingPolicy()
    need, decision = request_observation_escalation(
        _reducible(0.9),
        _ambiguous_cone(),
        policy,
        target="lineage-a",
        now_ns=1,
        causal_relevance=0.9,
    )
    assert need.worth_collecting is True
    assert policy.considered == 1
    assert decision.escalated is True
    assert decision.level is not ObservationLevel.BASELINE


def test_a_refusal_is_recorded_and_never_retried():
    # max_escalations_per_window=0 makes AOP refuse everything that clears the
    # score threshold, which is the refusal path Stage 2 must respect.
    policy = _CountingPolicy(AOPBudget(max_escalations_per_window=0))
    tracker = InformationNeedTracker()
    _, first = tracker.request(
        _reducible(0.9), _ambiguous_cone(), policy, target="lineage-a", now_ns=1
    )
    assert first.escalated is False
    assert first.refused_reason
    consulted = policy.considered
    need, second = tracker.request(
        _reducible(0.9), _ambiguous_cone(), policy, target="lineage-a", now_ns=2
    )
    assert policy.considered == consulted, "a refusal must not be retried"
    assert second is first
    assert need.worth_collecting is False
    assert tracker.report().escalations_refused == 1
    assert len(tracker.refusals()) == 1


def test_measured_reduction_stays_none_until_an_observation_comes_back():
    policy = _CountingPolicy()
    tracker = InformationNeedTracker()
    tracker.request(
        _reducible(0.9), _ambiguous_cone(), policy, target="lineage-a", now_ns=1
    )
    assert tracker.report().measured_reduction is None
    reduction = tracker.record_observation(
        policy,
        target="lineage-a",
        extra_events=4,
        uncertainty_before=0.9,
        uncertainty_after=0.4,
    )
    assert reduction == pytest.approx(0.5)
    assert tracker.report().measured_reduction == pytest.approx(0.5)


def test_tracker_is_bounded_and_reports_truncation():
    policy = _CountingPolicy()
    tracker = InformationNeedTracker(max_requests=2)
    for index in range(5):
        tracker.request(
            _Estimate(value=0.1, sources={"ENTROPY": 1.0}),
            None,
            policy,
            target=f"lineage-{index}",
            now_ns=index,
        )
    report = tracker.report()
    assert len(report.requests) == 2
    assert report.truncated == 3
    with pytest.raises(ContractError):
        InformationNeedTracker(max_requests=0)


def test_uncertainty_only_control_thresholds_uncertainty_alone():
    policy = _CountingPolicy()
    below = uncertainty_only_requests(
        _Estimate(value=0.2), policy, target="lineage-a", now_ns=1
    )
    assert below.escalated is False
    assert policy.considered == 0
    above = uncertainty_only_requests(
        _Estimate(value=0.95), policy, target="lineage-b", now_ns=2
    )
    assert policy.considered == 1
    assert above.escalated is True


# --- G2.7: the measured attribution comparison ------------------------------


@dataclass(frozen=True, slots=True)
class _Attribution:
    mechanism: str
    nodes_inspected: float
    chain_recall: float
    #: Mean over only the sessions where recall matched the naive path. A gain
    #: averaged over sessions where recall was worse would be a smaller number
    #: dressed up as a better one, so the denominator travels with it.
    conciseness_gain: float | None
    sessions_at_naive_recall: int
    sessions: int


def _probe_session_with(
    session: _Session, *, model_based: bool
) -> AttributionReport:
    """Probe every transition once and report what an analyst would read."""
    quantizer, lattice = session.model()
    window = session.window()
    expander = _make_expander()
    nodes = {node.signature: node for node in naive_ancestry(session.memory)}
    ledger = CausalCreditLedger(probe_budget=len(session.encoded) + 1)
    for index, signature in enumerate(session.signatures):
        node = nodes.get(signature)
        if node is None:
            continue
        probe = (
            counterfactual_probe(
                window,
                quantizer,
                lattice,
                target_index=index,
                cone_expander=expander,
            )
            if model_based
            else phi_only_probe(window, target_index=index)
        )
        ledger.assign_causal_credit(probe, node)
    return ledger.report(session.memory, ground_truth=session.ground_truth)


def _measure_g27(
    seeds: tuple[int, ...],
) -> tuple[tuple[_Attribution, ...], dict[str, int]]:
    """The four mechanisms of spec §5, averaged over a fixed split."""
    verdict = {"g27_met_sessions": 0, "spine_beats_phi_recall": 0, "sessions": len(seeds)}
    rows: dict[str, list[tuple[int, float]]] = {
        "credit_spine": [],
        "naive_full_ancestry": [],
        "top_k_by_delta_phi": [],
        "phi_only_probe": [],
    }
    gains: dict[str, list[float]] = {
        "credit_spine": [],
        "phi_only_probe": [],
        "top_k_by_delta_phi": [],
    }
    for seed in seeds:
        session = _session(seed)
        truth = session.ground_truth
        naive = naive_ancestry(session.memory)
        naive_recall = chain_recall(
            frozenset(node.signature for node in naive), ground_truth=truth
        )
        assert naive_recall is not None
        rows["naive_full_ancestry"].append((len(naive), naive_recall))

        for mechanism, model_based in (
            ("credit_spine", True),
            ("phi_only_probe", False),
        ):
            report = _probe_session_with(session, model_based=model_based)
            rows[mechanism].append((report.nodes_inspected, report.chain_recall or 0.0))
            if report.conciseness_gain is not None:
                gains[mechanism].append(report.conciseness_gain)

        spine_nodes, spine_recall = rows["credit_spine"][-1]
        top_k = top_k_by_delta_phi(session.memory, k=max(1, spine_nodes))
        top_recall = chain_recall(
            frozenset(node.signature for node in top_k), ground_truth=truth
        )
        assert top_recall is not None
        rows["top_k_by_delta_phi"].append((len(top_k), top_recall))
        if top_recall >= naive_recall and top_k:
            gains["top_k_by_delta_phi"].append(len(naive) / len(top_k))
        if spine_nodes < len(naive) and spine_recall >= naive_recall:
            verdict["g27_met_sessions"] += 1
        if spine_recall > rows["phi_only_probe"][-1][1]:
            verdict["spine_beats_phi_recall"] += 1

    return tuple(
        _Attribution(
            mechanism=mechanism,
            nodes_inspected=sum(n for n, _ in samples) / len(samples),
            chain_recall=sum(r for _, r in samples) / len(samples),
            conciseness_gain=(
                sum(gains[mechanism]) / len(gains[mechanism])
                if gains.get(mechanism)
                else None
            ),
            sessions_at_naive_recall=len(gains.get(mechanism, ())),
            sessions=len(samples),
        )
        for mechanism, samples in rows.items()
    ), verdict


def _real_model(session: _Session) -> tuple[BehaviourQuantizer, TransitionLattice]:
    """Fit the real D2.6 quantizer and lattice over one session.

    The state is reconstructed from each step's ``state_delta_mask`` at level 1 —
    the same approximation the probe makes — so the atoms a probe looks up were
    built on the same footing it reasons on.
    """
    quantizer = BehaviourQuantizer()
    lattice = TransitionLattice()
    state = SecurityStateV1()
    previous: int | None = None
    for sequence, step in enumerate(session.encoded):
        for index, name in enumerate(DIMENSIONS):
            if step.state_delta_mask & (1 << index):
                state = state.raised_to(name, DIMENSIONS[name](1))
        result = quantizer.quantize_behaviour_atom(
            step, state=state, epoch_id=step.epoch_id, sequence=sequence
        )
        if previous is not None:
            lattice.observe(
                previous,
                result.atom_id,
                epoch_id=step.epoch_id,
                delta_phi=step.delta_phi,
                uncertainty=0.2,
            )
        previous = result.atom_id
    return quantizer, lattice


def test_default_expander_drives_the_real_d28_cone_and_the_real_work_ledger():
    """The seam, not a stand-in: real D2.6 atoms, real D2.8 cone, real D2.4 ledger."""
    session = _session(11)
    quantizer, lattice = _real_model(session)
    ledger = WorkLedger()
    ledger.begin("event-1")
    probe = counterfactual_probe(
        session.window(),
        quantizer,
        lattice,
        target_index=_credential_chain_index(session),
        ledger=ledger,
    )
    account = ledger.close()
    ledger.assert_no_phantom_savings()
    assert 0.0 <= probe.divergence <= 1.0
    assert probe.measured
    assert account.performed_units > 0.0
    # The enum, not the StrEnum value: the fallback import path must not be what
    # ran now that D2.4 is present.
    kinds = {record.kind for record in account.work}
    # Two cones are expanded per measured probe, and the observed one is charged
    # separately from the counterfactual so a refusal can cost 0.0 honestly.
    assert kinds == {WorkKind.CONE_EXPANSION, WorkKind.COUNTERFACTUAL}
    assert all(isinstance(kind, WorkKind) for kind in kinds)


def test_probe_does_not_mutate_the_real_quantizer_or_lattice():
    """The isolation invariant against the real D2.6 objects, not the stand-ins."""
    session = _session(11)
    quantizer, lattice = _real_model(session)
    before_atoms = tuple(atom.to_dict() for atom in quantizer.atoms())
    before_stats = quantizer.stats().to_dict()
    before_lattice = lattice.memory_bytes(), lattice.evictions()
    target = _credential_chain_index(session)

    for intervention in Intervention:
        counterfactual_probe(
            session.window(),
            quantizer,
            lattice,
            target_index=target,
            intervention=intervention,
        )

    assert tuple(atom.to_dict() for atom in quantizer.atoms()) == before_atoms
    assert quantizer.stats().to_dict() == before_stats
    assert (lattice.memory_bytes(), lattice.evictions()) == before_lattice


def test_real_uncertainty_estimate_flows_through_value_of_information():
    session = _session(11)
    quantizer, lattice = _real_model(session)
    cone = predict_future_cone(
        lattice,
        quantizer,
        from_atom=quantizer.atoms()[0].atom_id,
        state=SecurityStateV1(),
        epoch_id=0,
    )
    estimate = UncertaintyEstimate(
        value=0.9,
        sources={"EVIDENCE_INCOMPLETE": 0.7, "CONE_AMBIGUITY": 0.3},
        calibration_id=None,
        quadrant=EpistemicQuadrant.ESCALATE,
        abstain=False,
        detail="",
    )
    policy = _CountingPolicy()
    need, decision = request_observation_escalation(
        estimate, cone, policy, target="lineage-a", now_ns=1
    )
    assert need.worth_collecting is True
    assert policy.considered == 1
    # AOP may still refuse on its own budget score; Stage 2 records that answer.
    assert decision.escalated or decision.refused_reason
    tracker = InformationNeedTracker()
    tracker.request(estimate, cone, policy, target="lineage-b", now_ns=2)
    assert tracker.report().measured_reduction is None


def test_g27_attribution_comparison_on_the_real_lattice_and_cone(capsys):
    """G2.7 again, with the real D2.6/D2.8 stack instead of the stand-ins.

    Reported, not asserted into a verdict: this is the number ADR-0122 must be
    re-derived against once the sibling packages settle.
    """
    inspected: list[int] = []
    recalls: list[float] = []
    naive_nodes: list[int] = []
    for seed in FIXTURE_SEEDS:
        session = _session(seed)
        quantizer, lattice = _real_model(session)
        nodes = {node.signature: node for node in naive_ancestry(session.memory)}
        ledger = CausalCreditLedger(probe_budget=len(session.encoded) + 1)
        window = session.window()
        for index, signature in enumerate(session.signatures):
            node = nodes.get(signature)
            if node is not None:
                ledger.assign_causal_credit(
                    counterfactual_probe(
                        window, quantizer, lattice, target_index=index
                    ),
                    node,
                )
        report = ledger.report(session.memory, ground_truth=session.ground_truth)
        inspected.append(report.nodes_inspected)
        recalls.append(report.chain_recall or 0.0)
        naive_nodes.append(report.naive_ancestry_nodes)
    mean_inspected = sum(inspected) / len(inspected)
    mean_recall = sum(recalls) / len(recalls)
    mean_naive = sum(naive_nodes) / len(naive_nodes)
    with capsys.disabled():
        print(
            f"\nG2.7 with the REAL D2.6 quantizer and D2.8 cone, "
            f"seeds={FIXTURE_SEEDS}, synthetic_data=True"
        )
        print(
            f"credit_spine nodes_inspected={mean_inspected:.2f} "
            f"chain_recall={mean_recall:.4f}  |  "
            f"naive_full_ancestry nodes={mean_naive:.2f} chain_recall=1.0000"
        )
        print(
            "G2.7 met on the aggregate: "
            f"{mean_inspected < mean_naive and mean_recall >= 1.0}"
        )
    assert 0.0 <= mean_recall <= 1.0
    assert mean_inspected < mean_naive, "the spine must at least be more concise"


def test_g27_attribution_comparison_is_measured_and_reported(capsys):
    """G2.7. Reports all four mechanisms; asserts only that each was measured.

    No assertion says the credit spine wins. If it does not, ADR-0122 records
    that and the honest recommendation is to keep the Φ-only path.
    """
    results, verdict = _measure_g27(FIXTURE_SEEDS)
    by_mechanism = {row.mechanism: row for row in results}
    assert set(by_mechanism) == {
        "credit_spine",
        "naive_full_ancestry",
        "top_k_by_delta_phi",
        "phi_only_probe",
    }
    with capsys.disabled():
        print(
            f"\nG2.7 attribution, fixture 'fixture-escalation-chain', "
            f"seeds={FIXTURE_SEEDS}, sessions={len(FIXTURE_SEEDS)}, synthetic_data=True"
        )
        print(
            f"{'mechanism':<22}{'nodes_inspected':>17}{'chain_recall':>14}"
            f"{'conciseness':>13}{'at_naive_recall':>17}"
        )
        for row in results:
            is_control = row.mechanism == "naive_full_ancestry"
            gain = (
                "-"
                if is_control
                else ("None" if row.conciseness_gain is None else f"{row.conciseness_gain:.4f}")
            )
            at = "-" if is_control else f"{row.sessions_at_naive_recall}/{row.sessions}"
            print(
                f"{row.mechanism:<22}{row.nodes_inspected:>17.2f}"
                f"{row.chain_recall:>14.4f}{gain:>13}{at:>17}"
            )
    naive = by_mechanism["naive_full_ancestry"]
    assert naive.chain_recall == pytest.approx(1.0)
    for row in results:
        assert row.nodes_inspected >= 0.0
        assert 0.0 <= row.chain_recall <= 1.0
    # The gate criterion, evaluated rather than asserted into existence.
    spine = by_mechanism["credit_spine"]
    phi = by_mechanism["phi_only_probe"]
    g27_met = (
        spine.nodes_inspected < naive.nodes_inspected
        and spine.chain_recall >= naive.chain_recall
    )
    with capsys.disabled():
        print(
            f"G2.7 met on the aggregate: {g27_met}; "
            f"met per session: {verdict['g27_met_sessions']}/{verdict['sessions']}; "
            f"credit spine beats phi_only_probe recall on "
            f"{verdict['spine_beats_phi_recall']}/{verdict['sessions']} sessions"
        )
    # Recorded as a measurement, not a requirement: if the Φ-only control is not
    # worse, the model-based twin has not earned its place (ADR-0122).
    assert phi.chain_recall >= 0.0 and spine.chain_recall >= 0.0
