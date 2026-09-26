"""D5.19 — the response corpus, and the three defects it is built to make visible.

Every case here is a fixture this wave wrote. The declared answer lives in
:class:`GroundTruthResponse`, named ``truth`` at every use site so no reader
mistakes it for a measurement of a Linux host: it is a table, and "collateral"
means "what that table says". Spec §6.1 and §9.2 carry the confound in full; this
module carries it in the field name.

**The ambiguous pair is the point.** Each pair is a benign-administrator case and
a compromised case whose :class:`CBFResolutionV1` is *byte-identical* — same claim
graph, same evidence lineage, two hypotheses within ``IDENTIFIABILITY_MARGIN`` of
one another — and whose simulated hosts hold the same rows. They differ **only**
in ``truth``. A planner that commits to the leading world must be wrong on half of
them; a planner that can decline may return no action or an O0/O1 candidate. If
multi-world evaluation does not reduce collateral here, falsifier F2 has fired and
that is the result.

**Three honesty rules, each from a defect already paid for in this repository, and
each enforced by a test in tests/test_stage5_benchmarks.py.**

1. *Session-unique identities.* Stage 1 carries lineage state across scenarios, and
   a corpus reusing process identities between sessions silently erased its own
   signal — median dPhi 0.00 for both classes, and a +0.042 headline that had to be
   retracted (``planning/MEMORY.md``). Every identity here is unique in
   ``(pid, start_time_ticks)`` by construction: ``pid`` is a bijection of
   ``(seed, offset)`` and the tick is a function of the pid.
2. *No operator vocabulary signal.* Corpora here have twice leaked through
   vocabulary, handing a bag-of-features control a free perfect score. The harmful
   and sufficient operator-id vocabularies are **identical** across the
   ambiguous/unambiguous split, so nothing can be keyed on which operators appear.
3. *Indistinguishable pairs.* A pair whose two resolutions differ anywhere does not
   test ambiguity; it tests whether the planner can read the difference.

**Two corpus parameters that are not measurements**, stated here because they will
otherwise be misread as findings. Both exist because two other packages' defaults
compose into a corpus on which nothing ever acts:

- ``CORPUS_MAX_AUTONOMOUS_DOWNTIME_SECONDS`` is 900, not
  ``DEFAULT_MISSION_INVARIANTS``' 300. Every O3+ catalog entry declares
  ``max_duration_seconds = 900`` and ``generate_action_field`` proposes a candidate
  at exactly that TTL, so under a 300 s bound ``SUSPEND_PROCESS`` is refused at
  generation on *every* case and every baseline takes zero actions.
- ``CORPUS_INVARIANTS`` carries **no** ``EVIDENCE_RETENTION`` member. With one, a
  ``DEGRADES_VOLATILE`` operator is structurally unusable: a retained signal the
  target carries makes ``MissionInvariantSet.violations`` refuse the operator
  before it is proposed, and a retained signal the target does *not* carry makes
  the ``OBSERVATION_RETAINED`` postcondition fail at VERIFY. Either way no suspend
  ever commits. Evidence preservation here is therefore carried by
  ``RetentionPolicy.uniquely_necessary`` at the gate — the mechanism §13 actually
  names — and :func:`build_evidence_destroying_cases` exercises it.
  :data:`RETENTION_INVARIANTS` keeps a set *with* the retention member so the
  interaction can be reproduced rather than quietly designed around.

``DEFAULT_MISSION_INVARIANTS`` is not modified. These are corpus objects.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef, digest_of_bytes
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage1.state.security_state import (
    CredentialExposure,
    Discovery,
    ExecutionControl,
    ModificationCapability,
    Persistence,
    Privilege,
    Reachability,
    SecurityStateV1,
    Trust,
)
from pocketsec.stage4.stage5_interface import CBFResolutionV1
from pocketsec.stage5.constitution.schema import (
    InvariantKind,
    MissionInvariant,
    MissionInvariantSet,
)
from pocketsec.stage5.executor.identity import ManualClock
from pocketsec.stage5.host.simulated import (
    FaultProfile,
    ProcessRow,
    ProcessState,
    ServiceRow,
    SimulatedHost,
)
from pocketsec.stage5.operators.algebra import OperatorClass, ProcessIdentity
from pocketsec.stage5.operators.catalog import CATALOG
from pocketsec.stage5.safe.action_field import HarmModel

__all__ = [
    "AMBIGUOUS_SUPPORT_GAP",
    "BENIGN_MECHANISMS",
    "BUILDER_SLICES",
    "CLEAR_SUPPORT_GAP",
    "CORPUS_INVARIANTS",
    "CORPUS_MAX_AUTONOMOUS_DOWNTIME_SECONDS",
    "CORPUS_MAX_CONTAINMENT_SECONDS",
    "CRITICAL_UNITS",
    "HOSTILE_MECHANISMS",
    "MAX_CASE_PROCESSES",
    "MAX_CORPUS_CASES",
    "MAX_SESSIONS_PER_FLOOD_CASE",
    "NEIGHBOUR_UNIT",
    "ORDINARY_UNIT",
    "ORDINARY_VOLATILE",
    "POLICY_HARM_BY_MECHANISM",
    "RESPONSE_CORPUS_VERSION",
    "RETENTION_INVARIANTS",
    "UNIQUELY_NECESSARY_VOLATILE",
    "GroundTruthResponse",
    "ResponseCase",
    "build_action_flood",
    "build_ambiguous_pairs",
    "build_critical_service_baits",
    "build_evidence_destroying_cases",
    "build_response_corpus",
    "build_toctou_cases",
    "build_two_epoch_corpus",
    "corpus_digest",
    "corpus_identities",
    "operator_vocabulary",
]

RESPONSE_CORPUS_VERSION: str = "stage5-response-corpus-v0.1.0"

#: Spec bound: a case may hold no more processes than this. The flood builder fills
#: a case to the bound, which drives candidate explosion without an unbounded fixture.
MAX_CASE_PROCESSES: int = 24

#: Bounds the per-builder pid slice arithmetic. A larger corpus would let two
#: builders' pid ranges meet, and a reused identity is the defect rule 1 prevents.
MAX_CORPUS_CASES: int = 400

#: ``SimulatedHost`` bounds a host at ``MAX_SIMULATED_SESSIONS = 16``. The corpus
#: respects that bound rather than raising it, so only this many flood rows carry a
#: session.
MAX_SESSIONS_PER_FLOOD_CASE: int = 12

#: Within ``IDENTIFIABILITY_MARGIN`` (0.15, ``stage4/identifiability/resolution.py``):
#: two hypotheses this close are not separable, which is what the pair asserts.
AMBIGUOUS_SUPPORT_GAP: float = 0.10

#: Wide enough that the trailing hypothesis lands at exactly ``RULED_OUT_SUPPORT``
#: (0.05, ``safe/action_field.py``) and *is* ruled out. That matters: with a rival that
#: survives, ``check_response_identifiability`` refuses every intervention on every
#: case, the multi-world arm never acts, and the corpus has no headroom to show
#: anything. ``_resolution`` maps this gap to supports 0.95 / 0.05.
CLEAR_SUPPORT_GAP: float = 0.90

#: Chosen corpus parameters. See the module docstring; neither is a measurement.
CORPUS_MAX_AUTONOMOUS_DOWNTIME_SECONDS: int = 900
CORPUS_MAX_CONTAINMENT_SECONDS: int = 900

CRITICAL_UNITS: frozenset[str] = frozenset({"sshd.service", "systemd-journald.service"})
ORDINARY_UNIT: str = "app.service"
NEIGHBOUR_UNIT: str = "cache.service"

#: Volatile signals an ordinary target carries — deliberately disjoint from
#: ``DEFAULT_RETENTION.uniquely_necessary``, so an ordinary case exercises the
#: permitted path through the preservation gate and the destroying builder
#: exercises the refusal.
ORDINARY_VOLATILE: tuple[str, ...] = ("audit_trail", "environment")

#: Two members of ``DEFAULT_RETENTION.uniquely_necessary``. A target carrying these
#: makes any ``DEGRADES_VOLATILE`` operator a refusal at the gate.
UNIQUELY_NECESSARY_VOLATILE: tuple[str, ...] = ("process_memory", "socket_table")

#: Rule 1's arithmetic. Each builder owns a disjoint pid slice; one case occupies
#: ``MAX_CASE_PROCESSES`` consecutive offsets inside it.
BUILDER_SLICES: Mapping[str, int] = {
    "corpus": 0,
    "ambiguous": 10_000,
    "bait": 20_000,
    "toctou": 30_000,
    "evidence": 40_000,
    "flood": 50_000,
    "two_epoch": 60_000,
}

_PID_BASE: int = 100_000
#: One seed's whole pid space; every slice plus its offsets fits inside it, which is
#: what makes ``pid`` a bijection of ``(seed, offset)``.
_PID_STRIDE: int = 100_000
_TICK_BASE: int = 4_000_000

#: Mechanism ids whose world is benign administration, and ids whose world is
#: hostile. The split is **load-bearing**: :data:`POLICY_HARM_BY_MECHANISM` keys on
#: the mechanism, and a corpus where ``benign_admin`` did not follow the mechanism id
#: would hand the planner a harm table that contradicts its own ground truth.
BENIGN_MECHANISMS: tuple[str, ...] = ("admin_maintenance_window", "service_reconfiguration")
HOSTILE_MECHANISMS: tuple[str, ...] = ("credential_theft_chain", "persistence_install")
_MECHANISMS: tuple[str, ...] = (*BENIGN_MECHANISMS, *HOSTILE_MECHANISMS)

#: The defender's **policy** harm table: which operator classes are unacceptable in
#: each world. A pure function of the mechanism id, and therefore **identical for
#: both members of an ambiguous pair** — which is the point. Deriving this from
#: ``GroundTruthResponse.harmful_operator_ids`` instead would hand the planner the
#: answer through its own policy input, and the pair would stop testing ambiguity.
#: Intervening at all in a maintenance world is unacceptable; in a hostile world only
#: the session-wide, service-wide and irreversible classes are.
POLICY_HARM_BY_MECHANISM: Mapping[str, frozenset[OperatorClass]] = {
    "admin_maintenance_window": frozenset(
        cls for cls in OperatorClass if cls >= OperatorClass.O2_REVERSIBLE_RESTRICT
    ),
    "service_reconfiguration": frozenset(
        cls for cls in OperatorClass if cls >= OperatorClass.O2_REVERSIBLE_RESTRICT
    ),
    "credential_theft_chain": frozenset(
        cls for cls in OperatorClass if cls >= OperatorClass.O4_LOCAL_REVOKE
    ),
    "persistence_install": frozenset(
        cls for cls in OperatorClass if cls >= OperatorClass.O4_LOCAL_REVOKE
    ),
}

#: Both sides of the split draw from *these two sets*, so the vocabularies are
#: identical and rule 2 holds by construction rather than by a later audit. Which
#: ids land in which field is what differs between a benign-admin case and a
#: compromised one — and ``truth`` is never an input to any planner or baseline.
_INTERVENTION_IDS: tuple[str, ...] = (
    "SUSPEND_PROCESS",
    "RESTRICT_LOCAL_SOCKET",
    "REVOKE_LOCAL_SESSION",
    "CONSTRAIN_SERVICE",
    "TERMINATE_PROCESS",
)
_OBSERVATION_IDS: tuple[str, ...] = (
    "OBSERVE_PROCESS_METADATA",
    "SNAPSHOT_PROCESS_STATE",
    "PRESERVE_VOLATILE_EVIDENCE",
    "HASH_EXECUTABLE",
)

#: Phi 4.0 under ``stage1.state.potential.phi`` — below the B2 playbook's chosen
#: threshold of 6.0, which sits between Stage 1's measured benign mean of 0.62 and
#: malicious 9.46. The states are fixtures; those two Stage 1 figures are measured.
_BENIGN_ADMIN_STATE = SecurityStateV1(
    privilege=Privilege.ROOT,
    trust=Trust.TRUSTED,
    discovery=Discovery.LOCAL_INVENTORY,
    modification=ModificationCapability.CONFIG,
)
#: Phi 10.0 — above that threshold, so the playbook fires.
_COMPROMISED_STATE = SecurityStateV1(
    privilege=Privilege.ROOT,
    trust=Trust.UNTRUSTED,
    credential=CredentialExposure.READABLE,
    reachability=Reachability.LAN,
    persistence=Persistence.USER,
    execution=ExecutionControl.INTERPRETER,
)

#: ``(id, kind, subject, bound_seconds, detail)`` rows. Data, kept compact because
#: nine nested constructor calls read worse than nine rows.
_K = InvariantKind
_INVARIANT_ROWS: tuple[tuple[str, InvariantKind, str, int | None, str], ...] = (
    ("MC-01", _K.CRITICAL_SERVICE, "sshd.service", None, "the admin could be stranded"),
    ("MC-02", _K.CRITICAL_SERVICE, "systemd-journald.service", None, "the incident log path"),
    ("MC-03", _K.ADMIN_RECOVERY_ACCESS, "admin-recovery", None, "the recovery session"),
    ("MC-04", _K.BOUNDARY_NOT_CROSSED, "netns:quarantine", None, "off-boundary namespace"),
    ("MC-05", _K.MAX_AUTONOMOUS_DOWNTIME, "", CORPUS_MAX_AUTONOMOUS_DOWNTIME_SECONDS,
     "a chosen corpus bound; see the module docstring, not a measurement"),
    ("MC-06", _K.MAX_CONTAINMENT_DURATION, "", CORPUS_MAX_CONTAINMENT_SECONDS,
     "the catalog's own maximum operator duration"),
    ("MC-07", _K.FORBIDDEN_KERNEL_MODIFICATION, "", None, "no kernel surface"),
    ("MC-08", _K.HOST_LOCAL_SCOPE, "", None, "this host only"),
)

#: The retention row the corpus set deliberately omits; see the module docstring.
_RETENTION_ROW = (
    "MC-09", _K.EVIDENCE_RETENTION, ORDINARY_VOLATILE[0], 900,
    "a retained signal an ordinary target carries; see the module docstring",
)

#: Eight invariants covering seven of the eight kinds. ``EVIDENCE_RETENTION`` is
#: absent for the reason the module docstring gives at length.
CORPUS_INVARIANTS: MissionInvariantSet = MissionInvariantSet(
    tuple(MissionInvariant(*row) for row in _INVARIANT_ROWS)
)

#: The same set plus the retention member, so the interaction the docstring
#: describes can be reproduced rather than taken on trust.
RETENTION_INVARIANTS: MissionInvariantSet = MissionInvariantSet(
    tuple(MissionInvariant(*row) for row in (*_INVARIANT_ROWS, _RETENTION_ROW))
)


@dataclass(frozen=True, slots=True)
class GroundTruthResponse:
    """What the corpus author declares about a case. **Not a measurement.**

    Bound to the name ``truth`` wherever it is used, including
    ``check_response_identifiability(..., truth=...)``, because every quality number
    this corpus produces is a number about these six fields.
    """

    harmful_operator_ids: frozenset[str]
    sufficient_operator_ids: frozenset[str]
    critical_units: frozenset[str]
    uniquely_necessary_evidence: frozenset[str]
    true_mechanism_id: str
    benign_admin: bool

    def __post_init__(self) -> None:
        for name in ("harmful_operator_ids", "sufficient_operator_ids"):
            ids = frozenset(getattr(self, name))
            unknown = sorted(ids - set(CATALOG))
            if unknown:
                raise ContractError(
                    f"GroundTruthResponse.{name} names {unknown}, which are not catalog "
                    "entries; a truth table naming an operator the executor cannot build "
                    "measures nothing (Stage 3 shipped seven such forms, ADR-0027)"
                )
            object.__setattr__(self, name, ids)
        object.__setattr__(self, "critical_units", frozenset(self.critical_units))
        object.__setattr__(
            self, "uniquely_necessary_evidence", frozenset(self.uniquely_necessary_evidence)
        )
        if not self.true_mechanism_id:
            raise ContractError("GroundTruthResponse.true_mechanism_id must be non-empty")
        if not isinstance(self.benign_admin, bool):
            raise ContractError("GroundTruthResponse.benign_admin must be a bool")

    def to_dict(self) -> dict[str, Any]:
        return {
            "harmful_operator_ids": sorted(self.harmful_operator_ids),
            "sufficient_operator_ids": sorted(self.sufficient_operator_ids),
            "critical_units": sorted(self.critical_units),
            "uniquely_necessary_evidence": sorted(self.uniquely_necessary_evidence),
            "true_mechanism_id": self.true_mechanism_id,
            "benign_admin": self.benign_admin,
        }


@dataclass(frozen=True, slots=True)
class ResponseCase:
    """One incident: the upstream resolution, a simulated host, and the answer.

    ``faults`` is carried beyond the spec's field list for one reason: ten baseline
    arms must each see a *pristine* host, and :meth:`respawn` cannot rebuild a
    :class:`SimulatedHost` from a snapshot alone because a snapshot does not carry
    the fault profile. Without it, arm two would measure the host arm one left
    behind — the class of defect that made a Stage 2 baseline score 0.55, and 0.94
    once fixed.
    """

    case_id: str
    resolution: CBFResolutionV1
    host: SimulatedHost
    truth: GroundTruthResponse
    harm: HarmModel
    invariants: MissionInvariantSet
    ambiguous: bool
    faults: FaultProfile

    def __post_init__(self) -> None:
        if not self.case_id:
            raise ContractError("ResponseCase.case_id must be non-empty")
        if not isinstance(self.ambiguous, bool):
            raise ContractError("ResponseCase.ambiguous must be a bool")
        held = len(self.host.snapshot().processes)
        if held > MAX_CASE_PROCESSES:
            raise ContractError(
                f"{self.case_id} holds {held} processes, over "
                f"MAX_CASE_PROCESSES={MAX_CASE_PROCESSES}"
            )

    def respawn(self) -> ResponseCase:
        """An identical case on a brand-new host, for the next arm to run on.

        The harness calls this before every arm, so the caller's corpus stays
        pristine and ten arms start from byte-identical hosts. Called on a case that
        has already been executed against, it returns that case's *current* state,
        which is why the harness never does.
        """
        snapshot = self.host.snapshot()
        return replace(
            self,
            host=SimulatedHost(
                processes=snapshot.processes,
                services=snapshot.services,
                sessions=snapshot.sessions,
                security_state=snapshot.security_state,
                faults=self.faults,
                clock=ManualClock(at=snapshot.at),
            ),
        )


# --- identities, the rule-1 arithmetic ---------------------------------------


def _offset(builder: str, index: int, slot: int) -> int:
    """A corpus-wide unique offset for one process in one case."""
    if builder not in BUILDER_SLICES:
        raise ContractError(f"unknown corpus builder {builder!r}; known: {sorted(BUILDER_SLICES)}")
    if not 0 <= index < MAX_CORPUS_CASES:
        raise ContractError(
            f"case index {index} is outside [0, MAX_CORPUS_CASES={MAX_CORPUS_CASES}); a larger "
            "corpus would let two builders' pid slices meet, and a reused identity erases the "
            "signal it was built to carry"
        )
    if not 0 <= slot < MAX_CASE_PROCESSES:
        raise ContractError(f"process slot {slot} is outside [0, {MAX_CASE_PROCESSES})")
    return BUILDER_SLICES[builder] + index * MAX_CASE_PROCESSES + slot


def _identity(
    builder: str, index: int, slot: int, *, seed: int, uid: int = 1000
) -> ProcessIdentity:
    """A session-unique identity. ``pid`` is a bijection of ``(seed, offset)``.

    The executable digest is a **fixture**, not a file hash: real executable hashing
    needs a real filesystem (§9.2 item 8). It is present rather than ``None``
    because ``DEFAULT_RETENTION.required_signals`` includes ``executable_digest``,
    so a corpus of ``None`` digests would make the preservation gate answer
    ``INSUFFICIENT_EVIDENCE`` on every case and nothing downstream would ever run.
    """
    if not 0 <= seed < 1000:
        raise ContractError(f"corpus seed {seed} must be in [0, 1000) for pid uniqueness")
    pid = _PID_BASE + seed * _PID_STRIDE + _offset(builder, index, slot)
    return ProcessIdentity(
        pid=pid,
        start_time_ticks=_TICK_BASE + pid,
        uid=uid,
        executable_digest=digest_of_bytes(f"fixture-executable-{pid}".encode()),
        cgroup_id=f"cg:{builder}:{index}",
        namespace_id="netns:app",
    )


def corpus_identities(cases: Sequence[ResponseCase]) -> tuple[tuple[int, int], ...]:
    """Every ``(pid, start_time_ticks)`` pair the cases' hosts hold, in order."""
    return tuple(
        (row.identity.pid, row.identity.start_time_ticks)
        for case in cases
        for row in case.host.snapshot().processes
    )


def corpus_digest(cases: Sequence[ResponseCase]) -> str:
    """Bare-hex sha256 over every case's resolution, host rows and ``truth``, in order.

    The ledger's ``dataset_sha256`` field. A recorded ablation that cannot name the
    exact corpus it ran on is a result nobody can reproduce, so the digest covers the
    three things an arm's outcome depends on and nothing else. Bare hex because that
    is the form ``experiments/registry.jsonl`` already stores.
    """
    if not cases:
        raise ContractError("an empty corpus has no digest worth recording")
    payload = [
        {
            "case_id": case.case_id,
            "resolution": case.resolution.to_dict(),
            "host": case.host.snapshot().to_dict(),
            "truth": case.truth.to_dict(),
        }
        for case in cases
    ]
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return digest_of_bytes(canonical.encode("utf-8")).removeprefix("sha256:")


def operator_vocabulary(cases: Sequence[ResponseCase]) -> frozenset[str]:
    """The union of every operator id the cases' ``truth`` tables name.

    Rule 2's measurable quantity: two splits whose vocabularies differ hand a
    bag-of-operators control a free signal, which is how two Stage 2 corpora leaked.
    """
    return frozenset(
        operator_id
        for case in cases
        for operator_id in (*case.truth.harmful_operator_ids, *case.truth.sufficient_operator_ids)
    )


# --- resolutions --------------------------------------------------------------


def _evidence(case_id: str) -> EvidenceRef:
    return EvidenceRef(
        store="stage5-labs",
        locator=f"response-corpus/{case_id}",
        digest=digest_of_bytes(f"{RESPONSE_CORPUS_VERSION}:{case_id}".encode()),
    )


def _hypothesis(mechanism: str, support: float, digest: str, uncertainty: float) -> dict[str, Any]:
    return {
        "mechanism_id": mechanism,
        "support": support,
        "consequence": 1.0,
        "uncertainty": uncertainty,
        "claim_ids": [],
        "evidence_digests": [digest],
    }


def _lineage_row(reference: EvidenceRef, row: ProcessRow) -> dict[str, str]:
    """The lineage row ``generate_action_field`` resolves a target from.

    Only the four closed ``LINEAGE_TARGET_KEYS`` plus the ``EvidenceRef`` triple. No
    prose: the field layer reads keys, never sentences.
    """
    named: dict[str, str] = {
        "store": reference.store,
        "locator": reference.locator,
        "digest": reference.digest,
        "target_pid": str(row.identity.pid),
    }
    if row.unit is not None:
        named["target_unit"] = row.unit
    if row.session_id is not None:
        named["target_session"] = row.session_id
    if row.socket_ids:
        named["target_socket"] = row.socket_ids[0]
    return named


def _resolution(
    *,
    case_id: str,
    epoch_id: int,
    leading: str,
    rival: str,
    gap: float,
    rows: Sequence[ProcessRow],
    uncertainty: float,
    identifiability: str = "IDENTIFIED",
) -> CBFResolutionV1:
    """Built through Stage 4's own type, so Stage 4's export refusals apply.

    ``claim_ids`` are empty: a cited claim must resolve in the exported claim graph,
    and a fixture citing a claim it does not carry would be refused by Stage 4's
    seam rather than by anything this corpus is testing.
    """
    reference = _evidence(case_id)
    leading_support = min(0.95, 0.5 + gap / 2.0)
    return CBFResolutionV1(
        resolution_id=f"RES-{case_id}",
        incident_id=f"INC-{case_id}",
        epoch_id=epoch_id,
        verdict=Verdict.MALICIOUS,
        identifiability=identifiability,
        hypotheses=(
            _hypothesis(leading, leading_support, reference.digest, uncertainty),
            _hypothesis(rival, round(leading_support - gap, 4), reference.digest, uncertainty),
        ),
        consequence_distribution={"service_disruption": 0.3, "credential_loss": 0.2},
        claim_graph={"claims": []},
        evidence_lineage=tuple(_lineage_row(reference, row) for row in rows),
        uncertainty=uncertainty,
        shadow={"unobserved_signals": 1},
        information_gaps=(),
        truncations=(),
        degradations=(),
    )


# --- hosts and truth ----------------------------------------------------------


def _process(
    identity: ProcessIdentity,
    *,
    unit: str | None,
    session: str | None,
    socket: str | None,
    volatile: Sequence[str],
) -> ProcessRow:
    return ProcessRow(
        identity=identity,
        state=ProcessState.RUNNING,
        unit=unit,
        session_id=session,
        socket_ids=() if socket is None else (socket,),
        children=(),
        volatile_signals=tuple(volatile),
    )


def _host(
    rows: Sequence[ProcessRow],
    *,
    state: SecurityStateV1,
    faults: FaultProfile,
    units: Sequence[str],
    at: int = 1_000,
) -> SimulatedHost:
    return SimulatedHost(
        processes=tuple(rows),
        services=tuple(
            ServiceRow(
                unit=unit,
                running=True,
                constrained=False,
                restartable=True,
                depends_on=(),
                healthy=True,
            )
            for unit in units
        ),
        sessions=tuple(
            dict.fromkeys(row.session_id for row in rows if row.session_id is not None)
        ),
        security_state=state,
        faults=faults,
        clock=ManualClock(at=at),
    )


def _truth(
    *, benign_admin: bool, mechanism_id: str, evidence: Sequence[str]
) -> GroundTruthResponse:
    """The declared answer for one case, drawn from the shared vocabularies.

    On a benign-administrator case every intervention is harmful and only
    observation is sufficient. On a compromised case the reversible O2/O3 pair is
    sufficient and the irreversible and service-wide ones stay harmful. Both sides
    name ids from :data:`_INTERVENTION_IDS` and :data:`_OBSERVATION_IDS` only, so
    the two vocabularies are identical (rule 2).

    **No observation operator is sufficient on a compromised case.** An earlier
    revision listed ``OBSERVE_PROCESS_METADATA`` there, which scored an arm that
    merely looked at a hostile process as having *contained* it. That flatters any
    arm that declines to intervene — the multi-world planner above all — and turns
    the containment axis into a count of actions. Declining on a compromised case is
    a miss, and it is the honest price of caution on an ambiguous pair.
    """
    if benign_admin:
        harmful = frozenset(_INTERVENTION_IDS)
        sufficient = frozenset(_OBSERVATION_IDS)
    else:
        harmful = frozenset({"REVOKE_LOCAL_SESSION", "CONSTRAIN_SERVICE", "TERMINATE_PROCESS"})
        sufficient = frozenset({"SUSPEND_PROCESS", "RESTRICT_LOCAL_SOCKET"})
    return GroundTruthResponse(
        harmful_operator_ids=harmful,
        sufficient_operator_ids=sufficient,
        critical_units=CRITICAL_UNITS,
        uniquely_necessary_evidence=frozenset(evidence),
        true_mechanism_id=mechanism_id,
        benign_admin=benign_admin,
    )


def _harm(mechanisms: Sequence[str]) -> HarmModel:
    """The defender's policy harm table for the worlds this case names.

    A pure function of the **mechanism ids** — never of ``truth`` and never of a model
    score. Two consequences, both deliberate:

    * both members of an ambiguous pair get the *same* harm model, so the planner
      cannot read the answer out of its own policy input;
    * §D5.2's rule holds: the table is authored or invariant-derived, and a harm model
      inferred from a prediction would let confidence grant authority by the back door.
    """
    return HarmModel(
        unacceptable=frozenset(
            (mechanism_id, operator_class)
            for mechanism_id in mechanisms
            for operator_class in POLICY_HARM_BY_MECHANISM[mechanism_id]
        )
    )


def _case(
    *,
    case_id: str,
    rows: Sequence[ProcessRow],
    state: SecurityStateV1,
    truth: GroundTruthResponse,
    epoch_id: int,
    gap: float,
    rival: str,
    uncertainty: float,
    faults: FaultProfile,
    invariants: MissionInvariantSet = CORPUS_INVARIANTS,
    ambiguous: bool = False,
) -> ResponseCase:
    return ResponseCase(
        case_id=case_id,
        resolution=_resolution(
            case_id=case_id,
            epoch_id=epoch_id,
            leading=truth.true_mechanism_id,
            rival=rival,
            gap=gap,
            rows=rows,
            uncertainty=uncertainty,
        ),
        host=_host(
            rows,
            state=state,
            faults=faults,
            units=(ORDINARY_UNIT, NEIGHBOUR_UNIT, *sorted(CRITICAL_UNITS)),
        ),
        truth=truth,
        harm=_harm((truth.true_mechanism_id, rival)),
        invariants=invariants,
        ambiguous=ambiguous,
        faults=faults,
    )


def _world_pair(slot: int, *, benign: bool) -> tuple[str, str]:
    """``(leading, rival)`` mechanism ids for one case.

    The leading world is the one the case's ``truth`` declares real, so an
    unambiguous case's evidence points at the right answer and the simple controls
    are *right* on it. The ambiguous builder does not use this: there, the benign
    world leads and the truth is the trailing one half the time.
    """
    benign_id = BENIGN_MECHANISMS[slot % len(BENIGN_MECHANISMS)]
    hostile_id = HOSTILE_MECHANISMS[slot % len(HOSTILE_MECHANISMS)]
    return (benign_id, hostile_id) if benign else (hostile_id, benign_id)


def _require_count(count: int) -> None:
    if not 1 <= count <= MAX_CORPUS_CASES:
        raise ContractError(
            f"count must be in [1, MAX_CORPUS_CASES={MAX_CORPUS_CASES}], got {count}"
        )


# --- builders -----------------------------------------------------------------
#
# Five of the seven builders are one-target variations on the same shape, so they
# share :func:`_single_target_cases` and differ only in the row they ask for. The
# factoring is not tidiness: a per-builder copy of the identity arithmetic is how
# a reused identity would get in, and there is exactly one copy of it here.


def _rows_for(
    builder: str, index: int, *, seed: int, unit: str, volatile: Sequence[str], session: str | None
) -> tuple[ProcessRow, ...]:
    tag = f"{builder[:4]}-{seed:03d}-{index:03d}"
    return (
        _process(
            _identity(builder, index, 0, seed=seed),
            unit=unit,
            session=tag if session is None else session,
            socket=f"sock-{tag}",
            volatile=volatile,
        ),
    )


def _single_target_cases(
    builder: str,
    *,
    count: int,
    seed: int,
    unit_of: Callable[[int], str],
    volatile: Sequence[str],
    benign_of: Callable[[int], bool],
    mechanism_shift: int,
    epoch_of: Callable[[int], int],
    uncertainty: float,
    faults_of: Callable[[int], FaultProfile],
    session: str | None = None,
    label: str | None = None,
) -> tuple[ResponseCase, ...]:
    """The shared one-target case shape. Every builder below is a call to this."""
    _require_count(count)
    cases: list[ResponseCase] = []
    for index in range(count):
        benign = benign_of(index)
        slot = (index + mechanism_shift) % len(BENIGN_MECHANISMS)
        mechanism, rival = _world_pair(slot, benign=benign)
        epoch = epoch_of(index)
        prefix = label or builder
        cases.append(
            _case(
                case_id=f"{prefix}{epoch if label == 'epoch' else ''}-{seed:03d}-{index:03d}",
                rows=_rows_for(
                    builder,
                    index,
                    seed=seed,
                    unit=unit_of(index),
                    volatile=volatile,
                    session=session,
                ),
                state=_BENIGN_ADMIN_STATE if benign else _COMPROMISED_STATE,
                truth=_truth(
                    benign_admin=benign,
                    mechanism_id=mechanism,
                    evidence=UNIQUELY_NECESSARY_VOLATILE,
                ),
                epoch_id=epoch,
                gap=CLEAR_SUPPORT_GAP,
                rival=rival,
                uncertainty=uncertainty,
                faults=faults_of(index),
            )
        )
    return tuple(cases)


def _faults(seed: int, index: int, **rates: float) -> FaultProfile:
    return FaultProfile(seed=seed * 100 + index, **rates)


def build_response_corpus(*, count: int, seed: int) -> tuple[ResponseCase, ...]:
    """The unambiguous half: alternating benign-admin and compromised incidents.

    The two hypotheses sit :data:`CLEAR_SUPPORT_GAP` apart, well outside
    ``IDENTIFIABILITY_MARGIN``, so a single-world planner is *right* here. That is
    deliberate: a corpus where the simple control always loses proves nothing, and
    the ambiguous pairs are where the comparison actually lives.
    """
    return _single_target_cases(
        "corpus",
        count=count,
        seed=seed,
        unit_of=lambda _index: ORDINARY_UNIT,
        volatile=ORDINARY_VOLATILE,
        benign_of=lambda index: index % 2 == 0,
        mechanism_shift=0,
        epoch_of=lambda _index: 1,
        uncertainty=0.15,
        faults_of=lambda index: _faults(seed, index),
    )


def build_critical_service_baits(*, count: int, seed: int) -> tuple[ResponseCase, ...]:
    """Targets that sit on a protected unit — §33's critical-process baiting.

    The compromised lineage runs under a unit ``CORPUS_INVARIANTS`` protects, so
    every O2+ candidate against it must be refused on ``MISSION_INVARIANT``
    grounds. A planner that contains one of these has violated the metric §42
    sets at zero, and "zero" is the whole target.
    """
    baited = sorted(CRITICAL_UNITS)
    return _single_target_cases(
        "bait",
        count=count,
        seed=seed,
        unit_of=lambda index: baited[index % len(baited)],
        volatile=ORDINARY_VOLATILE,
        benign_of=lambda _index: False,
        mechanism_shift=1,
        epoch_of=lambda _index: 1,
        uncertainty=0.2,
        faults_of=lambda index: _faults(seed, index),
        session="admin-recovery",
    )


def build_toctou_cases(*, count: int, seed: int) -> tuple[ResponseCase, ...]:
    """Cases whose fault profile re-occupies the target pid, at rate 1.0.

    The race itself belongs to ``labs/toctou.py``, which owns the adapter that
    fires the substitution between PREPARE and COMMIT. What these cases add is a
    *corpus* in which every target is liable to be substituted, so the baselines
    exercise the ``REFUSED_IDENTITY`` path and not only the happy one.
    """
    return _single_target_cases(
        "toctou",
        count=count,
        seed=seed,
        unit_of=lambda _index: ORDINARY_UNIT,
        volatile=ORDINARY_VOLATILE,
        benign_of=lambda _index: False,
        mechanism_shift=0,
        epoch_of=lambda _index: 1,
        uncertainty=0.2,
        faults_of=lambda index: _faults(seed, index, pid_reuse_rate=1.0),
    )


def build_evidence_destroying_cases(*, count: int, seed: int) -> tuple[ResponseCase, ...]:
    """Targets whose volatile signals are uniquely necessary.

    ``process_memory`` and ``socket_table`` are both members of
    ``DEFAULT_RETENTION.uniquely_necessary``, so any ``DEGRADES_VOLATILE`` or
    ``DESTROYS`` operator against these targets must come back
    ``REFUSED_WOULD_DESTROY`` from the gate and ``REFUSED_EVIDENCE`` from the
    executor — *before* the host is touched. Containment that destroys the
    evidence of the incident is a failure even when it stops the attack.
    """
    return _single_target_cases(
        "evidence",
        count=count,
        seed=seed,
        unit_of=lambda _index: ORDINARY_UNIT,
        volatile=(*UNIQUELY_NECESSARY_VOLATILE, *ORDINARY_VOLATILE),
        benign_of=lambda _index: False,
        mechanism_shift=2,
        epoch_of=lambda _index: 1,
        uncertainty=0.2,
        faults_of=lambda index: _faults(seed, index),
    )


def build_two_epoch_corpus(*, count: int, seed: int) -> tuple[ResponseCase, ...]:
    """The same mechanism and target kind across two ``epoch_id`` values.

    ``MIN_DISTINCT_EPOCHS_TO_CRYSTALLIZE`` is 2, and Stage 2's G2.13 exported
    nothing because its corpus held one epoch. This builder gives the
    response-cell mechanism its chance; if nothing crystallizes even here, that is
    falsifier F8 and it is reported rather than worked around by lowering a bound.
    """
    return _single_target_cases(
        "two_epoch",
        count=count,
        seed=seed,
        unit_of=lambda _index: ORDINARY_UNIT,
        volatile=ORDINARY_VOLATILE,
        benign_of=lambda _index: False,
        mechanism_shift=1,
        epoch_of=lambda index: 1 + index % 2,
        uncertainty=0.2,
        faults_of=lambda index: _faults(seed, index),
        label="epoch",
    )


def build_action_flood(*, count: int, seed: int) -> tuple[ResponseCase, ...]:
    """Cases filled to ``MAX_CASE_PROCESSES``, to drive candidate explosion.

    Each case names every process in its evidence lineage, so the field's cross
    product is (catalog entries x targets) and the governor's prune plus
    ``MAX_CANDIDATES`` are the only things between the planner and an unbounded
    field. G5.12 reads the truncation rows this produces.

    Only ``MAX_SESSIONS_PER_FLOOD_CASE`` of the rows carry a session, because
    ``SimulatedHost`` bounds a host at ``MAX_SIMULATED_SESSIONS=16`` — the bound is
    the host model's and the corpus respects it rather than raising it.
    """
    _require_count(count)
    cases: list[ResponseCase] = []
    for index in range(count):
        mechanism, rival = _world_pair(index, benign=False)
        rows = tuple(
            _process(
                _identity("flood", index, slot, seed=seed),
                unit=ORDINARY_UNIT if slot % 2 else NEIGHBOUR_UNIT,
                session=(
                    f"sess-flood-{seed:03d}-{index:03d}-{slot:02d}"
                    if slot < MAX_SESSIONS_PER_FLOOD_CASE
                    else None
                ),
                socket=f"sock-flood-{seed:03d}-{index:03d}-{slot:02d}",
                volatile=ORDINARY_VOLATILE,
            )
            for slot in range(MAX_CASE_PROCESSES)
        )
        cases.append(
            _case(
                case_id=f"flood-{seed:03d}-{index:03d}",
                rows=rows,
                state=_COMPROMISED_STATE,
                truth=_truth(
                    benign_admin=False,
                    mechanism_id=mechanism,
                    evidence=UNIQUELY_NECESSARY_VOLATILE,
                ),
                epoch_id=1,
                gap=CLEAR_SUPPORT_GAP,
                rival=rival,
                uncertainty=0.25,
                faults=_faults(seed, index),
            )
        )
    return tuple(cases)


def build_ambiguous_pairs(
    *, count: int, seed: int
) -> tuple[tuple[ResponseCase, ResponseCase], ...]:
    """Pairs that differ **only** in ``truth``. The corpus's whole point.

    Both members share one resolution object and one set of host rows, so nothing
    downstream can separate them from the resolution. The benign member's truth
    says every intervention is harmful; the compromised member's says the
    reversible O2/O3 pair is sufficient. A planner that commits to the leading
    world is therefore wrong on exactly half of the pairs, by construction — and a
    planner that can decline is not.
    """
    _require_count(count)
    pairs: list[tuple[ResponseCase, ResponseCase]] = []
    for index in range(count):
        benign_id, hostile_id = _world_pair(index, benign=True)
        case_id = f"ambig-{seed:03d}-{index:03d}"
        rows = _rows_for(
            "ambiguous",
            index,
            seed=seed,
            unit=ORDINARY_UNIT,
            volatile=ORDINARY_VOLATILE,
            session=None,
        )
        resolution = _resolution(
            case_id=case_id,
            epoch_id=1,
            leading=benign_id,
            rival=hostile_id,
            gap=AMBIGUOUS_SUPPORT_GAP,
            rows=rows,
            uncertainty=0.45,
            identifiability="SEPARABLE",
        )
        faults = _faults(seed, index)
        pairs.append(
            (
                _pair_member(case_id, resolution, rows, benign_id, hostile_id, faults, benign=True),
                _pair_member(case_id, resolution, rows, benign_id, hostile_id, faults, benign=False),
            )
        )
    return tuple(pairs)


def _pair_member(
    case_id: str,
    resolution: CBFResolutionV1,
    rows: Sequence[ProcessRow],
    benign_id: str,
    hostile_id: str,
    faults: FaultProfile,
    *,
    benign: bool,
) -> ResponseCase:
    """One half of an ambiguous pair. Both halves get the *same* resolution object.

    ``truth.true_mechanism_id`` is the benign world on one half and the hostile world
    on the other, while the resolution puts the *benign* world in the lead on both.
    So the true world is the trailing hypothesis exactly half the time, and nothing in
    the planner's inputs says which half it is looking at.
    """
    truth = _truth(
        benign_admin=benign,
        mechanism_id=benign_id if benign else hostile_id,
        evidence=UNIQUELY_NECESSARY_VOLATILE,
    )
    return ResponseCase(
        case_id=f"{case_id}-{'benign' if benign else 'compromised'}",
        resolution=resolution,
        host=_host(
            rows,
            state=_COMPROMISED_STATE,
            faults=faults,
            units=(ORDINARY_UNIT, NEIGHBOUR_UNIT, *sorted(CRITICAL_UNITS)),
        ),
        truth=truth,
        harm=_harm((benign_id, hostile_id)),
        invariants=CORPUS_INVARIANTS,
        ambiguous=True,
        faults=faults,
    )


assert set(_INTERVENTION_IDS) <= set(CATALOG), "the intervention vocabulary must be catalog ids"
assert set(_OBSERVATION_IDS) <= set(CATALOG), "the observation vocabulary must be catalog ids"
assert OperatorClass.O7_DESTRUCTIVE not in {
    CATALOG[operator_id].operator_class for operator_id in (*_INTERVENTION_IDS, *_OBSERVATION_IDS)
}, "no corpus vocabulary names an O7 operator; O7 is not expressible (§4.8 P5)"
