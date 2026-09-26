"""D5.17 — Response Knowledge Cells and melting: automation that stays questionable.

Architecture §29: repeated *incident invariant + action + verified effect + stable
rollback + stable constraints* may crystallise into a response cell, and "a
response cell is stricter than a detection cell" — it carries the operator, the
boundary, the authority, the mission invariants, the rollback and the
postcondition verifier. §30 then says previously safe responses **never become
permanent unquestionable automation**: six triggers melt them.

This module reuses Stage 3's :class:`~pocketsec.stage3.cells.schema.HardConstraint`,
:class:`~pocketsec.stage3.cells.schema.CellPhase` and
:class:`~pocketsec.stage3.cells.schema.AssuranceLevel` rather than forking them.
A second phase lattice would be a second place to get demotion wrong.

What this module refuses to do:

- **It refuses to crystallise on one epoch's evidence.** Stage 2's G2.13 hit this
  exact wall — "distinct_epochs 1 < 2, so NOTHING was exported" — and the honest
  expectation is that Stage 5's corpus hits it too (falsifier F8). The bound is
  **not** lowered to make a cell appear; a refusal is recorded instead, with its
  reason, so the count of zero is explained rather than mysterious.
- **It refuses a cell with no verifier.** ``postconditions`` may not be empty: a
  cell that cannot check its own effect is a wish, and §29 lists the
  postcondition verifier as part of the cell.
- **It refuses authority it may not hold.** An active cell above
  ``MAX_AUTONOMOUS_AUTHORITY`` raises at construction, so a permissive cell
  cannot be built and then handed to a planner.
- **It refuses to key two ways.** :func:`incident_invariant_key` is the single
  key function for both :meth:`ResponseCellField.crystallize` and
  :meth:`ResponseCellField.lookup` (Rule A, §4.9), and a test asserts the stored
  string equals the string a lookup builds for the same incident.

**One declared deviation, and the reason.** §29 describes the incident invariant
as "the stable ``mechanism_id`` + ``StateDelta.bitmask`` signature", but §27's
``EffectStats`` — the evidence crystallisation reads — does not carry a bitmask,
and :func:`~pocketsec.stage5.memory.effectiveness.context_key` does not either.
Rather than invent a mask at crystallisation time (which would produce a key
space the planner's lookup could never match: S2-FC-01), ``crystallize`` takes the
mask explicitly and **refuses** when it is absent. A missing mask yields no cell
and a recorded refusal, never a cell under a guessed key.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    digest_of_bytes,
    register_schema,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage1.epoch.model import EpochDecision
from pocketsec.stage3.cells.schema import (
    AssuranceLevel,
    CellPhase,
    ConstraintKind,
    HardConstraint,
)
from pocketsec.stage5.constitution.invariants import (
    AUTHORITY_ORDER,
    MAX_AUTONOMOUS_AUTHORITY,
    AuthorityClass,
)
from pocketsec.stage5.constitution.schema import MissionInvariantSet
from pocketsec.stage5.executor.verify import PostconditionKind
from pocketsec.stage5.memory.effectiveness import (
    ContextKey,
    EffectivenessMemory,
    split_context_key,
)
from pocketsec.stage5.operators.algebra import OperatorClass, OperatorSpec, TargetKind
from pocketsec.stage5.operators.catalog import spec

__all__ = [
    "ACTIVE_PHASES",
    "FULL_MELT_TRIGGERS",
    "MAX_REFUSAL_RECORDS",
    "MAX_RESPONSE_CELLS",
    "MIN_DISTINCT_EPOCHS_TO_CRYSTALLIZE",
    "MIN_VERIFIED_EFFECTS_TO_CRYSTALLIZE",
    "RESPONSE_CELL_V1_ID",
    "RESPONSE_CELL_V1_VERSION",
    "CrystallizationRefusal",
    "MeltScope",
    "MeltTrigger",
    "RefusalRecord",
    "ResponseCellField",
    "ResponseCellV1",
    "ResponseMeltReport",
    "incident_invariant_key",
]

RESPONSE_CELL_V1_ID = "pocketsec.response_cell.v1"
RESPONSE_CELL_V1_VERSION = register_schema(RESPONSE_CELL_V1_ID, "1.0.0")

#: Bounded endpoint state. A melted cell is *kept* (it is the record of what was
#: believed and why it stopped being true), so the bound is on the whole field
#: and crystallisation refuses when it is reached rather than evicting history.
MAX_RESPONSE_CELLS: int = 64
#: Verified security effects required before an action may become automation.
MIN_VERIFIED_EFFECTS_TO_CRYSTALLIZE: int = 5
#: Distinct epochs the evidence must span. "Safe last epoch" is not evidence
#: after a corroborated system change, so one epoch can never be enough.
MIN_DISTINCT_EPOCHS_TO_CRYSTALLIZE: int = 2
#: The refusal log is bounded like everything else on the endpoint.
MAX_REFUSAL_RECORDS: int = 64

#: Phases in which a cell may actually be used. ``FLUID`` is a proposal and
#: ``MELTED`` is a record; everything between is live automation, so the
#: authority ceiling applies to all three — including ``STRESSED``, which is
#: still consulted while under suspicion.
ACTIVE_PHASES: frozenset[CellPhase] = frozenset(
    {CellPhase.STRUCTURED, CellPhase.CRYSTALLIZED, CellPhase.STRESSED}
)

_KEY_SEPARATOR = "|"


class MeltTrigger(StrEnum):
    """§30's six triggers, one member each."""

    DEPENDENCY_DRIFT = "DEPENDENCY_DRIFT"
    SERVICE_EPOCH_CHANGE = "SERVICE_EPOCH_CHANGE"
    RESIDUAL_INCREASE = "RESIDUAL_INCREASE"
    COLLATERAL_INCREASE = "COLLATERAL_INCREASE"
    ROLLBACK_DEGRADATION = "ROLLBACK_DEGRADATION"
    AUTHORITY_POLICY_CHANGE = "AUTHORITY_POLICY_CHANGE"


class MeltScope(StrEnum):
    PARTIAL = "PARTIAL"
    FULL = "FULL"


#: Triggers that invalidate the cell's *premises* rather than degrade its
#: statistics. A changed epoch, a rollback that stopped working or a changed
#: authority policy means the evidence was gathered about a different system, so
#: partial demotion would leave automation running on withdrawn premises.
FULL_MELT_TRIGGERS: frozenset[MeltTrigger] = frozenset(
    {
        MeltTrigger.SERVICE_EPOCH_CHANGE,
        MeltTrigger.ROLLBACK_DEGRADATION,
        MeltTrigger.AUTHORITY_POLICY_CHANGE,
    }
)


class CrystallizationRefusal(StrEnum):
    """Why no cell was produced. Every refusal is recorded, never silent."""

    NO_RECORD = "NO_RECORD"
    MISSING_STATE_DELTA = "MISSING_STATE_DELTA"
    EPOCH_MISMATCH = "EPOCH_MISMATCH"
    TOO_FEW_VERIFIED_EFFECTS = "TOO_FEW_VERIFIED_EFFECTS"
    TOO_FEW_EPOCHS = "TOO_FEW_EPOCHS"
    ROLLBACK_NOT_PERFECT = "ROLLBACK_NOT_PERFECT"
    AUTHORITY_TOO_HIGH = "AUTHORITY_TOO_HIGH"
    NO_POSTCONDITIONS = "NO_POSTCONDITIONS"
    FIELD_FULL = "FIELD_FULL"


@dataclass(frozen=True, slots=True)
class RefusalRecord:
    reason: CrystallizationRefusal
    identifier: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "reason": self.reason.value,
            "identifier": self.identifier,
            "detail": self.detail,
        }


def incident_invariant_key(
    *, mechanism_id: str, state_delta_mask: int, target_kind: TargetKind
) -> str:
    """THE incident-invariant key: produced by crystallisation, read by lookup.

    ``mechanism_id`` comes from Stage 4's hypothesis and the mask from Stage 1's
    ``StateDelta.bitmask()``; the target kind is included because the same
    mechanism against a service is not the same incident as against a process,
    and a cell that ignored the difference would authorise an operator that was
    never verified for that target.
    """
    require_identifier(mechanism_id, "incident_invariant_key.mechanism_id")
    require_non_negative_int(state_delta_mask, "incident_invariant_key.state_delta_mask")
    if not isinstance(target_kind, TargetKind):
        raise ContractError(
            f"incident_invariant_key.target_kind must be a TargetKind, got {target_kind!r}"
        )
    return _KEY_SEPARATOR.join(
        (mechanism_id, f"m{state_delta_mask}", target_kind.value)
    )


@dataclass(frozen=True, slots=True)
class ResponseCellV1:
    """§29's response cell. Stricter than a detection cell, and it says why."""

    cell_id: str
    incident_invariant: str
    operator_id: str
    target_kind: TargetKind
    authority: AuthorityClass
    mission_invariant_ids: tuple[str, ...]
    rollback_operator_id: str | None
    postconditions: tuple[PostconditionKind, ...]
    verified_effect_n: int
    simulated_rollback_success: float | None
    constraints: tuple[HardConstraint, ...]
    epochs: frozenset[int]
    phase: CellPhase
    assurance: AssuranceLevel
    version: int
    parent_cell_id: str | None
    schema_version: str = RESPONSE_CELL_V1_VERSION

    def __post_init__(self) -> None:
        require_identifier(self.cell_id, "ResponseCellV1.cell_id")
        require_non_negative_int(self.verified_effect_n, "ResponseCellV1.verified_effect_n")
        if self.version < 1:
            raise ContractError("ResponseCellV1.version starts at 1")
        if not self.postconditions:
            raise ContractError(
                f"ResponseCellV1 {self.cell_id!r} has no postconditions; a cell "
                "with no verifier is a wish, not automation (§29)"
            )
        if not self.epochs:
            raise ContractError(
                f"ResponseCellV1 {self.cell_id!r} names no epoch; a cell with no "
                "epoch cannot be melted when the system changes"
            )
        if self.phase in ACTIVE_PHASES and (
            AUTHORITY_ORDER[self.authority] > AUTHORITY_ORDER[MAX_AUTONOMOUS_AUTHORITY]
        ):
            raise ContractError(
                f"ResponseCellV1 {self.cell_id!r} is {self.phase.value} at authority "
                f"{self.authority.value}, above MAX_AUTONOMOUS_AUTHORITY "
                f"{MAX_AUTONOMOUS_AUTHORITY.value}"
            )
        operator_class = spec(self.operator_id).operator_class
        if (
            self.rollback_operator_id is None
            and operator_class >= OperatorClass.O2_REVERSIBLE_RESTRICT
        ):
            raise ContractError(
                f"ResponseCellV1 {self.cell_id!r} automates {operator_class.name} "
                "with no rollback operator"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "cell_id": self.cell_id,
            "incident_invariant": self.incident_invariant,
            "operator_id": self.operator_id,
            "target_kind": self.target_kind.value,
            "authority": self.authority.value,
            "mission_invariant_ids": list(self.mission_invariant_ids),
            "rollback_operator_id": self.rollback_operator_id,
            "postconditions": [kind.value for kind in self.postconditions],
            "verified_effect_n": self.verified_effect_n,
            "simulated_rollback_success": self.simulated_rollback_success,
            "constraints": [constraint.to_dict() for constraint in self.constraints],
            "epochs": sorted(self.epochs),
            "phase": self.phase.value,
            "assurance": self.assurance.value,
            "version": self.version,
            "parent_cell_id": self.parent_cell_id,
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True, slots=True)
class ResponseMeltReport:
    cell_id: str
    triggers: tuple[MeltTrigger, ...]
    scope: MeltScope
    demoted_to: CellPhase
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "cell_id": self.cell_id,
            "triggers": [trigger.value for trigger in self.triggers],
            "scope": self.scope.value,
            "demoted_to": self.demoted_to.value,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class _Evidence:
    """The cross-epoch evidence crystallisation is allowed to consider."""

    epochs: frozenset[int]
    verified: int
    rollback_attempts: int
    rollback_successes: int


def _constraints_for(operator_id: str) -> tuple[HardConstraint, ...]:
    """The hard constraints every response cell carries.

    Both are Stage 3 constraint kinds, deliberately: a response cell is a
    compiled belief like any other, and the two things it may never do are
    suppress the evidence the incident is made of and talk its own consequence
    down.
    """
    return (
        HardConstraint(
            constraint_id=f"rc.evidence.{operator_id}",
            kind=ConstraintKind.NEVER_SUPPRESS_MANDATORY_EVIDENCE,
            detail=(
                "an automated response may not run where it would suppress a "
                "mandatory evidence signal; the preservation gate runs first"
            ),
        ),
        HardConstraint(
            constraint_id=f"rc.consequence.{operator_id}",
            kind=ConstraintKind.NEVER_DOWNGRADE_CONSEQUENCE,
            detail=(
                "reuse of this cell may not lower the consequence class of the "
                "incident it matched; cheap reuse is not a reason to re-grade harm"
            ),
        ),
    )


class ResponseCellField:
    """The bounded set of response cells, plus every reason one was refused."""

    def __init__(self, *, max_cells: int = MAX_RESPONSE_CELLS) -> None:
        if max_cells < 1:
            raise ContractError("ResponseCellField.max_cells must be >= 1")
        self._max_cells = max_cells
        self._cells: dict[str, ResponseCellV1] = {}
        self._refusals: list[RefusalRecord] = []

    def cells(self) -> tuple[ResponseCellV1, ...]:
        return tuple(self._cells.values())

    def refusals(self) -> tuple[RefusalRecord, ...]:
        return tuple(self._refusals)

    def crystallize(
        self,
        *,
        memory: EffectivenessMemory,
        context: str,
        operator_id: str,
        invariants: MissionInvariantSet,
        epoch_id: int,
        state_delta_mask: int | None = None,
    ) -> ResponseCellV1 | None:
        """Turn measured evidence into automation, or refuse and say why.

        Returns ``None`` far more often than it returns a cell, and that is the
        designed behaviour rather than a bug to be tuned away.
        """
        parsed = split_context_key(context)
        record = memory.record(context=context, operator_id=operator_id)
        entry = spec(operator_id)
        if record is None:
            return self._refuse(CrystallizationRefusal.NO_RECORD, context, operator_id)
        if parsed.epoch_id != epoch_id:
            return self._refuse(
                CrystallizationRefusal.EPOCH_MISMATCH,
                context,
                f"{operator_id}: context epoch {parsed.epoch_id} != {epoch_id}",
            )
        if state_delta_mask is None:
            return self._refuse(
                CrystallizationRefusal.MISSING_STATE_DELTA,
                context,
                f"{operator_id}: no StateDelta.bitmask supplied, so the incident "
                "invariant would be keyed on a guess",
            )
        evidence = _gather(memory, parsed=parsed, operator_id=operator_id)
        refusal = _check(evidence, entry=entry, full=len(self._cells) >= self._max_cells)
        if refusal is not None:
            return self._refuse(refusal, context, f"{operator_id}: {evidence}")
        return self._insert(
            _build_cell(
                entry=entry,
                parsed=parsed,
                evidence=evidence,
                invariants=invariants,
                state_delta_mask=state_delta_mask,
            )
        )

    def lookup(
        self, *, incident_invariant: str, epoch_id: int
    ) -> ResponseCellV1 | None:
        """Find a usable cell for this incident in this epoch.

        A cell is usable only in an epoch its evidence covers, and never once
        melted. Both conditions are checked here rather than by the caller: a
        planner that forgot one would be automating on withdrawn premises.
        """
        for cell in self._cells.values():
            if cell.incident_invariant != incident_invariant:
                continue
            if epoch_id not in cell.epochs:
                continue
            if cell.phase not in ACTIVE_PHASES:
                continue
            return cell
        return None

    def melt(
        self, cell_id: str, *, triggers: Sequence[MeltTrigger]
    ) -> ResponseMeltReport:
        cell = self._cells.get(cell_id)
        if cell is None:
            raise ContractError(f"no response cell {cell_id!r} to melt")
        if not triggers:
            raise ContractError(
                "melting needs at least one trigger; an unexplained demotion "
                "cannot be reviewed or reversed"
            )
        fired = tuple(dict.fromkeys(triggers))
        scope = (
            MeltScope.FULL
            if any(trigger in FULL_MELT_TRIGGERS for trigger in fired)
            else MeltScope.PARTIAL
        )
        demoted_to = CellPhase.MELTED if scope is MeltScope.FULL else CellPhase.STRESSED
        # The melted cell is kept, at its new phase: rollback and reconstruction
        # paths are first-class, and a deleted cell is a lost counterexample.
        self._cells[cell_id] = replace(
            cell, phase=demoted_to, version=cell.version + 1, parent_cell_id=cell.cell_id
        )
        return ResponseMeltReport(
            cell_id=cell_id,
            triggers=fired,
            scope=scope,
            demoted_to=demoted_to,
            detail=(
                f"{cell.operator_id} demoted from {cell.phase.value} on "
                + ",".join(trigger.value for trigger in fired)
            ),
        )

    def observe_epoch(self, decision: EpochDecision) -> tuple[ResponseMeltReport, ...]:
        """A corroborated epoch change melts every cell that predates it.

        §30's first two triggers, read literally: the evidence behind every cell
        was gathered about a system that has now changed. Nothing here asks
        whether the change "looks relevant" — that judgement is how automation
        becomes unquestionable.
        """
        if not isinstance(decision, EpochDecision):
            raise ContractError(f"observe_epoch needs an EpochDecision, got {decision!r}")
        if not decision.transitioned:
            return ()
        triggers = [MeltTrigger.SERVICE_EPOCH_CHANGE]
        if "service_digest" in decision.changed_components:
            triggers.append(MeltTrigger.DEPENDENCY_DRIFT)
        if decision.changed_components & {"policy_digest", "user_role_digest"}:
            triggers.append(MeltTrigger.AUTHORITY_POLICY_CHANGE)
        reports = [
            self.melt(cell_id, triggers=triggers)
            for cell_id, cell in sorted(self._cells.items())
            if cell.phase in ACTIVE_PHASES
        ]
        return tuple(reports)

    def state_bytes(self) -> int:
        payload = [cell.to_dict() for cell in self._cells.values()]
        return len(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())

    def _insert(self, cell: ResponseCellV1) -> ResponseCellV1:
        self._cells[cell.cell_id] = cell
        return cell

    def _refuse(
        self, reason: CrystallizationRefusal, identifier: str, detail: str
    ) -> None:
        if len(self._refusals) >= MAX_REFUSAL_RECORDS:
            self._refusals.pop(0)
        self._refusals.append(
            RefusalRecord(reason=reason, identifier=identifier, detail=detail)
        )
        return None


def _gather(
    memory: EffectivenessMemory, *, parsed: ContextKey, operator_id: str
) -> _Evidence:
    """Collect this operator's evidence for this mechanism across **all** epochs.

    Records are epoch-keyed by construction, so the two-epoch requirement can
    only be answered by looking across records — never by reading one record's
    own epoch twice, which is how "distinct_epochs 1" gets reported as 2.
    """
    epochs: set[int] = set()
    verified = 0
    attempts = 0
    successes = 0
    for row in memory.rows():
        if row["operator_id"] != operator_id:
            continue
        other = split_context_key(str(row["context"]))
        if (
            other.mechanism_id != parsed.mechanism_id
            or other.target_kind is not parsed.target_kind
        ):
            continue
        epochs.add(other.epoch_id)
        verified += int(row["verified_security_effect"])
        attempts += int(row["rollback_attempts"])
        successes += int(row["rollback_successes"])
    return _Evidence(
        epochs=frozenset(epochs),
        verified=verified,
        rollback_attempts=attempts,
        rollback_successes=successes,
    )


def _check(
    evidence: _Evidence, *, entry: OperatorSpec, full: bool
) -> CrystallizationRefusal | None:
    """Every bar, in order. Not one of them is adjustable at a call site."""
    if full:
        return CrystallizationRefusal.FIELD_FULL
    if not entry.postconditions:
        return CrystallizationRefusal.NO_POSTCONDITIONS
    if evidence.verified < MIN_VERIFIED_EFFECTS_TO_CRYSTALLIZE:
        return CrystallizationRefusal.TOO_FEW_VERIFIED_EFFECTS
    if len(evidence.epochs) < MIN_DISTINCT_EPOCHS_TO_CRYSTALLIZE:
        return CrystallizationRefusal.TOO_FEW_EPOCHS
    if evidence.rollback_successes != evidence.rollback_attempts:
        return CrystallizationRefusal.ROLLBACK_NOT_PERFECT
    if AUTHORITY_ORDER[entry.authority] > AUTHORITY_ORDER[MAX_AUTONOMOUS_AUTHORITY]:
        return CrystallizationRefusal.AUTHORITY_TOO_HIGH
    return None


def _build_cell(
    *,
    entry: OperatorSpec,
    parsed: ContextKey,
    evidence: _Evidence,
    invariants: MissionInvariantSet,
    state_delta_mask: int,
) -> ResponseCellV1:
    invariant_key = incident_invariant_key(
        mechanism_id=parsed.mechanism_id,
        state_delta_mask=state_delta_mask,
        target_kind=parsed.target_kind,
    )
    digest = digest_of_bytes(f"{invariant_key}|{entry.operator_id}".encode())
    rollback_rate = (
        evidence.rollback_successes / evidence.rollback_attempts
        if evidence.rollback_attempts
        else None
    )
    return ResponseCellV1(
        cell_id=f"rc.{digest.removeprefix('sha256:')[:16]}",
        incident_invariant=invariant_key,
        operator_id=entry.operator_id,
        target_kind=parsed.target_kind,
        authority=entry.authority,
        mission_invariant_ids=tuple(
            invariant.invariant_id for invariant in invariants.invariants
        ),
        rollback_operator_id=entry.rollback_operator_id,
        postconditions=tuple(entry.postconditions),
        verified_effect_n=evidence.verified,
        simulated_rollback_success=rollback_rate,
        constraints=_constraints_for(entry.operator_id),
        epochs=evidence.epochs,
        phase=CellPhase.CRYSTALLIZED,
        # A2, not A5: the evidence is measured inside the simulated host model.
        # A5 means "formally verified property set, if actually proven" and needs
        # a named prover; nothing in this module can award it (stage3 §25).
        assurance=AssuranceLevel.A2,
        version=1,
        parent_cell_id=None,
    )
