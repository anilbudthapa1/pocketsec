"""D3.8 Oracle B — Stage 1's explicit security invariants, applied to a cell's output.

This module exists because **Oracle A is the thing being compiled**. The architecture
(§20) assumes the teacher is a DTL whose mistakes the security specification can
catch; ADR-0010 rejected the DTL and the first crystallization target is Stage 1's
own Φ-oracle. A dual oracle whose second half is also the teacher catches nothing, so
everything that actually *catches* lives here, in rules that were written and measured
before any cell existed.

What this module refuses to do: it refuses to accept a cell result on the strength of
teacher agreement. Every check below is evaluated against Stage 1 code that already
ships — :func:`pocketsec.stage1.state.potential.phi`,
:meth:`SecurityStateV1.join`, and :data:`MANDATORY_SIGNALS` — so a violation is a
disagreement with the security calculus, not with an opinion.

Abstention is deliberately **not** a violation. ``CellResult.abstained`` routes the
frame back to the learned path, and ``UNKNOWN`` is a valid PocketSec output
(``planning/MEMORY.md``, non-negotiable invariants). A cell that declines to answer
has suppressed nothing; a cell that answers *benignly* about a HIGH-consequence frame
has, and that is what :data:`ConstraintKind.NEVER_NORMALISE_HIGH_CONSEQUENCE` is for.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef
from pocketsec.stage1.observation.policy import MANDATORY_SIGNALS
from pocketsec.stage1.state.potential import phi
from pocketsec.stage1.state.security_state import (
    DIMENSIONS,
    SecurityStateV1,
    StateDelta,
)
from pocketsec.stage3.cells.schema import ConstraintKind
from pocketsec.stage3.oracles.teacher import frame_digest
from pocketsec.stage3.theory import SecurityConsequence, consequence_of

if TYPE_CHECKING:  # pragma: no cover - typing only; keeps the runtime seam thin
    from pocketsec.stage3.bytecode.vm import CellFrame, CellResult
    from pocketsec.stage3.cells.operator import OperatorProgram

__all__ = [
    "BENIGN_RISK_CEILING",
    "CellLike",
    "Violation",
    "apply_delta",
    "check_hard_security_constraints",
    "is_benign_result",
    "mandatory_evidence",
]

#: A result at or below this risk is *benign*: it says "nothing here". The number is a
#: threshold, not a measurement — it is the point below which a result stops asking any
#: downstream stage to look, which is exactly what a HIGH-consequence frame may not
#: receive. It is a named constant so a future change to it is a visible change.
BENIGN_RISK_CEILING = 0.25

#: Evidence stores and locators are dotted/slashed identifiers
#: (``raw.privilege_change``, ``stage1.evidence``). A mandatory signal is recognised by
#: appearing as a whole token, never as a substring: ``credential_accessory`` is not
#: ``credential_access``.
_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")


@runtime_checkable
class CellLike(Protocol):
    """The only thing the oracles read off a cell: its identity and its program.

    Deliberately structural. ``crystallize`` (D3.2) evaluates a *candidate* long before
    anything is a ``KnowledgeCellV1``, and refusing to judge an unpromoted candidate
    would put the dual oracle after the decision it exists to gate.
    """

    @property
    def cell_id(self) -> str: ...

    @property
    def operator(self) -> OperatorProgram: ...


@dataclass(frozen=True, slots=True)
class Violation:
    """One hard security constraint that a cell's result broke.

    A violation is not a weighted error term. §19 separates the two on purpose: a
    divergence can be traded against cost, and this cannot.
    """

    constraint_id: str
    kind: ConstraintKind
    detail: str
    frame_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.constraint_id, str) or not self.constraint_id.strip():
            raise ContractError("Violation.constraint_id must be a non-empty string")
        if not isinstance(self.kind, ConstraintKind):
            raise ContractError(f"Violation.kind must be a ConstraintKind, got {self.kind!r}")
        if not isinstance(self.detail, str) or not self.detail.strip():
            raise ContractError("Violation.detail must be a non-empty string")
        if not isinstance(self.frame_digest, str) or not self.frame_digest:
            raise ContractError("Violation.frame_digest must be a non-empty string")

    def to_dict(self) -> dict[str, Any]:
        return {
            "constraint_id": self.constraint_id,
            "kind": self.kind.value,
            "detail": self.detail,
            "frame_digest": self.frame_digest,
        }


def _tokens(ref: EvidenceRef) -> frozenset[str]:
    return frozenset(_TOKEN_RE.findall(f"{ref.store} {ref.locator}"))


def mandatory_evidence(refs: Sequence[EvidenceRef]) -> tuple[EvidenceRef, ...]:
    """The subset of ``refs`` that carries a :data:`MANDATORY_SIGNALS` signal.

    Stage 1 names mandatory signals; Stage 0 names evidence by ``store``/``locator``.
    Joining them by whole-token match is the narrowest rule that does not require a new
    field on ``EvidenceRef`` — which is frozen (ADR-0007) and not Stage 3's to change.
    """
    return tuple(ref for ref in refs if _tokens(ref) & MANDATORY_SIGNALS)


def apply_delta(state: SecurityStateV1, delta: StateDelta) -> SecurityStateV1 | None:
    """Apply ``delta`` to ``state`` *literally*, including any claimed downgrade.

    ``SecurityStateV1.raised_to`` clamps: it silently ignores a level below the current
    one, which would make ``NEVER_LOWER_PHI`` unfalsifiable — no delta could ever lower
    Φ because no delta could ever lower a dimension. The oracle therefore builds the
    state the result *asserts*, so a downgrade is visible and can be refused.

    Returns ``None`` when a claimed level is outside its lattice, which is itself a
    monotonicity failure and is reported by the caller.
    """
    levels = state.to_levels()
    for name, (_before, after) in delta.raised.items():
        if name not in DIMENSIONS:
            return None
        lattice = DIMENSIONS[name]
        if after not in {int(member) for member in lattice}:
            return None
        levels[name] = after
    return SecurityStateV1(
        **{name: DIMENSIONS[name](levels[name]) for name in DIMENSIONS}  # type: ignore[arg-type]
    )


def is_benign_result(result: CellResult) -> bool:
    """True when the result tells the rest of the system there is nothing to look at.

    Abstention is excluded: an abstaining cell hands the frame back to the learned path
    rather than declaring it harmless.
    """
    return not result.abstained and float(result.risk) <= BENIGN_RISK_CEILING


def _violation(
    kind: ConstraintKind, cell_id: str, detail: str, frame_digest: str
) -> Violation:
    return Violation(
        constraint_id=f"{cell_id}:{kind.value}",
        kind=kind,
        detail=detail,
        frame_digest=frame_digest,
    )


def _check_mandatory_evidence(
    cell_id: str, frame: CellFrame, result: CellResult, digest: str
) -> Iterable[Violation]:
    if result.abstained:
        # Abstention is UNKNOWN, not suppression — the module docstring's own
        # rule, and ``_check_consequence`` and ``is_benign_result`` both already
        # honour it. ``CellVM._abstained`` hard-codes ``evidence=()``, so without
        # this line every abstention on a frame carrying a MANDATORY_SIGNALS
        # token was reported as NEVER_SUPPRESS_MANDATORY_EVIDENCE. That includes
        # every non-BYTECODE operator form, which ``CellVM.run`` declines to
        # execute: CRYSTAL then recorded "every candidate violated a hard
        # security constraint" when the true cause was an unexecuted form, and
        # wrote that false accusation into the permanent counterexample store.
        return ()
    required = mandatory_evidence(frame.evidence)
    if not required:
        return ()
    carried = {ref.digest for ref in result.evidence}
    missing = [ref for ref in required if ref.digest not in carried]
    if not missing:
        return ()
    return (
        _violation(
            ConstraintKind.NEVER_SUPPRESS_MANDATORY_EVIDENCE,
            cell_id,
            "result drops mandatory-signal evidence "
            + ", ".join(f"{ref.store}/{ref.locator}" for ref in missing),
            digest,
        ),
    )


def _check_state_monotone_and_phi(
    cell_id: str, frame: CellFrame, result: CellResult, digest: str
) -> Iterable[Violation]:
    asserted = apply_delta(frame.state, result.delta)
    if asserted is None:
        return (
            _violation(
                ConstraintKind.STATE_MONOTONE,
                cell_id,
                f"result delta {result.delta.to_dict()} names a level outside its lattice",
                digest,
            ),
        )
    found: list[Violation] = []
    if SecurityStateV1.join(frame.state, asserted) != asserted:
        found.append(
            _violation(
                ConstraintKind.STATE_MONOTONE,
                cell_id,
                "join(before, after) != after: the result lowers a capability the "
                "lineage already holds",
                digest,
            )
        )
    before_phi = phi(frame.state).total
    after_phi = phi(asserted).total
    if after_phi < before_phi:
        found.append(
            _violation(
                ConstraintKind.NEVER_LOWER_PHI,
                cell_id,
                f"Φ falls from {before_phi} to {after_phi} under the result's delta",
                digest,
            )
        )
    return tuple(found)


def _check_consequence(
    cell_id: str, frame: CellFrame, result: CellResult, digest: str
) -> Iterable[Violation]:
    """The clause that catches teacher error.

    A frame whose ``consequence_of`` is HIGH or CRITICAL may not receive a benign
    result **whatever the teacher says**. Oracle A is a frozen snapshot of the very
    scorer being compiled, so if the snapshot is wrong about a critical frame nothing
    else in the pipeline disagrees with it. This is the disagreement.
    """
    frame_consequence = consequence_of(frame.delta, frame.state)
    found: list[Violation] = []
    if frame_consequence >= SecurityConsequence.HIGH and is_benign_result(result):
        found.append(
            _violation(
                ConstraintKind.NEVER_NORMALISE_HIGH_CONSEQUENCE,
                cell_id,
                f"frame consequence is {frame_consequence.name} but the result is benign "
                f"(risk {float(result.risk)} <= {BENIGN_RISK_CEILING})",
                digest,
            )
        )
    if result.abstained:
        # Abstention is UNKNOWN, not a downgrade. It carries no consequence claim.
        return tuple(found)
    result_consequence = consequence_of(result.delta, frame.state)
    if result_consequence < frame_consequence:
        found.append(
            _violation(
                ConstraintKind.NEVER_DOWNGRADE_CONSEQUENCE,
                cell_id,
                f"frame consequence {frame_consequence.name} downgraded to "
                f"{result_consequence.name} by the result's delta",
                digest,
            )
        )
    return tuple(found)


def check_hard_security_constraints(
    cell: CellLike, frame: CellFrame, result: CellResult
) -> tuple[Violation, ...]:
    """Oracle B. Every hard constraint Q_i (§19), evaluated against Stage 1 code.

    The checks are independent and all of them run: a result that both suppresses
    evidence and normalises a critical frame reports two violations, because a caller
    fixing one must not be told the other has gone away.
    """
    cell_id = cell.cell_id
    digest = frame_digest(frame)
    violations: list[Violation] = []
    violations.extend(_check_mandatory_evidence(cell_id, frame, result, digest))
    violations.extend(_check_state_monotone_and_phi(cell_id, frame, result, digest))
    violations.extend(_check_consequence(cell_id, frame, result, digest))
    return tuple(violations)
