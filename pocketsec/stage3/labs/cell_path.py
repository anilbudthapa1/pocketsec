"""S3 — the Φ-oracle's knowledge wrapped in a Knowledge Cell, and the runtime path over it.

This is not a baseline. It is the **mechanism** the five baselines in
``labs/baselines.py`` control for, and it lives in its own module so that nobody
reading the controls can mistake it for one of them.

Two structural results are recorded here rather than in a findings document,
because they are properties of the code and would otherwise drift away from it:

1. **A cell cannot reproduce the Φ-oracle's scores.** The Φ-oracle is
   ``|ΔΦ| / (|ΔΦ| + 8)``; the PCB ISA defines no division opcode, so the closest
   a verified program gets is ``clamp01(ΔΦ)``. Falsifier F1 is stated "at
   identical scores", and that precondition is **not met** on this wave.
2. **WITHDRAWN — "a global rule cannot be crystallised as one cell."** This module
   used to claim that a boundary over all nine ``DIMENSIONS`` expands to
   8 families x 512 delta masks = 4096 index keys and is refused by
   ``BoundaryIndex.insert`` at ``MAX_KEYS_PER_CELL=64``. Measured directly in the
   Stage 3 measurement wave (``results/PS-S3-20260925-H4-cell-path-constant-0002.json``),
   a boundary claims **8** keys at 1, 2, 3, 4 and 9 declared dimensions alike, and
   every one of them is **accepted**. ``CellBoundary.keys`` folds the declared
   dimensions into a single union delta mask, so declaring more of them costs the
   index nothing — the same defect class already retracted for threat case T7 in
   ``labs/boundary_evasion.py``, whose repair was never propagated here. The
   narrowing of :data:`CELL_STATE_DIMENSIONS` is therefore **not** forced by the
   index cap, and no structural result about the cell format follows from it.

Result 1 belongs in ADR-0021. Result 2 is withdrawn there and in
``docs/stage-3-findings.md``.
"""

from __future__ import annotations

from pocketsec.stage0.contracts.common import EvidenceRef, digest_of_bytes
from pocketsec.stage2.compile_candidates.phi_oracle_candidate import PHI_ORACLE_CANDIDATE_ID
from pocketsec.stage3.boundary.index import BoundaryIndex
from pocketsec.stage3.bytecode.isa import (
    DELTA_SLOTS,
    MAX_STATE_BYTES,
    Instruction,
    Op,
    encode,
)
from pocketsec.stage3.bytecode.vm import CellVM
from pocketsec.stage3.boundary.index import CellBoundary
from pocketsec.stage3.cells.invariant import (
    ConsequentSpec,
    Invariant,
    PredicateRole,
    SemanticPredicate,
)
from pocketsec.stage3.cells.operator import OperatorForm, OperatorProgram
from pocketsec.stage3.cells.schema import (
    AssuranceLevel,
    AuditPolicy,
    CellPhase,
    ConstraintKind,
    HardConstraint,
    KnowledgeCellV1,
)
from pocketsec.stage3.labs.crystal_corpus import CrystalCorpus, CrystalSession, session_frames
from pocketsec.stage3.theory import ResolutionState, SecurityConsequence

__all__ = [
    "CELL_STATE_DIMENSIONS",
    "CellPathBaseline",
    "DEFAULT_CELL_SUPPORT",
    "phi_oracle_cell",
]

#: Distinct causal lineages behind the Φ-oracle cell. Support counts lineages,
#: never events: a pattern seen a thousand times in one lineage has one witness.
DEFAULT_CELL_SUPPORT = 4

#: The slice of ``DIMENSIONS`` this cell declares.
#:
#: This used to be documented as forced by ``MAX_KEYS_PER_CELL=64``, on the
#: arithmetic ``families x actor masks x delta masks``. **Measured, and false:**
#: ``CellBoundary.keys`` folds the declared dimensions into one union delta mask,
#: so this boundary claims 8 index keys whether it declares two dimensions or all
#: nine, and the index accepts every width. The cap is not what decides the
#: region here; this pair is a **choice**, and a wider cell is a measurement a
#: later wave can simply run.
CELL_STATE_DIMENSIONS = frozenset({"privilege", "credential"})

#: Carries the ``credential_access`` token, so it is MANDATORY_SIGNALS evidence.
_MANDATORY = EvidenceRef(
    store="raw.credential_access",
    locator="rec-0001",
    digest=digest_of_bytes(b"raw.credential_access/rec-0001"),
)

def phi_oracle_cell(
    *,
    cell_id: str = "cell-phi-oracle",
    epochs: frozenset[int] = frozenset({0, 1, 2}),
    confidence: float = 0.9,
) -> KnowledgeCellV1:
    """A ``KnowledgeCellV1`` carrying the Φ-oracle's knowledge as verified bytecode.

    **It does not reproduce the Φ-oracle's scores, and cannot.** The Φ-oracle is
    ``|ΔΦ| / (|ΔΦ| + 8)``; the PCB ISA (D3.6) defines no division opcode, so the
    closest a verified program gets is ``clamp01(ΔΦ)`` — a different function that
    happens to be monotone in |ΔΦ| only below 1.0. That is a structural finding
    about the ISA, not a defect in this helper, and it means the "identical
    scores" precondition of falsifier F1 is **not met** on this wave. Reporting a
    cost comparison as if the scores matched would be the lie F1 exists to catch.

    The boundary is also **narrower than the Φ-oracle**, and the reason given for
    that here was wrong. It used to say a boundary over all nine ``DIMENSIONS``
    expands to 4096 index keys and is refused at ``MAX_KEYS_PER_CELL=64``, and to
    conclude that a global zero-parameter rule cannot be crystallised as one
    cell. Measured: the boundary claims 8 keys at any declared width and the index
    accepts all of them, so the restriction to :data:`CELL_STATE_DIMENSIONS` is a
    choice this helper makes and not a cap it hits. Frames outside those
    dimensions still abstain, so the narrowness is real; the *explanation* is
    withdrawn, and with it the structural conclusion ADR-0021 drew from it.

    Within that region the boundary is deliberately permissive — every epoch, the
    full Φ range, no predicates. That is what a first crystallisation looks like,
    and it is also threat case 1 in ``labs/boundary_evasion.py``: a permissive
    boundary is a boundary an attacker can sit just inside.
    """
    program = OperatorProgram(
        form=OperatorForm.BYTECODE,
        words=encode(
            (
                Instruction(Op.LOAD_DELTA, DELTA_SLOTS.index("delta_phi")),
                Instruction(Op.UPDATE_PHI, 0),
                Instruction(Op.PRESERVE_EVIDENCE, 0),
                Instruction(Op.RETURN_STATE, 0),
            )
        ),
        table={},
        max_steps=4,
        max_state_bytes=MAX_STATE_BYTES,
    )
    predicate = SemanticPredicate(
        role=PredicateRole.ACTOR,
        required_properties=frozenset(),
        forbidden_properties=frozenset(),
        relation_family=None,
        entity_kind=None,
    )
    invariant = Invariant(
        invariant_id="inv-phi-oracle",
        antecedent=(predicate,),
        consequent=ConsequentSpec(
            required_dimensions=frozenset({"privilege"}),
            min_delta_phi=0.0,
            required_evidence_kinds=frozenset({"credential_access"}),
            consequence=SecurityConsequence.ELEVATED,
        ),
        support=DEFAULT_CELL_SUPPORT,
        contradictions=0,
        identities_collapsed=0,
        epochs=epochs,
        falsifier="a transition whose |ΔΦ| is large and which is not worth observing",
        evidence=(_MANDATORY,),
    )
    boundary = CellBoundary(
        predicates=(),
        state_dimensions=CELL_STATE_DIMENSIONS,
        phi_range=(0.0, 1e9),
        max_uncertainty=1.0,
        epochs=epochs,
        forbidden_combinations=(),
    )
    return KnowledgeCellV1(
        cell_id=cell_id,
        invariant=invariant,
        boundary=boundary,
        operator=program,
        resolution=ResolutionState(
            predictive_stability=1.0,
            calibrated_uncertainty=0.0,
            validated_breadth=len(epochs),
            counterfactual_consistency=1.0,
            evidence_agreement=1.0,
            drift_stability=len(epochs),
            measured_by="pocketsec.stage3.labs.baselines:phi_oracle_cell",
        ),
        confidence=confidence,
        assurance=AssuranceLevel.A1,
        phase=CellPhase.CRYSTALLIZED,
        evidence_lineage=(_MANDATORY,),
        constraints=(
            HardConstraint(
                constraint_id="q-never-lower-phi",
                kind=ConstraintKind.NEVER_LOWER_PHI,
                detail="a cell may not report a state whose Φ is below Stage 1's",
            ),
        ),
        epochs=epochs,
        audit_policy=AuditPolicy(
            base_rate=0.05, min_rate=0.01, max_rate=0.5, jitter_salt="stage3-labs"
        ),
        version=1,
        parent_cell_id=None,
        source_candidate_id=PHI_ORACLE_CANDIDATE_ID,
    )


class CellPathBaseline:
    """S3. The Stage 3 runtime path: boundary lookup, then a verified program.

    This is the row G3.9 turns on. It is **not** a baseline — it is the mechanism
    the baselines control for — and it is measured in the same run, through the
    same scorer interface, so the comparison is a within-run ratio.
    """

    baseline_id = "S3"
    description = "BoundaryIndex.lookup + CellVM.run over a Φ-oracle KnowledgeCellV1"

    def __init__(self, *, cell: KnowledgeCellV1 | None = None) -> None:
        self._cell = cell if cell is not None else phi_oracle_cell()
        self._index = BoundaryIndex()
        self._index.insert(self._cell)
        self._vm = CellVM()
        self.abstentions = 0

    @property
    def cell(self) -> KnowledgeCellV1:
        return self._cell

    def fit(self, corpus: CrystalCorpus) -> CellPathBaseline:
        return self

    def score(self, session: CrystalSession) -> float:
        best = 0.0
        for frame in session_frames(session):
            cell = self._index.lookup(frame)
            if cell is None:
                self.abstentions += 1
                continue
            result = self._vm.run(cell.operator, frame)
            if result.abstained:
                self.abstentions += 1
                continue
            best = max(best, float(result.risk))
        return best

    def size_bytes(self) -> int:
        return self._cell.size_bytes() + self._index.memory_bytes()
