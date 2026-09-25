"""D4.14 (feedback half) / CBF-F19 — Stage 4 questions Stage 3, and may not overrule it.

Architecture §27: **no stage is permanently unquestionable.** An incident that
repeatedly contradicts a crystallised Knowledge Cell has found something, and a
system where the only flow is Stage 3 → Stage 4 cannot learn from it.

Falsifier F9 is the other half of the same sentence, and it is why every threshold
here exists: **no stage may be destabilised by one observation either.** A single
contradiction produces nothing. :data:`MIN_CONTRADICTIONS_FOR_STRESS` distinct
contradicting claims are required, they must be *authoritative* claims (OBS or DER —
an inference may not question a cell, which is the authority discipline of §22), and
the incident must actually have entered the cell's boundary. A stress signal for a
region the incident never touched is noise that would make Stage 3 audit itself at
an attacker's convenience.

**Neither signal promotes anything.** A :class:`CellStressSignalV1` *requests* an
audit; a :class:`CrystalCandidateSignalV1` *proposes* a cell. Stage 4 has no path to
melt a cell and no path to create one, and there is no function in this module — or
anywhere in Stage 4 — whose name contains ``melt``, ``promote`` or ``crystallize``.
``tests/test_stage4_runtime.py`` asserts that by walking every Stage 4 module's
``__all__``, so the property is mechanical rather than a promise.

The transport is **canonical JSON with a sha256 digest**, in both directions: Stage 4
reads Stage 3's handoff as JSON (``crystal/handoff.py``) and writes these signals as
JSON for a later Stage 3 session to read. There is **zero** ``import pocketsec.stage3``
anywhere under ``pocketsec/stage4/`` and zero import the other way. Stage 3 is being
redesigned (ADR-0021 is live) and a JSON reader survives a redesign where an import
does not.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    digest_of_bytes,
    register_schema,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage4.claims.graph import ClaimGraph
from pocketsec.stage4.claims.typed_claim import is_authoritative_kind
from pocketsec.stage4.crystal.handoff import CrystalKnowledge

__all__ = [
    "CELL_STRESS_V1_ID",
    "CELL_STRESS_V1_VERSION",
    "CRYSTAL_CANDIDATE_V1_ID",
    "CRYSTAL_CANDIDATE_V1_VERSION",
    "MAX_CANDIDATE_SIGNALS",
    "MAX_STRESS_SIGNALS",
    "MIN_CONTRADICTIONS_FOR_STRESS",
    "MIN_RESOLUTIONS_FOR_CRYSTAL_CANDIDATE",
    "CellStressSignalV1",
    "CrystalCandidateSignalV1",
    "ResolutionRecord",
    "contradicting_claim_ids",
    "propose_crystal_candidates",
    "stress_stage3_cell",
    "write_feedback",
]

CELL_STRESS_V1_ID = "pocketsec.cell_stress_signal.v1"
CELL_STRESS_V1_VERSION = register_schema(CELL_STRESS_V1_ID, "1.0.0")
CRYSTAL_CANDIDATE_V1_ID = "pocketsec.crystal_candidate_signal.v1"
CRYSTAL_CANDIDATE_V1_VERSION = register_schema(CRYSTAL_CANDIDATE_V1_ID, "1.0.0")

#: Distinct authoritative claims that must contradict a cell before Stage 4 will
#: ask Stage 3 to look at it. Three, not one: falsifier F9 fires if a single
#: contradiction destabilises trusted knowledge, and a cell is *supposed* to be hard
#: to unseat — that is what crystallisation bought.
MIN_CONTRADICTIONS_FOR_STRESS: int = 3

#: Times the same mechanism must resolve an incident before Stage 4 proposes it as a
#: cell. Also three, and for the mirror-image reason: one resolution is an anecdote,
#: and a candidate built from one would hand Stage 3 the incident rather than the
#: pattern.
MIN_RESOLUTIONS_FOR_CRYSTAL_CANDIDATE: int = 3

#: Bounds per run. Feedback is endpoint state that gets written to disk, and an
#: unbounded signal file is a denial-of-service against the Stage 3 session that has
#: to read it.
MAX_STRESS_SIGNALS: int = 32
MAX_CANDIDATE_SIGNALS: int = 16

_KEY_LENGTH = 3


def _require_boundary_key(value: object, field: str) -> tuple[int, int, int]:
    """A boundary key is exactly three ints: relation family, actor mask, ΔS mask.

    Validated rather than trusted because it arrives from a JSON file Stage 3 wrote
    and will be written back into a JSON file Stage 3 reads. A malformed key would
    make the round trip silently address a different region of the boundary index.
    """
    if not isinstance(value, (tuple, list)) or len(value) != _KEY_LENGTH:
        raise ContractError(f"{field} must be three ints (relation, actor, delta), got {value!r}")
    parts: list[int] = []
    for index, item in enumerate(value):
        if not isinstance(item, int) or isinstance(item, bool) or item < 0:
            raise ContractError(f"{field}[{index}] must be a non-negative int, got {item!r}")
        parts.append(int(item))
    return (parts[0], parts[1], parts[2])


def _require_digests(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)):
        raise ContractError(f"{field} must be a sequence of sha256 digests")
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.startswith("sha256:"):
            raise ContractError(f"{field} holds {item!r}, which is not a 'sha256:' digest")
        if item not in out:
            out.append(item)
    return tuple(out)


@dataclass(frozen=True, slots=True)
class CellStressSignalV1:
    """A request that Stage 3 audit one cell. Not a melt, and not a verdict.

    Carries the evidence digests so the Stage 3 session that reads it can reach the
    raw evidence itself rather than trusting Stage 4's reading of it — the same
    lineage discipline ``EvidenceRef`` imposes everywhere else.
    """

    signal_id: str
    cell_id: str
    boundary_key: tuple[int, int, int]
    contradiction_count: int
    contradicting_claim_ids: tuple[str, ...]
    evidence_digests: tuple[str, ...]
    incident_ids: tuple[str, ...]
    interface_version: str = CELL_STRESS_V1_VERSION

    def __post_init__(self) -> None:
        require_identifier(self.signal_id, "CellStressSignalV1.signal_id")
        require_identifier(self.cell_id, "CellStressSignalV1.cell_id")
        object.__setattr__(
            self,
            "boundary_key",
            _require_boundary_key(self.boundary_key, "CellStressSignalV1.boundary_key"),
        )
        require_non_negative_int(
            self.contradiction_count, "CellStressSignalV1.contradiction_count"
        )
        object.__setattr__(self, "contradicting_claim_ids", tuple(self.contradicting_claim_ids))
        object.__setattr__(
            self,
            "evidence_digests",
            _require_digests(self.evidence_digests, "CellStressSignalV1.evidence_digests"),
        )
        object.__setattr__(self, "incident_ids", tuple(self.incident_ids))
        if self.contradiction_count < MIN_CONTRADICTIONS_FOR_STRESS:
            raise ContractError(
                f"CellStressSignalV1({self.cell_id!r}) carries "
                f"{self.contradiction_count} contradictions, under "
                f"MIN_CONTRADICTIONS_FOR_STRESS={MIN_CONTRADICTIONS_FOR_STRESS}; one "
                "observation may not destabilise crystallised knowledge (falsifier F9)"
            )
        if len(self.contradicting_claim_ids) != self.contradiction_count:
            raise ContractError(
                f"CellStressSignalV1({self.cell_id!r}) counts "
                f"{self.contradiction_count} contradictions but names "
                f"{len(self.contradicting_claim_ids)}; a count Stage 3 cannot check is not "
                "evidence"
            )
        if not self.incident_ids:
            raise ContractError(
                "CellStressSignalV1 names no incident; a stress signal with no incident "
                "cannot be audited back to what produced it"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "interface_version": self.interface_version,
            "schema_id": CELL_STRESS_V1_ID,
            "signal_id": self.signal_id,
            "cell_id": self.cell_id,
            "boundary_key": list(self.boundary_key),
            "contradiction_count": self.contradiction_count,
            "contradicting_claim_ids": list(self.contradicting_claim_ids),
            "evidence_digests": list(self.evidence_digests),
            "incident_ids": list(self.incident_ids),
            "requests": "stage3_audit",
        }


@dataclass(frozen=True, slots=True)
class CrystalCandidateSignalV1:
    """A proposal that Stage 3 consider crystallising a repeatedly resolved structure.

    ``stable_claim_rule_ids`` is what makes it a pattern rather than an incident: the
    deterministic derivation rules that fired in *every* resolution, not the union
    over them. A union would propose a cell for whatever happened once.
    """

    signal_id: str
    mechanism_id: str
    resolution_count: int
    stable_claim_rule_ids: tuple[str, ...]
    boundary_keys: tuple[tuple[int, int, int], ...]
    evidence_digests: tuple[str, ...]
    interface_version: str = CRYSTAL_CANDIDATE_V1_VERSION

    def __post_init__(self) -> None:
        require_identifier(self.signal_id, "CrystalCandidateSignalV1.signal_id")
        require_identifier(self.mechanism_id, "CrystalCandidateSignalV1.mechanism_id")
        require_non_negative_int(
            self.resolution_count, "CrystalCandidateSignalV1.resolution_count"
        )
        object.__setattr__(self, "stable_claim_rule_ids", tuple(self.stable_claim_rule_ids))
        object.__setattr__(
            self,
            "boundary_keys",
            tuple(
                _require_boundary_key(key, "CrystalCandidateSignalV1.boundary_keys")
                for key in self.boundary_keys
            ),
        )
        object.__setattr__(
            self,
            "evidence_digests",
            _require_digests(
                self.evidence_digests, "CrystalCandidateSignalV1.evidence_digests"
            ),
        )
        if self.resolution_count < MIN_RESOLUTIONS_FOR_CRYSTAL_CANDIDATE:
            raise ContractError(
                f"CrystalCandidateSignalV1({self.mechanism_id!r}) rests on "
                f"{self.resolution_count} resolutions, under "
                f"MIN_RESOLUTIONS_FOR_CRYSTAL_CANDIDATE="
                f"{MIN_RESOLUTIONS_FOR_CRYSTAL_CANDIDATE}"
            )
        if not self.stable_claim_rule_ids:
            raise ContractError(
                f"CrystalCandidateSignalV1({self.mechanism_id!r}) names no stable rule; a "
                "candidate with nothing stable across its resolutions is an incident, "
                "not a pattern"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "interface_version": self.interface_version,
            "schema_id": CRYSTAL_CANDIDATE_V1_ID,
            "signal_id": self.signal_id,
            "mechanism_id": self.mechanism_id,
            "resolution_count": self.resolution_count,
            "stable_claim_rule_ids": list(self.stable_claim_rule_ids),
            "boundary_keys": [list(key) for key in self.boundary_keys],
            "evidence_digests": list(self.evidence_digests),
            "proposes": "stage3_candidate_review",
        }


@dataclass(frozen=True, slots=True)
class ResolutionRecord:
    """One incident this mechanism resolved, as :func:`propose_crystal_candidates` reads it.

    A named type rather than a tuple because the intersection of ``rule_ids`` across
    records is the whole mechanism, and a positional row would let two callers
    disagree about which slot held them.
    """

    mechanism_id: str
    incident_id: str
    rule_ids: tuple[str, ...]
    boundary_keys: tuple[tuple[int, int, int], ...]
    evidence_digests: tuple[str, ...]

    def __post_init__(self) -> None:
        require_identifier(self.mechanism_id, "ResolutionRecord.mechanism_id")
        require_identifier(self.incident_id, "ResolutionRecord.incident_id")
        object.__setattr__(self, "rule_ids", tuple(dict.fromkeys(self.rule_ids)))
        object.__setattr__(
            self,
            "boundary_keys",
            tuple(
                _require_boundary_key(key, "ResolutionRecord.boundary_keys")
                for key in self.boundary_keys
            ),
        )
        object.__setattr__(
            self,
            "evidence_digests",
            _require_digests(self.evidence_digests, "ResolutionRecord.evidence_digests"),
        )


def contradicting_claim_ids(
    graph: ClaimGraph, subjects: Sequence[str]
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Authoritative claims whose subject is one the incident found contradictory.

    Authoritative only — OBS and DER. An ``InferredClaim`` may not question a
    crystallised cell: allowing it would let Stage 4's own guess unseat validated
    knowledge, which is precisely the authority inversion ADR-0003 forbids. Returns
    ``(claim_id, evidence_digests)`` pairs so the caller need not re-walk the graph.
    """
    wanted = frozenset(subjects)
    if not wanted:
        return ()
    found: list[tuple[str, tuple[str, ...]]] = []
    for claim_id in sorted(graph.authoritative):
        claim = graph.claims.get(claim_id)
        if claim is None or not is_authoritative_kind(claim):
            continue
        if claim.subject not in wanted:
            continue
        found.append((claim_id, tuple(ref.digest for ref in claim.evidence)))
    return tuple(found)


def stress_stage3_cell(
    knowledge: CrystalKnowledge,
    graph: ClaimGraph,
    *,
    incident_ids: Sequence[str],
    entered_keys: Sequence[tuple[int, int, int]] = (),
    contradicted_subjects: Sequence[str] = (),
) -> tuple[CellStressSignalV1, ...]:
    """CBF-F19 — request a Stage 3 audit for cells this incident actually contradicted.

    ``entered_keys`` and ``contradicted_subjects`` are keyword extensions to the
    spec's signature and both default to empty, which makes the default behaviour
    **no signals at all**. That is deliberate and it is the F9 half of §27: a
    ``ClaimGraph`` alone cannot say which boundary region the incident entered — the
    claims carry subjects and digests, not boundary masks — so deriving entry from
    the graph would mean guessing, and a guessed boundary entry lets an incident
    stress a cell it never touched.

    Four conditions, all required:

    1. the incident entered the cell's boundary (an entered key matches one of the
       cell's keys);
    2. the cell is not already melted — a melted cell has been questioned already, and
       ``melt_history`` is in the handoff precisely so this can be told apart from
       "never crystallised";
    3. at least :data:`MIN_CONTRADICTIONS_FOR_STRESS` distinct authoritative claims,
       resting on at least as many distinct evidence digests, contradict it;
    4. the incident set is non-empty, so the request can be audited back.
    """
    if not incident_ids:
        raise ContractError(
            "stress_stage3_cell needs the incident ids that produced the graph; a signal "
            "nobody can trace is not evidence"
        )
    entered = frozenset(
        _require_boundary_key(key, "stress_stage3_cell entered_keys") for key in entered_keys
    )
    if not entered:
        return ()
    pairs = contradicting_claim_ids(graph, contradicted_subjects)
    claim_ids = tuple(claim_id for claim_id, _ in pairs)
    digests = tuple(
        dict.fromkeys(digest for _, refs in pairs for digest in refs if digest)
    )
    # Counted in distinct EVIDENCE, not distinct claims. The compiler emits one OBS
    # per world per evidence reference and fission children inherit their parent's
    # references, so one raw observation shared by three sibling worlds was three
    # "contradictions" — the F9 failure this threshold exists to prevent (S4-SEC-07).
    if len(pairs) < MIN_CONTRADICTIONS_FOR_STRESS or len(digests) < MIN_CONTRADICTIONS_FOR_STRESS:
        return ()
    signals: list[CellStressSignalV1] = []
    for cell_id in knowledge.cell_ids():
        if knowledge.melted(cell_id):
            continue
        matched = sorted(entered & frozenset(knowledge.keys_for(cell_id)))
        if not matched:
            continue
        if len(signals) >= MAX_STRESS_SIGNALS:
            break
        signals.append(
            CellStressSignalV1(
                signal_id=f"s4-stress-{cell_id}",
                cell_id=cell_id,
                boundary_key=matched[0],
                contradiction_count=len(claim_ids),
                contradicting_claim_ids=claim_ids,
                evidence_digests=digests,
                incident_ids=tuple(dict.fromkeys(incident_ids)),
            )
        )
    return tuple(signals)


def propose_crystal_candidates(
    history: Sequence[ResolutionRecord],
) -> tuple[CrystalCandidateSignalV1, ...]:
    """Propose mechanisms that resolved repeatedly, with a stable derivation.

    A **proposal**, never a promotion: Stage 4 has no path to create a cell, and
    Stage 3 owns every gate between a candidate and crystallised knowledge.

    The ``stable_claim_rule_ids`` are the **intersection** across the mechanism's
    resolutions. A union would propose a cell covering whatever happened once, which
    is how a validated-knowledge layer acquires rules nobody can reproduce.
    """
    grouped: dict[str, list[ResolutionRecord]] = {}
    for record in history:
        if not isinstance(record, ResolutionRecord):
            raise ContractError(
                "propose_crystal_candidates takes ResolutionRecord rows, got "
                f"{type(record).__name__}"
            )
        grouped.setdefault(record.mechanism_id, []).append(record)
    signals: list[CrystalCandidateSignalV1] = []
    for mechanism_id in sorted(grouped):
        records = grouped[mechanism_id]
        incidents = {record.incident_id for record in records}
        if len(incidents) < MIN_RESOLUTIONS_FOR_CRYSTAL_CANDIDATE:
            continue
        stable: set[str] | None = None
        for record in records:
            stable = (
                set(record.rule_ids) if stable is None else stable & set(record.rule_ids)
            )
        if not stable:
            continue
        if len(signals) >= MAX_CANDIDATE_SIGNALS:
            break
        signals.append(
            CrystalCandidateSignalV1(
                signal_id=f"s4-candidate-{mechanism_id}",
                mechanism_id=mechanism_id,
                resolution_count=len(incidents),
                stable_claim_rule_ids=tuple(sorted(stable)),
                boundary_keys=tuple(
                    sorted({key for record in records for key in record.boundary_keys})
                ),
                evidence_digests=tuple(
                    dict.fromkeys(
                        digest for record in records for digest in record.evidence_digests
                    )
                ),
            )
        )
    return tuple(signals)


def write_feedback(
    signals: Sequence[CellStressSignalV1 | CrystalCandidateSignalV1], path: Path
) -> str:
    """Write canonical JSON and return its ``sha256:`` digest.

    Canonical (sorted keys, no NaN, fixed indent, trailing newline) so the digest is
    reproducible and a later Stage 3 session can prove the signals it read are the
    signals Stage 4 wrote. The payload separates the two kinds because they mean
    different things: one asks for an audit, the other offers a candidate, and a
    single undifferentiated list would invite a reader to treat them alike.
    """
    stress: list[Mapping[str, Any]] = []
    candidates: list[Mapping[str, Any]] = []
    for signal in signals:
        if isinstance(signal, CellStressSignalV1):
            stress.append(signal.to_dict())
        elif isinstance(signal, CrystalCandidateSignalV1):
            candidates.append(signal.to_dict())
        else:
            raise ContractError(
                f"write_feedback takes Stage 4 feedback signals, got {type(signal).__name__}"
            )
    payload = {
        "schema_id": "pocketsec.stage4_feedback.v1",
        "stress_signals": stress,
        "candidate_signals": candidates,
        "authority": "none: a stress signal requests an audit, a candidate proposes review",
    }
    encoded = (
        json.dumps(payload, sort_keys=True, allow_nan=False, indent=2).encode("utf-8") + b"\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded)
    return digest_of_bytes(encoded)
