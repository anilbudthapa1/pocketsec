"""D6.4 — procedural memory: what Stage 5 did, and whether it was verified.

**Procedural memory changes no detection outcome.** Nothing in :func:`score_session`
reads a PROCEDURE item, and nothing in Stages 1-5 reads this module. It is a bounded,
typed record store whose consumers are the Stage 7 export and the gate's lineage
check. The gate reports it as *not a detection mechanism* and reports its lookup
count; it is never counted as evidence that learning helped. Saying so in the module
that defines it is deliberate: a record store with "memory" in its name is easy to
mistake for a capability.

What it refuses to do:

* **It never promotes an unverified outcome to verified.** Only a receipt row whose
  ``outcome`` equals Stage 5's own ``VERIFIED_OUTCOME`` counts as verified; an
  unrecognised outcome string counts as *unverified*, never as success. Refusal rows
  (Stage 5's ``REFUSAL_OUTCOMES``) are the system declining to act and describe no
  procedure, so they are ignored.
* **It never forgets that a result was simulated.** ``simulated`` is sticky: one
  simulated row, a row that does not say, or a capsule flagged ``SIMULATED_RECORD``
  makes the record simulated, and :func:`merge_procedure` ORs it. Every Stage 5 record
  today is simulated (ADR-0046), so every procedure Stage 6 learns today is too.
* **It carries no authority.** A record names an operator id; it cannot invoke one.
  Only Stage 5 typed operators touch privilege (ADR-0003).
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage5.stage6_interface import REFUSAL_OUTCOMES, VERIFIED_OUTCOME
from pocketsec.stage6.capsule.experience_capsule import (
    CapsuleKind,
    ContaminationFlag,
    ExperienceCapsuleV1,
)
from pocketsec.stage6.memory.semantic import (
    MAX_ITEM_CAPSULE_REFS,
    ItemKind,
    TrustedKnowledgeState,
    item_applies,
)

__all__ = [
    "ProceduralMemory",
    "ProcedureRecord",
    "merge_procedure",
    "procedure_key",
    "procedure_observations",
]

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_REFUSALS: frozenset[str] = frozenset(str(outcome) for outcome in REFUSAL_OUTCOMES)


def procedure_key(operator_id: str, context_id: str) -> str:
    """THE procedure key, ``"<operator_id>|<context_id>"`` — one function, both sides."""
    return f"{operator_id}|{context_id}"


def _count(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ContractError(f"ProcedureRecord.{field} must be a non-negative int, got {value!r}")
    return value


@dataclass(frozen=True, slots=True)
class ProcedureRecord:
    """Outcome counts for one operator in one knowledge context."""

    operator_id: str
    operator_class: int
    context_id: str
    verified: int
    unverified: int
    rolled_back: int
    failed: int
    simulated: bool
    evidence_digests: tuple[str, ...]
    #: True when more evidence digests existed than ``MAX_ITEM_CAPSULE_REFS``. The
    #: surplus lives on in the capsule and the lineage DAG; the flag says it was cut.
    evidence_truncated: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.operator_id, str) or not self.operator_id or "|" in self.operator_id:
            raise ContractError("ProcedureRecord.operator_id must be a non-empty id without '|'")
        if not isinstance(self.context_id, str) or not self.context_id.startswith("ctx-"):
            raise ContractError("ProcedureRecord.context_id comes from context_id_for()")
        for name in ("operator_class", "verified", "unverified", "rolled_back", "failed"):
            _count(getattr(self, name), name)
        if not isinstance(self.simulated, bool) or not isinstance(self.evidence_truncated, bool):
            raise ContractError("ProcedureRecord.simulated / evidence_truncated are bools")
        digests = tuple(self.evidence_digests)
        if len(digests) > MAX_ITEM_CAPSULE_REFS:
            raise ContractError(
                f"a procedure cites at most {MAX_ITEM_CAPSULE_REFS} evidence digests; "
                "truncate explicitly and set evidence_truncated"
            )
        if any(not isinstance(d, str) or not _DIGEST_RE.fullmatch(d) for d in digests):
            raise ContractError("procedure evidence is referenced by sha256 digest only")
        object.__setattr__(self, "evidence_digests", digests)

    @property
    def key(self) -> str:
        return procedure_key(self.operator_id, self.context_id)

    def to_payload(self) -> dict[str, Any]:
        return {
            "operator_id": self.operator_id,
            "operator_class": self.operator_class,
            "context_id": self.context_id,
            "verified": self.verified,
            "unverified": self.unverified,
            "rolled_back": self.rolled_back,
            "failed": self.failed,
            "simulated": self.simulated,
            "evidence_digests": list(self.evidence_digests),
            "evidence_truncated": self.evidence_truncated,
        }

    @classmethod
    def from_payload(cls, raw: Mapping[str, Any]) -> ProcedureRecord:
        if not isinstance(raw, Mapping) or set(raw) != set(cls.__dataclass_fields__):
            raise ContractError("a procedure payload has the wrong keys")
        return cls(**{**raw, "evidence_digests": tuple(raw["evidence_digests"])})


def _bounded_digests(digests: list[str]) -> tuple[tuple[str, ...], bool]:
    unique = list(dict.fromkeys(digests))
    return tuple(unique[:MAX_ITEM_CAPSULE_REFS]), len(unique) > MAX_ITEM_CAPSULE_REFS


def merge_procedure(left: ProcedureRecord, right: ProcedureRecord) -> ProcedureRecord:
    """Sum two records for the same operator and context. ``simulated`` is ORed (sticky)."""
    if left.key != right.key or left.operator_class != right.operator_class:
        raise ContractError(f"cannot merge procedures {left.key!r} and {right.key!r}")
    digests, cut = _bounded_digests([*left.evidence_digests, *right.evidence_digests])
    return dataclasses.replace(
        left,
        verified=left.verified + right.verified,
        unverified=left.unverified + right.unverified,
        rolled_back=left.rolled_back + right.rolled_back,
        failed=left.failed + right.failed,
        simulated=left.simulated or right.simulated,
        evidence_digests=digests,
        evidence_truncated=left.evidence_truncated or right.evidence_truncated or cut,
    )


def _classify(row: Mapping[str, Any]) -> str | None:
    """Which counter a receipt row increments, or None for a refusal row."""
    outcome = str(row.get("outcome"))
    if outcome in _REFUSALS:
        return None
    if outcome == VERIFIED_OUTCOME:
        return "verified"
    if row.get("rollback_succeeded") is True:
        return "rolled_back"
    if row.get("rollback_attempted") is True:
        return "failed"
    # COMMITTED_UNVERIFIED, ESCALATED and any outcome this module does not know: an
    # unknown outcome is never success.
    return "unverified"


def procedure_observations(capsule: ExperienceCapsuleV1) -> tuple[ProcedureRecord, ...]:
    """One record per operator in a RESPONSE_OUTCOME capsule; () for any other kind."""
    if capsule.kind is not CapsuleKind.RESPONSE_OUTCOME:
        return ()
    flagged = ContaminationFlag.SIMULATED_RECORD in capsule.contamination_flags
    tallies: dict[str, dict[str, Any]] = {}
    for row in capsule.procedure_rows:
        kind = _classify(row)
        if kind is None:
            continue
        operator_id = row.get("operator_id")
        operator_class = row.get("operator_class")
        if not isinstance(operator_id, str) or not isinstance(operator_class, int):
            raise ContractError("a receipt row carries operator_id (str) and operator_class (int)")
        tally = tallies.setdefault(
            operator_id,
            {"operator_class": operator_class, "simulated": flagged, "digests": [],
             "verified": 0, "unverified": 0, "rolled_back": 0, "failed": 0},
        )
        if tally["operator_class"] != operator_class:
            raise ContractError(f"operator {operator_id!r} reported two operator classes")
        tally[kind] += 1
        # A row that does not say whether it was simulated is treated as simulated.
        tally["simulated"] = tally["simulated"] or row.get("simulated", True) is not False
        tally["digests"].extend(capsule.evidence_refs)
        bundle = row.get("evidence_bundle_digest")
        if isinstance(bundle, str) and _DIGEST_RE.fullmatch(bundle):
            tally["digests"].append(bundle)
    return tuple(_record(op, capsule.context_id, t) for op, t in sorted(tallies.items()))


def _record(operator_id: str, context_id: str, tally: Mapping[str, Any]) -> ProcedureRecord:
    digests, cut = _bounded_digests(tally["digests"])
    return ProcedureRecord(
        operator_id=operator_id,
        operator_class=tally["operator_class"],
        context_id=context_id,
        verified=tally["verified"],
        unverified=tally["unverified"],
        rolled_back=tally["rolled_back"],
        failed=tally["failed"],
        simulated=tally["simulated"],
        evidence_digests=digests,
        evidence_truncated=cut,
    )


class ProceduralMemory:
    """Read-only view over a trusted state's PROCEDURE items. Counts its own lookups."""

    __slots__ = ("_by_key", "_hits", "_lookups")

    def __init__(self, state: TrustedKnowledgeState) -> None:
        if not isinstance(state, TrustedKnowledgeState):
            raise ContractError("ProceduralMemory views a TrustedKnowledgeState")
        self._by_key = {
            item.pattern_key: item
            for item in state.items
            if item.kind is ItemKind.PROCEDURE and item.procedure is not None
        }
        self._lookups = 0
        self._hits = 0

    def lookup(self, operator_id: str, *, context_id: str) -> ProcedureRecord | None:
        """The ACTIVE record for this operator in this context, or None."""
        self._lookups += 1
        item = self._by_key.get(procedure_key(operator_id, context_id))
        if item is None or not item_applies(item, context_id):
            return None
        self._hits += 1
        return item.procedure

    @property
    def lookups(self) -> int:
        return self._lookups

    @property
    def hits(self) -> int:
        return self._hits
