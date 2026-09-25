"""D3.9 — counterexample memory: permanent test material, bounded but never deleted.

Every failed crystallization attempt produces a counterexample (§21). It stays as
regression material until a versioned specification *supersedes* it — which marks it,
and keeps it.

**There is no delete method and one may not be added.** "Never delete prior research
artefacts, counterexamples, provenance or rollback information" is the project rule, and
here it is enforced by the absence of the method rather than by review: a
``CounterexampleStore`` exposes no API through which a caller can remove a record, and
``tests/test_stage3_oracles.py`` asserts that over ``dir()``. Eviction is *spilling* to
an append-only cold archive, not deletion, and a store with nowhere to spill refuses to
accept more rather than losing what it holds.

An incident-linked counterexample is never spilled at all (§29, §40). If every hot entry
is incident-linked, :meth:`CounterexampleStore.record` raises. Raising is the correct
behaviour: the alternative is choosing which piece of incident evidence to lose, and no
bound is worth that.
"""

from __future__ import annotations

import json
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef, require_identifier
from pocketsec.stage1.state.security_state import SecurityStateV1

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pocketsec.stage1.ssir.transition import SSIRTransitionV1
    from pocketsec.stage3.bytecode.vm import CellFrame, CellResult, CellVM
    from pocketsec.stage3.oracles.security_specs import CellLike

__all__ = [
    "MAX_HOT_BYTES",
    "MAX_HOT_COUNTEREXAMPLES",
    "Counterexample",
    "CounterexampleStore",
    "replay_corpus_size",
]

#: §38 bounds the hot store. Both caps bind; whichever is reached first triggers a spill.
MAX_HOT_COUNTEREXAMPLES = 2048
MAX_HOT_BYTES = 15 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class Counterexample:
    """§21, field for field, plus the three fields lineage needs.

    ``incident_linked`` and ``superseded_by`` are not decoration: the first makes an
    entry immune to spilling and to melting, the second is how a record is retired
    without being destroyed.
    """

    counterexample_id: str
    cell_candidate_id: str
    transitions: tuple[SSIRTransitionV1, ...]
    state: SecurityStateV1
    epoch_id: int
    expected: CellResult
    observed: CellResult
    divergence_type: str
    evidence: tuple[EvidenceRef, ...]
    incident_linked: bool = False
    superseded_by: str | None = None

    def __post_init__(self) -> None:
        require_identifier(self.counterexample_id, "Counterexample.counterexample_id")
        require_identifier(self.cell_candidate_id, "Counterexample.cell_candidate_id")
        if not isinstance(self.transitions, tuple) or not self.transitions:
            raise ContractError(
                "Counterexample.transitions must be a non-empty tuple: a counterexample "
                "with no events cannot be replayed and is not regression material"
            )
        if not isinstance(self.state, SecurityStateV1):
            raise ContractError("Counterexample.state must be a SecurityStateV1")
        if (
            not isinstance(self.epoch_id, int)
            or isinstance(self.epoch_id, bool)
            or self.epoch_id < 0
        ):
            raise ContractError(
                f"Counterexample.epoch_id must be a non-negative int, got {self.epoch_id!r}"
            )
        if not isinstance(self.divergence_type, str) or not self.divergence_type.strip():
            raise ContractError("Counterexample.divergence_type must be a non-empty string")
        if not isinstance(self.evidence, tuple) or not all(
            isinstance(ref, EvidenceRef) for ref in self.evidence
        ):
            raise ContractError("Counterexample.evidence must be a tuple of EvidenceRef")
        if not isinstance(self.incident_linked, bool):
            raise ContractError("Counterexample.incident_linked must be a bool")
        if self.superseded_by is not None:
            require_identifier(self.superseded_by, "Counterexample.superseded_by")
            if self.superseded_by == self.counterexample_id:
                raise ContractError("a counterexample cannot supersede itself")

    def to_dict(self) -> dict[str, Any]:
        """Archive form. Transitions and results are serialised through their own contracts."""
        return {
            "counterexample_id": self.counterexample_id,
            "cell_candidate_id": self.cell_candidate_id,
            "transitions": [t.to_dict() for t in self.transitions],
            "state": self.state.to_dict(),
            "epoch_id": self.epoch_id,
            "expected": _result_to_dict(self.expected),
            "observed": _result_to_dict(self.observed),
            "divergence_type": self.divergence_type,
            "evidence": [ref.to_dict() for ref in self.evidence],
            "incident_linked": self.incident_linked,
            "superseded_by": self.superseded_by,
        }

    def size_bytes(self) -> int:
        """The record's archived size in canonical JSON — the unit :data:`MAX_HOT_BYTES` caps.

        Measuring the serialised form rather than ``sys.getsizeof`` is deliberate: the
        bound that matters on a 2 GB host is what the store will hold and write, and an
        object-graph estimate of a shared, interned transition is not that.
        """
        return len(_canonical_line(self.to_dict()))


def _result_to_dict(result: CellResult) -> dict[str, Any]:
    """Serialise a ``CellResult`` without importing the bytecode package at runtime.

    The oracles judge results; they do not construct them. Reading the documented fields
    keeps the store usable while ``bytecode`` is still being built, and keeps this module
    off the import path of a subsystem it does not need.
    """
    return {
        "abstained": bool(result.abstained),
        "delta": result.delta.to_dict(),
        "evidence": [ref.to_dict() for ref in result.evidence],
        "risk": float(result.risk),
        "escalation": None if result.escalation is None else result.escalation.to_dict(),
        "steps_taken": int(result.steps_taken),
        "reason": str(result.reason),
    }


def _canonical_line(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, allow_nan=False).encode("utf-8") + b"\n"


class CounterexampleStore:
    """Bounded hot memory over an append-only cold archive.

    The bound is on the *hot* store only. Nothing is ever removed from the archive, and
    nothing reaches the archive except by being spilled out of hot, so the archive is the
    full history in insertion order.
    """

    __slots__ = (
        "_archived",
        "_cold_archive",
        "_frame_builder",
        "_hot",
        "_hot_bytes",
        "_max_bytes",
        "_max_hot",
    )

    def __init__(
        self,
        *,
        cold_archive: Path | None,
        max_hot: int = MAX_HOT_COUNTEREXAMPLES,
        max_bytes: int = MAX_HOT_BYTES,
        frame_builder: Callable[[Counterexample], CellFrame] | None = None,
    ) -> None:
        """``frame_builder`` reconstructs the frame a counterexample was found on.

        §21 fixes the counterexample's fields and a ``CellFrame`` is not among them, so
        :meth:`replay_all` cannot rebuild one by itself without duplicating the frame
        construction that ``bytecode``/``knowledge_boundary`` own. The builder is
        injected rather than assumed, and its absence is an explicit refusal in
        :meth:`replay_all` rather than a silently empty regression corpus.
        """
        if not isinstance(max_hot, int) or isinstance(max_hot, bool) or max_hot < 1:
            raise ContractError(f"max_hot must be a positive int, got {max_hot!r}")
        if max_hot > MAX_HOT_COUNTEREXAMPLES:
            raise ContractError(
                f"max_hot {max_hot} exceeds the §38 bound {MAX_HOT_COUNTEREXAMPLES}"
            )
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
            raise ContractError(f"max_bytes must be a positive int, got {max_bytes!r}")
        if max_bytes > MAX_HOT_BYTES:
            raise ContractError(f"max_bytes {max_bytes} exceeds the §38 bound {MAX_HOT_BYTES}")
        if cold_archive is not None and not isinstance(cold_archive, Path):
            raise ContractError("cold_archive must be a Path or None")
        self._cold_archive = cold_archive
        self._max_hot = max_hot
        self._max_bytes = max_bytes
        self._frame_builder = frame_builder
        self._hot: OrderedDict[str, Counterexample] = OrderedDict()
        self._hot_bytes = 0
        self._archived = 0

    # --- reading -------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._hot)

    @property
    def cold_archive(self) -> Path | None:
        return self._cold_archive

    @property
    def archived_count(self) -> int:
        """How many records have been spilled to cold. They still exist; they are not here."""
        return self._archived

    def hot(self) -> tuple[Counterexample, ...]:
        """Every hot record, oldest first."""
        return tuple(self._hot.values())

    def for_candidate(self, candidate_id: str) -> tuple[Counterexample, ...]:
        require_identifier(candidate_id, "candidate_id")
        return tuple(cx for cx in self._hot.values() if cx.cell_candidate_id == candidate_id)

    def memory_bytes(self) -> int:
        """Canonical-JSON bytes currently held hot."""
        return self._hot_bytes

    # --- writing -------------------------------------------------------------

    def record(self, cx: Counterexample) -> None:
        """Admit a counterexample, spilling the oldest non-incident entry if at capacity.

        Re-recording a record that is *identical* to one already held is a no-op, not an
        error: producers derive a counterexample id from its content, so the same failure
        found twice is one fact, not two. Recording a **different** record under a held
        id is refused, because that would overwrite evidence — the one thing this store
        exists to make impossible. A full store with nothing spillable is refused too.
        """
        if not isinstance(cx, Counterexample):
            raise ContractError(f"record takes a Counterexample, got {type(cx).__name__}")
        held = self._hot.get(cx.counterexample_id)
        if held is not None:
            if held == cx:
                return
            raise ContractError(
                f"counterexample {cx.counterexample_id!r} is already held with different "
                "content; ids are permanent and are never reused"
            )
        incoming = cx.size_bytes()
        if incoming > self._max_bytes:
            raise ContractError(
                f"counterexample {cx.counterexample_id!r} is {incoming} bytes, larger than "
                f"the whole hot bound {self._max_bytes}"
            )
        while len(self._hot) + 1 > self._max_hot or self._hot_bytes + incoming > self._max_bytes:
            self._spill_oldest_spillable()
        self._hot[cx.counterexample_id] = cx
        self._hot_bytes += incoming

    def supersede(self, old_id: str, new_id: str) -> None:
        """Mark ``old_id`` as superseded by ``new_id``. The record stays exactly where it is.

        Both must be held. A successor that does not exist would break the lineage chain
        this method exists to preserve, and a record may be superseded only once so the
        chain stays single-valued.
        """
        require_identifier(old_id, "old_id")
        require_identifier(new_id, "new_id")
        if old_id == new_id:
            raise ContractError("a counterexample cannot supersede itself")
        old = self._hot.get(old_id)
        if old is None:
            raise ContractError(f"counterexample {old_id!r} is not held hot; cannot supersede")
        if new_id not in self._hot:
            raise ContractError(
                f"successor {new_id!r} is not held; superseding by a record that does not "
                "exist would break the lineage"
            )
        if old.superseded_by is not None:
            raise ContractError(
                f"counterexample {old_id!r} is already superseded by {old.superseded_by!r}"
            )
        updated = replace(old, superseded_by=new_id)
        self._hot_bytes += updated.size_bytes() - old.size_bytes()
        self._hot[old_id] = updated

    # --- regression ----------------------------------------------------------

    def replay_all(self, cell: CellLike, *, vm: CellVM) -> tuple[Counterexample, ...]:
        """The regression corpus: every non-superseded record this cell still fails.

        The corpus is deliberately **global**, not scoped to the cell's own candidate id.
        A counterexample is a fact about the world, not about the cell that happened to
        find it, so a newly synthesised cell must not reintroduce a failure a sibling
        already paid for. :meth:`for_candidate` gives the scoped view when that is what
        the caller wants.
        """
        if self._frame_builder is None:
            raise ContractError(
                "replay_all needs a frame_builder: §21 does not give a Counterexample a "
                "CellFrame, and this store will not invent one"
            )
        still_failing: list[Counterexample] = []
        for cx in self._hot.values():
            if cx.superseded_by is not None:
                continue
            observed = vm.run(cell.operator, self._frame_builder(cx))
            if _diverges(cx.expected, observed):
                still_failing.append(replace(cx, observed=observed))
        return tuple(still_failing)

    # --- internals -----------------------------------------------------------

    def _spill_oldest_spillable(self) -> None:
        """Move the oldest non-incident-linked record to cold. Never called on an incident."""
        spillable = next(
            (key for key, cx in self._hot.items() if not cx.incident_linked),
            None,
        )
        if spillable is None:
            raise ContractError(
                "the hot store is full and every record is incident-linked; an "
                "incident-linked counterexample is never dropped, so the store refuses "
                "rather than choosing which evidence to lose"
            )
        if self._cold_archive is None:
            raise ContractError(
                "the hot store is full and no cold archive is configured; spilling "
                "would delete a counterexample, which this store will not do"
            )
        cx = self._hot[spillable]
        self._write_cold(cx)
        self._hot_bytes -= cx.size_bytes()
        self._archived += 1
        # Not a deletion: the canonical record is already in the append-only archive.
        self._hot.pop(spillable)

    def _write_cold(self, cx: Counterexample) -> None:
        archive = self._cold_archive
        if archive is None:  # pragma: no cover - guarded by the caller
            raise ContractError("no cold archive configured")
        archive.parent.mkdir(parents=True, exist_ok=True)
        with archive.open("ab") as handle:
            handle.write(_canonical_line(cx.to_dict()))


def _diverges(expected: CellResult, observed: CellResult) -> bool:
    """Two results differ when any security-relevant field differs.

    ``steps_taken`` and ``reason`` are excluded: a cell that reaches the same security
    conclusion by a different route has not regressed.
    """
    return (
        bool(expected.abstained) != bool(observed.abstained)
        or expected.delta.raised != observed.delta.raised
        or float(expected.risk) != float(observed.risk)
        or tuple(ref.digest for ref in expected.evidence)
        != tuple(ref.digest for ref in observed.evidence)
    )


def replay_corpus_size(store: CounterexampleStore) -> int:
    """How many hot records are live regression material (i.e. not superseded)."""
    return sum(1 for cx in store.hot() if cx.superseded_by is None)
