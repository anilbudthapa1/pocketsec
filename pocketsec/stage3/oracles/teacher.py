"""D3.8 Oracle A — the teacher as a frozen, signed artifact. Never a live forward pass.

Integration plan §2.5 is the rule this module implements: "Teacher consultation happens
offline … and its result is a signed artifact." The runtime therefore holds a
``Mapping[frame_digest, score]`` and nothing else. It never imports a research class, it
never loads weights, and it cannot be made to by configuration — there is no code path
here that evaluates a model.

**Sources.** ``TEACHER_SOURCES`` has two members. This wave produces only
``"phi-oracle"``, built from Stage 2's zero-parameter
:class:`DeterministicScorerSpec` at the pinned feature index
:data:`PHI_SQUASHED_FEATURE_INDEX` (73). The ``"tcn"`` source is **loadable but
UNMEASURED**: no TCN snapshot exists in this repository, because Stage 3 ships no
``research/`` package and no numpy (spec §2.3). Its absence is a recorded decision, not
a zero — :meth:`TeacherOracle.consult` returns ``None`` for a frame it has no response
for, and ``None`` means UNKNOWN all the way through the dual oracle. Nobody reading a
later result may treat the missing TCN teacher as agreement.

What this module refuses to do: it refuses to guess. There is no default score, no
fallback to ``0.0``, and no interpolation between neighbouring digests. A snapshot whose
content digest does not match its bytes does not load at all.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    digest_of_bytes,
    register_schema,
    require_identifier,
)
from pocketsec.stage0.experiments.ids import parse_experiment_id
from pocketsec.stage2.compile_candidates.phi_oracle_candidate import (
    PHI_SQUASHED_FEATURE_INDEX,
    DeterministicScorerSpec,
)

# Imported, never redefined. ``frame_digest`` is the snapshot join key, and a
# snapshot written with one implementation and read with another joins on
# nothing: every ``TeacherOracle.consult`` would miss, the dual oracle would
# report TEACHER_UNAVAILABLE, and G3.5 would become silently unmeasurable
# instead of failing. The canonical definition sits beside the fields it
# digests, in ``cells/frame.py``, so the two cannot drift apart. Re-exported
# here because spec §4 D3.8 names this module as the import path.
from pocketsec.stage3.cells.frame import frame_digest

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pocketsec.stage3.bytecode.vm import CellFrame

__all__ = [
    "PHI_SQUASHED_SCALE",
    "TEACHER_SNAPSHOT_V1_ID",
    "TEACHER_SNAPSHOT_V1_VERSION",
    "TEACHER_SOURCES",
    "TeacherOracle",
    "TeacherSnapshotV1",
    "build_phi_oracle_snapshot",
    "frame_digest",
    "load_snapshot",
    "phi_oracle_score",
    "write_snapshot",
]

TEACHER_SNAPSHOT_V1_ID = "pocketsec.teacher_snapshot.v1"
TEACHER_SNAPSHOT_V1_VERSION = register_schema(TEACHER_SNAPSHOT_V1_ID, "1.0.0")

#: Closed set. Adding a member is adding a teacher, which needs a producer and an
#: experiment id, so it is a deliberate edit rather than a string that happens to parse.
TEACHER_SOURCES = frozenset({"phi-oracle", "tcn"})

#: ``ssir_encoder.py:72`` — the squash constant behind feature 73. Reproducing the
#: recorded 0.7484 PR-AUC requires *this* definition; an unsquashed ΔΦ is a different
#: scorer (``phi_oracle_candidate.py`` docstring).
PHI_SQUASHED_SCALE = 8.0

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_MEASURED_BY_RE = re.compile(r"^[A-Za-z_][\w.]*:[A-Za-z_]\w*$")


def _canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    """Canonical JSON: sorted keys, no NaN, trailing newline. The digest is over this."""
    return (
        json.dumps(payload, sort_keys=True, allow_nan=False, indent=2).encode("utf-8") + b"\n"
    )


def phi_oracle_score(delta_phi: float) -> float:
    """The Φ-oracle's score for one event: ``|ΔΦ| / (|ΔΦ| + 8.0)``.

    Magnitude, not direction. ``PHI_SIGN_FEATURE_INDEX`` exists in the encoder and is
    deliberately not read: a large fall in Φ is as worth looking at as a large rise, and
    folding sign in would make the scorer assert something about intent that the
    representation does not carry.
    """
    magnitude = abs(float(delta_phi))
    if magnitude == 0.0:
        return 0.0
    return magnitude / (magnitude + PHI_SQUASHED_SCALE)


@dataclass(frozen=True, slots=True)
class TeacherSnapshotV1:
    """A pinned-seed, offline-produced map from frame digest to teacher score.

    The snapshot is the whole of Oracle A. It carries its own provenance — encoder
    version, corpus version, seed, producing function and experiment id — so a
    divergence measured against it can be re-derived, and so a snapshot from a different
    split cannot be mistaken for this one.
    """

    teacher_id: str
    source: str
    encoder_version: str
    corpus_version: str
    seed: int
    responses: Mapping[str, float]
    measured_by: str
    experiment_id: str
    digest: str

    def __post_init__(self) -> None:
        require_identifier(self.teacher_id, "TeacherSnapshotV1.teacher_id")
        if self.source not in TEACHER_SOURCES:
            raise ContractError(
                f"TeacherSnapshotV1.source must be one of {sorted(TEACHER_SOURCES)}, "
                f"got {self.source!r}"
            )
        for field in ("encoder_version", "corpus_version"):
            value = getattr(self, field)
            if not isinstance(value, str) or not value.strip():
                raise ContractError(f"TeacherSnapshotV1.{field} must be a non-empty string")
        if not isinstance(self.seed, int) or isinstance(self.seed, bool) or self.seed < 0:
            raise ContractError(
                f"TeacherSnapshotV1.seed must be a non-negative int, got {self.seed!r}"
            )
        if not _MEASURED_BY_RE.fullmatch(self.measured_by):
            raise ContractError(
                "TeacherSnapshotV1.measured_by must look like 'module:function', got "
                f"{self.measured_by!r}"
            )
        parse_experiment_id(self.experiment_id)
        object.__setattr__(self, "responses", _frozen_responses(self.responses))
        if not _DIGEST_RE.fullmatch(self.digest):
            raise ContractError(
                f"TeacherSnapshotV1.digest must look like 'sha256:<64 hex>', got "
                f"{self.digest!r}"
            )
        expected = digest_of_bytes(_canonical_bytes(self._body()))
        if expected != self.digest:
            raise ContractError(
                f"TeacherSnapshotV1 digest mismatch: declared {self.digest}, content "
                f"hashes to {expected}. A snapshot whose bytes changed is not the "
                "artifact the measurement was taken against."
            )

    def _body(self) -> dict[str, Any]:
        """Everything the digest covers — i.e. the record minus the digest itself."""
        return _body_dict(
            teacher_id=self.teacher_id,
            source=self.source,
            encoder_version=self.encoder_version,
            corpus_version=self.corpus_version,
            seed=self.seed,
            responses=self.responses,
            measured_by=self.measured_by,
            experiment_id=self.experiment_id,
        )

    def to_dict(self) -> dict[str, Any]:
        payload = self._body()
        payload["digest"] = self.digest
        return payload

    @classmethod
    def create(
        cls,
        *,
        teacher_id: str,
        source: str,
        encoder_version: str,
        corpus_version: str,
        seed: int,
        responses: Mapping[str, float],
        measured_by: str,
        experiment_id: str,
    ) -> TeacherSnapshotV1:
        """Build a snapshot and compute its content digest.

        The digest is never supplied by a caller on the producing path: a producer that
        could choose its own digest could ship a snapshot that does not hash to its own
        contents, which is exactly what :meth:`__post_init__` refuses.
        """
        body = _body_dict(
            teacher_id=teacher_id,
            source=source,
            encoder_version=encoder_version,
            corpus_version=corpus_version,
            seed=seed,
            responses=_frozen_responses(responses),
            measured_by=measured_by,
            experiment_id=experiment_id,
        )
        return cls(
            teacher_id=teacher_id,
            source=source,
            encoder_version=encoder_version,
            corpus_version=corpus_version,
            seed=seed,
            responses=responses,
            measured_by=measured_by,
            experiment_id=experiment_id,
            digest=digest_of_bytes(_canonical_bytes(body)),
        )

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> TeacherSnapshotV1:
        declared = str(payload.get("schema", ""))
        if declared != TEACHER_SNAPSHOT_V1_ID:
            raise ContractError(f"expected schema {TEACHER_SNAPSHOT_V1_ID}, got {declared!r}")
        responses = payload.get("responses")
        if not isinstance(responses, Mapping):
            raise ContractError("TeacherSnapshotV1.responses must be a mapping")
        try:
            return cls(
                teacher_id=str(payload["teacher_id"]),
                source=str(payload["source"]),
                encoder_version=str(payload["encoder_version"]),
                corpus_version=str(payload["corpus_version"]),
                seed=int(payload["seed"]),
                responses={str(k): float(v) for k, v in responses.items()},
                measured_by=str(payload["measured_by"]),
                experiment_id=str(payload["experiment_id"]),
                digest=str(payload["digest"]),
            )
        except KeyError as exc:
            raise ContractError(f"TeacherSnapshotV1 missing field {exc.args[0]!r}") from exc
        except (OverflowError, TypeError, ValueError) as exc:
            # ``parse_experiment_id`` raises ValueError on a malformed id and
            # ``float()`` raises ValueError or OverflowError on a malformed
            # response, so only KeyError being caught let a loaded snapshot fail
            # with an exception type no caller guards on.
            raise ContractError(f"TeacherSnapshotV1 could not be rebuilt: {exc}") from exc


def _body_dict(
    *,
    teacher_id: str,
    source: str,
    encoder_version: str,
    corpus_version: str,
    seed: int,
    responses: Mapping[str, float],
    measured_by: str,
    experiment_id: str,
) -> dict[str, Any]:
    """The digest-covered body. Scores are serialised via ``repr`` so the digest is exact.

    ``json.dumps`` round-trips a float, but through the shortest repr that survives; a
    score written as a string removes any doubt that two runs on two builds hash the
    same bytes for the same number.
    """
    return {
        "schema": TEACHER_SNAPSHOT_V1_ID,
        "schema_version": TEACHER_SNAPSHOT_V1_VERSION,
        "teacher_id": teacher_id,
        "source": source,
        "encoder_version": encoder_version,
        "corpus_version": corpus_version,
        "seed": seed,
        "responses": {key: repr(float(value)) for key, value in sorted(responses.items())},
        "measured_by": measured_by,
        "experiment_id": experiment_id,
    }


def _frozen_responses(responses: Mapping[str, float]) -> Mapping[str, float]:
    if not isinstance(responses, Mapping):
        raise ContractError("TeacherSnapshotV1.responses must be a mapping")
    snapshot: dict[str, float] = {}
    for key, value in responses.items():
        if not isinstance(key, str) or not _DIGEST_RE.fullmatch(key):
            raise ContractError(
                f"teacher response keys must be frame digests 'sha256:<64 hex>', got {key!r}"
            )
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ContractError(f"teacher response for {key} must be a number, got {value!r}")
        numeric = float(value)
        if numeric != numeric or numeric in (float("inf"), float("-inf")):
            raise ContractError(f"teacher response for {key} must be finite, got {value!r}")
        snapshot[key] = numeric
    return MappingProxyType(snapshot)


def write_snapshot(snapshot: TeacherSnapshotV1, path: Path) -> str:
    """Write the snapshot as canonical JSON; return the ``sha256:`` digest of the file.

    Two digests exist and they are not the same thing. ``snapshot.digest`` covers the
    *content* and travels with the record; the value returned here covers the *bytes on
    disk* and is what a gate pins so a re-run can prove it read the same file.
    """
    payload = _canonical_bytes(snapshot.to_dict())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return digest_of_bytes(payload)


def load_snapshot(path: Path) -> TeacherSnapshotV1:
    """Load a snapshot, refusing any file whose declared digest is not its content digest."""
    try:
        payload = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, ValueError) as exc:
        raise ContractError(f"cannot read teacher snapshot at {path}: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise ContractError(f"teacher snapshot at {path} is not a JSON object")
    return TeacherSnapshotV1.from_dict(payload)


def build_phi_oracle_snapshot(
    frames: Sequence[CellFrame],
    *,
    scorer: DeterministicScorerSpec,
    teacher_id: str,
    corpus_version: str,
    seed: int,
    experiment_id: str,
) -> TeacherSnapshotV1:
    """Produce the ``"phi-oracle"`` snapshot: Oracle A for this wave, as data.

    One ``CellFrame`` is one event, so every window aggregation in
    :data:`AGGREGATIONS` collapses to the value itself; the aggregation is still
    recorded in the scorer so a later windowed producer cannot be confused with this one.

    The scorer's feature index is checked against the pinned Φ slot rather than trusted.
    A scorer pointing anywhere else is not the Φ-oracle, and a snapshot built from it
    would reproduce a different number under the same name.
    """
    if scorer.feature_index != PHI_SQUASHED_FEATURE_INDEX:
        raise ContractError(
            f"the Φ-oracle teacher must read feature {PHI_SQUASHED_FEATURE_INDEX}; "
            f"scorer {scorer.scorer_id!r} reads {scorer.feature_index}"
        )
    if not frames:
        raise ContractError(
            "a teacher snapshot over zero frames is not an empty teacher, it is no "
            "teacher; build it from the corpus the cell will be judged on"
        )
    encoder_versions = {str(frame.encoder_version) for frame in frames}
    if len(encoder_versions) != 1:
        raise ContractError(
            f"frames span encoder versions {sorted(encoder_versions)}; a snapshot keyed "
            "on frame digests from two encoders cannot be re-derived"
        )
    responses = {frame_digest(frame): phi_oracle_score(frame.delta_phi) for frame in frames}
    return TeacherSnapshotV1.create(
        teacher_id=teacher_id,
        source="phi-oracle",
        encoder_version=encoder_versions.pop(),
        corpus_version=corpus_version,
        seed=seed,
        responses=responses,
        measured_by="pocketsec.stage3.oracles.teacher:build_phi_oracle_snapshot",
        experiment_id=experiment_id,
    )


class TeacherOracle:
    """Oracle A at runtime: a lookup, and an honest ``None`` when there is no entry.

    ``consult`` returning ``None`` means UNKNOWN — the snapshot has no opinion about
    this frame. It does **not** mean zero, and the dual oracle must not treat it as
    agreement. That distinction is the reason this class exists at all rather than a
    bare dict.
    """

    __slots__ = ("_snapshot",)

    def __init__(self, snapshot: TeacherSnapshotV1 | None) -> None:
        if snapshot is not None and not isinstance(snapshot, TeacherSnapshotV1):
            raise ContractError(
                f"TeacherOracle takes a TeacherSnapshotV1 or None, got {type(snapshot).__name__}"
            )
        self._snapshot = snapshot

    @property
    def available(self) -> bool:
        return self._snapshot is not None

    @property
    def snapshot(self) -> TeacherSnapshotV1 | None:
        return self._snapshot

    @property
    def source(self) -> str | None:
        return None if self._snapshot is None else self._snapshot.source

    def consult(self, frame: CellFrame) -> float | None:
        """The teacher's recorded score for this frame, or ``None`` for UNKNOWN."""
        if self._snapshot is None:
            return None
        return self._snapshot.responses.get(frame_digest(frame))
