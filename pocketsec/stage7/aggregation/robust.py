"""ORPH-F09 / D7.9 — the aggregator families ECHO must beat, with fixed, exact semantics.

This module exists so the comparison in spec §7 is honest. Every family reads the SAME
stance matrix built from the SAME pool, and the rules below are fixed in the spec so no
baseline can be quietly tuned down. They are the dumbest things that could work: an
identity vote, FedAvg's mean, the median, the trimmed mean, Krum / Multi-Krum / Bulyan,
"any locally-validated antibody", a root quorum, a single curated feed, and no sharing.

The matrix is deliberately indexed by IDENTITY (peer id), not by dependence cluster. That is
the point of the comparison: the identity-counting families are exactly what a Sybil
adversary with many identities attacks, and ``ROOT_QUORUM`` is the one family that is given
clusters, as the simplest Sybil-robust control.

``MEAN`` is FedAvg's aggregation rule applied to stance vectors. There are no model
parameters to average in Stage 7 (ADR-0062), so FedProx and personalised FL are not
applicable, and nothing here pretends otherwise.

What this module refuses to do: it never computes ECHO (that is ``echo/inference.py``; the
suite reads ECHO's ELIGIBLE set from the fabric), never validates locally by itself (the
caller injects ``local_ok``), and never hands anything to Stage 6. An ``AggregateResult`` is
a set of antibody keys a baseline WOULD accept, nothing more.

Cost: Krum is O(n^2 d) over the matrix. ``n`` is bounded by the ingress pool
(``MAX_POOL_CAPSULES``) because ``stance_matrix`` refuses a larger pool.
"""

from __future__ import annotations

import statistics
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage7.capsule.knowledge_capsule import KnowledgeType, Stance

if TYPE_CHECKING:
    from pocketsec.stage7.hivelock.ingress import PooledCapsule

__all__ = [
    "ACCEPT_LEVEL",
    "BYZANTINE_ASSUMED_SHARE",
    "MAX_MATRIX_IDENTITIES",
    "MIN_QUORUM",
    "TRIM_SHARE",
    "AggregateResult",
    "Aggregator",
    "StanceMatrix",
    "aggregate",
    "krum_scores",
    "plus_local_validation",
    "stance_matrix",
]

#: Share of voters dropped from EACH end by TRIMMED_MEAN (beta). Chosen, not measured.
TRIM_SHARE: float = 0.2
#: Minimum voters for MAJORITY and MEAN. Chosen, not measured.
MIN_QUORUM: int = 2
#: MEAN / TRIMMED_MEAN accept a key strictly above this level. Chosen, not measured.
ACCEPT_LEVEL: float = 0.0
#: The Byzantine share Krum/Bulyan are told to tolerate: f = max(1, floor(share * n)).
BYZANTINE_ASSUMED_SHARE: float = 0.2
#: Rows a matrix may hold: the ingress pool's cap (spec §4.23 ``MAX_POOL_CAPSULES`` = 2048).
#: Restated, not imported, so this baseline module stays importable without the ingress
#: package; ``tests/test_stage7_echo.py`` pins the two equal when ingress is present.
MAX_MATRIX_IDENTITIES: int = 2048

_STANCE_VALUE: dict[str, int] = {Stance.SUPPORT.value: 1, Stance.CONTEST.value: -1}


class Aggregator(StrEnum):
    NO_SHARING = "NO_SHARING"
    MAJORITY = "MAJORITY"
    MEAN = "MEAN"
    MEDIAN = "MEDIAN"
    TRIMMED_MEAN = "TRIMMED_MEAN"
    KRUM = "KRUM"
    MULTI_KRUM = "MULTI_KRUM"
    BULYAN = "BULYAN"
    VALIDATION_FILTER = "VALIDATION_FILTER"
    ROOT_QUORUM = "ROOT_QUORUM"
    CENTRAL_FEED = "CENTRAL_FEED"
    ECHO = "ECHO"


@dataclass(frozen=True, slots=True)
class StanceMatrix:
    """Rows are identities (NOT clusters), columns antibody keys; +1 / -1 / 0 (silent)."""

    identities: tuple[str, ...]
    keys: tuple[str, ...]
    values: tuple[tuple[int, ...], ...]
    roots: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("identities", "keys", "roots"):
            items = tuple(getattr(self, name))
            if any(not isinstance(item, str) or not item for item in items):
                raise ContractError(f"StanceMatrix.{name} must hold non-empty strings")
            object.__setattr__(self, name, items)
        if len(set(self.identities)) != len(self.identities) or len(set(self.keys)) != len(
            self.keys
        ):
            raise ContractError("StanceMatrix identities and keys must be distinct")
        if len(self.identities) > MAX_MATRIX_IDENTITIES:
            raise ContractError(f"StanceMatrix holds at most {MAX_MATRIX_IDENTITIES} identities")
        if len(self.roots) != len(self.identities):
            raise ContractError("StanceMatrix needs one declared root per identity")
        rows = tuple(tuple(row) for row in self.values)
        if len(rows) != len(self.identities) or any(len(row) != len(self.keys) for row in rows):
            raise ContractError("StanceMatrix.values must be identities x keys")
        if any(v not in (-1, 0, 1) or isinstance(v, bool) for row in rows for v in row):
            raise ContractError("StanceMatrix values are -1, 0 or +1")
        object.__setattr__(self, "values", rows)

    def column(self, key_index: int) -> tuple[int, ...]:
        return tuple(row[key_index] for row in self.values)


@dataclass(frozen=True, slots=True)
class AggregateResult:
    method: Aggregator
    accepted: tuple[str, ...]
    refused_reason: str | None
    excluded_identities: tuple[str, ...]


def stance_matrix(pool: Sequence[PooledCapsule]) -> StanceMatrix:
    """One row per contributing identity, one column per antibody key, from ANTIBODY capsules.

    An identity's latest capsule on a key (pool order) decides its stance there: a peer may
    change its mind, and its earlier word is not a second vote. Other knowledge types carry
    no stance on an antibody key and are skipped. The first declared root seen for an
    identity is its row's root.
    """
    stances: dict[str, dict[str, int]] = {}
    roots: dict[str, str] = {}
    for pooled in pool:
        capsule = pooled.capsule
        if capsule.knowledge_type != KnowledgeType.ANTIBODY:
            continue
        identity = pooled.peer_id
        roots.setdefault(identity, capsule.provenance_commitment.provenance_root)
        row = stances.setdefault(identity, {})
        row[capsule.compact_feature_signature] = _STANCE_VALUE[str(capsule.stance)]
        if len(stances) > MAX_MATRIX_IDENTITIES:
            raise ContractError(f"a stance matrix holds at most {MAX_MATRIX_IDENTITIES} identities")
    identities = tuple(sorted(stances))
    keys = tuple(sorted({key for row in stances.values() for key in row}))
    values = tuple(tuple(stances[i].get(k, 0) for k in keys) for i in identities)
    return StanceMatrix(identities, keys, values, tuple(roots[i] for i in identities))


def plus_local_validation(
    result: AggregateResult, local_ok: Callable[[str], bool]
) -> AggregateResult:
    """The "+LV" variant: the accepted set intersected with local validation (lesson 4)."""
    kept = tuple(key for key in result.accepted if local_ok(key))
    return AggregateResult(result.method, kept, result.refused_reason, result.excluded_identities)


# --- identity-vote families --------------------------------------------------------


def _voters(column: tuple[int, ...]) -> list[int]:
    return [v for v in column if v != 0]


def _trimmed_mean(values: Sequence[float], cut: int) -> float | None:
    ordered = sorted(values)
    kept = ordered[cut : len(ordered) - cut] if cut else ordered
    return statistics.fmean(kept) if kept else None


def _vote_accepts(method: Aggregator, column: tuple[int, ...], *, trim: float, quorum: int) -> bool:
    voters = _voters(column)
    if not voters:
        return False
    if method is Aggregator.MAJORITY:
        return sum(voters) > 0 and len(voters) >= quorum
    if method is Aggregator.MEAN:
        return statistics.fmean(voters) > ACCEPT_LEVEL and len(voters) >= quorum
    if method is Aggregator.MEDIAN:
        return statistics.median(voters) > 0
    level = _trimmed_mean(voters, int(trim * len(voters)))
    return level is not None and level > ACCEPT_LEVEL


# --- Krum family --------------------------------------------------------------------


def _squared(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    return sum((x - y) * (x - y) for x, y in zip(a, b, strict=True))


def krum_scores(values: Sequence[tuple[int, ...]], f: int) -> tuple[int, ...]:
    """Krum's score per row: the sum of squared distances to its n - f - 2 nearest others."""
    n = len(values)
    neighbours = n - f - 2
    if neighbours < 1:
        raise ContractError(f"Krum needs n > 2f + 2, got n={n}, f={f}")
    scores = []
    for i, row in enumerate(values):
        distances = sorted(_squared(row, other) for j, other in enumerate(values) if j != i)
        scores.append(sum(distances[:neighbours]))
    return tuple(scores)


def _best(scores: Sequence[int], count: int) -> list[int]:
    # Ties break on row order, i.e. identity order: deterministic and documented.
    return sorted(range(len(scores)), key=lambda i: (scores[i], i))[:count]


def _krum_family(
    matrix: StanceMatrix, method: Aggregator, *, byzantine_share: float
) -> AggregateResult:
    n = len(matrix.identities)
    f = max(1, int(byzantine_share * n))
    if n <= 2 * f + 2:
        return AggregateResult(method, (), f"krum_needs_n_gt_2f_plus_2:n={n},f={f}", ())
    if method is Aggregator.BULYAN and n < 4 * f + 3:
        return AggregateResult(method, (), f"bulyan_needs_n_ge_4f_plus_3:n={n},f={f}", ())
    scores = krum_scores(matrix.values, f)
    size = {Aggregator.KRUM: 1, Aggregator.MULTI_KRUM: n - f, Aggregator.BULYAN: n - 2 * f}[method]
    chosen = _best(scores, size)
    selected = [matrix.values[i] for i in chosen]
    accepted = []
    for k, key in enumerate(matrix.keys):
        column = [row[k] for row in selected]
        if method is Aggregator.BULYAN:
            level = _trimmed_mean(column, f)  # drop f from each end of the n - 2f selected
        else:
            level = statistics.fmean(column)
        if level is not None and level > 0:
            accepted.append(key)
    kept = set(chosen)
    excluded = tuple(matrix.identities[i] for i in range(n) if i not in kept)
    return AggregateResult(method, tuple(accepted), None, excluded)


# --- validation-anchored families ---------------------------------------------------


def _require(value: object, name: str, method: Aggregator) -> None:
    if value is None:
        raise ContractError(f"{method.value} needs {name}")


def _clusters_of(matrix: StanceMatrix, clusters: Mapping[str, str] | None) -> tuple[str, ...]:
    if clusters is None:
        return matrix.roots  # the declared-root control: roots trusted as independence
    missing = [i for i in matrix.identities if i not in clusters]
    if missing:
        raise ContractError(f"ROOT_QUORUM has no cluster for identity {missing[0]!r}")
    return tuple(clusters[i] for i in matrix.identities)


def _root_quorum(
    matrix: StanceMatrix, clusters: Mapping[str, str] | None, local_ok: Callable[[str], bool]
) -> tuple[str, ...]:
    groups = _clusters_of(matrix, clusters)
    accepted = []
    for k, key in enumerate(matrix.keys):
        column = matrix.column(k)
        supporting = {groups[i] for i, v in enumerate(column) if v > 0}
        contesting = {groups[i] for i, v in enumerate(column) if v < 0}
        if len(supporting) >= 2 and len(supporting) > len(contesting) and local_ok(key):
            accepted.append(key)
    return tuple(accepted)


def _feed(matrix: StanceMatrix, feed_root: str, local_ok: Callable[[str], bool]) -> tuple[str, ...]:
    accepted = []
    for k, key in enumerate(matrix.keys):
        column = matrix.column(k)
        if any(v > 0 and matrix.roots[i] == feed_root for i, v in enumerate(column)) and local_ok(
            key
        ):
            accepted.append(key)
    return tuple(accepted)


def _check_knobs(byzantine_share: float, trim: float, quorum: int) -> None:
    if not 0.0 <= byzantine_share < 0.5:
        raise ContractError(f"byzantine_share must be in [0, 0.5), got {byzantine_share!r}")
    if not 0.0 <= trim < 0.5:
        raise ContractError(f"trim must be in [0, 0.5), got {trim!r}")
    if isinstance(quorum, bool) or not isinstance(quorum, int) or quorum < 1:
        raise ContractError(f"quorum must be a positive int, got {quorum!r}")


def aggregate(
    matrix: StanceMatrix,
    method: Aggregator,
    *,
    clusters: Mapping[str, str] | None = None,
    local_ok: Callable[[str], bool] | None = None,
    feed_root: str | None = None,
    byzantine_share: float = BYZANTINE_ASSUMED_SHARE,
    trim: float = TRIM_SHARE,
    quorum: int = MIN_QUORUM,
) -> AggregateResult:
    """Apply one family with the spec's exact semantics (D7.9). ECHO is refused here."""
    if not isinstance(matrix, StanceMatrix):
        raise ContractError("aggregate needs a StanceMatrix")
    method = Aggregator(method)
    _check_knobs(byzantine_share, trim, quorum)
    if method is Aggregator.ECHO:
        raise ContractError("ECHO is computed by echo/inference.py, not by a baseline family")
    if method is Aggregator.NO_SHARING:
        return AggregateResult(method, (), None, ())
    if method in (Aggregator.KRUM, Aggregator.MULTI_KRUM, Aggregator.BULYAN):
        return _krum_family(matrix, method, byzantine_share=byzantine_share)
    if method in (Aggregator.MAJORITY, Aggregator.MEAN, Aggregator.MEDIAN, Aggregator.TRIMMED_MEAN):
        accepted = tuple(
            key
            for k, key in enumerate(matrix.keys)
            if _vote_accepts(method, matrix.column(k), trim=trim, quorum=quorum)
        )
        return AggregateResult(method, accepted, None, ())
    _require(local_ok, "local_ok", method)
    assert local_ok is not None  # narrowed for the type checker; _require raised otherwise
    if method is Aggregator.VALIDATION_FILTER:
        accepted = tuple(
            key for k, key in enumerate(matrix.keys) if 1 in matrix.column(k) and local_ok(key)
        )
        return AggregateResult(method, accepted, None, ())
    if method is Aggregator.ROOT_QUORUM:
        return AggregateResult(method, _root_quorum(matrix, clusters, local_ok), None, ())
    _require(feed_root, "feed_root", method)
    assert feed_root is not None
    return AggregateResult(method, _feed(matrix, feed_root, local_ok), None, ())
