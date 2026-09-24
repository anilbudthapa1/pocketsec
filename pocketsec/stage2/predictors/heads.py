"""D2.5 runtime — the eight predictive heads (DTL-F06) as stdlib inference.

Spec section 8 defines eight heads H1…H8. This module is their **runtime** half:
an inference surface over a frozen representation, loaded as plain data.

Three measured facts shape every decision here.

* **The heads are detached, permanently.** Training them jointly with detection
  scored 0.3333 PR-AUC against 1.0000 detached, and re-weighting did not fix it
  (``w_detect=8.0`` still 0.3333, ADR-0009). So this module has no training
  loop, no gradient, and no shared parameter with any detector. It reads
  ``HeadWeights`` that some *other*, offline run produced, and a head that
  cannot name the run that produced it is rejected by ``__post_init__``.
* **The runtime never holds a research class reference** (ADR-0008). Weights
  arrive as JSON from ``models/experimental/``; nothing here imports numpy or
  anything under ``research/``.
* **Max-over-time is the only pooling this project measured as justified**
  (+0.046 PR-AUC; multiscale dilations +0.068 are the core's business, not the
  heads'). So pooling here is element-wise max over the window, and nothing
  else. Mean pooling is not offered because nothing measured it.

What this module refuses to do: produce a detection score. The heads describe
what is likely to happen next; ``residual.py`` measures how wrong they were; and
per ADR-0009 neither number is allowed to reach a verdict. Vocabulary sizes are
read from Stage 1's enums and from the frozen encoder layout, never written down
here, because a literal ``24`` silently becomes wrong the day a relation is added.
"""

from __future__ import annotations

import json
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Mapping, Sequence

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.experiments.ids import parse_experiment_id
from pocketsec.stage1.ssir.relations import Relation, RelationFamily
from pocketsec.stage1.ssir.transition import TemporalContext
from pocketsec.stage1.state.security_state import DIMENSIONS, StateDelta
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_LAYOUT, FEATURE_WIDTH

if TYPE_CHECKING:  # pragma: no cover - typing only
    # `state/window.py` is owned by the `routing` package and built in parallel.
    # Only `.features()` is consumed, so the dependency is structural: the real
    # window plugs in with no runtime import and no import cycle.
    from pocketsec.stage2.state.window import LineageWindow

__all__ = [
    "EPOCH_CLASSES",
    "HEAD_CLASSES",
    "HEAD_IDS",
    "OBJECT_PROPERTY_CLASSES",
    "PHI_BUCKET_EDGES",
    "PHI_CLASSES",
    "TIME_BUCKETS",
    "UNCERTAINTY_CLASSES",
    "UNCERTAINTY_LABELS",
    "HeadPrediction",
    "HeadWeights",
    "PredictiveHeads",
    "phi_bucket",
    "pool_window",
    "softmax",
]

#: H1…H8 of spec section 8, in that order. `object` is H2 (likely target class),
#: `causal` is H5 (likely responsible predecessor family), `epoch` is H6,
#: `phi` is H7 (expected ΔΦ), `uncertainty` is H8.
HEAD_IDS: tuple[str, ...] = (
    "relation",
    "object",
    "state_delta",
    "time",
    "causal",
    "epoch",
    "phi",
    "uncertainty",
)

_LAYOUT: dict[str, int] = dict(FEATURE_LAYOUT)

#: H2's vocabulary is the *encoder's* object-property vocabulary, so its width
#: comes from the frozen feature layout rather than from ``SemanticProperty``:
#: the encoder exposes a deliberate subset, and ``object_property_mask`` bit
#: indices are positions in that subset.
OBJECT_PROPERTY_CLASSES: int = _LAYOUT["object_semantics"]

#: 16 log-spaced buckets, derived by asking Stage 1's own bucketer for its
#: ceiling instead of restating it.
TIME_BUCKETS: int = TemporalContext.bucket(1 << 62) + 1

#: H6 is binary: does this behaviour fit the current regime or not. Epochs are
#: opened by corroborated system change (Stage 1), never by this head.
EPOCH_CLASSES: int = 2

#: H7 discretises ΔΦ. Signed, asymmetric edges: a fall in security potential is
#: reported coarsely because nothing in this project acts on it, while the rises
#: that matter get finer resolution. These edges are a *reporting granularity*,
#: declared here and not fitted to anything.
PHI_BUCKET_EDGES: tuple[float, ...] = (-2.0, -0.5, 0.0, 0.5, 1.0, 2.0, 4.0)
PHI_CLASSES: int = len(PHI_BUCKET_EDGES) + 1

#: H8 keeps UNKNOWN as its own class. Collapsing it into "uncertain" would make
#: the unknownness signal unrecoverable, and UNKNOWN is a valid output.
UNCERTAINTY_LABELS: tuple[str, ...] = ("CONFIDENT", "UNCERTAIN", "UNKNOWN")
UNCERTAINTY_CLASSES: int = len(UNCERTAINTY_LABELS)

#: Head id -> class count. Every entry is derived, so a weights file trained
#: against a stale vocabulary is a contract error rather than a silent misread.
HEAD_CLASSES: Mapping[str, int] = MappingProxyType(
    {
        "relation": len(Relation),
        "object": OBJECT_PROPERTY_CLASSES,
        "state_delta": len(DIMENSIONS),
        "time": TIME_BUCKETS,
        "causal": len(RelationFamily),
        "epoch": EPOCH_CLASSES,
        "phi": PHI_CLASSES,
        "uncertainty": UNCERTAINTY_CLASSES,
    }
)

assert set(HEAD_CLASSES) == set(HEAD_IDS), "every head needs a derived vocabulary"
assert HEAD_CLASSES["state_delta"] == _LAYOUT["state_delta_raised"], (
    "the state-delta head and the encoder must agree on the dimension count"
)

#: Measured, not assumed: what one float actually costs in this interpreter.
_FLOAT_BYTES: int = sys.getsizeof(0.0)

#: Above this sigmoid probability a state-delta bit is reported as predicted.
#: 0.5 is the only threshold that needs no justification; anything else would
#: need a calibration run, and calibration is D2.9's job.
_DELTA_THRESHOLD: float = 0.5


def phi_bucket(delta_phi: float) -> int:
    """Bucket a signed ΔΦ into H7's class index."""
    for index, edge in enumerate(PHI_BUCKET_EDGES):
        if delta_phi < edge:
            return index
    return PHI_CLASSES - 1


def softmax(logits: Sequence[float]) -> tuple[float, ...]:
    """Numerically stable softmax over a non-empty logit vector.

    Stability is not cosmetic: a head fed a saturated feature vector produces
    logits large enough that a naive ``exp`` overflows to ``inf`` and the whole
    distribution becomes ``nan`` — which would then be reported as a confident
    prediction rather than as a failure.
    """
    if not logits:
        raise ContractError("softmax needs at least one logit")
    finite = [x for x in logits if not math.isnan(x)]
    if len(finite) != len(logits):
        raise ContractError("softmax refuses NaN logits")
    peak = max(logits)
    if peak == math.inf:
        # Infinite logits are a degenerate one-hot; splitting the mass evenly
        # between the infinities is the only answer that stays a distribution.
        winners = [1.0 if x == math.inf else 0.0 for x in logits]
        total = sum(winners)
        return tuple(w / total for w in winners)
    exps = [math.exp(x - peak) for x in logits]
    total = sum(exps)
    if total <= 0.0:  # pragma: no cover - peak - peak == 0 guarantees exp == 1
        raise ContractError("softmax produced a zero partition function")
    return tuple(value / total for value in exps)


def _sigmoid(logit: float) -> float:
    """Logistic, clamped so a saturated logit returns 0.0/1.0 instead of raising.

    ``math.exp(710)`` overflows; a state-delta bit whose head is merely very
    confident must not become an exception at the top of the runtime path.

    A non-finite logit is refused rather than clamped, because the clamp swallows
    it in the worst possible direction: ``min(700.0, nan)`` returns 700.0 in
    CPython (two-argument ``min`` returns ``b if b < a else a``, and every
    comparison with NaN is False), so ``_sigmoid(nan)`` was **1.0** — maximum
    confidence — and ``predict_security_state_delta`` then asserted that the
    corresponding security dimension was about to be raised, on every event,
    with no exception anywhere to reveal it (S2-AUTH-03). ``softmax`` one method
    above already refuses NaN logits for exactly this reason; this now agrees
    with it.
    """
    if not math.isfinite(logit):
        raise ContractError(
            f"_sigmoid refuses a non-finite logit ({logit!r}); clamping it would "
            "report an undefined prediction as a confident one"
        )
    return 1.0 / (1.0 + math.exp(-max(-700.0, min(700.0, logit))))


def _entropy(probabilities: Sequence[float]) -> float:
    return -sum(p * math.log(p) for p in probabilities if p > 0.0)


def pool_window(rows: Sequence[Sequence[float]]) -> tuple[float, ...]:
    """Element-wise max over time — the one pooling operation with an ablation.

    Max-over-time measured +0.046 PR-AUC on the ambiguous corpus and is the only
    pooling this repository has evidence for. A short escalating chain inside a
    long benign session is exactly what a max survives and a mean dilutes.
    """
    if not rows:
        raise ContractError("cannot pool an empty window")
    width = len(rows[0])
    pooled = [-math.inf] * width
    for row in rows:
        if len(row) != width:
            raise ContractError(
                f"ragged window: row width {len(row)} != {width}"
            )
        for index, value in enumerate(row):
            if value > pooled[index]:
                pooled[index] = value
    return tuple(pooled)


@dataclass(frozen=True, slots=True)
class HeadWeights:
    """One head's parameters as plain data loaded from ``models/experimental/``.

    ``trained_experiment_id`` is required and non-empty. A head with no recorded
    training run cannot be audited, cannot be reproduced, and is therefore
    rejectable by construction — the same rule the compile-candidate exporter
    applies downstream.
    """

    head_id: str
    input_width: int
    classes: int
    #: Row-major, shape (classes, input_width): logits = W·x + b.
    weights: tuple[tuple[float, ...], ...]
    bias: tuple[float, ...]
    trained_experiment_id: str

    def __post_init__(self) -> None:
        if self.head_id not in HEAD_CLASSES:
            raise ContractError(
                f"unknown head id {self.head_id!r}; known: {sorted(HEAD_CLASSES)}"
            )
        self._refuse_non_finite()
        expected = HEAD_CLASSES[self.head_id]
        if self.classes != expected:
            raise ContractError(
                f"head {self.head_id!r} declares {self.classes} classes but the "
                f"Stage 1 vocabulary has {expected}"
            )
        if self.input_width != FEATURE_WIDTH:
            raise ContractError(
                f"head {self.head_id!r} input_width {self.input_width} != "
                f"encoder FEATURE_WIDTH {FEATURE_WIDTH}"
            )
        if len(self.weights) != self.classes:
            raise ContractError(
                f"head {self.head_id!r} has {len(self.weights)} weight rows for "
                f"{self.classes} classes"
            )
        for index, row in enumerate(self.weights):
            if len(row) != self.input_width:
                raise ContractError(
                    f"head {self.head_id!r} row {index} has width {len(row)}, "
                    f"expected {self.input_width}"
                )
        if len(self.bias) != self.classes:
            raise ContractError(
                f"head {self.head_id!r} has {len(self.bias)} biases for "
                f"{self.classes} classes"
            )
        if not self.trained_experiment_id.strip():
            raise ContractError(
                f"head {self.head_id!r} has no trained_experiment_id; a head "
                "with no recorded training run is not loadable"
            )
        # A non-empty string is not a recorded training run. The class docstring
        # claims the head is "rejectable by construction" if it cannot be
        # audited, and an id that does not parse cannot be looked up in
        # `experiments/registry.jsonl` at all, so it identifies nothing
        # (S2-AUTH-03). Parseability is checked here because it is a property of
        # the string; registry membership is checked where the append-only
        # ledger exists, which is not on the endpoint.
        try:
            parse_experiment_id(self.trained_experiment_id)
        except (ValueError, ContractError) as exc:
            raise ContractError(
                f"head {self.head_id!r} trained_experiment_id "
                f"{self.trained_experiment_id!r} does not parse as an experiment "
                f"id ({exc}); an id that identifies no registered run is not "
                "provenance"
            ) from exc

    def _refuse_non_finite(self) -> None:
        """Reject NaN/Infinity weights and biases at the load boundary.

        ``models/experimental/`` is a gitignored artefact store and ``from_json``
        reads it with a bare ``json.loads``, which accepts the non-standard bare
        ``NaN`` and ``Infinity`` literals. A head trained to divergence, a
        truncated download or a locally edited file therefore loaded cleanly, and
        one non-finite weight row made ``predict_security_state_delta`` report
        that dimension as rising on every event (S2-AUTH-03). The write side
        already uses ``allow_nan=False`` everywhere, so the read side refuses
        exactly what the write side would never emit.
        """
        for index, row in enumerate(self.weights):
            for column, value in enumerate(row):
                if not math.isfinite(value):
                    raise ContractError(
                        f"head {self.head_id!r} weight [{index}][{column}] is "
                        f"{value!r}; a non-finite parameter cannot produce a "
                        "prediction, only a confident-looking one"
                    )
        for index, value in enumerate(self.bias):
            if not math.isfinite(value):
                raise ContractError(
                    f"head {self.head_id!r} bias [{index}] is {value!r}; a "
                    "non-finite parameter cannot produce a prediction, only a "
                    "confident-looking one"
                )

    def logits(self, pooled: Sequence[float]) -> tuple[float, ...]:
        if len(pooled) != self.input_width:
            raise ContractError(
                f"head {self.head_id!r} expects {self.input_width} features, "
                f"got {len(pooled)}"
            )
        return tuple(
            sum(w * x for w, x in zip(row, pooled, strict=True)) + b
            for row, b in zip(self.weights, self.bias, strict=True)
        )

    def parameters(self) -> int:
        return self.classes * self.input_width + self.classes

    def memory_bytes(self) -> int:
        """Measured with ``sys.getsizeof``, not estimated from a formula."""
        total = sys.getsizeof(self.weights) + sys.getsizeof(self.bias)
        total += _FLOAT_BYTES * len(self.bias)
        for row in self.weights:
            total += sys.getsizeof(row) + _FLOAT_BYTES * len(row)
        return total

    def to_dict(self) -> dict[str, Any]:
        return {
            "head_id": self.head_id,
            "input_width": self.input_width,
            "classes": self.classes,
            "weights": [list(row) for row in self.weights],
            "bias": list(self.bias),
            "trained_experiment_id": self.trained_experiment_id,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> HeadWeights:
        try:
            return cls(
                head_id=str(payload["head_id"]),
                input_width=int(payload["input_width"]),
                classes=int(payload["classes"]),
                weights=tuple(
                    tuple(float(v) for v in row) for row in payload["weights"]
                ),
                bias=tuple(float(v) for v in payload["bias"]),
                trained_experiment_id=str(payload["trained_experiment_id"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ContractError(f"malformed head weights payload: {exc}") from exc


@dataclass(frozen=True, slots=True)
class HeadPrediction:
    """One head's output. ``entropy`` is in nats."""

    head_id: str
    probabilities: tuple[float, ...]
    argmax: int
    entropy: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "head_id": self.head_id,
            "argmax": self.argmax,
            "entropy": round(self.entropy, 6),
            "probabilities": [round(p, 6) for p in self.probabilities],
        }


class PredictiveHeads:
    """Inference over a frozen representation. No training, ever.

    A partial head set is legal: heads are optional mechanisms (DTL-F09 is
    ``OPTIONAL`` in ``core_ids``), and a deployment that only carries the
    required state-delta head must still load.
    """

    __slots__ = ("_weights",)

    def __init__(self, weights: Mapping[str, HeadWeights]) -> None:
        if not weights:
            raise ContractError("PredictiveHeads needs at least one head")
        for head_id, head in weights.items():
            if head_id != head.head_id:
                raise ContractError(
                    f"head registered as {head_id!r} declares {head.head_id!r}"
                )
        self._weights: Mapping[str, HeadWeights] = MappingProxyType(dict(weights))

    @property
    def head_ids(self) -> tuple[str, ...]:
        """Present heads, in spec section 8 order."""
        return tuple(head_id for head_id in HEAD_IDS if head_id in self._weights)

    @classmethod
    def from_json(cls, path: Path) -> PredictiveHeads:
        """Load from ``models/experimental/*.json``.

        Plain data in, plain data out: the runtime never unpickles and never
        holds a reference to the research class that produced the numbers.
        """
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ContractError(f"cannot read head weights from {path}: {exc}") from exc
        if not isinstance(payload, dict):
            raise ContractError("head weights file must hold a JSON object")
        heads = payload.get("heads", payload)
        if not isinstance(heads, dict):
            raise ContractError("'heads' must map head id -> weights object")
        return cls(
            {
                str(head_id): HeadWeights.from_dict(entry)
                for head_id, entry in heads.items()
            }
        )

    def _pooled(self, window: LineageWindow) -> tuple[float, ...]:
        return pool_window(window.features())

    def predict(self, window: LineageWindow) -> dict[str, HeadPrediction]:
        """Every loaded head's distribution over the *next* transition."""
        pooled = self._pooled(window)
        predictions: dict[str, HeadPrediction] = {}
        for head_id in self.head_ids:
            head = self._weights[head_id]
            probabilities = softmax(head.logits(pooled))
            predictions[head_id] = HeadPrediction(
                head_id=head_id,
                probabilities=probabilities,
                argmax=max(range(len(probabilities)), key=probabilities.__getitem__),
                entropy=_entropy(probabilities),
            )
        return predictions

    def predict_security_state_delta(self, window: LineageWindow) -> StateDelta:
        """DTL-F06 — which security dimensions are about to move.

        The nine state-delta bits are independent facts, so they are thresholded
        as nine sigmoids rather than read off a softmax argmax: an escalation
        that raises privilege *and* credential is the case that matters, and a
        single-label head cannot express it.

        The delta reports ``(0, 1)`` per predicted dimension — one lattice step.
        The head predicts *which* dimensions move, not how far; nothing in this
        repository has measured a magnitude head, so claiming a magnitude here
        would be a guess wearing a type.
        """
        head = self._weights.get("state_delta")
        if head is None:
            raise ContractError(
                "predict_security_state_delta needs the 'state_delta' head "
                "(DTL-F06 is REQUIRED); loaded heads: "
                f"{sorted(self._weights)}"
            )
        logits = head.logits(self._pooled(window))
        raised = {
            name: (0, 1)
            for name, logit in zip(DIMENSIONS, logits, strict=True)
            if _sigmoid(logit) > _DELTA_THRESHOLD
        }
        return StateDelta(raised=raised)

    def parameters(self) -> int:
        return sum(head.parameters() for head in self._weights.values())

    def memory_bytes(self) -> int:
        return sum(head.memory_bytes() for head in self._weights.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "head_ids": list(self.head_ids),
            "parameters": self.parameters(),
            "memory_bytes": self.memory_bytes(),
            "trained_experiment_ids": sorted(
                {head.trained_experiment_id for head in self._weights.values()}
            ),
        }
