"""D6.18 — quantised candidate export: what INT8/INT4 costs a symbolic trusted state.

Architecture §31 asks for FP32/INT8/INT4 variants, measured for size and for security
degradation, rejected when recall or calibration degrades past a bound. Stage 6 ships no
``research/`` package and no numpy (ADR-0050), so there is no network to export to ONNX:
**ONNX FP32/INT8/INT4 export and the RSS/PSS of an ONNX inference workspace are
UNMEASURED.** What *is* float-bearing in a symbolic state is quantised here, with stdlib
``array``/``struct``:

* every BASELINE anchor (26 Stage 2 meaning floats each),
* every DETECTOR weight (its precision estimate),
* the THRESHOLD.

Motifs are integer bitmasks and are not quantised; BASELINE radii, validation counters and
lineage are copied from the template unchanged.

Scheme: symmetric, per-tensor (one scale over the concatenated floats), zero point 0,
``q = round(x / scale)`` clamped to ``[-(2**(bits-1) - 1), 2**(bits-1) - 1]``. INT8 codes
are one signed byte each; INT4 codes are packed two per byte.

**Stated in advance (spec §D6.18):** most meaning features are {0, 1}, which INT8
represents exactly, so INT8 was expected to be lossless on detection and the only effect a
size change. **Measured in this package's tests, that expectation is refuted at the default
threshold:** one symmetric scale over a state whose peak float is 1.0 cannot represent 0.5
(127 levels either side of zero), so ``DEFAULT_THRESHOLD = 0.5`` dequantises to
64/127 = 0.50394 — just above ``UNEXPLAINED_WEIGHT = 0.5`` — and every alert carried by the
unexplained term alone is lost. :func:`evaluate_quantized` rejects that variant on the
recall bound (``test_int8_at_the_default_threshold_is_not_lossless_and_is_rejected``). At a
threshold off the half-step (0.4) INT8 was lossless on the same replay. The replay is a
hand-built fixture of four episodes: these are statements about the quantiser, **not a
detection result**.

What it refuses:

* **Accepting an unmeasured variant.** A quantised variant is accepted only when recall
  drop ≤ ``QUANT_MAX_RECALL_DROP``, false-positive-rate increase ≤ ``EPS_FP_RATE`` **and**
  consistency agreement ≥ ``QUANT_MIN_AGREEMENT`` were all *measured*. A replay with no
  positives, no negatives, or no baseline decisions leaves a figure ``None`` and the variant
  is **not** accepted — unmeasured is not within bound.
* **Dequantising onto the wrong template.** The template's digest must equal the
  quantised state's ``base_digest``.

A dequantised state is an evaluation artefact: its items are rebuilt (a BASELINE's id is
content-addressed over its anchor, so a moved anchor is a new id), it is never fossilised,
and only the promotion controller can install trusted state.
"""

from __future__ import annotations

import dataclasses
import struct
from array import array
from collections.abc import Sequence
from dataclasses import dataclass

from pocketsec.stage0.benchmark.security_metrics import confusion_at_threshold
from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage2.adaptation.quarantine import meaning_distance, pattern_key
from pocketsec.stage6.constitution.learning import touches_protected
from pocketsec.stage6.memory.episodic import EpisodeSkeleton
from pocketsec.stage6.memory.semantic import (
    ItemKind,
    KnowledgeItem,
    TrustedKnowledgeState,
    anchor_masks,
    item_applies,
    knowledge_item_id,
    score_session,
)

__all__ = [
    "EPS_FP_RATE",
    "QUANT_BITS",
    "QUANT_MAX_RECALL_DROP",
    "QUANT_MIN_AGREEMENT",
    "QuantizedCandidate",
    "QuantizedState",
    "dequantize_state",
    "evaluate_quantized",
    "quantize_state",
]

#: §4.21. Chosen parameters, not measurements.
QUANT_BITS: tuple[int, ...] = (8, 4)
QUANT_MAX_RECALL_DROP: float = 0.01
QUANT_MIN_AGREEMENT: float = 0.99
#: The conservation gate's false-positive-rate bound (``conservation/gate.py``, §4.21),
#: restated here because an export module may not import the conservation gate; a test
#: pins that the two values agree.
EPS_FP_RATE: float = 0.01

#: Bytes of per-tensor metadata a quantised state carries: a float64 scale and an int32
#: zero point. Counted in ``quantized_bytes`` so the size comparison is honest.
_METADATA_BYTES = struct.calcsize("<di")


@dataclass(frozen=True, slots=True)
class QuantizedState:
    base_digest: str
    bits: int
    scale: float
    zero_point: int
    payload: bytes
    float_count: int


@dataclass(frozen=True, slots=True)
class QuantizedCandidate:
    base_digest: str
    bits: int
    fp_bytes: int
    quantized_bytes: int
    recall_fp: float | None
    recall_q: float | None
    fp_rate_fp: float | None
    fp_rate_q: float | None
    consistency_agreement: float | None
    accepted: bool
    reason: str


def _require_bits(bits: int) -> None:
    if bits not in QUANT_BITS:
        raise ContractError(f"bits must be one of {QUANT_BITS}, got {bits!r}")


def _float_items(state: TrustedKnowledgeState) -> tuple[KnowledgeItem, ...]:
    """Items that carry quantised floats, in the state's canonical (item_id) order."""
    kinds = (ItemKind.BASELINE, ItemKind.DETECTOR, ItemKind.THRESHOLD)
    return tuple(item for item in state.items if item.kind in kinds)


def _floats_of(item: KnowledgeItem) -> tuple[float, ...]:
    return item.anchor if item.kind is ItemKind.BASELINE else (item.weight,)


def _qmax(bits: int) -> int:
    return 2 ** (bits - 1) - 1


def _pack(codes: Sequence[int], bits: int) -> bytes:
    if bits == 8:
        return array("b", codes).tobytes()
    packed = bytearray()
    for index in range(0, len(codes), 2):
        low = codes[index] & 0x0F
        high = (codes[index + 1] & 0x0F) if index + 1 < len(codes) else 0
        packed.append(low | (high << 4))
    return bytes(packed)


def _nibble(value: int) -> int:
    return value - 16 if value >= 8 else value


def _unpack(payload: bytes, bits: int, count: int) -> tuple[int, ...]:
    if bits == 8:
        codes = array("b")
        codes.frombytes(payload)
        return tuple(codes[:count])
    codes_list: list[int] = []
    for byte in payload:
        codes_list.extend((_nibble(byte & 0x0F), _nibble(byte >> 4)))
    return tuple(codes_list[:count])


def quantize_state(state: TrustedKnowledgeState, *, bits: int) -> QuantizedState:
    """Symmetric per-tensor quantisation of every anchor, detector weight and the threshold."""
    _require_bits(bits)
    floats = [value for item in _float_items(state) for value in _floats_of(item)]
    peak = max((abs(v) for v in floats), default=0.0)
    qmax = _qmax(bits)
    scale = peak / qmax if peak > 0.0 else 1.0
    codes = [max(-qmax, min(qmax, round(v / scale))) for v in floats]
    return QuantizedState(
        base_digest=state.digest(),
        bits=bits,
        scale=scale,
        zero_point=0,
        payload=_pack(codes, bits),
        float_count=len(floats),
    )


def _rebuilt(item: KnowledgeItem, values: tuple[float, ...]) -> KnowledgeItem:
    if item.kind is not ItemKind.BASELINE:
        return dataclasses.replace(item, weight=min(1.0, max(0.0, values[0])))
    props, raised = anchor_masks(values)
    protected = item.protected or bool(touches_protected(props, raised))
    new_id = knowledge_item_id(item.kind, item.motif, values, item.pattern_key, item.context_ids)
    return dataclasses.replace(item, item_id=new_id, anchor=values, protected=protected)


def _dequantized_items(
    quantized: QuantizedState, template: TrustedKnowledgeState
) -> dict[str, KnowledgeItem]:
    """Template item id -> its rebuilt item, in the template's canonical order."""
    if template.digest() != quantized.base_digest:
        raise ContractError("dequantize_state: template digest does not match the quantised base")
    _require_bits(quantized.bits)
    codes = _unpack(quantized.payload, quantized.bits, quantized.float_count)
    if len(codes) != quantized.float_count:
        raise ContractError("quantised payload is shorter than its declared float count")
    values = [code * quantized.scale for code in codes]
    rebuilt: dict[str, KnowledgeItem] = {}
    cursor = 0
    for item in _float_items(template):
        width = len(_floats_of(item))
        rebuilt[item.item_id] = _rebuilt(item, tuple(values[cursor : cursor + width]))
        cursor += width
    return rebuilt


def dequantize_state(
    quantized: QuantizedState, *, template: TrustedKnowledgeState
) -> TrustedKnowledgeState:
    """Rebuild a state from ``template`` with its floats replaced by the dequantised values.

    Raises ``ContractError`` if the result is not a valid state — for instance two
    baselines whose anchors collapse onto one code and therefore one content id.
    """
    rebuilt = _dequantized_items(quantized, template)
    items = tuple(rebuilt.get(item.item_id, item) for item in template.items)
    return dataclasses.replace(template, items=items)


def _rates(
    state: TrustedKnowledgeState, replay: Sequence[EpisodeSkeleton], context_id: str
) -> tuple[float | None, float | None]:
    """(recall on MALICIOUS, FP rate on BENIGN) at the state's own threshold.

    Episodes with any other verdict are left out: UNKNOWN is not a negative.
    """
    labelled = [sk for sk in replay if sk.verdict in (Verdict.MALICIOUS, Verdict.BENIGN)]
    labels = [1 if sk.verdict is Verdict.MALICIOUS else 0 for sk in labelled]
    scores = [score_session(state, sk.steps, context_id=context_id).score for sk in labelled]
    matrix = confusion_at_threshold(labels, scores, state.threshold())
    return matrix.recall, matrix.false_positive_rate


def _radius_agreement(
    pairs: Sequence[tuple[KnowledgeItem, KnowledgeItem]],
    replay: Sequence[EpisodeSkeleton],
    context_id: str,
) -> float | None:
    """Share of Stage 2 radius decisions (step within a same-key baseline's radius) unchanged.

    ``pairs`` are (full-precision baseline, its dequantised rebuild); pairing by origin
    rather than by position matters because a moved anchor re-sorts the rebuilt item.
    """
    applicable = [(fp, q) for fp, q in pairs if item_applies(fp, context_id)]
    total = same = 0
    for skeleton in replay:
        for step in skeleton.steps:
            key = pattern_key(step.to_encoded())
            meaning = step.meaning()
            for fp, q in applicable:
                if fp.pattern_key != key:
                    continue
                total += 1
                same += (meaning_distance(meaning, fp.anchor) <= fp.weight) == (
                    meaning_distance(meaning, q.anchor) <= q.weight
                )
    return None if total == 0 else same / total


def _verdict(
    recall: tuple[float | None, float | None],
    fp_rate: tuple[float | None, float | None],
    agreement: float | None,
) -> tuple[bool, str]:
    """Accept only when all three figures were measured and all three bounds hold."""
    recall_fp, recall_q = recall
    fp_fp, fp_q = fp_rate
    if recall_fp is None or recall_q is None or fp_fp is None or fp_q is None or agreement is None:
        missing = [
            name
            for name, pair in (
                ("recall", recall),
                ("fp_rate", fp_rate),
                ("consistency_agreement", (agreement,)),
            )
            if any(v is None for v in pair)
        ]
        return False, "UNMEASURED: " + ", ".join(missing) + " could not be measured on this replay"
    reasons = []
    if recall_fp - recall_q > QUANT_MAX_RECALL_DROP:
        reasons.append(f"recall drop {recall_fp - recall_q:.4f} > {QUANT_MAX_RECALL_DROP}")
    if fp_q - fp_fp > EPS_FP_RATE:
        reasons.append(f"fp-rate increase {fp_q - fp_fp:.4f} > {EPS_FP_RATE}")
    if agreement < QUANT_MIN_AGREEMENT:
        reasons.append(f"consistency agreement {agreement:.4f} < {QUANT_MIN_AGREEMENT}")
    return (not reasons), ("accepted" if not reasons else "; ".join(reasons))


def evaluate_quantized(
    state: TrustedKnowledgeState, *, bits: int, replay: Sequence[EpisodeSkeleton], context_id: str
) -> QuantizedCandidate:
    """Quantise, dequantise, replay both, and accept only on three measured bounds."""
    quantized = quantize_state(state, bits=bits)
    recall_fp, fp_rate_fp = _rates(state, replay, context_id)
    recall_q = fp_rate_q = agreement = None
    try:
        rebuilt = _dequantized_items(quantized, state)
        restored = dequantize_state(quantized, template=state)
    except ContractError as exc:
        accepted, reason = False, f"dequantised state is invalid: {exc}"
    else:
        recall_q, fp_rate_q = _rates(restored, replay, context_id)
        pairs = [(item, rebuilt[item.item_id]) for item in state.baselines()]
        agreement = _radius_agreement(pairs, replay, context_id)
        accepted, reason = _verdict((recall_fp, recall_q), (fp_rate_fp, fp_rate_q), agreement)
    return QuantizedCandidate(
        base_digest=quantized.base_digest,
        bits=bits,
        fp_bytes=len(array("d", [0.0] * quantized.float_count).tobytes()),
        quantized_bytes=len(quantized.payload) + _METADATA_BYTES,
        recall_fp=recall_fp,
        recall_q=recall_q,
        fp_rate_fp=fp_rate_fp,
        fp_rate_q=fp_rate_q,
        consistency_agreement=agreement,
        accepted=accepted,
        reason=reason,
    )
