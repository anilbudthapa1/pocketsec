"""D4.16 — the 40-experiment register, the flag ablation, and the saturation guard.

Architecture §43 names forty experiments, ``S4X-01`` to ``S4X-40``. All forty are
enumerated here with the architecture's own ids and titles, each bound to the
``CBF-F*`` ids it exercises. **:func:`blocked_experiments` being non-empty is a
required output, not untidiness**: declaring what this wave cannot run is the
deliverable, and a register that quietly listed only the runnable ones would
misrepresent the stage's coverage. Three blocking reasons exist and they are closed —
``needs real telemetry``, ``needs numpy``, ``needs a local LM`` — because an
open-ended reason field becomes a place to hide.

:func:`run_ablation` calls :func:`saturation_check` **first** and returns
``DEGENERATE`` rows with the reason rather than a delta when the split cannot tell
mechanisms apart. Stage 1's ``ParetoReport.degenerate`` is the precedent and Stage 2's
G2.2 is the warning: it reported ``ORDER_FREE_BASELINE_TIES_BEST`` with best 1.0 and
median 0.6586, and a delta computed on such a split measures the split.

Four verdicts, and the distinction between two of them is the one this project fought
hardest for. **``NOT_YET_JUSTIFIED`` is not ``REJECTED``.** On a corpus with no
headroom, "no measured benefit" cannot demonstrate absence of benefit — ADR-0009 got
that right under pressure, and two of the three components it flagged later turned out
to be actively *harmful* on a corpus that did have headroom. ``HARMFUL`` is reserved
for a measured negative delta, which is a different and stronger claim.

**This module never writes to the real experiment ledger.** ``experiments/registry.jsonl``
is append-only and digest-chained, and a Stage 3 gate that appended a row every time
the test suite ran grew the permanent ledger as a side effect of testing. Nothing here
constructs an :class:`ExperimentRegistry`; ``registry_experiment_id`` is a *field a
human fills in* after a deliberate ``register`` invocation, and it is ``None`` until
then.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage1.telemetry.raw_event_v1 import SensorPath
from pocketsec.stage4.core_ids import CORE_IDS
from pocketsec.stage4.engine.lucid import INERT_FLAGS, LucidConfig
from pocketsec.stage4.labs.baseline_metrics import BaselineOutcome
from pocketsec.stage4.labs.baselines import replay_corpus, run_engine_baseline
from pocketsec.stage4.labs.incident_corpus import (
    INCIDENT_CORPUS_VERSION,
    IncidentCase,
    median_peak_delta_phi,
    operation_share_gap,
    pooled_order_free_scores,
)
from pocketsec.stage4.visibility.model import fit_visibility_model, measure_visibility

__all__ = [
    "ABLATION_EXPERIMENTS",
    "ABLATION_METRIC",
    "BLOCKED_REASONS",
    "EXPERIMENTS",
    "JUSTIFICATION_EPSILON",
    "MAX_ORDER_FREE_ADVANTAGE",
    "STAGE4_EXPERIMENTS_VERSION",
    "AblationRow",
    "ExperimentSpec",
    "blocked_experiments",
    "experiment",
    "run_ablation",
    "runnable_experiments",
    "saturation_check",
]

STAGE4_EXPERIMENTS_VERSION: str = f"stage4-experiments-v0.1.0+{INCIDENT_CORPUS_VERSION}"

#: Closed set of reasons an experiment cannot run in this repository. Closed because an
#: open reason field is where "we did not get to it" hides behind "it is blocked".
BLOCKED_REASONS: frozenset[str] = frozenset(
    {"needs real telemetry", "needs numpy", "needs a local LM"}
)

#: The metric the ablation reads. World-set recall, because G4.2 is the criterion the
#: multi-world machinery exists to meet: does the surviving field still contain an
#: explanation that covers what actually happened?
ABLATION_METRIC: str = "world_set_recall"

#: A delta smaller than this is not a justification. Same magnitude as
#: ``SATURATION_EPSILON``, so a mechanism cannot be justified by a difference the
#: corpus cannot resolve.
JUSTIFICATION_EPSILON: float = 0.01

#: An order-free bag-of-operations control this far above the base rate means the label
#: is readable from the operation histogram, and no order-sensitive Stage 4 result on
#: this corpus would mean anything (MEMORY trap 4; two corpora leaked this way).
MAX_ORDER_FREE_ADVANTAGE: float = 0.02

#: The architecture's own id shape. Matched exactly, because the id is the join key
#: back to §43 and a near-miss would silently detach a row from the document.
_EXPERIMENT_ID_RE = re.compile(r"^S4X-\d{2}$")


@dataclass(frozen=True, slots=True)
class ExperimentSpec:
    """One of §43's forty experiments, with what it exercises and what blocks it."""

    experiment_id: str
    title: str
    core_ids: tuple[str, ...]
    runnable: bool
    #: Why this experiment cannot run here. Spec D4.16 names it ``blocked_reason``;
    #: ``block`` is a ``FORBIDDEN_AUTHORITY_FIELDS`` token and §2.4's rule has no
    #: exemption list, so the field is ``refusal_reason`` — the vocabulary
    #: ``BirthRefusal`` and ``spawn_refusal`` already use elsewhere in Stage 4.
    refusal_reason: str = ""
    #: ``PS-S4-...`` once a human has deliberately registered a measurement for it.
    #: ``None`` means *not measured*, and nothing in this module ever sets it.
    registry_experiment_id: str | None = None

    def __post_init__(self) -> None:
        if not _EXPERIMENT_ID_RE.fullmatch(self.experiment_id):
            raise ContractError(
                f"experiment_id must be 'S4X-01'..'S4X-40', got {self.experiment_id!r}; §43 "
                "names exactly forty and the architecture's own ids are the join key — a "
                "renamed or invented one loses the trace back to the document"
            )
        if not 1 <= int(self.experiment_id[4:]) <= 40:
            raise ContractError(
                f"{self.experiment_id} is outside S4X-01..S4X-40; §43 names exactly forty "
                "experiments and a forty-first would be this wave's invention"
            )
        if not self.title.strip():
            raise ContractError(f"{self.experiment_id} has no title")
        object.__setattr__(self, "core_ids", tuple(self.core_ids))
        unknown = [item for item in self.core_ids if item not in CORE_IDS]
        if unknown:
            raise ContractError(
                f"{self.experiment_id} names core ids {unknown} that are not in CORE_IDS"
            )
        if not isinstance(self.runnable, bool):
            raise ContractError(f"{self.experiment_id}.runnable must be a bool")
        if self.runnable and self.refusal_reason:
            raise ContractError(
                f"{self.experiment_id} is runnable but carries a refusal_reason; one of the "
                "two is wrong and a reader cannot tell which"
            )
        if not self.runnable and self.refusal_reason not in BLOCKED_REASONS:
            raise ContractError(
                f"{self.experiment_id} is blocked for {self.refusal_reason!r}, which is not "
                f"one of {sorted(BLOCKED_REASONS)}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "title": self.title,
            "core_ids": list(self.core_ids),
            "runnable": self.runnable,
            "refusal_reason": self.refusal_reason,
            "registry_experiment_id": self.registry_experiment_id,
        }


def _spec(
    number: int, title: str, core_ids: Sequence[str], blocked: str = ""
) -> ExperimentSpec:
    return ExperimentSpec(
        experiment_id=f"S4X-{number:02d}",
        title=title,
        core_ids=tuple(core_ids),
        runnable=not blocked,
        refusal_reason=blocked,
    )


#: §43's forty experiments, in the architecture's own order, with its own titles.
#: Eight are blocked and say why. The blocked set is a **required output**: three need
#: real Linux telemetry (every sensor path here is a replay of a synthetic corpus),
#: two need numerical linear algebra ADR-0030 forbids, and one needs a local language
#: model this repository does not contain.
EXPERIMENTS: tuple[ExperimentSpec, ...] = (
    _spec(1, "partial-observability simulator", ("CBF-F06",)),
    _spec(
        2,
        "sensor visibility calibration",
        ("CBF-F06",),
        "needs real telemetry",
    ),
    _spec(3, "CBF representation comparison", ("CBF-F01",)),
    _spec(4, "world birth", ("CBF-F02",)),
    _spec(5, "world death", ("CBF-F03",)),
    _spec(6, "fission/fusion", ("CBF-F04", "CBF-F05")),
    _spec(7, "evidence tension", ("CBF-F07",)),
    _spec(8, "negative evidence", ("CBF-F06", "CBF-F07")),
    _spec(9, "sensor-shadow reasoning", ("CBF-F06",)),
    _spec(10, "bounded counterfactual intervention", ("CBF-F09",)),
    _spec(11, "responsibility flux", ("CBF-F10",)),
    _spec(12, "future-cone composition", ("CBF-F11",)),
    _spec(13, "world dominance pruning", ("CBF-F17",)),
    _spec(14, "incident entropy budget", ("CBF-F01", "CBF-F17")),
    _spec(15, "sequential evidence accumulation", ("CBF-F08",)),
    _spec(
        16,
        "conformal/set-valued abstention baseline",
        ("CBF-F12",),
        "needs numpy",
    ),
    _spec(17, "calibration under epoch drift", ("CBF-F12",)),
    _spec(18, "identifiability test", ("CBF-F12",)),
    _spec(19, "non-identifiable incident benchmark", ("CBF-F12",)),
    _spec(20, "information-gain sensing", ("CBF-F13", "CBF-F14")),
    _spec(21, "counterfactual sensor planning", ("CBF-F09", "CBF-F13")),
    _spec(22, "security-free-energy objective", ("CBF-F13", "CBF-F14")),
    _spec(23, "active sensing cost comparison", ("CBF-F13", "CBF-F14")),
    _spec(24, "slow-attack world persistence", ("CBF-F01", "CBF-F02")),
    _spec(25, "benign-admin ambiguity", ("CBF-F12",)),
    _spec(26, "missing telemetry", ("CBF-F06", "CBF-F07")),
    _spec(27, "event flood", ("CBF-F17",)),
    _spec(28, "semantic rename invariance", ("CBF-F16",)),
    _spec(29, "decoy ancestry", ("CBF-F16",)),
    _spec(30, "self-questioning", ("CBF-F15",)),
    _spec(31, "adversarial belief stress", ("CBF-F16",)),
    _spec(32, "typed epistemic graph", ("CBF-F18",)),
    _spec(33, "claim compiler", ("CBF-F18",)),
    _spec(
        34,
        "tiny-LM verbalizer guard",
        ("CBF-F18",),
        "needs a local LM",
    ),
    _spec(35, "Stage3 contradiction feedback", ("CBF-F19",)),
    _spec(36, "belief crystallization", ("CBF-F19",)),
    _spec(37, "sparse world graph", ("CBF-F17",)),
    _spec(38, "resource benchmark", ("CBF-F01",)),
    _spec(39, "full ablation", tuple(sorted(CORE_IDS))),
    _spec(
        40,
        "falsification / simpler-model challenge",
        ("CBF-F01",),
        "needs real telemetry",
    ),
)


def _validate_register() -> None:
    """Exactly forty, unique ids, and every ``CBF-F*`` id exercised by at least one row.

    Run at import so a malformed register cannot be discovered by the gate instead of
    by the module that owns it. The coverage check is the useful half: a register of
    forty experiments that never touches half the core ids is not a research program.
    """
    if len(EXPERIMENTS) != 40:
        raise ContractError(
            f"§43 names forty experiments; EXPERIMENTS holds {len(EXPERIMENTS)}"
        )
    ids = [spec.experiment_id for spec in EXPERIMENTS]
    if len(set(ids)) != len(ids):
        raise ContractError(f"duplicate experiment ids: {sorted({i for i in ids if ids.count(i) > 1})}")
    expected = [f"S4X-{n:02d}" for n in range(1, 41)]
    if ids != expected:
        raise ContractError("EXPERIMENTS must be S4X-01..S4X-40 in the architecture's order")
    covered = {core_id for spec in EXPERIMENTS for core_id in spec.core_ids}
    missing = sorted(set(CORE_IDS) - covered)
    if missing:
        raise ContractError(f"core ids exercised by no experiment: {missing}")


_validate_register()


def runnable_experiments() -> tuple[ExperimentSpec, ...]:
    return tuple(spec for spec in EXPERIMENTS if spec.runnable)


def blocked_experiments() -> tuple[ExperimentSpec, ...]:
    """The experiments this repository cannot run, with the reason each.

    Non-empty by design. Eight of forty is the honest coverage of a stage whose
    telemetry is synthetic, whose arithmetic is stdlib and whose language model does
    not exist.
    """
    return tuple(spec for spec in EXPERIMENTS if not spec.runnable)


def experiment(experiment_id: str) -> ExperimentSpec:
    for spec in EXPERIMENTS:
        if spec.experiment_id == experiment_id:
            return spec
    raise KeyError(f"unknown experiment {experiment_id!r}")


# --- the ablation ------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AblationRow:
    """One flag's measured effect. ``verdict`` is the whole point of the row."""

    core_id: str
    flag: str
    with_value: float
    without_value: float
    delta: float
    metric: str
    verdict: str

    #: ``INERT`` is a flag whose mechanism cannot reach the measured output by
    #: construction (``engine.lucid_support.INERT_FLAGS``). No delta is computed for
    #: it: a structural 0.0 entered as NOT_YET_JUSTIFIED told the next wave to go and
    #: build a better corpus for a mechanism that was never wired in (S4-FC-08).
    _VERDICTS = ("JUSTIFIED", "NOT_YET_JUSTIFIED", "HARMFUL", "DEGENERATE", "INERT")

    def __post_init__(self) -> None:
        if self.verdict not in self._VERDICTS:
            raise ContractError(
                f"AblationRow.verdict must be one of {list(self._VERDICTS)}, got "
                f"{self.verdict!r}"
            )
        if not self.flag:
            raise ContractError("AblationRow.flag must name the LucidConfig flag removed")
        if self.core_id and self.core_id not in CORE_IDS:
            raise ContractError(f"AblationRow.core_id {self.core_id!r} is not in CORE_IDS")

    def to_dict(self) -> dict[str, Any]:
        return {
            "core_id": self.core_id,
            "flag": self.flag,
            "with_value": self.with_value,
            "without_value": self.without_value,
            "delta": self.delta,
            "metric": self.metric,
            "verdict": self.verdict,
        }


def saturation_check(corpus: Sequence[IncidentCase]) -> tuple[bool, str]:
    """Can this corpus separate mechanisms at all? Run **before** any ablation.

    Three ways to fail, all of which this project has already paid for:

    1. **median peak ΔΦ of 0.00 for either class** — the identity-reuse defect's
       signature. A corpus that reuses process identities across sessions puts every
       lineage at saturated privilege and erases its own signal; that retracted a
       +0.042 published result (``MEMORY.md``).
    2. **an order-free control above the base rate by more than**
       :data:`MAX_ORDER_FREE_ADVANTAGE` — the label is readable from the operation
       histogram, so nothing order-sensitive measured here means anything.
    3. **a per-operation share gap above** :data:`MAX_ORDER_FREE_ADVANTAGE` — an
       operation one class never emits is a free perfect score for a counting model.

    Returns ``(degenerate, reason)``. The reason is recorded on every row rather than
    thrown away, because "this corpus cannot answer the question" is a finding about
    the corpus.
    """
    if not corpus:
        return True, "empty corpus"
    medians = median_peak_delta_phi(corpus)
    zeroed = sorted(label for label, value in medians.items() if value <= 0.0)
    if zeroed:
        return True, (
            f"median peak delta_phi is 0.00 for label(s) {zeroed}; identity reuse erases "
            "the signal (MEMORY.md corpus trap)"
        )
    base_rate = sum(case.label for case in corpus) / len(corpus)
    scores = pooled_order_free_scores(corpus)
    labels = [case.label for case in corpus]
    order_free = _average_precision(scores, labels)
    if order_free - base_rate > MAX_ORDER_FREE_ADVANTAGE:
        return True, (
            f"order-free control reaches {order_free:.4f} against base rate "
            f"{base_rate:.4f}; the label is readable from the operation histogram"
        )
    gap = operation_share_gap(corpus)
    if gap > MAX_ORDER_FREE_ADVANTAGE:
        return True, f"per-operation share gap {gap:.4f} leaks the label through vocabulary"
    return False, (
        f"medians {medians}, order-free {order_free:.4f} vs base rate {base_rate:.4f}, "
        f"share gap {gap:.4f}"
    )


def _average_precision(scores: Sequence[float], labels: Sequence[int]) -> float:
    """Average precision, stdlib. Ties broken by index so the figure is reproducible."""
    if not scores or len(scores) != len(labels):
        return 0.0
    ordered = sorted(range(len(scores)), key=lambda i: (-scores[i], i))
    positives = sum(1 for label in labels if label)
    if positives == 0:
        return 0.0
    hits = 0
    total = 0.0
    for rank, index in enumerate(ordered, start=1):
        if labels[index]:
            hits += 1
            total += hits / rank
    return total / positives


def _metric_of(outcome: BaselineOutcome) -> float | None:
    return getattr(outcome, ABLATION_METRIC)


def _verdict_for(delta: float | None) -> str:
    if delta is None:
        return "NOT_YET_JUSTIFIED"
    if delta > JUSTIFICATION_EPSILON:
        return "JUSTIFIED"
    if delta < -JUSTIFICATION_EPSILON:
        return "HARMFUL"
    return "NOT_YET_JUSTIFIED"


def _core_id_for(flag: str) -> str:
    """The first ``CBF-F*`` id this flag removes, or ``""`` for a flag with none.

    ``enable_free_energy`` and ``enable_verbalizer`` have no core id: §18's objective
    and D4.15's guard are not among §36's twenty functions. Returning ``""`` rather
    than inventing an id keeps the register honest — ``AblationRow`` accepts an empty
    ``core_id`` and refuses an unknown one.
    """
    for core_id, spec in sorted(CORE_IDS.items()):
        if spec.ablation_flag == flag:
            return core_id
    return ""


def run_ablation(
    corpus: Sequence[IncidentCase], *, seed: int
) -> tuple[AblationRow, ...]:
    """Flip each :class:`LucidConfig` flag and measure the delta on :data:`ABLATION_METRIC`.

    :func:`saturation_check` runs **first**. On a degenerate split every row is
    ``DEGENERATE`` carrying the reason and **no delta is computed at all** — not a zero
    delta, because a zero would enter the ledger looking like a measurement.

    Each flag is flipped from its shipped default, so ``enable_free_energy`` (off) is
    measured by turning it *on* and the rest by turning them off. That is the direction
    a reader cares about: does enabling the mechanism help?
    """
    degenerate, reason = saturation_check(corpus)
    flags = LucidConfig.flag_names()
    if degenerate:
        return tuple(
            AblationRow(
                core_id=_core_id_for(flag),
                flag=flag,
                with_value=0.0,
                without_value=0.0,
                delta=0.0,
                metric=f"{ABLATION_METRIC}:not-computed({reason})",
                verdict="DEGENERATE",
            )
            for flag in flags
        )

    replays = replay_corpus(corpus)
    model = fit_visibility_model(
        measure_visibility(
            Stage1Pipeline,
            [case.scenario for case in corpus],
            [SensorPath.EBPF, SensorPath.AUDITD],
        )
    )
    shipped = LucidConfig()
    reference = _metric_of(
        run_engine_baseline(replays, model, shipped, baseline_id="ablation-reference")
    )
    rows: list[AblationRow] = []
    for flag in flags:
        if flag in INERT_FLAGS:
            rows.append(
                AblationRow(
                    core_id=_core_id_for(flag),
                    flag=flag,
                    with_value=0.0,
                    without_value=0.0,
                    delta=0.0,
                    metric=f"{ABLATION_METRIC}:not-computed(inert: {INERT_FLAGS[flag]})",
                    verdict="INERT",
                )
            )
            continue
        flipped = _flip(shipped, flag)
        variant = _metric_of(
            run_engine_baseline(replays, model, flipped, baseline_id=f"ablation-{flag}")
        )
        enabled_value, disabled_value = (
            (reference, variant) if getattr(shipped, flag) else (variant, reference)
        )
        delta = (
            None
            if enabled_value is None or disabled_value is None
            else enabled_value - disabled_value
        )
        rows.append(
            AblationRow(
                core_id=_core_id_for(flag),
                flag=flag,
                with_value=float(enabled_value) if enabled_value is not None else 0.0,
                without_value=float(disabled_value) if disabled_value is not None else 0.0,
                delta=float(delta) if delta is not None else 0.0,
                metric=ABLATION_METRIC if delta is not None else f"{ABLATION_METRIC}:None",
                verdict=_verdict_for(delta),
            )
        )
    return tuple(rows)


def _flip(config: LucidConfig, flag: str) -> LucidConfig:
    """A copy of ``config`` with one flag inverted. Frozen, so a copy is the only way."""
    values: dict[str, Any] = {
        name: getattr(config, name) for name in LucidConfig.flag_names()
    }
    if flag not in values:
        raise ContractError(f"{flag!r} is not a LucidConfig flag")
    values[flag] = not values[flag]
    return LucidConfig(max_worlds=config.max_worlds, budget=config.budget, **values)


#: Which experiments the flag ablation actually settles, so the register and the
#: ablation cannot drift apart silently.
ABLATION_EXPERIMENTS: Mapping[str, str] = MappingProxyType(
    {
        "enable_fission_fusion": "S4X-06",
        "enable_sequential_evidence": "S4X-15",
        "enable_counterfactual": "S4X-10",
        "enable_active_sensing": "S4X-23",
        "enable_self_questioning": "S4X-30",
        "enable_stress": "S4X-31",
        "enable_cell_feedback": "S4X-35",
        "enable_free_energy": "S4X-22",
        "enable_verbalizer": "S4X-34",
    }
)
