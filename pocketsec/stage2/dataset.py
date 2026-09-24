"""D2.2 (part) — the shared Stage 2 dataset.

One dataset construction, used by DTL and every baseline. Acceptance criterion 1
requires identical Stage 1 inputs and evaluation splits; the way to guarantee
that is to build the data once and hand the same object to everyone.

Each sample is a scenario: a sequence of encoded SSIR transitions, a security
label, and per-step next-transition targets for the predictive heads. Two
evaluation tracks run over the same data:

* **prediction** — can the model say what happens next? (cross-entropy, top-k)
* **security** — can it tell benign from malicious? (PR-AUC, recall at a FP budget)

DTL's thesis is that the first produces the second: surprise against a
well-learned future is the detection signal, rather than a label fitted directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pocketsec.stage1.labs.hard_corpus import build_hard_corpus
from pocketsec.stage1.labs.ambiguous_corpus import build_ambiguous_corpus
from pocketsec.stage1.labs.longhorizon_corpus import build_long_horizon_corpus
from pocketsec.stage1.pipeline import ScenarioResult, Stage1Pipeline
from pocketsec.stage2.encoder.ssir_encoder import (
    ENCODER_VERSION,
    FEATURE_WIDTH,
    EncodedTransition,
    encode_ssir_transition,
)

__all__ = ["Stage2Dataset", "Stage2Sample", "build_dataset"]


@dataclass(frozen=True, slots=True)
class Stage2Sample:
    """One scenario, encoded once for every model."""

    sample_id: str
    steps: tuple[EncodedTransition, ...]
    label: int
    technique: str | None
    unseen_technique: bool
    #: Final host-lineage security potential, carried for hazard supervision.
    final_phi: float

    def __len__(self) -> int:
        return len(self.steps)

    @property
    def features(self) -> tuple[tuple[float, ...], ...]:
        return tuple(step.features for step in self.steps)

    def next_step_targets(self) -> tuple[tuple[EncodedTransition, EncodedTransition], ...]:
        """(context, next) pairs for next-transition prediction."""
        return tuple(zip(self.steps[:-1], self.steps[1:], strict=True))

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "length": len(self.steps),
            "label": self.label,
            "technique": self.technique,
            "unseen_technique": self.unseen_technique,
            "final_phi": round(self.final_phi, 4),
        }


@dataclass(frozen=True, slots=True)
class Stage2Dataset:
    """An immutable split, with the provenance a result needs to be comparable."""

    name: str
    seed: int
    corpus: str
    encoder_version: str
    feature_width: int
    samples: tuple[Stage2Sample, ...]

    def __len__(self) -> int:
        return len(self.samples)

    def __iter__(self):  # type: ignore[no-untyped-def]
        return iter(self.samples)

    @property
    def labels(self) -> tuple[int, ...]:
        return tuple(sample.label for sample in self.samples)

    @property
    def positive_count(self) -> int:
        return sum(self.labels)

    @property
    def transition_count(self) -> int:
        return sum(len(sample) for sample in self.samples)

    @property
    def base_rate(self) -> float:
        return self.positive_count / len(self.samples) if self.samples else 0.0

    def to_provenance(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "seed": self.seed,
            "corpus": self.corpus,
            "mean_length": round(
                self.transition_count / max(len(self.samples), 1), 2
            ),
            "encoder_version": self.encoder_version,
            "feature_width": self.feature_width,
            "samples": len(self.samples),
            "transitions": self.transition_count,
            "positives": self.positive_count,
            "base_rate": round(self.base_rate, 4),
            "unseen_technique_samples": sum(
                1 for s in self.samples if s.unseen_technique
            ),
        }


def _encode(result: ScenarioResult, index: int) -> Stage2Sample | None:
    """Encode one compiled scenario, or ``None`` if it produced no transitions."""
    if not result.transitions:
        return None
    return Stage2Sample(
        sample_id=f"{result.scenario.name}-{index:04d}",
        steps=tuple(encode_ssir_transition(t) for t in result.transitions),
        label=result.scenario.label,
        technique=result.scenario.technique,
        unseen_technique=result.scenario.unseen_technique,
        final_phi=result.peak_phi,
    )


def build_dataset(
    *, name: str, count: int, seed: int, corpus: str = "hard"
) -> Stage2Dataset:
    """Compile a hard-corpus split through Stage 1 and encode it.

    Each split gets a fresh :class:`Stage1Pipeline`, so novelty and lattice state
    never leak between the split a model is fitted on and the split it is scored
    on. Sharing a pipeline would let the fit split warm the novelty engine that
    scores the eval split — a subtle and total leak.
    """
    builders = {
        "hard": build_hard_corpus,
        "long": build_long_horizon_corpus,
        "ambiguous": build_ambiguous_corpus,
    }
    if corpus not in builders:
        raise ValueError(f"unknown corpus {corpus!r}; known: {sorted(builders)}")
    builder = builders[corpus]
    pipeline = Stage1Pipeline()
    samples: list[Stage2Sample] = []
    for index, scenario in enumerate(
        builder(count=count, seed=seed, split="eval")
    ):
        encoded = _encode(pipeline.run_scenario(scenario, offset=index), index)
        if encoded is not None:
            samples.append(encoded)

    return Stage2Dataset(
        name=name,
        corpus=corpus,
        seed=seed,
        encoder_version=ENCODER_VERSION,
        feature_width=FEATURE_WIDTH,
        samples=tuple(samples),
    )
