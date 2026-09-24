"""D2.2 — the Stage 2 baseline suite (ADR-0008: research only).

Nine baselines, all trained on the identical encoded Stage 1 dataset and scored
on the identical held-out split. The Stage 2 spec is blunt about why this
matters (section 28): a unified provenance-IDS evaluation found simple neural
networks matching or beating far more complex systems while being lighter and
real-time, so **DTL has no right to exist unless it demonstrates a measurable
advantage** over these.

Baselines are therefore given every fair chance: the same features, the same
epochs, the same optimiser, the same seeds, and hyperparameters in the range
each architecture normally works in. A baseline that lost because it was
starved would make the whole comparison worthless.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

import numpy as np

from pocketsec.stage2.dataset import Stage2Dataset, Stage2Sample
from pocketsec.stage2.encoder.ssir_encoder import NEED_SIGNAL_INDICES
from pocketsec.stage2.research.autograd import (
    Tensor,
    binary_cross_entropy,
    bmm,
    concat,
    sigmoid,
)

__all__ = [
    "BASELINE_REGISTRY",
    "GRUBaseline",
    "LSTMBaseline",
    "MLPBaseline",
    "MarkovBaseline",
    "SSMBaseline",
    "Stage2Model",
    "TCNBaseline",
    "TransformerBaseline",
    "PhiOracleBaseline",
    "VQPrototypeBaseline",
    "build_baselines",
]

DEFAULT_EPOCHS = 60
DEFAULT_LR = 0.05


class Stage2Model(Protocol):
    """What every Stage 2 model — baseline or DTL — must provide."""

    name: str

    def fit(self, dataset: Stage2Dataset) -> Stage2Model: ...

    def predict_scores(self, dataset: Stage2Dataset) -> list[float]:
        """One detection score per sample, higher = more suspicious."""
        ...

    def resource_profile(self) -> dict[str, Any]:
        """Parameter count and state bytes. Measured, not estimated."""
        ...


# --- shared plumbing ---------------------------------------------------------


def _pad(samples: tuple[Stage2Sample, ...]) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Right-pad variable-length scenarios into a dense batch plus a mask."""
    width = len(samples[0].steps[0].features)
    longest = max(len(s) for s in samples)
    batch = np.zeros((len(samples), longest, width))
    mask = np.zeros((len(samples), longest))
    labels = np.zeros((len(samples), 1))
    for row, sample in enumerate(samples):
        for step, encoded in enumerate(sample.steps):
            batch[row, step] = encoded.features
            mask[row, step] = 1.0
        labels[row, 0] = sample.label
    return batch, mask, labels


@dataclass
class _TorchLikeModule:
    """Shared SGD-with-momentum training loop for the gradient baselines."""

    name: str
    hidden: int = 32
    epochs: int = DEFAULT_EPOCHS
    learning_rate: float = DEFAULT_LR
    batch_size: int = 16
    seed: int = 7
    params: list[Tensor] = field(default_factory=list)
    _velocity: list[np.ndarray] = field(default_factory=list)
    _losses: list[float] = field(default_factory=list)

    def _rng(self) -> np.random.Generator:
        return np.random.default_rng(self.seed)

    def _parameter(self, *shape: int, scale: float | None = None) -> Tensor:
        rng = self._rng() if not self.params else np.random.default_rng(
            self.seed + len(self.params)
        )
        limit = scale if scale is not None else float(np.sqrt(1.0 / max(shape[0], 1)))
        tensor = Tensor(rng.uniform(-limit, limit, size=shape), requires_grad=True)
        self.params.append(tensor)
        return tensor

    def _bias(self, size: int) -> Tensor:
        tensor = Tensor(np.zeros((1, size)), requires_grad=True)
        self.params.append(tensor)
        return tensor

    def forward(self, batch: np.ndarray, mask: np.ndarray) -> Tensor:
        raise NotImplementedError

    def fit(self, dataset: Stage2Dataset) -> _TorchLikeModule:
        """Mini-batch SGD.

        Full-batch training gives one gradient step per epoch, so 30 epochs is
        30 updates — enough for a shallow pooled model and nowhere near enough
        for a deep recurrent one. Comparing them under that budget measures
        depth-of-optimisation, not architecture, and produced baselines scoring
        *below* the base rate.
        """
        batch, mask, labels = _pad(dataset.samples)
        self._build(batch.shape[-1])
        self._velocity = [np.zeros_like(p.data) for p in self.params]

        rows = len(batch)
        size = max(1, min(self.batch_size, rows))
        rng = np.random.default_rng(self.seed)

        for _ in range(self.epochs):
            order = rng.permutation(rows)
            epoch_loss = 0.0
            batches = 0
            for start in range(0, rows, size):
                index = order[start : start + size]
                for parameter in self.params:
                    parameter.zero_grad()
                loss = binary_cross_entropy(
                    self.forward(batch[index], mask[index]), labels[index]
                )
                loss.backward()
                self._step()
                epoch_loss += float(loss.data)
                batches += 1
            self._losses.append(epoch_loss / max(batches, 1))
        return self

    def _step(self) -> None:
        for index, parameter in enumerate(self.params):
            if parameter.grad is None:
                continue
            gradient = np.clip(parameter.grad, -5.0, 5.0)
            self._velocity[index] = 0.9 * self._velocity[index] + gradient
            parameter.data -= self.learning_rate * self._velocity[index]

    def _build(self, width: int) -> None:
        raise NotImplementedError

    def predict_scores(self, dataset: Stage2Dataset) -> list[float]:
        batch, mask, _ = _pad(dataset.samples)
        return [float(v) for v in sigmoid(self.forward(batch, mask).data).reshape(-1)]

    def resource_profile(self) -> dict[str, Any]:
        parameters = sum(int(np.prod(p.data.shape)) for p in self.params)
        return {
            "parameters": parameters,
            # FP32 deployment is the reference point; Stage 2 tests lower
            # precision separately.
            "model_bytes_fp32": parameters * 4,
            "hidden": self.hidden,
            "final_loss": round(self._losses[-1], 5) if self._losses else None,
        }


# --- 1. Markov / n-gram ------------------------------------------------------


@dataclass
class MarkovBaseline:
    """Relation-bigram surprise. The cheapest possible sequence model.

    No parameters, no gradients, counts only. If this matches the neural
    baselines, the Stage 2 falsification criteria say the neural layer has to
    justify its cost.
    """

    name: str = "markov-bigram"
    alpha: float = 1.0
    _transitions: dict[tuple[int, int], int] = field(default_factory=dict)
    _contexts: dict[int, int] = field(default_factory=dict)
    _vocabulary: set[int] = field(default_factory=set)

    def fit(self, dataset: Stage2Dataset) -> MarkovBaseline:
        # Benign-only fit keeps this an anomaly baseline and avoids leaking
        # attack labels into the transition table.
        for sample in dataset.samples:
            if sample.label != 0:
                continue
            previous = -1
            for step in sample.steps:
                self._transitions[(previous, step.relation)] = (
                    self._transitions.get((previous, step.relation), 0) + 1
                )
                self._contexts[previous] = self._contexts.get(previous, 0) + 1
                self._vocabulary.add(step.relation)
                previous = step.relation
        return self

    def predict_scores(self, dataset: Stage2Dataset) -> list[float]:
        scores: list[float] = []
        vocabulary = len(self._vocabulary) + 1
        for sample in dataset.samples:
            previous = -1
            surprises: list[float] = []
            for step in sample.steps:
                count = self._transitions.get((previous, step.relation), 0)
                total = self._contexts.get(previous, 0)
                probability = (count + self.alpha) / (total + self.alpha * vocabulary)
                surprises.append(-np.log2(probability))
                previous = step.relation
            scores.append(float(np.mean(surprises)) if surprises else 0.0)
        highest = max(scores) or 1.0
        return [s / highest for s in scores]

    def resource_profile(self) -> dict[str, Any]:
        return {
            "parameters": len(self._transitions),
            "model_bytes_fp32": len(self._transitions) * 12,
            "hidden": 0,
            "final_loss": None,
        }


# --- 2. MLP over pooled features --------------------------------------------


@dataclass
class MLPBaseline(_TorchLikeModule):
    """Mean/max-pooled features through one hidden layer. No recurrence."""

    name: str = "mlp-pooled"

    def _build(self, width: int) -> None:
        if self.params:
            return
        self.w1 = self._parameter(width * 2, self.hidden)
        self.b1 = self._bias(self.hidden)
        self.w2 = self._parameter(self.hidden, 1)
        self.b2 = self._bias(1)

    def forward(self, batch: np.ndarray, mask: np.ndarray) -> Tensor:
        lengths = np.maximum(mask.sum(axis=1, keepdims=True), 1.0)
        pooled_mean = (batch * mask[..., None]).sum(axis=1) / lengths
        pooled_max = np.max(batch * mask[..., None], axis=1)
        pooled = Tensor(np.concatenate([pooled_mean, pooled_max], axis=-1))
        hidden = (pooled @ self.w1 + self.b1).relu()
        return hidden @ self.w2 + self.b2


# --- 3/4. GRU and LSTM -------------------------------------------------------


@dataclass
class GRUBaseline(_TorchLikeModule):
    """Compact gated recurrent baseline."""

    name: str = "gru"

    def _build(self, width: int) -> None:
        if self.params:
            return
        size = width + self.hidden
        self.wz = self._parameter(size, self.hidden)
        self.bz = self._bias(self.hidden)
        self.wr = self._parameter(size, self.hidden)
        self.br = self._bias(self.hidden)
        self.wh = self._parameter(size, self.hidden)
        self.bh = self._bias(self.hidden)
        self.wo = self._parameter(self.hidden, 1)
        self.bo = self._bias(1)

    def forward(self, batch: np.ndarray, mask: np.ndarray) -> Tensor:
        rows, steps, _ = batch.shape
        hidden = Tensor(np.zeros((rows, self.hidden)))
        for step in range(steps):
            x = Tensor(batch[:, step, :])
            keep = Tensor(mask[:, step : step + 1])
            joined = concat([x, hidden], axis=-1)
            z = (joined @ self.wz + self.bz).sigmoid()
            r = (joined @ self.wr + self.br).sigmoid()
            candidate = (concat([x, hidden * r], axis=-1) @ self.wh + self.bh).tanh()
            updated = hidden * (1.0 - z) + candidate * z
            # Padded steps must not move the state, or short scenarios would be
            # silently rewritten by whatever the padding happens to be.
            hidden = updated * keep + hidden * (1.0 - keep)
        return hidden @ self.wo + self.bo


@dataclass
class LSTMBaseline(_TorchLikeModule):
    """Gated recurrent baseline with an explicit cell state."""

    name: str = "lstm"

    def _build(self, width: int) -> None:
        if self.params:
            return
        size = width + self.hidden
        for gate in ("i", "f", "o", "g"):
            setattr(self, f"w{gate}", self._parameter(size, self.hidden))
            setattr(self, f"b{gate}", self._bias(self.hidden))
        self.wout = self._parameter(self.hidden, 1)
        self.bout = self._bias(1)

    def forward(self, batch: np.ndarray, mask: np.ndarray) -> Tensor:
        rows, steps, _ = batch.shape
        hidden = Tensor(np.zeros((rows, self.hidden)))
        cell = Tensor(np.zeros((rows, self.hidden)))
        for step in range(steps):
            x = Tensor(batch[:, step, :])
            keep = Tensor(mask[:, step : step + 1])
            joined = concat([x, hidden], axis=-1)
            input_gate = (joined @ self.wi + self.bi).sigmoid()
            forget_gate = (joined @ self.wf + self.bf).sigmoid()
            output_gate = (joined @ self.wo + self.bo).sigmoid()
            candidate = (joined @ self.wg + self.bg).tanh()
            new_cell = cell * forget_gate + candidate * input_gate
            new_hidden = new_cell.tanh() * output_gate
            cell = new_cell * keep + cell * (1.0 - keep)
            hidden = new_hidden * keep + hidden * (1.0 - keep)
        return hidden @ self.wout + self.bout


# --- 5. TCN ------------------------------------------------------------------


@dataclass
class TCNBaseline(_TorchLikeModule):
    """Causal 1-D convolution over the sequence, then max-pool.

    Parallel local temporal modelling: no recurrence, fixed receptive field.
    """

    name: str = "tcn"
    kernel: int = 3

    def _build(self, width: int) -> None:
        if self.params:
            return
        self.wc = self._parameter(width * self.kernel, self.hidden)
        self.bc = self._bias(self.hidden)
        self.wo = self._parameter(self.hidden, 1)
        self.bo = self._bias(1)

    def forward(self, batch: np.ndarray, mask: np.ndarray) -> Tensor:
        rows, steps, width = batch.shape
        padded = np.concatenate(
            [np.zeros((rows, self.kernel - 1, width)), batch], axis=1
        )
        windows = np.stack(
            [padded[:, i : i + self.kernel, :].reshape(rows, -1) for i in range(steps)],
            axis=1,
        )
        activations = []
        for step in range(steps):
            window = Tensor(windows[:, step, :])
            keep = Tensor(mask[:, step : step + 1])
            # Masked steps are driven to zero so the max-pool cannot select them.
            activations.append(((window @ self.wc + self.bc).relu()) * keep)
        pooled = activations[0]
        for activation in activations[1:]:
            larger = Tensor((activation.data > pooled.data).astype(np.float64))
            pooled = pooled * (1.0 - larger) + activation * larger
        return pooled @ self.wo + self.bo


# --- 6. Tiny Transformer -----------------------------------------------------


@dataclass
class TransformerBaseline(_TorchLikeModule):
    """Single-head self-attention with a learned positional signal."""

    name: str = "tiny-transformer"

    def _build(self, width: int) -> None:
        if self.params:
            return
        self.wq = self._parameter(width, self.hidden)
        self.wk = self._parameter(width, self.hidden)
        self.wv = self._parameter(width, self.hidden)
        self.wf = self._parameter(self.hidden, self.hidden)
        self.bf = self._bias(self.hidden)
        self.wo = self._parameter(self.hidden, 1)
        self.bo = self._bias(1)

    def forward(self, batch: np.ndarray, mask: np.ndarray) -> Tensor:
        rows, steps, width = batch.shape
        # Sinusoidal positions: fixed, so the comparison is not confounded by
        # an extra learned embedding the recurrent baselines do not get.
        positions = np.zeros((steps, width))
        index = np.arange(steps)[:, None]
        divisor = np.exp(np.arange(0, width, 2) * (-np.log(10000.0) / width))
        positions[:, 0::2] = np.sin(index * divisor)
        positions[:, 1::2] = np.cos(index * divisor)[:, : width // 2]

        flat = Tensor(
            (batch + positions[None, :, :]).reshape(rows * steps, width)
        )
        # Every projection stays inside the graph. Computing scores from .data
        # detaches wq/wk/wv and leaves the model unable to learn what to attend
        # to — it then scores barely above the base rate, which looks like
        # "attention does not help here" rather than "attention never trained".
        queries = (flat @ self.wq).reshape(rows, steps, self.hidden)
        keys = (flat @ self.wk).reshape(rows, steps, self.hidden)
        values = (flat @ self.wv).reshape(rows, steps, self.hidden)

        scores = bmm(queries, keys.transpose(0, 2, 1)) * (1.0 / np.sqrt(self.hidden))
        # Additive mask, so padded keys get no attention weight.
        scores = scores + Tensor(np.where(mask[:, None, :] > 0, 0.0, -1e9))
        weights = scores.log_softmax(axis=-1).exp()

        attended = bmm(weights, values)
        lengths = np.maximum(mask.sum(axis=1, keepdims=True), 1.0)
        pooled = (attended * Tensor(mask[..., None])).sum(axis=1) * Tensor(1.0 / lengths)
        hidden = (pooled @ self.wf + self.bf).relu()
        return hidden @ self.wo + self.bo


# --- 7. Selective SSM --------------------------------------------------------


@dataclass
class SSMBaseline(_TorchLikeModule):
    """Linear-time state space with input-dependent (selective) gating.

    A Mamba-like baseline in the sense that matters here: the decay and input
    gates are functions of the input, so the model chooses what propagates. Not
    an implementation of Mamba, and no claim to be one.
    """

    name: str = "selective-ssm"

    def _build(self, width: int) -> None:
        if self.params:
            return
        self.w_decay = self._parameter(width, self.hidden)
        self.b_decay = self._bias(self.hidden)
        self.w_in = self._parameter(width, self.hidden)
        self.b_in = self._bias(self.hidden)
        self.w_gate = self._parameter(width, self.hidden)
        self.b_gate = self._bias(self.hidden)
        self.wo = self._parameter(self.hidden, 1)
        self.bo = self._bias(1)

    def forward(self, batch: np.ndarray, mask: np.ndarray) -> Tensor:
        rows, steps, _ = batch.shape
        state = Tensor(np.zeros((rows, self.hidden)))
        for step in range(steps):
            x = Tensor(batch[:, step, :])
            keep = Tensor(mask[:, step : step + 1])
            decay = (x @ self.w_decay + self.b_decay).sigmoid()
            signal = (x @ self.w_in + self.b_in).tanh()
            gate = (x @ self.w_gate + self.b_gate).sigmoid()
            updated = state * decay + signal * gate
            state = updated * keep + state * (1.0 - keep)
        return state @ self.wo + self.bo


# --- 8. VQ prototype ---------------------------------------------------------


@dataclass
class VQPrototypeBaseline:
    """Discrete-prototype baseline: k-means over pooled features, then scoring.

    The honest control for DTL's Behaviour Atoms. If discrete prototypes help,
    this cheap version should already show some of that benefit; if it does not,
    that is evidence against the atom layer before DTL is even built.
    """

    name: str = "vq-prototype"
    clusters: int = 12
    iterations: int = 40
    seed: int = 7

    def __post_init__(self) -> None:
        self._centroids: np.ndarray | None = None
        self._risk: np.ndarray | None = None

    @staticmethod
    def _pool(dataset: Stage2Dataset) -> np.ndarray:
        batch, mask, _ = _pad(dataset.samples)
        lengths = np.maximum(mask.sum(axis=1, keepdims=True), 1.0)
        return (batch * mask[..., None]).sum(axis=1) / lengths

    def fit(self, dataset: Stage2Dataset) -> VQPrototypeBaseline:
        pooled = self._pool(dataset)
        rng = np.random.default_rng(self.seed)
        centroids = pooled[rng.choice(len(pooled), size=self.clusters, replace=False)]
        for _ in range(self.iterations):
            distances = np.linalg.norm(pooled[:, None, :] - centroids[None, :, :], axis=-1)
            assignment = np.argmin(distances, axis=1)
            for cluster in range(self.clusters):
                members = pooled[assignment == cluster]
                if len(members):
                    centroids[cluster] = members.mean(axis=0)
        self._centroids = centroids

        labels = np.array(dataset.labels)
        distances = np.linalg.norm(pooled[:, None, :] - centroids[None, :, :], axis=-1)
        assignment = np.argmin(distances, axis=1)
        # Laplace-smoothed per-prototype risk, so an empty cluster falls back to
        # the base rate instead of asserting 0.0.
        self._risk = np.array(
            [
                (labels[assignment == c].sum() + labels.mean())
                / ((assignment == c).sum() + 1.0)
                for c in range(self.clusters)
            ]
        )
        return self

    def predict_scores(self, dataset: Stage2Dataset) -> list[float]:
        if self._centroids is None or self._risk is None:
            return [0.0] * len(dataset)
        pooled = self._pool(dataset)
        distances = np.linalg.norm(
            pooled[:, None, :] - self._centroids[None, :, :], axis=-1
        )
        assignment = np.argmin(distances, axis=1)
        return [float(self._risk[a]) for a in assignment]

    def resource_profile(self) -> dict[str, Any]:
        size = 0 if self._centroids is None else int(self._centroids.size)
        return {
            "parameters": size,
            "model_bytes_fp32": size * 4,
            "hidden": self.clusters,
            "final_loss": None,
        }


@dataclass
class PhiOracleBaseline:
    """The complexity sanity check (spec section 28): no learning at all.

    Scores a session by the largest single-transition ΔΦ it contains. Stage 1
    computes ΔΦ against the *lineage's* accumulated state (ADR-0005), so a
    lineage that completes a dangerous capability combination produces one large
    value and three unrelated processes each doing one step do not.

    This measures how much of the task Stage 1's representation already solves
    before any Stage 2 model is involved. If it matches the learned models, the
    learning is not where the value is — and that is worth knowing before
    building Behaviour Atoms on top of it.
    """

    name: str = "phi-oracle"

    def fit(self, dataset: Stage2Dataset) -> PhiOracleBaseline:
        return self  # nothing to learn

    def predict_scores(self, dataset: Stage2Dataset) -> list[float]:
        index = NEED_SIGNAL_INDICES["delta_phi"]
        return [
            max((step.features[index] for step in sample.steps), default=0.0)
            for sample in dataset.samples
        ]

    def resource_profile(self) -> dict[str, Any]:
        return {"parameters": 0, "model_bytes_fp32": 0, "hidden": 0, "final_loss": None}


BASELINE_REGISTRY: dict[str, type] = {
    "phi-oracle": PhiOracleBaseline,
    "markov-bigram": MarkovBaseline,
    "mlp-pooled": MLPBaseline,
    "gru": GRUBaseline,
    "lstm": LSTMBaseline,
    "tcn": TCNBaseline,
    "tiny-transformer": TransformerBaseline,
    "selective-ssm": SSMBaseline,
    "vq-prototype": VQPrototypeBaseline,
}


def build_baselines(*, hidden: int = 32, epochs: int = DEFAULT_EPOCHS) -> list[Any]:
    """Instantiate every baseline with identical training budget."""
    return [
        PhiOracleBaseline(),
        MarkovBaseline(),
        MLPBaseline(name="mlp-pooled", hidden=hidden, epochs=epochs),
        GRUBaseline(name="gru", hidden=hidden, epochs=epochs),
        LSTMBaseline(name="lstm", hidden=hidden, epochs=epochs),
        TCNBaseline(name="tcn", hidden=hidden, epochs=epochs),
        TransformerBaseline(name="tiny-transformer", hidden=hidden, epochs=epochs),
        SSMBaseline(name="selective-ssm", hidden=hidden, epochs=epochs),
        VQPrototypeBaseline(),
    ]
