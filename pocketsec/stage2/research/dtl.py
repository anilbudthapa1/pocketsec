"""D2.3 + D2.4 + D2.5 — the trainable DTL core (ADR-0008: research only).

Three mechanisms, each an independently ablatable hypothesis:

**D2.3 Multi-timescale state.** ``z = [z_fast, z_session, z_host, z_epoch,
z_causal, z_uncertainty]``. Six blocks on different timescales, each with its
own update and decay. The claim under test is that factorising the state beats a
single monolithic hidden vector of the same total size — an event should not
force every block to wake.

**D2.4 Need-to-Compute router.** ``Need = f(novelty, Φ, uncertainty,
responsibility, prediction error)`` produces per-block wake gates and an
execution path P0–P4. The gates are soft during training (so they are
learnable) and hard-thresholded at inference (so they actually save compute).
The headline metric is the *distribution* of events across paths, not latency.

**D2.5 Multi-head predictive engine.** Eight heads produce a structured
**surprise vector**, not a scalar anomaly score. Two events with equal aggregate
surprise can differ radically: one temporally odd but harmless, one an
improbable privilege→credential transition. Downstream risk uses the direction
of surprise, not only its magnitude.

Detection is derived from prediction: risk comes from how badly the learned
future model was violated, in which directions. That is the Stage 2 thesis, and
it is why DTL is trained on next-transition prediction as well as on the label.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import numpy as np

from pocketsec.stage1.ssir.relations import Relation, RelationFamily
from pocketsec.stage1.state.security_state import DIMENSIONS
from pocketsec.stage2.core_ids import PATH_COST_UNITS, ExecutionPath
from pocketsec.stage2.dataset import Stage2Dataset, Stage2Sample
from pocketsec.stage2.encoder.ssir_encoder import NEED_SIGNAL_INDICES
from pocketsec.stage2.research.autograd import (
    Tensor,
    binary_cross_entropy,
    normalised_bce,
    normalised_cross_entropy,
    concat,
    cross_entropy,
    sigmoid,
    softmax,
)

__all__ = ["DTL_BLOCKS", "DTLConfig", "DTLModel", "SurpriseVector"]

#: (name, dimension share, decay). Decay is per-step multiplicative retention
#: when a block is NOT woken: fast state forgets quickly, host state persists.
DTL_BLOCKS: tuple[tuple[str, float, float], ...] = (
    ("fast", 0.30, 0.50),
    ("session", 0.25, 0.85),
    ("host", 0.15, 0.97),
    ("epoch", 0.10, 0.99),
    ("causal", 0.15, 0.90),
    ("uncertainty", 0.05, 0.80),
)

_N_RELATIONS = len(Relation)
_N_FAMILIES = len(RelationFamily)
_N_DIMENSIONS = len(DIMENSIONS)
_N_TIME_BUCKETS = 16


@dataclass(frozen=True, slots=True)
class DTLConfig:
    latent: int = 48
    #: Router gate above which a block is considered awake at inference.
    wake_threshold: float = 0.5
    epochs: int = 60
    learning_rate: float = 0.05
    batch_size: int = 16
    seed: int = 7
    #: Loss weights. Ablated individually (spec section 26); no head survives
    #: because it sounds sophisticated.
    w_detect: float = 1.0
    w_relation: float = 0.5
    w_family: float = 0.25
    w_delta: float = 0.5
    w_time: float = 0.25
    w_phi: float = 0.5
    #: Penalty on the mean wake gate: compute is a first-class loss term, so
    #: the router is pushed to sleep unless waking earns its cost.
    w_wake: float = 0.05

    def block_sizes(self) -> dict[str, int]:
        sizes = {
            name: max(2, int(round(self.latent * share)))
            for name, share, _ in DTL_BLOCKS
        }
        # Absorb rounding drift into the largest block so the total is exact.
        drift = self.latent - sum(sizes.values())
        sizes["fast"] += drift
        return sizes


@dataclass(frozen=True, slots=True)
class SurpriseVector:
    """Structured surprise (spec section 9). Direction matters, not just size."""

    relation: float
    object_semantics: float
    state: float
    time: float
    causal: float
    epoch: float

    def as_tuple(self) -> tuple[float, ...]:
        return (
            self.relation,
            self.object_semantics,
            self.state,
            self.time,
            self.causal,
            self.epoch,
        )

    @property
    def magnitude(self) -> float:
        return float(np.linalg.norm(self.as_tuple()))

    @property
    def security_weighted(self) -> float:
        """Surprise weighted toward security-carrying directions.

        A temporally odd but capability-neutral event is not the same as an
        improbable privilege-to-credential transition, even at equal magnitude.
        """
        return 2.0 * self.state + 1.5 * self.causal + 1.0 * self.relation + 0.5 * (
            self.object_semantics + self.epoch + self.time
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "relation": round(self.relation, 4),
            "object_semantics": round(self.object_semantics, 4),
            "state": round(self.state, 4),
            "time": round(self.time, 4),
            "causal": round(self.causal, 4),
            "epoch": round(self.epoch, 4),
            "magnitude": round(self.magnitude, 4),
            "security_weighted": round(self.security_weighted, 4),
        }


def _pad(samples: tuple[Stage2Sample, ...]) -> dict[str, np.ndarray]:
    """Dense batch plus every per-step supervision target."""
    width = len(samples[0].steps[0].features)
    longest = max(len(s) for s in samples)
    rows = len(samples)

    batch = np.zeros((rows, longest, width))
    mask = np.zeros((rows, longest))
    labels = np.zeros((rows, 1))
    next_mask = np.zeros((rows, longest))
    next_relation = np.zeros((rows, longest), dtype=np.int64)
    next_family = np.zeros((rows, longest), dtype=np.int64)
    next_delta = np.zeros((rows, longest, _N_DIMENSIONS))
    next_time = np.zeros((rows, longest), dtype=np.int64)
    next_phi = np.zeros((rows, longest))

    for row, sample in enumerate(samples):
        labels[row, 0] = sample.label
        for step, encoded in enumerate(sample.steps):
            batch[row, step] = encoded.features
            mask[row, step] = 1.0
            if step + 1 < len(sample.steps):
                following = sample.steps[step + 1]
                next_mask[row, step] = 1.0
                next_relation[row, step] = following.relation
                next_family[row, step] = following.relation_family
                for bit in range(_N_DIMENSIONS):
                    next_delta[row, step, bit] = (
                        1.0 if following.state_delta_mask & (1 << bit) else 0.0
                    )
                next_time[row, step] = min(following.time_bucket, _N_TIME_BUCKETS - 1)
                next_phi[row, step] = min(1.0, max(0.0, following.delta_phi / 8.0))

    return {
        "batch": batch,
        "mask": mask,
        "labels": labels,
        "next_mask": next_mask,
        "next_relation": next_relation,
        "next_family": next_family,
        "next_delta": next_delta,
        "next_time": next_time,
        "next_phi": next_phi,
    }


class DTLModel:
    """The Dynamic Transition Lattice predictive core."""

    name = "dtl"

    def __init__(self, config: DTLConfig | None = None, **overrides: Any) -> None:
        self.config = config or DTLConfig(**overrides)
        self.params: list[Tensor] = []
        self._velocity: list[np.ndarray] = []
        self._losses: list[float] = []
        self._built = False
        self.block_sizes = self.config.block_sizes()
        self._wake_history: list[float] = []

    # --- construction ---------------------------------------------------

    def _parameter(self, *shape: int) -> Tensor:
        rng = np.random.default_rng(self.config.seed + len(self.params) * 17)
        limit = float(np.sqrt(1.0 / max(shape[0], 1)))
        tensor = Tensor(rng.uniform(-limit, limit, size=shape), requires_grad=True)
        self.params.append(tensor)
        return tensor

    def _bias(self, size: int) -> Tensor:
        tensor = Tensor(np.zeros((1, size)), requires_grad=True)
        self.params.append(tensor)
        return tensor

    def _build(self, width: int) -> None:
        if self._built:
            return
        latent = self.config.latent

        # D2.4 router: a deliberately tiny network over the five need signals.
        # It must be small enough that routing is cheaper than what it saves.
        self.router_w1 = self._parameter(5, 16)
        self.router_b1 = self._bias(16)
        self.router_w2 = self._parameter(16, len(DTL_BLOCKS))
        self.router_b2 = self._bias(len(DTL_BLOCKS))

        # D2.3 per-block GRU-style update.
        self.block_update: dict[str, tuple[Tensor, ...]] = {}
        for name, size in self.block_sizes.items():
            joined = width + size
            self.block_update[name] = (
                self._parameter(joined, size),  # candidate
                self._bias(size),
                self._parameter(joined, size),  # input gate
                self._bias(size),
            )

        # D2.5 heads over the concatenated state.
        self.head_relation = (self._parameter(latent, _N_RELATIONS), self._bias(_N_RELATIONS))
        self.head_family = (self._parameter(latent, _N_FAMILIES), self._bias(_N_FAMILIES))
        self.head_delta = (self._parameter(latent, _N_DIMENSIONS), self._bias(_N_DIMENSIONS))
        self.head_time = (self._parameter(latent, _N_TIME_BUCKETS), self._bias(_N_TIME_BUCKETS))
        self.head_phi = (self._parameter(latent, 1), self._bias(1))
        self.head_detect = (self._parameter(latent + 6, 1), self._bias(1))
        self._built = True

    # --- forward --------------------------------------------------------

    @staticmethod
    def _need_signals(batch: np.ndarray) -> np.ndarray:
        """Extract the five Need-to-Compute inputs from the encoded features.

        Indices follow the frozen encoder layout. Pulling them explicitly keeps
        the router's inputs auditable: it must route on novelty, potential,
        uncertainty, responsibility and error — not on whatever correlates.
        """
        return np.stack(
            [
                batch[..., NEED_SIGNAL_INDICES["novelty_peak"]],
                batch[..., NEED_SIGNAL_INDICES["delta_phi"]],
                batch[..., NEED_SIGNAL_INDICES["uncertainty"]],
                batch[..., NEED_SIGNAL_INDICES["responsibility"]],
                batch[..., NEED_SIGNAL_INDICES["state_delta_magnitude"]],
            ],
            axis=-1,
        )

    def forward(self, data: dict[str, np.ndarray], *, collect: bool = False) -> dict[str, Any]:
        batch, mask = data["batch"], data["mask"]
        rows, steps, _ = batch.shape
        self._build(batch.shape[-1])

        states = {
            name: Tensor(np.zeros((rows, size)))
            for name, size in self.block_sizes.items()
        }
        decays = {name: decay for name, _, decay in DTL_BLOCKS}
        need = self._need_signals(batch)

        step_logits: dict[str, list[Tensor]] = {
            "relation": [],
            "family": [],
            "delta": [],
            "time": [],
            "phi": [],
        }
        gate_values: list[np.ndarray] = []
        gate_tensors: list[Tensor] = []

        for step in range(steps):
            x = Tensor(batch[:, step, :])
            keep = Tensor(mask[:, step : step + 1])

            hidden = (Tensor(need[:, step, :]) @ self.router_w1 + self.router_b1).tanh()
            gates = (hidden @ self.router_w2 + self.router_b2).sigmoid()
            # Masked so padded steps cannot dilute the measured wake rate.
            gate_tensors.append(gates * keep)
            if collect:
                gate_values.append(gates.data.copy())

            for index, (name, _, _) in enumerate(DTL_BLOCKS):
                gate = gates.slice_cols(index, index + 1)
                candidate_w, candidate_b, input_w, input_b = self.block_update[name]
                joined = concat([x, states[name]], axis=-1)
                candidate = (joined @ candidate_w + candidate_b).tanh()
                write = (joined @ input_w + input_b).sigmoid()
                woken = states[name] * (1.0 - write) + candidate * write
                # A sleeping block decays rather than freezing: stale fast state
                # must not masquerade as current.
                slept = states[name] * decays[name]
                updated = woken * gate + slept * (1.0 - gate)
                states[name] = updated * keep + states[name] * (1.0 - keep)

            latent = concat([states[name] for name, _, _ in DTL_BLOCKS], axis=-1)
            step_logits["relation"].append(
                latent @ self.head_relation[0] + self.head_relation[1]
            )
            step_logits["family"].append(latent @ self.head_family[0] + self.head_family[1])
            step_logits["delta"].append(latent @ self.head_delta[0] + self.head_delta[1])
            step_logits["time"].append(latent @ self.head_time[0] + self.head_time[1])
            step_logits["phi"].append(latent @ self.head_phi[0] + self.head_phi[1])

        final_latent = concat([states[name] for name, _, _ in DTL_BLOCKS], axis=-1)
        surprise = self._surprise_summary(data, step_logits)
        detect_input = concat([final_latent, Tensor(surprise)], axis=-1)
        detect_logit = detect_input @ self.head_detect[0] + self.head_detect[1]

        # The wake penalty must see EVERY step. Penalising only the final step
        # leaves the router free to wake everything for the whole sequence at
        # almost no cost, which is exactly what it did.
        total_gate = gate_tensors[0]
        for gate_tensor in gate_tensors[1:]:
            total_gate = total_gate + gate_tensor
        live_steps = float(max(mask.sum(), 1.0))

        result: dict[str, Any] = {
            "detect_logit": detect_logit,
            "step_logits": step_logits,
            "wake_cost": total_gate.sum() * (1.0 / (live_steps * len(DTL_BLOCKS))),
        }
        if collect:
            result["gate_values"] = np.stack(gate_values, axis=1)
            result["surprise"] = surprise
            result["need"] = need
        return result

    @staticmethod
    def _surprise_summary(
        data: dict[str, np.ndarray], step_logits: dict[str, list[Tensor]]
    ) -> np.ndarray:
        """Per-sample structured surprise, computed outside the graph.

        Surprise is a *measurement of* the prediction, not a thing to
        backpropagate through: gradients flow via the head losses. Feeding it to
        the detection head as a constant keeps the two signals separable, which
        is what makes the "does prediction produce detection?" ablation clean.
        """
        next_mask = data["next_mask"]
        rows, steps = next_mask.shape
        out = np.zeros((rows, 6))
        counts = np.maximum(next_mask.sum(axis=1), 1.0)

        for step in range(steps):
            active = next_mask[:, step]
            if not active.any():
                continue
            relation_p = softmax(step_logits["relation"][step].data, axis=-1)
            picked = relation_p[np.arange(rows), data["next_relation"][:, step]]
            out[:, 0] += active * -np.log(np.clip(picked, 1e-9, 1.0))

            family_p = softmax(step_logits["family"][step].data, axis=-1)
            picked_family = family_p[np.arange(rows), data["next_family"][:, step]]
            out[:, 1] += active * -np.log(np.clip(picked_family, 1e-9, 1.0))

            delta_p = 1.0 / (1.0 + np.exp(-step_logits["delta"][step].data))
            target = data["next_delta"][:, step, :]
            bce = -(
                target * np.log(np.clip(delta_p, 1e-9, 1.0))
                + (1 - target) * np.log(np.clip(1 - delta_p, 1e-9, 1.0))
            ).mean(axis=-1)
            out[:, 2] += active * bce

            time_p = softmax(step_logits["time"][step].data, axis=-1)
            picked_time = time_p[np.arange(rows), data["next_time"][:, step]]
            out[:, 3] += active * -np.log(np.clip(picked_time, 1e-9, 1.0))

            phi_pred = 1.0 / (1.0 + np.exp(-step_logits["phi"][step].data[:, 0]))
            out[:, 4] += active * np.abs(phi_pred - data["next_phi"][:, step])

        out[:, 5] = 0.0  # epoch consistency: reserved, measured in D2.12
        return out / counts[:, None]

    # --- training -------------------------------------------------------

    def fit(self, dataset: Stage2Dataset) -> DTLModel:
        """Mini-batch SGD, matching the baselines' budget exactly."""
        data = _pad(dataset.samples)
        self._build(data["batch"].shape[-1])
        self._velocity = [np.zeros_like(p.data) for p in self.params]

        rows = len(data["batch"])
        size = max(1, min(self.config.batch_size, rows))
        rng = np.random.default_rng(self.config.seed)

        for _ in range(self.config.epochs):
            order = rng.permutation(rows)
            epoch_loss = 0.0
            batches = 0
            for start in range(0, rows, size):
                index = order[start : start + size]
                chunk = {k: v[index] for k, v in data.items()}
                for parameter in self.params:
                    parameter.zero_grad()
                loss = self._loss(chunk, self.forward(chunk))
                loss.backward()
                self._step()
                epoch_loss += float(loss.data)
                batches += 1
            self._losses.append(epoch_loss / max(batches, 1))
        return self

    def _loss(self, data: dict[str, np.ndarray], output: dict[str, Any]) -> Tensor:
        cfg = self.config
        loss = normalised_bce(output["detect_logit"], data["labels"]) * cfg.w_detect

        next_mask = data["next_mask"]
        active_steps = [s for s in range(next_mask.shape[1]) if next_mask[:, s].any()]
        for step in active_steps:
            rows = np.flatnonzero(next_mask[:, step])
            if rows.size == 0:
                continue
            scale = 1.0 / len(active_steps)
            loss = loss + normalised_cross_entropy(
                output["step_logits"]["relation"][step],
                data["next_relation"][:, step],
                _N_RELATIONS,
            ) * (cfg.w_relation * scale)
            loss = loss + normalised_cross_entropy(
                output["step_logits"]["family"][step], data["next_family"][:, step],
                _N_FAMILIES,
            ) * (cfg.w_family * scale)
            loss = loss + normalised_bce(
                output["step_logits"]["delta"][step], data["next_delta"][:, step, :]
            ) * (cfg.w_delta * scale)
            loss = loss + normalised_cross_entropy(
                output["step_logits"]["time"][step], data["next_time"][:, step],
                _N_TIME_BUCKETS,
            ) * (cfg.w_time * scale)
            loss = loss + normalised_bce(
                output["step_logits"]["phi"][step],
                data["next_phi"][:, step].reshape(-1, 1),
            ) * (cfg.w_phi * scale)

        # Compute is a loss term, not an afterthought.
        loss = loss + output["wake_cost"] * cfg.w_wake
        return loss

    def _step(self) -> None:
        for index, parameter in enumerate(self.params):
            if parameter.grad is None:
                continue
            gradient = np.clip(parameter.grad, -5.0, 5.0)
            self._velocity[index] = 0.9 * self._velocity[index] + gradient
            parameter.data -= self.config.learning_rate * self._velocity[index]

    # --- inference ------------------------------------------------------

    def predict_scores(self, dataset: Stage2Dataset) -> list[float]:
        data = _pad(dataset.samples)
        output = self.forward(data)
        return [float(v) for v in sigmoid(output["detect_logit"].data).reshape(-1)]

    def route(self, dataset: Stage2Dataset) -> dict[str, Any]:
        """DTL-F02 at inference: hard gates and the execution-path histogram."""
        data = _pad(dataset.samples)
        output = self.forward(data, collect=True)
        gates, mask = output["gate_values"], data["mask"]
        awake = (gates >= self.config.wake_threshold) * mask[..., None]
        total_steps = float(mask.sum())

        histogram = self.path_histogram(output["need"], mask)
        cost = sum(
            histogram[path.value] * PATH_COST_UNITS[path] for path in ExecutionPath
        ) / max(total_steps, 1.0)

        return {
            "mean_blocks_awake": float(awake.sum() / max(total_steps, 1.0)),
            "compute_units_per_event": float(cost),
            "path_fractions": {
                key: round(value / max(total_steps, 1.0), 4)
                for key, value in histogram.items()
            },
            "block_wake_rate": {
                name: float(awake[..., index].sum() / max(total_steps, 1.0))
                for index, (name, _, _) in enumerate(DTL_BLOCKS)
            },
            "path_histogram": histogram,
            "total_steps": int(total_steps),
        }

    @staticmethod
    def path_histogram(need: np.ndarray, mask: np.ndarray) -> dict[str, int]:
        """DTL-F02 path policy: Need determines the execution path.

        A deterministic, auditable policy rather than a learned head. There is
        no ground-truth label for "which path should this event have taken", so
        a learned head would be fitting noise — and in an earlier version it did
        exactly that, emitting paths with no supervision behind them.

        Thresholds follow spec section 6: routine known behaviour takes the
        cheap path; novelty, consequence and uncertainty buy more compute.
        """
        novelty, phi, uncertainty, responsibility, delta = (
            need[..., 0],
            need[..., 1],
            need[..., 2],
            need[..., 3],
            need[..., 4],
        )
        score = (
            0.35 * novelty
            + 0.25 * phi
            + 0.20 * uncertainty
            + 0.15 * responsibility
            + 0.05 * delta
        )
        histogram: dict[str, int] = {path.value: 0 for path in ExecutionPath}
        rows, steps = mask.shape
        for row in range(rows):
            for step in range(steps):
                if not mask[row, step]:
                    continue
                value = score[row, step]
                if value < 0.15:
                    path = ExecutionPath.P0_COMPILED
                elif value < 0.30:
                    path = ExecutionPath.P1_LATTICE
                elif value < 0.50:
                    path = ExecutionPath.P2_LOCAL
                elif value < 0.70:
                    path = ExecutionPath.P3_PREDICTIVE
                else:
                    path = ExecutionPath.P4_DEEP
                histogram[path.value] += 1
        return histogram

    def surprise_vectors(self, dataset: Stage2Dataset) -> list[SurpriseVector]:
        data = _pad(dataset.samples)
        raw = self.forward(data, collect=True)["surprise"]
        return [SurpriseVector(*row) for row in raw]

    def resource_profile(self) -> dict[str, Any]:
        parameters = sum(int(np.prod(p.data.shape)) for p in self.params)
        return {
            "parameters": parameters,
            "model_bytes_fp32": parameters * 4,
            "hidden": self.config.latent,
            "final_loss": round(self._losses[-1], 5) if self._losses else None,
            "block_sizes": dict(self.block_sizes),
        }
