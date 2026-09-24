"""DTL-C — the convolutional DTL core (ADR-0009).

The recurrent DTL core failed Stage 2 falsification criterion 1: a plain TCN
scored 1.0000 against DTL's 0.4736 on long-horizon sessions, at half the
parameters. Spec section 36 anticipates exactly this outcome and requires
simplification rather than persistence.

**What changed.** The six multi-timescale state blocks stop being recurrent
cells and become **dilated causal convolutions**, one dilation per timescale:

    z_fast        dilation  1    process/file/network micro-dynamics
    z_uncertainty dilation  2    what the model does not yet know
    z_session     dilation  4    login/session/privilege trajectory
    z_causal      dilation  8    the security-carrying causal spine
    z_host        dilation 16    stable host behavioural dynamics
    z_epoch       dilation 32    configuration regime

This is the same factorisation the spec describes — independent blocks on
separate timescales, each gated — implemented with the inductive bias the
measurement actually supports. A dilation-16 kernel reaches 32 events back
without having to carry anything through 90 steps of gradient.

**What was kept**, because none of it was what failed:

* the Need-to-Compute router (DTL-F02), now gating *branches* rather than cells,
* per-timescale decay, as a learned mix between branch output and carried mean,
* the multi-head predictive engine and the structured surprise vector,
* the compute term in the loss.

**What was added**: max-pooling over time. That is the mechanism that lets a
short escalating chain be found anywhere inside a long benign session, and its
absence is the single clearest reason the recurrent core lost.

Every retained component is ablated in `experiments.ablation_study`. Anything
that does not earn its keep is removed, per acceptance criterion 12.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np

from pocketsec.stage1.ssir.relations import Relation, RelationFamily
from pocketsec.stage1.state.security_state import DIMENSIONS
from pocketsec.stage2.core_ids import PATH_COST_UNITS, ExecutionPath
from pocketsec.stage2.dataset import Stage2Dataset
from pocketsec.stage2.encoder.ssir_encoder import NEED_SIGNAL_INDICES
from pocketsec.stage2.research.autograd import (
    Tensor,
    binary_cross_entropy,
    normalised_bce,
    normalised_cross_entropy,
    concat,
    cross_entropy,
    sigmoid,
)
from pocketsec.stage2.research.dtl import DTLModel, SurpriseVector, _pad

__all__ = ["DTLC_BLOCKS", "DTLConvConfig", "DTLConvModel"]

#: (name, dimension share, dilation). Dilation *is* the timescale.
DTLC_BLOCKS: tuple[tuple[str, float, int], ...] = (
    ("fast", 0.25, 1),
    ("uncertainty", 0.10, 2),
    ("session", 0.20, 4),
    ("causal", 0.15, 8),
    ("host", 0.20, 16),
    ("epoch", 0.10, 32),
)

_N_RELATIONS = len(Relation)
_N_FAMILIES = len(RelationFamily)
_N_DIMENSIONS = len(DIMENSIONS)
_N_TIME_BUCKETS = 16
_KERNEL = 3


@dataclass(frozen=True, slots=True)
class DTLConvConfig:
    latent: int = 48
    epochs: int = 30
    learning_rate: float = 0.05
    batch_size: int = 16
    seed: int = 7
    wake_threshold: float = 0.5
    #: Which mechanisms are active. Ablation flips these off one at a time.
    #: Measured HARMFUL on the ambiguous corpus (-0.115 PR-AUC) and neutral
    #: elsewhere, so acceptance criterion 12 says remove it. Retained as an
    #: option for retest, defaulted off.
    use_router: bool = False
    #: Measured beneficial: +0.068 PR-AUC on the ambiguous corpus.
    use_multiscale: bool = True
    #: Measured HARMFUL on the ambiguous corpus (-0.073 PR-AUC). Same treatment
    #: as the router.
    use_surprise: bool = False
    #: The load-bearing component: +0.046 on ambiguous, +0.66 on long-horizon.
    use_maxpool: bool = True
    #: Pool per ACTOR LINEAGE, then take the worst lineage.
    #:
    #: Measured to add NOTHING once the attribution corpus was corrected
    #: (1.0000 with and without). The reason is a positive result for Stage 1:
    #: its lineage-scoped state calculus (ADR-0005) already performs the
    #: attribution, so a single transition's delta-phi encodes "this actor,
    #: given its own history, just did something consequential". Stage 2 does
    #: not need to re-derive it. Defaulted off per acceptance criterion 12;
    #: retained for retest on a corpus where Stage 1 cannot attribute.
    use_lineage_pool: bool = False
    #: Maximum lineage slots tracked per session. Bounded, like everything else.
    max_lineages: int = 8
    #: Train the predictive heads on a DETACHED representation.
    #: Joint training on a shared representation measured -0.67 PR-AUC: the
    #: heads optimise the conv features for next-step prediction, which is
    #: incompatible with what detection needs. Detaching keeps the heads (and
    #: the surprise vector they produce) without letting them corrupt the
    #: features detection depends on.
    detach_heads: bool = True
    w_detect: float = 1.0
    w_relation: float = 0.5
    w_family: float = 0.25
    w_delta: float = 0.5
    w_time: float = 0.25
    w_phi: float = 0.5
    w_wake: float = 0.05

    def block_sizes(self) -> dict[str, int]:
        if not self.use_multiscale:
            # Ablation control: one branch at dilation 1 with the full budget,
            # so the comparison is capacity-matched rather than capacity-starved.
            return {"fast": self.latent}
        sizes = {
            name: max(2, int(round(self.latent * share)))
            for name, share, _ in DTLC_BLOCKS
        }
        sizes["fast"] += self.latent - sum(sizes.values())
        return sizes

    def dilations(self) -> dict[str, int]:
        if not self.use_multiscale:
            return {"fast": 1}
        return {name: dilation for name, _, dilation in DTLC_BLOCKS}


class DTLConvModel:
    """The convolutional Dynamic Transition Lattice core."""

    name = "dtl-conv"

    def __init__(self, config: DTLConvConfig | None = None, **overrides: Any) -> None:
        self.config = config or DTLConvConfig(**overrides)
        self.params: list[Tensor] = []
        self._velocity: list[np.ndarray] = []
        self._losses: list[float] = []
        self._built = False
        self.block_sizes = self.config.block_sizes()
        self.block_dilations = self.config.dilations()

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
        latent = sum(self.block_sizes.values())

        if self.config.use_router:
            self.router_w1 = self._parameter(5, 16)
            self.router_b1 = self._bias(16)
            self.router_w2 = self._parameter(16, len(self.block_sizes))
            self.router_b2 = self._bias(len(self.block_sizes))

        self.branch: dict[str, tuple[Tensor, Tensor]] = {}
        for name, size in self.block_sizes.items():
            self.branch[name] = (self._parameter(width * _KERNEL, size), self._bias(size))

        self.head_relation = (self._parameter(latent, _N_RELATIONS), self._bias(_N_RELATIONS))
        self.head_family = (self._parameter(latent, _N_FAMILIES), self._bias(_N_FAMILIES))
        self.head_delta = (self._parameter(latent, _N_DIMENSIONS), self._bias(_N_DIMENSIONS))
        self.head_time = (self._parameter(latent, _N_TIME_BUCKETS), self._bias(_N_TIME_BUCKETS))
        self.head_phi = (self._parameter(latent, 1), self._bias(1))

        detect_width = latent * (2 if self.config.use_maxpool else 1)
        if self.config.use_lineage_pool:
            detect_width += latent
        if self.config.use_surprise:
            detect_width += 6
        self.detect_w1 = self._parameter(detect_width, 32)
        self.detect_b1 = self._bias(32)
        self.detect_w2 = self._parameter(32, 1)
        self.detect_b2 = self._bias(1)
        self._built = True

    # --- forward --------------------------------------------------------

    @staticmethod
    def _need_signals(batch: np.ndarray) -> np.ndarray:
        return np.stack(
            [batch[..., NEED_SIGNAL_INDICES[k]] for k in
             ("novelty_peak", "delta_phi", "uncertainty", "responsibility",
              "state_delta_magnitude")],
            axis=-1,
        )

    @staticmethod
    def _dilated_windows(batch: np.ndarray, dilation: int) -> np.ndarray:
        """Causal dilated windows: (B, S, kernel*W).

        Left-padded with zeros so step *t* only ever sees steps <= t. A
        non-causal window would leak the future into the prediction heads.
        """
        rows, steps, width = batch.shape
        offsets = [(_KERNEL - 1 - i) * dilation for i in range(_KERNEL)]
        pieces = []
        for offset in offsets:
            if offset == 0:
                pieces.append(batch)
                continue
            padded = np.concatenate(
                [np.zeros((rows, offset, width)), batch[:, : steps - offset, :]], axis=1
            )
            pieces.append(padded)
        return np.concatenate(pieces, axis=-1)

    def forward(self, data: dict[str, np.ndarray], *, collect: bool = False) -> dict[str, Any]:
        batch, mask = data["batch"], data["mask"]
        rows, steps, width = batch.shape
        self._build(width)

        need = self._need_signals(batch)
        gates_per_block: dict[str, Tensor] = {}
        gate_values: np.ndarray | None = None

        if self.config.use_router:
            flat_need = Tensor(need.reshape(rows * steps, 5))
            hidden = (flat_need @ self.router_w1 + self.router_b1).tanh()
            gates = (hidden @ self.router_w2 + self.router_b2).sigmoid()
            for index, name in enumerate(self.block_sizes):
                gates_per_block[name] = gates.slice_cols(index, index + 1).reshape(
                    rows, steps, 1
                )
            if collect:
                gate_values = gates.data.reshape(rows, steps, -1)

        branch_outputs: list[Tensor] = []
        for name, size in self.block_sizes.items():
            windows = self._dilated_windows(batch, self.block_dilations[name])
            flat = Tensor(windows.reshape(rows * steps, width * _KERNEL))
            weight, bias = self.branch[name]
            activation = (flat @ weight + bias).relu().reshape(rows, steps, size)
            if self.config.use_router:
                activation = activation * gates_per_block[name]
            branch_outputs.append(activation)

        latent_seq = concat(branch_outputs, axis=-1)
        latent_width = sum(self.block_sizes.values())
        mask3 = Tensor(mask[..., None])
        masked = latent_seq * mask3

        lengths = np.maximum(mask.sum(axis=1, keepdims=True), 1.0)
        pooled_mean = masked.sum(axis=1) * Tensor(1.0 / lengths)

        parts = [pooled_mean]
        if self.config.use_maxpool:
            # Max over time is what finds a short chain anywhere in a long
            # session. Its absence is the clearest reason the recurrent core
            # lost, so it is a first-class component here.
            neg = np.where(mask[..., None] > 0, 0.0, -1e9)
            shifted = masked + Tensor(neg)
            selector = np.zeros((rows, steps, latent_width))
            arg = np.argmax(shifted.data, axis=1)
            for row in range(rows):
                for channel in range(latent_width):
                    selector[row, arg[row, channel], channel] = 1.0
            parts.append((latent_seq * Tensor(selector)).sum(axis=1))

        head_input = (
            Tensor(latent_seq.data) if self.config.detach_heads else latent_seq
        )
        if self.config.use_lineage_pool:
            parts.append(self._lineage_pool(latent_seq, data, rows, steps, latent_width))

        step_logits = self._heads(head_input, rows, steps, latent_width)
        surprise = DTLModel._surprise_summary(data, step_logits)
        if self.config.use_surprise:
            parts.append(Tensor(surprise))

        summary = concat(parts, axis=-1)
        detect_logit = (summary @ self.detect_w1 + self.detect_b1).relu() @ self.detect_w2 + self.detect_b2

        wake_cost = (
            (concat(list(gates_per_block.values()), axis=-1) * mask3).sum()
            * (1.0 / (max(float(mask.sum()), 1.0) * len(self.block_sizes)))
            if self.config.use_router
            else Tensor(0.0)
        )

        result: dict[str, Any] = {
            "detect_logit": detect_logit,
            "step_logits": step_logits,
            "wake_cost": wake_cost,
        }
        if collect:
            result["gate_values"] = gate_values
            result["surprise"] = surprise
            result["need"] = need
        return result

    def _lineage_pool(
        self,
        latent_seq: Tensor,
        data: dict[str, np.ndarray],
        rows: int,
        steps: int,
        width: int,
    ) -> Tensor:
        """Mean-pool within each lineage, then take the max across lineages.

        Two-stage by design. Pooling within a lineage accumulates what that one
        actor did across the whole session, however far apart its events sit.
        Taking the max across lineages asks the security question directly: is
        there *any* actor whose accumulated behaviour is alarming? A flat pool
        averages that actor away among its well-behaved neighbours.
        """
        slots = data["actor_slot"]
        mask = data["mask"]
        limit = self.config.max_lineages
        selector = np.zeros((rows, steps, width))
        best = np.full((rows, width), -1e18)
        per_slot: list[np.ndarray] = []

        for slot in range(limit):
            member = ((slots == slot) & (mask > 0)).astype(np.float64)
            count = np.maximum(member.sum(axis=1, keepdims=True), 1.0)
            pooled = (latent_seq.data * member[..., None]).sum(axis=1) / count
            pooled = np.where(member.sum(axis=1, keepdims=True) > 0, pooled, -1e18)
            per_slot.append(pooled)

        stacked = np.stack(per_slot, axis=0)
        winner = np.argmax(stacked, axis=0)
        for row in range(rows):
            for channel in range(width):
                slot = winner[row, channel]
                member = (slots[row] == slot) & (mask[row] > 0)
                total = member.sum()
                if total:
                    selector[row, member, channel] = 1.0 / total
        assert best is not None
        return (latent_seq * Tensor(selector)).sum(axis=1)

    def _heads(
        self, latent_seq: Tensor, rows: int, steps: int, width: int
    ) -> dict[str, list[Tensor]]:
        flat = latent_seq.reshape(rows * steps, width)
        out: dict[str, list[Tensor]] = {}
        for key, (weight, bias) in (
            ("relation", self.head_relation),
            ("family", self.head_family),
            ("delta", self.head_delta),
            ("time", self.head_time),
            ("phi", self.head_phi),
        ):
            projected = flat @ weight + bias
            columns = projected.shape[-1]
            reshaped = projected.reshape(rows, steps, columns)
            out[key] = [
                reshaped.slice_step(step).reshape(rows, columns) for step in range(steps)
            ]
        return out

    # --- training -------------------------------------------------------

    def fit(self, dataset: Stage2Dataset) -> DTLConvModel:
        data = _pad(dataset.samples)
        self._build(data["batch"].shape[-1])
        self._velocity = [np.zeros_like(p.data) for p in self.params]

        rows = len(data["batch"])
        size = max(1, min(self.config.batch_size, rows))
        rng = np.random.default_rng(self.config.seed)
        for _ in range(self.config.epochs):
            order = rng.permutation(rows)
            total, batches = 0.0, 0
            for start in range(0, rows, size):
                index = order[start : start + size]
                chunk = {k: v[index] for k, v in data.items()}
                for parameter in self.params:
                    parameter.zero_grad()
                loss = self._loss(chunk, self.forward(chunk))
                loss.backward()
                self._step()
                total += float(loss.data)
                batches += 1
            self._losses.append(total / max(batches, 1))
        return self

    def _loss(self, data: dict[str, np.ndarray], output: dict[str, Any]) -> Tensor:
        cfg = self.config
        loss = normalised_bce(output["detect_logit"], data["labels"]) * cfg.w_detect
        next_mask = data["next_mask"]
        active = [s for s in range(next_mask.shape[1]) if next_mask[:, s].any()]
        if active:
            scale = 1.0 / len(active)
            for step in active:
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
        return loss + output["wake_cost"] * cfg.w_wake

    def _step(self) -> None:
        for index, parameter in enumerate(self.params):
            if parameter.grad is None:
                continue
            gradient = np.clip(parameter.grad, -5.0, 5.0)
            self._velocity[index] = 0.9 * self._velocity[index] + gradient
            parameter.data -= self.config.learning_rate * self._velocity[index]

    # --- inference ------------------------------------------------------

    def predict_scores(self, dataset: Stage2Dataset) -> list[float]:
        output = self.forward(_pad(dataset.samples))
        return [float(v) for v in sigmoid(output["detect_logit"].data).reshape(-1)]

    def route(self, dataset: Stage2Dataset) -> dict[str, Any]:
        data = _pad(dataset.samples)
        output = self.forward(data, collect=True)
        mask = data["mask"]
        total = max(float(mask.sum()), 1.0)
        histogram = DTLModel.path_histogram(output["need"], mask)
        report: dict[str, Any] = {
            "path_fractions": {k: round(v / total, 4) for k, v in histogram.items()},
            "compute_units_per_event": round(
                sum(histogram[p.value] * PATH_COST_UNITS[p] for p in ExecutionPath) / total, 2
            ),
            "total_steps": int(total),
        }
        if output["gate_values"] is not None:
            awake = (output["gate_values"] >= self.config.wake_threshold) * mask[..., None]
            report["mean_blocks_awake"] = float(awake.sum() / total)
            report["block_wake_rate"] = {
                name: float(awake[..., index].sum() / total)
                for index, name in enumerate(self.block_sizes)
            }
        return report

    def surprise_vectors(self, dataset: Stage2Dataset) -> list[SurpriseVector]:
        raw = self.forward(_pad(dataset.samples), collect=True)["surprise"]
        return [SurpriseVector(*row) for row in raw]

    def resource_profile(self) -> dict[str, Any]:
        parameters = sum(int(np.prod(p.data.shape)) for p in self.params)
        return {
            "parameters": parameters,
            "model_bytes_fp32": parameters * 4,
            "hidden": self.config.latent,
            "final_loss": round(self._losses[-1], 5) if self._losses else None,
            "block_sizes": dict(self.block_sizes),
            "dilations": dict(self.block_dilations),
        }
