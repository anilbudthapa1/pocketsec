"""A minimal reverse-mode autodiff over numpy (ADR-0008: research only).

Stage 2's gate requires at least five strong baselines trained under identical
inputs. Implementing backprop once, correctly, and sharing it across GRU, LSTM,
TCN, Transformer and SSM is the only way to be confident that a baseline lost on
its merits rather than on a bug in its hand-written gradients.

Deliberately small: vectorised reverse-mode over ``numpy`` arrays, with only the
operations these baselines need. There is no graph optimisation, no GPU, and no
attempt at generality. Correctness is checked against finite differences in
``tests/test_stage2_autograd.py`` — an autodiff nobody gradient-checked is a
silent source of wrong conclusions.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from typing import Any

import numpy as np

__all__ = [
    "Tensor",
    "binary_cross_entropy",
    "bmm",
    "concat",
    "cross_entropy",
    "relu",
    "sigmoid",
    "softmax",
    "tanh",
    "zeros_like_params",
]


class Tensor:
    """A node in the autodiff graph."""

    __slots__ = ("data", "grad", "requires_grad", "_backward", "_parents", "_op")

    def __init__(
        self,
        data: np.ndarray | Sequence[Any] | float,
        *,
        requires_grad: bool = False,
        parents: tuple[Tensor, ...] = (),
        op: str = "",
    ) -> None:
        self.data = np.asarray(data, dtype=np.float64)
        self.requires_grad = requires_grad
        self.grad: np.ndarray | None = None
        self._backward: Callable[[], None] = lambda: None
        self._parents = parents
        self._op = op

    # --- graph plumbing -------------------------------------------------

    @property
    def shape(self) -> tuple[int, ...]:
        return self.data.shape

    def _child(
        self, data: np.ndarray, parents: tuple[Tensor, ...], op: str
    ) -> Tensor:
        return Tensor(
            data,
            requires_grad=any(p.requires_grad for p in parents),
            parents=parents,
            op=op,
        )

    def _accumulate(self, gradient: np.ndarray) -> None:
        if not self.requires_grad:
            return
        self.grad = gradient if self.grad is None else self.grad + gradient

    def zero_grad(self) -> None:
        self.grad = None

    def backward(self) -> None:
        """Seed a scalar output with 1.0 and propagate in reverse topo order."""
        if self.data.size != 1:
            raise ValueError("backward() requires a scalar output")

        ordered: list[Tensor] = []
        seen: set[int] = set()

        def visit(node: Tensor) -> None:
            if id(node) in seen:
                return
            seen.add(id(node))
            for parent in node._parents:
                visit(parent)
            ordered.append(node)

        visit(self)
        self.grad = np.ones_like(self.data)
        for node in reversed(ordered):
            node._backward()

    # --- operations -----------------------------------------------------

    def __add__(self, other: Tensor | float) -> Tensor:
        other = other if isinstance(other, Tensor) else Tensor(other)
        out = self._child(self.data + other.data, (self, other), "add")

        def _backward() -> None:
            if out.grad is None:
                return
            self._accumulate(_unbroadcast(out.grad, self.data.shape))
            other._accumulate(_unbroadcast(out.grad, other.data.shape))

        out._backward = _backward
        return out

    def __mul__(self, other: Tensor | float) -> Tensor:
        other = other if isinstance(other, Tensor) else Tensor(other)
        out = self._child(self.data * other.data, (self, other), "mul")

        def _backward() -> None:
            if out.grad is None:
                return
            self._accumulate(_unbroadcast(out.grad * other.data, self.data.shape))
            other._accumulate(_unbroadcast(out.grad * self.data, other.data.shape))

        out._backward = _backward
        return out

    def __sub__(self, other: Tensor | float) -> Tensor:
        return self + (other if isinstance(other, Tensor) else Tensor(other)) * -1.0

    def __rsub__(self, other: float) -> Tensor:
        return Tensor(other) + self * -1.0

    __radd__ = __add__
    __rmul__ = __mul__

    def __neg__(self) -> Tensor:
        return self * -1.0

    def matmul(self, other: Tensor) -> Tensor:
        out = self._child(self.data @ other.data, (self, other), "matmul")

        def _backward() -> None:
            if out.grad is None:
                return
            self._accumulate(out.grad @ other.data.T)
            other._accumulate(self.data.T @ out.grad)

        out._backward = _backward
        return out

    __matmul__ = matmul

    def sum(self, axis: int | None = None, keepdims: bool = False) -> Tensor:
        out = self._child(
            np.sum(self.data, axis=axis, keepdims=keepdims), (self,), "sum"
        )

        def _backward() -> None:
            if out.grad is None:
                return
            gradient = out.grad
            if axis is not None and not keepdims:
                gradient = np.expand_dims(gradient, axis)
            self._accumulate(np.broadcast_to(gradient, self.data.shape).copy())

        out._backward = _backward
        return out

    def mean(self, axis: int | None = None) -> Tensor:
        divisor = self.data.size if axis is None else self.data.shape[axis]
        return self.sum(axis=axis) * (1.0 / divisor)

    def tanh(self) -> Tensor:
        value = np.tanh(self.data)
        out = self._child(value, (self,), "tanh")

        def _backward() -> None:
            if out.grad is not None:
                self._accumulate(out.grad * (1.0 - value**2))

        out._backward = _backward
        return out

    def sigmoid(self) -> Tensor:
        value = _stable_sigmoid(self.data)
        out = self._child(value, (self,), "sigmoid")

        def _backward() -> None:
            if out.grad is not None:
                self._accumulate(out.grad * value * (1.0 - value))

        out._backward = _backward
        return out

    def relu(self) -> Tensor:
        value = np.maximum(self.data, 0.0)
        out = self._child(value, (self,), "relu")

        def _backward() -> None:
            if out.grad is not None:
                self._accumulate(out.grad * (self.data > 0.0))

        out._backward = _backward
        return out

    def log_softmax(self, axis: int = -1) -> Tensor:
        shifted = self.data - np.max(self.data, axis=axis, keepdims=True)
        log_sum = np.log(np.sum(np.exp(shifted), axis=axis, keepdims=True))
        value = shifted - log_sum
        out = self._child(value, (self,), "log_softmax")

        def _backward() -> None:
            if out.grad is None:
                return
            probabilities = np.exp(value)
            self._accumulate(
                out.grad - probabilities * np.sum(out.grad, axis=axis, keepdims=True)
            )

        out._backward = _backward
        return out

    def index_select(self, indices: np.ndarray, axis: int = 0) -> Tensor:
        out = self._child(np.take(self.data, indices, axis=axis), (self,), "index")

        def _backward() -> None:
            if out.grad is None:
                return
            gradient = np.zeros_like(self.data)
            np.add.at(gradient, indices, out.grad)
            self._accumulate(gradient)

        out._backward = _backward
        return out

    def slice_rows(self, start: int, stop: int) -> Tensor:
        out = self._child(self.data[start:stop], (self,), "slice")

        def _backward() -> None:
            if out.grad is None:
                return
            gradient = np.zeros_like(self.data)
            gradient[start:stop] = out.grad
            self._accumulate(gradient)

        out._backward = _backward
        return out


    def reshape(self, *shape: int) -> Tensor:
        original = self.data.shape
        out = self._child(self.data.reshape(shape), (self,), "reshape")

        def _backward() -> None:
            if out.grad is not None:
                self._accumulate(out.grad.reshape(original))

        out._backward = _backward
        return out

    def transpose(self, *axes: int) -> Tensor:
        out = self._child(np.transpose(self.data, axes), (self,), "transpose")
        inverse = np.argsort(axes)

        def _backward() -> None:
            if out.grad is not None:
                self._accumulate(np.transpose(out.grad, inverse))

        out._backward = _backward
        return out

    def exp(self) -> Tensor:
        value = np.exp(np.clip(self.data, -60.0, 60.0))
        out = self._child(value, (self,), "exp")

        def _backward() -> None:
            if out.grad is not None:
                self._accumulate(out.grad * value)

        out._backward = _backward
        return out


def bmm(left: Tensor, right: Tensor) -> Tensor:
    """Batched matmul: (B, N, M) @ (B, M, P) -> (B, N, P).

    Needed so attention scores stay inside the graph. Computing them from
    ``.data`` detaches the query/key/value projections, which silently leaves
    an attention baseline unable to learn what to attend to.
    """
    out = Tensor(
        left.data @ right.data,
        requires_grad=left.requires_grad or right.requires_grad,
        parents=(left, right),
        op="bmm",
    )

    def _backward() -> None:
        if out.grad is None:
            return
        left._accumulate(out.grad @ np.transpose(right.data, (0, 2, 1)))
        right._accumulate(np.transpose(left.data, (0, 2, 1)) @ out.grad)

    out._backward = _backward
    return out


def _unbroadcast(gradient: np.ndarray, shape: tuple[int, ...]) -> np.ndarray:
    """Reduce a broadcast gradient back to ``shape``."""
    while gradient.ndim > len(shape):
        gradient = gradient.sum(axis=0)
    for axis, size in enumerate(shape):
        if size == 1 and gradient.shape[axis] != 1:
            gradient = gradient.sum(axis=axis, keepdims=True)
    return gradient


def _stable_sigmoid(x: np.ndarray) -> np.ndarray:
    positive = x >= 0
    out = np.empty_like(x)
    out[positive] = 1.0 / (1.0 + np.exp(-x[positive]))
    exp_x = np.exp(x[~positive])
    out[~positive] = exp_x / (1.0 + exp_x)
    return out


def concat(tensors: Sequence[Tensor], axis: int = -1) -> Tensor:
    data = np.concatenate([t.data for t in tensors], axis=axis)
    out = Tensor(
        data,
        requires_grad=any(t.requires_grad for t in tensors),
        parents=tuple(tensors),
        op="concat",
    )
    sizes = [t.data.shape[axis] for t in tensors]

    def _backward() -> None:
        if out.grad is None:
            return
        offset = 0
        for tensor, size in zip(tensors, sizes, strict=True):
            index = [slice(None)] * out.grad.ndim
            index[axis] = slice(offset, offset + size)
            tensor._accumulate(out.grad[tuple(index)])
            offset += size

    out._backward = _backward
    return out


def cross_entropy(logits: Tensor, targets: np.ndarray) -> Tensor:
    """Mean negative log-likelihood over a batch of integer targets.

    Implemented as a single op with its analytic gradient
    ``(softmax(x) - onehot(y)) / N`` rather than composed from log_softmax and
    a gather. Composing it is where the subtle indexing bugs live, and a wrong
    loss gradient would quietly handicap whichever baselines used it most.
    """
    targets = np.asarray(targets, dtype=np.int64)
    probabilities = softmax(logits.data, axis=-1)
    rows = np.arange(len(targets))
    picked = np.clip(probabilities[rows, targets], 1e-12, 1.0)
    value = float(-np.mean(np.log(picked)))

    out = Tensor(value, requires_grad=logits.requires_grad, parents=(logits,), op="ce")

    def _backward() -> None:
        if out.grad is None:
            return
        gradient = probabilities.copy()
        gradient[rows, targets] -= 1.0
        logits._accumulate(gradient * (float(out.grad) / len(targets)))

    out._backward = _backward
    return out


def binary_cross_entropy(logits: Tensor, targets: np.ndarray) -> Tensor:
    """Stable BCE-with-logits, averaged. Gradient is ``(sigmoid(x) - y) / N``."""
    targets = np.asarray(targets, dtype=np.float64).reshape(logits.data.shape)
    stable = (
        np.maximum(logits.data, 0.0)
        - logits.data * targets
        + np.log1p(np.exp(-np.abs(logits.data)))
    )
    value = float(np.mean(stable))
    out = Tensor(value, requires_grad=logits.requires_grad, parents=(logits,), op="bce")

    def _backward() -> None:
        if out.grad is None:
            return
        gradient = _stable_sigmoid(logits.data) - targets
        logits._accumulate(gradient * (float(out.grad) / targets.size))

    out._backward = _backward
    return out


def softmax(values: np.ndarray, axis: int = -1) -> np.ndarray:
    shifted = values - np.max(values, axis=axis, keepdims=True)
    exponent = np.exp(shifted)
    return exponent / np.sum(exponent, axis=axis, keepdims=True)


def sigmoid(values: np.ndarray) -> np.ndarray:
    return _stable_sigmoid(np.asarray(values, dtype=np.float64))


def tanh(values: np.ndarray) -> np.ndarray:
    return np.tanh(values)


def relu(values: np.ndarray) -> np.ndarray:
    return np.maximum(values, 0.0)


def zeros_like_params(params: Iterable[Tensor]) -> None:
    for parameter in params:
        parameter.zero_grad()
