"""DTL-F03 — ``update_multiscale_state`` as a bounded per-lineage window.

ADR-0119. The recurrent DTL core is rejected (ADR-0009: TCN 1.0000 vs DTL 0.4736
on long-horizon sessions at half the parameters), and the accepted Stage 2 core
is a causal dilated convolution. A convolution does not carry state forward; it
reads a *window*. So the runtime side of DTL-F03 is a window store, and this
module deliberately refuses to be a recurrent cell: there is no hidden vector, no
timescale gate and no carried activation anywhere in it. Rebuilding those would
resurrect a design this repository has already measured and rejected.

What the window is *for*: `dilated_context` hands a caller exactly the taps that
`research/dtl_conv.py::_dilated_windows` builds offline, so a runtime inference
path and the research vehicle see the same shape at the same dilation. Step *t*
sees only steps ≤ *t*; a non-causal window would leak the future into a
prediction and there is a test pinning that at every dilation the core uses.

What it refuses to do:

* **It never keys on identity.** The lineage key is the root of the
  ``causal_signature`` / ``parent_signature`` chain, which Stage 1 builds from
  semantics alone (`stage1/causal/memory.py:55-70`) — no pid, no path, no
  command line, no ``display_name`` (ADR-0006, ADR-0007). A consequence worth
  stating: two behaviourally identical lineages share one key. That is the
  intended semantics, not a collision bug — ADR-0006 says semantics are earned by
  behaviour, so "did the same thing" is the same lineage as far as the model is
  concerned, and nothing here may separate them by process identity.
* **It never truncates silently.** Every window that dropped a step carries
  ``truncated=True`` and every dropped step is counted in
  ``WindowStats.truncated_steps``. That holds for **both** ways history is lost:
  the per-window step cap, and lineage eviction. Eviction used to be exempt —
  ``_evict_lineages`` incremented ``_evicted_lineages`` without adding the
  discarded steps to ``_truncated_steps``, and a lineage that reappeared got a
  fresh window with ``truncated=False``, so the window that had lost the most
  history was the one reporting none (S2-08). The Stage 0 bounded-window
  invariant is that truncation is explicit, not that it does not happen.
* **It never guesses its own footprint.** ``memory_bytes`` is summed from real
  payload, and the part that cannot be bounded (variable-length evidence
  locators) is reported separately rather than folded in and called bounded.

Stdlib only: this runs on the endpoint.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.ssir.transition import SSIRTransitionV1
from pocketsec.stage2.encoder.ssir_encoder import (
    FEATURE_WIDTH,
    EncodedTransition,
    encode_ssir_transition,
)

__all__ = [
    "DEFAULT_KERNEL",
    "MAX_LINEAGES",
    "MAX_WINDOW",
    "LineageWindow",
    "WindowStats",
    "WindowStore",
]

#: Hard ceiling on tracked lineages. Bounded endpoint state is a Stage 0
#: invariant, so this is a refusal limit and not a tuning hint: a store asked for
#: more raises rather than quietly allocating it.
MAX_LINEAGES: int = 64

#: Hard ceiling on steps retained per lineage. The widest receptive field the
#: accepted core uses is kernel 3 at dilation 32, i.e. 65 steps; 64 is one short
#: of that on purpose, because the alternative to an explicit truncation flag on
#: the deepest tap is an unbounded window.
MAX_WINDOW: int = 64

#: Kernel width of the accepted core (`research/dtl_conv.py::_KERNEL`).
DEFAULT_KERNEL: int = 3

#: Bytes per float payload slot, and per pointer in a tuple. Used to *measure*
#: rather than estimate; interpreter object headers are excluded and said to be
#: excluded, which makes `memory_bytes` a payload figure and a lower bound on RSS.
_FLOAT_BYTES: int = 8
_POINTER_BYTES: int = 8

#: The eight scalar target fields on `EncodedTransition` (relation,
#: relation_family, state_delta_mask, time_bucket, delta_phi,
#: object_property_mask, epoch_id, actor_slot).
_SCALAR_FIELDS: int = 8


def _is_chain_root(parent_signature: str) -> bool:
    """True when a transition starts a causal chain.

    Stage 1 writes ``"0" * 16`` for "no parent"
    (`stage1/compiler/semantic_compiler.py:292`), and `at_level` can blank the
    field entirely, so both shapes count as a root.
    """
    return not parent_signature or parent_signature.strip("0") == ""


def _step_bytes(encoded: EncodedTransition) -> int:
    """Fixed payload of one retained step, excluding evidence locators."""
    return (
        len(encoded.features) * (_FLOAT_BYTES + _POINTER_BYTES)
        + _SCALAR_FIELDS * _FLOAT_BYTES
        + len(encoded.evidence) * _POINTER_BYTES
    )


def _evidence_bytes(encoded: EncodedTransition) -> int:
    """Variable-length share of one retained step.

    Kept separate because it is the one part of this store that the store cannot
    bound: locator length is decided by Stage 1's evidence store, not here.
    """
    return sum(len(locator) for locator in encoded.evidence)


@dataclass(frozen=True, slots=True)
class WindowStats:
    """What the window store is holding, and what it threw away."""

    lineages: int
    transitions_held: int
    evicted_lineages: int
    truncated_steps: int
    memory_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "lineages": self.lineages,
            "transitions_held": self.transitions_held,
            "evicted_lineages": self.evicted_lineages,
            "truncated_steps": self.truncated_steps,
            "memory_bytes": self.memory_bytes,
        }


@dataclass(frozen=True, slots=True)
class LineageWindow:
    """The last ``<= MAX_WINDOW`` encoded steps of one causal lineage, oldest first."""

    #: Root of the causal-signature chain. Never a pid, a path or a name.
    lineage_key: str
    steps: tuple[EncodedTransition, ...]
    #: True once this window has dropped at least one step. Never reset.
    truncated: bool
    last_sequence: int

    def __post_init__(self) -> None:
        if not self.lineage_key:
            raise ContractError("lineage_key must be a non-empty causal signature")
        if len(self.steps) > MAX_WINDOW:
            raise ContractError(
                f"window holds {len(self.steps)} steps, ceiling is {MAX_WINDOW}"
            )
        if self.last_sequence < 0:
            raise ContractError(
                f"last_sequence must be non-negative, got {self.last_sequence}"
            )

    def features(self) -> tuple[tuple[float, ...], ...]:
        """The raw feature rows, oldest first. One row per retained step."""
        return tuple(step.features for step in self.steps)

    def dilated_context(
        self, dilation: int, kernel: int = DEFAULT_KERNEL
    ) -> tuple[tuple[float, ...], ...]:
        """Causal left-padded kernel window at ``dilation``, one row per step.

        Row *t* is the concatenation of the taps at ``t - (kernel-1)*dilation``
        … ``t - dilation``, ``t`` — widest tap first, matching
        ``research/dtl_conv.py::_dilated_windows`` so runtime and research read
        the same layout. Taps before the start of the window are zero padding,
        which is what makes step *t* unable to see step *t+1*.
        """
        if dilation < 1:
            raise ContractError(f"dilation must be >= 1, got {dilation}")
        if kernel < 1:
            raise ContractError(f"kernel must be >= 1, got {kernel}")
        rows = self.features()
        padding = (0.0,) * FEATURE_WIDTH
        offsets = tuple((kernel - 1 - tap) * dilation for tap in range(kernel))
        context: list[tuple[float, ...]] = []
        for index in range(len(rows)):
            row: list[float] = []
            for offset in offsets:
                source = index - offset
                row.extend(rows[source] if source >= 0 else padding)
            context.append(tuple(row))
        return tuple(context)


class _BoundedKeySet:
    """A set of lineage keys with a hard cap, oldest forgotten first.

    Endpoint state, so it may not grow with the attacker's lineage count.
    Forgetting a key costs a ``truncated=True`` flag on a lineage that
    reappears long after its eviction; it never costs a count, because
    ``WindowStats.truncated_steps`` is incremented at eviction time.
    """

    __slots__ = ("capacity", "_keys")

    def __init__(self, capacity: int) -> None:
        self.capacity = max(1, capacity)
        self._keys: OrderedDict[str, None] = OrderedDict()

    def add(self, key: str) -> None:
        self._keys[key] = None
        self._keys.move_to_end(key)
        while len(self._keys) > self.capacity:
            self._keys.popitem(last=False)

    def __contains__(self, key: str) -> bool:
        return key in self._keys

    def __len__(self) -> int:
        return len(self._keys)

    def clear(self) -> None:
        self._keys.clear()


class WindowStore:
    """Bounded per-lineage windows. DTL-F03's runtime half.

    Eviction is LRU by ``last_sequence`` with a deterministic tie-break on the
    lineage key, because the Stage 0 reproducibility policy forbids an eviction
    order that depends on dict iteration luck. Every eviction and every dropped
    step is counted; nothing here reports a bound it did not enforce.
    """

    def __init__(
        self, *, max_lineages: int = MAX_LINEAGES, max_window: int = MAX_WINDOW
    ) -> None:
        if not 1 <= max_lineages <= MAX_LINEAGES:
            raise ContractError(
                f"max_lineages must be in [1, {MAX_LINEAGES}], got {max_lineages}"
            )
        if not 1 <= max_window <= MAX_WINDOW:
            raise ContractError(
                f"max_window must be in [1, {MAX_WINDOW}], got {max_window}"
            )
        self.max_lineages = max_lineages
        self.max_window = max_window
        #: Signature -> chain root. Bounded, because a per-signature map over an
        #: unbounded stream is exactly the leak this project keeps refusing.
        self.max_roots = max_lineages * max_window
        self._windows: OrderedDict[str, LineageWindow] = OrderedDict()
        self._roots: OrderedDict[str, str] = OrderedDict()
        #: Lineage keys whose window was evicted, so a reappearance is reported
        #: as truncated rather than as a fresh, complete window. Bounded by the
        #: same rule as everything else here: it holds at most `max_roots` keys
        #: and the oldest are forgotten, which costs a `truncated` flag and
        #: never a wrong count.
        self._evicted_keys = _BoundedKeySet(max_lineages * 4)
        self._evicted_lineages = 0
        self._truncated_steps = 0
        self._root_evictions = 0
        self._unresolved_parents = 0

    # --- DTL-F03 -------------------------------------------------------------

    def update_multiscale_state(
        self, transition: SSIRTransitionV1, *, actor_slot: int = 0
    ) -> LineageWindow:
        """Append one transition to its lineage's window and return the window.

        Named for DTL-F03, but there is no latent state to update: the returned
        window *is* the state, and it is a slice of history rather than a
        compressed activation. That is the whole of ADR-0119.
        """
        if not isinstance(transition, SSIRTransitionV1):
            raise ContractError(
                "update_multiscale_state takes an SSIRTransitionV1, "
                f"got {type(transition).__name__}"
            )
        key = self._resolve_lineage_key(transition)
        encoded = encode_ssir_transition(transition, actor_slot=actor_slot)

        existing = self._windows.get(key)
        steps = (existing.steps if existing is not None else ()) + (encoded,)
        if existing is not None:
            truncated = existing.truncated
        else:
            # A lineage that was evicted and has now reappeared HAS dropped
            # history, and its window must say so. Reporting `truncated=False`
            # here made the window that lost everything look complete.
            truncated = key in self._evicted_keys
        if len(steps) > self.max_window:
            dropped = len(steps) - self.max_window
            steps = steps[dropped:]
            self._truncated_steps += dropped
            truncated = True

        window = LineageWindow(
            lineage_key=key,
            steps=steps,
            truncated=truncated,
            last_sequence=transition.sequence,
        )
        self._windows[key] = window
        self._windows.move_to_end(key)
        self._evict_lineages()
        return window

    def get(self, lineage_key: str) -> LineageWindow | None:
        """The stored window, or None when it was never seen or was evicted."""
        return self._windows.get(lineage_key)

    def reset(self) -> None:
        """Drop all state *and* all accounting.

        Read `stats()` first: the eviction and truncation counts are evidence,
        and this discards them rather than carrying stale numbers into a new
        session where they would be attributed to the wrong corpus.
        """
        self._windows.clear()
        self._roots.clear()
        self._evicted_keys.clear()
        self._evicted_lineages = 0
        self._truncated_steps = 0
        self._root_evictions = 0
        self._unresolved_parents = 0

    # --- accounting ----------------------------------------------------------

    def stats(self) -> WindowStats:
        return WindowStats(
            lineages=len(self._windows),
            transitions_held=sum(len(w.steps) for w in self._windows.values()),
            evicted_lineages=self._evicted_lineages,
            truncated_steps=self._truncated_steps,
            memory_bytes=self.memory_bytes(),
        )

    def memory_bytes(self) -> int:
        """Measured payload of everything this store holds alive.

        Summed from real lengths. Interpreter object headers are excluded, so
        this is a payload figure and a lower bound on RSS, not an RSS
        measurement — `stage0.benchmark.resource_metrics.ResourceSampler` is the
        only thing in this repository that measures RSS.
        """
        return self.fixed_bytes() + self.evidence_bytes()

    def fixed_bytes(self) -> int:
        """The share of `memory_bytes` that `memory_bound_bytes` actually bounds."""
        windows = sum(
            len(window.lineage_key)
            + _POINTER_BYTES
            + _FLOAT_BYTES
            + sum(_step_bytes(step) for step in window.steps)
            for window in self._windows.values()
        )
        roots = sum(
            len(signature) + len(root) + _POINTER_BYTES
            for signature, root in self._roots.items()
        )
        return windows + roots

    def evidence_bytes(self) -> int:
        """Variable-length evidence-locator bytes held alive by the windows.

        Reported separately and never folded into the bound, because this store
        does not choose locator lengths and therefore cannot honestly claim to
        bound them. A caller that needs a hard total must bound its own locators.
        """
        return sum(
            _evidence_bytes(step)
            for window in self._windows.values()
            for step in window.steps
        )

    def memory_bound_bytes(self, *, signature_bytes: int = 16) -> int:
        """Upper bound on `fixed_bytes()` at full occupancy.

        ``signature_bytes`` is the causal-signature length Stage 1 emits (16 hex
        characters, `stage1/causal/memory.py:70`); it is a parameter rather than
        a constant so a future signature width does not silently invalidate the
        bound. Excludes `evidence_bytes()` by construction — see there.
        """
        if signature_bytes < 1:
            raise ContractError("signature_bytes must be >= 1")
        per_step = FEATURE_WIDTH * (_FLOAT_BYTES + _POINTER_BYTES) + (
            _SCALAR_FIELDS * _FLOAT_BYTES
        )
        windows = self.max_lineages * (
            signature_bytes + _POINTER_BYTES + _FLOAT_BYTES + self.max_window * per_step
        )
        roots = self.max_roots * (2 * signature_bytes + _POINTER_BYTES)
        return windows + roots

    def root_evictions(self) -> int:
        """Signature→root entries dropped to stay bounded.

        Non-zero means some later transition in a long chain will be keyed on its
        parent instead of the true root, which splits a lineage. That is a
        bounded-state cost, and it is counted rather than hidden.
        """
        return self._root_evictions

    def unresolved_parents(self) -> int:
        """Transitions whose parent signature was never seen or was evicted."""
        return self._unresolved_parents

    # --- internals -----------------------------------------------------------

    def _resolve_lineage_key(self, transition: SSIRTransitionV1) -> str:
        """Chain root of the causal signature. Semantics only, never identity."""
        signature = transition.causal_signature
        if not signature:
            raise ContractError("transition has no causal_signature to key on")
        parent = transition.parent_signature
        if _is_chain_root(parent):
            root = signature
        else:
            known = self._roots.get(parent)
            if known is None:
                # Unseen or evicted parent. Falling back to the parent signature
                # keeps the key deterministic, bounded and derived from
                # semantics; deriving one from a pid would violate ADR-0006 and
                # inventing one would break reproducibility.
                self._unresolved_parents += 1
                root = parent
            else:
                root = known
        self._remember_root(signature, root)
        return root

    def _remember_root(self, signature: str, root: str) -> None:
        if signature in self._roots:
            self._roots.move_to_end(signature)
        else:
            self._roots[signature] = root
        while len(self._roots) > self.max_roots:
            self._roots.popitem(last=False)
            self._root_evictions += 1

    def _evict_lineages(self) -> None:
        while len(self._windows) > self.max_lineages:
            victim = min(
                self._windows.values(),
                key=lambda window: (window.last_sequence, window.lineage_key),
            )
            self._windows.pop(victim.lineage_key)
            self._evicted_lineages += 1
            # Steps discarded with the window are counted too. They used not to
            # be, so the window that lost the MOST history — all of it — was the
            # one reporting none, and a reappearing lineage started again with
            # `truncated=False` while the docstring said "every dropped step is
            # counted in WindowStats.truncated_steps" (S2-08 / MEDIUM).
            self._truncated_steps += len(victim.steps)
            self._evicted_keys.add(victim.lineage_key)
