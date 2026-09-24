# Stage 2 — exact API reference

> **Scope.** The Stage 2 encoder, dataset, core functional IDs, research core
> (recurrent DTL and convolutional DTL-C), autograd, baseline suite,
> sleeping-brain benchmark, experiment program, and the eleven empty placeholder
> packages.
>
> **Honesty contract.** Every signature, line number, field default and numeric
> value below was read out of the `.py` files or produced by running code in the
> session that wrote this document (2026-09-24, Python on this machine,
> `PYTHONPATH=/home/anil/Documents/Research/pocketsec`). Numbers taken from
> `planning/MEMORY.md` or an ADR are attributed as such and are *not* re-claimed
> as measurements made here. Anything not measured is marked **UNMEASURED**.
>
> **Placeholder warning.** Eleven of the twelve Stage 2 subpackages contain
> nothing but a 0-byte `__init__.py`. Their names are not implementations. See
> §7.

---

## 1. Purpose

Stage 2 turns Stage 1's SSIR transitions into a fixed-width numeric encoding and
then asks, under one shared dataset and one shared training budget, whether *any*
learned predictive core earns its compute on that encoding. It ships exactly
three runtime (stdlib-only) modules — the twenty functional IDs and the
execution-path ladder (`core_ids.py`), the 96-slot feature encoder
(`encoder/ssir_encoder.py`), and the shared dataset builder (`dataset.py`) — plus
one offline research package (`research/`, numpy-permitted, ADR-0008) holding a
hand-written reverse-mode autodiff, nine baselines, two DTL cores (recurrent
`DTLModel`, convolutional `DTLConvModel`), the sleeping-brain cost benchmark, and
the experiment program. Its measured outcome is negative and is recorded as such:
per `planning/MEMORY.md` and ADR-0010, DTL was **rejected** — the Stage 2 core is
a TCN (causal convolution plus max-over-time pooling) with optional *detached*
auxiliary heads retained for Stage 3 — and the Stage 2 gate is **BLOCKED**.
Deliverables D2.6–D2.15 (lattice, atoms, future cones, credit, counterfactuals,
cache, compile candidates) are **not implemented at all**; the packages that
would hold them are empty.

---

## 2. Public symbol table

Column `file:line` is the definition site. All paths are relative to the
repository root `/home/anil/Documents/Research/pocketsec`.

### 2.1 `pocketsec/stage2/__init__.py`

Docstring only, no symbols (21 lines).

### 2.2 `pocketsec/stage2/core_ids.py` — D2.1, stdlib only

`__all__` (lines 23–30) = `["CORE_IDS", "DTL_INTERFACE_ID",
"DTL_INTERFACE_VERSION", "CoreFunction", "ExecutionPath", "FunctionClass"]`.
**`PATH_COST_UNITS` and `REQUIRED_IDS` are public and used by other modules and
tests but are NOT in `__all__`** — import them by name, not with `*`.

| Symbol | Full signature / definition | file:line | Purpose |
|---|---|---|---|
| `DTL_INTERFACE_ID` | `DTL_INTERFACE_ID: str = "pocketsec.dtl_interface.v1"` | `core_ids.py:32` | Schema id for the versioned Stage 2 interface. |
| `DTL_INTERFACE_VERSION` | `DTL_INTERFACE_VERSION = register_schema(DTL_INTERFACE_ID, "1.0.0")` — measured value `"1.0.0"` | `core_ids.py:33` | Registers into the Stage 0 schema registry at import time. A breaking change needs a new `...v2` id. |
| `FunctionClass` | `class FunctionClass(StrEnum)`; members `REQUIRED = "REQUIRED"`, `OPTIONAL = "OPTIONAL"` | `core_ids.py:36` | REQUIRED = hub cannot operate without it; OPTIONAL = ablation may delete it. |
| `ExecutionPath` | `class ExecutionPath(StrEnum)`; members in order `P0_COMPILED = "P0_COMPILED"`, `P1_LATTICE = "P1_LATTICE"`, `P2_LOCAL = "P2_LOCAL"`, `P3_PREDICTIVE = "P3_PREDICTIVE"`, `P4_DEEP = "P4_DEEP"` | `core_ids.py:43` | The Need-to-Compute ladder (spec §6). |
| `PATH_COST_UNITS` | `PATH_COST_UNITS: dict[ExecutionPath, float]` = `{P0_COMPILED: 1.0, P1_LATTICE: 2.0, P2_LOCAL: 8.0, P3_PREDICTIVE: 40.0, P4_DEEP: 200.0}` | `core_ids.py:62` | Relative cost weights for "compute units per event". A **plain mutable dict**, not a `MappingProxyType`. |
| `CoreFunction` | `@dataclass(frozen=True, slots=True)` with fields `core_id: str`, `name: str`, `purpose: str`, `function_class: FunctionClass`, `deliverable: str` (all required, no defaults, this positional order) | `core_ids.py:71-78` | One functional ID record. |
| `CoreFunction.to_dict` | `def to_dict(self) -> dict[str, Any]` — keys `"core_id"`, `"name"`, `"purpose"`, `"class"` (note: **`"class"`, not `"function_class"`**), `"deliverable"` | `core_ids.py:80` | JSON projection. |
| `CORE_IDS` | `CORE_IDS = MappingProxyType({function.core_id: function for function in _FUNCTIONS})` → `Mapping[str, CoreFunction]` | `core_ids.py:233` | Measured: exactly 20 entries, keys `"DTL-F01"` … `"DTL-F20"`. Read-only. |
| `REQUIRED_IDS` | `REQUIRED_IDS = frozenset(fn.core_id for fn in _FUNCTIONS if fn.function_class is FunctionClass.REQUIRED)` | `core_ids.py:236` | Measured: 8 members = `DTL-F01, DTL-F02, DTL-F03, DTL-F06, DTL-F07, DTL-F18, DTL-F19, DTL-F20`. |
| module assert | `assert len(CORE_IDS) == 20, "the spec defines exactly twenty core functional IDs"` | `core_ids.py:240` | Runs at import. **Stripped under `python -O`.** |

#### The twenty functional IDs (`core_ids.py:90-231`), verbatim

| ID | `name` | `function_class` | `deliverable` | Implemented? |
|---|---|---|---|---|
| DTL-F01 | `encode_ssir_transition` | REQUIRED | D2.3 | **Yes** — `encoder/ssir_encoder.py:195` |
| DTL-F02 | `route_information_need` | REQUIRED | D2.4 | Research only — `DTLModel.route` / `DTLModel.path_histogram`; **no runtime module** |
| DTL-F03 | `update_multiscale_state` | REQUIRED | D2.3 | Research only — `DTLModel.forward`, `DTLConvModel.forward`; `stage2/state/` empty |
| DTL-F04 | `quantize_behaviour_atom` | OPTIONAL | D2.6 | **No** — `stage2/lattice/` empty |
| DTL-F05 | `predict_future_cone` | OPTIONAL | D2.8 | **No** — `stage2/predictors/` empty |
| DTL-F06 | `predict_security_state_delta` | REQUIRED | D2.5 | Research only — `head_delta` / `head_phi` in both cores |
| DTL-F07 | `estimate_uncertainty` | REQUIRED | D2.9 | **No** — `stage2/uncertainty/` empty |
| DTL-F08 | `estimate_security_hazard` | OPTIONAL | D2.8 | **No** |
| DTL-F09 | `score_prediction_residual` | OPTIONAL | D2.5 | Research only — `SurpriseVector` / `_surprise_summary` |
| DTL-F10 | `assign_causal_credit` | OPTIONAL | D2.10 | **No** — `stage2/credit/` empty |
| DTL-F11 | `counterfactual_probe` | OPTIONAL | D2.10 | **No** — `stage2/counterfactual/` empty |
| DTL-F12 | `request_observation_escalation` | OPTIONAL | D2.11 | **No** |
| DTL-F13 | `merge_equivalent_atoms` | OPTIONAL | D2.7 | **No** |
| DTL-F14 | `split_heterogeneous_atom` | OPTIONAL | D2.7 | **No** |
| DTL-F15 | `forget_low_utility_memory` | OPTIONAL | D2.13 | **No** |
| DTL-F16 | `lookup_transition_cache` | OPTIONAL | D2.13 | **No** — `stage2/cache/` empty |
| DTL-F17 | `propose_compile_candidate` | OPTIONAL | D2.13 | **No** — `stage2/compile_candidates/` empty |
| DTL-F18 | `detect_epoch_mismatch` | REQUIRED | D2.12 | **No** — `stage2/adaptation/` empty |
| DTL-F19 | `quarantine_adaptation_sample` | REQUIRED | D2.12 | **No** — `stage2/adaptation/` empty |
| DTL-F20 | `export_evidence_bound_prediction` | REQUIRED | D2.15 | Partial — `EncodedTransition.evidence` carries locators; no exporter exists |

Four of the eight REQUIRED functions (F07, F18, F19, and the export half of F20)
have **no code anywhere in the repository.**

### 2.3 `pocketsec/stage2/encoder/ssir_encoder.py` — DTL-F01, stdlib only

`__all__` (lines 34–43) = `["ENCODER_VERSION", "GROUP_OFFSETS",
"NEED_SIGNAL_INDICES", "FEATURE_LAYOUT", "FEATURE_WIDTH", "EncodedTransition",
"encode_ssir_transition", "feature_names"]`.

| Symbol | Full signature / definition | file:line |
|---|---|---|
| `ENCODER_VERSION` | `ENCODER_VERSION = "dtl-encoder.1.0.0"` (measured) | `ssir_encoder.py:45` |
| `FEATURE_LAYOUT` | `FEATURE_LAYOUT: tuple[tuple[str, int], ...] = _feature_layout()` — `(group, width)` pairs | `ssir_encoder.py:94` (built by `_feature_layout()` at `:75`) |
| `FEATURE_WIDTH` | `FEATURE_WIDTH: int = sum(width for _, width in FEATURE_LAYOUT)` — **measured value `96`** | `ssir_encoder.py:95` |
| `GROUP_OFFSETS` | `GROUP_OFFSETS: dict[str, int] = _group_offsets()` — start index per group | `ssir_encoder.py:108` (built at `:98`) |
| `NEED_SIGNAL_INDICES` | `NEED_SIGNAL_INDICES: dict[str, int]` — measured `{"novelty_peak": 83, "delta_phi": 73, "uncertainty": 85, "responsibility": 90, "state_delta_magnitude": 71}` | `ssir_encoder.py:113` |
| `feature_names` | `def feature_names() -> tuple[str, ...]` — measured length `96`, one name per slot | `ssir_encoder.py:122` |
| `EncodedTransition` | `@dataclass(frozen=True, slots=True)` — see field table below | `ssir_encoder.py:142` |
| `EncodedTransition.to_dict` | `def to_dict(self) -> dict[str, Any]` — keys `relation, relation_family, state_delta_mask, time_bucket, delta_phi` (rounded 4), `object_property_mask, epoch_id, evidence` (list). **Omits `features` and `actor_slot`.** | `ssir_encoder.py:174` |
| `encode_ssir_transition` | `def encode_ssir_transition(transition: SSIRTransitionV1, *, actor_slot: int = 0) -> EncodedTransition` | `ssir_encoder.py:195-197` |

#### `EncodedTransition` fields, in declaration order

| Field | Type | Default | file:line | Meaning |
|---|---|---|---|---|
| `features` | `tuple[float, ...]` | — | `:151` | Length is exactly `FEATURE_WIDTH` (96), enforced at `:244`. |
| `relation` | `int` | — | `:153` | `int(transition.relation)`. Target for the next-step relation head. |
| `relation_family` | `int` | — | `:154` | `int(family_of(transition.relation))`. |
| `state_delta_mask` | `int` | — | `:155` | `transition.state_delta.bitmask()`. |
| `time_bucket` | `int` | — | `:156` | `transition.temporal.since_actor_bucket` (**actor**, not host). |
| `delta_phi` | `float` | — | `:157` | Raw, signed, unbounded ΔΦ. Distinct from the two squashed feature slots. |
| `object_property_mask` | `int` | — | `:158` | Bitmask over `_ENCODED_PROPERTIES` (15 properties), object side only. |
| `epoch_id` | `int` | — | `:159` | Stage 1 epoch id. |
| `actor_slot` | `int` | `0` | `:169` | Session-local lineage index by order of first appearance. A **grouping key, not an identity**; assigned in `dataset._encode`, never by the encoder. |
| `evidence` | `tuple[str, ...]` | `()` | `:172` | Stage 1 evidence locators for DTL-F20. **Never a model feature.** |

#### The frozen 96-slot feature layout (measured this session)

| # | group | width | offset range |
|---|---|---|---|
| 1 | `relation_onehot` | 24 | 0–23 |
| 2 | `relation_family_onehot` | 8 | 24–31 |
| 3 | `actor_semantics` | 15 | 32–46 |
| 4 | `object_semantics` | 15 | 47–61 |
| 5 | `state_delta_raised` | 9 | 62–70 |
| 6 | `state_delta_scalars` | 2 | 71–72 (`[71]` = magnitude/4 clipped to 1, `[72]` = raised-count / 9) |
| 7 | `delta_phi` | 2 | 73–74 (`[73]` = `abs(φ)/(abs(φ)+8.0)`, `[74]` = `1.0 if φ > 0 else 0.0`) |
| 8 | `novelty_tensor` | 8 | 75–82 (one per `NOVELTY_CONTEXTS`: host, user, actor, parent_child, object, relation, time, causal) |
| 9 | `novelty_scalars` | 2 | 83–84 (`[83]` = peak, `[84]` = mean) |
| 10 | `uncertainty` | 2 | 85–86 (`[85]` = uncertainty, `[86]` = `observation_incomplete`) |
| 11 | `temporal` | 3 | 87–89 (actor bucket / 15, host bucket / 15, burst = `actor_bucket <= 1`) |
| 12 | `causal` | 2 | 90–91 (`[90]` = `min(1, responsibility/8.0)`, `[91]` = has-parent) |
| 13 | `representation_level` | 4 | 92–95 (one-hot over `int(transition.level)`) |

Widths are derived, measured this session: `len(Relation) == 24`,
`len(RelationFamily) == 8`, `len(DIMENSIONS) == 9`,
`len(NOVELTY_CONTEXTS) == 8`, `len(_ENCODED_PROPERTIES) == 15`. Module-private
constants: `_ENCODED_PROPERTIES` (`:50`), `_DIMENSION_NAMES` (`:68`),
`_MAX_TIME_BUCKET = 15.0` (`:69`), `_PHI_SCALE = 8.0` (`:72`).

### 2.4 `pocketsec/stage2/dataset.py` — D2.2 (part), stdlib only

`__all__` (line 34) = `["Stage2Dataset", "Stage2Sample", "build_dataset"]`.

| Symbol | Full signature | file:line |
|---|---|---|
| `Stage2Sample` | `@dataclass(frozen=True, slots=True)` — fields below | `dataset.py:37` |
| `Stage2Sample.__len__` | `def __len__(self) -> int` → `len(self.steps)` | `dataset.py:49` |
| `Stage2Sample.features` | `@property def features(self) -> tuple[tuple[float, ...], ...]` | `dataset.py:52-53` |
| `Stage2Sample.next_step_targets` | `def next_step_targets(self) -> tuple[tuple[EncodedTransition, EncodedTransition], ...]` — `(context, next)` pairs via `zip(steps[:-1], steps[1:], strict=True)` | `dataset.py:56` |
| `Stage2Sample.to_dict` | `def to_dict(self) -> dict[str, Any]` — keys `sample_id, length, label, technique, unseen_technique, final_phi` (rounded 4) | `dataset.py:60` |
| `Stage2Dataset` | `@dataclass(frozen=True, slots=True)` — fields below | `dataset.py:71` |
| `Stage2Dataset.__len__` | `def __len__(self) -> int` → **number of samples**, not transitions | `dataset.py:82` |
| `Stage2Dataset.__iter__` | `def __iter__(self)` → `iter(self.samples)` | `dataset.py:85` |
| `Stage2Dataset.labels` | `@property def labels(self) -> tuple[int, ...]` | `dataset.py:88-89` |
| `Stage2Dataset.positive_count` | `@property def positive_count(self) -> int` → `sum(self.labels)` | `dataset.py:92-93` |
| `Stage2Dataset.transition_count` | `@property def transition_count(self) -> int` → `sum(len(s) for s in samples)` | `dataset.py:96-97` |
| `Stage2Dataset.base_rate` | `@property def base_rate(self) -> float` → `positive_count / len(samples)`, `0.0` if empty | `dataset.py:100-101` |
| `Stage2Dataset.to_provenance` | `def to_provenance(self) -> dict[str, Any]` — keys `name, seed, corpus, mean_length, encoder_version, feature_width, samples, transitions, positives, base_rate, unseen_technique_samples` | `dataset.py:104` |
| `build_dataset` | `def build_dataset(*, name: str, count: int, seed: int, corpus: str = "hard") -> Stage2Dataset` — keyword-only | `dataset.py:147-149` |
| `_encode` (private) | `def _encode(result: ScenarioResult, index: int) -> Stage2Sample \| None` | `dataset.py:124` |

`Stage2Sample` fields: `sample_id: str` (`:41`), `steps: tuple[EncodedTransition, ...]` (`:42`),
`label: int` (`:43`), `technique: str | None` (`:44`), `unseen_technique: bool` (`:45`),
`final_phi: float` (`:47`). No defaults on any field.

`Stage2Dataset` fields, in **declaration order** — `name: str` (`:75`), `seed: int` (`:76`),
`corpus: str` (`:77`), `encoder_version: str` (`:78`), `feature_width: int` (`:79`),
`samples: tuple[Stage2Sample, ...]` (`:80`). No defaults. (`build_dataset` constructs it
with keywords in a *different* order, `dataset.py:174-181`; positional construction
would silently swap `seed` and `corpus`.)

`build_dataset` accepts `corpus` in `{"hard", "long", "ambiguous"}` (`dataset.py:157-161`,
mapping to `build_hard_corpus`, `build_long_horizon_corpus`, `build_ambiguous_corpus`) and
raises `ValueError(f"unknown corpus {corpus!r}; known: {sorted(builders)}")` otherwise
(`dataset.py:163`).

### 2.5 `pocketsec/stage2/research/__init__.py`

Docstring only, no symbols (13 lines). States the ADR-0008 boundary.

### 2.6 `pocketsec/stage2/research/autograd.py` — research only (numpy)

`__all__` (lines 24–37) = `["Tensor", "binary_cross_entropy", "bmm", "concat",
"cross_entropy", "normalised_bce", "normalised_cross_entropy", "relu",
"sigmoid", "softmax", "tanh", "zeros_like_params"]`.

| Symbol | Full signature | file:line |
|---|---|---|
| `Tensor` | `class Tensor` with `__slots__ = ("data", "grad", "requires_grad", "_backward", "_parents", "_op")` | `autograd.py:40` |
| `Tensor.__init__` | `def __init__(self, data: np.ndarray \| Sequence[Any] \| float, *, requires_grad: bool = False, parents: tuple[Tensor, ...] = (), op: str = "") -> None` — coerces to `np.float64` | `autograd.py:45-52` |
| `Tensor.shape` | `@property def shape(self) -> tuple[int, ...]` | `autograd.py:62-63` |
| `Tensor.zero_grad` | `def zero_grad(self) -> None` — sets `self.grad = None` | `autograd.py:81` |
| `Tensor.backward` | `def backward(self) -> None` — **requires a scalar output**; raises `ValueError("backward() requires a scalar output")` otherwise. Iterative reverse topo walk (no recursion). | `autograd.py:84` |
| `Tensor.__add__` / `__radd__` | `def __add__(self, other: Tensor \| float) -> Tensor`; `__radd__ = __add__` | `autograd.py:113`, `:145` |
| `Tensor.__mul__` / `__rmul__` | `def __mul__(self, other: Tensor \| float) -> Tensor`; `__rmul__ = __mul__` | `autograd.py:126`, `:146` |
| `Tensor.__sub__` | `def __sub__(self, other: Tensor \| float) -> Tensor` | `autograd.py:139` |
| `Tensor.__rsub__` | `def __rsub__(self, other: float) -> Tensor` | `autograd.py:142` |
| `Tensor.__neg__` | `def __neg__(self) -> Tensor` | `autograd.py:148` |
| `Tensor.matmul` / `__matmul__` | `def matmul(self, other: Tensor) -> Tensor`; `__matmul__ = matmul` | `autograd.py:151`, `:163` |
| `Tensor.sum` | `def sum(self, axis: int \| None = None, keepdims: bool = False) -> Tensor` | `autograd.py:165` |
| `Tensor.mean` | `def mean(self, axis: int \| None = None) -> Tensor` | `autograd.py:181` |
| `Tensor.tanh` | `def tanh(self) -> Tensor` | `autograd.py:185` |
| `Tensor.sigmoid` | `def sigmoid(self) -> Tensor` — numerically stable | `autograd.py:196` |
| `Tensor.relu` | `def relu(self) -> Tensor` | `autograd.py:207` |
| `Tensor.log_softmax` | `def log_softmax(self, axis: int = -1) -> Tensor` | `autograd.py:218` |
| `Tensor.index_select` | `def index_select(self, indices: np.ndarray, axis: int = 0) -> Tensor` — **backward ignores `axis`; broken for `axis != 0`, see §6 trap 15** | `autograd.py:235` |
| `Tensor.slice_rows` | `def slice_rows(self, start: int, stop: int) -> Tensor` — rows, i.e. axis 0 | `autograd.py:248` |
| `Tensor.slice_cols` | `def slice_cols(self, start: int, stop: int) -> Tensor` — `data[:, start:stop]`, requires 2-D | `autograd.py:262` |
| `Tensor.slice_step` | `def slice_step(self, step: int) -> Tensor` — `data[:, step:step+1, :]`, requires 3-D `(batch, steps, channels)` | `autograd.py:275` |
| `Tensor.reshape` | `def reshape(self, *shape: int) -> Tensor` — **varargs, not a tuple**: `t.reshape(6, 2)` | `autograd.py:289` |
| `Tensor.transpose` | `def transpose(self, *axes: int) -> Tensor` — varargs; axes are **required** (backward uses `np.argsort(axes)`) | `autograd.py:300` |
| `Tensor.exp` | `def exp(self) -> Tensor` — input clipped to `[-60, 60]` | `autograd.py:311` |
| `bmm` | `def bmm(left: Tensor, right: Tensor) -> Tensor` — `(B,N,M) @ (B,M,P) -> (B,N,P)` | `autograd.py:323` |
| `concat` | `def concat(tensors: Sequence[Tensor], axis: int = -1) -> Tensor` | `autograd.py:366` |
| `cross_entropy` | `def cross_entropy(logits: Tensor, targets: np.ndarray) -> Tensor` — mean NLL; single fused op with analytic gradient `(softmax(x) - onehot(y)) / N` | `autograd.py:390` |
| `binary_cross_entropy` | `def binary_cross_entropy(logits: Tensor, targets: np.ndarray) -> Tensor` — stable BCE-with-logits, mean; targets reshaped to `logits.data.shape` | `autograd.py:417` |
| `normalised_cross_entropy` | `def normalised_cross_entropy(logits: Tensor, targets: np.ndarray, classes: int) -> Tensor` — `cross_entropy / ln(max(classes, 2))`; `classes` is **positional** | `autograd.py:438` |
| `normalised_bce` | `def normalised_bce(logits: Tensor, targets: np.ndarray) -> Tensor` — `binary_cross_entropy / ln(2)` | `autograd.py:450` |
| `softmax` | `def softmax(values: np.ndarray, axis: int = -1) -> np.ndarray` — **plain numpy, not a Tensor op** | `autograd.py:455` |
| `sigmoid` | `def sigmoid(values: np.ndarray) -> np.ndarray` — plain numpy | `autograd.py:461` |
| `tanh` | `def tanh(values: np.ndarray) -> np.ndarray` — plain numpy | `autograd.py:465` |
| `relu` | `def relu(values: np.ndarray) -> np.ndarray` — plain numpy | `autograd.py:469` |
| `zeros_like_params` | `def zeros_like_params(params: Iterable[Tensor]) -> None` — calls `zero_grad()` on each; **returns `None` despite the name** | `autograd.py:473` |

Private helpers: `_unbroadcast(gradient, shape)` (`:347`), `_stable_sigmoid(x)` (`:357`),
`Tensor._child` (`:66`), `Tensor._accumulate` (`:76`).

### 2.7 `pocketsec/stage2/research/dtl.py` — recurrent DTL core (D2.3+D2.4+D2.5), **rejected per ADR-0010**

`__all__` (line 51) = `["DTL_BLOCKS", "DTLConfig", "DTLModel", "SurpriseVector"]`.
`_pad` is private but **imported by `dtl_conv.py:59`**.

| Symbol | Full signature | file:line |
|---|---|---|
| `DTL_BLOCKS` | `DTL_BLOCKS: tuple[tuple[str, float, float], ...] = (("fast", 0.30, 0.50), ("session", 0.25, 0.85), ("host", 0.15, 0.97), ("epoch", 0.10, 0.99), ("causal", 0.15, 0.90), ("uncertainty", 0.05, 0.80))` — `(name, dimension share, per-step decay when asleep)` | `dtl.py:55` |
| `DTLConfig` | `@dataclass(frozen=True, slots=True)` — fields below | `dtl.py:70` |
| `DTLConfig.block_sizes` | `def block_sizes(self) -> dict[str, int]` — `max(2, round(latent*share))` per block, drift absorbed into `"fast"` | `dtl.py:91` |
| `SurpriseVector` | `@dataclass(frozen=True, slots=True)` — fields `relation: float`, `object_semantics: float`, `state: float`, `time: float`, `causal: float`, `epoch: float` (this order, no defaults) | `dtl.py:102-111` |
| `SurpriseVector.as_tuple` | `def as_tuple(self) -> tuple[float, ...]` — same order as fields | `dtl.py:113` |
| `SurpriseVector.magnitude` | `@property def magnitude(self) -> float` — `np.linalg.norm(as_tuple())` | `dtl.py:123-124` |
| `SurpriseVector.security_weighted` | `@property def security_weighted(self) -> float` — `2.0*state + 1.5*causal + 1.0*relation + 0.5*(object_semantics + epoch + time)` | `dtl.py:127-128` |
| `SurpriseVector.to_dict` | `def to_dict(self) -> dict[str, Any]` — six components plus `magnitude` and `security_weighted`, all rounded 4 | `dtl.py:138` |
| `_pad` | `def _pad(samples: tuple[Stage2Sample, ...]) -> dict[str, np.ndarray]` — keys listed below | `dtl.py:151` |
| `DTLModel` | `class DTLModel`; class attribute `name = "dtl"` | `dtl.py:200`, `:203` |
| `DTLModel.__init__` | `def __init__(self, config: DTLConfig \| None = None, **overrides: Any) -> None` — `self.config = config or DTLConfig(**overrides)`. **If `config` is given, `overrides` are silently discarded.** | `dtl.py:205-206` |
| `DTLModel.forward` | `def forward(self, data: dict[str, np.ndarray], *, collect: bool = False) -> dict[str, Any]` | `dtl.py:281` |
| `DTLModel._need_signals` | `@staticmethod def _need_signals(batch: np.ndarray) -> np.ndarray` — `(..., 5)` in order novelty_peak, delta_phi, uncertainty, responsibility, state_delta_magnitude | `dtl.py:262-263` |
| `DTLModel._surprise_summary` | `@staticmethod def _surprise_summary(data: dict[str, np.ndarray], step_logits: dict[str, list[Tensor]]) -> np.ndarray` — `(rows, 6)`, computed **outside** the graph. **Reused by `DTLConvModel.forward` (`dtl_conv.py:295`).** | `dtl.py:360-363` |
| `DTLModel.fit` | `def fit(self, dataset: Stage2Dataset) -> DTLModel` — mini-batch SGD with momentum 0.9, grads clipped to ±5 | `dtl.py:408` |
| `DTLModel._loss` | `def _loss(self, data: dict[str, np.ndarray], output: dict[str, Any]) -> Tensor` | `dtl.py:435` |
| `DTLModel._step` | `def _step(self) -> None` | `dtl.py:471` |
| `DTLModel.predict_scores` | `def predict_scores(self, dataset: Stage2Dataset) -> list[float]` — sigmoid of the detection logit, one per sample | `dtl.py:481` |
| `DTLModel.route` | `def route(self, dataset: Stage2Dataset) -> dict[str, Any]` — keys `mean_blocks_awake`, `compute_units_per_event`, `path_fractions`, `block_wake_rate`, `path_histogram`, `total_steps` | `dtl.py:486` |
| `DTLModel.path_histogram` | `@staticmethod def path_histogram(need: np.ndarray, mask: np.ndarray) -> dict[str, int]` — deterministic policy: `score = 0.35*novelty + 0.25*phi + 0.20*uncertainty + 0.15*responsibility + 0.05*delta`, thresholds `<0.15 → P0`, `<0.30 → P1`, `<0.50 → P2`, `<0.70 → P3`, else `P4`. Keys are `ExecutionPath.value` strings. | `dtl.py:514-515` |
| `DTLModel.surprise_vectors` | `def surprise_vectors(self, dataset: Stage2Dataset) -> list[SurpriseVector]` | `dtl.py:560` |
| `DTLModel.resource_profile` | `def resource_profile(self) -> dict[str, Any]` — keys `parameters`, `model_bytes_fp32`, `hidden`, `final_loss`, `block_sizes` | `dtl.py:565` |

`DTLConfig` fields with types and defaults (`dtl.py:72-89`): `latent: int = 48`,
`wake_threshold: float = 0.5`, `epochs: int = 60`, `learning_rate: float = 0.05`,
`batch_size: int = 16`, `seed: int = 7`, `w_detect: float = 1.0`,
`w_relation: float = 0.5`, `w_family: float = 0.25`, `w_delta: float = 0.5`,
`w_time: float = 0.25`, `w_phi: float = 0.5`, `w_wake: float = 0.05`.

Module-private constants: `_N_RELATIONS = len(Relation)` (24), `_N_FAMILIES = len(RelationFamily)` (8),
`_N_DIMENSIONS = len(DIMENSIONS)` (9), `_N_TIME_BUCKETS = 16` (`dtl.py:64-67`).

**`_pad` output dict keys and shapes** (`dtl.py:186-197`), with `rows = len(samples)`,
`longest = max(len(s) for s in samples)`, `width = len(samples[0].steps[0].features)`:

| key | shape | dtype | content |
|---|---|---|---|
| `batch` | `(rows, longest, width)` | float64 | features, right-zero-padded |
| `mask` | `(rows, longest)` | float64 | 1.0 for real steps |
| `labels` | `(rows, 1)` | float64 | sample label |
| `next_mask` | `(rows, longest)` | float64 | 1.0 where step `t+1` exists |
| `next_relation` | `(rows, longest)` | int64 | `steps[t+1].relation` |
| `next_family` | `(rows, longest)` | int64 | `steps[t+1].relation_family` |
| `next_delta` | `(rows, longest, 9)` | float64 | bit expansion of `steps[t+1].state_delta_mask` |
| `next_time` | `(rows, longest)` | int64 | `min(steps[t+1].time_bucket, 15)` |
| `next_phi` | `(rows, longest)` | float64 | `min(1.0, max(0.0, steps[t+1].delta_phi / 8.0))` — **negative ΔΦ collapses to 0.0** |
| `actor_slot` | `(rows, longest)` | int64 | `steps[t].actor_slot`, **`-1` on padded positions** |

### 2.8 `pocketsec/stage2/research/dtl_conv.py` — DTL-C (ADR-0009)

`__all__` (line 61) = `["DTLC_BLOCKS", "DTLConvConfig", "DTLConvModel"]`.

| Symbol | Full signature | file:line |
|---|---|---|
| `DTLC_BLOCKS` | `DTLC_BLOCKS: tuple[tuple[str, float, int], ...] = (("fast", 0.25, 1), ("uncertainty", 0.10, 2), ("session", 0.20, 4), ("causal", 0.15, 8), ("host", 0.20, 16), ("epoch", 0.10, 32))` — `(name, dimension share, dilation)`. Note the **order differs from `DTL_BLOCKS`**. | `dtl_conv.py:64` |
| `DTLConvConfig` | `@dataclass(frozen=True, slots=True)` — fields below | `dtl_conv.py:80` |
| `DTLConvConfig.block_sizes` | `def block_sizes(self) -> dict[str, int]` — returns `{"fast": latent}` when `use_multiscale is False` | `dtl_conv.py:127` |
| `DTLConvConfig.dilations` | `def dilations(self) -> dict[str, int]` — returns `{"fast": 1}` when `use_multiscale is False` | `dtl_conv.py:139` |
| `DTLConvModel` | `class DTLConvModel`; class attribute `name = "dtl-conv"` | `dtl_conv.py:145`, `:148` |
| `DTLConvModel.__init__` | `def __init__(self, config: DTLConvConfig \| None = None, **overrides: Any) -> None` — same silent-discard behaviour as `DTLModel` | `dtl_conv.py:150-151` |
| `DTLConvModel._need_signals` | `@staticmethod def _need_signals(batch: np.ndarray) -> np.ndarray` | `dtl_conv.py:207-208` |
| `DTLConvModel._dilated_windows` | `@staticmethod def _dilated_windows(batch: np.ndarray, dilation: int) -> np.ndarray` → `(B, S, 3*width)`; causal, left zero-padded. `dilation` is **keyword-or-positional**; tests call it as `_dilated_windows(batch, dilation=2)`. | `dtl_conv.py:216-217` |
| `DTLConvModel.forward` | `def forward(self, data: dict[str, np.ndarray], *, collect: bool = False) -> dict[str, Any]` | `dtl_conv.py:236` |
| `DTLConvModel._lineage_pool` | `def _lineage_pool(self, latent_seq: Tensor, data: dict[str, np.ndarray], rows: int, steps: int, width: int) -> Tensor` | `dtl_conv.py:320` |
| `DTLConvModel._heads` | `def _heads(self, latent_seq: Tensor, rows: int, steps: int, width: int) -> dict[str, list[Tensor]]` — keys `relation, family, delta, time, phi` | `dtl_conv.py:362` |
| `DTLConvModel.fit` | `def fit(self, dataset: Stage2Dataset) -> DTLConvModel` | `dtl_conv.py:384` |
| `DTLConvModel._loss` | `def _loss(self, data: dict[str, np.ndarray], output: dict[str, Any]) -> Tensor` | `dtl_conv.py:408` |
| `DTLConvModel._step` | `def _step(self) -> None` | `dtl_conv.py:438` |
| `DTLConvModel.predict_scores` | `def predict_scores(self, dataset: Stage2Dataset) -> list[float]` | `dtl_conv.py:448` |
| `DTLConvModel.route` | `def route(self, dataset: Stage2Dataset) -> dict[str, Any]` — **key set depends on `use_router`**, see §6 trap 4 | `dtl_conv.py:452` |
| `DTLConvModel.surprise_vectors` | `def surprise_vectors(self, dataset: Stage2Dataset) -> list[SurpriseVector]` | `dtl_conv.py:474` |
| `DTLConvModel.resource_profile` | `def resource_profile(self) -> dict[str, Any]` — keys `parameters`, `model_bytes_fp32`, `hidden`, `final_loss`, `block_sizes`, `dilations` | `dtl_conv.py:478` |

`DTLConvConfig` fields with types and defaults (`dtl_conv.py:82-125`):

| field | type | default | file:line | Recorded verdict (source: in-file comments + `planning/MEMORY.md`) |
|---|---|---|---|---|
| `latent` | `int` | `48` | `:82` | — |
| `epochs` | `int` | `30` | `:83` | Note: `DTLConfig.epochs` defaults to `60`, these differ. |
| `learning_rate` | `float` | `0.05` | `:84` | — |
| `batch_size` | `int` | `16` | `:85` | — |
| `seed` | `int` | `7` | `:86` | — |
| `wake_threshold` | `float` | `0.5` | `:87` | — |
| `use_router` | `bool` | **`False`** | `:92` | HARMFUL, −0.115 PR-AUC on the ambiguous corpus. Removed per criterion 12. |
| `use_multiscale` | `bool` | **`True`** | `:94` | Beneficial, +0.068 PR-AUC. |
| `use_surprise` | `bool` | **`False`** | `:97` | HARMFUL, −0.073 PR-AUC. |
| `use_maxpool` | `bool` | **`True`** | `:99` | Load-bearing: +0.046 ambiguous, +0.66 long-horizon. |
| `use_lineage_pool` | `bool` | **`False`** | `:109` | Adds nothing after the corpus was corrected (1.0000 with and without). |
| `max_lineages` | `int` | `8` | `:111` | Bounded slot count for lineage pooling. |
| `detach_heads` | `bool` | **`True`** | `:118` | Joint training measured −0.67 PR-AUC; `w_detect=8` did not fix it. |
| `w_detect` | `float` | `1.0` | `:119` | — |
| `w_relation` | `float` | `0.5` | `:120` | — |
| `w_family` | `float` | `0.25` | `:121` | — |
| `w_delta` | `float` | `0.5` | `:122` | — |
| `w_time` | `float` | `0.25` | `:123` | — |
| `w_phi` | `float` | `0.5` | `:124` | — |
| `w_wake` | `float` | `0.05` | `:125` | Only has effect when `use_router is True` (`wake_cost` is `Tensor(0.0)` otherwise, `dtl_conv.py:302-307`). |

Module-private constants: `_N_RELATIONS`, `_N_FAMILIES`, `_N_DIMENSIONS`,
`_N_TIME_BUCKETS = 16`, `_KERNEL = 3` (`dtl_conv.py:73-77`).

### 2.9 `pocketsec/stage2/research/baselines.py` — D2.2

`__all__` (lines 33–46) = `["BASELINE_REGISTRY", "GRUBaseline", "LSTMBaseline",
"MLPBaseline", "MarkovBaseline", "SSMBaseline", "Stage2Model", "TCNBaseline",
"TransformerBaseline", "PhiOracleBaseline", "VQPrototypeBaseline",
"build_baselines"]`.

| Symbol | Full signature | file:line |
|---|---|---|
| `DEFAULT_EPOCHS` | `DEFAULT_EPOCHS = 60` | `baselines.py:48` |
| `DEFAULT_LR` | `DEFAULT_LR = 0.05` | `baselines.py:49` |
| `Stage2Model` | `class Stage2Model(Protocol)` with `name: str`, `fit(self, dataset: Stage2Dataset) -> Stage2Model`, `predict_scores(self, dataset: Stage2Dataset) -> list[float]`, `resource_profile(self) -> dict[str, Any]`. **Not `@runtime_checkable`; does not include `route` or `surprise_vectors`.** | `baselines.py:52-65` |
| `_pad` | `def _pad(samples: tuple[Stage2Sample, ...]) -> tuple[np.ndarray, np.ndarray, np.ndarray]` → `(batch, mask, labels)`. **Different function, same name, different return type from `dtl._pad`.** | `baselines.py:71` |
| `_TorchLikeModule` | `@dataclass class _TorchLikeModule` — shared SGD loop; fields below | `baselines.py:86-98` |
| `_TorchLikeModule.forward` | `def forward(self, batch: np.ndarray, mask: np.ndarray) -> Tensor` — `raise NotImplementedError`. Note the **numpy-array signature**, unlike the DTL cores' dict signature. | `baselines.py:117` |
| `_TorchLikeModule.fit` | `def fit(self, dataset: Stage2Dataset) -> _TorchLikeModule` | `baselines.py:120` |
| `_TorchLikeModule._build` | `def _build(self, width: int) -> None` — `raise NotImplementedError` | `baselines.py:163` |
| `_TorchLikeModule.predict_scores` | `def predict_scores(self, dataset: Stage2Dataset) -> list[float]` | `baselines.py:166` |
| `_TorchLikeModule.resource_profile` | `def resource_profile(self) -> dict[str, Any]` — keys `parameters`, `model_bytes_fp32`, `hidden`, `final_loss` | `baselines.py:170` |
| `MarkovBaseline` | `@dataclass` with `name: str = "markov-bigram"`, `alpha: float = 1.0`, `_transitions: dict[tuple[int,int], int] = field(default_factory=dict)`, `_contexts: dict[int,int] = field(default_factory=dict)`, `_vocabulary: set[int] = field(default_factory=set)` | `baselines.py:186-198` |
| `MarkovBaseline.fit` | `def fit(self, dataset: Stage2Dataset) -> MarkovBaseline` — **fits on `label == 0` samples only** (`:202-204`) | `baselines.py:200` |
| `MarkovBaseline.predict_scores` | `def predict_scores(self, dataset: Stage2Dataset) -> list[float]` — mean bigram surprise, then divided by `max(scores) or 1.0` (`:229`) | `baselines.py:216` |
| `MarkovBaseline.resource_profile` | `def resource_profile(self) -> dict[str, Any]` — `parameters = len(self._transitions)`, `model_bytes_fp32 = len * 12` | `baselines.py:232` |
| `MLPBaseline` | `@dataclass class MLPBaseline(_TorchLikeModule)`, `name: str = "mlp-pooled"` | `baselines.py:245`, `:248` |
| `MLPBaseline._build` / `.forward` | `_build(self, width: int) -> None` builds `w1: (2*width, hidden)`, `b1`, `w2: (hidden, 1)`, `b2`; `forward` concatenates masked mean-pool and max-pool | `baselines.py:250`, `:258` |
| `GRUBaseline` | `@dataclass class GRUBaseline(_TorchLikeModule)`, `name: str = "gru"` | `baselines.py:271`, `:274` |
| `LSTMBaseline` | `@dataclass class LSTMBaseline(_TorchLikeModule)`, `name: str = "lstm"`; gate params created via `setattr` as `wi/bi, wf/bf, wo/bo, wg/bg` plus `wout/bout` | `baselines.py:307`, `:310`, `:312-320` |
| `TCNBaseline` | `@dataclass class TCNBaseline(_TorchLikeModule)`, `name: str = "tcn"`, `kernel: int = 3` | `baselines.py:345`, `:351-352` |
| `TransformerBaseline` | `@dataclass class TransformerBaseline(_TorchLikeModule)`, `name: str = "tiny-transformer"`; fixed sinusoidal positions, single-head attention | `baselines.py:388`, `:391` |
| `SSMBaseline` | `@dataclass class SSMBaseline(_TorchLikeModule)`, `name: str = "selective-ssm"` | `baselines.py:441`, `:449` |
| `VQPrototypeBaseline` | `@dataclass` with `name: str = "vq-prototype"`, `clusters: int = 12`, `iterations: int = 40`, `seed: int = 7`; `__post_init__` sets `_centroids = None`, `_risk = None` | `baselines.py:481`, `:489-494` |
| `VQPrototypeBaseline._pool` | `@staticmethod def _pool(dataset: Stage2Dataset) -> np.ndarray` — masked mean pool | `baselines.py:498-499` |
| `VQPrototypeBaseline.fit` | `def fit(self, dataset: Stage2Dataset) -> VQPrototypeBaseline` — k-means then **label-supervised** Laplace-smoothed per-cluster risk | `baselines.py:504` |
| `VQPrototypeBaseline.predict_scores` | `def predict_scores(self, dataset: Stage2Dataset) -> list[float]` — returns `[0.0] * len(dataset)` if unfitted | `baselines.py:531` |
| `PhiOracleBaseline` | `@dataclass` with `name: str = "phi-oracle"`; `fit` returns `self` unchanged | `baselines.py:552`, `:566`, `:568` |
| `PhiOracleBaseline.predict_scores` | `def predict_scores(self, dataset: Stage2Dataset) -> list[float]` — `max(step.features[NEED_SIGNAL_INDICES["delta_phi"]] ...)`, i.e. index **73**, the *squashed absolute* ΔΦ | `baselines.py:571` |
| `BASELINE_REGISTRY` | `BASELINE_REGISTRY: dict[str, type]` mapping `"phi-oracle", "markov-bigram", "mlp-pooled", "gru", "lstm", "tcn", "tiny-transformer", "selective-ssm", "vq-prototype"` to their classes | `baselines.py:582` |
| `build_baselines` | `def build_baselines(*, hidden: int = 32, epochs: int = DEFAULT_EPOCHS) -> list[Any]` — keyword-only; returns 9 **fresh, unfitted** instances in registry order | `baselines.py:595` |

`_TorchLikeModule` fields, in order (subclasses inherit them and must keep
`name` first because it has no default in the base): `name: str` (`:90`, no
default), `hidden: int = 32` (`:91`), `epochs: int = DEFAULT_EPOCHS` (`:92`),
`learning_rate: float = DEFAULT_LR` (`:93`), `batch_size: int = 16` (`:94`),
`seed: int = 7` (`:95`), `params: list[Tensor] = field(default_factory=list)` (`:96`),
`_velocity: list[np.ndarray] = field(default_factory=list)` (`:97`),
`_losses: list[float] = field(default_factory=list)` (`:98`).

### 2.10 `pocketsec/stage2/research/sleeping_brain.py` — S2-E19

`__all__` (line 35) = `["SleepingBrainPoint", "sleeping_brain_report"]`.

| Symbol | Full signature | file:line |
|---|---|---|
| `TIMING_REPEATS` | `TIMING_REPEATS = 5` — best-of-N, minimum reported | `sleeping_brain.py:40` |
| `SleepingBrainPoint` | `@dataclass(frozen=True, slots=True)` with fields, in order: `name: str`, `pr_auc: float`, `transitions: int`, `predict_seconds: float`, `parameters: int`, `path_fractions: dict[str, float]`, `compute_units_per_event: float \| None`. **No defaults — all seven are required.** | `sleeping_brain.py:44-56` |
| `SleepingBrainPoint.microseconds_per_event` | `@property def microseconds_per_event(self) -> float` — `predict_seconds / max(transitions, 1) * 1e6` | `sleeping_brain.py:58-59` |
| `SleepingBrainPoint.cheap_path_share` | `@property def cheap_path_share(self) -> float \| None` — sum of P0+P1+P2 fractions; `None` when `path_fractions` is empty | `sleeping_brain.py:62-63` |
| `SleepingBrainPoint.to_dict` | `def to_dict(self) -> dict[str, Any]` — keys `name, pr_auc, microseconds_per_event, predict_seconds, parameters, transitions, path_fractions, compute_units_per_event, cheap_path_share` | `sleeping_brain.py:79` |
| `sleeping_brain_report` | `def sleeping_brain_report(models: list[Any], train: Stage2Dataset, test: Stage2Dataset) -> dict[str, Any]` — **positional args**; returns keys `dataset`, `points`, `pareto`, `path_cost_model`. Calls `model.fit(train)` on each model. | `sleeping_brain.py:108-109` |
| `_time_prediction` (private) | `def _time_prediction(model: Any, dataset: Stage2Dataset) -> tuple[float, list[float]]` | `sleeping_brain.py:97` |
| `_pareto` (private) | `def _pareto(points: list[SleepingBrainPoint]) -> dict[str, Any]` — keys `best_quality`, `tied_at_best_quality`, `cheapest_at_best_quality`, `cheapest_microseconds_per_event`, `dominated`, `verdict`; `{}` when `points` is empty. Tolerance 0.01 PR-AUC, domination requires `< 0.95 ×` cost. | `sleeping_brain.py:143` |

### 2.11 `pocketsec/stage2/research/experiments.py` — D2.14

`__all__` (lines 35–42) = `["ModelResult", "ablation_study",
"baseline_comparison", "build_splits", "latent_sweep", "sleeping_brain"]`.

> **This whole module drives `DTLModel` (the recurrent core rejected by
> ADR-0010), never `DTLConvModel`.** It imports only
> `from pocketsec.stage2.research.dtl import DTLConfig, DTLModel`
> (`experiments.py:33`). Results it produces describe the rejected architecture.

| Symbol | Full signature | file:line |
|---|---|---|
| `TRAIN_SEED` | `TRAIN_SEED = 3` | `experiments.py:44` |
| `TEST_SEED` | `TEST_SEED = 11` | `experiments.py:45` |
| `DEFAULT_SIZE` | `DEFAULT_SIZE = 240` | `experiments.py:46` |
| `FPR_BUDGET` | `FPR_BUDGET = 0.05` | `experiments.py:47` |
| `build_splits` | `def build_splits(size: int = DEFAULT_SIZE) -> tuple[Stage2Dataset, Stage2Dataset]` — **positional**; `("s2-train", seed=3)` and `("s2-test", seed=11)`, both on the **default `corpus="hard"`** | `experiments.py:50` |
| `ModelResult` | `@dataclass(frozen=True, slots=True)` fields in order: `name: str`, `pr_auc: float \| None`, `recall_at_budget: float \| None`, `precision: float \| None`, `recall: float \| None`, `false_positives: int`, `parameters: int`, `model_bytes: int`, `fit_seconds: float`, `predict_seconds: float`. No defaults. | `experiments.py:59-69` |
| `ModelResult.to_dict` | `def to_dict(self) -> dict[str, Any]` | `experiments.py:71` |
| `_evaluate` (private) | `def _evaluate(model: Any, train: Stage2Dataset, test: Stage2Dataset) -> ModelResult` | `experiments.py:90` |
| `baseline_comparison` | `def baseline_comparison(*, size: int = DEFAULT_SIZE, hidden: int = 24, epochs: int = 40) -> dict[str, Any]` — keyword-only. Builds `DTLModel(DTLConfig(latent=hidden*2, epochs=epochs))`. Returns keys `train`, `test`, `results`, `best_baseline`, `dtl_vs_best_baseline`, `falsification_verdict`. | `experiments.py:120-122` |
| `_falsification_verdict` (private) | `def _falsification_verdict(dtl: ModelResult, baseline: ModelResult) -> dict[str, Any]` — `{"status", "detail"}`; status ∈ `{"DTL_FAILS_CRITERION_1", "DTL_COMPARABLE_BUT_COSTLIER", "DTL_ADVANTAGE_MEASURED"}`. Thresholds: comparable `< 0.02`, baseline wins `> +0.005`. | `experiments.py:152` |
| `latent_sweep` | `def latent_sweep(*, dimensions: tuple[int, ...] = (8, 16, 24, 32, 48, 64, 96, 128), size: int = DEFAULT_SIZE, epochs: int = 40) -> dict[str, Any]` — keys `points`, `best`, `knee`, `note`; knee tolerance 0.01. **The default `dimensions` crashes — see §6 trap 1.** | `experiments.py:190-192` |
| `sleeping_brain` | `def sleeping_brain(*, wake_penalties: tuple[float, ...] = (0.0, 0.05, 0.25, 1.0, 4.0, 16.0), size: int = DEFAULT_SIZE, latent: int = 48, epochs: int = 40) -> dict[str, Any]` — keys `points`, `unpenalised_pr_auc`, `pareto_point`, `routing_is_selective`. **Distinct function from `sleeping_brain.sleeping_brain_report`.** | `experiments.py:221-223` |
| `ABLATIONS` | `ABLATIONS: tuple[tuple[str, dict[str, Any]], ...]` — 7 entries: `full`, `no_relation_head` (`w_relation=0, w_family=0`), `no_state_delta_head` (`w_delta=0`), `no_time_head` (`w_time=0`), `no_phi_head` (`w_phi=0`), `no_prediction_at_all` (all five zeroed), `no_wake_penalty` (`w_wake=0`) | `experiments.py:269-280` |
| `ablation_study` | `def ablation_study(*, size: int = DEFAULT_SIZE, latent: int = 48, epochs: int = 40) -> dict[str, Any]` — keys `results`, `full_pr_auc`, `mechanisms_with_measured_benefit`, `note`; benefit threshold `delta_vs_full < -0.005` | `experiments.py:283-285` |

---

## 3. How to construct and drive the subsystem

The snippet below was **executed successfully in this session** against these
exact signatures (wall clock 3.1 s, `epochs=3`, `count=40`). It is a smoke run,
not a result: the PR-AUC it prints at 3 epochs is meaningless and is
deliberately not quoted here.

```python
# Stage 2 must be driven with the repository root on sys.path, e.g.
#   PYTHONPATH=/home/anil/Documents/Research/pocketsec python drive.py
from pocketsec.stage0.benchmark.security_metrics import average_precision
from pocketsec.stage2.dataset import build_dataset
from pocketsec.stage2.research.baselines import TCNBaseline, build_baselines
from pocketsec.stage2.research.dtl_conv import DTLConvConfig, DTLConvModel
from pocketsec.stage2.research.sleeping_brain import sleeping_brain_report

# 1. Build two disjoint splits. Each call constructs its OWN Stage1Pipeline, so
#    novelty/lattice state never leaks between fit and eval. All keyword-only.
#    corpus must be one of "hard" | "long" | "ambiguous"; the default is "hard",
#    which planning/MEMORY.md records as SATURATED.
train = build_dataset(name="s2-train", count=40, seed=3,  corpus="ambiguous")
test  = build_dataset(name="s2-test",  count=40, seed=11, corpus="ambiguous")
print(train.to_provenance())
assert train.feature_width == test.feature_width  # 96
assert train.encoder_version == test.encoder_version

# 2. Fit a model. Pass EITHER a config object OR **overrides, never both:
#    DTLConvModel(cfg, epochs=3) silently discards epochs=3.
model = DTLConvModel(DTLConvConfig(latent=48, epochs=3)).fit(train)

# 3. Detection scores: one float in [0, 1] per SAMPLE (not per transition),
#    aligned with dataset.labels / dataset.samples order.
scores = model.predict_scores(test)
assert len(scores) == len(test)              # len(dataset) == number of samples
print("pr_auc", average_precision(list(test.labels), scores))

# 4. Routing report. With use_router=False (the default) the report has only
#    {path_fractions, compute_units_per_event, total_steps}; mean_blocks_awake
#    and block_wake_rate appear ONLY when use_router=True.
print(model.route(test))

# 5. Structured surprise, one SurpriseVector per sample. `.epoch` is always 0.0.
print(model.surprise_vectors(test)[0].to_dict())

# 6. Resource profile: parameters, model_bytes_fp32, hidden, final_loss,
#    block_sizes, dilations.
print(model.resource_profile())

# 7. Compare on the cost axis. Every model passed here must be FRESH and
#    UNFITTED: sleeping_brain_report calls .fit() itself, and refitting an
#    already-fitted model CONTINUES training rather than restarting.
report = sleeping_brain_report(
    [TCNBaseline(hidden=24, epochs=3),
     DTLConvModel(DTLConvConfig(latent=48, epochs=3))],
    train,
    test,
)
print(report["pareto"]["verdict"])

# 8. The full baseline suite, identical budget for everyone.
for baseline in build_baselines(hidden=24, epochs=3):
    baseline.fit(train)
    print(baseline.name, average_precision(list(test.labels),
                                           baseline.predict_scores(test)))
```

Measured on the run above (`count=40`, `corpus="ambiguous"`, 96-wide features):
`DTLConvModel(latent=48)` default flags → `parameters = 19851`,
`model_bytes_fp32 = 79404`, `block_sizes = {'fast': 11, 'uncertainty': 5,
'session': 10, 'causal': 7, 'host': 10, 'epoch': 5}`,
`dilations = {'fast': 1, 'uncertainty': 2, 'session': 4, 'causal': 8,
'host': 16, 'epoch': 32}`; `TCNBaseline(hidden=24)` → `parameters = 6961`,
`model_bytes_fp32 = 27844`.

To encode a single Stage 1 transition directly (the runtime path, stdlib only):

```python
from pocketsec.stage1.labs.corpus import ATTACK_EXFIL, Scenario
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage2.encoder.ssir_encoder import (
    FEATURE_WIDTH, NEED_SIGNAL_INDICES, encode_ssir_transition, feature_names,
)

transitions = Stage1Pipeline().run_scenario(Scenario("a", ATTACK_EXFIL, 1)).transitions
encoded = encode_ssir_transition(transitions[0], actor_slot=0)
assert len(encoded.features) == FEATURE_WIDTH == 96
assert len(feature_names()) == FEATURE_WIDTH
print(encoded.features[NEED_SIGNAL_INDICES["delta_phi"]])   # squashed |ΔΦ|, not raw
print(encoded.delta_phi)                                    # raw signed ΔΦ
print(encoded.evidence)                                     # locators for DTL-F20
```

---

## 4. Invariants enforced in code

Each row names the enforcing line or test. "Prose only" means the docstring
asserts it but nothing checks it.

| # | Invariant | Enforced at |
|---|---|---|
| 1 | Exactly twenty core functional IDs exist. | `core_ids.py:240` (module-level `assert`, **stripped under `-O`**) and `tests/test_stage2_foundation.py::test_twenty_core_ids_are_defined` |
| 2 | Every core ID key starts with `DTL-F`. | `tests/test_stage2_foundation.py::test_twenty_core_ids_are_defined` |
| 3 | REQUIRED and OPTIONAL sets are disjoint and both non-empty. | `tests/test_stage2_foundation.py::test_required_and_optional_functions_are_distinguished` |
| 4 | Every core ID names a `D2.*` deliverable. | `tests/test_stage2_foundation.py::test_every_core_id_names_a_deliverable` |
| 5 | `CORE_IDS` is immutable. | `core_ids.py:233` (`MappingProxyType`) |
| 6 | Execution-path costs increase monotonically P0→P4. | `tests/test_stage2_foundation.py::test_execution_path_costs_increase_monotonically`; `tests/test_stage2_sleeping_brain.py::test_path_costs_are_ordered_cheapest_first` |
| 7 | The Stage 2 interface version is registered once and cannot silently change. | `core_ids.py:33` via `pocketsec.stage0.contracts.common.register_schema` (`common.py:49`, raises `ContractError` on a differing re-registration) |
| 8 | Encoder output length always equals the declared layout width. | `ssir_encoder.py:244-247` (`AssertionError` at runtime) and `tests/test_stage2_foundation.py::test_feature_layout_matches_declared_width` |
| 9 | `feature_names()` has exactly one name per feature slot. | `tests/test_stage2_foundation.py::test_feature_layout_matches_declared_width` |
| 10 | Encoding is deterministic for the same transition. | `tests/test_stage2_foundation.py::test_encoding_is_deterministic` |
| 11 | Every feature is finite and within `[-1.0, 1.0]`. | `tests/test_stage2_foundation.py::test_every_feature_is_finite_and_bounded` |
| 12 | ADR-0007: identity and display name are invisible to the model — two transitions differing only in those fields encode identically. | `tests/test_stage2_foundation.py::test_encoder_ignores_identity_and_display_name` |
| 13 | ADR-0007 belt-and-braces: the encoder source never accesses `.identity` or `.display_name` (AST check). | `tests/test_stage2_foundation.py::test_encoder_module_never_reads_identity_fields` |
| 14 | Evidence locators survive encoding for DTL-F20 and are not features. | `tests/test_stage2_foundation.py::test_encoder_preserves_evidence_for_binding` |
| 15 | Need-signal indices are derived from the layout, never hardcoded. | `ssir_encoder.py:113-119` (built from `GROUP_OFFSETS`) |
| 16 | Every split gets a fresh `Stage1Pipeline`, so novelty state cannot leak fit→eval. | `dataset.py:165`; `tests/test_stage2_foundation.py::test_dataset_build_is_independent_of_call_order`, with its own guard test `::test_a_shared_pipeline_would_change_features` |
| 17 | Dataset provenance is complete (encoder version, feature width, seed, base rate…). | `tests/test_stage2_foundation.py::test_dataset_provenance_is_complete` |
| 18 | Built datasets contain both classes. | `tests/test_stage2_foundation.py::test_dataset_contains_both_classes`; `tests/test_stage2_dtl_conv.py::test_ambiguous_corpus_has_both_classes` |
| 19 | Unknown corpus names are rejected, not silently defaulted. | `dataset.py:162-163` (`ValueError`) |
| 20 | `backward()` refuses a non-scalar output. | `autograd.py:86-87`; `tests/test_stage2_foundation.py::test_backward_requires_a_scalar` |
| 21 | Autodiff gradients match finite differences for tanh, sigmoid, relu, log_softmax, cross_entropy, binary_cross_entropy, matmul, bmm, concat, reshape, transpose, exp. | `tests/test_stage2_foundation.py::test_gradient_*` (12 tests, tolerance `1e-6`) |
| 22 | Normalised losses start at ≈1.0 regardless of vocabulary size. | `tests/test_stage2_dtl_conv.py::test_normalised_losses_start_near_one` |
| 23 | At least five baselines exist (acceptance criterion 1). | `tests/test_stage2_foundation.py::test_at_least_five_baselines_exist` |
| 24 | Every baseline beats the dataset base rate — a below-chance model is a bug. | `tests/test_stage2_foundation.py::test_every_baseline_beats_the_base_rate` |
| 25 | Every baseline reports a measured resource profile and scores every sample. | `tests/test_stage2_foundation.py::test_baselines_report_measured_resource_profiles`, `::test_every_baseline_scores_every_sample` |
| 26 | Padded steps never move recurrent/convolutional state. | `baselines.py:302` (GRU), `:336-337` (LSTM), `:376` (TCN); `dtl.py:325`; `tests/test_stage2_foundation.py::test_padding_does_not_change_a_recurrent_verdict` |
| 27 | Dilated conv windows are causal (step *t* sees only steps ≤ *t*). | `dtl_conv.py:217-234`; `tests/test_stage2_dtl_conv.py::test_dilated_windows_are_causal` |
| 28 | Dilations are strictly increasing and start at 1. | `tests/test_stage2_dtl_conv.py::test_dilations_are_strictly_increasing` |
| 29 | Block shares sum exactly to the latent budget. | `dtl.py:96-98`, `dtl_conv.py:136`; `tests/test_stage2_dtl_conv.py::test_block_shares_sum_to_the_latent_budget` (**only checked at `latent=48`** — see §6 trap 1) |
| 30 | Ablating multiscale keeps the capacity budget (capacity-matched control). | `dtl_conv.py:128-131`; `tests/test_stage2_dtl_conv.py::test_ablating_multiscale_keeps_the_capacity_budget` |
| 31 | `route()` path fractions sum to 1.0 and compute units are positive. | `tests/test_stage2_dtl_conv.py::test_routing_reports_a_path_distribution` |
| 32 | Router and surprise are off by default; multiscale and maxpool on. | `tests/test_stage2_dtl_conv.py::test_router_and_surprise_are_removed_by_default` |
| 33 | Lineage pooling is off by default and measurably changes nothing. | `tests/test_stage2_dtl_conv.py::test_lineage_pooling_is_off_by_default`, `::test_lineage_pooling_adds_nothing_because_stage1_already_attributes` |
| 34 | `actor_slot` is session-local: slots start at 0 and are dense. | `dataset.py:128-136`; `tests/test_stage2_dtl_conv.py::test_actor_slot_is_a_grouping_key_not_an_identity` |
| 35 | The ambiguous corpus is aggregate-matched — the label is not inferable from operation counts. | `tests/test_stage2_dtl_conv.py::test_ambiguous_corpus_is_aggregate_matched` |
| 36 | ADR-0009 findings cannot regress quietly: detached beats joint heads by >0.3; re-weighting does not fix joint; maxpool is load-bearing (>0.3); DTL-C matches the TCN within 0.02. | `tests/test_stage2_dtl_conv.py::test_joint_heads_destroy_detection`, `::test_joint_head_damage_is_not_a_weighting_problem`, `::test_maxpool_is_the_load_bearing_component`, `::test_dtl_conv_matches_the_best_baseline` (all `@pytest.mark.slow`) |
| 37 | ADR-0010's verdict cannot regress: the TCN is cheaper per event at equal-or-better quality. | `tests/test_stage2_sleeping_brain.py::test_dtl_is_dominated_on_cost_at_equal_quality` (`@pytest.mark.slow`) |
| 38 | The ambiguous corpus saturation state is pinned; making it harder deliberately fails the test as a prompt to re-run ablations. | `tests/test_stage2_dtl_conv.py::test_ambiguous_corpus_is_currently_saturated` |
| 39 | ADR-0008 both directions: no runtime module imports `pocketsec.stage2.research`, and `research/` is the only numpy user. Checked by AST, so a docstring naming the boundary is not mistaken for crossing it. | `tests/test_repository_structure.py::test_runtime_never_imports_research_code` (`:89`), `::test_research_package_is_the_only_numpy_user` (`:111`); `RESEARCH_PREFIX` at `:73` |
| 40 | ADR-0001: the endpoint runtime depends on the stdlib alone. | `tests/test_repository_structure.py:122-123` |
| 41 | `cheap_path_share` counts only P0+P1+P2, and is `None` without routing. | `tests/test_stage2_sleeping_brain.py::test_cheap_path_share_counts_only_the_cheap_tiers`, `::test_models_without_routing_report_no_path_share` |
| 42 | The Pareto verdict names a model that is actually tied at best quality. | `tests/test_stage2_sleeping_brain.py::test_pareto_identifies_the_cheapest_model_at_best_quality` |
| **Prose only** | "The three signals stay separate" (novelty / Φ / uncertainty occupy distinct slots). | `ssir_encoder.py:13-15` docstring. Nothing checks it; it holds by inspection of the layout (groups 7, 9, 10). |
| **Prose only** | "Surprise is a measurement, not a thing to backpropagate through." | `dtl.py:364-370`. Held by construction (`_surprise_summary` works on `.data`), not by a test. |
| **Prose only** | `PATH_COST_UNITS` "calibrated from measured CPU time in `research.sleeping_brain`". | `core_ids.py:60-61`. **No calibration code exists in `sleeping_brain.py`**; the five values are literals. Treat the calibration claim as **UNMEASURED**. |

---

## 5. Extension points

### Sanctioned — plug in here

1. **`Stage2Model` protocol (`baselines.py:52`).** Any new model implements
   `name: str`, `fit(dataset) -> Self`, `predict_scores(dataset) -> list[float]`,
   `resource_profile() -> dict[str, Any]` (which must contain `"parameters"` and
   `"model_bytes_fp32"` — `_evaluate` at `experiments.py:111-112` and
   `sleeping_brain_report` at `sleeping_brain.py:129` both index them). Optional
   extras `route(dataset)` and `surprise_vectors(dataset)` are discovered by
   `hasattr` at `sleeping_brain.py:122`.
2. **`BASELINE_REGISTRY` (`baselines.py:582`) and `build_baselines`
   (`baselines.py:595`).** Add a class to the registry *and* an instance to
   `build_baselines` — nothing derives one list from the other, so adding to only
   one silently leaves the new baseline out of every comparison.
3. **`build_dataset(corpus=...)` (`dataset.py:147`).** New corpora register in
   the `builders` dict at `dataset.py:157-161`. A builder must accept
   `(*, count: int, seed: int, split: str)` and return `tuple[Scenario, ...]`.
4. **`DTLConvConfig` mechanism flags (`dtl_conv.py:92-118`).** `use_router`,
   `use_multiscale`, `use_surprise`, `use_maxpool`, `use_lineage_pool`,
   `detach_heads` are the sanctioned ablation switches. `experiments.ABLATIONS`
   (`experiments.py:269`) is the sanctioned place to add a new loss-weight
   ablation for the recurrent core.
5. **`EncodedTransition.evidence` (`ssir_encoder.py:172`).** The intended hand-off
   for DTL-F20 / Stage 3 evidence binding. It is carried end-to-end and is
   guaranteed never to be a model feature.
6. **`EncodedTransition.actor_slot` (`ssir_encoder.py:169`).** A session-local
   grouping key available to any model that needs per-lineage structure. Measured
   to add nothing on current corpora, but the plumbing is live.
7. **`DTLModel.path_histogram` (`dtl.py:514`).** A deliberately *deterministic,
   auditable* policy, not a learned head. Changing the five weights or four
   thresholds here is the sanctioned way to change path assignment. Stage 3 should
   read `ExecutionPath` / `PATH_COST_UNITS` from `core_ids.py`, never redefine them.
8. **The eleven empty packages (§7).** They are the named homes for D2.6–D2.15.
   A later stage implementing DTL-F04/F07/F10/F11/F16/F17/F18/F19 puts the code
   in the matching package, stdlib-only.

### Forbidden — do NOT plug in here

1. **Never import `pocketsec.stage2.research.*` from any runtime module.** That
   would pull numpy onto the 2 GB endpoint. Enforced by AST at
   `tests/test_repository_structure.py:89`. This also means: do not import
   `dtl._pad`, `Tensor`, `SurpriseVector`, `DTLConvModel` or anything else from
   `research/` into `stage2/router/`, `stage2/state/`, `stage2/lattice/` etc.
2. **Do not change `FEATURE_LAYOUT` (`ssir_encoder.py:75-91`) without bumping
   `ENCODER_VERSION` (`:45`).** Every trained weight, every `GROUP_OFFSETS`
   consumer, every `NEED_SIGNAL_INDICES` consumer and every stored dataset
   provenance record is indexed against it. `Stage2Dataset.encoder_version`
   exists precisely so a stale artifact is detectable.
3. **Do not add identity, name, path, pid or command-string features to the
   encoder.** ADR-0007; two tests fail, one of them an AST check
   (`test_encoder_module_never_reads_identity_fields`).
4. **Do not re-register `DTL_INTERFACE_ID` with a different version.** A breaking
   change takes a new id (`...v2`); `register_schema` raises `ContractError`.
5. **Do not build a learned execution-path head.** There is no ground truth for
   "which path should this event have taken"; an earlier learned version fitted
   noise, which is why `path_histogram` is a fixed policy (`dtl.py:516-524`,
   and `planning/MEMORY.md` benchmarking trap 6).
6. **Do not treat `DTLModel` or `DTLConvModel` as the Stage 2 core.** ADR-0010
   rejected DTL. Per `planning/MEMORY.md`, the Stage 2 core is a TCN
   (`TCNBaseline`, `baselines.py:345`) with optional *detached* auxiliary heads.
7. **Do not build D2.6–D2.15 on the current core or on the current corpora.**
   `planning/MEMORY.md` records that all four corpora are either trivial or
   impossible, that the ambiguous corpus is saturated again
   (`test_ambiguous_corpus_is_currently_saturated`), and that real telemetry is
   required before a predictive core can be judged. The Stage 2 gate is BLOCKED.
8. **Do not mutate `PATH_COST_UNITS`** (`core_ids.py:62`). It is a plain dict and
   a module-level global; a mutation changes every subsequent
   `compute_units_per_event` in the process.
9. **Do not add `route` / `surprise_vectors` to the `Stage2Model` protocol.**
   `sleeping_brain_report` deliberately treats them as optional so
   non-routing baselines stay comparable.

---

## 6. Traps — concrete ways to get silently wrong results

All of the following were **verified by running code in this session** unless
marked otherwise.

1. **`latent_sweep()` with its own defaults crashes; and just above the crash
   boundary a block is silently annihilated.** The `max(2, ...)` floor per block
   combined with absorbing all rounding drift into `"fast"`
   (`dtl.py:92-98`, `dtl_conv.py:131-136`) makes `"fast"` go negative or zero at
   small budgets. Measured on this machine, `epochs=1`, 6-sample ambiguous split:

   | `latent` | `DTLConfig.block_sizes()["fast"]` | `.fit()` | `DTLConvConfig` `"fast"` | `.fit()` |
   |---|---|---|---|---|
   | 6 | −4 | `ValueError: negative dimensions are not allowed` | −4 | same `ValueError` |
   | 7 | −3 | `ValueError` | −3 | `ValueError` |
   | 8 | −2 | `ValueError` | −2 | `ValueError` |
   | 9 | −1 | `ValueError` | −1 | `ValueError` |
   | 10 | **0** | **trains without error** | **0** | **trains without error** |
   | 11 | **0** | **trains without error** | 1 | OK |
   | 12 | 1 | OK | 2 | OK |
   | 48 | 15 | OK | 11 | OK |

   Two separate hazards. (a) `latent_sweep` defaults to
   `dimensions=(8, 16, 24, 32, 48, 64, 96, 128)` (`experiments.py:191`), so
   calling it with no arguments dies on its **first** point with
   `ValueError: negative dimensions are not allowed`. (b) At `latent=10`
   (both cores) and `latent=11` (`DTLModel` only) the `"fast"` block gets width
   **0** and the model trains happily with the fastest timescale **entirely
   absent** — no error, no warning, and `block_sizes` still sums to `latent`
   so invariant 29 still holds. Smallest latent at which every block is
   non-degenerate: **12** for `DTLModel`, **11** for `DTLConvModel`. The guard
   test (`test_block_shares_sum_to_the_latent_budget`) only checks `latent=48`
   and only checks the sum, so neither hazard is caught.
2. **Passing a config *and* keyword overrides silently discards the overrides.**
   `self.config = config or DTLConfig(**overrides)` (`dtl.py:206`,
   `dtl_conv.py:151`). Measured: `DTLModel(DTLConfig(latent=48), latent=8,
   epochs=1).config` is `DTLConfig(latent=48, ..., epochs=60, ...)` — the
   `epochs=1` was dropped. You then train for 60 epochs believing you asked for
   1. Use one form or the other, never both.
3. **Fitting an already-fitted model continues training instead of restarting.**
   `_build` returns early on `self._built` (`dtl.py:229-230`,
   `dtl_conv.py:174-175`) or on `if self.params: return`
   (`baselines.py:251, 277, 313, 355, 394, 452`). Measured on
   `TCNBaseline(epochs=2)`: after two `fit()` calls `len(model.params)` is still
   `4` but `len(model._losses)` is `4` and the loss fell from `0.7358` to
   `0.7013`. Anything that fits models for you — `sleeping_brain_report`
   (`sleeping_brain.py:120`), `_evaluate` (`experiments.py:92`) — therefore
   requires **fresh instances**. Reusing one across two corpora gives a model
   trained on both.
4. **`DTLConvModel.route()` returns a different key set depending on
   `use_router`.** Measured: with the default `use_router=False` the keys are
   `{compute_units_per_event, path_fractions, total_steps}`; with
   `use_router=True` they are those plus `{block_wake_rate, mean_blocks_awake}`
   (`dtl_conv.py:465-471`). `DTLModel.route()` always returns all six plus
   `path_histogram` (`dtl.py:499-512`). Code written against `DTLModel.route`
   and pointed at `DTLConvModel` raises `KeyError: 'mean_blocks_awake'` — which
   is exactly what `experiments.sleeping_brain` does at `experiments.py:245`.
5. **Path accounting is notional, not real savings.** `planning/MEMORY.md`
   (ADR-0010) records that the router reported 100% cheap-path resolution while
   still being 3.4× slower, because **every branch is computed regardless of its
   gate**. In `dtl_conv.forward` the gate multiplies an activation that was
   already computed (`dtl_conv.py:258-264`); in `dtl.forward` every block's
   candidate and write gate are computed before gating (`dtl.py:314-325`).
   `route()["path_fractions"]` and `compute_units_per_event` are therefore a
   *policy simulation*, not a measurement of work avoided. The only honest cost
   number in the subsystem is `SleepingBrainPoint.microseconds_per_event`
   (wall clock).
6. **`Stage2Sample.final_phi` is not the final Φ — it is `result.peak_phi`**
   (`dataset.py:143`). Measured example: an attack sample from the ambiguous
   corpus reported `final_phi: 0.0`. Supervising a hazard head on this field
   under the assumption it is a terminal state value will train on a peak.
7. **`PhiOracleBaseline` scores the *squashed absolute* ΔΦ, not raw ΔΦ.** It
   reads `features[NEED_SIGNAL_INDICES["delta_phi"]]` = index 73
   (`baselines.py:572-576`), which is `abs(φ)/(abs(φ)+8.0)`
   (`ssir_encoder.py:221`). Consequences: scores are bounded in `[0, 1)`
   (measured range on one small split: `0.2`–`0.5`), a large *negative* ΔΦ
   scores as high as a large positive one, and the sign bit lives in a separate
   slot (index 74) that the oracle never reads. Any reproduction of the
   "phi-oracle reaches 0.7484 with zero parameters" figure from
   `planning/MEMORY.md` must use this exact definition.
8. **`MarkovBaseline.predict_scores` is not independent per sample.** It divides
   every score by `max(scores) or 1.0` over the batch it was handed
   (`baselines.py:229-230`). Measured: the same sample scores `0.981` when the
   40-sample split is passed and `1.0` when only the first 3 samples are passed.
   Consequences: scores are not comparable across evaluation runs, a
   per-sample streaming caller gets `1.0` for everything, and calibration is
   meaningless. It also fits on benign samples only (`baselines.py:202-204`), so
   an all-positive dataset leaves `_contexts` empty.
9. **`VQPrototypeBaseline` is supervised, despite reading like a clustering
   baseline.** `fit` uses `dataset.labels` to build per-prototype risk
   (`baselines.py:517-528`). It is not an unsupervised anomaly control, and its
   `predict_scores` returns risk *probabilities*, not distances. Unfitted it
   returns all-zeros (`baselines.py:532-533`) rather than raising — a silent
   all-zero score vector.
10. **`build_dataset` always requests `split="eval"`** (`dataset.py:168`),
    hard-coded. All three corpus builders accept `split` and have a benign-only
    `"train"` mode (`hard_corpus.py:249`, `longhorizon_corpus.py:170`,
    `ambiguous_corpus.py:268`), which is **unreachable through the Stage 2 API**.
    So the "train" and "test" splits differ only by seed, and both are mixed
    label splits. Anyone assuming Stage 2's train split is benign-only (as an
    anomaly-detection setup would require) is wrong.
11. **The default corpus is the saturated one.** `build_dataset(corpus="hard")`
    is the default (`dataset.py:148`), and `experiments.build_splits`
    (`experiments.py:50-55`) uses it. `planning/MEMORY.md` records the hard
    corpus as saturated (five architectures tie at 0.9992), so ablations run on
    the defaults cannot show that any component helps. Use `corpus="ambiguous"`
    or `"long"` deliberately — and note that
    `test_ambiguous_corpus_is_currently_saturated` records ambiguous as
    saturated too.
12. **`build_dataset` silently returns fewer samples than `count`.** Scenarios
    that produce no transitions are dropped (`dataset.py:170-172`), and
    `sample_id` embeds the *scenario* index, not the sample index
    (`dataset.py:139`). Never assume `len(dataset) == count`.
13. **Two different `_pad` functions share one name.** `baselines._pad`
    (`baselines.py:71`) returns `(batch, mask, labels)`; `dtl._pad`
    (`dtl.py:151`) returns a 10-key dict. `dtl_conv.py:59` imports the private
    `dtl._pad`. Importing the wrong one gives a `TypeError` at best and silently
    mis-shaped tensors at worst. Neither tolerates an empty `samples` tuple
    (`max()` over an empty sequence, and `samples[0].steps[0]`).
14. **`_pad`'s `actor_slot` uses `-1` for padding** (`dtl.py:166`), while every
    other array pads with `0`. `DTLConvModel._lineage_pool` relies on the
    `mask > 0` conjunct to exclude them (`dtl_conv.py:344`); any new consumer
    that groups by `actor_slot` without masking will create a phantom lineage
    `-1` and, worse, real slot 0 is a valid lineage.
15. **`Tensor.index_select` has a wrong/broken backward for `axis != 0`.**
    `np.add.at(gradient, indices, out.grad)` at `autograd.py:242` ignores the
    `axis` argument entirely. Measured: `Tensor(x, requires_grad=True)
    .index_select(np.array([0, 2]), axis=1).sum().backward()` raises
    `ValueError: array is not broadcastable to correct shape`. Where shapes
    happen to be broadcastable it will produce **silently wrong gradients**.
    Nothing in the repository uses it and no test covers it. Do not use it with
    `axis != 0` without fixing it first.
16. **The autodiff gradient-check suite does not cover every op used in
    training.** `tests/test_stage2_foundation.py` checks tanh, sigmoid, relu,
    log_softmax, cross_entropy, binary_cross_entropy, matmul, bmm, concat,
    reshape, transpose and exp. It does **not** check `sum(axis=…)`, `mean`,
    `slice_cols`, `slice_step`, `slice_rows`, `index_select`, broadcast `add`,
    `mul`, `sub`, `rsub` or `neg` — several of which are load-bearing in both
    DTL cores. I gradient-checked the gaps in this session: `slice_cols`,
    `slice_step`, `slice_rows`, `sum(axis=1)`, `sum(axis=1, keepdims=True)`,
    `mean(axis=1)`, `mean()`, broadcast `add`, `mul`/`sub` by scalar, `rsub` and
    `neg` all agree with finite differences to ≤ 3.1e-10. `index_select` with
    `axis != 0` is the only failure (trap 15). If you add an op, add its check —
    the test file is not a safety net for ops it does not name.
17. **`SurpriseVector.epoch` is always exactly 0.0.** `_surprise_summary` sets
    `out[:, 5] = 0.0` with the comment "epoch consistency: reserved, measured in
    D2.12" (`dtl.py:403`) — and D2.12 does not exist. So `magnitude` and
    `security_weighted` both include a permanently dead sixth component. Do not
    read epoch surprise from this vector.
18. **With `detach_heads=True` (the default), the head loss weights cannot
    affect detection.** `head_input = Tensor(latent_seq.data)`
    (`dtl_conv.py:288-290`) creates a parentless tensor, so no gradient from
    `w_relation`, `w_family`, `w_delta`, `w_time` or `w_phi` reaches the
    convolutional branches. Ablating them on `DTLConvModel` will correctly
    measure "no effect" — and that is a property of the wiring, not evidence
    about prediction-driven detection. `experiments.ABLATIONS` ablates exactly
    these weights, but on `DTLModel` (which is *not* detached), so the two
    results are not interchangeable.
19. **With `use_surprise=False` (the default), the surprise vector is still
    computed every forward pass.** `surprise = DTLModel._surprise_summary(...)`
    at `dtl_conv.py:295` runs unconditionally, before the flag is consulted at
    `:296`. It costs a Python loop over every step. Timing `DTLConvModel` and
    attributing the cost to the mechanisms that are switched *on* will
    mis-attribute it.
20. **`w_wake` is inert on `DTLConvModel` unless `use_router=True`.**
    `wake_cost` is `Tensor(0.0)` otherwise (`dtl_conv.py:302-307`). Sweeping
    `w_wake` with default flags sweeps nothing. `DTLModel` always has a live
    wake cost (`dtl.py:352`).
21. **`experiments.py` measures the rejected architecture.** All four entry
    points (`baseline_comparison`, `latent_sweep`, `sleeping_brain`,
    `ablation_study`) construct `DTLModel`, never `DTLConvModel`
    (`experiments.py:33, 127, 198, 235, 298`). Presenting their output as "the
    Stage 2 result" reports the recurrent core that ADR-0009 replaced and
    ADR-0010 rejected.
22. **Two different functions are called `sleeping_brain`.**
    `experiments.sleeping_brain` (`experiments.py:221`) sweeps `w_wake` on
    `DTLModel`. `sleeping_brain.sleeping_brain_report`
    (`sleeping_brain.py:108`) times an arbitrary model list. They return
    different key sets and answer different questions.
23. **`ExecutionPath` is a `StrEnum`, so path keys are strings in some places and
    enum members in others.** `path_histogram` keys by `path.value`
    (`dtl.py:540`); `PATH_COST_UNITS` keys by the enum member
    (`core_ids.py:62`). Because `StrEnum` members compare equal to their values
    this mostly works, but `dict[ExecutionPath, float]` and `dict[str, float]`
    are not interchangeable for `isinstance`/type-checking purposes, and a
    literal-string key that is not a valid path name will `KeyError` only at cost
    aggregation time.
24. **`PATH_COST_UNITS` and `REQUIRED_IDS` are absent from `core_ids.__all__`.**
    `from pocketsec.stage2.core_ids import *` gives you neither, even though both
    are used by `dtl.py`, `dtl_conv.py`, `sleeping_brain.py` and the tests.
25. **`Stage2Dataset` positional construction is a foot-gun.** Declaration order
    is `(name, seed, corpus, encoder_version, feature_width, samples)`
    (`dataset.py:75-80`) while `build_dataset` passes keywords in the order
    `(name, corpus, seed, …)` (`dataset.py:174-181`). Constructing positionally
    in the order you read in `build_dataset` swaps `seed` and `corpus` — both
    land in `to_provenance()` and nothing type-checks it (`seed: int` would
    receive `"ambiguous"`).
26. **`len(dataset)` is sample count; `dataset.transition_count` is event
    count.** `microseconds_per_event` divides by `transitions`
    (`sleeping_brain.py:60`, fed `test.transition_count` at
    `sleeping_brain.py:128`). Mixing the two silently rescales every cost figure
    by the mean sequence length (measured `73.1` on one 40-sample ambiguous
    split).
27. **`DTL_BLOCKS` and `DTLC_BLOCKS` list the six blocks in *different
    orders*.** `DTL_BLOCKS` = fast, session, host, epoch, causal, uncertainty
    (`dtl.py:55`). `DTLC_BLOCKS` = fast, uncertainty, session, causal, host,
    epoch (`dtl_conv.py:64`). Router gate index *i* therefore means a different
    block in each core, and `block_wake_rate` keys are enumerated from
    `self.block_sizes` insertion order (`dtl_conv.py:468-471`) versus
    `DTL_BLOCKS` order (`dtl.py:507-509`). Never index a gate column by a
    position learned from the other core.
28. **`_lineage_pool` gradients flow only through a selector built from
    `.data`.** The argmax and the per-slot means are computed on raw numpy
    (`dtl_conv.py:339-358`) and only the final `latent_seq * Tensor(selector)`
    is differentiable. The winner assignment is treated as a constant, which is
    standard for max-pooling but means no gradient teaches the model *which*
    lineage to select. The local `best` array and its `assert best is not None`
    (`dtl_conv.py:340, 359`) are dead code.
29. **`TransformerBaseline`'s positional encoding assumes an even feature
    width.** `positions[:, 1::2] = np.cos(index * divisor)[:, : width // 2]`
    (`baselines.py:412`). It works at the current width of 96; an odd width
    would raise a shape error. If `FEATURE_LAYOUT` ever grows by an odd amount,
    this baseline breaks before the encoder does.
30. **`MLPBaseline` and `VQPrototypeBaseline` max/mean-pool `batch * mask`,
    which assumes non-negative features.** `np.max(batch * mask[..., None],
    axis=1)` (`baselines.py:261`) returns `0.0` for a channel whose real values
    are all negative. Current features are measured to be in `[-1, 1]` but the
    bounded-feature test permits negatives, so adding a signed feature to the
    layout would silently corrupt these two baselines only.
31. **`ruff` and `mypy` have never been run on this repository**
    (`planning/MEMORY.md`, "Known gap"). Consistent with that, I found four
    unused imports by AST in `research/`: `dtl.py` imports `field`,
    `binary_cross_entropy` and `cross_entropy` without using them
    (`dtl.py:30, 41, 47`); `dtl_conv.py` imports `binary_cross_entropy` and
    `cross_entropy` without using them (`dtl_conv.py:52, 57`). Harmless, but do
    not read their presence as evidence that either loss is in use.
32. **`core_ids.py`'s twenty-ID invariant is a bare `assert`** (`core_ids.py:240`)
    and disappears under `python -O`. The pytest equivalent
    (`test_twenty_core_ids_are_defined`) is the durable guard.
33. **`Stage2Sample.next_step_targets` and `Tensor.mean`, `Tensor.slice_rows`,
    `zeros_like_params`, `BASELINE_REGISTRY` and the `Stage2Model` protocol are
    public but unused anywhere in `pocketsec/` or `tests/`** (verified by grep).
    They are untested by use. `zeros_like_params` in particular returns `None`
    despite a name that suggests it returns zeroed arrays.

---

## 7. The eleven empty placeholder packages

Verified by `stat`: each of the following is a directory containing exactly one
file, `__init__.py`, of **0 bytes**. There is no other code in any of them.

| Package | Bytes | Deliverable / core IDs it is named for (inferred from `core_ids.py` deliverable strings — **not asserted in code**) |
|---|---|---|
| `pocketsec/stage2/adaptation/__init__.py` | 0 | D2.12 — DTL-F18 `detect_epoch_mismatch`, DTL-F19 `quarantine_adaptation_sample` (**both REQUIRED**) |
| `pocketsec/stage2/cache/__init__.py` | 0 | D2.13 — DTL-F15 `forget_low_utility_memory`, DTL-F16 `lookup_transition_cache` |
| `pocketsec/stage2/compile_candidates/__init__.py` | 0 | D2.13 — DTL-F17 `propose_compile_candidate` (Stage 3 hand-off) |
| `pocketsec/stage2/counterfactual/__init__.py` | 0 | D2.10 / D2.11 — DTL-F11 `counterfactual_probe`, DTL-F12 `request_observation_escalation` |
| `pocketsec/stage2/credit/__init__.py` | 0 | D2.10 — DTL-F10 `assign_causal_credit` |
| `pocketsec/stage2/lattice/__init__.py` | 0 | D2.6 / D2.7 — DTL-F04 `quantize_behaviour_atom`, DTL-F13 `merge_equivalent_atoms`, DTL-F14 `split_heterogeneous_atom` |
| `pocketsec/stage2/predictors/__init__.py` | 0 | D2.5 / D2.8 — DTL-F05 `predict_future_cone`, DTL-F06, DTL-F08 `estimate_security_hazard`, DTL-F09 |
| `pocketsec/stage2/router/__init__.py` | 0 | D2.4 — DTL-F02 `route_information_need` (**REQUIRED**) |
| `pocketsec/stage2/state/__init__.py` | 0 | D2.3 — DTL-F03 `update_multiscale_state` (**REQUIRED**) |
| `pocketsec/stage2/uncertainty/__init__.py` | 0 | D2.9 — DTL-F07 `estimate_uncertainty` (**REQUIRED**) |
| `pocketsec/stage2/encoder/__init__.py` | 0 | Package init only; the implementation is the sibling file `encoder/ssir_encoder.py` (260 lines). This is the one "empty `__init__`" that does **not** mean an empty subsystem. |

Consequences for a later-stage implementer:

- `from pocketsec.stage2.router import ...` imports successfully and exports
  nothing. An `ImportError` on a name is the *only* signal you get; there is no
  `NotImplementedError` stub anywhere.
- No runtime module implements DTL-F02, F03, F07, F18, F19 or the export half of
  F20 — six of the eight REQUIRED functions have no stdlib-only implementation.
  Only DTL-F01 is fully implemented on the runtime path.
- Nothing outside `pocketsec/stage2/` imports `pocketsec.stage2` at all (verified
  by grep across `pocketsec/`). Stage 2 is currently a leaf: no consumer exists,
  so no contract is yet load-bearing on these names.
- Whatever lands in these packages must be **stdlib only** and must not import
  `pocketsec.stage2.research` (see §5 forbidden #1).

---

## 8. Recorded Stage 2 verdicts (source-attributed, not re-measured here)

These are quoted from `planning/MEMORY.md` and the ADRs it names. I did not
reproduce any of them in this session; reproducing them requires the `slow`
tests. They are included because an implementer who does not know them will
rebuild rejected machinery.

- **ADR-0010: DTL is rejected.** At equal detection (1.0000) the TCN cost
  6.6 µs/event versus DTL-C's 22.3 with 2.8× the parameters → dominated. Stage 2
  core = a TCN with optional detached auxiliary heads retained for Stage 3.
- **ADR-0009: the recurrent core lost to a plain TCN** on long-horizon sessions
  (TCN 1.0000 vs DTL 0.4736 at half the parameters), which is why
  multi-timescale recurrence became multi-dilation causal convolution.
- **Predictive heads must be detached.** Joint 0.3333 vs detached 1.0000;
  `w_detect=8` did not fix it. "Detection emerges from prediction" is
  **contradicted as implemented**.
- **Component verdicts on the ambiguous corpus:** multi-timescale dilations
  +0.068 JUSTIFIED; max-pool +0.046 JUSTIFIED; Need router −0.115 HARMFUL;
  surprise vector −0.073 HARMFUL.
- **Stage 1 is vindicated:** the phi-oracle reaches 0.7484 with zero parameters.
  About three quarters of the task is solved by the representation alone.
- **Per-lineage pooling was RETRACTED**; the earlier +0.042 was label noise from
  two corpus defects.
- **Corpus trap:** Stage 1 carries lineage state *across scenarios* on a shared
  pipeline, so any corpus reusing process identities between sessions erases its
  own signal. `build_dataset` avoids this by constructing a fresh pipeline per
  split (`dataset.py:165`).
- **Synthetic data cannot settle this.** Four corpora produced only trivial or
  impossible tasks. Real telemetry is required before a predictive core can be
  judged. The Stage 2 gate is **BLOCKED**.
