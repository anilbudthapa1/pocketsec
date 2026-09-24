# Stage 2 — DTL completion specification (D2.1 … D2.15)

- **Status:** Implementation contract for the Stage 2 completion wave. Binding on all eight work packages.
- **Date:** 2026-09-24
- **Architecture source of truth:** `docs/architecture/sources/stage-02-dtl.md`
- **Build contract:** `docs/architecture/stage-3-12-integration-plan.md`
- **Binding prior decisions:** ADR-0009, ADR-0010, `docs/stage-2-dtl-findings.md`, `planning/MEMORY.md`
- **ADR block assigned to this wave:** **0113–0122** (see §8; 0011–0012 are pre-assigned to Wave 3, 0013–0112 are the Stage 3–12 reserved blocks)

---

## 0. What is settled before a line is written

This wave does **not** re-open any of the following. Each is a measured result already
recorded in this repository, and re-litigating it is the most expensive failure available.

| Settled | Evidence | Consequence for this wave |
|---|---|---|
| The recurrent DTL core is rejected | ADR-0009; TCN 1.0000 vs DTL 0.4736 on long-horizon sessions at half the parameters | No package rebuilds multi-timescale recurrent state. `stage2/state/` holds a bounded window, not a recurrent cell (ADR-0119). |
| DTL as a distinct architecture is rejected | ADR-0010; equal detection (1.0000), TCN 6.6 µs/event vs DTL-C 22.3 at 2.8× params → dominated | The Stage 2 core is a TCN with optional **detached** heads. `DTLConvModel` stays the research vehicle only. |
| Predictive heads must be detached | ADR-0009; joint 0.3333 vs detached 1.0000, and `w_detect=8.0` still 0.3333 | No package re-enables joint training. `predictors/` consumes a frozen representation. |
| The Need-to-Compute router is harmful | −0.115 PR-AUC on the ambiguous corpus (`planning/MEMORY.md`) | `stage2/router/` implements the **accounting honesty fix**, not a live router. |
| Path accounting was notional | ADR-0010: the router reported 100 % cheap-path resolution while every branch was computed regardless of its gate, and was still 3.4× slower | Any wake-rate number this stage emits must come from a ledger that can only mark a path skipped if the work genuinely did not run (D2.4, ADR-0114). |
| The structured surprise vector is harmful | −0.073 PR-AUC | Retained default-off; `predictors/residual.py` measures residuals without feeding them to detection. |
| Per-lineage pooling is retracted | Corrected corpus: 1.0000 with and without; the earlier +0.042 was label noise from two corpus defects | No package adds pooling as a default. Stage 1's lineage-scoped state calculus (ADR-0005) already attributes. |
| Stage 1's Φ-oracle solves most of the task for free | 0.7484 PR-AUC, 0 parameters, ~0 µs/event (`planning/MEMORY.md`) | Every component in this wave is measured against the Φ-oracle, not only against neural baselines. The Φ-oracle is also the **first compile candidate** (D2.13/D2.15). |

### 0.1 One new measurement, produced in this session

Run as `PYTHONPATH=/home/anil/Documents/Research/pocketsec PYTHONHASHSEED=0 python -c ...`
using `pocketsec.stage2.dataset.build_dataset`, `research.baselines.PhiOracleBaseline`
and `stage0.benchmark.security_metrics.average_precision` on Python 3.14.7,
Linux 7.1.5+kali-amd64:

| corpus | count | seed | samples | base rate | Φ-oracle PR-AUC (0 parameters) |
|---|---|---|---|---|---|
| hard | 60 | 11 | 60 | 0.4000 | **0.7600** |
| long | 60 | 11 | 60 | 0.3333 | **0.3226** |
| ambiguous | 60 | 11 | 60 | 0.3333 | **1.0000** |
| ambiguous | 120 | 11 | 120 | 0.3333 | **0.8495** |
| ambiguous | 240 | 11 | 240 | 0.3333 | **0.5975** |
| ambiguous | 240 | 3 | 240 | 0.3333 | **0.5897** |
| long | 240 | 11 | 240 | 0.3333 | **0.3172** |
| long | 240 | 3 | 240 | 0.3333 | **0.3251** |

**This is the most consequential fact in this specification.** A zero-parameter scorer's
PR-AUC on the *same generator* moves 0.4025 (1.0000 → 0.5975) purely with corpus size.
Therefore:

1. Every comparison in this wave fixes `corpus`, `count` **and** `seed`, and records all
   three in the experiment entry. A result quoted without those three is void.
2. The `ambiguous` corpus is saturated at `count=60` (the Φ-oracle alone reaches 1.0000)
   and partly informative at `count=240`. `long` is useless to the Φ-oracle (0.3172 vs a
   0.3333 base rate) yet a TCN reaches 1.0000 on it — the two corpora disagree about what
   the task even is.
3. The degeneracy guard (ADR-0120, §5.3) is not defensive paperwork. It is the only thing
   standing between this wave and eleven components "justified" by a corpus-size artefact.

---

## 1. Existing code this wave builds on

`find /home/anil/Documents/Research/pocketsec/pocketsec -type d` shows 13 stage directories.
Stage 2's own tree, measured with `wc -l` this session:

```
pocketsec/stage2/
    __init__.py                 21 lines, docstring only        [INTEGRATOR-OWNED]
    core_ids.py                240 lines  D2.1  — FROZEN, 20 IDs, schema pocketsec.dtl_interface.v1 @ 1.0.0
    dataset.py                 181 lines  D2.2  — Stage2Sample / Stage2Dataset / build_dataset
    encoder/ssir_encoder.py    260 lines  D2.3  — DTL-F01, 96-slot encoder, ENCODER_VERSION "dtl-encoder.1.0.0"
    research/autograd.py       475 lines         — hand-written reverse-mode autodiff (numpy)
    research/baselines.py      607 lines  D2.2  — 9 baselines incl. TCNBaseline, PhiOracleBaseline
    research/dtl.py            573 lines  D2.3/4/5 — recurrent core, REJECTED (ADR-0009)
    research/dtl_conv.py       487 lines  D2.3/4/5 — DTL-C, rejected as architecture (ADR-0010)
    research/sleeping_brain.py 179 lines  S2-E19 — the only honest cost number in the subsystem
    research/experiments.py    324 lines  D2.14 — drives the REJECTED recurrent core only
    adaptation/  cache/  compile_candidates/  counterfactual/  credit/
    lattice/  predictors/  router/  state/  uncertainty/     ← 0-byte __init__.py, ELEVEN EMPTY PACKAGES
    encoder/__init__.py                                       ← 0 bytes but the sibling module is real
```

Three further directories exist that are **not even packages** (no `__init__.py`,
confirmed with `ls -la`): `pocketsec/stage2/atoms/`, `pocketsec/stage2/dtl/`,
`pocketsec/stage2/prediction/`. They are deleted by the integrator (ADR-0121).

Stage 2 has **no `gate.py` and no `cli.py`**, and `pyproject.toml` declares only
`pocketsec-stage0` and `pocketsec-stage1`. Stage 2's gate status is recorded in prose in
`planning/PROGRESS.md`; ADR-0113 says a stage may not be declared failed by prose.

Experiment counter: `experiments/registry.jsonl` holds `PS-S2-…-0001` … `-0006`.
**This wave starts at `-0007`.**

---

## 2. Deliverables, module by module

Every type below is a concrete Python type. Nothing is TBD. All runtime modules are
**stdlib-only** with `from __future__ import annotations`, an `__all__`, a module docstring
saying what the module is *for*, frozen slotted dataclasses, and every public API annotated.
numpy appears only under `pocketsec/stage2/research/`.

### D2.1 — DTL Core specification and versioned functional IDs — **EXISTS, UNCHANGED**

`pocketsec/stage2/core_ids.py` (240 lines). 20 `CoreFunction` records, 8 REQUIRED
(`DTL-F01, F02, F03, F06, F07, F18, F19, F20`), `ExecutionPath` P0…P4,
`PATH_COST_UNITS`, `DTL_INTERFACE_ID = "pocketsec.dtl_interface.v1"` registered at 1.0.0.

**No package may edit this file.** It is a registered schema; a change needs a new
`…v2` id and an ADR. What this wave changes is that the functions stop being names:
after this wave, all 8 REQUIRED ids have a stdlib-only implementation (today only F01 does).
`PATH_COST_UNITS`' docstring claims calibration from measured CPU time and there is no
calibration code — the `report` package must either calibrate it or mark it UNMEASURED
in the findings ledger.

### D2.2 — Baseline suite and unified benchmark harness — **EXISTS, EXTENDED BY `report`**

`research/baselines.py`: 9 baselines under one `Stage2Model` protocol and one budget.
`research/sleeping_brain.py`: `sleeping_brain_report(models, train, test)` — wall-clock
`microseconds_per_event`. `dataset.py`: one shared dataset builder.

Extension, owned by the `report` package: `research/saturation.py` and
`research/stage2_report.py`. **No second harness, no second corpus builder, no second
experiment ledger may be created.** Measurements go through
`stage0.benchmark.harness.run_benchmark` and `stage0.experiments.registry.ExperimentRegistry`.

### D2.3 — Multi-timescale predictive core — **RE-BOUND; runtime half owned by `routing`**

The research core exists (`research/dtl_conv.py`, six dilations 1/2/4/8/16/32) and is
rejected as an architecture. What is missing is the **runtime** side of DTL-F03: a
convolutional core needs a bounded causal window per lineage, not recurrent state.

`pocketsec/stage2/state/window.py` (ADR-0119):

```python
MAX_LINEAGES: int = 64
MAX_WINDOW: int = 64          # >= the widest dilation receptive field (3 * 32 = 96 -> 64 kept, truncation explicit)

@dataclass(frozen=True, slots=True)
class WindowStats:
    lineages: int
    transitions_held: int
    evicted_lineages: int
    truncated_steps: int
    memory_bytes: int
    def to_dict(self) -> dict[str, Any]: ...

@dataclass(frozen=True, slots=True)
class LineageWindow:
    lineage_key: str                       # SSIRTransitionV1.causal_signature root, never a pid or name
    steps: tuple[EncodedTransition, ...]   # len <= MAX_WINDOW, oldest first
    truncated: bool
    last_sequence: int
    def features(self) -> tuple[tuple[float, ...], ...]: ...
    def dilated_context(self, dilation: int, kernel: int = 3) -> tuple[tuple[float, ...], ...]: ...

class WindowStore:
    def __init__(self, *, max_lineages: int = MAX_LINEAGES, max_window: int = MAX_WINDOW) -> None: ...
    def update_multiscale_state(self, transition: SSIRTransitionV1, *, actor_slot: int = 0) -> LineageWindow: ...   # DTL-F03
    def get(self, lineage_key: str) -> LineageWindow | None: ...
    def stats(self) -> WindowStats: ...
    def reset(self) -> None: ...
```

Bounds: ≤ 64 lineages × ≤ 64 steps × 96 float slots. Eviction is LRU by
`last_sequence`, deterministic, and counted in `WindowStats.evicted_lineages`.
`truncated` is explicit on every window that dropped a step. `memory_bytes` is computed,
not guessed.

### D2.4 — Need-to-Compute sparse router — **NEGATIVE RESULT PRESERVED; honest accounting built**

The router is measured harmful (−0.115) and its savings were notional. This wave does
**not** ship a router. It ships the mechanism that makes any future savings claim checkable.

`pocketsec/stage2/router/accounting.py` (ADR-0114):

```python
class WorkKind(StrEnum):
    CACHE_LOOKUP = "CACHE_LOOKUP"
    LATTICE_LOOKUP = "LATTICE_LOOKUP"
    WINDOW_UPDATE = "WINDOW_UPDATE"
    CORE_INFERENCE = "CORE_INFERENCE"
    CONE_EXPANSION = "CONE_EXPANSION"
    COUNTERFACTUAL = "COUNTERFACTUAL"

@dataclass(frozen=True, slots=True)
class WorkRecord:
    kind: WorkKind
    performed: bool          # True only when the work actually ran
    units: float             # PATH_COST_UNITS-comparable
    detail: str

@dataclass(frozen=True, slots=True)
class PathAccount:
    path: ExecutionPath
    work: tuple[WorkRecord, ...]
    @property
    def performed_units(self) -> float: ...
    @property
    def skipped_kinds(self) -> frozenset[WorkKind]: ...

class WorkLedger:
    """A path may be reported as skipped only if nothing recorded it as performed."""
    def __init__(self, *, max_events: int = 4096) -> None: ...
    def begin(self, event_key: str) -> None: ...
    def record(self, kind: WorkKind, *, performed: bool, units: float, detail: str = "") -> None: ...
    def close(self) -> PathAccount: ...          # path DERIVED from what ran, never declared
    def histogram(self) -> dict[str, int]: ...
    def compute_units_per_event(self) -> float: ...
    def truncated(self) -> bool: ...
    def assert_no_phantom_savings(self) -> None: ...  # raises if a skipped kind has a performed record

@contextmanager
def measured(ledger: WorkLedger, kind: WorkKind, units: float) -> Iterator[None]: ...
```

`pocketsec/stage2/router/policy.py` holds the deterministic, auditable need-score policy
(the five weights and four thresholds already in `dtl.path_histogram`) as
`route_information_need(signals: NeedSignals) -> ExecutionPath` — DTL-F02 — and a
`ROUTER_DEFAULT_ENABLED = False` constant. The policy *proposes*; the ledger *decides* what
is reported. `ExecutionPath` is derived from the highest-cost `WorkKind` actually performed.

Bounds: ledger holds ≤ 4096 event accounts, truncation explicit.

### D2.5 — Multi-head predictive/surprise engine — **runtime half owned by `predictors`**

Research heads exist (relation, family, delta, time, phi) on a detached representation.
The runtime half is the stdlib inference surface plus the residual scorer.

`pocketsec/stage2/predictors/heads.py`:

```python
HEAD_IDS: tuple[str, ...] = ("relation", "object", "state_delta", "time", "causal", "epoch", "phi", "uncertainty")

@dataclass(frozen=True, slots=True)
class HeadWeights:
    """Plain data loaded from models/experimental/*.json — never a research class."""
    head_id: str
    input_width: int
    classes: int
    weights: tuple[tuple[float, ...], ...]
    bias: tuple[float, ...]
    trained_experiment_id: str          # required, non-empty
    def __post_init__(self) -> None: ...   # raises ContractError on shape mismatch or empty experiment id

@dataclass(frozen=True, slots=True)
class HeadPrediction:
    head_id: str
    probabilities: tuple[float, ...]
    argmax: int
    entropy: float

class PredictiveHeads:
    def __init__(self, weights: Mapping[str, HeadWeights]) -> None: ...
    @classmethod
    def from_json(cls, path: Path) -> PredictiveHeads: ...
    def predict(self, window: LineageWindow) -> dict[str, HeadPrediction]: ...
    def predict_security_state_delta(self, window: LineageWindow) -> StateDelta: ...   # DTL-F06
    def parameters(self) -> int: ...
    def memory_bytes(self) -> int: ...
```

`pocketsec/stage2/predictors/residual.py` — DTL-F09 and §23 negative-space learning:

```python
@dataclass(frozen=True, slots=True)
class Residual:
    observed_surprise: float          # -log p(observed | context)
    absent_expected: tuple[str, ...]  # expected continuations that did not occur
    absent_mass: float                # probability mass of the missing continuations
    components: dict[str, float]      # per-head, the structured surprise geometry
    @property
    def magnitude(self) -> float: ...
def score_prediction_residual(predicted: Mapping[str, HeadPrediction],
                              observed: EncodedTransition,
                              *, expectation_floor: float = 0.05) -> Residual: ...
```

Residuals are **measured, never backpropagated and never added to the detection score**
(the surprise vector is −0.073). Default-off in the runtime slot.

### D2.6 — Behaviour Atom quantizer and bounded lattice — `lattice`

`pocketsec/stage2/lattice/atom.py`:

```python
class CompileStatus(StrEnum):
    NEURAL = "NEURAL"
    CANDIDATE = "CANDIDATE"
    EXECUTABLE = "EXECUTABLE"

@dataclass(frozen=True, slots=True)
class BehaviourAtom:
    atom_id: int
    prototype: tuple[float, ...]              # len == FEATURE_WIDTH (96)
    visit_count: int
    epoch_counts: dict[int, int]              # bounded to MAX_EPOCHS_PER_ATOM = 8
    state_summary: SecurityStateV1            # capability meaning (spec §11)
    delta_phi_mean: float
    delta_phi_m2: float                       # Welford, so variance needs no stored samples
    uncertainty_envelope: tuple[float, float] # (min, max) observed uncertainty
    compile_status: CompileStatus
    first_sequence: int
    last_sequence: int
    def distance(self, features: Sequence[float]) -> float: ...       # squared L2
    def epoch_valid(self, epoch_id: int) -> bool: ...
    def variance(self) -> float: ...
    def memory_bytes(self) -> int: ...
    def to_dict(self) -> dict[str, Any]: ...
```

`pocketsec/stage2/lattice/quantizer.py`:

```python
MAX_ATOMS: int = 256
SPLIT_RADIUS: float = 0.35          # a point beyond this from every prototype opens a new atom

@dataclass(frozen=True, slots=True)
class QuantizeResult:
    atom_id: int
    distance: float
    created: bool
    evicted_atom_id: int | None
    inside_envelope: bool

class BehaviourQuantizer:
    """Online, bounded, deterministic k-prototype quantizer. No numpy, no training loop."""
    def __init__(self, *, max_atoms: int = MAX_ATOMS, radius: float = SPLIT_RADIUS,
                 learning_rate: float = 0.05) -> None: ...
    def quantize_behaviour_atom(self, encoded: EncodedTransition, *,
                                state: SecurityStateV1, epoch_id: int,
                                sequence: int) -> QuantizeResult: ...      # DTL-F04
    def atoms(self) -> tuple[BehaviourAtom, ...]: ...
    def get(self, atom_id: int) -> BehaviourAtom | None: ...
    def stats(self) -> QuantizerStats: ...
    def memory_bytes(self) -> int: ...

@dataclass(frozen=True, slots=True)
class HashBucketQuantizer:
    """THE SIMPLE CONTROL (§6). atom_id = a deterministic bucket of
    (relation_family, state_delta_mask, object_property_mask). Zero training, zero drift."""
    def quantize_behaviour_atom(self, encoded: EncodedTransition, *, state: SecurityStateV1,
                                epoch_id: int, sequence: int) -> QuantizeResult: ...
```

`pocketsec/stage2/lattice/transitions.py`:

```python
MAX_TRANSITIONS: int = 4096

@dataclass(frozen=True, slots=True)
class LatticeTransition:
    source: int
    target: int
    count: int
    epoch_counts: dict[int, int]
    delta_phi_sum: float
    uncertainty_mean: float
    compile_status: CompileStatus
    @property
    def probability_hint(self) -> float: ...
    def to_dict(self) -> dict[str, Any]: ...

class TransitionLattice:
    def __init__(self, *, max_transitions: int = MAX_TRANSITIONS, alpha: float = 1.0) -> None: ...
    def observe(self, source: int, target: int, *, epoch_id: int,
                delta_phi: float, uncertainty: float) -> None: ...
    def probability(self, source: int, target: int, *, epoch_id: int | None = None) -> float: ...
    def successors(self, source: int, *, epoch_id: int | None = None,
                   limit: int = 8) -> tuple[tuple[int, float], ...]: ...
    def log_loss(self, pairs: Sequence[tuple[int, int]]) -> float: ...
    def evictions(self) -> int: ...
    def memory_bytes(self) -> int: ...
```

Bounds: ≤ 256 atoms × 96 floats, ≤ 4096 transitions, ≤ 8 epochs recorded per atom/edge.
Eviction is lowest `visit_count` then oldest `last_sequence`; every eviction counted.
Epoch-conditioned probability (spec §24) is the epoch-filtered count with Laplace `alpha`.

### D2.7 — Merge/fission and predictive-equivalence evaluator — `lattice`

`pocketsec/stage2/lattice/equivalence.py`:

```python
@dataclass(frozen=True, slots=True)
class EquivalenceVerdict:
    left: int
    right: int
    distance: float                  # symmetric KL / Jensen-Shannon over successor distributions
    epoch_compatible: bool
    uncertainty_compatible: bool
    state_compatible: bool           # SecurityStateV1 summaries must not disagree on any dimension
    equivalent: bool
    detail: str

def predictive_equivalence(lattice: TransitionLattice, left: BehaviourAtom, right: BehaviourAtom,
                           *, epsilon: float = 0.05, min_evidence: int = 8) -> EquivalenceVerdict: ...
```

`pocketsec/stage2/lattice/restructure.py`:

```python
MAX_MACRO_STATES: int = 64

@dataclass(frozen=True, slots=True)
class MacroState:
    macro_id: int
    members: frozenset[int]
    created_at_sequence: int
    merge_evidence: tuple[EquivalenceVerdict, ...]

@dataclass(frozen=True, slots=True)
class RestructureReport:
    merges: int
    fissions: int
    refused: int
    macro_states: int
    reason_counts: dict[str, int]
    def to_dict(self) -> dict[str, Any]: ...

class LatticeRestructurer:
    def __init__(self, *, epsilon: float = 0.05, heterogeneity: float = 0.25,
                 max_macro: int = MAX_MACRO_STATES) -> None: ...
    def merge_equivalent_atoms(self, quantizer: BehaviourQuantizer,
                               lattice: TransitionLattice) -> RestructureReport: ...   # DTL-F13
    def split_heterogeneous_atom(self, quantizer: BehaviourQuantizer,
                                 lattice: TransitionLattice, atom_id: int) -> RestructureReport: ...  # DTL-F14
    def unmerge(self, macro_id: int) -> RestructureReport: ...   # merging is REVERSIBLE (spec §13)
    def stability(self, other: LatticeRestructurer) -> float: ...  # Rand-style agreement, stdlib
```

Fission triggers on measured heterogeneity only: successor-distribution entropy above
`heterogeneity`, or a state summary that disagrees with a member on any of the nine
`DIMENSIONS`, or an uncertainty envelope wider than the atom's own. A merge is refused —
and counted in `RestructureReport.refused` — whenever evidence is below `min_evidence`.

### D2.8 — Future Cone / hazard prototype — `predictors`

`pocketsec/stage2/predictors/future_cone.py`:

```python
MAX_BRANCHES: int = 4         # spec §7: "deliberately shallow and bounded"
MAX_DEPTH: int = 3

@dataclass(frozen=True, slots=True)
class ConeBranch:
    label: str                       # e.g. "normal_continuation", "administrative_escalation"
    atom_path: tuple[int, ...]       # len <= MAX_DEPTH
    probability: float
    terminal_state: SecurityStateV1
    delta_phi: float
    evidence: tuple[str, ...]

@dataclass(frozen=True, slots=True)
class FutureCone:
    branches: tuple[ConeBranch, ...]           # len <= MAX_BRANCHES
    unresolved_mass: float                     # the explicit "unknown" branch — never folded away
    depth: int
    truncated: bool
    def __post_init__(self) -> None: ...        # sum(p) + unresolved_mass == 1.0 +/- 1e-9, else ContractError
    def most_consequential(self) -> ConeBranch | None: ...
    def to_dict(self) -> dict[str, Any]: ...

def predict_future_cone(lattice: TransitionLattice, quantizer: BehaviourQuantizer,
                        *, from_atom: int, state: SecurityStateV1, epoch_id: int,
                        max_branches: int = MAX_BRANCHES, max_depth: int = MAX_DEPTH,
                        ledger: WorkLedger | None = None) -> FutureCone: ...   # DTL-F05

def marginal_cone(lattice: TransitionLattice, *, epoch_id: int) -> FutureCone: ...
    # THE SIMPLE CONTROL: the epoch-marginal continuation distribution, ignoring the current atom.
```

`pocketsec/stage2/predictors/hazard.py`:

```python
HORIZONS: tuple[int, ...] = (1, 4, 16)     # in relevant events, not wall time

@dataclass(frozen=True, slots=True)
class HazardEstimate:
    outcome: str                # "privilege_raise" | "credential_exposure" | "egress" | "persistence"
    horizon: int
    probability: float
    evidence_count: int
    calibration_id: str | None  # None when this estimate is NOT calibrated; never a guess

@dataclass(frozen=True, slots=True)
class HazardReport:
    estimates: tuple[HazardEstimate, ...]
    def for_outcome(self, outcome: str, horizon: int) -> HazardEstimate | None: ...
    def to_dict(self) -> dict[str, Any]: ...

def estimate_security_hazard(cone: FutureCone, lattice: TransitionLattice,
                             *, state: SecurityStateV1,
                             horizons: Sequence[int] = HORIZONS) -> HazardReport: ...   # DTL-F08

def constant_hazard(counts: Mapping[tuple[str, int], tuple[int, int]]) -> HazardReport: ...
    # THE SIMPLE CONTROL: empirical base rate per (outcome, horizon) bucket. No state, no cone.
```

### D2.9 — Calibrated uncertainty and abstention — `uncertainty`

Stage 1 ships `calibration_id=None` honestly. Stage 2 fixes that **for its own outputs**.

`pocketsec/stage2/uncertainty/calibration.py`:

```python
@dataclass(frozen=True, slots=True)
class ReliabilityBin:
    lower: float
    upper: float
    count: int
    mean_confidence: float
    empirical_accuracy: float

@dataclass(frozen=True, slots=True)
class CalibrationReport:
    calibration_id: str | None       # None when it could not be fitted. NEVER a plausible-looking string.
    bins: tuple[ReliabilityBin, ...]
    expected_calibration_error: float | None
    max_calibration_error: float | None
    brier_score: float | None
    sample_count: int
    refusal_reason: str = ""
    def to_dict(self) -> dict[str, Any]: ...

def expected_calibration_error(labels: Sequence[int], confidences: Sequence[float], *, bins: int = 10) -> float | None: ...
def brier_score(labels: Sequence[int], confidences: Sequence[float]) -> float | None: ...

class IsotonicCalibrator:
    """Pool-adjacent-violators, stdlib only. Refuses a single-class fit
    (Stage 1 guillotine trap 2) and returns calibration_id=None rather than a bad map."""
    def fit(self, labels: Sequence[int], scores: Sequence[float]) -> CalibrationReport: ...
    def apply(self, score: float) -> float: ...
    def calibration_id(self) -> str | None: ...        # "stage2-isotonic-<sha256[:12]>" of the fitted knots
    def to_json(self) -> str: ...
    @classmethod
    def from_json(cls, payload: str) -> IsotonicCalibrator: ...
```

`pocketsec/stage2/uncertainty/conformal.py`:

```python
@dataclass(frozen=True, slots=True)
class ConformalInterval:
    lower: float
    upper: float
    nominal_coverage: float
    empirical_coverage: float | None
    calibration_size: int

class SplitConformal:
    def __init__(self, *, nominal_coverage: float = 0.9, max_calibration: int = 1024) -> None: ...
    def fit(self, residuals: Sequence[float]) -> None: ...
    def interval(self, point: float) -> ConformalInterval: ...
    def coverage(self, labels: Sequence[int], scores: Sequence[float]) -> float | None: ...
```

`pocketsec/stage2/uncertainty/abstention.py`:

```python
class UncertaintySource(StrEnum):
    ENTROPY = "ENTROPY"
    PROTOTYPE_DISTANCE = "PROTOTYPE_DISTANCE"
    CONE_AMBIGUITY = "CONE_AMBIGUITY"
    EVIDENCE_INCOMPLETE = "EVIDENCE_INCOMPLETE"

class EpistemicQuadrant(StrEnum):
    CHEAP_PATH = "CHEAP_PATH"              # low U, low Phi
    OBSERVE_LAZILY = "OBSERVE_LAZILY"      # high U, low Phi
    KNOWN_HIGH_RISK = "KNOWN_HIGH_RISK"    # low U, high Phi
    ESCALATE = "ESCALATE"                  # high U, high Phi  -> AOP + deep inference + preserve evidence

@dataclass(frozen=True, slots=True)
class UncertaintyEstimate:
    value: float                            # [0, 1]
    sources: dict[str, float]               # per-source contribution, kept separate (never one score)
    calibration_id: str | None
    quadrant: EpistemicQuadrant
    abstain: bool
    detail: str
    def to_dict(self) -> dict[str, Any]: ...

def estimate_uncertainty(*, heads: Mapping[str, HeadPrediction] | None,
                         cone: FutureCone | None,
                         prototype_distance: float | None,
                         transition: SSIRTransitionV1,
                         calibrator: IsotonicCalibrator | None = None,
                         phi_total: float) -> UncertaintyEstimate: ...   # DTL-F07

MAX_SOFTMAX_CONTROL: str = "one_minus_max_probability"
def one_minus_max(heads: Mapping[str, HeadPrediction]) -> float: ...     # THE SIMPLE CONTROL
```

Hard rule kept from Stage 1: **novelty, Φ and uncertainty stay three separate signals**;
`UncertaintyEstimate` never absorbs novelty or Φ into `value`. Abstention is a valid
output and scores 0.0 in the Stage 0 harness, so it cannot manufacture recall.

### D2.10 — Counterfactual Twin and Causal Credit Ledger — `credit`

`pocketsec/stage2/counterfactual/twin.py`:

```python
MAX_PROBES_PER_EVENT: int = 4
MAX_PROBE_DEPTH: int = 8

class Intervention(StrEnum):
    MASK = "MASK"                # remove the transition
    SUBSTITUTE_BENIGN = "SUBSTITUTE_BENIGN"
    DELAY = "DELAY"

@dataclass(frozen=True, slots=True)
class CounterfactualProbe:
    target_signature: str
    intervention: Intervention
    observed_cone: FutureCone
    counterfactual_cone: FutureCone
    divergence: float                 # Jensen-Shannon over branch labels
    delta_phi_shift: float
    budget_exhausted: bool
    evidence: tuple[str, ...]
    def to_dict(self) -> dict[str, Any]: ...

def counterfactual_probe(window: LineageWindow, quantizer: BehaviourQuantizer,
                         lattice: TransitionLattice, *, target_index: int,
                         intervention: Intervention = Intervention.MASK,
                         ledger: WorkLedger | None = None) -> CounterfactualProbe: ...   # DTL-F11

def phi_only_probe(window: LineageWindow, *, target_index: int) -> CounterfactualProbe: ...
    # THE SIMPLE CONTROL: replay with the transition removed and score with Stage 1's Phi alone.
```

`pocketsec/stage2/credit/ledger.py`:

```python
MAX_LEDGER_ENTRIES: int = 256

@dataclass(frozen=True, slots=True)
class CreditEntry:
    signature: str
    parent_signature: str
    sequence: int
    credit: float                     # divergence when masked, under the probe budget
    delta_phi: float
    probes_spent: int
    evidence: tuple[str, ...]
    def to_dict(self) -> dict[str, Any]: ...

@dataclass(frozen=True, slots=True)
class AttributionReport:
    spine: tuple[CreditEntry, ...]
    nodes_inspected: int              # what an analyst must read  <-- the metric that matters
    naive_ancestry_nodes: int         # the control, from CausalMemory.spine(min_responsibility=0.0)
    chain_recall: float | None        # recall of ground-truth chain nodes, None when no ground truth
    conciseness_gain: float | None    # naive/ours at equal recall; None when unmeasurable
    def to_dict(self) -> dict[str, Any]: ...

class CausalCreditLedger:
    def __init__(self, *, capacity: int = MAX_LEDGER_ENTRIES, probe_budget: int = 64) -> None: ...
    def assign_causal_credit(self, probe: CounterfactualProbe, node: CausalNode) -> CreditEntry | None: ...  # DTL-F10
    def report(self, memory: CausalMemory, *, ground_truth: frozenset[str] | None = None) -> AttributionReport: ...
    def evictions(self) -> int: ...
    def memory_bytes(self) -> int: ...
```

Only transitions that *materially* changed the predicted future are kept (spec §17);
eviction is lowest credit. Bounded at 256 entries, probes bounded at 4/event and 64/session.

### D2.11 — AOP feedback / value-of-information — `credit`

`pocketsec/stage2/counterfactual/value_of_information.py`:

```python
@dataclass(frozen=True, slots=True)
class InformationNeed:
    target: str
    expected_uncertainty_reduction: float
    collection_cost: float              # AOP budget units
    value_of_information: float         # reduction / cost, the quantity being tested
    worth_collecting: bool
    detail: str

@dataclass(frozen=True, slots=True)
class VoIReport:
    requests: tuple[InformationNeed, ...]
    escalations_requested: int
    escalations_granted: int
    escalations_refused: int
    measured_reduction: float | None    # None until an observation actually came back
    def to_dict(self) -> dict[str, Any]: ...

def request_observation_escalation(estimate: UncertaintyEstimate, cone: FutureCone,
                                   policy: AdaptiveObservationPolicy, *, target: str,
                                   now_ns: int) -> tuple[InformationNeed, EscalationDecision]: ...  # DTL-F12

def uncertainty_only_requests(estimate: UncertaintyEstimate, policy: AdaptiveObservationPolicy,
                              *, target: str, now_ns: int) -> EscalationDecision: ...
    # THE SIMPLE CONTROL: Stage 1's existing threshold on uncertainty alone.
```

Stage 2 **never** creates a second observation path. It calls
`AdaptiveObservationPolicy.consider(...)` and respects `MANDATORY_SIGNALS`; AOP can refuse,
and a refusal is recorded, not retried.

### D2.12 — Epoch-conditioned and anti-poisoning adaptation — `adaptation`

`pocketsec/stage2/adaptation/epoch_guard.py`:

```python
@dataclass(frozen=True, slots=True)
class EpochMismatch:
    atom_id: int
    current_epoch: int
    valid_epochs: frozenset[int]
    mismatch: bool
    corroborated_system_change: bool     # from EpochModel; behavioural novelty ALONE never suffices
    detail: str

def detect_epoch_mismatch(atom: BehaviourAtom, *, epoch: Epoch,
                          decision: EpochDecision | None) -> EpochMismatch: ...   # DTL-F18

@dataclass(frozen=True, slots=True)
class DriftReport:
    transitions_to_recover: int | None   # None when recovery did not happen inside the corpus
    atoms_invalidated: int
    atoms_reused_after_change: int
    malicious_patterns_normalised: int   # MUST be 0
    def to_dict(self) -> dict[str, Any]: ...
```

`pocketsec/stage2/adaptation/quarantine.py`:

```python
MAX_QUARANTINE: int = 512

class QuarantineOutcome(StrEnum):
    HELD = "HELD"
    PROMOTED = "PROMOTED"
    REFUSED = "REFUSED"
    RETAINED_AS_EVIDENCE = "RETAINED_AS_EVIDENCE"

@dataclass(frozen=True, slots=True)
class AdaptationSample:
    encoded: EncodedTransition
    state: SecurityStateV1
    epoch_id: int
    delta_phi: float
    uncertainty: float
    evidence: tuple[str, ...]
    received_at_sequence: int

@dataclass(frozen=True, slots=True)
class QuarantineVerdict:
    outcome: QuarantineOutcome
    checks_passed: tuple[str, ...]
    checks_failed: tuple[str, ...]
    epochs_observed: int
    detail: str

class QuarantineBuffer:
    def __init__(self, *, capacity: int = MAX_QUARANTINE, min_epochs: int = 2,
                 min_observations: int = 8, max_delta_phi: float = 2.0) -> None: ...
    def quarantine_adaptation_sample(self, sample: AdaptationSample) -> QuarantineVerdict: ...  # DTL-F19
    def dropped(self) -> int: ...
    def memory_bytes(self) -> int: ...
```

`pocketsec/stage2/adaptation/promotion.py` holds `PromotionController.promote(...)`, the
**only** path by which a quarantined sample may update a trusted atom, prototype or
candidate. A high-ΔΦ or high-uncertainty sample is `RETAINED_AS_EVIDENCE`, never silently
normalised. Promotion requires `min_epochs` distinct epochs of corroboration; frequency
alone is explicitly insufficient (spec §37).

Fixtures owned by this package: `pocketsec/stage2/labs/drift_corpus.py`
(`DRIFT_VERSION`, `build_drift_corpus(*, count, seed, split)`) and
`pocketsec/stage2/labs/poison_suite.py` (`POISON_VERSION`, `build_poison_suite(...)`).
Both reuse Stage 1's `Behaviour`/`Scenario`, use **session-unique identities**, and ship the
mandatory guard test that median per-class ΔΦ is non-zero before any model is fitted
(`planning/MEMORY.md` corpus trap; integration plan §5.4).

### D2.13 — Transition cache and compile-candidate exporter — `export`

`pocketsec/stage2/cache/transition_cache.py`:

```python
MAX_CACHE_ENTRIES: int = 1024

@dataclass(frozen=True, slots=True)
class CachedTransition:
    key: str                          # (atom, epoch, state_delta_mask) digest, deterministic
    atom_id: int
    epoch_id: int
    model_version: str                # cache entries are versioned by model AND epoch (spec §37)
    encoder_version: str
    predicted_delta: StateDelta
    predicted_phi: float
    uncertainty: float
    hits: int
    utility: float
    last_sequence: int

@dataclass(frozen=True, slots=True)
class CacheStats:
    entries: int
    hits: int
    misses: int
    evictions: int
    version_rejections: int
    proven_skipped_units: float        # from the WorkLedger, never inferred
    memory_bytes: int
    def hit_rate(self) -> float | None: ...

class TransitionCache:
    def __init__(self, *, capacity: int = MAX_CACHE_ENTRIES, model_version: str,
                 encoder_version: str) -> None: ...
    def lookup_transition_cache(self, *, atom_id: int, epoch_id: int, state_delta_mask: int,
                                ledger: WorkLedger | None = None) -> CachedTransition | None: ...  # DTL-F16
    def store(self, entry: CachedTransition) -> None: ...
    def invalidate_epoch(self, epoch_id: int) -> int: ...
    def stats(self) -> CacheStats: ...
```

`pocketsec/stage2/cache/utility.py` — DTL-F15, spec §20 (forget by future utility, not age):

```python
def future_security_utility(entry: CachedTransition, *, credit: float, uncertainty_reduction: float) -> float: ...
def forget_low_utility_memory(cache: TransitionCache, *, keep: int) -> tuple[str, ...]: ...   # DTL-F15
def lru_control(cache: TransitionCache, *, keep: int) -> tuple[str, ...]: ...      # THE SIMPLE CONTROL
def random_control(cache: TransitionCache, *, keep: int, seed: int) -> tuple[str, ...]: ...   # the dumbest control
```

`pocketsec/stage2/compile_candidates/candidate.py` — the load-bearing schema (ADR-0118):

```python
COMPILE_CANDIDATE_V1_ID = "pocketsec.compile_candidate.v1"
COMPILE_CANDIDATE_V1_VERSION = register_schema(COMPILE_CANDIDATE_V1_ID, "1.0.0")

class CandidateKind(StrEnum):
    DETERMINISTIC_SCORER = "DETERMINISTIC_SCORER"   # zero-parameter rule, e.g. the Phi-oracle
    TRANSITION_TABLE = "TRANSITION_TABLE"           # lattice edges
    NEURAL_REGION = "NEURAL_REGION"                 # a frozen head/TCN region

@dataclass(frozen=True, slots=True)
class ValidityBoundary:
    epochs: frozenset[int]
    encoder_version: str
    state_dimensions: frozenset[str]              # subset of DIMENSIONS this candidate reads
    max_uncertainty: float
    min_evidence_count: int
    unseen_input_behaviour: str                   # "ABSTAIN" — never "GUESS"
    def contains(self, *, epoch_id: int, encoder_version: str, uncertainty: float) -> bool: ...

@dataclass(frozen=True, slots=True)
class MeasuredCost:
    microseconds_per_event: float | None          # None == UNMEASURED, never a guess
    parameters: int
    bytes_on_disk: int
    peak_rss_bytes: int | None
    measured_by: str                              # "module:function" that produced it
    def __post_init__(self) -> None: ...          # ContractError if measured_by is empty

@dataclass(frozen=True, slots=True)
class CompileCandidateV1:
    candidate_id: str
    kind: CandidateKind
    boundary: ValidityBoundary
    evidence_lineage: tuple[EvidenceRef, ...]     # MUST be non-empty
    cost: MeasuredCost
    experiment_id: str                            # MUST parse via stage0.experiments.ids
    payload: Mapping[str, Any]                    # plain JSON data. NEVER a research object.
    stability: CandidateStability
    schema_version: str = COMPILE_CANDIDATE_V1_VERSION
    def __post_init__(self) -> None: ...
        # raises ContractError when: evidence_lineage is empty; experiment_id does not parse;
        # cost.microseconds_per_event is None AND kind != DETERMINISTIC_SCORER;
        # any payload key matches FORBIDDEN_AUTHORITY_FIELDS.
        # A candidate with no recorded measurement is REJECTABLE BY CONSTRUCTION.
    def to_dict(self) -> dict[str, Any]: ...
    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> CompileCandidateV1: ...

@dataclass(frozen=True, slots=True)
class CandidateStability:
    observations: int
    distinct_epochs: int
    reruns_agreeing: int
    reruns_total: int
    drift_invalidations: int
    @property
    def stable(self) -> bool: ...    # >= min_observations, >= 2 epochs, all reruns agree, 0 invalidations
```

`pocketsec/stage2/compile_candidates/exporter.py`:

```python
@dataclass(frozen=True, slots=True)
class ExportReport:
    candidates: tuple[CompileCandidateV1, ...]
    refused: tuple[tuple[str, str], ...]          # (candidate_id, reason)
    total_bytes: int
    def to_dict(self) -> dict[str, Any]: ...

def propose_compile_candidate(*, atom: BehaviourAtom | None, transition: LatticeTransition | None,
                              scorer: DeterministicScorerSpec | None, cost: MeasuredCost,
                              experiment_id: str, evidence: Sequence[EvidenceRef],
                              stability: CandidateStability) -> CompileCandidateV1: ...   # DTL-F17

def export_candidates(candidates: Sequence[CompileCandidateV1], path: Path, *,
                      max_candidates: int = 256) -> ExportReport: ...
```

`pocketsec/stage2/compile_candidates/phi_oracle_candidate.py` — the **first-class
zero-parameter candidate** the integration plan §6.3 names as Stage 3's first
crystallisation target:

```python
@dataclass(frozen=True, slots=True)
class DeterministicScorerSpec:
    """A zero-parameter rule expressed as data Stage 3 can compile without importing Stage 2."""
    scorer_id: str
    feature_index: int                 # 73, the squashed |dPhi| slot -- quoted, not re-derived
    aggregation: str                   # "max_over_window"
    threshold: float | None
    expression: str                    # e.g. "max(features[73]) over the lineage window"
    def evaluate(self, window: LineageWindow) -> float: ...

PHI_ORACLE_SCORER: DeterministicScorerSpec
def phi_oracle_candidate(*, cost: MeasuredCost, experiment_id: str,
                         evidence: Sequence[EvidenceRef],
                         stability: CandidateStability) -> CompileCandidateV1: ...
```

### D2.14 — Full resource, robustness, drift, attribution and ablation report — `report`

`pocketsec/stage2/research/saturation.py` (numpy permitted, offline):

```python
@dataclass(frozen=True, slots=True)
class SaturationVerdict:
    corpus: str
    count: int
    seed: int
    best: float | None
    median: float | None
    spread: float | None
    order_free_baseline: float | None      # MLPBaseline: ignores order
    phi_oracle: float | None               # zero parameters
    degenerate: bool
    reason: str
    def to_dict(self) -> dict[str, Any]: ...

DEGENERATE_SPREAD: float = 0.01
ORDER_FREE_TOLERANCE: float = 0.02

def saturation_check(train: Stage2Dataset, test: Stage2Dataset) -> SaturationVerdict: ...
def refuse_if_degenerate(verdict: SaturationVerdict) -> None: ...   # raises; an ablation on a degenerate corpus is not recorded
```

`pocketsec/stage2/research/stage2_report.py`:

```python
@dataclass(frozen=True, slots=True)
class ComponentVerdict:
    component: str
    core_ids: tuple[str, ...]
    control: str                 # the simple mechanism it was measured against
    metric: str
    with_component: float | None
    without_component: float | None
    delta: float | None
    experiment_id: str | None
    verdict: str                 # "JUSTIFIED" | "REJECTED" | "NOT_YET_JUSTIFIED" | "UNMEASURABLE"

@dataclass(frozen=True, slots=True)
class Stage2Report:
    saturation: tuple[SaturationVerdict, ...]
    components: tuple[ComponentVerdict, ...]
    resources: dict[str, Any]          # ResourceMetrics + ProfileReport for the runtime path
    drift: dict[str, Any]
    poisoning: dict[str, Any]
    attribution: dict[str, Any]
    latent_frontier: dict[str, Any]
    sleeping_brain: dict[str, Any]
    def to_dict(self) -> dict[str, Any]: ...

def build_report(*, corpus: str = "ambiguous", count: int = 240, train_seed: int = 3,
                 test_seed: int = 11) -> Stage2Report: ...
def latent_frontier(*, dimensions: tuple[int, ...] = (12, 16, 24, 32, 48, 64, 96),
                    corpus: str, count: int, seed: int) -> dict[str, Any]: ...
```

`latent_frontier`'s default dimensions start at **12**, not 8: the block-share floor makes
`"fast"` negative below 11 and **silently zero-width at 10–11** (interface map §6 trap 1).
The existing `experiments.latent_sweep` default crashes on its first point; `report` must not
reproduce that.

### D2.15 — Stage 3 neural-to-executable compiler interface — `export`

`pocketsec/stage2/compile_candidates/stage3_interface.py`:

```python
STAGE3_HANDOFF_V1_ID = "pocketsec.stage3_handoff.v1"
STAGE3_HANDOFF_V1_VERSION = register_schema(STAGE3_HANDOFF_V1_ID, "1.0.0")

@dataclass(frozen=True, slots=True)
class EvidenceBoundPrediction:
    """DTL-F20. A prediction that cannot be detached from the evidence it was made from."""
    score: float
    verdict: str                     # Verdict value from stage0, incl. UNKNOWN / UNIDENTIFIABLE
    uncertainty: UncertaintyEstimate
    evidence: tuple[EvidenceRef, ...]      # non-empty or the constructor raises
    compute_path: ExecutionPath
    calibration_id: str | None
    candidate_id: str | None
    def __post_init__(self) -> None: ...   # ContractError on empty evidence or a forbidden authority field
    def to_dict(self) -> dict[str, Any]: ...

def export_evidence_bound_prediction(...) -> EvidenceBoundPrediction: ...   # DTL-F20

@dataclass(frozen=True, slots=True)
class Stage3Handoff:
    """Everything Stage 3 needs, and nothing DTL-specific."""
    handoff_id: str
    candidates: tuple[CompileCandidateV1, ...]
    atom_prototypes: tuple[Mapping[str, Any], ...]     # plain data; no BehaviourAtom class crosses the seam
    transition_statistics: tuple[Mapping[str, Any], ...]
    uncertainty_envelopes: tuple[Mapping[str, Any], ...]
    evidence_requirements: tuple[Mapping[str, Any], ...]
    encoder_version: str
    interface_version: str = STAGE3_HANDOFF_V1_VERSION
    def to_dict(self) -> dict[str, Any]: ...
    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> Stage3Handoff: ...

def build_handoff(report: ExportReport, *, handoff_id: str) -> Stage3Handoff: ...
def write_handoff(handoff: Stage3Handoff, path: Path) -> str: ...      # returns the sha256 digest
```

**The seam rule, tested by AST:** nothing in `compile_candidates/` imports
`pocketsec.stage2.research.*`, and `Stage3Handoff.to_dict()` contains no key naming an
atom class, a DTL config, a tensor or a model object. Stage 3 reads JSON and never imports
Stage 2 machinery. The handoff must round-trip: `from_dict(to_dict(h)) == h`.

---

## 3. The data seam

### 3.1 Consumed from Stage 0 — quoted from `docs/architecture/interfaces/stage0-*.md` and verified in source

| Type / function | Path:line | How Stage 2 uses it |
|---|---|---|
| `EvidenceRef(store, locator, digest)` — digest must match `sha256:[0-9a-f]{64}` | `stage0/contracts/common.py:125` | every candidate's `evidence_lineage`, every `EvidenceBoundPrediction` |
| `register_schema(schema_id, version) -> str`; re-registering a different version raises `ContractError` | `common.py:49` | `pocketsec.compile_candidate.v1`, `pocketsec.stage3_handoff.v1` |
| `ContractError(ValueError)` | `common.py:32` | every `__post_init__` rejection |
| `GateCheck(id, title, passed, detail)`, `GateReport(checks)` with `.passed` / `.failures` | `stage0/gate.py:45`, `:56` | the 13 Stage 2 gate checks |
| `ResourceSampler(interval_seconds=...)`, `ResourceMetrics` with `peak_sampled_rss_bytes`, `cpu_seconds_per_event` | `benchmark/resource_metrics.py:103`, `:58` | G2.11; a resource figure from anywhere else is UNMEASURED |
| `check_profile(metrics, "edge", model_bytes=...) -> ProfileReport`; `within_target` is `None` when nothing was measured, never `True` | `benchmark/profiles.py:85`, `:62` | G2.11 |
| `average_precision`, `recall_at_max_fpr`, `evaluate_scores`, `SecurityMetrics` | `benchmark/security_metrics.py:92`, `:122`, `:211`, `:178` | every PR-AUC in this stage |
| `run_benchmark(slot, dataset, case, *, experiment_id, seeds, synthetic_data, model_bytes)` — `synthetic_data` is **required** | `benchmark/harness.py:133` | the single measurement path |
| `ExperimentRegistry.register(**kwargs)` — append-only, digest-chained, no update/delete | `experiments/registry.py:138` | `PS-S2-20260924-H*-…-0007` onward |
| `Verdict`, `ComputePath`, `FORBIDDEN_AUTHORITY_FIELDS` | `contracts/threat_prediction_v1.py:66`, `:84`, `:48` | `EvidenceBoundPrediction.verdict`; the T5-style field check |
| `HOST_RAM_TARGET_BYTES = 2 * 1024 * MB` | `benchmark/profiles.py` | the 2 GB constraint |

Note: Stage 0 has **no** ECE, Brier, reliability-bin or conformal machinery. D2.9 implements
them in `stage2/uncertainty/`, stdlib-only. This is not a duplicate harness; it is a metric
family Stage 0 does not provide.

### 3.2 Consumed from Stage 1 — the real classes

| Type | Path:line | Fields Stage 2 reads |
|---|---|---|
| `SSIRTransitionV1` | `stage1/ssir/transition.py:82` | `actor`, `relation`, `object`, `state_delta`, `uncertainty`, `novelty`, `causal_signature`, `parent_signature`, `responsibility`, `temporal`, `evidence: tuple[EvidenceRef, ...]`, `epoch_id`, `sequence`, `level`, `delta_phi`, `observation_incomplete`; property `is_high_consequence` |
| `RepresentationLevel` (L0…L3), `TemporalContext(since_actor_bucket, since_host_bucket)` with `bucket()` in `[0,15]` | `transition.py:39`, `:49` | temporal features, `time_bucket` targets |
| `SecurityStateV1` — nine defaulted lattice fields; `level(dim)`, `raised_to()`, `delta_from()`, `join()` (per-dimension max, monotone, order-independent) | `stage1/state/security_state.py:122` | `BehaviourAtom.state_summary`, `ConeBranch.terminal_state` |
| `StateDelta(raised: dict[str, tuple[int,int]])` — `__bool__`, `dimensions`, `magnitude`, `bitmask()` in `DIMENSIONS` insertion order | `security_state.py:181` | atom/transition keys, `predict_security_state_delta` |
| `DIMENSIONS: dict[str, type[IntEnum]]` — 9 entries, the single source of truth | `security_state.py:108` | `ValidityBoundary.state_dimensions` |
| `phi(state) -> PhiBreakdown` (`total`, `base`, `base_terms`, `active_interactions`, `interaction_total`); `delta_phi(prev, cur) -> float` | `stage1/state/potential.py:170`, `:195` | Φ-oracle candidate, hazard outcomes, quadrant selection |
| `Epoch(epoch_id, identity, key, opened_at_ns, observed_transitions)`, `EpochDecision(epoch_id, reason, changed_components, corroborated, detail)`, `EpochModel.evaluate(...)` | `stage1/epoch/model.py:105`, `:81`, `:170` | `detect_epoch_mismatch`; **behavioural novelty alone can never open an epoch** |
| `CausalMemory` (`record`, `spine(min_responsibility=0.01)`, `report()`, `memory_bytes`), `CausalNode(signature, parent_signature, sequence, relation, state_delta_mask, delta_phi, resolution, evidence_locators)` | `stage1/causal/memory.py:155`, `:83` | the naive-ancestry control for D2.10 |
| `AdaptiveObservationPolicy.consider(...)`, `AOPBudget(escalation_threshold=0.5, max_concurrent=8, …)`, `EscalationDecision(target, level, budget_score, escalated, refused_reason)`, `ObservationLevel`, `MANDATORY_SIGNALS` | `stage1/observation/policy.py:151`, `:60`, `:93`, `:39`, `:47` | D2.11. Stage 2 never builds a second observation path |
| `NoveltyTensor`, `NoveltyEngine`; `CountMinSketch`, `StableBloomFilter`, `BoundedLRUCounter`, `EWMA` (each with `memory_bytes()`) | `stage1/novelty/engine.py:46`, `:103`; `sketches.py:39`, `:97`, `:186`, `:244` | bounded counting inside the lattice and cache — **reuse, do not reimplement** |
| `Stage1Pipeline.run_scenario(scenario, *, sensor, offset) -> ScenarioResult`; `ScenarioResult(scenario, transitions, emitted, final_state, peak_phi, peak_novelty, peak_uncertainty, unresolved)` | `stage1/pipeline.py:78`, `:47` | corpus compilation. A fresh pipeline per split, always |
| `Behaviour`, `Scenario`, `build_corpus`; `build_hard_corpus`, `build_long_horizon_corpus`, `build_ambiguous_corpus` | `stage1/labs/corpus.py:34`, `:45`, `:220`; `hard_corpus.py:249`, `longhorizon_corpus.py:170`, `ambiguous_corpus.py:268` | `labs/drift_corpus.py` and `labs/poison_suite.py` reuse these; **no fifth scenario type** |
| `Relation` (24), `RelationFamily` (8), `family_of` | `stage1/ssir/relations.py:19`, `:56`, `:95` | head vocabularies |

### 3.3 Consumed from Stage 2's own existing code

| Type | Path:line | Note |
|---|---|---|
| `EncodedTransition` — `features` (exactly 96), `relation`, `relation_family`, `state_delta_mask`, `time_bucket`, `delta_phi` (raw, signed), `object_property_mask`, `epoch_id`, `actor_slot = 0`, `evidence: tuple[str, ...] = ()` | `stage2/encoder/ssir_encoder.py:143` | `evidence` here is a tuple of **locator strings**, not `EvidenceRef`; the exporter re-binds them to `EvidenceRef` via Stage 1's transition |
| `encode_ssir_transition(transition, *, actor_slot=0)`; `FEATURE_WIDTH == 96`; `NEED_SIGNAL_INDICES = {"novelty_peak": 83, "delta_phi": 73, "uncertainty": 85, "responsibility": 90, "state_delta_magnitude": 71}`; `ENCODER_VERSION = "dtl-encoder.1.0.0"` | `ssir_encoder.py:195`, `:95`, `:113`, `:45` | index 73 is the **squashed absolute** ΔΦ; the sign lives at 74 |
| `Stage2Sample(sample_id, steps, label, technique, unseen_technique, final_phi)`, `Stage2Dataset`, `build_dataset(*, name, count, seed, corpus="hard")` | `stage2/dataset.py:38`, `:72`, `:147` | `final_phi` is actually `peak_phi` — do not supervise a hazard head on it as a terminal value |
| `ExecutionPath` P0…P4, `PATH_COST_UNITS`, `FunctionClass`, `CoreFunction`, `CORE_IDS` (20), `REQUIRED_IDS` (8) | `stage2/core_ids.py:43`, `:62`, `:36`, `:72`, `:233`, `:236` | `PATH_COST_UNITS` and `REQUIRED_IDS` are **not** in `__all__`; import by name |
| research only: `TCNBaseline`, `PhiOracleBaseline`, `DTLConvModel`, `sleeping_brain_report`, `BASELINE_REGISTRY` | `research/baselines.py:345`, `:552`, `dtl_conv.py:145`, `sleeping_brain.py:108`, `baselines.py:582` | **never imported by a runtime module** |

### 3.4 Exposed to Stage 3

Stage 3 imports exactly four things, all from `pocketsec/stage2/compile_candidates/`:

1. `CompileCandidateV1` / `CandidateKind` / `ValidityBoundary` / `MeasuredCost` / `CandidateStability` (`candidate.py`)
2. `DeterministicScorerSpec` and `PHI_ORACLE_SCORER` (`phi_oracle_candidate.py`) — the first crystallisation target
3. `Stage3Handoff` / `build_handoff` / `write_handoff` (`stage3_interface.py`)
4. `EvidenceBoundPrediction` / `export_evidence_bound_prediction` (`stage3_interface.py`) — DTL-F20

Plus `ExecutionPath` and `PATH_COST_UNITS` from `core_ids.py`, which Stage 3 reads and never
redefines. **Nothing else in Stage 2 is part of Stage 3's contract.** Per integration plan
§6.5 Stage 3 does not consume Behaviour Atoms, the lattice, Future Cones or the
counterfactual twin as *prerequisites*; they reach Stage 3 only as plain data inside a
`Stage3Handoff`, and only if this wave measures them worth exporting.

---

## 4. The acceptance gate as thirteen executable checks

`pocketsec/stage2/gate.py` — integrator-owned, stdlib-only (the CI `gate` job runs a bare
`pip install -e .`, so a gate that needs numpy is not a gate). Shape copied from
`stage1/gate.py:55-110`: one `Stage2GateContext.build()`, thirteen `_check_*` functions,
`run_gate() -> GateReport`. Every check runs the real subsystem; none inspects a document
(`stage0/gate.py:92` is the anti-pattern not to copy).

| id | Criterion (§38) | Executable check | Meetable now? |
|---|---|---|---|
| G2.1 | At least five strong baselines implemented under identical Stage 1 inputs and evaluation splits | `len(build_baselines()) >= 5`; all fit and score the **same** `(train, test)` pair; every PR-AUC `> test.base_rate`; then `sleeping_brain_report([PhiOracleBaseline, MLPBaseline, TCNBaseline, DTLConvModel], train, test)` and require `pareto["verdict"]` to show the Stage 2 core is **not** dominated by a simpler mechanism (§36 falsification criterion 1) | **NO** |
| G2.2 | A minimum-sufficient latent-state frontier has been measured | `saturation_check` must pass, then `latent_frontier(dimensions=(12,16,24,32,48,64,96))` must return a knee within 0.01 PR-AUC of the best point, on a fixed `(corpus, count, seed)` | **NO** |
| G2.3 | Selective routing reduces measured compute without unacceptable security loss | `WorkLedger.assert_no_phantom_savings()` on every event, then require wall-clock `microseconds_per_event` strictly lower with routing on than off **and** PR-AUC loss ≤ 0.01 | **NO** |
| G2.4 | Behaviour Atoms are stable enough to reuse, **or** the discrete layer is rejected | Quantize the same corpus twice in two orders; `LatticeRestructurer.stability(...) >= 0.90`; atoms must beat `HashBucketQuantizer` on transition log-loss at equal memory **or** improve ledger-proven skipped units. Else the check passes only in the REJECTED branch: `BehaviourQuantizer` disabled by default **and** an ADR in `docs/adr/` records the measured rejection | **YES** (rejection is a pass) |
| G2.5 | Prediction uncertainty is calibrated well enough to support abstention/AOP | `IsotonicCalibrator.fit` on a held-out split; require `calibration_id is not None`, `expected_calibration_error <= 0.10`, `brier_score` reported, and `SplitConformal.coverage` within ±0.05 of nominal | **YES** |
| G2.6 | Future Cone or hazard adds measurable value beyond next-event prediction, **or** is removed | Brier of `predict_future_cone` branch probabilities vs `marginal_cone`; Brier+ECE of `estimate_security_hazard` vs `constant_hazard`; require a strict improvement on at least one. Else the REMOVED branch: cone/hazard default-off plus an ADR | **YES** (removal is a pass) |
| G2.7 | Causal credit produces more concise attribution than naive ancestry under controlled attacks | On the attack scenarios, `AttributionReport.nodes_inspected < naive_ancestry_nodes` at `chain_recall` greater than or equal to the naive path's, where ground truth is the scenario's own chain behaviours | **YES** |
| G2.8 | Concept-drift/epoch tests adapt without normalizing repeated malicious behaviour | Run `build_drift_corpus`; require `DriftReport.transitions_to_recover is not None` and `malicious_patterns_normalised == 0`; assert no attack atom becomes cache-resident or epoch-valid without a corroborated `EpochDecision` | **YES** |
| G2.9 | Poisoning tests validate the quarantine/promotion path | Run `build_poison_suite`; require every poisoned sample to end `REFUSED` or `RETAINED_AS_EVIDENCE`; require `PromotionController` to refuse frequency-only promotion; assert `QuarantineBuffer` bounded and `dropped()` counted | **YES** |
| G2.10 | Sleeping-brain results quantify how much traffic avoids expensive inference | `WorkLedger.histogram()` over the full runtime path with `assert_no_phantom_savings()`, plus wall-clock µs/event from `sleeping_brain_report`. The criterion is *quantify*, so a bad number still passes; a **fakeable** number does not | **YES** |
| G2.11 | Stage 2 remains within the Stage 0 Edge memory/CPU envelope on the 2 GB target | `ResourceSampler` around the whole stdlib runtime path; `check_profile(metrics, "edge", model_bytes=...)`; require `within_target is True` (not `None`) and peak incremental RSS ≤ the 80 MB Stage 2 ceiling (spec §31) | **YES** |
| G2.12 | Every surviving DTL component has an ablation-supported reason to exist | Enumerate `FunctionClass.OPTIONAL` ids in `CORE_IDS`; each must resolve to a `ComponentVerdict` whose `experiment_id` exists in `experiments/registry.jsonl` and whose `verdict` is `JUSTIFIED` **or** whose mechanism is default-off with verdict `REJECTED`. `NOT_YET_JUSTIFIED` or a missing experiment id is **FAILED**, never pending | **YES** (attainable only by rejecting what does not measure up) |
| G2.13 | Stable transition candidates exportable to Stage 3 without embedding DTL assumptions in the hub | Build `phi_oracle_candidate(...)`, `export_candidates`, `build_handoff`, `write_handoff`; assert `from_dict(to_dict(h)) == h`; assert a candidate with `evidence_lineage=()` or an unparseable `experiment_id` raises `ContractError`; AST-assert `compile_candidates/` imports nothing under `*/research/` and no handoff key names a Stage 2 class | **YES** |

### 4.1 Criteria that cannot be met, and why — declared, not quietly passed

**G2.1 — cannot be met on synthetic data.** Measured (ADR-0010): at equal detection
(1.0000) the TCN costs 6.6 µs/event against DTL-C's 22.3 with 2.8× the parameters, so the
Stage 2 core is *dominated* by a simpler mechanism. Worse, the Φ-oracle reaches 0.7484 with
**zero** parameters. No amount of implementation changes this; only a corpus on which a
predictive core beats a TCN on detection, compute or attribution would. Four synthetic
corpora produced only trivial or impossible tasks. **The gate must report G2.1 FAILED and
the wave must not restate the criterion to make it pass.**

**G2.2 — cannot be met on synthetic data.** A latent frontier is only meaningful on a
corpus with headroom. Measured this session: the Φ-oracle scores 1.0000 on `ambiguous` at
`count=60` and 0.5975 at `count=240`, a 0.4025 swing from corpus size alone; `hard` ties
five architectures at 0.9992 (`planning/MEMORY.md`); `long` leaves the Φ-oracle at 0.3172
against a 0.3333 base rate yet a TCN reaches 1.0000. `saturation_check` will therefore
refuse every available corpus, and `refuse_if_degenerate` will stop the sweep. Recording a
knee anyway would be recording a corpus-size artefact. **FAILED, with the reason
`DEGENERATE_CORPUS`.**

**G2.3 — cannot be met.** The router is measured at −0.115 PR-AUC and 3.4× slower while
claiming 100 % cheap-path resolution. This wave builds the accounting that makes such a
claim impossible to repeat; it does not build a router that delivers savings, because no
measured design does. **FAILED**, and the honest artefact is `WorkLedger`, not a number.

Everything else is meetable, several of them **only by rejecting a component** — which the
architecture gate explicitly permits for Behaviour Atoms (G2.4) and the Future Cone (G2.6),
and which criterion 12 (G2.12) demands. **Rejection is the expected outcome for at least one
of them, and the ADR gets written either way.**

### 4.2 Gate-adjacent checks that belong in tests, not the gate

- `test_stage2_has_no_empty_subpackages` — every package under `pocketsec/stage2/` exports at
  least one class or function, asserted by `ast`. An empty package is a defect (integration
  plan §1.1 and risk 1).
- `test_runtime_never_imports_research_code` / `test_runtime_has_no_third_party_imports`
  (`tests/test_repository_structure.py:89`, `:121`) must keep passing for all ten new packages.
- The `tests/` suite imports numpy but numpy is declared in neither `dependencies` nor the
  `dev` extra, so the CI `test` job as written cannot pass (integration plan §5.6). The
  integrator fixes the declaration; it is not a licence to skip research tests.

---

## 5. Baselines: the dumbest thing each component must beat

The architecture gate demands simpler-baseline comparison for everything. Each row names the
specific control, the module that implements it, and the metric. **A component with no
control implemented is not measured, and G2.12 fails it.**

| Component (deliverable) | The dumbest thing that could work | Control lives at | Metric that decides |
|---|---|---|---|
| Behaviour Atom quantizer (D2.6) | `HashBucketQuantizer` — atom id = deterministic bucket of `(relation_family, state_delta_mask, object_property_mask)`; zero training, zero drift | `lattice/quantizer.py` | transition log-loss at equal `memory_bytes`, plus atom count and ledger-proven skipped units |
| Transition lattice (D2.6) | order-1 bigram over `relation_family` — already `MarkovBaseline` | `research/baselines.py:186` | top-1 / top-3 next-family accuracy and perplexity |
| Merge / fission (D2.7) | fixed-K atoms, no restructuring at all | `lattice/restructure.py` via `max_macro=0` | predictive log-loss per lattice byte, and `stability()` across reruns |
| Future Cone (D2.8) | `marginal_cone` — the epoch-marginal continuation distribution, ignoring the current atom; and the 1-branch argmax cone | `predictors/future_cone.py` | Brier over branch labels; PR-AUC of "reaches a high-Φ state within H events" |
| Hazard heads (D2.8) | `constant_hazard` — empirical base rate per `(outcome, horizon)` bucket, no state | `predictors/hazard.py` | Brier + ECE per horizon |
| Uncertainty (D2.9) | `one_minus_max` (1 − max probability) and raw prototype distance | `uncertainty/abstention.py` | ECE, Brier, and risk–coverage AUC for abstention |
| Counterfactual Twin (D2.10) | `phi_only_probe` — drop one transition, replay, score with Stage 1's Φ alone. **Zero parameters** | `counterfactual/twin.py` | precision / recall of ground-truth chain nodes |
| Causal Credit Ledger (D2.10) | `CausalMemory.spine(min_responsibility=0.0)` (full naive ancestry) and top-k by raw ΔΦ | `stage1/causal/memory.py:256` | `nodes_inspected` at equal `chain_recall` (ORTHRUS-style Quality of Attribution) |
| AOP / VoI (D2.11) | `uncertainty_only_requests` — Stage 1's existing `escalation_threshold=0.5` on uncertainty alone | `counterfactual/value_of_information.py` | measured uncertainty reduction per extra event collected; escalations spent per attack detected |
| Epoch guard (D2.12) | accept-everything, and accept-nothing | `adaptation/epoch_guard.py` tests | `transitions_to_recover` after legitimate change; `malicious_patterns_normalised` (must be 0) |
| Quarantine / promotion (D2.12) | promote on frequency alone | `adaptation/promotion.py` tests | poisoned samples promoted (must be 0); buffer bounded |
| Transition cache (D2.13) | plain LRU keyed on `(relation_family, state_delta_mask)` — `BoundedLRUCounter` | `stage1/novelty/sketches.py:186` | ledger-proven skipped-computation fraction and µs/event at equal PR-AUC |
| Predictive-utility forgetting (D2.13) | `lru_control` and `random_control` | `cache/utility.py` | hit rate at equal capacity |
| Compile-candidate exporter (D2.13/D2.15) | the Φ-oracle itself — 0 parameters, ~0 µs/event, 0.7484 PR-AUC | `compile_candidates/phi_oracle_candidate.py` | can the format carry it as a first-class candidate? and does any neural candidate beat it on µs/event at equal PR-AUC? (today: 0.0 vs 6.6 → **no**) |
| Multiscale window (D2.3) | a single most-recent transition (window = 1) | `state/window.py` tests | next-family accuracy and `memory_bytes` |
| Whole Stage 2 runtime path | the Φ-oracle, and the TCN at 6.6 µs/event | `research/sleeping_brain.py:108` | PR-AUC vs µs/event Pareto; anything dominated is rejected |

---

## 6. What would falsify Stage 2's central claim

**The claim.** *A small adaptive machine can learn the dynamics of a Linux host well enough
that detection emerges from prediction, that repeated understanding condenses into discrete
reusable structure, and that computation becomes proportional to novelty.*

Each falsifier below is a measurement, and three of them have **already fired**.

| # | Falsifier | Status |
|---|---|---|
| F1 | Training the predictive heads jointly with detection degrades detection | **FIRED.** 0.3333 joint vs 1.0000 detached; `w_detect=8.0` does not fix it (ADR-0009). "Detection emerges from prediction" is contradicted as implemented. |
| F2 | A simple baseline matches the learned core at materially lower cost | **FIRED.** TCN 6.6 µs/event vs DTL-C 22.3 at equal 1.0000 PR-AUC and 2.8× the parameters (ADR-0010). |
| F3 | A zero-parameter scorer over Stage 1's representation is within tolerance of the best learned core | **FIRED.** Φ-oracle 0.7484 with 0 parameters and ~0 µs/event: about three quarters of the task is the representation, not the model. |
| F4 | Routing labels work rather than avoiding it | **FIRED and being fixed.** 100 % cheap-path reported while every branch computed; the `WorkLedger` (D2.4) makes the claim checkable from now on. |
| F5 | Atom assignments disagree across reruns of the same corpus (`stability() < 0.90`) | To measure — G2.4 |
| F6 | Learned atoms do not beat `HashBucketQuantizer` on transition log-loss at equal memory | To measure — G2.4 |
| F7 | Cone branch probabilities are no better calibrated than `marginal_cone` (Brier no lower) | To measure — G2.6 |
| F8 | Hazard estimates are no better than `constant_hazard` at any horizon | To measure — G2.6 |
| F9 | `nodes_inspected` is not smaller than naive ancestry at equal chain recall | To measure — G2.7 |
| F10 | Ledger-proven skipped-computation fraction is no higher than a plain LRU key cache achieves | To measure — G2.10, G2.13 |
| F11 | Predictive-utility forgetting does not beat LRU or random eviction on hit rate | To measure — D2.13 |
| F12 | Calibration cannot be fitted (`calibration_id is None`) or ECE > 0.10 | To measure — G2.5 |
| F13 | Peak incremental RSS > 80 MB, or CPU/event above the TCN's on the same path | To measure — G2.11 |
| F14 | Poisoned samples reach a trusted atom or candidate | To measure — G2.9 |
| F15 | A repeated malicious pattern becomes epoch-valid or cache-resident | To measure — G2.8 |
| F16 | **Every available corpus stays degenerate** (best − median < 0.01 PR-AUC, or an order-free pooled baseline within 0.02 of best) | **Currently true.** Then no result from this wave supports *or* refutes the claim, and the honest conclusion is **UNMEASURABLE**, not "supported". |

F16 is the meta-falsifier and the one most likely to decide this wave. If it holds, the
correct output is: mechanisms implemented and unit-verified, value **UNMEASURED**, gate
FAILED on G2.1/G2.2/G2.3, and an ADR recording that real telemetry — not more synthetic
corpora — is the blocker. That is a result, and it is the one this repository has been
trending toward since ADR-0010.

---

## 7. Work partition

Eight packages. **No two packages share a file.** `pocketsec/stage2/gate.py`,
`pocketsec/stage2/cli.py`, `pocketsec/stage2/__init__.py`, `pyproject.toml`,
`.github/workflows/ci.yml`, `docs/adr/*`, `docs/stage-2-*findings*.md`,
`planning/MEMORY.md` and `planning/PROGRESS.md` belong to the **integrator** and to no
package. `core_ids.py`, `dataset.py`, `encoder/ssir_encoder.py` and everything under
`research/` except the two new modules named in `report` are **frozen** for this wave.

| # | key | Owns (files, exclusively) | Delivers | Depends on |
|---|---|---|---|---|
| 1 | `lattice` | `lattice/{__init__,atom,quantizer,transitions,equivalence,restructure}.py`, `tests/test_stage2_lattice.py` | D2.6 (DTL-F04), D2.7 (DTL-F13, F14) | — |
| 2 | `routing` | `state/{__init__,window}.py`, `router/{__init__,accounting,policy}.py`, `tests/test_stage2_routing.py` | D2.3 runtime (DTL-F03), D2.4 (DTL-F02) | — |
| 3 | `predictors` | `predictors/{__init__,heads,residual,future_cone,hazard}.py`, `tests/test_stage2_predictors.py` | D2.5 runtime (DTL-F06, F09), D2.8 (DTL-F05, F08) | `lattice`, `routing` |
| 4 | `uncertainty` | `uncertainty/{__init__,calibration,conformal,abstention}.py`, `tests/test_stage2_uncertainty.py` | D2.9 (DTL-F07) | `predictors` |
| 5 | `credit` | `counterfactual/{__init__,twin,value_of_information}.py`, `credit/{__init__,ledger}.py`, `tests/test_stage2_credit.py` | D2.10 (DTL-F10, F11), D2.11 (DTL-F12) | `lattice`, `routing`, `predictors`, `uncertainty` |
| 6 | `adaptation` | `adaptation/{__init__,epoch_guard,quarantine,promotion}.py`, `labs/{__init__,drift_corpus,poison_suite}.py`, `tests/test_stage2_adaptation.py` | D2.12 (DTL-F18, F19) | `lattice` |
| 7 | `export` | `cache/{__init__,transition_cache,utility}.py`, `compile_candidates/{__init__,candidate,exporter,phi_oracle_candidate,stage3_interface}.py`, `tests/test_stage2_export.py` | D2.13 (DTL-F15, F16, F17), D2.15 (DTL-F20) | `lattice`, `routing`, `uncertainty`, `adaptation` |
| 8 | `report` | `research/{saturation,stage2_report}.py`, `tests/test_stage2_report.py` | D2.14, plus the D2.2 saturation extension and the D2.1 accuracy audit | all seven above |

Note on `__init__.py`: the integration plan §1.1 requires them **empty**, and consumers
import from the leaf module. `test_stage2_has_no_empty_subpackages` is satisfied by the
sibling modules, exactly as `encoder/` already is.

---

## 8. ADRs this wave must write

Block **0113–0122**, assigned here to avoid colliding with the pre-assigned 0011/0012 and
the Stage 3–12 reserved blocks 0013–0112. Every ADR keeps the options table with a
**measured** consequence column; without one it is a design note, not an ADR.

| ADR | Subject | Written by |
|---|---|---|
| 0113 | Stage 2 has an executable gate reporting FAILED; a stage may not be declared failed by prose | integrator |
| 0114 | Honest path accounting: a path is reported skipped only when the `WorkLedger` proves the work did not run. Supersedes the notional accounting of ADR-0010 | `routing` |
| 0115 | Behaviour Atoms: accepted or rejected on measured stability and reuse (written **either way**) | `lattice` |
| 0116 | Future Cone / hazard: retained or removed on measured calibration value (written **either way**) | `predictors` |
| 0117 | Stage 2 carries a real `calibration_id`; what it identifies and when it is honestly `None` | `uncertainty` |
| 0118 | `CompileCandidateV1` and the Φ-oracle as a first-class zero-parameter candidate | `export` |
| 0119 | Runtime multiscale state is a bounded per-lineage window, not recurrent state — closes DTL-F03 without resurrecting recurrence | `routing` |
| 0120 | Corpus degeneracy guard; records the measured Φ-oracle corpus-size instability (1.0000 → 0.5975) | `report` |
| 0121 | Deletion of `stage2/{atoms,dtl,prediction}/`; an empty package is a defect | integrator |
| 0122 | Counterfactual credit: accepted or rejected on measured attribution conciseness (written **either way**) | `credit` |

---

## 9. Honest limits — what this wave cannot prove

1. **No detection result generalises.** Every corpus is synthetic. `synthetic_data=True`
   travels with every `BenchmarkResult`, and every findings claim must repeat it.
2. **A zero-parameter baseline's score is a corpus-size artefact here** (measured:
   1.0000 → 0.8495 → 0.5975 on `ambiguous` at count 60/120/240). No component delta measured
   on these corpora can be trusted as a property of the component.
3. **Wake-rate and sleeping-brain figures reflect the synthetic operation mix**, not a real
   host's distribution.
4. **Calibration is calibration on this distribution only.** A valid `calibration_id` on
   synthetic data says nothing about a real host; conformal coverage transfers only under
   exchangeability, which a real host violates.
5. **Drift "recovery time" is counted in synthetic transitions**, not wall time, and the
   epoch changes are the ones we wrote.
6. **Poisoning resistance is tested against our own poison patterns.** It is a mechanism
   test, not an adversarial proof.
7. **RSS and CPU are measured on this development host** (Python 3.14.7, Linux
   7.1.5+kali-amd64), not on a 2 GB device. The 2 GB constraint is checked through the Stage 0
   `edge` profile, which is a target comparison, not a device measurement.
8. **Atom stability is measured across reruns of one generator.** It says nothing about
   stability under real concept drift.
9. **`PATH_COST_UNITS` is uncalibrated.** Its docstring claims calibration from measured CPU
   time; no calibration code exists. Until `report` calibrates it, every
   `compute_units_per_event` is a policy simulation and must be reported as UNMEASURED
   alongside the wall-clock µs/event, which is the only honest cost number.
10. **`ruff` and `mypy` have still never run** on this repository. Lint and type status
    across the new code is UNVERIFIED unless this wave runs them and reports the count.
11. **No formal verification is claimed anywhere.** Every property in this specification is
    an empirical or a construction-enforced claim, and the words "proven" and "verified" are
    reserved for properties with a named prover module — there is none.
