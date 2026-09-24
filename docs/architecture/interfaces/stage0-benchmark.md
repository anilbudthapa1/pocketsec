# Stage 0 — Benchmark Harness, Metrics, Profiles, Experiment Registry, Repro

**Exact API reference.** Every signature and line number below was read out of the `.py` files
in this repository, not from prose. Every number reported as measured was produced by running
code in the session that wrote this document; anything not measured is marked `UNMEASURED`.

Scope (files documented here):
`pocketsec/stage0/benchmark/{dataset,fixtures,harness,profiles,resource_metrics,security_metrics}.py`,
`pocketsec/stage0/experiments/{ids,registry}.py`,
`pocketsec/stage0/repro/{environment,seeds}.py`,
`pocketsec/stage0/gate.py`, `pocketsec/stage0/cli.py`,
`pocketsec/stage0/baselines/frequency_baseline.py`, `pocketsec/stage0/smoke.py`.

Not documented here (separate subsystem, referenced only where a signature needs it):
`pocketsec/stage0/contracts/*`, `pocketsec/stage0/hypotheses.py`, `pocketsec/stage0/prior_art.py`.

---

## 1. Purpose

This subsystem is the single measurement authority for the whole project: `run_benchmark` takes
any object satisfying the `ModelSlot` protocol plus a checksum-bound `SequenceDataset` and returns
one immutable, JSON-serialisable `BenchmarkResult` that carries security quality
(`SecurityMetrics`), measured runtime cost (`ResourceMetrics`), novelty economics
(`NoveltyEconomics`), a resource-profile verdict (`ProfileReport`), and full reproducibility
provenance (`EnvironmentFingerprint`, `SeedSet`, `HostFacts`, dataset name/version/SHA-256) — with
an explicitly-supplied `synthetic_data` flag travelling alongside it. Around that core sit the
immutable experiment-id convention (`format_experiment_id` / `parse_experiment_id`), the
append-only digest-chained `ExperimentRegistry` that is the only sanctioned place a result's
provenance is recorded, the three fixed resource profiles (`nano`, `edge`, `research_max`), the H0
`FrequencyBaselineSlot` that every proposed mechanism must beat, a deterministic synthetic fixture
generator, and the executable Stage 0 acceptance gate (`run_gate`) that refuses to pass unless a
baseline genuinely runs through the harness. Stages 1–12 are expected to report **through** this
harness rather than re-derive its metric definitions, which is what makes Stage 0's measurement
rules binding without each later stage renegotiating them.

---

## 2. Public symbols

Line numbers are `file:line` of the `def`/`class`/assignment statement. All dataclasses listed as
`@dataclass(frozen=True, slots=True)` unless stated otherwise — they are immutable and cannot take
new attributes.

### 2.1 `pocketsec/stage0/benchmark/dataset.py`

`__all__ = ["DatasetError", "LabelledSequence", "SequenceDataset", "sha256_file"]` (dataset.py:20)

| Symbol | Full signature / fields | file:line |
|---|---|---|
| `DatasetError` | `class DatasetError(RuntimeError)` — missing, malformed, or checksum-failing dataset | dataset.py:23 |
| `sha256_file` | `def sha256_file(path: Path) -> str` — streams in 65 536-byte chunks, returns bare hex (no `sha256:` prefix) | dataset.py:27 |
| `LabelledSequence` | `@dataclass(frozen=True, slots=True)` | dataset.py:36 |
| → `sequence` | `sequence: SecurityEventSequenceV1` | dataset.py:39 |
| → `label` | `label: int` — must be `0` or `1` | dataset.py:40 |
| → `technique` | `technique: str | None = None` — metadata only, never a model input | dataset.py:43 |
| → `unseen_technique` | `unseen_technique: bool = False` | dataset.py:45 |
| → `__post_init__` | `def __post_init__(self) -> None` — raises `DatasetError` if `label not in (0, 1)` | dataset.py:47 |
| `SequenceDataset` | `@dataclass(frozen=True, slots=True)` | dataset.py:53 |
| → `name` | `name: str` | dataset.py:56 |
| → `version` | `version: str` | dataset.py:57 |
| → `sha256` | `sha256: str` — the **measured** digest, bare hex | dataset.py:58 |
| → `path` | `path: Path` | dataset.py:59 |
| → `items` | `items: tuple[LabelledSequence, ...]` | dataset.py:60 |
| → `__len__` | `def __len__(self) -> int` | dataset.py:62 |
| → `__iter__` | `def __iter__(self) -> Iterator[LabelledSequence]` | dataset.py:65 |
| → `event_count` | `@property def event_count(self) -> int` — sum of `len(item.sequence.events)` | dataset.py:69 |
| → `positive_count` | `@property def positive_count(self) -> int` | dataset.py:73 |
| → `to_provenance` | `def to_provenance(self) -> dict[str, Any]` — keys: `name, version, sha256, path, item_count, event_count, positive_count` | dataset.py:76 |
| → `load_jsonl` | `@classmethod def load_jsonl(cls, path: Path, *, name: str, version: str, expected_sha256: str | None = None) -> SequenceDataset` | dataset.py:88 |

JSONL line schema consumed by `load_jsonl` (dataset.py:116–123): object with
`sequence` (a `SecurityEventSequenceV1.to_dict()` payload, **required**), `label` (required, coerced
via `int()`), `technique` (optional), `unseen_technique` (optional, coerced via `bool()`). Blank
lines and lines starting with `#` are skipped (dataset.py:114).

### 2.2 `pocketsec/stage0/benchmark/fixtures.py`

`__all__ = ["FIXTURE_VERSION", "write_fixture"]` (fixtures.py:26)

| Symbol | Full signature / value | file:line |
|---|---|---|
| `FIXTURE_VERSION` | `FIXTURE_VERSION = "tiny-linux-events-v0.1.0"` | fixtures.py:28 |
| `write_fixture` | `def write_fixture(path: Path, *, split: str, count: int, seed: int, host: str = "fixture-host-01") -> dict[str, Any]` | fixtures.py:104 |

`split` must be `"train"` or `"eval"` (`ValueError` otherwise, fixtures.py:113–114). Returned
provenance dict keys: `name` (`f"tiny-linux-events-{split}"`), `version` (`FIXTURE_VERSION`),
`split`, `seed`, `item_count`, `sha256`, `synthetic` (always `True`), `path` (**basename only** —
`path.name`, fixtures.py:156).

Private but load-bearing constants: `_BENIGN_PATTERNS` (fixtures.py:30),
`_ATTACK_CHAIN = ("auth.sudo", "cred.read", "net.connect.external")` (fixtures.py:40),
`_UNSEEN_CHAIN = ("ptrace.attach", "mem.dump", "net.connect.external")` (fixtures.py:46).
Generated events use `source="fixture.synthetic"`, `boot_id="boot-0001"`,
`base_ns = 1_760_000_000_000_000_000`, `window_capacity=64`, `truncated=False`
(fixtures.py:57–89, 117).

### 2.3 `pocketsec/stage0/benchmark/harness.py`

`__all__ = ["BenchmarkCase", "BenchmarkResult", "NoveltyEconomics", "run_benchmark"]` (harness.py:39)

| Symbol | Full signature / fields | file:line |
|---|---|---|
| `BenchmarkCase` | `@dataclass(frozen=True, slots=True)` | harness.py:43 |
| → `case_id` | `case_id: str` (no validation) | harness.py:46 |
| → `threshold` | `threshold: float = 0.5` — score `>=` threshold counts positive | harness.py:48 |
| → `fpr_budget` | `fpr_budget: float = 0.01` | harness.py:50 |
| → `host_count` | `host_count: int = 1` | harness.py:52 |
| → `duration_seconds` | `duration_seconds: float = 86_400.0` | harness.py:53 |
| → `resource_profile` | `resource_profile: str = "edge"` — must be a `PROFILES` key | harness.py:54 |
| → `to_dict` | `def to_dict(self) -> dict[str, Any]` | harness.py:56 |
| `NoveltyEconomics` | `@dataclass(frozen=True, slots=True)` | harness.py:68 |
| → `events_total` | `events_total: int` (per **event**) | harness.py:71 |
| → `predictions_total` | `predictions_total: int` (per **window**) | harness.py:72 |
| → `path_counts` | `path_counts: dict[str, int]` — keys are `ComputePath` **string values** | harness.py:73 |
| → `resolved_without_inference` | `resolved_without_inference: float` — `(total - learned_solver) / total` | harness.py:74 |
| → `learned_solver_wake_rate` | `learned_solver_wake_rate: float` | harness.py:75 |
| → `mean_compute_budget_units` | `mean_compute_budget_units: float` | harness.py:76 |
| → `mean_surprise_bits` | `mean_surprise_bits: float | None` | harness.py:77 |
| → `to_dict` | `def to_dict(self) -> dict[str, Any]` | harness.py:79 |
| `BenchmarkResult` | `@dataclass(frozen=True, slots=True)` | harness.py:92 |
| → `experiment_id` | `experiment_id: str` | harness.py:95 |
| → `case` | `case: BenchmarkCase` | harness.py:96 |
| → `slot_name` | `slot_name: str` | harness.py:97 |
| → `model_state_version` | `model_state_version: str` | harness.py:98 |
| → `dataset` | `dataset: dict[str, Any]` — `SequenceDataset.to_provenance()` | harness.py:99 |
| → `security` | `security: SecurityMetrics` | harness.py:100 |
| → `resources` | `resources: ResourceMetrics` | harness.py:101 |
| → `novelty` | `novelty: NoveltyEconomics` | harness.py:102 |
| → `profile_report` | `profile_report: ProfileReport` | harness.py:103 |
| → `environment` | `environment: EnvironmentFingerprint` | harness.py:104 |
| → `seeds` | `seeds: dict[str, int]` — `SeedSet.as_dict()` | harness.py:105 |
| → `host` | `host: HostFacts` | harness.py:106 |
| → `calibrated` | `calibrated: bool` — `all(p.is_calibrated for p in predictions)` | harness.py:107 |
| → `synthetic_data` | `synthetic_data: bool` | harness.py:108 |
| → `started_at_ns` | `started_at_ns: int` (`time.time_ns()`) | harness.py:109 |
| → `finished_at_ns` | `finished_at_ns: int` | harness.py:110 |
| → `to_dict` | `def to_dict(self) -> dict[str, Any]` — fully JSON-serialisable | harness.py:112 |
| `run_benchmark` | `def run_benchmark(slot: ModelSlot, dataset: SequenceDataset, case: BenchmarkCase, *, experiment_id: str, seeds: SeedSet, synthetic_data: bool, model_bytes: int | None = None) -> BenchmarkResult` | harness.py:133 |

Private helpers an implementer must understand even though they are not importable API:

| Helper | Signature | Behaviour | file:line |
|---|---|---|---|
| `_detection_score` | `def _detection_score(prediction: ThreatPredictionV1) -> float` | `0.0` if `not prediction.is_committal`; `1.0 - confidence` if `verdict is Verdict.BENIGN`; else `confidence` | harness.py:207 |
| `_require_matching_sequence` | `def _require_matching_sequence(prediction: ThreatPredictionV1, sequence_id: str) -> None` | raises `ValueError` on mismatch | harness.py:226 |
| `_novelty_economics` | `def _novelty_economics(predictions: list[ThreatPredictionV1], events_total: int) -> NoveltyEconomics` | | harness.py:234 |
| `_with_unseen_recall` | `def _with_unseen_recall(security: SecurityMetrics, dataset: SequenceDataset, scores: list[float], case: BenchmarkCase) -> SecurityMetrics` | rebuilds `SecurityMetrics` with `unseen_technique_recall` | harness.py:259 |

Execution order inside `run_benchmark` (harness.py:149–204), in this exact order:
`validate_slot(slot)` → `parse_experiment_id(experiment_id)` → `seeds.apply()` →
`started_at_ns = time.time_ns()` → `EnvironmentFingerprint.capture(seeds=seeds)` timed into
`startup_seconds` → `with ResourceSampler()` loop calling `slot.predict(item.sequence)` per item
with per-call `perf_counter_ns` latency and a sequence-id match check →
`sampler.result(events_processed=dataset.event_count, startup_seconds=startup_seconds)` →
`evaluate_scores(...)` → `_with_unseen_recall(...)` → `check_profile(resources,
case.resource_profile, model_bytes=model_bytes)` → `HostFacts.capture()` → `BenchmarkResult`.

`run_benchmark` performs **no file I/O** and does **not** touch the experiment registry.

### 2.4 `pocketsec/stage0/benchmark/profiles.py`

`__all__ = ["PROFILES", "ProfileReport", "ResourceProfile", "check_profile"]` (profiles.py:15)

| Symbol | Full signature / value | file:line |
|---|---|---|
| `ResourceProfile` | `@dataclass(frozen=True, slots=True)`: `name: str`, `agent_rss_target_bytes: int`, `model_bytes_target: int | None`, `purpose: str`, `to_dict() -> dict[str, Any]` | profiles.py:21 (fields :22–:25, `to_dict` :27) |
| `PROFILES` | `PROFILES: dict[str, ResourceProfile]` — keys `"nano"`, `"edge"`, `"research_max"` | profiles.py:36 |
| `HOST_RAM_TARGET_BYTES` | `HOST_RAM_TARGET_BYTES = 2 * 1024 * _MB` (= 2 147 483 648) — **not in `__all__`** | profiles.py:58 |
| `ProfileReport` | `@dataclass(frozen=True, slots=True)`: `profile: str`, `observations: tuple[str, ...]`, `exceeded: tuple[str, ...]`, `unmeasured: tuple[str, ...]` | profiles.py:62 (fields :63–:66) |
| → `within_target` | `@property def within_target(self) -> bool | None` — `None` when `unmeasured and not exceeded`; else `not exceeded` | profiles.py:69 |
| → `to_dict` | `def to_dict(self) -> dict[str, Any]` — keys `profile, within_target, observations, exceeded, unmeasured` | profiles.py:75 |
| `check_profile` | `def check_profile(metrics: ResourceMetrics, profile_name: str, *, model_bytes: int | None = None) -> ProfileReport` — raises `KeyError` on unknown profile | profiles.py:85 |

Profile values, literally (profiles.py:36–55, `_MB = 1024 * 1024` at profiles.py:17):

| name | `agent_rss_target_bytes` | `model_bytes_target` | `purpose` |
|---|---|---|---|
| `nano` | `50 * _MB` (52 428 800) | `5 * _MB` (5 242 880) | Extreme low-spec / embedded research target |
| `edge` | `100 * _MB` (104 857 600) | `25 * _MB` (26 214 400) | Primary PocketSec target |
| `research_max` | `200 * _MB` (209 715 200) | `None` | Higher-capability experimental ceiling |

`check_profile` uses `metrics.peak_sampled_rss_bytes or metrics.peak_rss_bytes` as the observed RSS
(profiles.py:97). If that is `None` it appends `"agent_rss"` to `unmeasured`. If
`profile.model_bytes_target is None` it records `"model size target: flexible for this profile"` as
an *observation* (so `research_max` never lands in `unmeasured` for model size); otherwise a
`model_bytes=None` argument appends `"model_bytes"` to `unmeasured` (profiles.py:108–118).

### 2.5 `pocketsec/stage0/benchmark/resource_metrics.py`

`__all__ = ["ResourceMetrics", "ResourceSampler", "read_pss_bytes", "read_rss_bytes"]`
(resource_metrics.py:21)

| Symbol | Full signature / fields | file:line |
|---|---|---|
| `read_rss_bytes` | `def read_rss_bytes() -> int | None` — `VmRSS:` from `/proc/self/status`, `None` off Linux | resource_metrics.py:38 |
| `read_pss_bytes` | `def read_pss_bytes() -> int | None` — `Pss:` from `/proc/self/smaps_rollup` | resource_metrics.py:43 |
| `ResourceMetrics` | `@dataclass(frozen=True, slots=True)` | resource_metrics.py:58 |
| → `idle_rss_bytes` | `idle_rss_bytes: int | None` — RSS at sampler `__enter__` | resource_metrics.py:61 |
| → `peak_rss_bytes` | `peak_rss_bytes: int | None` — `getrusage` `ru_maxrss`, **process lifetime** | resource_metrics.py:62 |
| → `peak_sampled_rss_bytes` | `peak_sampled_rss_bytes: int | None` — `max()` of samples inside the region | resource_metrics.py:63 |
| → `pss_bytes` | `pss_bytes: int | None` | resource_metrics.py:64 |
| → `delta_rss_bytes` | `delta_rss_bytes: int | None` | resource_metrics.py:65 |
| → `cpu_seconds` | `cpu_seconds: float` (`time.process_time()` delta) | resource_metrics.py:66 |
| → `wall_seconds` | `wall_seconds: float` (`time.perf_counter()` delta) | resource_metrics.py:67 |
| → `events_processed` | `events_processed: int` | resource_metrics.py:68 |
| → `startup_seconds` | `startup_seconds: float | None` | resource_metrics.py:69 |
| → `sample_count` | `sample_count: int` | resource_metrics.py:70 |
| → `unavailable` | `unavailable: tuple[str, ...] = ()` — subset of `{"rss", "pss", "peak_rss"}` | resource_metrics.py:71 |
| → `cpu_seconds_per_event` | `@property def cpu_seconds_per_event(self) -> float | None` — `None` if `events_processed <= 0` | resource_metrics.py:74 |
| → `events_per_second` | `@property def events_per_second(self) -> float | None` — `None` if `wall_seconds <= 0` | resource_metrics.py:80 |
| → `to_dict` | `def to_dict(self) -> dict[str, Any]` (also emits the two derived properties) | resource_metrics.py:85 |
| `ResourceSampler` | `class ResourceSampler` — plain class, **not** a dataclass, context manager | resource_metrics.py:103 |
| → `__init__` | `def __init__(self, *, interval_seconds: float = 0.01) -> None` — `ValueError` if `<= 0` | resource_metrics.py:112 |
| → `__enter__` | `def __enter__(self) -> ResourceSampler` — starts a daemon thread named `"rss-sampler"` only when `read_rss_bytes()` is not `None` | resource_metrics.py:125 |
| → `__exit__` | `def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None` — joins with `timeout=2.0` | resource_metrics.py:136 |
| → `result` | `def result(self, *, events_processed: int, startup_seconds: float | None) -> ResourceMetrics` | resource_metrics.py:156 |
| `HostFacts` | `@dataclass(frozen=True, slots=True)` | resource_metrics.py:188 |
| → `cpu_count` | `cpu_count: int | None = field(default_factory=os.cpu_count)` | resource_metrics.py:191 |
| → `total_ram_bytes` | `total_ram_bytes: int | None = None` | resource_metrics.py:192 |
| → `kernel` | `kernel: str = ""` | resource_metrics.py:193 |
| → `machine` | `machine: str = ""` | resource_metrics.py:194 |
| → `capture` | `@classmethod def capture(cls) -> HostFacts` — `MemTotal:` from `/proc/meminfo`, `platform.release()`, `platform.machine()` | resource_metrics.py:197 |
| → `to_dict` | `def to_dict(self) -> dict[str, Any]` | resource_metrics.py:205 |

`_peak_rss_bytes()` (resource_metrics.py:48, private) multiplies `ru_maxrss` by 1024 except on
Darwin, where it is already bytes.

### 2.6 `pocketsec/stage0/benchmark/security_metrics.py`

`__all__ = ["ConfusionMatrix", "SecurityMetrics", "average_precision", "evaluate_scores",
"false_positives_per_host_day", "percentiles", "recall_at_max_fpr"]` (security_metrics.py:14).
Note `confusion_at_threshold` is **public in practice but absent from `__all__`** — Stage 1 and
Stage 2 already import it (`pocketsec/stage1/guillotine/ablation.py:29`,
`pocketsec/stage2/research/experiments.py:26`).

| Symbol | Full signature / fields | file:line |
|---|---|---|
| `ConfusionMatrix` | `@dataclass(frozen=True, slots=True)`; positional order is **`(true_positives, false_positives, true_negatives, false_negatives)`** | security_metrics.py:26 |
| → fields | `true_positives: int`, `false_positives: int`, `true_negatives: int`, `false_negatives: int` | :27, :28, :29, :30 |
| → `precision` | `@property def precision(self) -> float | None` — `None` when no predicted positives | security_metrics.py:33 |
| → `recall` | `@property def recall(self) -> float | None` — `None` when no actual positives | security_metrics.py:40 |
| → `false_positive_rate` | `@property def false_positive_rate(self) -> float | None` — `None` when no actual negatives | security_metrics.py:47 |
| → `f1` | `@property def f1(self) -> float | None` | security_metrics.py:54 |
| → `to_dict` | `def to_dict(self) -> dict[str, Any]` (counts plus the four derived properties) | security_metrics.py:60 |
| `confusion_at_threshold` | `def confusion_at_threshold(labels: Sequence[int], scores: Sequence[float], threshold: float) -> ConfusionMatrix` | security_metrics.py:73 |
| `average_precision` | `def average_precision(labels: Sequence[int], scores: Sequence[float]) -> float | None` — step-wise AP (not trapezoid); `None` when no positives; emits one point per tied score block | security_metrics.py:92 |
| `recall_at_max_fpr` | `def recall_at_max_fpr(labels: Sequence[int], scores: Sequence[float], max_fpr: float) -> tuple[float | None, float | None]` — returns `(recall, threshold)`; `ValueError` if `max_fpr` outside `[0, 1]`; `(None, None)` if either class is absent | security_metrics.py:122 |
| `false_positives_per_host_day` | `def false_positives_per_host_day(false_positives: int, host_count: int, duration_seconds: float) -> float | None` — `None` if `host_count <= 0` or `duration_seconds <= 0` | security_metrics.py:155 |
| `percentiles` | `def percentiles(values: Sequence[float], points: Sequence[int] = (50, 95, 99)) -> dict[str, float]` — nearest-rank; `{}` for empty input; keys are `f"p{point}"` | security_metrics.py:165 |
| `SecurityMetrics` | `@dataclass(frozen=True, slots=True)` | security_metrics.py:178 |
| → `sample_count` | `sample_count: int` | :181 |
| → `positive_count` | `positive_count: int` | :182 |
| → `threshold` | `threshold: float` | :183 |
| → `confusion` | `confusion: ConfusionMatrix` | :184 |
| → `pr_auc` | `pr_auc: float | None` | :185 |
| → `recall_at_fpr_budget` | `recall_at_fpr_budget: float | None` | :186 |
| → `fpr_budget` | `fpr_budget: float` | :187 |
| → `threshold_at_fpr_budget` | `threshold_at_fpr_budget: float | None` | :188 |
| → `false_positives_per_host_day` | `false_positives_per_host_day: float | None` | :189 |
| → `detection_latency_ns` | `detection_latency_ns: dict[str, float]` | :190 |
| → `abstention_rate` | `abstention_rate: float` | :191 |
| → `unseen_technique_recall` | `unseen_technique_recall: float | None = None` | :192 |
| → `to_dict` | `def to_dict(self) -> dict[str, Any]` | security_metrics.py:194 |
| `evaluate_scores` | `def evaluate_scores(labels: Sequence[int], scores: Sequence[float], *, threshold: float, fpr_budget: float, latencies_ns: Sequence[float], abstentions: int, host_count: int, duration_seconds: float) -> SecurityMetrics` | security_metrics.py:211 |

`_require_aligned(labels, scores)` (security_metrics.py:243, private) raises `ValueError` on length
mismatch and on any label not in `(0, 1)`; it runs at the top of `confusion_at_threshold`,
`average_precision`, `recall_at_max_fpr` and `evaluate_scores`.

### 2.7 `pocketsec/stage0/experiments/ids.py`

`__all__ = ["EXPERIMENT_ID_PATTERN", "ExperimentId", "format_experiment_id", "parse_experiment_id"]`
(ids.py:19)

| Symbol | Full signature / value | file:line |
|---|---|---|
| `EXPERIMENT_ID_PATTERN` | compiled regex `^PS-S(?P<stage>\d{1,2})-(?P<date>\d{8})-(?P<hypothesis>H\d{1,2}|BASE)-(?P<slug>[a-z0-9]+(?:-[a-z0-9]+)*)-(?P<sequence>\d{4})$` | ids.py:26 |
| `ExperimentId` | `@dataclass(frozen=True, slots=True)`: `stage: int`, `date: str`, `hypothesis: str`, `slug: str`, `sequence: int`; `__str__` re-formats | ids.py:39 (fields :40–:44, `__str__` :46) |
| `format_experiment_id` | `def format_experiment_id(*, stage: int, hypothesis: str, slug: str, sequence: int, date: str | None = None) -> str` | ids.py:56 |
| `parse_experiment_id` | `def parse_experiment_id(value: str) -> ExperimentId` — `ValueError` on malformed input | ids.py:75 |

`format_experiment_id` validation (ids.py:60–71): `0 <= stage <= 12`; `hypothesis` matches
`^(H\d{1,2}|BASE)$`; `slug` matches `^[a-z0-9]+(?:-[a-z0-9]+)*$`; `0 <= sequence <= 9999`; `date`
defaults to `datetime.now(UTC).strftime("%Y%m%d")` and must be a real calendar date (`20260231` is
rejected via `strptime`). Output format: `f"PS-S{stage}-{stamp}-{hypothesis}-{slug}-{sequence:04d}"`.

### 2.8 `pocketsec/stage0/experiments/registry.py`

`__all__ = ["ExperimentEntry", "ExperimentRegistry", "RegistryError"]` (registry.py:27)

| Symbol | Full signature / fields | file:line |
|---|---|---|
| `GENESIS_DIGEST` | `GENESIS_DIGEST = "sha256:" + "0" * 64` — **not in `__all__`** | registry.py:29 |
| `RegistryError` | `class RegistryError(RuntimeError)` | registry.py:32 |
| `ExperimentEntry` | `@dataclass(frozen=True, slots=True)` | registry.py:37 |
| → `experiment_id` | `experiment_id: str` | :40 |
| → `hypothesis` | `hypothesis: str` | :41 |
| → `title` | `title: str` | :42 |
| → `slot_name` | `slot_name: str` | :43 |
| → `dataset_name` | `dataset_name: str` | :44 |
| → `dataset_version` | `dataset_version: str` | :45 |
| → `dataset_sha256` | `dataset_sha256: str` | :46 |
| → `git_commit` | `git_commit: str | None` | :47 |
| → `seeds` | `seeds: Mapping[str, int]` | :48 |
| → `synthetic_data` | `synthetic_data: bool` | :49 |
| → `recorded_at_ns` | `recorded_at_ns: int` | :50 |
| → `notes` | `notes: str = ""` | :51 |
| → `result_path` | `result_path: str | None = None` | :52 |
| → `previous_digest` | `previous_digest: str = GENESIS_DIGEST` | :53 |
| → `entry_digest` | `entry_digest: str = ""` | :54 |
| → `content_payload` | `def content_payload(self) -> dict[str, Any]` — every field **except** `entry_digest` | registry.py:56 |
| → `compute_digest` | `def compute_digest(self) -> str` — `digest_of_bytes(json.dumps(content_payload(), sort_keys=True, separators=(",", ":")).encode())`, i.e. `sha256:<hex>` | registry.py:75 |
| → `to_dict` | `def to_dict(self) -> dict[str, Any]` — `content_payload()` plus `entry_digest` | registry.py:79 |
| → `from_dict` | `@classmethod def from_dict(cls, payload: Mapping[str, Any]) -> ExperimentEntry` — `RegistryError` on a missing required field | registry.py:83 |
| `ExperimentRegistry` | `class ExperimentRegistry` — plain class | registry.py:106 |
| → `__init__` | `def __init__(self, path: Path) -> None`; exposes `self.path: Path` | registry.py:109 |
| → `all` | `def all(self) -> tuple[ExperimentEntry, ...]` | registry.py:114 |
| → `get` | `def get(self, experiment_id: str) -> ExperimentEntry | None` | registry.py:117 |
| → `register` | `def register(self, *, experiment_id: str, hypothesis: str, title: str, slot_name: str, dataset_name: str, dataset_version: str, dataset_sha256: str, git_commit: str | None, seeds: Mapping[str, int], synthetic_data: bool, notes: str = "", result_path: str | None = None) -> ExperimentEntry` | registry.py:138 |
| → `verify_integrity` | `def verify_integrity(self) -> list[str]` — empty list means intact | registry.py:193 |

`register` (registry.py:155–181): validates the id with `parse_experiment_id`, refuses a duplicate
id with `RegistryError`, stamps `recorded_at_ns = time.time_ns()`, chains
`previous_digest = existing[-1].entry_digest` (or `GENESIS_DIGEST`), seals with
`replace(entry, entry_digest=entry.compute_digest())`, appends one canonical JSON line and
`os.fsync`es (registry.py:183–189). There is **no update and no delete method** — that absence is
the API.

### 2.9 `pocketsec/stage0/repro/environment.py`

`__all__ = ["EnvironmentFingerprint", "git_state"]` (environment.py:22)

| Symbol | Full signature / fields | file:line |
|---|---|---|
| `git_state` | `def git_state(root: Path | None = None) -> tuple[str | None, bool | None]` — returns `(commit, dirty)`; `(None, None)` outside a work tree; default root is `Path(__file__).resolve().parents[3]` | environment.py:44 |
| `EnvironmentFingerprint` | `@dataclass(frozen=True, slots=True)` | environment.py:55 |
| → `captured_at_ns` | `captured_at_ns: int` | :58 |
| → `python_version` | `python_version: str` (`sys.version.split()[0]`) | :59 |
| → `python_implementation` | `python_implementation: str` | :60 |
| → `platform_summary` | `platform_summary: str` — serialised under the key **`"platform"`** | :61 |
| → `kernel` | `kernel: str` | :62 |
| → `machine` | `machine: str` | :63 |
| → `cpu_count` | `cpu_count: int | None` | :64 |
| → `git_commit` | `git_commit: str | None` | :65 |
| → `git_dirty` | `git_dirty: bool | None` | :66 |
| → `pythonhashseed` | `pythonhashseed: str | None` (`os.environ.get("PYTHONHASHSEED")`) | :67 |
| → `seeds` | `seeds: dict[str, int]` | :68 |
| → `source_root` | `source_root: str` | :69 |
| → `is_reproducible` | `@property def is_reproducible(self) -> bool` — `git_commit is not None and git_dirty is False` | environment.py:72 |
| → `caveats` | `@property def caveats(self) -> tuple[str, ...]` | environment.py:77 |
| → `to_dict` | `def to_dict(self) -> dict[str, Any]` — includes `is_reproducible` and `caveats` | environment.py:87 |
| → `capture` | `@classmethod def capture(cls, *, seeds: SeedSet, root: Path | None = None) -> EnvironmentFingerprint` | environment.py:106 |

`_git` (environment.py:27, private) shells out with a fixed argv, `timeout=_GIT_TIMEOUT_SECONDS = 5`
(environment.py:24), and returns `None` on any `OSError`/`SubprocessError`/non-zero exit.

### 2.10 `pocketsec/stage0/repro/seeds.py`

`__all__ = ["SeedSet"]` (seeds.py:15)

| Symbol | Full signature / value | file:line |
|---|---|---|
| `COMPONENTS` | `COMPONENTS = ("dataset_split", "model_init", "sampling", "augmentation", "evaluation")` — **not in `__all__`** | seeds.py:18 |
| `SeedSet` | `@dataclass(frozen=True, slots=True)`; single field `master: int` | seeds.py:24 (field :27) |
| → `__post_init__` | `def __post_init__(self) -> None` — `ValueError` unless `master` is a non-`bool` `int >= 0` | seeds.py:29 |
| → `derive` | `def derive(self, component: str) -> int` — `int.from_bytes(sha256(f"pocketsec-seed-v1:{master}:{component}").digest()[:8], "big") & (2**64 - 1)` | seeds.py:33 |
| → `as_dict` | `def as_dict(self) -> dict[str, int]` — `{"master": ...}` plus one key per `COMPONENTS` entry | seeds.py:38 |
| → `apply` | `def apply(self) -> None` — **only** `random.seed(self.derive("sampling"))` | seeds.py:43 |
| → `from_env` | `@classmethod def from_env(cls, default: int = 0) -> SeedSet` — reads `POCKETSEC_SEED`, accepted only if `str.isdigit()` | seeds.py:54 |

### 2.11 `pocketsec/stage0/gate.py`

`__all__ = ["GateCheck", "GateReport", "REPO_ROOT", "run_gate"]` (gate.py:31)

| Symbol | Full signature / fields | file:line |
|---|---|---|
| `REPO_ROOT` | `REPO_ROOT = Path(__file__).resolve().parents[2]` | gate.py:33 |
| `GateCheck` | `@dataclass(frozen=True, slots=True)`: `id: str`, `title: str`, `passed: bool`, `detail: str`; `to_dict() -> dict[str, Any]` | gate.py:45 (fields :46–:49, `to_dict` :51) |
| `GateReport` | `@dataclass(frozen=True, slots=True)`: `checks: tuple[GateCheck, ...]` | gate.py:56 (field :57) |
| → `passed` | `@property def passed(self) -> bool` | gate.py:60 |
| → `failures` | `@property def failures(self) -> tuple[GateCheck, ...]` | gate.py:64 |
| → `to_dict` | `def to_dict(self) -> dict[str, Any]` — `{"gate": "stage-0", "passed": ..., "checks": [...]}` | gate.py:67 |
| `run_gate` | `def run_gate() -> GateReport` — evaluates all nine clauses in a fixed order | gate.py:75 |

The nine checks, their ids and their enforcing function:

| id | title | function | file:line |
|---|---|---|---|
| `G0.1` | Objective frozen and versioned | `_check_objective_frozen` | gate.py:92 |
| `G0.2` | Hub/model boundary documented | `_check_boundary_documented` | gate.py:111 |
| `G0.3` | Contracts versioned | `_check_contracts_versioned` | gate.py:126 |
| `G0.4` | Profiles and metrics fixed | `_check_measurement_fixed` | gate.py:163 |
| `G0.5` | Experiment rules operational | `_check_experiment_rules_operational` | gate.py:178 |
| `G0.6` | Baseline runs through harness | `_check_baseline_runs` (actually calls `run_smoke_benchmark()`) | gate.py:197 |
| `G0.7` | Hypotheses not claimed as results | `_check_hypotheses_not_results` | gate.py:215 |
| `G0.8` | Prior-art ledger exists | `_check_prior_art_ledger` | gate.py:228 |
| `G0.9` | Stage 1 entry criteria defined | `_check_stage1_can_proceed` | gate.py:242 |

Filesystem paths the gate reads (all private module constants, gate.py:35–41):
`docs/stage-0-research-spec.md`, `docs/architecture/hub-model-boundary.md`,
`docs/reproducibility-policy.md`, `docs/stage-1-entry-criteria.md`,
`docs/adr/0000-adr-template.md`, `contracts/`, and **`experiments/registry.jsonl`** (gate.py:41).

### 2.12 `pocketsec/stage0/cli.py`

`__all__ = ["main"]` (cli.py:24)

| Symbol | Full signature | file:line |
|---|---|---|
| `main` | `def main(argv: Sequence[str] | None = None) -> int` | cli.py:45 |

Invocation: `python -m pocketsec.stage0.cli <command>` from the repo root, or the installed console
script `pocketsec-stage0` (`pyproject.toml` `[project.scripts]`). Global flag `--json` precedes the
subcommand (cli.py:29–30). Subcommands (cli.py:32–41):

| command | arguments | exit code |
|---|---|---|
| `gate` | — | `0` if `report.passed` else `1` (cli.py:82) |
| `smoke` | — | always `0` (cli.py:85–110) |
| `env` | — | `0`; prints `EnvironmentFingerprint.capture(seeds=SeedSet.from_env()).to_dict()` |
| `experiment-id` | `--stage` (int, required), `--hypothesis` (required), `--slug` (required), `--sequence` (int, required), `--date` (default `None`) | `0` |

### 2.13 `pocketsec/stage0/baselines/frequency_baseline.py` — the H0 reference slot

`__all__ = ["FrequencyBaselineSlot", "SURPRISE_SCALE_BITS"]` (frequency_baseline.py:35)

| Symbol | Full signature / value | file:line |
|---|---|---|
| `BOUNDARY` | `BOUNDARY = "<START>"` — not in `__all__` | frequency_baseline.py:37 |
| `LAPLACE_ALPHA` | `LAPLACE_ALPHA = 1.0` — not in `__all__` | frequency_baseline.py:38 |
| `SURPRISE_SCALE_BITS` | `SURPRISE_SCALE_BITS = 12.0` — bits mapped to novelty `1.0` | frequency_baseline.py:42 |
| `MIN_TRANSITIONS_TO_COMMIT` | `MIN_TRANSITIONS_TO_COMMIT = 8` — not in `__all__` | frequency_baseline.py:46 |
| `FrequencyBaselineSlot` | `class FrequencyBaselineSlot` — plain class, **mutable** | frequency_baseline.py:62 |
| → `input_schema` | `input_schema = ACCEPTED_INPUT_SCHEMA` (class attribute) | frequency_baseline.py:65 |
| → `output_schema` | `output_schema = PRODUCED_OUTPUT_SCHEMA` (class attribute) | frequency_baseline.py:66 |
| → `__init__` | `def __init__(self, *, slot_name: str = "h0-frequency-baseline", threshold_bits: float = 4.0)` — sets `self.slot_name`, `self.threshold_bits`, `self.model_state_version = "h0.0.0.0-unfitted"` | frequency_baseline.py:68 |
| → `fit` | `def fit(self, items: Iterable[LabelledSequence]) -> FrequencyBaselineSlot` — trains on `label == 0` items only, mutates `self`, returns `self`, rewrites `model_state_version` to `f"h0.1.0.0-b{benign}-t{transitions}-v{vocab}"` | frequency_baseline.py:76 |
| → `predict` | `def predict(self, sequence: SecurityEventSequenceV1) -> ThreatPredictionV1` | frequency_baseline.py:111 |

Behaviour that matters for comparison: below `MIN_TRANSITIONS_TO_COMMIT` total transitions it
abstains with `Verdict.INSUFFICIENT_EVIDENCE` (frequency_baseline.py:133–134); otherwise it emits
`SUSPICIOUS` when `mean_surprise >= threshold_bits` with `confidence = novelty`, else `BENIGN` with
`confidence = max(0.0, 1.0 - novelty)` (frequency_baseline.py:144–147). `calibration_id` is always
`None` — deliberately, so `BenchmarkResult.calibrated` is `False` rather than faked
(frequency_baseline.py:154). `compute_path` is `CHEAP_TRANSITION` when every bigram was already in
the table, else `STATISTICAL` (frequency_baseline.py:129–131).

### 2.14 `pocketsec/stage0/smoke.py`

`__all__ = ["SMOKE_CASE", "SMOKE_EXPERIMENT_ID", "run_smoke_benchmark"]` (smoke.py:20)

| Symbol | Full signature / value | file:line |
|---|---|---|
| `SMOKE_EXPERIMENT_ID` | `"PS-S0-20260924-H0-frequency-baseline-0000"` | smoke.py:22 |
| `SMOKE_CASE` | `BenchmarkCase(case_id="stage0-smoke", threshold=0.5, fpr_budget=0.01, host_count=1, duration_seconds=86_400.0, resource_profile="edge")` | smoke.py:23 |
| `TRAIN_COUNT` | `80` — not in `__all__` | smoke.py:32 |
| `EVAL_COUNT` | `60` — not in `__all__` | smoke.py:33 |
| `SEED` | `20_260_924` — not in `__all__` | smoke.py:34 |
| `run_smoke_benchmark` | `def run_smoke_benchmark(workdir: Path | None = None) -> BenchmarkResult` — regenerates fixtures into `workdir` (or a `TemporaryDirectory`), fits H0 on the train split, scores the eval split | smoke.py:37 |

`run_smoke_benchmark` always passes `synthetic_data=True` (smoke.py:80) and writes
`fixtures.meta.json` beside the splits (smoke.py:55–58). It does **not** register an experiment.

---

## 3. How to construct and drive the subsystem

The snippet below was **executed against this repository in the session that wrote this document**
and produced the output quoted after it. Run it from the repository root, or with
`PYTHONPATH=/home/anil/Documents/Research/pocketsec` if the interpreter's working directory is
elsewhere (there is no `sys.path` magic; the package is imported normally).

```python
"""Minimal, correct drive path for a later-stage model slot."""

from __future__ import annotations

import json
from pathlib import Path

from pocketsec.stage0.benchmark.dataset import SequenceDataset, sha256_file
from pocketsec.stage0.benchmark.harness import BenchmarkCase, run_benchmark
from pocketsec.stage0.contracts.common import EvidenceRef, digest_of_bytes
from pocketsec.stage0.contracts.model_slot import (
    ACCEPTED_INPUT_SCHEMA,
    PRODUCED_OUTPUT_SCHEMA,
)
from pocketsec.stage0.contracts.security_event_v1 import (
    SecurityEventSequenceV1,
    SecurityEventV1,
)
from pocketsec.stage0.contracts.threat_prediction_v1 import (
    ComputePath,
    EvidenceRelevance,
    NextEventExpectation,
    ThreatPredictionV1,
    Verdict,
)
from pocketsec.stage0.experiments.ids import format_experiment_id
from pocketsec.stage0.experiments.registry import ExperimentRegistry
from pocketsec.stage0.repro.environment import git_state
from pocketsec.stage0.repro.seeds import SeedSet


class MyStageNSlot:
    """Satisfies the ModelSlot protocol. Four attributes plus predict()."""

    slot_name = "s3-demo-slot"
    input_schema = ACCEPTED_INPUT_SCHEMA
    output_schema = PRODUCED_OUTPUT_SCHEMA

    def __init__(self) -> None:
        self.model_state_version = "s3.0.1.0-demo"

    def predict(self, sequence: SecurityEventSequenceV1) -> ThreatPredictionV1:
        hits = sum(1 for e in sequence.events if e.kind == "cred.read")
        if hits == 0:
            # A committal BENIGN verdict. confidence is confidence IN "benign",
            # so the harness scores this 1.0 - confidence = 0.1.
            return ThreatPredictionV1(
                prediction_id=f"{self.slot_name}-{sequence.sequence_id}",
                sequence_id=sequence.sequence_id,     # MUST echo the input id
                verdict=Verdict.BENIGN,
                confidence=0.9,
                novelty_score=0.1,
                uncertainty=0.2,
                model_state_version=self.model_state_version,
                compute_path=ComputePath.CHEAP_TRANSITION,
                compute_budget_units=float(len(sequence.events)),
                next_event=NextEventExpectation(surprise_bits=0.5),
                evidence_relevance=tuple(
                    EvidenceRelevance(ref=ref, weight=1.0 / len(sequence.evidence))
                    for ref in sequence.evidence
                ),
            )
        # A detection. confidence IS the detection score here.
        return ThreatPredictionV1(
            prediction_id=f"{self.slot_name}-{sequence.sequence_id}",
            sequence_id=sequence.sequence_id,
            verdict=Verdict.SUSPICIOUS,
            confidence=0.95,
            novelty_score=0.8,
            uncertainty=0.3,
            model_state_version=self.model_state_version,
            compute_path=ComputePath.LEARNED_SOLVER,
            compute_budget_units=float(len(sequence.events)) * 10.0,
            next_event=NextEventExpectation(surprise_bits=9.0),
        )


def make_sequence(seq_id: str, kinds: tuple[str, ...]) -> SecurityEventSequenceV1:
    events = tuple(
        SecurityEventV1(
            event_id=f"{seq_id}-e{i:03d}",
            host_id="demo-host",              # must equal the sequence host_id
            boot_id="boot-1",
            observed_at_ns=1_760_000_000_000_000_000 + i * 1_000_000,
            monotonic_ns=i * 1_000_000,       # non-decreasing within a boot_id
            source="demo.sensor",
            kind=kind,
            attributes={"idx": str(i)},       # the ONLY ontology extension point
            evidence=(
                EvidenceRef(
                    store="demo",
                    locator=f"{seq_id}#{i}",
                    digest=digest_of_bytes(f"{seq_id}:{i}".encode()),
                ),
            ),
        )
        for i, kind in enumerate(kinds)
    )
    return SecurityEventSequenceV1(
        sequence_id=seq_id,
        host_id="demo-host",
        events=events,
        window_capacity=64,
        truncated=False,
    )


def write_split(path: Path) -> str:
    """Emit the JSONL shape SequenceDataset.load_jsonl parses, return its digest."""
    rows = []
    for i in range(20):
        malicious = i % 4 == 3
        kinds = (
            ("process.exec", "auth.sudo", "cred.read", "net.connect.external")
            if malicious
            else ("process.exec", "file.open", "file.read", "process.exit")
        )
        rows.append(
            json.dumps(
                {
                    "sequence": make_sequence(f"ev-{i:04d}", kinds).to_dict(),
                    "label": 1 if malicious else 0,
                    "technique": "sudo-credential-exfil" if malicious else None,
                    "unseen_technique": bool(malicious and i == 15),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return sha256_file(path)


def main() -> None:
    root = Path("/tmp/stage0-demo")
    split = root / "eval.jsonl"
    digest = write_split(split)

    # Always pass expected_sha256. Omitting it silently skips verification.
    dataset = SequenceDataset.load_jsonl(
        split, name="demo-eval", version="demo-v0.1.0", expected_sha256=digest
    )

    seeds = SeedSet(20_260_924)
    experiment_id = format_experiment_id(
        stage=3, hypothesis="H4", slug="demo-slot", sequence=1, date="20260924"
    )
    case = BenchmarkCase(
        case_id="s3-demo",
        threshold=0.5,
        fpr_budget=0.01,
        host_count=1,
        duration_seconds=86_400.0,
        resource_profile="edge",
    )

    result = run_benchmark(
        MyStageNSlot(),
        dataset,
        case,
        experiment_id=experiment_id,
        seeds=seeds,
        synthetic_data=True,          # keyword-only, no default, REQUIRED
        model_bytes=1_234_567,        # omit and ProfileReport.within_target is None
    )

    # run_benchmark writes nothing. Persistence and provenance are the caller's job.
    out = root / f"{experiment_id}.json"
    out.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

    commit, dirty = git_state()
    registry = ExperimentRegistry(root / "registry.jsonl")
    entry = registry.register(
        experiment_id=experiment_id,
        hypothesis="H4",
        title="Demo slot on demo split",
        slot_name=result.slot_name,
        dataset_name=result.dataset["name"],
        dataset_version=result.dataset["version"],
        dataset_sha256=result.dataset["sha256"],
        git_commit=commit,
        seeds=result.seeds,
        synthetic_data=result.synthetic_data,
        notes=f"dirty_tree={dirty}",
        result_path=str(out),
    )
    assert registry.verify_integrity() == []
    print(entry.entry_digest, result.security.pr_auc)


if __name__ == "__main__":
    main()
```

Measured output of that script in this session (host: Linux 7.1.5+kali-amd64, CPython 3.14.7,
`/home/anil/Documents/Research/pocketsec`, dirty working tree, `PYTHONHASHSEED` unset). These
numbers describe the demo slot on a 20-item synthetic split; they are **not** a detection result
and must never be cited as one:

```
experiment_id        PS-S3-20260924-H4-demo-slot-0001
integrity problems   []
pr_auc               1.0
recall@fpr           1.0
thr@fpr              0.95
unseen recall        1.0
fp/host-day          0.0
abstention           0.0
calibrated           False
paths                {'CHEAP_TRANSITION': 15, 'LEARNED_SOLVER': 5}
resolved w/o infer   0.75
wake rate            0.25
mean budget units    13.0
mean surprise bits   2.625
profile              {'profile': 'edge', 'within_target': True,
                      'observations': ['peak agent RSS 22.7 MB', 'model size 1.18 MB'],
                      'exceeded': [], 'unmeasured': []}
resources            {'peak_sampled_rss_bytes': 23814144, 'events_processed': 80,
                      'cpu_seconds_per_event': 3.86e-06, 'sample_count': 1, 'unavailable': []}
latency pct          {'p50': 12425.0, 'p95': 21497.0, 'p99': 61870.0}
```

To run the shipped reference path instead, with no code of your own:

```bash
cd /home/anil/Documents/Research/pocketsec
python -m pocketsec.stage0.cli smoke          # H0 through the harness, human-readable
python -m pocketsec.stage0.cli smoke --json   # the full BenchmarkResult.to_dict()
python -m pocketsec.stage0.cli gate           # exit 0 on pass; runs the smoke benchmark for G0.6
python -m pocketsec.stage0.cli env            # EnvironmentFingerprint for this machine
python -m pocketsec.stage0.cli experiment-id --stage 3 --hypothesis H4 --slug my-thing --sequence 7
```

Measured in this session: `python -m pocketsec.stage0.cli gate` printed `GATE: PASSED` with all
nine checks passing, in 0.116 s wall; `python -m pocketsec.stage0.cli smoke` reported 60 eval
sequences, 12 positives, PR-AUC 1.0, compute paths `{'CHEAP_TRANSITION': 45, 'STATISTICAL': 15}`,
peak sampled RSS 25 829 376 B, `within_target: None` with `unmeasured: ['model_bytes']`;
`PYTHONHASHSEED=0 python -m pytest tests/test_harness_and_gate.py tests/test_security_metrics.py
tests/test_experiments_and_repro.py` reported `65 passed`.

---

## 4. Invariants enforced in code

Each row names the enforcing site, and the test that pins it where one exists. A row with no test
is enforced by the code only.

| Invariant | Enforced at | Test |
|---|---|---|
| A dataset that does not match its declared SHA-256 refuses to load | `dataset.py:97–102` | `test_dataset_refuses_a_checksum_mismatch` (`tests/test_harness_and_gate.py:28`) |
| An empty dataset is an error, not an empty result | `dataset.py:105–106` | — |
| A missing dataset file is an error | `dataset.py:93–94` | `test_missing_dataset_file_is_an_error` (`tests/test_harness_and_gate.py:78`) |
| A malformed dataset line reports its line number | `dataset.py:124–125` | `test_malformed_dataset_line_reports_its_line_number` (`tests/test_harness_and_gate.py:83`) |
| Labels are binary | `dataset.py:47–49`, `security_metrics.py:246–248` | `test_evaluate_scores_rejects_non_binary_labels` (`tests/test_security_metrics.py:186`) |
| Labels and scores must be the same length | `security_metrics.py:243–245` | `test_evaluate_scores_rejects_misaligned_inputs` (`tests/test_security_metrics.py:172`) |
| A slot must satisfy the frozen hub/model boundary before it is benchmarked | `harness.py:149` → `contracts/model_slot.py:57–76` | `test_a_slot_built_against_a_foreign_schema_is_refused` (`tests/test_authority_boundary.py:104`), `test_null_slot_satisfies_the_boundary_and_always_abstains` (`:95`) |
| An experiment id must be well-formed before a run proceeds | `harness.py:150` → `experiments/ids.py:75–78` | `test_harness_rejects_a_malformed_experiment_id` (`tests/test_harness_and_gate.py:133`) |
| A prediction must be for the sequence being scored, or the run aborts | `harness.py:166`, `harness.py:226–231` | — |
| `synthetic_data` is a required keyword argument, never inferred | `harness.py:140` (keyword-only, no default) | `test_smoke_benchmark_produces_a_complete_result` (`tests/test_harness_and_gate.py:114`) |
| A non-committal prediction scores `0.0`, so novelty cannot manufacture recall | `harness.py:219–220` | `test_high_novelty_abstention_scores_zero` (`tests/test_security_metrics.py:142`) |
| A confidently-BENIGN window is a weak detection, not a strong one | `harness.py:221–222` | `test_benign_confidence_does_not_rank_as_detection` (`tests/test_security_metrics.py:134`) |
| PR-AUC is step-wise average precision; tied scores get one point per tie block | `security_metrics.py:107–118` | `test_average_precision_does_not_order_ties_favourably` (`tests/test_security_metrics.py:53`) |
| An undefined metric is `None`, never `0.0` | `security_metrics.py:33–58, 99–100, 133–134, 159–160` | `test_metrics_are_none_not_zero_when_undefined` (`tests/test_security_metrics.py:34`), `test_average_precision_is_none_without_positives` (`:49`) |
| Empty percentile input yields `{}`, not zeros | `security_metrics.py:166–167` | `test_percentiles_of_nothing_is_empty_not_zero` (`tests/test_security_metrics.py:113`) |
| "No recall achievable inside the budget" is `0.0`; `None` means "not computable" | `security_metrics.py:143` (adds `max(scores) + 1.0` candidate) | `test_recall_at_budget_is_zero_not_none_when_unachievable` (`tests/test_security_metrics.py:76`), `test_recall_at_budget_is_none_when_a_class_is_absent` (`:88`) |
| An out-of-range FPR budget is refused | `security_metrics.py:131–132` | `test_recall_at_budget_rejects_an_out_of_range_budget` (`tests/test_security_metrics.py:92`) |
| An unmeasured profile target is not a met target (`within_target is None`) | `profiles.py:69–73` | `test_unmeasured_target_is_not_a_met_target` (`tests/test_harness_and_gate.py:181`) |
| Exceeding a profile target is reported, not rounded away | `profiles.py:102–118` | `test_exceeding_a_profile_target_is_reported` (`tests/test_harness_and_gate.py:201`) |
| An unknown resource profile is refused, not defaulted | `profiles.py:89–91` | `test_unknown_profile_is_refused` (`tests/test_harness_and_gate.py:219`) |
| The three spec profiles exist and the gate checks them | `profiles.py:36–55`, `gate.py:163–175` | `test_the_three_spec_profiles_exist` (`tests/test_harness_and_gate.py:226`) |
| A resource figure that could not be read is named in `unavailable` | `resource_metrics.py:160–166` | — |
| A sampler interval must be positive | `resource_metrics.py:113–114` | — |
| The sampled peak is scoped to the measured region and kept separate from the process high-water mark | `resource_metrics.py:125–184` | `test_resource_sampler_measures_a_region` (`tests/test_harness_and_gate.py:172`) |
| A master seed must be a non-negative, non-`bool` int | `seeds.py:29–31` | `test_negative_master_seed_is_refused` (`tests/test_experiments_and_repro.py:167`) |
| Component seeds are deterministic and distinct per component | `seeds.py:33–36` | `test_seed_derivation_is_deterministic_and_component_distinct` (`tests/test_experiments_and_repro.py:151`), `test_different_masters_give_different_streams` (`:157`), `test_seed_set_reports_every_component` (`:161`) |
| A dirty or unpinned tree is not called reproducible | `environment.py:72–74`, `environment.py:77–85` | `test_a_dirty_or_unpinned_tree_is_not_called_reproducible` (`tests/test_experiments_and_repro.py:183`) |
| The fingerprint always carries seeds, commit, dirtiness and `PYTHONHASHSEED` | `environment.py:106–122` | `test_fingerprint_captures_the_reproducibility_block` (`tests/test_experiments_and_repro.py:175`) |
| Experiment ids validate every component, including calendar-real dates | `ids.py:60–72` | `test_experiment_id_round_trips` (`tests/test_experiments_and_repro.py:22`), `test_malformed_experiment_ids_are_refused` (`:42`), `test_parsing_a_malformed_id_fails` (`:47`) |
| The registry has no update and no delete API | `registry.py:106–224` (absence is the enforcement) | `test_registry_exposes_no_update_or_delete` (`tests/test_experiments_and_repro.py:90`) |
| An experiment id is never reused | `registry.py:157–161` | `test_registry_refuses_to_reuse_an_experiment_id` (`tests/test_experiments_and_repro.py:83`) |
| Tampering with a recorded entry is detected (chain walked over **recomputed** digests) | `registry.py:210–223` | `test_registry_detects_content_tampering` (`tests/test_experiments_and_repro.py:96`), `test_registry_detects_a_removed_entry` (`:113`) |
| Appends are flushed and `fsync`ed | `registry.py:186–189` | — |
| A malformed registry row is an error naming its line | `registry.py:133–134` | `test_registry_rejects_a_malformed_id` (`tests/test_experiments_and_repro.py:131`) |
| The acceptance gate is executable and G0.6 genuinely runs a baseline through the harness | `gate.py:197–212`, `cli.py:82` | `test_stage0_acceptance_gate_passes` (`tests/test_harness_and_gate.py:253`), `test_gate_cli_exits_zero` (`:260`), `test_gate_cli_emits_json` (`:265`) |
| The fixture train split is benign-only and unseen techniques never appear in training | `fixtures.py:123` | `test_train_split_is_benign_only` (`tests/test_harness_and_gate.py:47`), `test_unseen_technique_items_do_not_appear_in_training` (`:56`) |
| Fixture generation is byte-deterministic for a fixed seed | `fixtures.py:116`, `fixtures.py:140` | `test_fixture_generation_is_deterministic` (`tests/test_harness_and_gate.py:41`) |
| The whole harness is deterministic for a fixed seed | `harness.py:151` | `test_harness_is_deterministic_for_a_fixed_seed` (`tests/test_harness_and_gate.py:126`) |
| An under-trained baseline abstains instead of guessing | `frequency_baseline.py:133–134` | `test_unfitted_baseline_abstains_rather_than_guessing` (`tests/test_harness_and_gate.py:93`) |
| The baseline reports its confidence as uncalibrated (`calibration_id=None`) | `frequency_baseline.py:154` | `test_baseline_reports_uncalibrated_confidence` (`tests/test_harness_and_gate.py:98`) |
| Compute path is measured per prediction, not asserted | `frequency_baseline.py:129–131`, `harness.py:237` | `test_baseline_distinguishes_cheap_from_statistical_paths` (`tests/test_harness_and_gate.py:103`) |
| The abstain-always slot is the measured floor (recall 0, abstention 1.0) | `contracts/model_slot.py:91–103` | `test_null_slot_scores_zero_recall_as_the_floor` (`tests/test_harness_and_gate.py:150`) |

---

## 5. Extension points

### Sanctioned

1. **Implement `ModelSlot` and hand it to `run_benchmark`.** This is *the* plug-in point. Provide
   four attributes (`slot_name`, `model_state_version`, `input_schema`, `output_schema`) and one
   method `predict(sequence) -> ThreatPredictionV1`. `input_schema` must be
   `ACCEPTED_INPUT_SCHEMA` and `output_schema` must be `PRODUCED_OUTPUT_SCHEMA`
   (`contracts/model_slot.py:36–37`), or `validate_slot` refuses the wiring
   (`contracts/model_slot.py:67–76`). A slot may carry any extra state, training method or
   constructor it likes — `FrequencyBaselineSlot.fit` (frequency_baseline.py:76) is precedent, and
   `run_benchmark` never calls anything but `predict`.
2. **Ontology goes in `SecurityEventV1.attributes`** (opaque `str -> str`,
   `contracts/security_event_v1.py:59`) and nowhere else. Adding richer semantics there needs no
   change to this subsystem.
3. **Bring your own dataset** as JSONL in the shape at §2.1, loaded through
   `SequenceDataset.load_jsonl(..., expected_sha256=...)`. Nothing requires the fixture generator;
   `write_fixture` exists only to make the smoke path self-contained.
4. **Pick your own `BenchmarkCase`.** `case_id` is free text; `threshold`, `fpr_budget`,
   `host_count`, `duration_seconds` and `resource_profile` are the per-stage deployment context.
   `resource_profile` must be one of the three `PROFILES` keys.
5. **Record provenance through `ExperimentRegistry.register`** and persist
   `BenchmarkResult.to_dict()` yourself. The observed repository convention is
   `results/<experiment_id>.json` alongside `experiments/registry.jsonl`; the existing rows there
   (`PS-S1-…`, `PS-S2-…`) show later stages already using the Stage 0 id convention.
6. **Reuse the metric primitives directly** when a stage needs a probe or ablation rather than a
   full `BenchmarkResult`: `average_precision`, `confusion_at_threshold`, `recall_at_max_fpr`,
   `percentiles`. Existing precedent: `pocketsec/stage1/guillotine/ablation.py:29`,
   `pocketsec/stage2/research/experiments.py:26`, `pocketsec/stage2/research/sleeping_brain.py:31`.
7. **Reuse `ResourceSampler`, `HostFacts` and `PROFILES`** for a stage's own cost measurement:
   `pocketsec/stage1/gate.py:13` and `pocketsec/stage1/gate.py:462` do exactly this.
8. **Build a stage gate on `GateCheck` / `GateReport`.** `pocketsec/stage1/gate.py:14` imports both
   from `pocketsec.stage0.gate` and composes its own 13-criterion report. Do that rather than
   inventing a parallel report type.
9. **New hypothesis labels** in ids are `H0`–`H99` or `BASE` (`ids.py:35`). A new stage number up to
   12 is already allowed (`ids.py:60`).

### Explicitly not extension points

- **Do not add fields to `ThreatPredictionV1` or `SecurityEventSequenceV1`.** Both are frozen at
  `1.0.0` with a closed JSON Schema; a breaking change requires a new schema `$id`
  (`contracts/common.py:59–64`) and gate check `G0.3` (`gate.py:126`) fails on any drift between the
  Python contracts and `contracts/*.schema.json`.
- **Do not edit `PROFILES` targets or metric definitions to make a result pass.** `G0.4`
  (`gate.py:163`) asserts the three profiles exist; the honesty rule is that a target is a research
  target to test, and an exceeded target is reported (`profiles.py:102–106`).
- **Do not add `update`, `delete`, or an in-place rewrite to `ExperimentRegistry`**, and do not edit
  `experiments/registry.jsonl` by hand. Both are detected (`verify_integrity`, registry.py:193) and
  the Stage 0 gate then fails at `G0.5` (`gate.py:185`) for the entire repository.
- **Do not change the direction or shape of `_detection_score`** (harness.py:207). Every PR-AUC and
  false-positive figure in the project depends on it, and it is not parameterised on purpose.
- **Do not reach into `ResourceSampler`'s interval from the harness.** `run_benchmark` constructs
  `ResourceSampler()` with no arguments (harness.py:161); there is no knob and monkeypatching it
  would silently change what "peak RSS" means across results.
- **Do not make `run_benchmark` write files, register experiments, or fit models.** It validates,
  measures and returns. Persistence, registration and training are the caller's.
- **Do not hand-construct `SecurityMetrics`, `ResourceMetrics` or `ProfileReport`** to populate a
  report. Anything not produced by `evaluate_scores` / `ResourceSampler.result` / `check_profile` is
  an unmeasured number wearing a measured number's type.

---

## 6. Traps — how a later-stage implementer silently gets wrong results

Each item below is a way to get a plausible-looking number that is wrong, with no exception raised.
Items marked *(measured)* were reproduced by running code in this session.

### Scoring direction and the `confidence` field

1. **`confidence` is confidence in the stated verdict, not a detection score.** A slot that always
   emits `Verdict.BENIGN` and puts its detection score in `confidence` gets an exactly **inverted**
   ranking, because `_detection_score` returns `1.0 - confidence` for `BENIGN` (harness.py:222).
   *(measured)* `BENIGN` with `confidence=0.1` scores **0.9** — above the default 0.5 threshold, so
   the most confidently-benign windows become the top detections. Emit `SUSPICIOUS`/`MALICIOUS` with
   `confidence` = detection score.
2. **`novelty_score` and `uncertainty` never reach the score.** A slot that expresses detection only
   through novelty scores `1.0 - confidence` or `confidence` on whatever verdict it happened to
   state, and its PR-AUC will hover near the base rate with no error. Novelty is deliberately
   firewalled out (harness.py:217–218 and MEMORY.md: *novelty is not maliciousness*).
3. **A non-committal verdict scores `0.0` even when `abstained=False`.** `_detection_score` branches
   on `is_committal` (verdict ∈ `{UNKNOWN, UNIDENTIFIABLE, INSUFFICIENT_EVIDENCE}`), not on the
   `abstained` flag *(measured)*. Meanwhile `abstention_rate` counts `prediction.abstained`
   (harness.py:181). A slot that sets one and not the other reports a coherent-looking pair of
   numbers that disagree about the same windows.
4. **`calibrated` is a run-level `all()`, not a rate** (harness.py:200). One prediction with
   `calibration_id=None` makes the whole run `False`, and `all([])` would be `True`. Do not read it
   as "fraction calibrated".

### Resource measurement

5. **`startup_seconds` is not model startup.** It times `EnvironmentFingerprint.capture`
   (harness.py:154–156), which is dominated by two `git` subprocesses with a 5 s timeout each
   (environment.py:24–51). *(measured)* In the smoke run `startup_seconds = 0.0041 s` while the
   whole measured region was `wall_seconds = 0.00079 s` — the "startup" figure is 5× the work it
   supposedly precedes. If you need model load cost, measure it yourself outside the harness.
6. **`peak_sampled_rss_bytes` can rest on a single sample.** The sampler interval is 10 ms
   (resource_metrics.py:112) and a fast dataset finishes inside one tick. *(measured)*
   `sample_count = 1` for both the 60-item smoke run and the 20-item demo run. A short benchmark's
   "peak RSS" is effectively one instantaneous reading, and `check_profile` prefers it over the
   process high-water mark (profiles.py:97).
7. **`peak_rss_bytes` is the whole-process lifetime high-water mark** from `getrusage`
   (resource_metrics.py:48–54). If you trained in the same process, or ran `run_gate` (which
   executes the smoke benchmark, gate.py:200–202), that allocation is inside your "peak". It becomes
   the profile verdict whenever `/proc` sampling is unavailable.
8. **Every RSS figure is the whole Python process, not the model.** The dataset is fully materialised
   by `load_jsonl` *before* the sampler starts, so its memory lands in `idle_rss_bytes` and is
   invisible in `delta_rss_bytes`. A large split makes the agent look heavy and shows nothing in the
   delta.
9. **`within_target` stays `None` forever on `nano`/`edge` unless you pass `model_bytes`.**
   *(measured)* The smoke run reports `within_target: None, unmeasured: ['model_bytes']` even though
   RSS was measured and well inside the target. Conversely `research_max` has
   `model_bytes_target=None`, so it reports `within_target: True` **without any model size being
   measured at all** (profiles.py:108–110). Reading `within_target` across profiles compares two
   different things.
10. **`ResourceSampler.result()` must be called after `__exit__`.** `cpu_seconds`/`wall_seconds` are
    only assigned in `__exit__` (resource_metrics.py:142–143), so calling `result()` inside the
    `with` block reports `0.0` and `events_per_second is None`. Also `result()` re-reads RSS/PSS at
    call time, so `delta_rss_bytes` is measured *after* the region, not at its edge.
11. **`HostFacts` is recorded but never enforced.** Nothing refuses to compare a result measured on
    one machine with a result measured on another. Comparability across hosts is a human
    responsibility.

### Reproducibility

12. **`SeedSet.apply()` seeds only the stdlib `random` module** (seeds.py:51). `numpy`, `torch` and
    any other RNG are untouched — and numpy *is* available in this environment and used by
    `pocketsec/stage2/research/`. A numpy-using slot produces a result whose `seeds` block claims
    reproducibility the run does not have. Seed your own RNGs from `seeds.derive("model_init")`.
13. **`SeedSet` derives only five component streams** (`COMPONENTS`, seeds.py:18). `derive()` accepts
    any string, so a new component name is fine and never disturbs existing seeds — but it must be
    applied by you; `apply()` only consumes `"sampling"`.
14. **`SeedSet.from_env` silently falls back.** It accepts `POCKETSEC_SEED` only when
    `str.isdigit()`. *(measured)* `"-5"`, `"0x10"`, `"12.5"` and `""` all yield `master = 0` (the
    default) with no warning. A typo in the environment produces a fully reproducible run of the
    wrong seed.
15. **`PYTHONHASHSEED` cannot be set at runtime** (seeds.py:46–49). An unset value is recorded as a
    caveat (environment.py:83–84), not fixed. A slot iterating a `set`/`dict` of strings can reorder
    between processes, and the only trace is a caveat string nobody reads.
16. **`git_state()`'s default root is positional on the file layout:**
    `Path(__file__).resolve().parents[3]` (environment.py:46). Copy or vendor `repro/environment.py`
    to a different depth and every result will fingerprint the wrong tree — or no tree — while still
    filling in `git_commit`.
17. **`is_reproducible` being `False` blocks nothing.** The harness records the caveats and proceeds
    (environment.py:6–7). In this session every run was produced from a dirty tree; the result
    records say so, and nothing stopped them.

### Identity, provenance and the registry

18. **`run_benchmark` does not consult the registry.** It only checks the id's *format*
    (harness.py:150). *(measured)* The same `experiment_id` ran twice and both calls returned a
    result. Nothing prevents two different measurements from being written under one id; only
    `ExperimentRegistry.register` refuses reuse (registry.py:157).
19. **`run_benchmark` writes nothing.** Forget to persist `result.to_dict()` and call `register(...)`
    and the measurement exists only in memory — the honesty contract's provenance chain is simply
    absent, with no error.
20. **The registry is not concurrency-safe.** `register` reads the whole ledger (registry.py:156)
    and then appends with `previous_digest` taken from the last row it saw (registry.py:177). Two
    processes registering at once produce two rows sharing one `previous_digest`;
    `verify_integrity()` then reports a chain break — and because gate check `G0.5` verifies the
    *real* repository ledger at `experiments/registry.jsonl` (gate.py:41, gate.py:185), the Stage 0
    gate starts failing for everyone. Serialise registration.
21. **`register` is O(n) per call** (it re-reads the whole file). Registering per-trial inside a
    sweep is quadratic and, worse, invites the concurrency break above.
22. **Tamper-evidence is not tamper-proof.** `verify_integrity` walks recomputed digests
    (registry.py:220), so a single edited row is caught — but someone who rewrites every subsequent
    row consistently is not (registry.py:201–206). Do not treat the chain as an external anchor.
23. **`ExperimentEntry.dataset_sha256` is only as honest as what you pass.** Use
    `result.dataset["sha256"]` (the digest the harness *measured*), never a digest you typed.

### Datasets and labels

24. **`expected_sha256=None` skips verification entirely** (dataset.py:97) and the resulting
    `SequenceDataset.sha256` is the *measured* digest of whatever bytes were on disk — which then
    flows into `to_provenance()` and into the registry looking exactly like a verified digest.
    Always pass the expected digest.
25. **A bad `label` value escapes the line-number wrapper.** `LabelledSequence.__post_init__` raises
    `DatasetError`, which is a `RuntimeError`, while `_parse_lines` only catches
    `KeyError`/`ValueError`/`TypeError` (dataset.py:124). *(measured)* `label: 2` produces
    `DatasetError: label must be 0 or 1, got 2` with **no `path:line` prefix**, so a corrupt line in
    a large split is much harder to find than the other parse errors.
26. **`technique` and `unseen_technique` are metadata, never model inputs** (dataset.py:41–45).
    Feeding `technique` into a slot is label leakage that nothing detects.
27. **`unseen_technique_recall` is measured at a *different* operating point than the headline
    recall.** When the unseen subset is all-positive, `recall_at_max_fpr` returns `None` (it has no
    negatives), and the harness falls back to `security.threshold_at_fpr_budget`, or to
    `case.threshold` if that is also `None` (harness.py:273–290). So the two recall numbers in one
    record can come from two thresholds. And if no item carries `unseen_technique=True`, the field
    stays `None` — which is *not* zero and *not* "the model failed".
28. **The shipped fixture is trivially separable and deliberately so.** The attack chains use event
    kinds (`auth.sudo`, `cred.read`, `net.connect.external`, `ptrace.attach`, `mem.dump`) that never
    occur in the train split (fixtures.py:30–50, 123). *(measured)* H0 scores PR-AUC 1.0 and
    recall@FPR 0.01 = 1.0 on it. That number proves the harness runs; citing it as detection quality
    is exactly the failure the honesty contract exists to prevent.
29. **Fixture positives are at deterministic indices.** `index % 5 == 3` are positive and
    `index % 10 == 8` are the unseen-technique items (fixtures.py:124–128). *(measured)* for
    `count=30`: positives at `[3, 8, 13, 18, 23, 28]`, unseen at `[8, 18, 28]`. Any model that
    picks up index structure looks perfect. Never tune on the fixture.
30. **`write_fixture` returns `"path": path.name`** — a basename, not the path it wrote
    (fixtures.py:156). Recording that value as a location produces provenance that cannot be
    resolved.
31. **`FrequencyBaselineSlot.fit` ignores every item with `label != 0`** (frequency_baseline.py:85).
    Hand it an eval split and it trains on a silently smaller set; `model_state_version` encodes the
    real count (`-b{benign}`), which is the only clue.
32. **`FrequencyBaselineSlot.fit` mutates the slot in place and returns `self`**
    (frequency_baseline.py:96–100), against the project's immutability rule. Re-fitting an instance
    already used in a recorded run changes the `model_state_version` that run's provenance refers
    to. Construct a fresh slot per experiment.

### Metric semantics

33. **`ConfusionMatrix`'s positional order is `(TP, FP, TN, FN)`** (security_metrics.py:27–30), not
    the conventional row-major `(TP, FN, FP, TN)`. Constructing one positionally from another
    library's output swaps false positives and true negatives, which inverts the FPR.
34. **`resolved_without_inference` is self-reported by the slot.** It is simply the fraction of
    predictions whose `compute_path != LEARNED_SOLVER` (harness.py:242, 252). The harness never
    verifies that any computation was actually skipped. MEMORY.md records this having already
    produced a wrong Stage 2 conclusion: *"the Need router reports 100% cheap-path resolution while
    still being 3.4x slower: path accounting is notional, every branch is computed regardless of its
    gate."* Corroborate with `cpu_seconds_per_event`, never with the path counts alone.
35. **`path_counts` and the two novelty ratios are per *window*, while `events_total` is per
    *event*** (harness.py:236–256). Despite the name, `resolved_without_inference` is not an
    "events resolved without inference" figure. *(measured)* In the smoke run:
    `predictions_total = 60`, `events_total = 260`, paths
    `{'CHEAP_TRANSITION': 45, 'STATISTICAL': 15}`, `resolved_without_inference = 1.00` — a ratio over
    60 windows, reported beside a 260-event total.
36. **`mean_surprise_bits` averages only over predictions that populated
    `next_event.surprise_bits`** (harness.py:243–247) and is `None` when none did. A slot that emits
    surprise on some paths and not others reports a mean over a biased subset with no indication of
    coverage.
37. **`detection_latency_ns` is per-call wall time of `slot.predict`** measured with
    `perf_counter_ns` (harness.py:163–165) — the cost of scoring one window, with nothing to do with
    how long after an attack began a detection arrived. Keys are the strings `"p50"`, `"p95"`,
    `"p99"`, values are nearest-rank (no interpolation, security_metrics.py:172).
38. **`false_positives_per_host_day` is derived from `case.host_count` and
    `case.duration_seconds`, which you declare** (security_metrics.py:155–162), not from anything
    measured. Leaving the defaults (`host_count=1`, `duration_seconds=86_400.0`) means "all these
    windows happened on one host in one day", which for a large split is a fiction that makes the
    figure look good or bad arbitrarily.
39. **`threshold` and `threshold_at_fpr_budget` are two different operating points in one record**
    (security_metrics.py:224–234). `confusion`, and therefore precision/recall/FPR and
    `false_positives_per_host_day`, come from `case.threshold`; `recall_at_fpr_budget` comes from the
    budget-selected threshold. Mixing them in one sentence is the easiest way to publish a number
    the record does not contain.
40. **`average_precision` returns `None` when the split has no positives**, and
    `recall_at_max_fpr` returns `(None, None)` when *either* class is absent
    (security_metrics.py:99, 133). *(measured)* Running the null slot over an all-benign split gives
    `pr_auc None, recall@fpr None, thr@fpr None, confusion.recall None`. A pipeline that coerces
    `None` to `0.0` for a chart converts "not computable" into "failed".

### Gate and environment

41. **`run_gate()` runs a full benchmark.** `G0.6` imports and calls `run_smoke_benchmark()`
    in-process (gate.py:199–202). It allocates, spawns a sampler thread, and shells out to `git`.
    Calling `run_gate()` from inside another measured region corrupts that region's RSS and CPU.
42. **`G0.6` swallows the failure cause into a string.** Any exception becomes
    `f"{type(exc).__name__}: {exc}"` on a failed `GateCheck` (gate.py:203–204) with no traceback. A
    broken later-stage change that breaks the smoke path shows up as a one-line gate detail.
43. **`REPO_ROOT` and the gate's document paths are layout-positional** (`parents[2]`, gate.py:33).
    The gate silently fails its document checks if the package is installed somewhere the
    `docs/`, `contracts/` and `experiments/` trees do not sit beside it.
44. **Importing `pocketsec.stage0` from outside the repository root needs the path set.**
    *(measured)* running a driver script by absolute path raised
    `ModuleNotFoundError: No module named 'pocketsec'` until `PYTHONPATH` pointed at the repo root.
    `python -m pocketsec.stage0.cli` works from the root because CWD is on `sys.path`; a console
    script requires an actual install.

---

## 7. What this document does not claim

- No detection-quality claim is made anywhere above. Every score quoted was produced on synthetic
  data (`synthetic_data=True`) and is labelled as such, per the fixture's own contract
  (fixtures.py:1–11) and the README's honest note.
- Resource figures quoted are from a single host in a single session and are not a profile
  conformance claim: the smoke run's `ProfileReport.within_target` was `None`, not `True`.
- `ruff` and `mypy` status for these files is **UNMEASURED** — neither was run in this session.
- Cross-platform behaviour of `read_rss_bytes`, `read_pss_bytes` and `_peak_rss_bytes` off Linux is
  **UNMEASURED**; only the Linux path was exercised.
