# Interface reference — test suite, repository structure, dependency boundary, pyproject, CI

> **Scope.** This document is the exact API reference for the *tooling and enforcement*
> subsystem: `tests/*.py`, `pyproject.toml`, `.github/workflows/ci.yml`, `.gitignore`.
> It is written for an engineer implementing Stages 3–12 who needs to add tests and
> repository structure without breaking the enforcement machinery that already exists.
>
> **Honesty contract.** Every number in this document was produced by running code in the
> session that wrote it, on this machine, on 2026-09-24. Commands and measured outputs are
> quoted inline. Anything not measured is written `UNMEASURED` or `UNVERIFIED`.
> Measurement host: Python 3.14.7, pytest 9.1.1, numpy 2.4.6.

---

## 1. Purpose

This subsystem is the part of PocketSec that turns the project's prose invariants into
executable refusals. It does three separable jobs. First, `tests/` holds 333 collected
tests (measured, §2.6) whose names are deliberately statements of the invariant they
protect, so weakening an invariant means deleting a test that says out loud what is being
given up. Second, `tests/test_repository_structure.py` is a meta-test module: it does not
exercise product behaviour at all but parses the repository's own Python with `ast` to
enforce ADR-0001 (the endpoint runtime imports nothing but the standard library),
ADR-0002 (all importable code lives under `pocketsec/`, top-level directories are artifact
stores) and ADR-0008 (the one-directional research/runtime dependency boundary, where
`pocketsec/stage2/research/` may use numpy and nothing else may, and where research may
import the runtime but the runtime may never import research). Third, `pyproject.toml` and
`.github/workflows/ci.yml` pin the toolchain — zero declared runtime dependencies, a
`dev` extra, pytest with `--strict-markers`, ruff, strict mypy over both `pocketsec` and
`tests`, a three-version test matrix, and an authoritative `gate` job that runs the Stage 0
and Stage 1 acceptance gates and the adversarial suite as installed console entry points.

---

## 2. Public symbols

### 2.1 `tests/conftest.py` — the only shared fixture module

There is exactly one `conftest.py` in the repository, at `tests/conftest.py`. Its
docstring says "Shared fixtures for the Stage 0 test suite" (`tests/conftest.py:1`) but its
helpers are imported by three modules and are the canonical way to build a Stage 0
sequence in any test.

| Symbol | Full signature | file:line | Purpose |
|---|---|---|---|
| `make_event` | `make_event(index: int, kind: str = "process.exec", host: str = "host-a") -> SecurityEventV1` | `tests/conftest.py:14` | Builds one valid `SecurityEventV1`. Derives `event_id=f"ev-{index:03d}"`, `boot_id="boot-1"`, `observed_at_ns=1_000_000_000 + index * 1000`, `monotonic_ns=index * 1000`, `source="test.source"`, `attributes={"i": str(index)}`, and a single-element `evidence` tuple holding `EvidenceRef(store="test", locator=f"e{index}", digest=digest_of_bytes(f"e{index}".encode()))`. |
| `make_sequence` | `make_sequence(kinds: tuple[str, ...] = ("process.exec", "file.open"), sequence_id: str = "seq-1", host: str = "host-a", **kwargs: object) -> SecurityEventSequenceV1` | `tests/conftest.py:32` | Builds a `SecurityEventSequenceV1` whose events are `tuple(make_event(i, kind, host) for i, kind in enumerate(kinds))`. `**kwargs` is forwarded verbatim to the `SecurityEventSequenceV1` constructor (carrying a `# type: ignore[arg-type]`), which is how tests pass `window_capacity=` and `truncated=`. |
| `sequence` | `sequence() -> SecurityEventSequenceV1` — decorated `@pytest.fixture` (default function scope) | fixture decorator at `tests/conftest.py:46`, function at `tests/conftest.py:47` | Returns `make_sequence()`. **Measured: no test in the suite currently requests this fixture** (`grep -rn "def test_.*(sequence" tests/` → no match). It is available and unused. |

Imports that `tests/conftest.py` makes, and therefore the contract surface it depends on:
`EvidenceRef`, `digest_of_bytes` from `pocketsec.stage0.contracts.common`
(`tests/conftest.py:7`); `SecurityEventSequenceV1`, `SecurityEventV1` from
`pocketsec.stage0.contracts.security_event_v1` (`tests/conftest.py:8-11`).

### 2.2 Cross-module import convention (load-bearing, easy to get wrong)

`tests/` contains **no `__init__.py`** (measured: `ls -a tests/` shows none). Consequently
pytest's default `prepend` import mode inserts `tests/` onto `sys.path`, and the three
modules below import the helpers as a *top-level* module named `conftest`, not as a
package-relative import:

- `tests/test_contracts.py:6` — `from conftest import make_event, make_sequence`
- `tests/test_harness_and_gate.py:9` — `from conftest import make_sequence`
- `tests/test_authority_boundary.py:90` — `from conftest import make_sequence` (deliberately
  function-local, inside `_sequence()`)

A new Stage 3+ test module must use this same `from conftest import ...` form. `from
tests.conftest import ...` and `from .conftest import ...` both break, because there is no
package.

### 2.3 `tests/test_repository_structure.py` — the enforcement module

This is the module a later stage will collide with most often. Its module-level names are
the repository's structural contract.

| Symbol | Full signature / value | file:line | Purpose |
|---|---|---|---|
| `SPEC_DIRECTORIES` | `tuple[str, ...]` — 17 entries: `"docs"`, `"docs/architecture"`, `"docs/adr"`, `"docs/prior-art"`, `"contracts"`, `"benchmarks"`, `"experiments"`, `"results"`, `"datasets"`, `"baselines"`, `"models"`, `"models/experimental"`, `"models/compiled"`, `"runtime"`, `"training"`, `"pocketsec"`, `"tests"` | `tests/test_repository_structure.py:14` | Every directory the Stage 0 skeleton requires. Parametrizes `test_spec_directory_exists`, i.e. 17 test cases. |
| `SPEC_DELIVERABLE_FILES` | `tuple[str, ...]` — 14 entries: `"docs/stage-0-research-spec.md"`, `"docs/architecture/hub-model-boundary.md"`, `"docs/adr/0000-adr-template.md"`, `"docs/reproducibility-policy.md"`, `"docs/prior-art/ledger.json"`, `"docs/stage-1-entry-criteria.md"`, `"docs/stage-1-ssir-spec.md"`, `"docs/stage-2-entry-criteria.md"`, `"docs/adr/0005-lineage-scoped-security-state.md"`, `"docs/adr/0006-semantics-are-earned-by-behaviour.md"`, `"contracts/security_event_sequence_v1.schema.json"`, `"contracts/threat_prediction_v1.schema.json"`, `"pyproject.toml"`, `".github/workflows/ci.yml"` | `tests/test_repository_structure.py:34` | Parametrizes `test_stage0_deliverable_exists`, i.e. 14 test cases. |
| `RESEARCH_PREFIX` | `RESEARCH_PREFIX = "pocketsec/stage2/research/"` (a `str`, commented `#: Offline research code, exempt from the stdlib-only rule (ADR-0008).`) | `tests/test_repository_structure.py:73` | **The single, literal, hard-coded numpy exemption.** Compared with `str(path.relative_to(REPO_ROOT)).startswith(RESEARCH_PREFIX)`. |
| `_runtime_modules` | `_runtime_modules() -> list[Path]` | `tests/test_repository_structure.py:76` | `sorted(...)` over `(REPO_ROOT / "pocketsec").rglob("*.py")` excluding paths whose repo-relative string starts with `RESEARCH_PREFIX`. Docstring: "Every module that could run on an endpoint (i.e. not offline research)." Note it covers `pocketsec/` only — `tests/` is never in this list. |
| `_research_modules` | `_research_modules() -> list[Path]` | `tests/test_repository_structure.py:85` | `sorted((REPO_ROOT / "pocketsec" / "stage2" / "research").rglob("*.py"))`. Hard-codes the stage-2 path a second time, independently of `RESEARCH_PREFIX`. |

Imported dependency: `REPO_ROOT` from `pocketsec.stage0.gate`
(`tests/test_repository_structure.py:11`). `REPO_ROOT` is defined at
`pocketsec/stage0/gate.py:33` as `Path(__file__).resolve().parents[2]` and is exported in
that module's `__all__` at `pocketsec/stage0/gate.py:31`. Every filesystem assertion in the
test suite anchors on it; there is no other repo-root helper.

### 2.4 Per-module helpers, constants and fixtures

These are private by naming convention (leading underscore) but are the working
construction API inside each module, and a later stage adding tests to an existing module
will call them. Fixtures are public to pytest by name.

| Symbol | Full signature | file:line | Notes |
|---|---|---|---|
| `SCHEMA_PATH` | `SCHEMA_PATH = REPO_ROOT / "contracts" / "threat_prediction_v1.schema.json"` | `tests/test_authority_boundary.py:25` | The JSON Schema half of the frozen prediction contract. |
| `_field_names` | `_field_names() -> set[str]` | `tests/test_authority_boundary.py:28` | `{field.name for field in dataclasses.fields(ThreatPredictionV1)}`. |
| `_sequence` | `_sequence()` — untyped, carries `# type: ignore[no-untyped-def]` | `tests/test_authority_boundary.py:89` | Function-local `from conftest import make_sequence`, then `return make_sequence()`. |
| `_prediction` | `_prediction(**overrides: object) -> ThreatPredictionV1` | `tests/test_contracts.py:159` | Defaults: `prediction_id="p1"`, `sequence_id="seq-1"`, `verdict=Verdict.BENIGN`, `confidence=0.9`, `novelty_score=0.1`, `uncertainty=0.1`, `model_state_version="m.1.0.0"`, `compute_path=ComputePath.CHEAP_TRANSITION`. `kwargs.update(overrides)` then constructs. |
| `_register` | `_register(registry: ExperimentRegistry, sequence: int) -> None` | `tests/test_experiments_and_repro.py:55` | Registers `format_experiment_id(stage=0, hypothesis="H0", slug="baseline", sequence=sequence, date="20260924")` with `dataset_sha256="0" * 64`, `git_commit=None`, `seeds={"master": 1}`, `synthetic_data=True`. |
| `_prediction` | `_prediction(verdict: Verdict, confidence: float, **kwargs: object) -> ThreatPredictionV1` | `tests/test_security_metrics.py:120` | Distinct from the `test_contracts.py` helper of the same name. Reads `kwargs.get("novelty", 0.0)` and `kwargs.get("abstained", False)`; `uncertainty` is hard-wired to `0.0`. |
| `_record` | `_record(index: int, key: str \| None, rtype: str, expected: str \| None = None) -> RawEventV1` | `tests/test_stage1_bounded.py:169` | Builds a `RawEventV1` with `sensor=SensorPath.AUDITD`, `fields={"path": "/tmp/x"}` plus `"_expected_records": expected` when `expected` is truthy. `assembly_key=key`. |
| `_model` | `_model() -> EpochModel` | `tests/test_stage1_bounded.py:249` | `EpochModel(identity=SystemIdentity(kernel_id="6.1", package_digest="a"))`. |
| `_run` | `_run(behaviours: tuple[Behaviour, ...], label: int = 0)` — untyped return, `# type: ignore[no-untyped-def]` | `tests/test_stage1_bounded.py:503` | `Stage1Pipeline().run_scenario(Scenario("s", behaviours, label))`. **A fresh pipeline per call** — see Trap 8. |
| `CORPUS` | `CORPUS = 140` | `tests/test_stage1_guillotine.py:25` | Guillotine corpus size per split. |
| `_compile` | `_compile(count: int, seed: int) -> list` (`# type: ignore[type-arg]`) | `tests/test_stage1_guillotine.py:28` | One fresh `Stage1Pipeline()`, then `run_scenario(scenario, offset=index)` over `build_hard_corpus(count=count, seed=seed, split="eval")`. |
| `splits` | `splits() -> tuple[list, list]` — `@pytest.fixture(scope="module")` | decorator `tests/test_stage1_guillotine.py:38`, function `:39` | `(_compile(CORPUS, 3), _compile(CORPUS, 11))` — the fit split is seed 3, the score split seed 11. Module-scoped so the corpus is compiled once. |
| `_slots` | `_slots()` — untyped, `# type: ignore[no-untyped-def]` | `tests/test_stage1_pipeline.py:153` | Builds `Stage1GateContext.build()`, keys results as `{f"s1-{i:04d}": r}`, returns `(keyed, StateCalculusSlot(results=keyed), NoveltyStatisticalSlot(results=keyed))`. |
| `_transitions` | `_transitions()` — untyped, `# type: ignore[no-untyped-def]` | `tests/test_stage2_foundation.py:74` | `Stage1Pipeline().run_scenario(Scenario("a", ATTACK_EXFIL, 1)).transitions`. |
| `_grad_check` | `_grad_check(fn, x: np.ndarray, tol: float = 1e-6) -> None` (`# type: ignore[no-untyped-def]`) | `tests/test_stage2_foundation.py:212` | Central-difference gradient check, step `1e-6`, compares `np.max(np.abs(analytic - numeric)) < tol`. `fn` must map a `Tensor` to a scalar `Tensor`. |
| `rng` | `rng() -> np.random.Generator` — `@pytest.fixture` (function scope) | decorator `tests/test_stage2_foundation.py:227`, function `:228` | `np.random.default_rng(0)`. Fixed seed; every gradient test draws from the same stream. |
| `trained` | `trained()` — `@pytest.fixture(scope="module")`, untyped | decorator `tests/test_stage2_foundation.py:286`, function `:287` | Returns `(models, train, test)` where `train = build_dataset(name="s2-train", count=180, seed=3)`, `test = build_dataset(name="s2-test", count=180, seed=11)`, `models = build_baselines(hidden=20, epochs=30)` each `.fit(train)`. |
| `CORPUS` | `CORPUS = 90` | `tests/test_stage2_dtl_conv.py:23` | Distinct from the guillotine `CORPUS = 140`. |
| `EPOCHS` | `EPOCHS = 20` | `tests/test_stage2_dtl_conv.py:24` | |
| `splits` | `splits()` — `@pytest.fixture(scope="module")`, untyped | decorator `tests/test_stage2_dtl_conv.py:27`, function `:28` | `(build_dataset(name="dtlc-train", count=CORPUS, seed=3, corpus="long"), build_dataset(name="dtlc-test", count=CORPUS, seed=11, corpus="long"))`. Note `corpus="long"`. |
| `_score` | `_score(model, test) -> float` (`# type: ignore[no-untyped-def]`) | `tests/test_stage2_dtl_conv.py:35` | `average_precision(list(test.labels), model.predict_scores(test)) or 0.0` — **`None` and `0.0` are collapsed**; see Trap 11. |
| `_train` | `_train(splits, **overrides)` — untyped | `tests/test_stage2_dtl_conv.py:39` | Unpacks `train, test = splits`, builds `DTLConvModel(DTLConvConfig(latent=48, epochs=EPOCHS, **overrides))`, fits on `train`, returns `(model, _score(model, test))`. |
| `ambiguous` | `ambiguous()` — `@pytest.fixture(scope="module")`, untyped | decorator `tests/test_stage2_dtl_conv.py:172`, function `:173` | `(build_dataset(name="amb-train", count=90, seed=3, corpus="ambiguous"), build_dataset(name="amb-test", count=90, seed=11, corpus="ambiguous"))`. |

### 2.5 Product symbols the test suite imports (the surface a later stage must keep alive)

Changing any of these signatures breaks tests. This is the complete import inventory across
`tests/*.py`, grouped by source package.

From `pocketsec.stage0.contracts.common`: `ContractError`, `EvidenceRef`,
`digest_of_bytes`, `register_schema`.
From `pocketsec.stage0.contracts.security_event_v1`: `MAX_SEQUENCE_CAPACITY`,
`SecurityEventSequenceV1`, `SecurityEventV1`.
From `pocketsec.stage0.contracts.threat_prediction_v1`: `ComputePath`,
`EvidenceRelevance`, `FORBIDDEN_AUTHORITY_FIELDS`, `NextEventExpectation`,
`ThreatPredictionV1`, `Verdict`.
From `pocketsec.stage0.contracts.model_slot`: `NullModelSlot`, `validate_slot`.
From `pocketsec.stage0.gate`: `REPO_ROOT`, `run_gate`.
From `pocketsec.stage0.cli`: `main` — signature `main(argv: Sequence[str] | None = None) -> int`
at `pocketsec/stage0/cli.py:45`.
From `pocketsec.stage0.smoke`: `SMOKE_EXPERIMENT_ID`, `run_smoke_benchmark`.
From `pocketsec.stage0.hypotheses`: `HYPOTHESES`, `unsupported_status_claims`.
From `pocketsec.stage0.prior_art`: `PriorArtLedger`.
From `pocketsec.stage0.baselines.frequency_baseline`: `FrequencyBaselineSlot`.
From `pocketsec.stage0.benchmark.*`: `dataset.DatasetError`, `dataset.SequenceDataset`,
`fixtures.write_fixture`, `harness.BenchmarkCase`, `harness.run_benchmark`,
`harness._detection_score` (a private symbol imported directly at
`tests/test_security_metrics.py:7`), `profiles.PROFILES`, `profiles.check_profile`,
`resource_metrics.ResourceMetrics`, `resource_metrics.ResourceSampler`,
`security_metrics.average_precision`, `security_metrics.confusion_at_threshold`,
`security_metrics.evaluate_scores`, `security_metrics.false_positives_per_host_day`,
`security_metrics.percentiles`, `security_metrics.recall_at_max_fpr`.
From `pocketsec.stage0.experiments.*`: `ids.format_experiment_id`,
`ids.parse_experiment_id`, `registry.GENESIS_DIGEST`, `registry.ExperimentRegistry`,
`registry.RegistryError`.
From `pocketsec.stage0.repro.*`: `environment.EnvironmentFingerprint`,
`seeds.COMPONENTS`, `seeds.SeedSet`.
From `pocketsec.stage1.cli`: `main` — signature `main(argv: Sequence[str] | None = None) -> int`
at `pocketsec/stage1/cli.py:41`.
From `pocketsec.stage1.gate`: `Stage1GateContext`, `_stub_sequence` (private, imported at
`tests/test_stage1_pipeline.py:12`; defined `_stub_sequence(sequence_id: str)` at
`pocketsec/stage1/gate.py:516`), `run_gate` (aliased `run_stage1_gate`).
From `pocketsec.stage1.pipeline`: `Stage1Pipeline`.
From `pocketsec.stage1.slot`: `NoveltyStatisticalSlot`, `StateCalculusSlot`.
From `pocketsec.stage1.aggregation.policy`: `AggregationPolicy`, `AggregationThresholds`.
From `pocketsec.stage1.causal.memory`: `CausalMemory`, `causal_signature`.
From `pocketsec.stage1.epoch.model`: `EpochModel`, `SystemIdentity`.
From `pocketsec.stage1.novelty.engine`: `NOVELTY_CONTEXTS`, `NoveltyEngine`.
From `pocketsec.stage1.novelty.sketches`: `BoundedLRUCounter`, `CountMinSketch`,
`StableBloomFilter`.
From `pocketsec.stage1.observation.policy`: `MANDATORY_SIGNALS`,
`AdaptiveObservationPolicy`, `AOPBudget`, `ObservationLevel`.
From `pocketsec.stage1.ssir.codec`: `LAYOUTS`, `SSIRCodec`.
From `pocketsec.stage1.ssir.entities`: `ASSERT_THRESHOLD`, `NEUTRAL_BELIEF`, `Entity`,
`EntityKind`, `SemanticBelief`, `SemanticProperty`.
From `pocketsec.stage1.ssir.relations`: `RELATION_FAMILIES`, `Relation`.
From `pocketsec.stage1.ssir.transition`: `RepresentationLevel`, `TemporalContext`.
From `pocketsec.stage1.state.potential`: `BASE_WEIGHTS`, `INTERACTIONS`, `calibrate`,
`delta_phi`, `phi`.
From `pocketsec.stage1.state.security_state`: `DIMENSIONS`, `CredentialExposure`,
`Persistence`, `Privilege`, `Reachability`, `SecurityStateV1`, `StateDelta`.
From `pocketsec.stage1.telemetry.assembler`: `EventAssembler`.
From `pocketsec.stage1.telemetry.raw_event_v1`: `RawEventV1`, `SensorPath`.
From `pocketsec.stage1.guillotine.*`: `ablation.ABLATIONS`, `ablation.run_guillotine`,
`features.FEATURE_FAMILIES`, `features.LogisticProbe`, `features.extract_features`,
`features.feature_names`, `stability.measure_stability`.
From `pocketsec.stage1.labs.*`: `adversarial.run_adversarial_suite`,
`ambiguous_corpus.build_ambiguous_corpus`, `corpus.ATTACK_EXFIL`,
`corpus.BENIGN_PRIVILEGED`, `corpus.Behaviour`, `corpus.Scenario`, `corpus.build_corpus`,
`corpus.emit`, `hard_corpus.DISCRIMINATOR_PAIRS`, `hard_corpus.build_hard_corpus`,
`hard_corpus._novelty_pair`, `hard_corpus._timing_pair`.
From `pocketsec.stage2.core_ids`: `CORE_IDS`, `PATH_COST_UNITS`, `REQUIRED_IDS`,
`ExecutionPath`, `FunctionClass`.
From `pocketsec.stage2.dataset`: `build_dataset`.
From `pocketsec.stage2.encoder.ssir_encoder`: `FEATURE_LAYOUT`, `FEATURE_WIDTH`,
`encode_ssir_transition`, `feature_names`; and the module object itself, imported as
`pocketsec.stage2.encoder.ssir_encoder` at `tests/test_stage2_foundation.py:130` so its
`__file__` can be re-parsed with `ast`.
From `pocketsec.stage2.research.autograd`: `Tensor`, `binary_cross_entropy`, `bmm`,
`concat`, `cross_entropy`, `normalised_bce`, `normalised_cross_entropy`.
From `pocketsec.stage2.research.baselines`: `GRUBaseline`, `MLPBaseline`, `TCNBaseline`,
`build_baselines`.
From `pocketsec.stage2.research.dtl_conv`: `DTLC_BLOCKS`, `DTLConvConfig`, `DTLConvModel`,
and the private static method `DTLConvModel._dilated_windows` (called at
`tests/test_stage2_dtl_conv.py:143`).
From `pocketsec.stage2.research.sleeping_brain`: `SleepingBrainPoint`,
`sleeping_brain_report`.

`SleepingBrainPoint` is additionally constructed positionally at
`tests/test_stage2_sleeping_brain.py:24` (keyword form) and `:43`
(`SleepingBrainPoint("m", 1.0, 10, 0.01, 0, {}, None)`), which pins its field order to
`(name, pr_auc, transitions, predict_seconds, parameters, path_fractions,
compute_units_per_event)`.

### 2.6 Measured collection inventory

Command: `PYTHONHASHSEED=0 python3 -m pytest --collect-only -q` in the repository root.

| Test module | collected tests |
|---|---|
| `tests/test_authority_boundary.py` | 9 |
| `tests/test_contracts.py` | 41 |
| `tests/test_experiments_and_repro.py` | 20 |
| `tests/test_harness_and_gate.py` | 26 |
| `tests/test_repository_structure.py` | 38 |
| `tests/test_security_metrics.py` | 19 |
| `tests/test_stage1_bounded.py` | 47 |
| `tests/test_stage1_guillotine.py` | 22 |
| `tests/test_stage1_pipeline.py` | 27 |
| `tests/test_stage1_semantics.py` | 29 |
| `tests/test_stage2_dtl_conv.py` | 19 |
| `tests/test_stage2_foundation.py` | 31 |
| `tests/test_stage2_sleeping_brain.py` | 5 |
| **total** | **333** |

`pytest --collect-only -q -m slow` reports 9 slow tests: 7 in
`tests/test_stage2_dtl_conv.py` and 2 in `tests/test_stage2_sleeping_brain.py`.
The 38 in `test_repository_structure.py` decompose as 17 (`SPEC_DIRECTORIES`) + 14
(`SPEC_DELIVERABLE_FILES`) + 7 non-parametrized tests.

Measured results in this session, all with `PYTHONHASHSEED=0`:

- `pytest -q -m "not slow"` → exit 0. 324 tests, no failures. `/usr/bin/time` reported
  **wall 116.71 s, max RSS 540776 KB** for the pytest process.
- `pytest -m slow -rA` → exit 0. Summary line: `9 passed, 324 deselected in 204.05s
  (0:03:24)`. All nine named as PASSED.
- `python -m pocketsec.stage0.cli gate` → exit 0.
  `python -m pocketsec.stage1.cli gate` → exit 0.
  `python -m pocketsec.stage1.cli adversarial` → exit 0.
- `Stage1GateContext.build()` timed in isolation: **0.23 s**.

So: **the whole suite (333 tests) passes on this machine on Python 3.14.7 with numpy
2.4.6 installed.** Ruff and mypy are **not installed** here (`which ruff` and `which mypy`
both report not found), so lint and type-check status is **UNVERIFIED**, consistent with
the "Known gap" section of `planning/MEMORY.md`.

### 2.7 `pyproject.toml` — every configured key

| Key | Value | file:line |
|---|---|---|
| `[build-system] requires` | `["setuptools>=68"]` | `pyproject.toml:2` |
| `[build-system] build-backend` | `"setuptools.build_meta"` | `pyproject.toml:3` |
| `project.name` | `"pocketsec"` | `pyproject.toml:6` |
| `project.version` | `"0.1.0"` | `pyproject.toml:7` |
| `project.description` | `"PocketSec — ultra-lightweight Linux security-event intelligence hub (Stage 0 research foundation)"` | `pyproject.toml:8` |
| `project.readme` | `"README.md"` | `pyproject.toml:9` |
| `project.requires-python` | `">=3.11"` | `pyproject.toml:10` |
| `project.license` | `{ text = "Proprietary" }` | `pyproject.toml:11` |
| `project.dependencies` | `[]` — preceded by the comment `# ADR-0002: the endpoint runtime has ZERO third-party runtime dependencies.` | comment `pyproject.toml:13-14`, value `pyproject.toml:15` |
| `project.optional-dependencies.dev` | `["pytest>=8", "ruff>=0.6", "mypy>=1.11"]` | `pyproject.toml:18` |
| `project.scripts.pocketsec-stage0` | `"pocketsec.stage0.cli:main"` | `pyproject.toml:21` |
| `project.scripts.pocketsec-stage1` | `"pocketsec.stage1.cli:main"` | `pyproject.toml:22` |
| `[tool.setuptools.packages.find] include` | `["pocketsec*"]` | `pyproject.toml:25` |
| `[tool.pytest.ini_options] testpaths` | `["tests"]` | `pyproject.toml:28` |
| `[tool.pytest.ini_options] addopts` | `"-q --strict-markers"` | `pyproject.toml:29` |
| `[tool.pytest.ini_options] markers` | `["slow: benchmark-style tests that sample real process resources"]` — **the only registered marker** | `pyproject.toml:30` |
| `[tool.ruff] line-length` | `100` | `pyproject.toml:33` |
| `[tool.ruff] target-version` | `"py311"` | `pyproject.toml:34` |
| `[tool.ruff.lint] select` | `["E", "F", "I", "B", "UP", "SIM", "RUF"]` | `pyproject.toml:37` |
| `[tool.mypy] python_version` | `"3.11"` | `pyproject.toml:40` |
| `[tool.mypy] strict` | `true` | `pyproject.toml:41` |
| `[tool.mypy] files` | `["pocketsec", "tests"]` — **tests are strictly type-checked too** | `pyproject.toml:42` |

Note the comment at `pyproject.toml:13` attributes the zero-dependency rule to ADR-0002,
while `.github/workflows/ci.yml:27` and `tests/test_repository_structure.py:122` attribute
it to ADR-0001. ADR-0001 is `docs/adr/0001-zero-dependency-endpoint-runtime.md`; the
pyproject comment's ADR number is the outlier. Do not "fix" it without an ADR-touching
change; it is recorded here so an implementer is not confused by the mismatch.

### 2.8 `.github/workflows/ci.yml` — every job and step

Workflow name `CI` (`ci.yml:1`); triggers `on: push` and `on: pull_request`
(`ci.yml:3-5`). Two jobs.

**Job `test`** (`ci.yml:10`): `runs-on: ubuntu-latest` (`:11`),
`strategy.fail-fast: false` (`:13`),
`strategy.matrix.python-version: ["3.11", "3.12", "3.13"]` (`:15`).
Steps: `actions/checkout@v4` with `fetch-depth: 0` (`:17-21`, commented "a shallow clone
would leave git_commit unresolvable"); `actions/setup-python@v5` with the matrix version
(`:23-25`); **"Install dev tooling"** → `python -m pip install --upgrade pip` then
`python -m pip install -e ".[dev]"` (`:28-31`); **"Lint"** → `ruff check pocketsec tests`
(`:33-34`); **"Type check"** → `mypy` (bare, relying on `[tool.mypy] files`) (`:36-37`);
**"Tests"** → `pytest -q` with `env: PYTHONHASHSEED: "0"` (`:39-43`).

**Job `gate`** (`ci.yml:45`): `runs-on: ubuntu-latest`, `needs: test` (`:47`) — it only runs
if every matrix leg of `test` passed. Header comment at `ci.yml:7-8` declares it
authoritative. Steps: checkout with `fetch-depth: 0` (`:49-51`); setup-python pinned to
`"3.12"` (`:53-55`); **"Install package"** → `python -m pip install -e .` (no `[dev]`,
`:57-58`); **"Stage 0 acceptance gate"** → `python -m pocketsec.stage0.cli gate` (`:60-63`);
**"Stage 1 acceptance gate"** → `python -m pocketsec.stage1.cli gate` (`:65-68`);
**"Stage 1 adversarial representation suite"** → `python -m pocketsec.stage1.cli adversarial`
(`:70-73`); **"Smoke benchmark (H0 baseline through the harness)"** →
`python -m pocketsec.stage0.cli --json smoke > smoke-result.json` (`:75-78`);
`actions/upload-artifact@v4` with `name: stage0-smoke-result`, `path: smoke-result.json`
(`:80-83`). Every gate step sets `PYTHONHASHSEED: "0"`.

### 2.9 `.gitignore` — every rule

Tooling/byproduct rules (`.gitignore:1-9`): `__pycache__/`, `*.py[cod]`, `.venv/`, `venv/`,
`*.egg-info/`, `.pytest_cache/`, `.mypy_cache/`, `.ruff_cache/`, `.coverage`, `htmlcov/`.

Artifact-store rules, introduced by the comment "Artifact stores: directory structure and
READMEs are tracked, contents are not." (`.gitignore:12-14`):
`results/*` with `!results/README.md` (`:15-16`); `datasets/*` with `!datasets/README.md`
(`:17-18`); `models/experimental/*` with `!models/experimental/README.md` (`:19-20`);
`models/compiled/*` with `!models/compiled/README.md` (`:21-22`).

Tooling runtime state (`.gitignore:24-26`): `.newcrm/`, `.wf/`.

Measured: `git check-ignore -v results/PS-S0-20260924-H0-frequency-baseline-0000.json`
reports `.gitignore:15:results/*`, so the nine result JSON files currently in `results/`
are ignored. `git check-ignore -v experiments/registry.jsonl` reports **no match** — the
file is tracked, but for a reason the comment at `.gitignore:14` misstates: there is no
`experiments/*` rule at all, so *everything* under `experiments/` is tracked, not just the
ledger.

---

## 3. How to construct and drive the subsystem

### 3.1 Running it

```bash
cd /home/anil/Documents/Research/pocketsec

# The full suite, exactly as CI runs it. Requires numpy (see Trap 1).
PYTHONHASHSEED=0 python -m pytest -q

# Fast loop: skip the nine model-training tests.
PYTHONHASHSEED=0 python -m pytest -q -m "not slow"

# Only the slow ones.
PYTHONHASHSEED=0 python -m pytest -q -m slow

# One module, one test.
PYTHONHASHSEED=0 python -m pytest -q tests/test_repository_structure.py
PYTHONHASHSEED=0 python -m pytest -q \
  tests/test_stage1_pipeline.py::test_stage1_acceptance_gate_passes

# The gate jobs. These need no third-party package at all (measured: they pass
# with numpy made unimportable).
PYTHONHASHSEED=0 python -m pocketsec.stage0.cli gate
PYTHONHASHSEED=0 python -m pocketsec.stage1.cli gate
PYTHONHASHSEED=0 python -m pocketsec.stage1.cli adversarial

# Lint and type check as CI does (neither tool is installed on this machine).
ruff check pocketsec tests
mypy
```

Never pass `-p no:cacheprovider` or an explicit `-c`; `testpaths` and `addopts` come from
`pyproject.toml` and dropping them silently disables `--strict-markers`.

### 3.2 A minimal, correct new test module for a later stage

This compiles and passes against the signatures documented above. It is deliberately
complete: the import form, the fixture reuse, the `REPO_ROOT` anchor, the marker
discipline and the type annotations that strict mypy requires.

```python
"""Stage 3 — AICT/CRYSTAL knowledge cells. Placeholder shape, real conventions."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from conftest import make_sequence  # top-level module: tests/ has no __init__.py

from pocketsec.stage0.contracts.model_slot import NullModelSlot, validate_slot
from pocketsec.stage0.contracts.threat_prediction_v1 import (
    FORBIDDEN_AUTHORITY_FIELDS,
    Verdict,
)
from pocketsec.stage0.gate import REPO_ROOT


def test_a_knowledge_cell_carries_no_response_authority() -> None:
    """ADR-0003 applies to every stage, not only to Stage 0's prediction type."""
    prediction = NullModelSlot().predict(make_sequence())
    payload = prediction.to_dict()
    assert not any(
        banned in key.lower() for key in payload for banned in FORBIDDEN_AUTHORITY_FIELDS
    )


def test_an_uncompiled_cell_abstains_rather_than_guessing() -> None:
    slot = NullModelSlot()
    validate_slot(slot)
    prediction = slot.predict(make_sequence())
    assert prediction.abstained is True
    assert prediction.verdict is Verdict.INSUFFICIENT_EVIDENCE


def test_stage3_package_stays_stdlib_only() -> None:
    """ADR-0001/ADR-0008: pocketsec/stage3/ is NOT exempt from the stdlib rule.

    RESEARCH_PREFIX in tests/test_repository_structure.py names exactly one
    directory, pocketsec/stage2/research/. Nothing under pocketsec/stage3/ is
    covered by it, so a numpy import here fails the repository-structure test.
    """
    package = REPO_ROOT / "pocketsec" / "stage3"
    if not package.is_dir():
        pytest.skip("Stage 3 package does not exist yet")
    for path in sorted(package.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(a.name.split(".")[0] != "numpy" for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] != "numpy"


@pytest.mark.slow  # the ONLY marker registered in pyproject.toml:30
def test_a_training_style_test_declares_itself_slow() -> None:
    assert True
```

Building a Stage 0 sequence with a non-default window, using the `**kwargs` passthrough at
`tests/conftest.py:32`:

```python
from conftest import make_event, make_sequence

seq = make_sequence(("process.exec", "file.open", "net.connect"), window_capacity=8)
truncated = make_sequence(truncated=True)
single = make_sequence(sequence_id="seq-42", host="host-b")
event = make_event(7, kind="net.connect", host="host-b")
```

Driving a Stage 1 pipeline inside a test, the way existing modules do (note the `offset`
argument, which is what keeps per-scenario timestamps from colliding):

```python
from pocketsec.stage1.labs.corpus import ATTACK_EXFIL, Scenario
from pocketsec.stage1.pipeline import Stage1Pipeline

pipeline = Stage1Pipeline()               # fresh: see Trap 8
result = pipeline.run_scenario(Scenario("attack", ATTACK_EXFIL, 1), offset=0)
```

### 3.3 Adding a directory or deliverable to the structural contract

Both are literal tuples, not globs. A new required directory must be appended to
`SPEC_DIRECTORIES` (`tests/test_repository_structure.py:14`) and a new required file to
`SPEC_DELIVERABLE_FILES` (`:34`). Adding an entry adds exactly one parametrized test case,
so the module's collected count rises from the measured 38.

### 3.4 Registering a new pytest marker

`addopts = "-q --strict-markers"` (`pyproject.toml:29`) turns an unregistered marker into a
**collection error**, not a warning. Measured: a file carrying `@pytest.mark.brandnew`,
run with `-c pyproject.toml`, produced

```
ERROR  - Failed: 'brandnew' not found in `markers` configuration option
!!!!!!!!!!!!!!!!!!!! Interrupted: 1 error during collection !!!!!!!!!!!!!!!!!!!!
```

Any new marker must be added to the `markers` list at `pyproject.toml:30`, in the same
`"name: description"` form as `slow`.

---

## 4. Invariants enforced in code

Each row names the file:line or test that does the refusing. Where a test name is given,
that test is the enforcement mechanism — deleting it removes the invariant.

| # | Invariant | Enforced by |
|---|---|---|
| I1 | Every directory the Stage 0 skeleton requires exists. | `tests/test_repository_structure.py:52-54`, `test_spec_directory_exists` (17 cases from `SPEC_DIRECTORIES`) |
| I2 | Every named Stage 0/1/2 deliverable file exists. | `tests/test_repository_structure.py:57-59`, `test_stage0_deliverable_exists` (14 cases from `SPEC_DELIVERABLE_FILES`) |
| I3 | ADR-0002: no importable Python module lives outside `pocketsec/` or `tests/`. | `test_no_importable_module_lives_outside_the_package`, `tests/test_repository_structure.py:62-69`. Implemented as `REPO_ROOT.glob("*/*.py")` filtered by prefix. |
| I4 | ADR-0008, direction: the runtime never imports `pocketsec.stage2.research`. Checked with `ast`, not text search, so a docstring naming the boundary is not a violation (comment at `:97-99`). | `test_runtime_never_imports_research_code`, `tests/test_repository_structure.py:89-108` |
| I5 | The numpy exemption is actually used, so it stays visible. | `test_research_package_is_the_only_numpy_user`, `tests/test_repository_structure.py:111-118`. Measured: 6 research modules contain `import numpy` — `experiments.py`, `dtl.py`, `__init__.py`, `baselines.py`, `dtl_conv.py`, `autograd.py`. See Trap 4 about what this test does *not* check. |
| I6 | ADR-0001: every runtime module imports only `sys.stdlib_module_names` plus `pocketsec`. Relative imports (`node.level != 0`) are skipped. | `test_runtime_has_no_third_party_imports`, `tests/test_repository_structure.py:121-138` |
| I7 | `pyproject.toml` literally contains `dependencies = []`. | `test_pyproject_declares_no_runtime_dependencies`, `tests/test_repository_structure.py:141-143` (a substring check on the file text) |
| I8 | Every runtime module parses. | `test_every_runtime_module_parses`, `tests/test_repository_structure.py:146-149` |
| I9 | `print()` appears only in files named `cli.py`. | `test_no_debug_prints_outside_the_cli`, `tests/test_repository_structure.py:152-166` |
| I10 | ADR-0003: `ThreatPredictionV1` has no authority-bearing field; the JSON Schema has no authority-bearing property; the schema is closed (`additionalProperties is False`); a serialised prediction exposes only schema-known keys; confidence 1.0 grants nothing. | `tests/test_authority_boundary.py:32`, `:45`, `:56`, `:62`, `:68` |
| I11 | The hub survives with no model: `NullModelSlot` validates, abstains, returns `INSUFFICIENT_EVIDENCE`, is non-committal, and does not mutate its input window. | `tests/test_authority_boundary.py:95`, `:118` |
| I12 | A slot built against a foreign input schema is refused. | `test_a_slot_built_against_a_foreign_schema_is_refused`, `tests/test_authority_boundary.py:104-115` (`pytest.raises(Exception, match="accepts")`) |
| I13 | Contract objects copy, never alias, caller-owned mutable state; attributes are not mutable through the contract; events are frozen. | `tests/test_contracts.py:68`, `:85`, `:91` |
| I14 | Bounded windows: empty rejected, mixed hosts rejected, backwards monotonic time rejected, declared capacity enforced, capacity ≤ `MAX_SEQUENCE_CAPACITY` (error text `within [1, 4096]`), truncation explicit. | `tests/test_contracts.py:100`, `:105`, `:111`, `:117`, `:126`, `:131` |
| I15 | A breaking schema change takes a new schema id, never a version bump in place; re-registration at the same version is idempotent. | `test_reregistering_a_schema_at_a_new_version_is_refused`, `tests/test_contracts.py:225-230` |
| I16 | Undefined metrics are `None`, never a plausible zero; but an unachievable recall inside a budget is `0.0`, not `None` (ADR-0004). | `tests/test_security_metrics.py:34`, `:76` |
| I17 | ADR-0004 score orientation: confident-benign must rank below confident-malicious, and a high-novelty abstention scores exactly `0.0` so novelty cannot manufacture recall. | `tests/test_security_metrics.py:134`, `:142` |
| I18 | `ProfileReport.within_target` is `None`, never `True`, when nothing was measured. | `test_unmeasured_target_is_not_a_met_target`, `tests/test_harness_and_gate.py:181-198` |
| I19 | Datasets refuse to load on a checksum mismatch; a missing file and a malformed line are errors, and the malformed-line error names its line number. | `tests/test_harness_and_gate.py:28`, `:78`, `:83` |
| I20 | Train splits are benign-only and unseen-technique items introduce kinds/operations absent from training (leakage-resistant by construction). | `tests/test_harness_and_gate.py:47`, `:56`; `tests/test_stage1_pipeline.py:106`, `:110` |
| I21 | The experiment registry is append-only and digest-chained: no `update`/`delete`/`remove`/`edit`/`overwrite` attribute exists, id reuse is refused, content tampering and entry removal are both detected. | `tests/test_experiments_and_repro.py:90`, `:83`, `:96`, `:113` |
| I22 | A dirty or unpinned tree is not called reproducible, and it says why in `caveats`. | `test_a_dirty_or_unpinned_tree_is_not_called_reproducible`, `tests/test_experiments_and_repro.py:183-217` |
| I23 | `run_benchmark` refuses a malformed experiment id. | `test_harness_rejects_a_malformed_experiment_id`, `tests/test_harness_and_gate.py:133-147` |
| I24 | No hypothesis claims an unevidenced result; every hypothesis has a prior-art entry; no novelty claim is currently permitted. | `tests/test_harness_and_gate.py:233`, `:237`, `:244` |
| I25 | The Stage 0 gate passes and has exactly **9** checks (asserted twice — in-process and through the `--json` CLI). | `tests/test_harness_and_gate.py:253-258`, `:265-269`. The nine are constructed at `pocketsec/stage0/gate.py:77-89`. |
| I26 | The Stage 1 gate passes and has exactly **13** checks. | `test_stage1_acceptance_gate_passes`, `tests/test_stage1_pipeline.py:221-225`. The thirteen are constructed at `pocketsec/stage1/gate.py:89-107`. |
| I27 | The Stage 1 adversarial suite passes with exactly **8** outcomes. | `test_adversarial_suite_passes`, `tests/test_stage1_pipeline.py:143-147` |
| I28 | Both Stage 1 slots satisfy the Stage 0 boundary, report uncalibrated confidence, carry no authority, abstain on an unknown sequence, and two model families disagree on the same representation. | `tests/test_stage1_pipeline.py:159`, `:165`, `:171`, `:181`, `:189` |
| I29 | Bounded memory under flood: CountMinSketch memory is fixed, the stable Bloom filter does not saturate (`fill_rate < 0.9`) and its false-positive rate is validated empirically against its own estimator (within 0.05 over 2000 trials), the LRU counter evicts and reports evicted keys as `0` rather than stale data, and the novelty engine stays under 2 MB after 30000 distinct observations. | `tests/test_stage1_bounded.py:46`, `:54`, `:68`, `:90`, `:159` |
| I30 | Novelty scoring is a pure query: `score()` does not learn, and a missing context key reads as novel (1.0), not familiar (0.0). | `tests/test_stage1_bounded.py:131`, `:141` |
| I31 | Behavioural novelty alone can never open an epoch; corroboration must match the dimension that changed; epoch history is bounded and compresses rather than erases. | `tests/test_stage1_bounded.py:253`, `:278`, `:300`, `:313` |
| I32 | AOP never disables `MANDATORY_SIGNALS`; the budget is a product so any zero factor suppresses; the concurrency cap, the duration expiry and the extra-event-rate cap all hold. | `tests/test_stage1_bounded.py:432`, `:440`, `:455`, `:472`, `:489` |
| I33 | Aggregation never touches a high-consequence transition, and an incompletely observed transition is returned unchanged. | `tests/test_stage1_bounded.py:512`, `:534` |
| I34 | The SSIR decoder refuses a foreign blob (`ContractError` matching `"magic"`) rather than silently misreading a security representation. | `test_decoder_refuses_a_foreign_blob`, `tests/test_stage1_bounded.py:564-569` |
| I35 | A supervised ablation probe refuses a single-class fit split. | `test_probe_refuses_a_single_class_fit`, `tests/test_stage1_guillotine.py:46-53` (`ValueError`, `match="both classes"`) |
| I36 | The guillotine frontier reports its own weaknesses: a same-split fit is flagged `OPTIMISTIC`, degeneracy is stated in the caveat, and stability requires unanimity across draws before a field becomes a freeze candidate. | `tests/test_stage1_guillotine.py:168`, `:209`, `:215`; `tests/test_stage1_pipeline.py:258` |
| I37 | ADR-0007: the Stage 2 encoder ignores identity and display name — proven behaviourally (renamed actor/object encode identically) **and** structurally (the encoder source contains no `identity` / `display_name` attribute access, checked by re-parsing the module with `ast`). | `tests/test_stage2_foundation.py:96-122`, `:125-137` |
| I38 | Every Stage 2 feature is finite and within `[-1.0, 1.0]`. | `test_every_feature_is_finite_and_bounded`, `tests/test_stage2_foundation.py:88-93` |
| I39 | Dataset construction is order-independent — a fresh Stage 1 pipeline per split, so a fit split cannot warm the novelty engine that scores the eval split — and the guard test proves a shared pipeline *would* change the features. | `test_dataset_build_is_independent_of_call_order`, `tests/test_stage2_foundation.py:166-177`; guard at `:180-201` |
| I40 | The autodiff is gradient-checked against central finite differences at tolerance `1e-6` for tanh, sigmoid, relu, log_softmax, cross_entropy, binary_cross_entropy, matmul, bmm, concat, reshape, transpose, exp; and `backward()` requires a scalar. | `tests/test_stage2_foundation.py:232-280` via `_grad_check` at `:212` |
| I41 | Every baseline beats the dataset base rate; a model below chance is treated as a bug. | `test_every_baseline_beats_the_base_rate`, `tests/test_stage2_foundation.py:302-315` |
| I42 | Multi-term losses are normalised so weights cannot silently encode vocabulary size (a 24-class head and a binary head both start near 1.0). | `test_normalised_losses_start_near_one`, `tests/test_stage2_dtl_conv.py:49-63` |
| I43 | Dilated convolution windows are causal — no future leakage into the prediction heads. | `test_dilated_windows_are_causal`, `tests/test_stage2_dtl_conv.py:140-150` |
| I44 | Auxiliary heads stay detached (joint training measured at −0.3+ PR-AUC and re-weighting does not fix it), and router/surprise/lineage-pooling ship off by default per acceptance criterion 12. | `tests/test_stage2_dtl_conv.py:82`, `:98`, `:221`, `:304` |
| I45 | The ambiguous corpus is aggregate-matched: per-session operation counts may not differ across classes by more than `max(1.5, 0.15 * max(benign, attack))`, so the label is not inferable by counting. | `test_ambiguous_corpus_is_aggregate_matched`, `tests/test_stage2_dtl_conv.py:251-274` |
| I46 | Known blockers are asserted **as measured**, not as wishes: the ambiguous corpus is pinned as saturated (`TCN ≥ 0.95`) with a failure message instructing the reader to update PROGRESS.md and re-run ablations rather than "fix" the test. | `test_ambiguous_corpus_is_currently_saturated`, `tests/test_stage2_dtl_conv.py:198-217` |
| I47 | A retracted result stays retracted: per-lineage pooling must change the score by less than 0.02, with a failure message telling the reader to reopen the criterion-12 verdict and ADR-0009. | `test_lineage_pooling_adds_nothing_because_stage1_already_attributes`, `tests/test_stage2_dtl_conv.py:277-301` |
| I48 | Execution-path costs increase monotonically from `P0_COMPILED` to `P4_DEEP`, and `cheap_path_share` counts only the cheap tiers. | `tests/test_stage2_foundation.py:62-68`; `tests/test_stage2_sleeping_brain.py:22`, `:47` |
| I49 | A model with no routing reports `cheap_path_share is None`, not a fabricated share. | `test_models_without_routing_report_no_path_share`, `tests/test_stage2_sleeping_brain.py:42-44` |
| I50 | ADR-0010's verdict is pinned: at equal quality the TCN is cheaper per event than DTL-C, with a failure message saying "if that has changed, reopen ADR-0010". | `test_dtl_is_dominated_on_cost_at_equal_quality`, `tests/test_stage2_sleeping_brain.py:52-76` |
| I51 | An unregistered pytest marker is a collection error, not a warning. | `addopts = "-q --strict-markers"`, `pyproject.toml:29`, with the allowed list at `:30`. Verified by measurement in §3.4. |
| I52 | Test-suite iteration is reproducible: `PYTHONHASHSEED: "0"` is set on every CI step that runs Python. | `.github/workflows/ci.yml:41-42`, `:61-62`, `:66-67`, `:71-72`, `:76-77` |
| I53 | The gate job cannot run unless all three matrix legs of `test` pass. | `needs: test`, `.github/workflows/ci.yml:47` |
| I54 | Git history is fully fetched so `git_commit` in the reproducibility block resolves. | `fetch-depth: 0` at `.github/workflows/ci.yml:21` and `:51` |
| I55 | Artifact-store *contents* are not committed, but the directory structure and each README are. | `.gitignore:15-22` |

---

## 5. Extension points

### 5.1 Sanctioned: add a new test module under `tests/`

A new file `tests/test_stage<N>_<topic>.py` is picked up automatically —
`testpaths = ["tests"]` (`pyproject.toml:28`) plus pytest's default `test_*.py` discovery.
No registration step exists and none should be added. Use `from conftest import ...` for
the shared builders (§2.2). Name tests after the invariant they protect, which is the
convention every existing module follows and the reason
`tests/test_authority_boundary.py:3-7` gives explicitly: "they are deliberately written so
that weakening the invariant means deleting a test whose name says what it protects."

### 5.2 Sanctioned: append to `SPEC_DIRECTORIES` / `SPEC_DELIVERABLE_FILES`

`tests/test_repository_structure.py:14` and `:34`. This is how a stage makes its own
required directory or deliverable document structurally mandatory. Each appended string is
one new parametrized test.

### 5.3 Sanctioned: add a package under `pocketsec/stage<N>/`

`[tool.setuptools.packages.find] include = ["pocketsec*"]` (`pyproject.toml:25`) picks up
any new `pocketsec.*` package with no packaging change. The new package is automatically
subject to I6 (stdlib-only), I8 (must parse) and I9 (no `print()` outside `cli.py`).

### 5.4 Sanctioned: add a console entry point and a CI gate step

`[project.scripts]` (`pyproject.toml:20-22`) is the pattern: a new
`pocketsec-stage<N> = "pocketsec.stage<N>.cli:main"` where `main` has the established
signature `main(argv: Sequence[str] | None = None) -> int` (see
`pocketsec/stage0/cli.py:45`, `pocketsec/stage1/cli.py:41`). A new gate belongs in the
`gate` job of `.github/workflows/ci.yml` alongside `:60-73`, invoked as
`python -m pocketsec.stage<N>.cli gate` with `PYTHONHASHSEED: "0"`, and it must run under
the `gate` job's bare `pip install -e .` — i.e. **stdlib only**.

### 5.5 Sanctioned: register a new pytest marker

Append to `markers` at `pyproject.toml:30`. Required before the marker can be used at all
(I51).

### 5.6 Sanctioned: add an artifact store with a tracked README

Follow the `results/*` + `!results/README.md` pattern at `.gitignore:15-22`, and add the
directory to `SPEC_DIRECTORIES` so its absence is a test failure rather than a silent gap.

### 5.7 NOT an extension point: `RESEARCH_PREFIX`

`RESEARCH_PREFIX = "pocketsec/stage2/research/"` (`tests/test_repository_structure.py:73`)
is a single literal string covering one directory. `pocketsec/stage3/research/`,
`pocketsec/stage6/research/` and so on are **not** exempt — they are runtime modules by
I6's definition and a numpy import in any of them fails
`test_runtime_has_no_third_party_imports`. Widening this prefix is a change to the
ADR-0008 dependency boundary and requires an ADR, not a test edit. `planning/MEMORY.md`
states the boundary as "Everything else stays stdlib-only and may NEVER import research."

### 5.8 NOT an extension point: the frozen contracts and their tests

`tests/test_contracts.py` and `tests/test_authority_boundary.py` encode
`pocketsec.security_event_sequence.v1` @ 1.0.0 and `pocketsec.threat_prediction.v1` @
1.0.0. Per the repository's own rule (README, "Contributing rules that are not
negotiable", item 4: "Do not weaken a contract to make a test pass"), a later stage extends
the ontology through `SecurityEventV1.attributes` and nowhere else. I15 makes a version
bump in place impossible: a breaking change needs a new schema id.

### 5.9 NOT an extension point: gate check counts

`len(report.checks) == 9` (`tests/test_harness_and_gate.py:258`, `:269`) and
`len(report.checks) == 13` (`tests/test_stage1_pipeline.py:225`) are exact. Adding a check
to an already-passed gate means editing a closed stage's test, which is a stage-reopening
decision. A new stage gets its own gate module, its own `run_gate()`, and its own count
assertion.

### 5.10 NOT an extension point: relaxing tool configuration

`strict = true` with `files = ["pocketsec", "tests"]` (`pyproject.toml:41-42`) means new
test code is strictly type-checked. The existing suite pays for this with explicit
`# type: ignore[...]` comments at known points (`tests/conftest.py:42`,
`tests/test_authority_boundary.py:89`/`:111`/`:115`,
`tests/test_stage1_bounded.py:348`/`:350`/`:365`/`:503`,
`tests/test_stage2_dtl_conv.py:28`/`:35`/`:39`, and others). Add an ignore comment at the
narrowest site; do not add per-module mypy overrides.

---

## 6. Traps

### Trap 1 — numpy is required by the test suite but declared nowhere. The CI `test` job as written cannot pass.

Measured facts: `grep -n numpy pyproject.toml` → no match. `project.dependencies = []`
(`pyproject.toml:15`); `dev = ["pytest>=8", "ruff>=0.6", "mypy>=1.11"]`
(`pyproject.toml:18`). `.github/workflows/ci.yml:31` installs exactly `-e ".[dev]"` and
`:43` then runs `pytest -q` — with no `-m "not slow"` and no numpy install step.
`tests/test_stage2_foundation.py:10` and `tests/test_stage2_dtl_conv.py:10` both do
`import numpy as np` at module scope, and `tests/test_stage2_sleeping_brain.py:14` imports
`pocketsec.stage2.research.baselines`, which imports numpy at `baselines.py:21`.

Measured by making numpy unimportable (a shim `numpy.py` that raises `ImportError`, put on
`PYTHONPATH`):

```
ERROR tests/test_stage2_dtl_conv.py
ERROR tests/test_stage2_foundation.py
ERROR tests/test_stage2_sleeping_brain.py
!!!!!!!!!!!!!!!!!!! Interrupted: 3 errors during collection !!!!!!!!!!!!!!!!!!!
```
exit code **2**, and **zero tests run** — `--strict-markers`-style collection interruption
means the other 10 modules never execute either.

The `gate` job is unaffected: with numpy blocked, `stage0 cli gate`, `stage1 cli gate` and
`stage1 cli adversarial` all exited 0 (measured). So the gate is genuinely stdlib-only, and
the defect is confined to the `test` job's dependency list.

An implementer who "fixes" this by adding numpy to `project.dependencies` breaks ADR-0001
and fails `test_pyproject_declares_no_runtime_dependencies`
(`tests/test_repository_structure.py:141`), which greps for the literal string
`dependencies = []`. The shape that satisfies both is a separate optional-dependency group
(for example a `research` extra) installed only in the `test` job. **This document does not
claim CI has ever been observed failing** — no CI run was inspected. It states the
mechanism, which was reproduced locally.

### Trap 2 — the local environment is Python 3.14.7; CI tests 3.11/3.12/3.13 and gates on 3.12.

`requires-python = ">=3.11"` (`pyproject.toml:10`), matrix
`["3.11", "3.12", "3.13"]` (`ci.yml:15`), gate job pinned `"3.12"` (`ci.yml:55`),
`[tool.mypy] python_version = "3.11"` (`pyproject.toml:40`), `[tool.ruff] target-version =
"py311"` (`pyproject.toml:34`). Measured local interpreter: **Python 3.14.7**. A green
local run therefore proves nothing about 3.11, and 3.14-only syntax or stdlib behaviour
would pass locally and fail everywhere in CI. Conversely, `sys.stdlib_module_names` — which
I6 uses as its allowlist at `tests/test_repository_structure.py:123` — **differs between
interpreter versions**, so a module that is stdlib on 3.14 and not on 3.11 makes
`test_runtime_has_no_third_party_imports` pass locally and fail on the oldest matrix leg.

### Trap 3 — `REPO_ROOT.glob("*/*.py")` is exactly one level deep.

`test_no_importable_module_lives_outside_the_package`
(`tests/test_repository_structure.py:62-69`) catches `runtime/foo.py` but **not**
`runtime/hub/foo.py`. ADR-0002 is only partially enforced. A later stage that puts code
under a nested path inside `runtime/` or `training/` gets no test failure and a silently
violated ADR. If you rely on this test to police ADR-0002 for your stage, it will not.

### Trap 4 — `test_research_package_is_the_only_numpy_user` does not check exclusivity.

Despite the name, `tests/test_repository_structure.py:111-118` asserts only
`assert using_numpy` — that *at least one* research module contains the substring
`import numpy`. The exclusivity half is carried entirely by
`test_runtime_has_no_third_party_imports` (I6), and only as a side effect of numpy not
being in `sys.stdlib_module_names`. Also note this test uses a **substring match on file
text**, not `ast`: a research module whose docstring mentions `import numpy` satisfies it
without importing anything. Do not treat this test as the boundary's enforcement.

### Trap 5 — the numpy exemption path is hard-coded twice, independently.

`RESEARCH_PREFIX = "pocketsec/stage2/research/"` (`:73`, consumed by `_runtime_modules` at
`:81`) and the literal path inside `_research_modules` at `:86`
(`REPO_ROOT / "pocketsec" / "stage2" / "research"`). Changing one without the other yields
a module that is excluded from the runtime check but not included in the research check, or
the reverse — an import boundary with a hole and no failing test.

### Trap 6 — `tests/` is not covered by the stdlib-only rule, and mypy strict does cover it.

`_runtime_modules()` globs `REPO_ROOT / "pocketsec"` only (`:80`), so test modules may
import numpy freely — which is why `tests/test_stage2_foundation.py:10` is legal. But
`[tool.mypy] files = ["pocketsec", "tests"]` with `strict = true` (`pyproject.toml:41-42`)
and `ruff check pocketsec tests` (`ci.yml:34`) both cover `tests/`. So a new test module
faces strict typing and the full ruff ruleset (`E`, `F`, `I`, `B`, `UP`, `SIM`, `RUF`) at a
100-column limit — while the existing suite's compliance with those two tools is
**UNVERIFIED** here, because neither binary is installed on this machine.

### Trap 7 — `from conftest import ...` is not an ordinary import and breaks under some invocations.

It works because `tests/` has no `__init__.py`, so pytest's `prepend` import mode puts
`tests/` on `sys.path`. Consequences an implementer hits: (a) running a test module
directly with `python tests/test_contracts.py` fails on the `conftest` import; (b)
switching pytest to `importmode=importlib` or adding `tests/__init__.py` breaks all three
importing modules at once; (c) a second `conftest.py` in a subdirectory of `tests/` would
shadow nothing but would not be importable under the bare name `conftest`. Keep new
modules flat in `tests/` and keep the `from conftest import ...` form.

### Trap 8 — Stage 1 pipeline state carries across scenarios, and test helpers differ in whether they share one.

`planning/MEMORY.md` records this as a corpus trap that produced a real wrong answer: "Stage
1 carries lineage state ACROSS scenarios on a shared pipeline. Any corpus reusing process
identities between sessions silently erases its own signal."

In the suite the two patterns sit side by side. `tests/test_stage1_bounded.py:503` `_run`
constructs a **fresh** `Stage1Pipeline()` on every call. `tests/test_stage1_guillotine.py:28`
`_compile` constructs **one** pipeline and feeds a whole corpus through it with
`offset=index`. `tests/test_stage1_pipeline.py:75` `test_two_sensor_paths_produce_identical_semantics`
deliberately uses two separate pipelines so the eBPF run cannot warm the auditd run.
`tests/test_stage2_foundation.py:180` (`test_a_shared_pipeline_would_change_features`) exists
purely to prove that sharing a pipeline **does** change the encoded features, guarding
`test_dataset_build_is_independent_of_call_order` at `:166`.

A later-stage implementer who reuses a pipeline across what should be independent samples
gets no error, no warning, and features that encode "I have seen this before". The only
symptom is a quietly better score.

### Trap 9 — module-scoped fixtures cache trained models; `-p no:randomly`-style reordering or splitting files changes what gets trained.

`tests/test_stage2_foundation.py:286` `trained`, `tests/test_stage2_dtl_conv.py:27` `splits`
and `:172` `ambiguous`, and `tests/test_stage1_guillotine.py:38` `splits` are all
`scope="module"`. Moving a test to another file silently gives it a *fresh* fixture — a
newly trained model, a newly compiled corpus — and therefore possibly a different number.
Conversely, adding a test to an existing module makes it share an already-trained model
with whatever tests ran before it in that module. Neither change produces an error.

### Trap 10 — `Stage1GateContext.build()` is not cached and is called repeatedly.

Measured: one `Stage1GateContext.build()` takes **0.23 s**, and
`grep -c "Stage1GateContext.build()" tests/test_stage1_pipeline.py` reports **5** direct
call sites, plus every test that calls `_slots()` (`tests/test_stage1_pipeline.py:153`)
builds another. There is no `lru_cache` in `pocketsec/stage1/gate.py` (measured: no `cache`
match in the file). The class docstring at `pocketsec/stage1/gate.py:56` says it exists "so
thirteen checks do not replay the corpus thirteen times" — that saving applies *within* one
`run_gate()` call, not across tests. A Stage 3+ gate that follows this pattern should expect
the same per-test cost, and should not assume `build()` is memoised.

### Trap 11 — `_score` collapses "not computable" into `0.0`.

`tests/test_stage2_dtl_conv.py:36` is
`return average_precision(list(test.labels), model.predict_scores(test)) or 0.0`.
`average_precision` returns `None` when there are no positives
(`test_average_precision_is_none_without_positives`,
`tests/test_security_metrics.py:49`), and a genuine AP of `0.0` is also falsy. So an
unbuildable metric and a measured zero are indistinguishable downstream. This directly
contradicts I16/ADR-0004 ("None means 'not computable', never 'scored zero'") inside a test
helper. Do not copy this idiom into a new module; write `score = average_precision(...)`
then `assert score is not None` first, as `tests/test_stage2_foundation.py:313-314` and
`tests/test_stage1_guillotine.py:181-182` correctly do.

### Trap 12 — several tests assert the *current measured state*, not a desired property. Making the system better makes them fail.

`test_ambiguous_corpus_is_currently_saturated` (`tests/test_stage2_dtl_conv.py:198`)
asserts `TCN ≥ 0.95` and its docstring says: "If someone makes the corpus harder, it will
fail — and that is the intent: the failure is a prompt to update PROGRESS.md and re-run the
component ablations, not a regression." Similarly
`test_lineage_pooling_adds_nothing_because_stage1_already_attributes` (`:277`) pins a
**retracted** result, `test_dtl_is_dominated_on_cost_at_equal_quality`
(`tests/test_stage2_sleeping_brain.py:52`) pins ADR-0010's verdict, and
`test_novelty_slot_fires_on_novel_benign_work` (`tests/test_stage1_pipeline.py:203`)
asserts that a pure-novelty detector **does** produce false positives. Read the docstring
before "fixing" any of these; the correct response to a failure is usually an ADR and a
PROGRESS.md update, not a changed assertion.

### Trap 13 — `test_guillotine_reports_its_own_degeneracy` is conditional, so it can pass while measuring nothing.

`tests/test_stage1_pipeline.py:277-279` wraps its strongest assertions in
`if held_out.degenerate:`. On a corpus where the frontier is not degenerate, that branch
never executes and the test passes having checked only `held_out` and a non-empty caveat.
Do not cite this test as evidence that degeneracy reporting works.

### Trap 14 — two different `_prediction` helpers, two different `CORPUS` constants, two different `splits` fixtures.

`_prediction` at `tests/test_contracts.py:159` takes `**overrides` only; `_prediction` at
`tests/test_security_metrics.py:120` takes `(verdict, confidence, **kwargs)` and hard-wires
`uncertainty=0.0`. `CORPUS` is `140` in `tests/test_stage1_guillotine.py:25` and `90` in
`tests/test_stage2_dtl_conv.py:23`. A fixture named `splits` exists in both
`tests/test_stage1_guillotine.py:39` (a tuple of `ScenarioResult` lists from the hard
corpus) and `tests/test_stage2_dtl_conv.py:28` (a tuple of Stage 2 datasets from the
`"long"` corpus). Copy-pasting a test between modules gets you the wrong one with no error.

### Trap 15 — `make_sequence(**kwargs)` is untyped passthrough.

`tests/conftest.py:32` declares `**kwargs: object` and forwards it with
`# type: ignore[arg-type]` (`:42`). A misspelled keyword surfaces as a `TypeError` from
`SecurityEventSequenceV1`, pointing at the contract rather than at the caller, and mypy
will not catch it. Also note `make_event` derives `observed_at_ns` and `monotonic_ns` from
`index`, so `make_sequence(("a.b", "c.d"))` produces strictly increasing monotonic
timestamps — building a sequence with out-of-order events requires constructing
`SecurityEventV1` directly, as `tests/test_contracts.py:111-114` does.

### Trap 16 — the pytest process' RSS is not the endpoint budget.

Measured: the `-m "not slow"` run peaked at **540776 KB max RSS** (~528 MB) in the pytest
process. `planning/MEMORY.md` records the Stage 1 endpoint measurement as **24.6 MB peak
RSS against the 100 MB Edge target**, measured through `ResourceSampler` around the
pipeline only. Never quote a pytest-process figure as a resource result; the sanctioned
path is `pocketsec.stage0.benchmark.resource_metrics.ResourceSampler` +
`profiles.check_profile`, and `test_unmeasured_target_is_not_a_met_target`
(`tests/test_harness_and_gate.py:181`) exists to stop an unmeasured target reading as met.

### Trap 17 — `results/` contents are git-ignored, so a result written there is invisible to a reviewer.

`.gitignore:15-16` ignore everything under `results/` except `README.md`. Measured:
`git check-ignore -v results/PS-S0-20260924-H0-frequency-baseline-0000.json` →
`.gitignore:15:results/*`, and nine such files currently sit there untracked. The tracked
ledger is `experiments/registry.jsonl`, which is tracked because **no rule ignores
`experiments/` at all** — the `.gitignore:14` comment calling it "the exception" is
misleading, since nothing under `experiments/` is excluded. A later stage that writes its
results only to `results/` and does not register them in the experiment ledger leaves
nothing behind in version control.

### Trap 18 — `mypy` is invoked bare in CI; passing paths changes what is checked.

`.github/workflows/ci.yml:37` is exactly `mypy`, which relies on
`[tool.mypy] files = ["pocketsec", "tests"]` (`pyproject.toml:42`). Running
`mypy pocketsec/stage3` locally checks a *different, smaller* set than CI does, and running
`mypy some_file.py` silently drops the strict-mode coverage of everything else. Reproduce
CI by running `mypy` with no arguments from the repository root.

### Trap 19 — `--strict-markers` turns a marker typo into zero tests run.

Because a collection error interrupts the session (`Interrupted: 1 error during
collection`, measured in §3.4), a single `@pytest.mark.slwo` in a new module prevents the
**entire** suite from running, not just that module. The only registered marker is `slow`
(`pyproject.toml:30`).

### Trap 20 — the `slow` marker is not skipped by default.

`addopts` is `"-q --strict-markers"` (`pyproject.toml:29`) — there is no `-m "not slow"` —
and `ci.yml:43` runs plain `pytest -q`. So the nine model-training tests run on every push,
on all three matrix legs. Measured cost of those nine alone on this machine: **204.05 s**.
Adding a `@pytest.mark.slow` test makes every CI run longer; it does not opt out of
anything.

### Trap 21 — `PYTHONHASHSEED` is set in CI but not by the test suite itself.

`.github/workflows/ci.yml:41-42` and the four gate steps set `PYTHONHASHSEED: "0"`, with the
comment "Fixed so hash-ordered iteration is reproducible across runs." Nothing inside
`tests/` or `pyproject.toml` sets it, and no test asserts it is set. A local run without it
can produce a different iteration order in any code that walks a `set` or `frozenset` of
strings — and `frozenset` sits in the middle of the causal-signature API
(`tests/test_stage1_bounded.py:327-367`). Always export `PYTHONHASHSEED=0` locally, as
`README.md` does in its quick start.

### Trap 22 — `_detection_score` and `_stub_sequence` are private symbols imported directly by tests.

`tests/test_security_metrics.py:7` imports `_detection_score` from
`pocketsec.stage0.benchmark.harness`, and `tests/test_stage1_pipeline.py:12` imports
`_stub_sequence` from `pocketsec.stage1.gate`
(defined `_stub_sequence(sequence_id: str)` at `pocketsec/stage1/gate.py:516`). Likewise
`tests/test_stage1_guillotine.py:129` and `:146` import `_timing_pair` and `_novelty_pair`
from `pocketsec.stage1.labs.hard_corpus`, and `tests/test_stage2_dtl_conv.py:143` calls
`DTLConvModel._dilated_windows`. Renaming any underscore-prefixed function in those modules
breaks tests even though nothing public changed. Grep `tests/` before renaming a private
helper in `pocketsec/`.

---

## 7. What this document does not claim

- **No CI run was observed.** Every statement about `.github/workflows/ci.yml` is read from
  the file. The numpy consequence in Trap 1 was reproduced locally by making numpy
  unimportable, not by watching CI.
- **Ruff and mypy status is UNVERIFIED.** Neither is installed here (`which ruff`, `which
  mypy` → not found), matching the "Known gap" in `planning/MEMORY.md`: "`ruff` and `mypy`
  are configured in `pyproject.toml` and wired into CI but have **never been run**."
  Nothing in this document should be read as a claim that the repository is lint-clean or
  type-clean.
- **All measurements are single-run, on one machine, on Python 3.14.7.** Wall times
  (116.71 s non-slow, 204.05 s slow, 0.23 s for one `Stage1GateContext.build()`) and the
  540776 KB max RSS are one observation each, not distributions.
- **Test counts are collection counts**, from `pytest --collect-only -q`, on this
  interpreter. A different Python version could change parametrization only if the
  parametrizing tuples changed, which they do not, but the number is stated as measured
  rather than derived.
