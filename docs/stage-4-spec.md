# Stage 4 — CBF + LUCID — implementation specification

- **Status:** the implementation contract for Wave 4. Binding on all eight work packages.
- **Date:** 2026-09-25
- **Architecture source of truth:** `docs/architecture/sources/stage-04-cbf-lucid.md`
- **Build contract:** `docs/architecture/stage-3-12-integration-plan.md` (layout §1.2, seams §3.2,
  trust topology §4, conventions §5)
- **Phase file:** `planning/PHASE_04_CLAUDE_CODE.md`
- **ADR block:** **0030–0039 only.** Verified free this session: `ls docs/adr/` returns
  `0000`–`0010`, `0020`–`0029`, `0113`–`0128`. Nothing in 0030–0039 is taken.
- **Gate check count:** **12** — fixed by integration plan §5.1, and §47 of the architecture
  document happens to contain exactly twelve bullets. One check per bullet. No thirteenth.

---

## 0. Measurement status of this document

Every `path:line` and every type name in §3 was read out of a `.py` file in this repository in the
session that wrote this document, and the imports were executed:

```
$ python3 - <<'PY'   # abridged; full script in §3.0
... from pocketsec.stage3.stage4_interface import CrystalHandoffV1, CRYSTAL_HANDOFF_V1_ID
PY
ALL IMPORTS OK
Verdict: ['BENIGN', 'SUSPICIOUS', 'MALICIOUS', 'UNKNOWN', 'UNIDENTIFIABLE', 'INSUFFICIENT_EVIDENCE']
NON_COMMITTAL: ['INSUFFICIENT_EVIDENCE', 'UNIDENTIFIABLE', 'UNKNOWN']
CrystalHandoffV1 fields: ['handoff_id', 'cells', 'assurance', 'boundary_keys', 'melt_history', 'encoder_version', 'interface_version']
DIMENSIONS: ['privilege', 'trust', 'credential', 'reachability', 'persistence', 'execution', 'modification', 'discovery', 'isolation']
MANDATORY_SIGNALS: ['authentication', 'boundary_crossing', 'credential_access', 'module_load', 'persistence_write', 'privilege_change']
SensorPath: ['auditd', 'ebpf', 'procfs', 'journald', 'lsm']
```

Host at the time of writing: Python 3.14.7, Linux 7.1.5+kali-amd64, `/proc/loadavg`
**1.88 3.29 5.15**. A second sample twenty minutes earlier read **3.04 4.47 6.11**. That spread on
an idle-looking host is the whole reason §6 forbids absolute timing claims.

**This document contains no performance, detection or resource number for Stage 4.** There is no
Stage 4 code yet; `find pocketsec/stage4 -type f` returns nothing. Numbers quoted from Stage 1, 2
and 3 are cited to `planning/MEMORY.md` / `planning/PROGRESS.md` and are explicitly marked *cited,
not measured here*. Wave 4 must produce its own, through `run_benchmark` and `ResourceSampler`, or
write `UNMEASURED`.

---

## 1. What Stage 4 is for, stated so no engineer mistakes it

Stage 4 exists to prevent **confident single-world storytelling**.

The system must be able to:

1. hold several competing explanations of the same telemetry at once;
2. know what it could not see;
3. know when the available evidence cannot identify a single answer;
4. go and gather the specific observation that would discriminate between the survivors.

Everything else in the architecture document is machinery in service of those four. If a mechanism
does not serve one of them and does not beat its simple control in §7, it is removed and the removal
gets an ADR.

Three consequences that change how this wave is built:

- **Naming a culprit is not the goal.** A system that always resolves to one world is not doing
  causal reasoning. `Verdict.UNIDENTIFIABLE` is a success state (§4, D4.8).
- **The typed claim graph is not documentation, it is the honesty mechanism.** Once
  OBS/DER/INF/CF/EXT/UNK separation is enforced by *construction*, "zero unsupported authoritative
  claims" becomes a graph walk instead of a promise (§4, D4.13; §6, G4.7/G4.8).
- **Stage 4 is an attachment, not a layer.** Stage 1–3 detection must keep working when Stage 4
  raises. That is an isolation property, it is a precondition for everything else, and it is built
  first (§4, D4.17; §5 package 2; §6, G4.11).

### 1.1 What Stage 4 will probably turn out to be worth, and why that is fine

Expect a negative or mixed result and plan the reporting for it now.

- Stage 2 rejected its own central thesis (ADR-0010: DTL reduces to a TCN) and returned **zero
  justified learned mechanisms across thirteen rows** — cited, not measured here.
- Stage 3's own spec (`docs/stage-3-spec.md` §6.1, ADR-0021) says plainly that its cell format may
  cost more than the rule it wraps, and that this is a result rather than a failure.
- Stage 4's multi-world machinery faces the same bar against a single-world MAP control (§7, B1).
  On synthetic data authored by this wave, B1 may well win.

If competing worlds do not beat single-world MAP on the measured frontier, **ADR-0036 says so and
recommends removal**, and `docs/stage-4-findings.md` leads with it. That is the required outcome,
not the fallback.

---

## 2. Repository rules this wave operates under

### 2.1 Layout — fixed by integration plan §1.2, extended here

The plan's skeleton for Stage 4 is:

```
stage4/{worlds/{world.py,field.py,lifecycle.py},
        visibility/{model.py,sensor_shadow.py},
        tension/evidence_tension.py,
        counterfactual/{intervention.py,stress.py},
        identifiability/{resolution.py,horizon.py},
        claims/{typed_claim.py,graph.py,compiler.py},
        sensing/active_plan.py,
        slot.py, labs/{ambiguous_incidents.py,dropped_telemetry.py}}
```

It does not name modules for six components the architecture document requires (sequential
evidence §31, calibration §32, self-questioning §24, sparse world graph §28, entropy budget §29,
Stage 3 feedback §27, the verbalizer guard §34, the incident future cone §15, or the LUCID loop
itself §35). This specification extends the skeleton; it does not contradict it. Full layout:

```
pocketsec/stage4/
    __init__.py                      # INTEGRATOR — lazy public surface, following stage3/__init__.py
    core_ids.py                      # CBF-F01..CBF-F20            [foundation]
    theory.py                        # measurable definitions       [foundation]
    resources.py                     # STAGE4_BUDGET + measurement  [runtime]
    slot.py                          # CBFSlot(ModelSlot)           [optionality]
    stage5_interface.py              # CBFResolutionV1 (plain JSON) [runtime]
    gate.py  gate_criteria.py  cli.py            # INTEGRATOR
    worlds/     world.py field.py                [foundation]
                lifecycle.py tombstone.py        [lifecycle]
    claims/     typed_claim.py graph.py compiler.py verbalizer.py   [claims]
    visibility/ model.py sensor_shadow.py        [visibility]
    tension/    evidence_tension.py negative_evidence.py            [visibility]
    counterfactual/ intervention.py stress.py questions.py          [counterfactual]
    cones/      incident_cone.py                 [counterfactual]
    identifiability/ resolution.py horizon.py    [resolution]
    evidence/   sequential.py calibration.py     [resolution]
    sensing/    active_plan.py simulate.py       [resolution]
    graph/      sparse_world_graph.py entropy_budget.py             [lifecycle]
    engine/     degradation.py integrator.py     [optionality]
                lucid.py                         [runtime]
    crystal/    handoff.py                       [optionality]
                feedback.py                      [runtime]
    labs/       incident_corpus.py               [foundation]
                dropped_telemetry.py             [visibility]
                nonidentifiable.py               [resolution]
                baselines.py experiments.py      [runtime]
```

Notes that are not optional:

- `labs/ambiguous_incidents.py` from the plan is named **`labs/incident_corpus.py`** here, because
  it builds three corpora (ambiguous, non-identifiable, flood) and the plan's name describes one.
- Every `<subsystem>/__init__.py` stays **empty**. Consumers import the leaf module.
- **`pocketsec/stage4/{causal,cbf,lucid}/` exist today and are empty.** `find pocketsec/stage4
  -type f` returns nothing. Under ADR-0121 an empty package directory is a defect: importable by
  accident as a namespace package and invisible to every structural test. The integrator deletes
  all three, and `tests/test_stage4_boundary.py` forbids their return by name, exactly as
  `tests/test_stage3_boundary.py:38` does for `compiler/`. `worlds/` survives because the plan
  assigns it modules.

### 2.2 Stage 4 ships **no** `research/` package and **no** numpy — ADR-0030

Integration plan §2.4 closes the list of stages that may have `research/` and Stage 4 is **not on
it**, with the reason given: "bounded-K world enumeration is combinatorial, not numerical; must run
on the endpoint". The generalised `RESEARCH_PREFIXES` tuple that ADR-0011 was pre-assigned to
create **was never written** — `tests/test_repository_structure.py:73` still reads
`RESEARCH_PREFIX = "pocketsec/stage2/research/"`. Stage 3 faced the identical situation and
resolved it with ADR-0020.

**Decision (ADR-0030): Stage 4 is stdlib-only end to end.** No `pocketsec/stage4/research/`, no
numpy, no third-party import anywhere, including in tests. Consequences an engineer will feel:

- Any probability, entropy, divergence or forward-algorithm arithmetic is written in pure Python
  over `float`, with `math` and `statistics` only. The baselines in §7 were chosen so that this is
  possible: a 2-state HMM forward pass and a categorical Jensen–Shannon over ≤16 worlds are a few
  dozen lines each.
- The tiny GNN and DBN baselines the architecture's §42 lists **cannot be built** and are declared
  UNMEASURED with this reason in §7 and in the honesty ledger. Fabricating a stdlib stand-in and
  calling it a GNN would be worse than the gap.
- A gate is a runtime module and the CI `gate` job runs a bare `pip install -e .`
  (integration plan §5.1). `pocketsec/stage4/gate.py` therefore cannot import numpy even lazily
  inside a function — `tests/test_repository_structure.py` walks the AST and catches deferred
  imports (`MEMORY.md`, "Architecture rule discovered this wave").

### 2.3 Hard mechanical constraints

| Constraint | Where it bites |
|---|---|
| Python ≥ 3.11, `from __future__ import annotations` in every module | all |
| Files < ~800 lines, functions < ~50 lines, explicit `__all__`, module docstring saying what the module is FOR | all |
| `[tool.mypy] strict = true` over `pocketsec` **and** `tests` (`pyproject.toml:41-42`); `ruff` `select = ["E","F","I","B","UP","SIM","RUF"]` at 100 columns | all. Neither has ever been run in this repo (`MEMORY.md`, "Known gap") — status UNVERIFIED, unchanged by this wave unless it installs them |
| `print()` only in `cli.py` (`tests/test_repository_structure.py:152`) | all |
| Contracts frozen: do not edit `contracts/*.schema.json`, `pocketsec/stage0/contracts/`, or Stage 1 contract types | all |
| New wire schema ids register through `register_schema` (`stage0/contracts/common.py:49`) | `worlds/world.py`, `claims/typed_claim.py`, `stage5_interface.py`, `crystal/feedback.py`, `core_ids.py` |
| **No dataclass field name anywhere in Stage 4 may contain** `action`, `remediation`, `execute`, `command`, `shell`, `kill`, `quarantine`, `block`, `authorize`, `authorization`, `privilege`, `sudo` (`FORBIDDEN_AUTHORITY_FIELDS`, `threat_prediction_v1.py:48`; trust rule T5) | **This bites Stage 4 harder than any other stage.** The architecture's own §9 writes `do(block privilege transition)`. Both words are forbidden. See §2.4 |
| A new pytest marker must be appended to `markers` (`pyproject.toml:30`) before use; `--strict-markers` turns a typo into zero tests run | `tests/test_stage4_*.py` |
| `tests/test_repository_structure.py` is **not to be edited** — another wave may be in it. Stage 4's boundary rules live in `tests/test_stage4_boundary.py` | `foundation` |

### 2.4 The authority-field trap, spelled out

`Privilege` is one of the nine Stage 1 lattice dimensions and `privilege` is one of the nine keys
in `DIMENSIONS`. Reading a *value* out of that mapping is fine. **Naming a Stage 4 dataclass field
`privilege_*` is a T5 violation.** So is `block_*`, `kill_*` and `quarantine_*`.

Required renamings, fixed here so eight engineers do not invent eight of them:

| architecture wording | forbidden field name | **use this** |
|---|---|---|
| `do(block privilege transition)` | `block_privilege_transition` | `InterventionKind.SUPPRESS_ESCALATION`, field `suppressed_dimension: str` |
| "privilege/risk cost" of a sensor action (§16) | `privilege_cost` | `authority_risk_units: float` |
| "quarantined incident state" (§45) | `quarantine_state` | `isolated_state` / `IsolationOutcome` |
| "recommended action" for Stage 5 | any `action`/`remediation` field | `information_gaps: tuple[InformationGap, ...]` — a gap is a question, not an instruction |

Each Stage 4 dataclass that crosses a seam calls a local `authority_named_fields(cls)` helper over
`__dataclass_fields__` in `__post_init__`, the way `KnowledgeCellV1` does. **Stage 4 implements its
own helper in `worlds/world.py`; it does not import Stage 3's.** See §2.5.

### 2.5 Stage 4 imports nothing from `pocketsec.stage3`

`pocketsec/stage3/stage4_interface.py:1-20` states the intent of the Stage 3→4 seam in its own
docstring: "too strict and a legitimate cell cannot cross, too loose and Stage 4 grows an import of
this package". Stage 3 already shipped that seam as **plain JSON** (`CrystalHandoffV1.to_dict()`
refuses to emit any payload whose keys name a Stage 3 class, and `write_crystal_handoff` returns a
`sha256:` digest of canonical bytes).

**Decision:** Stage 4's only contact with Stage 3 is `pocketsec/stage4/crystal/handoff.py`, which
parses that JSON file. Zero `import pocketsec.stage3` anywhere under `pocketsec/stage4/`, asserted
by AST in `tests/test_stage4_boundary.py`. This is stronger than the integration plan §3.2 wording
("Consumes … `KnowledgeCellV1`") and it is deliberate: Stage 3 may be redesigned (ADR-0021 is live),
and a JSON reader survives that where an import does not.

The reverse direction (D4.14, cell stress feedback) is also plain JSON: Stage 4 *writes*
`CellStressSignalV1` records; a later Stage 3 session reads them. No import in either direction.

### 2.6 Another wave may be building in this tree

`pocketsec/stage<other>/`, `tests/test_stage<other>_*.py` and `docs/stage-<other>-*.md` belong to
that wave. Never edit, revert or delete them. Never run `git checkout`, `git stash`, `git restore`,
`git clean` or `git commit`. When the full suite is run, failures in another stage's test files are
that wave's work in progress: report them and move on. Judge Stage 4 by `tests/test_stage4_*.py`
plus `python -m pocketsec.stage4.cli gate`.

### 2.7 A gate must never mutate the real experiment ledger

`experiments/registry.jsonl` is append-only and digest-chained, with no update or delete API
(`stage0/experiments/registry.py:138`, `:183`). It already carries four `PS-S3-*` rows
(`grep -c "PS-S3" experiments/registry.jsonl` → **4**, measured this session).

**Rule:** `pocketsec/stage4/gate.py` takes `registry_path: Path | None = None` and **reads** the
ledger only. Registration happens exclusively in a separate CLI subcommand
(`python -m pocketsec.stage4.cli register`) that the operator invokes deliberately. Every test that
needs a registry constructs `ExperimentRegistry(tmp_path / "registry.jsonl")` under a `tmp_path`
fixture. Running the test suite must leave `experiments/registry.jsonl` byte-identical;
`tests/test_stage4_runtime.py` asserts that with a digest taken before and after the gate runs.

### 2.8 Timing is contended on this host

A Stage 2 gate run at load average 23–67 reported 855.31/3040.63 µs/event for the same two passes
that read 122.48/647.23 at load 8–12 — a **7×** inflation (cited from `PROGRESS.md`, not measured
here). Therefore:

1. **The primary bound on reasoning cost is a deterministic work-unit counter, not milliseconds.**
   `EntropyBudget.max_reasoning_units` is the contract; `max_reasoning_ms` is advisory and
   observed-only. A wall-clock bound would be unreproducible on this host and would make G4.9 a
   coin flip.
2. Every timing figure is a **within-run ratio** between two paths measured in the same process,
   with `/proc/loadavg` recorded beside it.
3. No absolute microsecond figure is ever presented as a device measurement.

### 2.9 Hypothesis binding — no H10 is minted

Integration plan §5.2 pre-assigns H10 to Stage 4 via ADR-0012 — **which was never written**.
`pocketsec/stage0/hypotheses.py` holds H0–H8 only, `docs/prior-art/ledger.json` holds exactly
`['H0' … 'H8']` (measured this session), and `tests/test_harness_and_gate.py:241` asserts
`set(ledger.entries) == set(HYPOTHESES)`. Appending H10 fails the suite unless a ledger entry lands
in the same commit — in a Stage 0 file another wave may be editing.

Stage 3 hit this and took the honest route (`pocketsec/stage3/gate.py:119-124`: `STAGE3_HYPOTHESIS
= "H4"`). Stage 4 does the same:

```python
# pocketsec/stage4/gate.py
STAGE4_HYPOTHESIS = "H3"        # "Novelty-budgeted conditional compute"
STAGE4_SECONDARY = "H7"         # "Relational latent state" — the world representation
EXPERIMENT_ID = "PS-S4-20260925-H3-cbf-gate-0001"
```

H3 ("Test whether compute can scale with information novelty") is the honest existing binding for
active sensing and the entropy budget — the falsifiable, measurable half of Stage 4. `<NNNN>` is a
per-stage counter, so Stage 4 starts at `0001`.

---

## 3. The data seam

### 3.0 The verification script

Run before writing code; it is the proof that every type in §3.1 exists:

```python
from pocketsec.stage0.contracts.common import EvidenceRef, register_schema, ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import (
    ThreatPredictionV1, Verdict, ComputePath, NON_COMMITTAL_VERDICTS, FORBIDDEN_AUTHORITY_FIELDS)
from pocketsec.stage0.contracts.model_slot import ModelSlot, validate_slot
from pocketsec.stage0.gate import GateCheck, GateReport, REPO_ROOT
from pocketsec.stage1.ssir.transition import SSIRTransitionV1
from pocketsec.stage1.state.security_state import SecurityStateV1, StateDelta, DIMENSIONS
from pocketsec.stage1.state.potential import phi, delta_phi
from pocketsec.stage1.causal.memory import CausalMemory, CausalNode
from pocketsec.stage1.observation.policy import (
    AdaptiveObservationPolicy, AOPBudget, ObservationLevel, EscalationDecision, MANDATORY_SIGNALS)
from pocketsec.stage1.telemetry.raw_event_v1 import SensorPath
from pocketsec.stage1.pipeline import Stage1Pipeline, ScenarioResult
from pocketsec.stage1.labs.corpus import Behaviour, Scenario, build_corpus
from pocketsec.stage1.labs.ambiguous_corpus import build_ambiguous_corpus, AMBIGUOUS_VERSION
```

All fourteen import lines executed successfully this session.

### 3.1 Consumed from Stages 0–3 — every type below exists, cited `path:line`

**Stage 0 substrate.**

| Type / function | `path:line` | How Stage 4 uses it |
|---|---|---|
| `EvidenceRef(store, locator, digest)` — digest must match `^sha256:[0-9a-f]{64}$` | `stage0/contracts/common.py:125` | **The only** way an `ObservedClaim` may cite evidence. Raw evidence stays referenced, never inlined |
| `register_schema(schema_id, version) -> str` | `stage0/contracts/common.py:49` | five new Stage 4 schema ids |
| `ContractError` | `stage0/contracts/common.py:32` | every `__post_init__` refusal raises this, not `ValueError` |
| `require_identifier`, `require_finite_unit_interval`, `require_non_negative_int`, `digest_of_bytes`, `freeze_mapping` | `common.py:72`, `:84`, `:78`, `:116`, `:95` | field validation; reuse, do not re-implement |
| `Verdict` = `BENIGN SUSPICIOUS MALICIOUS UNKNOWN UNIDENTIFIABLE INSUFFICIENT_EVIDENCE` | `stage0/contracts/threat_prediction_v1.py:66` | **`UNIDENTIFIABLE` is Stage 4's non-identifiability output. Stage 4 defines no parallel enum** (ADR-0032) |
| `NON_COMMITTAL_VERDICTS` = {UNKNOWN, UNIDENTIFIABLE, INSUFFICIENT_EVIDENCE} | `:79` | `abstained=True` is legal only with one of these (`_validate_abstention`, `:187`) |
| `ComputePath` = `CHEAP_TRANSITION STATISTICAL LEARNED_SOLVER` | `:84` | `CBFSlot` emits `STATISTICAL`; `CHEAP_TRANSITION` only when a crystallised-cell row resolved the incident with no world branching |
| `ThreatPredictionV1(prediction_id, sequence_id, verdict, confidence, novelty_score, uncertainty, model_state_version, compute_path, compute_budget_units, state_identifier, calibration_id, abstained, evidence_relevance, next_event, schema_version)` | `:143` | what `CBFSlot.predict` returns. `calibration_id=None` means uncalibrated and **must stay `None`** until Stage 4 measures calibration (D4.10) |
| `EvidenceRelevance` | `:98` | the weighted pointers back from a resolution to evidence |
| `FORBIDDEN_AUTHORITY_FIELDS` (13 tokens) | `:48` | audited in `__post_init__`; see §2.4 |
| `ModelSlot` Protocol: `slot_name`, `model_state_version`, `input_schema`, `output_schema`, `predict(sequence) -> ThreatPredictionV1`; `validate_slot` | `stage0/contracts/model_slot.py:41`, `:57` | `CBFSlot` satisfies it. `NullModelSlot` (`:80`) is the precedent for honest degradation |
| `GateCheck(id, title, passed, detail)`, `GateReport(checks)` | `stage0/gate.py:45`, `:56` | the 12 checks |
| `run_benchmark(...)`, `BenchmarkCase`, `BenchmarkResult` | `stage0/benchmark/harness.py:133`, `:43`, `:92` | the **only** measurement path. `synthetic_data=True`, always, for every corpus in this repository |
| `SequenceDataset`, `LabelledSequence` | `stage0/benchmark/dataset.py:53`, `:36` | checksum-bound datasets |
| `ResourceSampler`, `ResourceMetrics` | `stage0/benchmark/resource_metrics.py:103`, `:58` | a resource figure from anywhere else is UNMEASURED |
| `check_profile`, `ProfileReport`, `PROFILES` | `stage0/benchmark/profiles.py:85`, `:62`, `:36` | `within_target is None` means unmeasured, never `True` |
| `SecurityMetrics`, `evaluate_scores` | `stage0/benchmark/security_metrics.py:178`, `:211` | a PR-AUC from anywhere else is UNMEASURED |
| `ExperimentRegistry.register`, `format_experiment_id` | `stage0/experiments/registry.py:138`, `stage0/experiments/ids.py:56` | §2.7: read in the gate, write only in the `register` subcommand |
| `PriorArtLedger.load`, `PriorArtEntry.novelty_claim_permitted` | `stage0/prior_art.py:76`, `:41` | G4.12 |
| `SeedSet` | `stage0/repro/seeds.py:24` | pinned seeds |

**Stage 1 substrate.**

| Type | `path:line` | How Stage 4 uses it |
|---|---|---|
| `SSIRTransitionV1` — fields `actor, relation, object, state_delta, uncertainty, novelty, causal_signature, parent_signature, responsibility, temporal, evidence, epoch_id, sequence, level, delta_phi, observation_incomplete, schema_version`; property `is_high_consequence` | `stage1/ssir/transition.py:82`, `:126` | **the atom of evidence.** One transition becomes one `ObservedClaim` plus zero or more `DerivedClaim`s. `observation_incomplete` is a direct input to the sensor shadow |
| `SecurityStateV1` (9 lattices), `.level()`, `.raised_to()`, `.delta_from()`, `.join()` | `stage1/state/security_state.py:122`, `:135`, `:141`, `:155`, `:165` | a world's `latent_state` is a `SecurityStateV1`; `join` is how a world composes the host view |
| `StateDelta`, `.dimensions`, `.magnitude`, `.bitmask()` | `:181`, `:198`, `:202`, `:206` | `bitmask()` keys the sparse world graph and the expected-evidence predicates |
| `DIMENSIONS` (9 keys, measured: `privilege trust credential reachability persistence execution modification discovery isolation`) | `:108` | the closed vocabulary a world's latent state and a claim's subject may reference |
| `phi(state) -> PhiBreakdown`, `delta_phi(prev, cur) -> float`, `PhiBreakdown`, `calibrate` | `stage1/state/potential.py:170`, `:195`, `:147`, `:237` | consequence weighting; the Φ-threshold playbook baseline (§7 B4) |
| `CausalMemory(capacity=512, l0_budget=64)`, `.record(...)`, `.spine(min_responsibility=0.01) -> tuple[CausalNode,...]`, `.responsibility(node)`, `.report()`, `.memory_bytes()` | `stage1/causal/memory.py:155`, `:187`, `:256`, `:246`, `:265`, `:180` | **worlds are hypotheses over the causal spine.** `spine()` is the candidate node set; Responsibility Flux perturbs it |
| `CausalNode(signature, parent_signature, sequence, relation, state_delta_mask, delta_phi, resolution, actor_identity, evidence_locators)`, `.demote()` | `:83`, `:99` | the graph node Stage 4 reasons over. Identity-free by construction |
| `causal_signature(...)`, `GENESIS_SIGNATURE`, `CausalResolution.L0_EXACT…L3_SIGNATURE` | `:47`, `:44`, `:73` | signatures are built from *semantics*, so renaming a binary does not change them — this is what makes §25's rename-invariance stress test meaningful |
| `AdaptiveObservationPolicy.consider(*, target, uncertainty, security_potential, causal_relevance, now_ns) -> EscalationDecision`; `.budget_score(...)`, `.record_observation(...)`, `.report()`, `.level_for()`, `.collects()`, `.is_mandatory()` | `stage1/observation/policy.py:215`, `:170`, `:278`, `:307`, `:195`, `:202`, `:199` | **the only observation planner.** D4.9 computes discrimination and consequence, then calls `consider()`. It never opens a sensor itself |
| `AOPBudget(max_concurrent=8, max_duration_ns=30e9, max_escalations_per_window=32, window_ns=60e9, max_extra_events_per_second=500, max_memory_bytes=262144, escalation_threshold=0.5)` | `:60` | Stage 4 respects these caps; it does not raise them |
| `EscalationDecision(target, level, budget_score, escalated, refused_reason)` | `:93` | the refusal string is recorded verbatim in the incident record |
| `ObservationLevel` = `BASELINE ELEVATED HIGH_RESOLUTION`; `MANDATORY_SIGNALS` (6, measured: `authentication boundary_crossing credential_access module_load persistence_write privilege_change`) | `:39`, `:47` | a mandatory signal is **always** observable: the visibility model must assign it `P(observe)=1.0` and the shadow may never mark it blind |
| `SensorPath` = `auditd ebpf procfs journald lsm` | `stage1/telemetry/raw_event_v1.py:41` | the visibility model is keyed on `(signal, SensorPath)` |
| `RawEventV1`, `EvidenceEvent` | `:56`, `:142` | evidence lineage |
| `Stage1Pipeline(host_id, identity, novelty, causal, aggregation, observation)`, `.run_scenario(scenario, *, sensor=SensorPath.EBPF, offset=0) -> ScenarioResult`, `.report()` | `stage1/pipeline.py:78`, `:99`, `:196` | the corpus driver. **Reuse it; do not build a second pipeline** |
| `ScenarioResult(scenario, transitions, emitted, final_state, peak_phi, peak_novelty, peak_uncertainty, unresolved)` | `:47` | the incident input |
| `Behaviour(operation, fields)`, `Scenario(name, behaviours, label, technique, unseen_technique)`, `build_corpus(*, count, seed, split, include_unseen)` | `stage1/labs/corpus.py:34`, `:45`, `:220` | Stage 4 defines **no fifth scenario type** (integration plan §5.4) |
| `build_ambiguous_corpus`, `AMBIGUOUS_VERSION` (measured: `stage1-ambiguous-v0.1.0`) | `stage1/labs/ambiguous_corpus.py:268`, `:45` | the only non-saturated corpus in the repository; Stage 4's incident corpus is built on top of it |
| `NoveltyEngine`, `NoveltyTensor`; `CountMinSketch`, `StableBloomFilter`, `BoundedLRUCounter`, `EWMA` | `stage1/novelty/engine.py:103`, `:46`; `sketches.py:39`, `:97`, `:186`, `:244` | bounded counting primitives for the world graph. Novelty is **not** maliciousness: it feeds world *birth*, never world *support* |
| `EpochModel`, `Epoch`, `SystemIdentity`, `EpochDecision` | `stage1/epoch/model.py:136`, `:105`, `:55`, `:81` | calibration is epoch-conditioned (D4.10); epoch invalidation is a world-death cause (§13) |
| `run_adversarial_suite`, `AdversarialReport` | `stage1/labs/adversarial.py:322`, `:58` | the precedent for §25's stress suite shape |

**Stage 2 substrate** (read-only, and small — ADR-0010 rejected the core).

| Type | `path:line` | Use |
|---|---|---|
| `EncodedTransition`, `encode_ssir_transition`, `FEATURE_LAYOUT`, `ENCODER_VERSION` | `stage2/encoder/ssir_encoder.py:143`, `:195`, `:94` | feature vector for the decision-tree playbook baseline only |
| `Stage2Sample`, `Stage2Dataset`, `build_dataset`, `.base_rate` | `stage2/dataset.py:38`, `:72`, `:147`, `:101` | base-rate guard: every baseline must beat it or the comparison is refused |
| `imported_modules`, `research_imports` | `stage2/gate_criteria.py` | the shared import resolver. **Import it, do not copy it** — S2-AUTH-01 was a hole that existed in two copies and was closed in neither |
| `build_drift_corpus`, `DRIFT_VERSION` (`stage2-drift-v0.1.0`) | `stage2/labs/drift_corpus.py:82` | the epoch-change variants §39 asks for |
| **Not consumed:** Behaviour Atoms, transition lattice, Future Cones, the counterfactual twin, the Need router, the surprise vector | — | ADR-0010, ADR-0115, ADR-0116, ADR-0122. Stage 4's incident future cone (D4.7) is built from world mechanisms over `CausalNode`s, **not** from `stage2/predictors/future_cone.py`, which is default-off and measured worse than its control |

**Stage 3 substrate — JSON only.** Quoted from `pocketsec/stage3/stage4_interface.py`:

```python
CRYSTAL_HANDOFF_V1_ID = "pocketsec.crystal_handoff.v1"           # :52

@dataclass(frozen=True, slots=True)
class CrystalHandoffV1:                                          # :157
    handoff_id: str
    cells: tuple[Mapping[str, Any], ...]
    assurance: tuple[Mapping[str, Any], ...]
    boundary_keys: tuple[Mapping[str, Any], ...]     # rows of {cell_id, relation_family,
    melt_history: tuple[Mapping[str, Any], ...]      #          actor_property_mask, state_delta_mask}
    encoder_version: str
    interface_version: str = CRYSTAL_HANDOFF_V1_VERSION

def write_crystal_handoff(handoff: CrystalHandoffV1, path: Path) -> str:   # :271
    """Write canonical JSON and return its ``sha256:`` digest."""
```

Field list confirmed by `CrystalHandoffV1.__dataclass_fields__` this session. `melt_history` is part
of the seam on purpose: Stage 4 must distinguish "never crystallised" from "crystallised then
melted", because those route differently.

### 3.2 Exposed to Stage 5

Trust rule **T1** permits `pocketsec/stage5/` to import `pocketsec.stage4`, and integration plan
§3.2 requires Stage 5 to consume `IncidentHypothesis`, `TypedClaim`, `ClaimGraph` and
`SecurityWorldV1` as types. Stage 4 therefore exposes both:

1. **Typed objects**, importable by Stage 5 from their leaf modules — the eleven names the plan
   assigns, all defined in §4.
2. **`CBFResolutionV1`** (`stage4/stage5_interface.py`) — a plain-JSON resolution object with a
   canonical digest, mirroring Stage 3's seam. This is what persists, what Stage 10 certifies and
   what Stage 11 reconstructs from. Architecture §49: Stage 5 "should not need to reinterpret raw
   logs".

Trust rule **T7** forbids `pocketsec/stage1/` and `pocketsec/stage2/` from importing
`pocketsec/stage4/`, which is how "Stage 4 remains optional" is made structural rather than
hopeful. `tests/test_stage4_boundary.py` asserts it for Stage 4's half.

---

## 4. Deliverables

The phase file has a **single generic checklist line** ("01. Implement and test the Stage 4
architecture components described in the source specification"), so the architecture document's §48
list is the only source of deliverables. **D4.1 – D4.16 map one-to-one onto its D4X.1 – D4X.16.**

Three deliverables are added because the acceptance gate (§47) and the dataset/failure-safety
sections (§39, §45) require components that §48 omits. They are numbered above 16 and their origin
is named, so nothing is silently invented and nothing is silently dropped:

| added | from | why it cannot be omitted |
|---|---|---|
| **D4.17** | §45 Failure-Safe Rules | gate criterion 11 ("Stage 4 remains optional … if it crashes") has no deliverable in §48 |
| **D4.18** | §39 Dataset Design | gate criteria 2, 3, 4, 5, 6 all require constructed corpora that §48 does not deliver |
| **D4.19** | §36 Core Functional IDs + §§5–33 definitions | the `core_ids.py` convention (integration plan §1.1) and G4.10's OPTIONAL-ablation enumeration need a typed id table |

Bounds named as `MAX_*` below are module constants, exported, and asserted in tests. Where the
architecture gives a range (§44: "K capped 4–16 normally"), the default is the low end and the
ceiling is explicit.

---

### D4.1 — Causal Belief Field formal specification `[foundation]`

```python
# pocketsec/stage4/theory.py
CBF_THEORY_VERSION: str          # "stage4-cbf-theory-v1.0.0"

@dataclass(frozen=True, slots=True)
class Definition:
    term: str                    # "evidence_tension", "sensor_shadow", "identifiable", ...
    architecture_section: str    # "§7", "§6", "§19" — traceability to the source document
    formula: str                 # the document's own expression, verbatim
    bound_to: str                # "pocketsec.stage4.tension.evidence_tension.EvidenceTension"
    measurable_as: str           # the exact function whose output realises it
    falsified_if: str            # the observation that would refute it

DEFINITIONS: tuple[Definition, ...]                  # >= 20, one per architecture construct
def definition(term: str) -> Definition: ...
def unbound_terms() -> tuple[str, ...]: ...          # every Definition whose bound_to does not import
```

`unbound_terms()` is the deliverable, not the table: it resolves each `bound_to` with
`importlib.import_module` + `getattr` and returns what is missing. G4.7's structural half asserts
it is empty. A definition table nobody can execute is prose.

**Bounds:** ≤ 40 definitions; module < 400 lines.

---

### D4.2 — LUCID update engine `[runtime]`

```python
# pocketsec/stage4/engine/lucid.py
MAX_UPDATE_STEPS_PER_TRANSITION: int = 16

@dataclass(frozen=True, slots=True)
class UpdateOutcome:
    field: CausalBeliefField
    spawned: tuple[str, ...]          # world_ids
    killed: tuple[tuple[str, str], ...]   # (world_id, cause)
    fissioned: tuple[tuple[str, tuple[str, str]], ...]
    fused: tuple[tuple[tuple[str, str], str], ...]
    truncations: tuple[Truncation, ...]
    work_units: int
    degraded: tuple[DegradationRecord, ...]

class LucidEngine:
    def __init__(self, *, config: LucidConfig, visibility: VisibilityModel,
                 observation: AdaptiveObservationPolicy | None = None,
                 cells: CrystalKnowledge | None = None) -> None: ...
    def open_incident(self, incident_id: str, epoch_id: int) -> CausalBeliefField: ...
    def update(self, field: CausalBeliefField, transition: SSIRTransitionV1,
               spine: tuple[CausalNode, ...]) -> UpdateOutcome: ...      # CBF-F01
    def resolve(self, field: CausalBeliefField) -> IncidentResolution: ...
    def close_incident(self, field: CausalBeliefField) -> CBFResolutionV1: ...

@dataclass(frozen=True, slots=True)
class LucidConfig:
    max_worlds: int = MAX_WORLDS                     # 8
    budget: EntropyBudget = ...
    enable_free_energy: bool = False                 # §18, default off until measured (ADR-0038)
    enable_sequential_evidence: bool = True
    enable_verbalizer: bool = False                  # §34, never required
    enable_active_sensing: bool = True
```

Every mechanism the architecture calls experimental is a **flag defaulting to off** until a measured
delta justifies it. Stage 2's lesson was the reverse: ADR-0116 said two mechanisms were "default
off" and no constant in the code said so, and the cone ran on every deep event while being
"removed" (`PROGRESS.md`, G2.6). A flag the engine does not honour is worse than no flag —
`tests/test_stage4_runtime.py` asserts each flag changes the `work_units` count.

`update()` is ordered and the order is part of the contract: integrate evidence → update visibility
and shadow → recompute tension → kill → fission → fuse → spawn → prune dominated → charge budget.
Spawn happens **after** kill so a spawn cannot be starved by worlds that were about to die.

**Bounds:** ≤ `MAX_UPDATE_STEPS_PER_TRANSITION` internal passes per transition; `update()` never
raises past the `engine/degradation.py` wrapper (D4.17); file < 600 lines.

---

### D4.3 — Sensor Visibility + Sensor Shadow model `[visibility]`

```python
# pocketsec/stage4/visibility/model.py
VISIBILITY_MODEL_V1_ID = "pocketsec.visibility_model.v1"

@dataclass(frozen=True, slots=True)
class VisibilityObservation:
    """One replay's worth of ground truth: the signal occurred; was it observed?"""
    signal: str                  # a MANDATORY_SIGNALS member or a corpus operation name
    sensor: SensorPath
    occurrences: int
    observations: int
    epoch_id: int

@dataclass(frozen=True, slots=True)
class VisibilityModel:
    """P(observe e | e occurred, A_t, V_t), fitted from replays — never defaulted."""
    rows: Mapping[tuple[str, str], VisibilityObservation]
    level: ObservationLevel = ObservationLevel.BASELINE
    dropped_paths: frozenset[SensorPath] = frozenset()

    def probability(self, signal: str, sensor: SensorPath) -> float | None: ...
    def is_mandatory(self, signal: str) -> bool: ...
    def with_dropped(self, sensor: SensorPath) -> VisibilityModel: ...
    def with_level(self, level: ObservationLevel) -> VisibilityModel: ...
    def coverage(self) -> float: ...          # fraction of (signal, sensor) pairs with evidence

def fit_visibility_model(observations: Sequence[VisibilityObservation]) -> VisibilityModel: ...
def measure_visibility(pipeline_factory: Callable[[], Stage1Pipeline],
                       scenarios: Sequence[Scenario],
                       sensors: Sequence[SensorPath]) -> tuple[VisibilityObservation, ...]:
    """Replay the same scenarios through each sensor path and count."""
```

**`probability()` returns `None` for a pair with no replay evidence, and every caller must handle
`None` as UNKNOWN.** There is no default of 0.5, no smoothing prior, no fallback. ADR-0004's lesson
("`None` never means zero") generalised: an unmeasured visibility is not a coin flip, and a
fabricated one would silently license the exact inference §5 exists to forbid.

`probability()` returns `1.0` for every member of `MANDATORY_SIGNALS`, because AOP may never
disable them (`policy.py:47`) — asserted, not assumed.

```python
# pocketsec/stage4/visibility/sensor_shadow.py
MAX_SHADOW_REGIONS: int = 32

@dataclass(frozen=True, slots=True)
class ShadowRegion:
    signal: str
    sensors_blind: tuple[SensorPath, ...]
    reason: str                  # "sensor_path_dropped" | "below_observation_level" |
                                 # "no_visibility_evidence" | "observation_incomplete"
    consequence_weight: float    # Φ weight of the dimensions this signal could have raised

@dataclass(frozen=True, slots=True)
class SensorShadow:
    """Shadow_t = PotentialSecurityEvidence - ObservableEvidence (§6)."""
    regions: tuple[ShadowRegion, ...]
    truncated: bool
    def confidence_penalty(self) -> float: ...          # in [0, 1]
    def covers(self, signal: str) -> bool: ...
    def to_dict(self) -> dict[str, Any]: ...

def estimate_sensor_shadow(model: VisibilityModel, *, expected: Sequence[str],
                           transitions: Sequence[SSIRTransitionV1]) -> SensorShadow: ...   # CBF-F06
```

`confidence_penalty()` is monotone in the shadow: adding a region can never lower the penalty, and
`tests/test_stage4_visibility.py` asserts monotonicity over 100 random region sets. **A dropped
sensor must produce reduced confidence, never a confident wrong answer** — that is the property, and
it is tested as an inequality on the resulting `ThreatPredictionV1.confidence`, not asserted in
prose.

**Bounds:** ≤ `MAX_SHADOW_REGIONS`, `truncated=True` when exceeded; visibility model ≤ 256 rows.

---

### D4.4 — Evidence Tension engine `[visibility]`

```python
# pocketsec/stage4/tension/evidence_tension.py
class TensionTerm(StrEnum):
    UNEXPECTED_OBSERVATION = "UNEXPECTED_OBSERVATION"
    MISSING_EXPECTED = "MISSING_EXPECTED"
    CAUSAL_INCONSISTENCY = "CAUSAL_INCONSISTENCY"
    TEMPORAL_INCONSISTENCY = "TEMPORAL_INCONSISTENCY"
    STATE_INCONSISTENCY = "STATE_INCONSISTENCY"
    VISIBILITY_ADJUSTED_CONTRADICTION = "VISIBILITY_ADJUSTED_CONTRADICTION"

TENSION_WEIGHTS: Mapping[TensionTerm, float]     # one per term, summing to 1.0
HARD_CONTRADICTION_TENSION: float = 1.0
TENSION_DEATH_THRESHOLD: float = 0.75
TENSION_SUSTAIN_STEPS: int = 3

@dataclass(frozen=True, slots=True)
class EvidenceTension:
    """Tension(W) (§7), always with its six terms attached — never a bare float."""
    terms: Mapping[TensionTerm, float]
    total: float
    hard_contradictions: tuple[str, ...]
    sustained_steps: int
    def is_fatal(self) -> bool: ...
    def to_dict(self) -> dict[str, Any]: ...

def calculate_evidence_tension(world: SecurityWorldV1, transition: SSIRTransitionV1,
                               *, shadow: SensorShadow, model: VisibilityModel,
                               history: EvidenceTension | None) -> EvidenceTension: ...  # CBF-F07
```

Returning the six terms beside the total is the same discipline as `PhiBreakdown`
(`potential.py:147`): a scalar with no reasoning attached cannot be audited, and Stage 1 already
learned to refuse them.

```python
# pocketsec/stage4/tension/negative_evidence.py
class NegativeEvidenceVerdict(StrEnum):
    INFORMATIVE_ABSENCE = "INFORMATIVE_ABSENCE"
    UNKNOWN_ABSENCE = "UNKNOWN_ABSENCE"
    NOT_EXPECTED = "NOT_EXPECTED"

MIN_INFORMATIVE_VISIBILITY: float = 0.9
MIN_PREDICTION_STRENGTH: float = 0.7

def classify_absence(*, signal: str, world: SecurityWorldV1, model: VisibilityModel,
                     observed: frozenset[str]) -> tuple[NegativeEvidenceVerdict, str]: ...
```

This is §8, the classic trap, as three lines of code: absence counts against a world **only** when
`model.probability(signal, sensor)` is not `None` **and** ≥ `MIN_INFORMATIVE_VISIBILITY` **and** the
world predicts the signal at ≥ `MIN_PREDICTION_STRENGTH`. Otherwise `UNKNOWN_ABSENCE`, and the
`MISSING_EXPECTED` term contributes **zero**. `tests/test_stage4_visibility.py` includes the
adversarial case: a world that would be killed by absence under full visibility must survive
unchanged when the relevant sensor is dropped.

**Bounds:** six terms exactly; `total ∈ [0, 1]` except `HARD_CONTRADICTION_TENSION`.

---

### D4.5 — World birth / death / fission / fusion `[lifecycle]`

```python
# pocketsec/stage4/worlds/lifecycle.py
MIN_RESIDUAL_FOR_BIRTH: float = 0.25
RESIDUAL_PERSISTENCE_STEPS: int = 2
MAX_FISSION_DEPTH: int = 2
FUSION_EQUIVALENCE_EPSILON: float = 0.05

class BirthRefusal(StrEnum):
    RESIDUAL_TOO_SMALL = "RESIDUAL_TOO_SMALL"
    NOT_PERSISTENT = "NOT_PERSISTENT"
    VISIBILITY_ARTIFACT = "VISIBILITY_ARTIFACT"
    EXPLAINED_BY_EXISTING = "EXPLAINED_BY_EXISTING"
    FIELD_AT_CAPACITY = "FIELD_AT_CAPACITY"
    NOT_SECURITY_RELEVANT = "NOT_SECURITY_RELEVANT"

class DeathCause(StrEnum):
    HARD_CONTRADICTION = "HARD_CONTRADICTION"
    SUSTAINED_TENSION = "SUSTAINED_TENSION"
    DOMINATED = "DOMINATED"
    EPOCH_INVALIDATION = "EPOCH_INVALIDATION"
    ASSURANCE_BELOW_THRESHOLD = "ASSURANCE_BELOW_THRESHOLD"
    BUDGET_TRUNCATION = "BUDGET_TRUNCATION"

@dataclass(frozen=True, slots=True)
class Residual:
    """Residual = ObservedEvidence - BestExplainedEvidence (§12)."""
    signals: frozenset[str]
    magnitude: float
    persistent_steps: int
    visibility_explained: bool
    consequence: float

def spawn_world(field, residual, *, shadow, epoch_id
               ) -> tuple[CausalBeliefField, str | None, BirthRefusal | None]: ...  # CBF-F02
def kill_world(field, world_id, cause: DeathCause, detail: str
              ) -> tuple[CausalBeliefField, WorldTombstone]: ...                    # CBF-F03
def fission_world(field, world_id, regimes: Sequence[EvidenceRegime]
                 ) -> tuple[CausalBeliefField, tuple[str, str] | None]: ...         # CBF-F04
def fuse_worlds(field, left_id, right_id) -> tuple[CausalBeliefField, str | None]: ...  # CBF-F05
def prune_dominated_worlds(field) -> tuple[CausalBeliefField, tuple[str, ...]]: ...  # CBF-F17

@dataclass(frozen=True, slots=True)
class DominanceTest:
    """§30: all five clauses, each reported separately so a pruning can be audited."""
    explains_critical_evidence: bool
    no_more_contradictions: bool
    no_more_unsupported_assumptions: bool
    within_representation_budget: bool
    no_unique_critical_future_lost: bool
    def dominates(self) -> bool: ...        # all five, and the fifth is a veto
```

The fifth clause is a hard veto and the reason dominance pruning is safe: if `W_b` predicts a
security-critical future no survivor predicts, `W_b` lives regardless of the other four. A pruning
that loses the only world predicting exfiltration has not reduced complexity, it has lost the
answer. `tests/test_stage4_lifecycle.py` constructs exactly that case.

```python
# pocketsec/stage4/worlds/tombstone.py
MAX_TOMBSTONES: int = 32

@dataclass(frozen=True, slots=True)
class WorldTombstone:
    world_id: str
    mechanism_id: str
    cause: DeathCause
    detail: str
    killed_at_sequence: int
    support_at_death: float
    reopenable: bool
    evidence_digests: tuple[str, ...]        # sha256 refs, so a world can be rebuilt

class TombstoneLedger:
    def record(self, stone: WorldTombstone) -> None: ...
    def oscillating(self, mechanism_id: str) -> bool: ...     # spawn→kill→spawn guard
    def reopen(self, mechanism_id: str) -> WorldTombstone | None: ...
    def memory_bytes(self) -> int: ...
```

**Bounds:** `MAX_TOMBSTONES` with oldest-lowest-consequence eviction; fission depth ≤
`MAX_FISSION_DEPTH`; a killed world's evidence digests are never deleted (project rule).

---

### D4.6 — Counterfactual Intervention + Responsibility Flux `[counterfactual]`

```python
# pocketsec/stage4/counterfactual/intervention.py
MAX_COUNTERFACTUALS_PER_INCIDENT: int = 32
MAX_INTERVENTION_DEPTH: int = 1              # bounded virtual intervention, §9

class InterventionKind(StrEnum):
    REMOVE_EVENT = "REMOVE_EVENT"                    # do(remove E17)
    REPLACE_ACTOR_CLASS = "REPLACE_ACTOR_CLASS"      # do(replace actor semantic class)
    SUPPRESS_ESCALATION = "SUPPRESS_ESCALATION"      # §9's do(block privilege transition) — renamed, §2.4
    REMOVE_NOVELTY = "REMOVE_NOVELTY"                # do(remove destination novelty)
    DELAY_STEP = "DELAY_STEP"                        # low-and-slow probe

@dataclass(frozen=True, slots=True)
class Intervention:
    kind: InterventionKind
    target_signature: str        # a CausalNode.signature — the real key space
    suppressed_dimension: str = ""    # a DIMENSIONS key, for SUPPRESS_ESCALATION
    replacement_class: str = ""       # a SemanticProperty value, for REPLACE_ACTOR_CLASS

@dataclass(frozen=True, slots=True)
class InterventionResult:
    intervention: Intervention
    support_shift: Mapping[str, float]       # world_id -> support delta
    outcome_shift: float                     # change in predicted consequence
    evidence_shift: float                    # JS divergence of predicted evidence distributions
    field_distance: float                    # JS divergence over the world support vector
    work_units: int

def counterfactual_intervene(field, intervention, *, spine) -> InterventionResult: ...   # CBF-F09

# pocketsec/stage4/counterfactual/intervention.py (same module — flux is the aggregate)
@dataclass(frozen=True, slots=True)
class ResponsibilityFlux:
    """RF(E_j, t) (§10): responsibility as a flux, not frozen at first detection."""
    node_signature: str
    flux: float
    at_sequence: int
    history: tuple[tuple[int, float], ...]   # bounded to MAX_FLUX_HISTORY

MAX_FLUX_HISTORY: int = 8

def calculate_responsibility_flux(field, spine, *, at_sequence: int
                                 ) -> tuple[ResponsibilityFlux, ...]: ...   # CBF-F10
```

**`target_signature` is a `CausalNode.signature`, and the join is asserted in a test.** Stage 2's
single most expensive defect (S2-FC-01) was exactly this: `nodes` keyed by
`CausalNode.signature` (16 hex) looked up by a positional locator `lineage:index:rN:mM`, two
disjoint key spaces, so the credit assignment function was **never called once** while the gate
reported a measurement. `tests/test_stage4_counterfactual.py` asserts, for a non-empty spine, that
at least one intervention resolves to a real node and that `counterfactual_intervene` was invoked
with a signature present in `spine` — a count, not a plausibility check.

```python
# pocketsec/stage4/counterfactual/stress.py
MAX_STRESS_PERTURBATIONS: int = 8

class PerturbationKind(StrEnum):
    INSERT_BENIGN_CONTEXT = "INSERT_BENIGN_CONTEXT"
    REMOVE_CRITICAL_EVENT = "REMOVE_CRITICAL_EVENT"
    RENAME_SEMANTIC_PRESERVING = "RENAME_SEMANTIC_PRESERVING"
    DELAY_LOW_AND_SLOW = "DELAY_LOW_AND_SLOW"
    INJECT_DECOY_ANCESTRY = "INJECT_DECOY_ANCESTRY"
    DROP_TELEMETRY = "DROP_TELEMETRY"
    REPLACE_IOC_WITH_EQUIVALENT = "REPLACE_IOC_WITH_EQUIVALENT"
    PERTURB_EPOCH_CONTEXT = "PERTURB_EPOCH_CONTEXT"

@dataclass(frozen=True, slots=True)
class StressResult:
    kind: PerturbationKind
    conclusion_survived: bool
    support_shift: float
    spurious_detected: bool
    detail: str

def stress_world_adversarially(field, world_id, *, corpus_hook) -> tuple[StressResult, ...]: ...  # CBF-F16
```

All eight §25 perturbations, one per `PerturbationKind`. `RENAME_SEMANTIC_PRESERVING` is the load
bearing one and it is nearly free, because `causal_signature` is built from semantics and excludes
identities (`memory.py:47`): a rename must leave the field **bit-identical**, and the test asserts
equality of the support vector, not similarity.

```python
# pocketsec/stage4/counterfactual/questions.py
MAX_QUESTIONS_PER_WORLD: int = 8

class QuestionKind(StrEnum):      # the eight questions of §24, verbatim in intent
    WHAT_WOULD_FALSIFY = "WHAT_WOULD_FALSIFY"
    WHAT_ALTERNATIVE_EXPLAINS = "WHAT_ALTERNATIVE_EXPLAINS"
    WHICH_CLAIM_DEPENDS_ON_BLINDNESS = "WHICH_CLAIM_DEPENDS_ON_BLINDNESS"
    WHICH_EVENT_CARRIES_TOO_MUCH = "WHICH_EVENT_CARRIES_TOO_MUCH"
    WHAT_EXPECTED_EVIDENCE_IS_ABSENT = "WHAT_EXPECTED_EVIDENCE_IS_ABSENT"
    WOULD_RENAMING_CHANGE_IT = "WOULD_RENAMING_CHANGE_IT"
    WOULD_REMOVING_NOVELTY_CHANGE_IT = "WOULD_REMOVING_NOVELTY_CHANGE_IT"
    IS_EXTERNAL_MAPPING_STRONGER_THAN_EVIDENCE = "IS_EXTERNAL_MAPPING_STRONGER_THAN_EVIDENCE"

@dataclass(frozen=True, slots=True)
class Challenge:
    kind: QuestionKind
    answered: bool
    finding: str
    material: bool               # did it change the field or a claim?
    claim_ids_affected: tuple[str, ...]

def self_question_world(field, world_id, *, shadow, graph) -> tuple[Challenge, ...]: ...  # CBF-F15
```

Every question is a **structured test that runs**, never a prompt (§24). `material` is what G4.10's
ablation reads: self-questioning survives only if it finds something ordinary validation does not.

**Bounds:** ≤ `MAX_COUNTERFACTUALS_PER_INCIDENT` interventions per incident, charged to the entropy
budget; ≤ 8 stresses and ≤ 8 questions per world; the counterfactual workspace is allocated per call
and dropped on return (§44).

---

### D4.7 — Incident Future Cone composer `[counterfactual]`

```python
# pocketsec/stage4/cones/incident_cone.py
MAX_BRANCHES_PER_WORLD: int = 4
MAX_CONE_DEPTH: int = 3
MIN_BRANCH_CONSEQUENCE: float = 0.1

@dataclass(frozen=True, slots=True)
class CausalBranch:
    branch_id: str
    label: str                   # "persistence" | "credential_access" | "data_staging" | "session_end"
    predicted_signals: frozenset[str]
    forbidden_signals: frozenset[str]
    raises_dimensions: frozenset[str]        # DIMENSIONS keys
    consequence: float                       # Φ of the state this branch would reach
    depth: int

@dataclass(frozen=True, slots=True)
class IncidentFutureCone:
    world_id: str
    branches: tuple[CausalBranch, ...]
    truncated_branches: int
    def discriminating_signals(self, other: IncidentFutureCone) -> frozenset[str]: ...
    def collapse(self, observed: frozenset[str]) -> IncidentFutureCone: ...

def predict_world_future_cone(world, *, depth: int = MAX_CONE_DEPTH) -> IncidentFutureCone: ...  # CBF-F11
def compose_cones(field) -> Mapping[str, IncidentFutureCone]: ...
```

`discriminating_signals` is the primitive D4.9 plans against, and it is the mechanism's actual
content: the useful intelligence is in the **differences** between world predictions (§4), so a
symmetric-difference over predicted signal sets is the honest core and anything more elaborate must
beat it.

**Explicitly not built on `stage2/predictors/future_cone.py`** — that module is `default off` and
measured worse than its marginal control (ADR-0116; cone Brier 1.566994 vs 1.850148, cited).

**Bounds:** ≤ `MAX_BRANCHES_PER_WORLD` × `MAX_WORLDS` = 32 branches per incident, depth ≤ 3,
branches below `MIN_BRANCH_CONSEQUENCE` dropped and counted in `truncated_branches`.

---

### D4.8 — Identifiability engine `[resolution]`

```python
# pocketsec/stage4/identifiability/resolution.py
IDENTIFIABILITY_MARGIN: float = 0.15      # support gap required to call a single world identified

class IdentifiabilityState(StrEnum):
    IDENTIFIED = "IDENTIFIED"
    UNIDENTIFIABLE = "UNIDENTIFIABLE"          # no affordable observation separates the leaders
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"   # separable, but not yet observed
    UNKNOWN = "UNKNOWN"                        # the field holds only an UNKNOWN world

@dataclass(frozen=True, slots=True)
class IdentifiabilityVerdict:
    """Identifiable(H) (§19), with the reason it went that way."""
    state: IdentifiabilityState
    leading_world_id: str | None
    support_margin: float
    material_alternatives: tuple[str, ...]
    discriminating_observations: tuple[str, ...]     # empty ⇒ genuinely non-identifiable
    affordable: bool
    shadow_penalty: float
    detail: str

    def to_verdict(self) -> Verdict: ...      # maps onto Stage 0's enum; see below
    def abstains(self) -> bool: ...

def test_identifiability(field, *, shadow, plan: ObservationPlan | None) -> IdentifiabilityVerdict: ...  # CBF-F12
```

**The mapping onto Stage 0's frozen enum is fixed here and ADR-0032 records it.** Stage 4 invents no
vocabulary:

| `IdentifiabilityState` | → `Verdict` | `abstained` |
|---|---|---|
| `IDENTIFIED` + leading world is malicious | `MALICIOUS` | `False` |
| `IDENTIFIED` + leading world is benign | `BENIGN` | `False` |
| `IDENTIFIED` + ambiguous mechanism | `SUSPICIOUS` | `False` |
| `UNIDENTIFIABLE` | `UNIDENTIFIABLE` | `True` |
| `INSUFFICIENT_EVIDENCE` | `INSUFFICIENT_EVIDENCE` | `True` |
| `UNKNOWN` | `UNKNOWN` | `True` |

`_validate_abstention` (`threat_prediction_v1.py:187`) already enforces that `abstained=True`
requires a non-committal verdict, and that `INSUFFICIENT_EVIDENCE` requires `abstained=True`. The
table is therefore checked by the contract, not by review.

**`UNIDENTIFIABLE` requires `discriminating_observations == ()`.** That is the difference between
"cannot decide" and "have not looked yet", and conflating them is the failure §19 exists to prevent.

```python
# pocketsec/stage4/identifiability/horizon.py
DEFAULT_HORIZON_TRANSITIONS: int = 64
DEFAULT_HORIZON_WORK_UNITS: int = 4096
DEFAULT_HORIZON_ESCALATIONS: int = 4

class HorizonOutcome(StrEnum):
    RESOLVED = "RESOLVED"
    ESCALATE_TO_ANALYST = "ESCALATE_TO_ANALYST"
    PRESERVE_UNRESOLVED = "PRESERVE_UNRESOLVED"
    REQUEST_HIGHER_OBSERVATION_TIER = "REQUEST_HIGHER_OBSERVATION_TIER"

@dataclass(frozen=True, slots=True)
class ResolutionHorizon:
    max_transitions: int = DEFAULT_HORIZON_TRANSITIONS
    max_work_units: int = DEFAULT_HORIZON_WORK_UNITS
    max_escalations: int = DEFAULT_HORIZON_ESCALATIONS
    consumed_transitions: int = 0
    consumed_work_units: int = 0
    consumed_escalations: int = 0
    def exhausted(self) -> bool: ...
    def charge(self, *, transitions: int = 0, work_units: int = 0, escalations: int = 0) -> ResolutionHorizon: ...
    def outcome(self, verdict: IdentifiabilityVerdict) -> HorizonOutcome: ...
```

**`outcome()` may never return `RESOLVED` for a non-committal verdict, and exhaustion may never
produce `BENIGN`.** §29: "It cannot silently simplify into benign." That is one assertion in
`tests/test_stage4_resolution.py` and it is the most important line in the file.

**Bounds:** all three horizon limits are hard; `charge()` is immutable and returns a new horizon.

---

### D4.9 — Discriminating Observation / Sensor Planner `[resolution]`

```python
# pocketsec/stage4/sensing/active_plan.py
MAX_CANDIDATE_ACTIONS: int = 8
MIN_DISCRIMINATION_TO_SPEND: float = 0.1

class SensorAction(StrEnum):                 # §17's six candidates, closed set
    TRACE_FILE_ACCESS_SUBTREE = "TRACE_FILE_ACCESS_SUBTREE"
    INCREASE_EXEC_LINEAGE_DEPTH = "INCREASE_EXEC_LINEAGE_DEPTH"
    CAPTURE_DNS_METADATA = "CAPTURE_DNS_METADATA"
    WATCH_PERSISTENCE_PATH = "WATCH_PERSISTENCE_PATH"
    COLLECT_PROCESS_HASH = "COLLECT_PROCESS_HASH"
    INSPECT_SERVICE_UNIT_CHANGE = "INSPECT_SERVICE_UNIT_CHANGE"

@dataclass(frozen=True, slots=True)
class SensorCost:
    cpu_units: float
    memory_bytes: int
    telemetry_bytes: int
    authority_risk_units: float      # §16's "privilege/risk cost" — renamed per §2.4
    def total(self) -> float: ...

SENSOR_COSTS: Mapping[SensorAction, SensorCost]     # measured by labs/experiments.py, not guessed

@dataclass(frozen=True, slots=True)
class ObservationRequest:
    action: SensorAction
    target: str                      # the AOP target string
    signals: frozenset[str]
    discrimination: float            # expected JS distance between posterior fields
    consequence: float
    cost: SensorCost
    utility: float                   # discrimination * consequence / cost.total()
    def worth_spending(self) -> bool: ...

@dataclass(frozen=True, slots=True)
class ObservationPlan:
    requests: tuple[ObservationRequest, ...]      # utility-ordered
    refused: tuple[tuple[SensorAction, str], ...] # (action, why)
    escalations: tuple[EscalationDecision, ...]   # what AOP actually granted
    def best(self) -> ObservationRequest | None: ...

def plan_discriminating_observation(field, *, cones, shadow,
                                    observation: AdaptiveObservationPolicy | None,
                                    now_ns: int) -> ObservationPlan: ...     # CBF-F13
```

```python
# pocketsec/stage4/sensing/simulate.py
def simulate_sensor_value(field, action: SensorAction, *, cones, model: VisibilityModel
                         ) -> float: ...                                     # CBF-F14
```

Two rules, both from §17 and both tested:

1. **If predicted outcomes are nearly identical across worlds, do not spend.** `simulate_sensor_value`
   returns the expected field distance *before* any escalation; below
   `MIN_DISCRIMINATION_TO_SPEND` the action is `refused` with the reason recorded. This is the
   entire low-overhead argument.
2. **Escalation goes through `AdaptiveObservationPolicy.consider()` and nowhere else.** Stage 4
   computes `discrimination` and `consequence`, maps them onto `uncertainty`,
   `security_potential` and `causal_relevance`, and calls AOP. Stage 4 has **no** code that enables
   a sensor, and `tests/test_stage4_resolution.py` asserts that every granted observation in a run
   has a matching `EscalationDecision` — a second observation planner would be a second, unbudgeted
   amplification path (ADR-0035).

`observation=None` is legal and means "no AOP available": every request is `refused` with
`"no observation policy"`, and the planner returns an empty plan rather than escalating on its own.

**Bounds:** ≤ `MAX_CANDIDATE_ACTIONS` simulated per planning call; ≤ `DEFAULT_HORIZON_ESCALATIONS`
granted per incident; AOP's own `AOPBudget` caps are never raised by Stage 4.

---

### D4.10 — Sequential evidence and calibration module `[resolution]`

```python
# pocketsec/stage4/evidence/sequential.py
MAX_EVIDENCE_STEPS: int = 256
E_VALUE_CEILING: float = 1e6
STOP_SUPPORT_THRESHOLD: float = 20.0      # e-value at which support is called sufficient
STOP_CONTRADICTION_THRESHOLD: float = 0.05

class StopReason(StrEnum):
    SUFFICIENT_SUPPORT = "SUFFICIENT_SUPPORT"
    SUFFICIENT_CONTRADICTION = "SUFFICIENT_CONTRADICTION"
    HORIZON_REACHED = "HORIZON_REACHED"
    NON_IDENTIFIABLE = "NON_IDENTIFIABLE"
    STILL_RUNNING = "STILL_RUNNING"

@dataclass(frozen=True, slots=True)
class SequentialEvidence:
    """An e-process-inspired accumulator (§31). Not a p-value, and it does not claim to be."""
    world_id: str
    e_value: float
    steps: int
    null_description: str        # what the null actually is, in words, or the guarantee is void
    anytime_valid: bool          # False unless the null is one this module can construct
    stop_reason: StopReason
    def update(self, likelihood_ratio: float) -> SequentialEvidence: ...     # CBF-F08
```

`anytime_valid` defaults to **`False`** and is set `True` only for the one null this module can
actually construct (a fixed benign-mechanism emission model over the corpus vocabulary). §31's own
wording — "without pretending all model scores satisfy statistical guarantees" — becomes a boolean
field a reader can check, and `null_description` is required non-empty.

```python
# pocketsec/stage4/evidence/calibration.py
CALIBRATION_BINS: int = 10
MAX_CALIBRATION_HISTORY: int = 512
CALIBRATION_ALERT_ECE: float = 0.15

@dataclass(frozen=True, slots=True)
class CalibrationReport:
    epoch_id: int
    bins: tuple[tuple[float, float, int], ...]    # (mean_confidence, observed_rate, count)
    ece: float | None                             # None when under-sampled — never 0.0
    brier: float | None
    samples: int
    calibration_id: str | None                    # None ⇒ uncalibrated, and stays None

class EpochCalibration:
    def observe(self, *, epoch_id: int, confidence: float, correct: bool) -> None: ...
    def report(self, epoch_id: int) -> CalibrationReport: ...
    def widen_uncertainty(self, epoch_id: int, uncertainty: float) -> float: ...
    def abstention_pressure(self, epoch_id: int) -> float: ...
    def memory_bytes(self) -> int: ...
```

`ece is None` when `samples < CALIBRATION_BINS * 5`. Stage 2's G2.5 recorded a held-out **ECE of
exactly 0.0 and Brier 0.0** on a perfectly separable split (cited) — a number that looked like
excellent calibration and was a saturation artifact. Returning `None` and failing the check is the
correction. `ThreatPredictionV1.calibration_id` stays `None` until a report with a non-`None` ECE
exists.

Rising calibration error must **widen** uncertainty and **raise** abstention (§32), asserted as two
monotonicity inequalities.

**Bounds:** ≤ `MAX_CALIBRATION_HISTORY` samples per epoch, ring-buffered; e-value clipped at
`E_VALUE_CEILING`; ≤ `MAX_EVIDENCE_STEPS` per world.

---

### D4.11 — Self-Questioning + Adversarial Belief Stress `[counterfactual]`

Delivered by `counterfactual/questions.py` (CBF-F15) and `counterfactual/stress.py` (CBF-F16),
specified under D4.6 because they share the intervention machinery and one engineer must own all
three to keep the work-unit accounting coherent. Listed separately here so the §48 numbering stays
one-to-one.

---

### D4.12 — Sparse World Graph and entropy-budget controller `[lifecycle]`

```python
# pocketsec/stage4/graph/sparse_world_graph.py
MAX_GRAPH_NODES: int = 512
MAX_GRAPH_EDGES: int = 1024
RETENTION_THRESHOLD: float = 0.05

@dataclass(frozen=True, slots=True)
class WorldGraphNode:
    signature: str               # CausalNode.signature
    causal_credit: float
    contradiction_value: float
    discrimination_value: float
    mandatory: bool              # a MANDATORY_SIGNALS-bearing node is retained unconditionally
    state_delta_mask: int
    def retained(self) -> bool: ...     # §28's four-clause rule

@dataclass(frozen=True, slots=True)
class Truncation:
    """An explicit, recorded loss. Never a silent drop."""
    what: str                    # "world" | "graph_node" | "graph_edge" | "branch" | "claim"
    identifier: str
    reason: str
    consequence_lost: float

class SparseWorldGraph:
    def add(self, node: WorldGraphNode) -> tuple[Truncation, ...]: ...
    def link(self, parent: str, child: str) -> tuple[Truncation, ...]: ...
    def prune(self) -> tuple[Truncation, ...]: ...
    def nodes(self) -> tuple[WorldGraphNode, ...]: ...
    def memory_bytes(self) -> int: ...
```

```python
# pocketsec/stage4/graph/entropy_budget.py
@dataclass(frozen=True, slots=True)
class EntropyBudget:
    """Budget_I (§29). max_reasoning_units is the contract; max_reasoning_ms is observed-only."""
    max_worlds: int = MAX_WORLDS
    max_edges: int = MAX_GRAPH_EDGES
    max_counterfactuals: int = MAX_COUNTERFACTUALS_PER_INCIDENT
    max_sensor_escalations: int = DEFAULT_HORIZON_ESCALATIONS
    max_reasoning_units: int = DEFAULT_HORIZON_WORK_UNITS
    max_memory_bytes: int = 8 * 1024 * 1024
    max_reasoning_ms: float | None = None          # advisory; see §2.8

class BudgetController:
    def charge(self, kind: str, units: int) -> None: ...
    def exhausted(self) -> bool: ...
    def spend_report(self) -> Mapping[str, int]: ...
    def safe_prune(self, field) -> tuple[CausalBeliefField, tuple[Truncation, ...]]: ...
```

`safe_prune` implements §45's first failure-safe rule: it prunes **low-consequence dominated worlds
first**, and it may never remove the last non-benign world or convert an unresolved field into a
benign resolution. `tests/test_stage4_lifecycle.py` floods the field and asserts that the
ground-truth world survives while the bound holds, and that every loss produced a `Truncation`
record.

**Bounds:** all of them, and the flood test is the proof. An attacker who can make the system branch
without limit has a denial of service, so the bound is demonstrated under adversarial load, not at
rest.

---

### D4.13 — Typed Epistemic Claim Graph + Claim Compiler `[claims]`

This is the load-bearing honesty mechanism. Separation is enforced by **construction**.

```python
# pocketsec/stage4/claims/typed_claim.py
TYPED_CLAIM_V1_ID = "pocketsec.typed_claim.v1"
MAX_CLAIM_TEXT = 240
MAX_PREMISES_PER_CLAIM = 8

class ClaimKind(StrEnum):
    OBS = "OBS"; DER = "DER"; INF = "INF"; CF = "CF"; EXT = "EXT"; UNK = "UNK"

#: Kinds that may appear in an authoritative output. Closed, and the only place
#: this policy is written down.
AUTHORITATIVE_KINDS: frozenset[ClaimKind] = frozenset({ClaimKind.OBS, ClaimKind.DER})
#: Kinds that may be a premise of a DER claim. A DER chain must root in OBS.
DERIVABLE_FROM: frozenset[ClaimKind] = frozenset({ClaimKind.OBS, ClaimKind.DER})

@dataclass(frozen=True, slots=True)
class _ClaimBase:
    claim_id: str
    subject: str                 # a DIMENSIONS key, a signal name, or a CausalNode.signature
    text: str                    # <= MAX_CLAIM_TEXT, no interpolated model output
    premises: tuple[str, ...] = ()
    evidence: tuple[EvidenceRef, ...] = ()
    def __post_init__(self) -> None: ...        # kind-specific refusals, see below
    @property
    def kind(self) -> ClaimKind: ...            # abstract on the base; fixed per subclass

@dataclass(frozen=True, slots=True)
class ObservedClaim(_ClaimBase):
    sensor: SensorPath
    at_sequence: int
    # __post_init__ REFUSES: empty evidence; any premises; a digest not matching sha256:<64hex>

@dataclass(frozen=True, slots=True)
class DerivedClaim(_ClaimBase):
    rule_id: str                 # the deterministic rule that derived it, e.g. "phi.delta"
    # REFUSES: empty premises; empty rule_id; inline evidence (a derivation cites premises)

@dataclass(frozen=True, slots=True)
class InferredClaim(_ClaimBase):
    world_id: str
    support: float
    shadow_penalty: float
    # REFUSES: empty world_id; support outside [0, 1]

@dataclass(frozen=True, slots=True)
class CounterfactualClaim(_ClaimBase):
    intervention: Intervention
    outcome_shift: float
    # REFUSES: an intervention whose target_signature is empty

@dataclass(frozen=True, slots=True)
class ExternalClaim(_ClaimBase):
    knowledge_source: str        # "attack" | "sigma" | "local"
    source_version: str          # REQUIRED and non-empty — §33's versioned adapter
    rationale: str               # REQUIRED: the evidence reason this mapping was retained
    # REFUSES: empty source_version or rationale

@dataclass(frozen=True, slots=True)
class UnknownClaim(_ClaimBase):
    reason: str                  # "shadowed" | "not_observed" | "insufficient_evidence"
    shadow_region: str = ""
    # REFUSES: any evidence; any premises

TypedClaim = (ObservedClaim | DerivedClaim | InferredClaim
              | CounterfactualClaim | ExternalClaim | UnknownClaim)

def kind_of(claim: TypedClaim) -> ClaimKind: ...
def is_authoritative_kind(claim: TypedClaim) -> bool: ...
```

**Why six classes and not one class with a `kind: str` field.** A tagged union with a string tag is
enforced by convention: nothing stops `ObservedClaim(kind="OBS", evidence=())` from being
constructed with an inference's content. Six frozen dataclasses with kind-specific `__post_init__`
refusals make the illegal state unconstructable, and `TypedClaim` as a `|` union makes `mypy
--strict` exhaustive over it. ADR-0031 records this.

```python
# pocketsec/stage4/claims/graph.py
MAX_CLAIMS_PER_GRAPH: int = 256
MAX_CLAIM_DEPTH: int = 8

class LaunderingAttempt(ContractError):
    """Raised when an insert would let an INF/CF/EXT/UNK claim support an authoritative one."""

@dataclass(frozen=True, slots=True)
class ClaimGraph:
    claims: Mapping[str, TypedClaim]
    authoritative: frozenset[str]
    truncated: tuple[Truncation, ...] = ()

    def insert(self, claim: TypedClaim, *, authoritative: bool = False) -> ClaimGraph: ...
    def roots_of(self, claim_id: str) -> tuple[TypedClaim, ...]: ...
    def traces_to_observation(self, claim_id: str) -> bool: ...
    def unsupported_authoritative(self) -> tuple[str, ...]: ...
    def kinds_present(self) -> Mapping[ClaimKind, int]: ...
    def to_dict(self) -> dict[str, Any]: ...
```

Four refusals in `insert`, each raising `LaunderingAttempt`:

1. `authoritative=True` with `kind_of(claim) not in AUTHORITATIVE_KINDS` — **an INF or CF claim can
   never be emitted as authoritative.**
2. A `DerivedClaim` whose premises are not all in `DERIVABLE_FROM` — no DER may rest on an INF.
3. A premise id absent from the graph — no dangling support.
4. Depth > `MAX_CLAIM_DEPTH`, or a cycle.

`unsupported_authoritative()` is the mechanical form of gate criterion 8: walk each authoritative
claim's premise chain and assert it terminates in `ObservedClaim`s with valid `sha256:` digests.
**G4.8 is that function returning `()`.**

`tests/test_stage4_claims.py` contains the adversarial suite that tries to launder an inference into
an observation. At minimum: (a) `ObservedClaim` with empty evidence; (b) `ObservedClaim` built from
an `InferredClaim`'s text with fabricated evidence whose digest is malformed; (c) a `DerivedClaim`
whose premise is an `InferredClaim`; (d) `insert(inferred, authoritative=True)`; (e) a DER cycle;
(f) an `ExternalClaim` with no `source_version`, marked authoritative; (g) a chain OBS→DER→INF→DER
where the second DER is marked authoritative. **All seven must raise.**

```python
# pocketsec/stage4/claims/compiler.py
@dataclass(frozen=True, slots=True)
class CompiledClaim:
    """§23's template, as data: headline + because / against / unknown."""
    headline: TypedClaim
    because: tuple[TypedClaim, ...]
    against: tuple[TypedClaim, ...]
    unknown: tuple[UnknownClaim, ...]
    def render(self) -> str: ...        # deterministic text, the authoritative rendering

def compile_typed_claim_graph(field, *, shadow, verdict: IdentifiabilityVerdict
                             ) -> tuple[ClaimGraph, tuple[CompiledClaim, ...]]: ...   # CBF-F18
```

**Semantic conservation (§21) is enforced here, and it is the one place factual amplification could
enter.** `AMPLIFICATION_RULES` is a closed mapping from an observed object class to the strongest
claim permitted about it:

```python
AMPLIFICATION_RULES: Mapping[str, frozenset[str]]
# "CREDENTIAL_MATERIAL" -> {"possible_credential_access"}  and NOT {"credential_stolen"}
FORBIDDEN_AMPLIFICATIONS: frozenset[str]     # "stolen", "exfiltrated", "compromised", "breached"
def amplification_violations(claims: Sequence[TypedClaim]) -> tuple[str, ...]: ...
```

`compile_typed_claim_graph` refuses to emit a claim whose text contains a
`FORBIDDEN_AMPLIFICATIONS` token unless an `ObservedClaim` in its premise chain directly evidences
it. `tests/test_stage4_claims.py` includes §21's exact case: evidence says *read object classified
CREDENTIAL_MATERIAL*, the graph may hold `[INF] possible credential access`, and
`[INF] password stolen` must raise.

**Bounds:** ≤ `MAX_CLAIMS_PER_GRAPH` claims, depth ≤ 8, text ≤ 240 chars, `truncated` explicit.

---

### D4.14 — Stage 3 contradiction / crystallization feedback `[runtime]`

```python
# pocketsec/stage4/crystal/handoff.py                          [optionality]
@dataclass(frozen=True, slots=True)
class CrystalKnowledge:
    """Stage 3's handoff, read as plain JSON. NO pocketsec.stage3 import (§2.5)."""
    handoff_id: str
    handoff_digest: str                      # sha256 of the bytes actually read
    cells: tuple[Mapping[str, Any], ...]
    assurance: tuple[Mapping[str, Any], ...]
    boundary_keys: tuple[Mapping[str, Any], ...]
    melt_history: tuple[Mapping[str, Any], ...]
    encoder_version: str
    def cell_ids(self) -> tuple[str, ...]: ...
    def melted(self, cell_id: str) -> bool: ...
    def keys_for(self, cell_id: str) -> tuple[tuple[int, int, int], ...]: ...

EMPTY_KNOWLEDGE: CrystalKnowledge            # the zero-cell value used when no handoff exists

def read_crystal_knowledge(path: Path) -> CrystalKnowledge: ...
def load_or_empty(path: Path) -> tuple[CrystalKnowledge, DegradationRecord | None]: ...
```

A missing, unreadable or schema-mismatched handoff yields `EMPTY_KNOWLEDGE` plus a
`DegradationRecord` — **never an exception**. Stage 3 being absent is a supported configuration.

```python
# pocketsec/stage4/crystal/feedback.py                         [runtime]
CELL_STRESS_V1_ID = "pocketsec.cell_stress_signal.v1"
MIN_CONTRADICTIONS_FOR_STRESS: int = 3
MIN_RESOLUTIONS_FOR_CRYSTAL_CANDIDATE: int = 3

@dataclass(frozen=True, slots=True)
class CellStressSignalV1:
    """§27: no stage is permanently unquestionable. Written as JSON; Stage 3 reads it."""
    signal_id: str
    cell_id: str
    boundary_key: tuple[int, int, int]
    contradiction_count: int
    contradicting_claim_ids: tuple[str, ...]
    evidence_digests: tuple[str, ...]
    incident_ids: tuple[str, ...]
    def to_dict(self) -> dict[str, Any]: ...

@dataclass(frozen=True, slots=True)
class CrystalCandidateSignalV1:
    """§26: a repeatedly resolved incident-world structure, proposed as a cell."""
    signal_id: str
    mechanism_id: str
    resolution_count: int
    stable_claim_rule_ids: tuple[str, ...]
    boundary_keys: tuple[tuple[int, int, int], ...]
    evidence_digests: tuple[str, ...]

def stress_stage3_cell(knowledge, graph, *, incident_ids) -> tuple[CellStressSignalV1, ...]: ...  # CBF-F19
def propose_crystal_candidates(history) -> tuple[CrystalCandidateSignalV1, ...]: ...
def write_feedback(signals, path: Path) -> str: ...      # canonical JSON, returns sha256 digest
```

**Neither signal promotes anything.** A stress signal is a *request* for a Stage 3 audit; a
candidate signal is a *proposal*. Stage 4 has no path to melt a cell or to create one.
`tests/test_stage4_runtime.py` asserts that no Stage 4 module exports a function whose name
contains `melt`, `promote` or `crystallize`.

**Bounds:** ≤ 32 stress signals and ≤ 16 candidates per run; `MIN_*` thresholds prevent one
contradiction from destabilising a trusted cell (falsifier F9).

---

### D4.15 — Optional guarded tiny-LM verbalizer `[claims]`

```python
# pocketsec/stage4/claims/verbalizer.py
VERBALIZER_DEFAULT_ENABLED: bool = False        # never required for detection or resolution

class Verbalizer(Protocol):
    def verbalize(self, compiled: CompiledClaim) -> str: ...

@dataclass(frozen=True, slots=True)
class VerbalizerVerdict:
    accepted: bool
    text: str                    # the accepted text, or the deterministic render on rejection
    rejected_reason: str
    unsupported_propositions: tuple[str, ...]
    fell_back: bool

def validate_verbalization(compiled: CompiledClaim, produced: str) -> VerbalizerVerdict: ...
def verbalize_guarded(compiled: CompiledClaim, verbalizer: Verbalizer | None) -> VerbalizerVerdict: ...
```

The validator is the deliverable; the model is not. `validate_verbalization` tokenises the produced
text and refuses it if it contains (a) any `FORBIDDEN_AMPLIFICATIONS` token not in the compiled
claim, (b) any `DIMENSIONS` key or `MANDATORY_SIGNALS` name not present in the compiled claim's
premise chain, (c) any digit sequence not appearing in the compiled claim, or (d) any negation of a
compiled `UnknownClaim`. On rejection the deterministic `CompiledClaim.render()` is used and
`fell_back=True` is recorded.

**No language model ships in this wave.** `verbalizer=None` is the shipped configuration;
`tests/test_stage4_claims.py` exercises the validator with a `StubVerbalizer` that deliberately
injects each of the four violation classes. Whether a real tiny LM helps is UNMEASURED and declared
so, because there is no local model in this repository to measure.

---

### D4.16 — 40-experiment benchmark, ablation and falsification report `[runtime]`

```python
# pocketsec/stage4/labs/experiments.py
STAGE4_EXPERIMENTS_VERSION: str

@dataclass(frozen=True, slots=True)
class ExperimentSpec:
    experiment_id: str           # "S4X-01" .. "S4X-40", the architecture's own ids (§43)
    title: str
    core_ids: tuple[str, ...]    # which CBF-F* it exercises
    runnable: bool               # False ⇒ blocked, with a reason
    blocked_reason: str          # "needs real telemetry" | "needs numpy" | "needs a local LM"
    registry_experiment_id: str | None       # PS-S4-... once measured

EXPERIMENTS: tuple[ExperimentSpec, ...]      # exactly 40
def runnable_experiments() -> tuple[ExperimentSpec, ...]: ...
def blocked_experiments() -> tuple[ExperimentSpec, ...]: ...

@dataclass(frozen=True, slots=True)
class AblationRow:
    core_id: str
    flag: str
    with_value: float
    without_value: float
    delta: float
    metric: str
    verdict: str                 # "JUSTIFIED" | "NOT_YET_JUSTIFIED" | "HARMFUL" | "DEGENERATE"

def run_ablation(corpus, *, seed: int) -> tuple[AblationRow, ...]: ...
def saturation_check(corpus) -> tuple[bool, str]: ...
```

All forty §43 ids are enumerated, and the ones that cannot run say why. **`blocked_experiments()`
being non-empty is a required output, not a failure of tidiness** — declaring the gap is the
deliverable. `run_ablation` calls `saturation_check` **first** and returns `DEGENERATE` rows with
the reason rather than a delta when the split cannot tell mechanisms apart (`ParetoReport.degenerate`
at `stage1/guillotine/ablation.py:180` is the precedent; Stage 2's G2.2 reported
`ORDER_FREE_BASELINE_TIES_BEST`).

```python
# pocketsec/stage4/labs/baselines.py — see §7 for what each one is and must lose on
BASELINE_REGISTRY: Mapping[str, Callable[..., BaselineOutcome]]

@dataclass(frozen=True, slots=True)
class BaselineOutcome:
    baseline_id: str
    world_set_recall: float | None
    premature_collapse_rate: float | None
    nonidentifiability_accuracy: float | None
    unsupported_claim_count: int
    telemetry_bytes: int
    cpu_units: float
    work_units: int
    resolution_efficiency: float | None
    def to_dict(self) -> dict[str, Any]: ...

def run_baselines(corpus, *, seed: int) -> tuple[BaselineOutcome, ...]: ...
def pareto_frontier(outcomes) -> tuple[tuple[str, ...], tuple[str, ...]]: ...   # (frontier, dominated)
```

Every metric is `float | None`, and `None` means not computable — never 0.0 (ADR-0004).

**Bounds:** exactly 40 specs; every baseline runs in the **same process** as the mechanism it
controls, with `/proc/loadavg` recorded, so only within-run ratios are reported.

---

### D4.17 — Failure-safe degradation and Stage 1–3 optionality `[optionality]`

**Derived from §45, which §48 omits. Gate criterion 11 depends on it, and it is built first.**

```python
# pocketsec/stage4/engine/degradation.py
class Subsystem(StrEnum):
    WORLD_LIFECYCLE = "WORLD_LIFECYCLE"
    CLAIM_COMPILER = "CLAIM_COMPILER"
    ACTIVE_SENSING = "ACTIVE_SENSING"
    COUNTERFACTUAL = "COUNTERFACTUAL"
    CALIBRATION = "CALIBRATION"
    EXTERNAL_KNOWLEDGE = "EXTERNAL_KNOWLEDGE"
    VERBALIZER = "VERBALIZER"
    CRYSTAL_HANDOFF = "CRYSTAL_HANDOFF"
    SEQUENTIAL_EVIDENCE = "SEQUENTIAL_EVIDENCE"
    WORLD_GRAPH = "WORLD_GRAPH"

@dataclass(frozen=True, slots=True)
class DegradationRecord:
    subsystem: Subsystem
    exception_type: str
    message: str                 # truncated to 240 chars, never a traceback
    at_sequence: int
    fallback: str                # the §45 rule applied, verbatim
    evidence_preserved: bool

#: §45, as a table the code consults rather than prose an engineer remembers.
FALLBACKS: Mapping[Subsystem, str] = {
    Subsystem.COUNTERFACTUAL: "disable counterfactual claims; preserve evidence and detection",
    Subsystem.ACTIVE_SENSING: "fall back to the Stage 1 default observation policy",
    Subsystem.CALIBRATION: "widen uncertainty and increase abstention",
    Subsystem.EXTERNAL_KNOWLEDGE: "drop EXT claims; internal reasoning continues",
    Subsystem.VERBALIZER: "deterministic typed claim rendering",
    ...
}

class DegradationLedger:
    def record(self, record: DegradationRecord) -> None: ...
    def records(self) -> tuple[DegradationRecord, ...]: ...
    def degraded(self, subsystem: Subsystem) -> bool: ...
    def memory_bytes(self) -> int: ...

def guarded(subsystem: Subsystem, ledger: DegradationLedger, *, at_sequence: int = 0):
    """Decorator/context manager. Catches BaseException except KeyboardInterrupt and
    SystemExit, records a DegradationRecord, and returns the declared fallback value.

    It NEVER converts uncertainty into a benign resolution: a guarded failure that
    would have resolved an incident downgrades the verdict to a non-committal one.
    """
```

```python
# pocketsec/stage4/engine/integrator.py
@dataclass(frozen=True, slots=True)
class IncidentEvidence:
    """Everything Stage 4 receives, and the only way it receives it."""
    incident_id: str
    epoch_id: int
    transitions: tuple[SSIRTransitionV1, ...]
    spine: tuple[CausalNode, ...]
    host_state: SecurityStateV1
    predictions: tuple[ThreatPredictionV1, ...]      # read as evidence only, never as authority
    knowledge: CrystalKnowledge
    sensor: SensorPath
    truncated: bool

MAX_TRANSITIONS_PER_INCIDENT: int = 4096            # matches Stage 0's bounded window

def integrate_evidence(result: ScenarioResult, *, memory: CausalMemory,
                       knowledge: CrystalKnowledge = EMPTY_KNOWLEDGE,
                       predictions: Sequence[ThreatPredictionV1] = (),
                       incident_id: str, sensor: SensorPath) -> IncidentEvidence: ...
```

```python
# pocketsec/stage4/slot.py
class CBFSlot:
    """ModelSlot over the CBF. Emits UNIDENTIFIABLE/abstained rather than a guess."""
    slot_name: str = "stage4-cbf-lucid"
    model_state_version: str
    input_schema: str = ACCEPTED_INPUT_SCHEMA
    output_schema: str = PRODUCED_OUTPUT_SCHEMA
    def predict(self, sequence: SecurityEventSequenceV1) -> ThreatPredictionV1: ...
```

**The isolation test is written before the cognition** and it is the first thing this wave produces.
`tests/test_stage4_optionality.py`:

1. Builds a Stage 1 pipeline over the ambiguous corpus and records the `ScenarioResult` and the
   Stage 2/3 detection outputs **with no Stage 4 present**. Digest them.
2. Attaches Stage 4 and, for each of the ten `Subsystem` values, injects a raised exception at that
   subsystem's entry point (monkeypatched to `raise RuntimeError` / `MemoryError` /
   `RecursionError`) **mid-incident**, at a transition index in the middle of the sequence.
3. Asserts, for all ten: the Stage 1 `ScenarioResult` digest is **unchanged**; the Stage 2/3
   detection verdicts are **unchanged**; no exception escaped; exactly one `DegradationRecord` was
   written naming the right subsystem and the right `FALLBACKS` string; the Stage 4 output is either
   absent or non-committal, and **never** `BENIGN`.
4. Asserts structurally (AST) that no module under `pocketsec/stage1/` or `pocketsec/stage2/`
   imports `pocketsec.stage4` — trust rule T7.

**If Stage 4 cannot crash safely, nothing else about it matters.** Packages 3–8 are not started
until this file passes.

---

### D4.18 — Stage 4 corpora `[foundation]` + `[visibility]` + `[resolution]`

**Derived from §39, which §48 omits.** Five of the twelve gate criteria depend on it.

```python
# pocketsec/stage4/labs/incident_corpus.py                     [foundation]
INCIDENT_CORPUS_VERSION: str = f"stage4-incident-v0.1.0+{AMBIGUOUS_VERSION}"

@dataclass(frozen=True, slots=True)
class GroundTruthWorld:
    """The world a constructed incident actually came from. The corpus knows; LUCID must not."""
    world_label: str             # "approved_admin" | "compromised_session" | "stolen_credential" |
                                 # "legitimate_automation" | "novel_unresolved"
    mechanism_id: str
    raises_dimensions: frozenset[str]
    discriminating_signal: str | None        # None ⇒ constructed to be non-identifiable

@dataclass(frozen=True, slots=True)
class IncidentCase:
    incident_id: str
    scenario: Scenario
    truth: GroundTruthWorld
    material_alternatives: tuple[str, ...]
    expected_state: IdentifiabilityState
    visibility_mask: frozenset[str] = frozenset()

def build_incident_corpus(*, count: int, seed: int) -> tuple[IncidentCase, ...]: ...
def build_shared_prefix_pairs(*, count: int, seed: int) -> tuple[tuple[IncidentCase, IncidentCase], ...]
def build_rename_variants(case: IncidentCase, *, seed: int) -> tuple[IncidentCase, ...]
def build_low_and_slow_variants(case: IncidentCase, *, seed: int) -> tuple[IncidentCase, ...]
def build_decoy_variants(case: IncidentCase, *, seed: int) -> tuple[IncidentCase, ...]
def build_world_flood(*, count: int, seed: int) -> tuple[IncidentCase, ...]
def median_peak_delta_phi(cases) -> dict[int, float]: ...
def operation_counts(cases) -> dict[int, Counter[str]]: ...
def pooled_order_free_scores(cases) -> list[float]: ...
```

```python
# pocketsec/stage4/labs/dropped_telemetry.py                   [visibility]
def drop_sensor_path(case: IncidentCase, sensor: SensorPath) -> IncidentCase: ...
def drop_signal(case: IncidentCase, signal: str) -> IncidentCase: ...
def paired_replay(case: IncidentCase, pipeline_factory) -> tuple[ScenarioResult, ScenarioResult]: ...

# pocketsec/stage4/labs/nonidentifiable.py                     [resolution]
def build_nonidentifiable_pairs(*, count: int, seed: int) -> tuple[tuple[IncidentCase, IncidentCase], ...]:
    """Two worlds explaining IDENTICAL observations, with NO discriminating observable.

    Constructed by making both worlds' expected and forbidden evidence sets equal
    over the corpus vocabulary and every SensorAction's reachable signal set. The
    construction is asserted, not intended: a test checks the two cases produce
    byte-identical SSIR semantic keys under every sensor path.
    """
def build_resolvable_after_one_observation(*, count: int, seed: int) -> tuple[IncidentCase, ...]:
    """§39's last row: non-identifiable at low telemetry, identifiable after ONE targeted observation."""
```

**Five mandatory corpus tests, from `MEMORY.md`'s hardest-won lessons.** Every one of them has
already cost this project a wrong published result:

1. `test_incident_corpus_uses_session_unique_identities` — `Stage1Pipeline` carries lineage state
   across scenarios. Reused process identities put every lineage at saturated privilege and the
   measured median ΔΦ was **0.00 for both classes** (cited), which retracted a +0.042 result.
2. `test_incident_corpus_median_delta_phi_is_nonzero_per_class` — asserted **before** any mechanism
   is measured on it.
3. `test_incident_corpus_carries_no_vocabulary_signal` — per-operation count distributions match
   across classes within noise, and a pooled order-free control scores within 0.05 of the base rate.
   Two corpora leaked this way already.
4. `test_nonidentifiable_pairs_are_actually_nonidentifiable` — identical semantic keys under every
   `SensorPath`, and every `SensorAction`'s reachable signal set gives zero discrimination. A
   "non-identifiable" case that one observation separates is not a non-identifiability test.
5. `test_world_flood_does_not_saturate` — the flood corpus must still contain a recoverable ground
   truth world; a flood where the true world is unrecoverable tests nothing about bounds.

**Bounds:** deterministic under `seed`; ≤ `MAX_TRANSITIONS_PER_INCIDENT` per case; every generator
exports its `*_VERSION` constant, which is what a `BenchmarkResult`'s provenance records
(integration plan §5.4).

---

### D4.19 — Core functional IDs `[foundation]`

```python
# pocketsec/stage4/core_ids.py
CBF_INTERFACE_ID = "pocketsec.cbf_interface.v1"
CBF_INTERFACE_VERSION = register_schema(CBF_INTERFACE_ID, "1.0.0")

class FunctionClass(StrEnum):
    REQUIRED = "REQUIRED"
    OPTIONAL = "OPTIONAL"

@dataclass(frozen=True, slots=True)
class CoreFunction:
    core_id: str                 # "CBF-F01" .. "CBF-F20"
    architecture_id: str         # "LUC-F01" .. "LUC-F20" (§36) — the rename stays auditable
    name: str
    purpose: str
    function_class: FunctionClass
    deliverable: str             # "D4.2"
    ablation_flag: str           # the LucidConfig flag that removes it, or "" for REQUIRED

CORE_IDS: Mapping[str, CoreFunction]
REQUIRED_IDS: tuple[str, ...]
OPTIONAL_IDS: tuple[str, ...]
ABLATION_FLAGS: Mapping[str, str]
```

All twenty `LUC-F01…LUC-F20` from §36 map one-to-one onto `CBF-F01…CBF-F20`, keeping the
architecture's order. The **OPTIONAL** set is where this wave commits to what it will delete:

| `CBF-F*` | function | class | flag |
|---|---|---|---|
| F01 `update_causal_belief_field` | the loop | REQUIRED | — |
| F02 `spawn_world`, F03 `kill_world` | birth/death | REQUIRED | — |
| F04 `fission_world`, F05 `fuse_worlds` | adaptive complexity | **OPTIONAL** | `enable_fission_fusion` |
| F06 `estimate_sensor_shadow`, F07 `calculate_evidence_tension` | partial observability | REQUIRED | — |
| F08 `update_sequential_evidence` | e-process | **OPTIONAL** | `enable_sequential_evidence` |
| F09 `counterfactual_intervene`, F10 `calculate_responsibility_flux` | causal responsibility | **OPTIONAL** | `enable_counterfactual` |
| F11 `predict_world_future_cone` | cones | REQUIRED (D4.9 needs it) | — |
| F12 `test_identifiability` | the gate | REQUIRED | — |
| F13 `plan_discriminating_observation`, F14 `simulate_sensor_value` | active sensing | **OPTIONAL** | `enable_active_sensing` |
| F15 `self_question_world`, F16 `stress_world_adversarially` | self-challenge | **OPTIONAL** | `enable_self_questioning`, `enable_stress` |
| F17 `prune_dominated_worlds` | bounds | REQUIRED | — |
| F18 `compile_typed_claim_graph` | honesty | REQUIRED | — |
| F19 `stress_stage3_cell` | reverse flow | **OPTIONAL** | `enable_cell_feedback` |
| F20 `export_incident_world_record` | Stage 5 seam | REQUIRED | — |

Nine OPTIONAL ids. **G4.10 enumerates every one of them and requires a registered experiment id
with a measured delta; an OPTIONAL function with no measured delta is `NOT_YET_JUSTIFIED`, never
"kept because it is there".** Nothing is marked OPTIONAL that this wave is not prepared to delete.

---

### The constant table, in one place

Every bound, with the architecture section it comes from. These are exported from the module named
and asserted in that package's test file.

| constant | value | module | source |
|---|---|---|---|
| `MAX_WORLDS` | 8 | `worlds/field.py` | §44 "K capped 4–16 normally" — default low end |
| `MAX_WORLDS_CEILING` | 16 | `worlds/field.py` | §44 "exceptional cap explicit" |
| `MAX_WORLD_BYTES` | 8192 | `worlds/world.py` | §44 "KB-scale/world" |
| `MAX_TOMBSTONES` | 32 | `worlds/tombstone.py` | §13 |
| `MAX_FISSION_DEPTH` | 2 | `worlds/lifecycle.py` | §14 |
| `MAX_CLAIMS_PER_GRAPH` | 256 | `claims/graph.py` | §29 `max_edges` |
| `MAX_CLAIM_DEPTH` | 8 | `claims/graph.py` | §23 |
| `MAX_CLAIM_TEXT` | 240 | `claims/typed_claim.py` | bounded state |
| `MAX_GRAPH_NODES` / `MAX_GRAPH_EDGES` | 512 / 1024 | `graph/sparse_world_graph.py` | §28 |
| `MAX_COUNTERFACTUALS_PER_INCIDENT` | 32 | `counterfactual/intervention.py` | §29 |
| `MAX_INTERVENTION_DEPTH` | 1 | `counterfactual/intervention.py` | §9 "bounded virtual interventions" |
| `MAX_STRESS_PERTURBATIONS` / `MAX_QUESTIONS_PER_WORLD` | 8 / 8 | `counterfactual/{stress,questions}.py` | §25, §24 |
| `MAX_BRANCHES_PER_WORLD` / `MAX_CONE_DEPTH` | 4 / 3 | `cones/incident_cone.py` | §15 |
| `MAX_CANDIDATE_ACTIONS` | 8 | `sensing/active_plan.py` | §17 (six actions + room) |
| `DEFAULT_HORIZON_TRANSITIONS` / `_WORK_UNITS` / `_ESCALATIONS` | 64 / 4096 / 4 | `identifiability/horizon.py` | §20 |
| `MAX_EVIDENCE_STEPS` / `E_VALUE_CEILING` | 256 / 1e6 | `evidence/sequential.py` | §31 |
| `MAX_CALIBRATION_HISTORY` | 512 | `evidence/calibration.py` | §32 |
| `MAX_SHADOW_REGIONS` | 32 | `visibility/sensor_shadow.py` | §6 |
| `MAX_TRANSITIONS_PER_INCIDENT` | 4096 | `engine/integrator.py` | Stage 0 bounded window |
| `STAGE4_NORMAL_INCREMENTAL_RSS_BYTES` | 45 × 1024² | `resources.py` | §44 "target < 25–45 MB" |
| `STAGE4_PEAK_CEILING_BYTES` | 90 × 1024² | `resources.py` | §44 "initial ceiling < 90 MB" |
| `MAX_INCIDENT_BYTES` | 8 × 1024² | `graph/entropy_budget.py` | §29 `max_memory_bytes` |

Every bound that can be hit produces a `Truncation` record. **A silent drop is a defect**, and
`tests/test_stage4_lifecycle.py` asserts that each bound, when exceeded, yields exactly one
`Truncation` naming what was lost and its `consequence_lost`.

---

### D4.1 (continued) — the two data structures of §37, bound to Python

The architecture gives `World` and `CausalBeliefField` as field lists (§37). They are the types six
packages share, so they are specified here in full and owned by `foundation`.

```python
# pocketsec/stage4/worlds/world.py
SECURITY_WORLD_V1_ID = "pocketsec.security_world.v1"
SECURITY_WORLD_V1_VERSION = register_schema(SECURITY_WORLD_V1_ID, "1.0.0")

MAX_WORLD_BYTES: int = 8192
MAX_EXPECTED_SIGNALS: int = 32
MAX_FORBIDDEN_SIGNALS: int = 16

class WorldSupportState(StrEnum):
    """§16: worlds may split, merge, crystallize, collapse or remain unresolved."""
    PROVISIONAL = "PROVISIONAL"
    SUPPORTED = "SUPPORTED"
    CRYSTALLIZED = "CRYSTALLIZED"
    COLLAPSING = "COLLAPSING"
    UNRESOLVED = "UNRESOLVED"

class BeliefGeometry(StrEnum):
    """§11: the representation is selected empirically. Whichever is in use is recorded,
    so no one later reads a log-odds as a probability."""
    LOG_ODDS = "LOG_ODDS"
    CALIBRATED_PROBABILITY = "CALIBRATED_PROBABILITY"
    EVIDENCE_INTERVAL = "EVIDENCE_INTERVAL"
    E_VALUE = "E_VALUE"

@dataclass(frozen=True, slots=True)
class WorldSupport:
    """Support with its geometry attached. `as_probability()` returns None unless the
    geometry is one that legitimately normalises — §11's whole point."""
    geometry: BeliefGeometry
    value: float
    interval: tuple[float, float] | None = None
    def as_probability(self) -> float | None: ...
    def combine(self, log_likelihood_ratio: float) -> WorldSupport: ...

@dataclass(frozen=True, slots=True)
class LatentSecurityState:
    """X_t (§5): what the world asserts is true, distinct from what was observed."""
    state: SecurityStateV1
    asserted_dimensions: frozenset[str]       # DIMENSIONS keys the world commits to
    consequence: float                        # phi(state).total
    def raises(self, dimension: str) -> bool: ...

@dataclass(frozen=True, slots=True)
class SecurityWorldV1:
    """W_i(t) — §21's ten-tuple, as a frozen dataclass.

    `mechanism_id` is a semantic descriptor ("compromised_admin_session"), never a
    technique name and never an ATT&CK id: external knowledge constrains and names,
    it does not decide the world (§33).
    """
    world_id: str
    mechanism_id: str
    latent_state: LatentSecurityState
    support: WorldSupport
    support_state: WorldSupportState
    expected_evidence: frozenset[str]
    forbidden_evidence: frozenset[str]
    contradictions: tuple[str, ...]
    tension: EvidenceTension | None
    uncertainty: float
    visibility_requirements: frozenset[str]        # signals this world's claims depend on seeing
    spine_signatures: tuple[str, ...]              # CausalNode.signature — the causal spine
    evidence_refs: tuple[EvidenceRef, ...]
    born_at_sequence: int
    fission_depth: int = 0
    schema_version: str = SECURITY_WORLD_V1_VERSION

    def __post_init__(self) -> None:
        """Refuses, in this order:
        - an authority-named field (authority_named_fields over __dataclass_fields__)
        - expected_evidence ∩ forbidden_evidence non-empty  (a self-contradicting world)
        - a dimension not in DIMENSIONS
        - uncertainty outside [0, 1]
        - more than MAX_EXPECTED_SIGNALS / MAX_FORBIDDEN_SIGNALS
        - state_bytes() > MAX_WORLD_BYTES
        - fission_depth > MAX_FISSION_DEPTH
        """
    def state_bytes(self) -> int: ...
    def predicts(self, signal: str) -> bool: ...
    def forbids(self, signal: str) -> bool: ...
    def observationally_equivalent(self, other: SecurityWorldV1, *, epsilon: float) -> bool: ...
    def to_dict(self) -> dict[str, Any]: ...

def authority_named_fields(cls: type) -> tuple[str, ...]:
    """Fields whose lowercased name contains a FORBIDDEN_AUTHORITY_FIELDS token.
    Stage 4's own copy: Stage 4 imports nothing from Stage 3 (§2.5)."""
```

```python
# pocketsec/stage4/worlds/field.py
CAUSAL_BELIEF_FIELD_V1_ID = "pocketsec.causal_belief_field.v1"
MAX_WORLDS: int = 8
MAX_WORLDS_CEILING: int = 16

@dataclass(frozen=True, slots=True)
class CausalBeliefField:
    """CBF_t = {(W_i, support_i)} for i = 1..K, K hard-bounded (§21)."""
    incident_id: str
    epoch_id: int
    worlds: tuple[SecurityWorldV1, ...]
    max_worlds: int = MAX_WORLDS
    sensor_shadow: SensorShadow | None = None
    horizon: ResolutionHorizon = ...
    budget: EntropyBudget = ...
    graph: SparseWorldGraph | None = None
    claim_graph: ClaimGraph | None = None
    evidence_refs: tuple[EvidenceRef, ...] = ()
    truncations: tuple[Truncation, ...] = ()
    at_sequence: int = 0
    schema_version: str = ...

    def __post_init__(self) -> None:
        """Refuses len(worlds) > max_worlds, max_worlds > MAX_WORLDS_CEILING,
        duplicate world_ids, and duplicate mechanism_ids (a duplicate mechanism is a
        fusion that did not happen)."""
    def world(self, world_id: str) -> SecurityWorldV1 | None: ...
    def leaders(self, *, n: int = 2) -> tuple[SecurityWorldV1, ...]: ...
    def support_vector(self) -> Mapping[str, float]: ...
    def support_distance(self, other: CausalBeliefField) -> float: ...   # categorical JS, stdlib
    def with_worlds(self, worlds: Sequence[SecurityWorldV1]) -> CausalBeliefField: ...
    def unknown_world(self) -> SecurityWorldV1 | None: ...
    def state_bytes(self) -> int: ...
    def to_dict(self) -> dict[str, Any]: ...

def unknown_world(incident_id: str, *, at_sequence: int) -> SecurityWorldV1:
    """The bounded UNKNOWN world of §12. Novelty is not maliciousness: its
    mechanism_id is 'unresolved_novel_mechanism' and it asserts no dimension."""
```

`CausalBeliefField` is **immutable**; every lifecycle function returns a new field. The repository's
immutability rule and the oscillation guard both depend on it: a mutated field cannot be compared
against its predecessor, and `support_distance` — the primitive under both Responsibility Flux and
sensor planning — needs the predecessor.

```python
# pocketsec/stage4/stage5_interface.py                          [runtime]
CBF_RESOLUTION_V1_ID = "pocketsec.cbf_resolution.v1"
FORBIDDEN_SEAM_TOKENS: frozenset[str]        # Stage 4 class names, as stage3/stage4_interface.py does

@dataclass(frozen=True, slots=True)
class InformationGap:
    """A recommended gap. A question, never an instruction (§2.4, ADR-0003)."""
    signal: str
    why_it_matters: str
    would_discriminate: tuple[str, ...]      # world_ids
    affordable: bool

@dataclass(frozen=True, slots=True)
class IncidentHypothesis:
    """One surviving world, as Stage 5 sees it."""
    mechanism_id: str
    support: float
    consequence: float
    uncertainty: float
    claim_ids: tuple[str, ...]
    evidence_refs: tuple[EvidenceRef, ...]

@dataclass(frozen=True, slots=True)
class CBFResolutionV1:
    """§49's handoff. Plain JSON: every nested member is a Mapping[str, Any] of JSON
    values and to_dict() refuses a payload whose keys name a Stage 4 class."""
    resolution_id: str
    incident_id: str
    epoch_id: int
    verdict: Verdict
    identifiability: str                     # IdentifiabilityState.value
    hypotheses: tuple[Mapping[str, Any], ...]
    consequence_distribution: Mapping[str, float]
    claim_graph: Mapping[str, Any]
    evidence_lineage: tuple[Mapping[str, str], ...]     # EvidenceRef.to_dict() rows
    uncertainty: float
    shadow: Mapping[str, Any]
    information_gaps: tuple[Mapping[str, Any], ...]
    truncations: tuple[Mapping[str, Any], ...]
    degradations: tuple[Mapping[str, Any], ...]
    interface_version: str = ...
    def to_dict(self) -> dict[str, Any]: ...
    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> CBFResolutionV1: ...

def export_incident_world_record(field, *, verdict, resolution_id: str) -> CBFResolutionV1: ...  # CBF-F20
def write_resolution(resolution: CBFResolutionV1, path: Path) -> str: ...    # canonical JSON + digest
```

Two refusals in `to_dict()`, both asserted in `tests/test_stage4_runtime.py`:

1. No key may name a Stage 4 class (`FORBIDDEN_SEAM_TOKENS`), for the reason Stage 3's seam gives:
   Stage 4 will be redesigned, and a handoff that carries objects becomes a coupling.
2. **No claim of kind `INF`, `CF`, `EXT` or `UNK` may appear in `hypotheses` without its
   `claim_ids` resolving to a claim in `claim_graph` that is *not* marked authoritative.** The
   `ClaimGraph.unsupported_authoritative()` walk runs at export time and a non-empty result raises.
   G4.8 is measured on the exported object, which is the only artefact Stage 5 ever sees.

---

## 5. Work packages

Eight packages. **No two share a file.** `pocketsec/stage4/{gate.py, gate_criteria.py, cli.py,
__init__.py}`, `docs/stage-4-findings.md` and the ten ADR files are **integrator-owned** and appear
in no package.

| # | key | delivers | owns (repo-relative) | depends on |
|---|---|---|---|---|
| 1 | `foundation` | D4.1, D4.19, core types, D4.18 (base corpus) | `core_ids.py`, `theory.py`, `worlds/world.py`, `worlds/field.py`, `labs/incident_corpus.py`, `tests/test_stage4_foundation.py`, `tests/test_stage4_boundary.py` | — |
| 2 | `optionality` | **D4.17**, the Stage 3 reader, the slot | `engine/degradation.py`, `engine/integrator.py`, `crystal/handoff.py`, `slot.py`, `tests/test_stage4_optionality.py` | foundation |
| 3 | `claims` | D4.13, D4.15 | `claims/typed_claim.py`, `claims/graph.py`, `claims/compiler.py`, `claims/verbalizer.py`, `tests/test_stage4_claims.py` | foundation |
| 4 | `visibility` | D4.3, D4.4 | `visibility/model.py`, `visibility/sensor_shadow.py`, `tension/evidence_tension.py`, `tension/negative_evidence.py`, `labs/dropped_telemetry.py`, `tests/test_stage4_visibility.py` | foundation |
| 5 | `lifecycle` | D4.5, D4.12 | `worlds/lifecycle.py`, `worlds/tombstone.py`, `graph/sparse_world_graph.py`, `graph/entropy_budget.py`, `tests/test_stage4_lifecycle.py` | foundation, visibility |
| 6 | `counterfactual` | D4.6, D4.7, D4.11 | `counterfactual/intervention.py`, `counterfactual/stress.py`, `counterfactual/questions.py`, `cones/incident_cone.py`, `tests/test_stage4_counterfactual.py` | foundation, claims, visibility |
| 7 | `resolution` | D4.8, D4.9, D4.10 | `identifiability/resolution.py`, `identifiability/horizon.py`, `evidence/sequential.py`, `evidence/calibration.py`, `sensing/active_plan.py`, `sensing/simulate.py`, `labs/nonidentifiable.py`, `tests/test_stage4_resolution.py` | foundation, visibility, counterfactual |
| 8 | `runtime` | D4.2, D4.14, D4.16, seams | `engine/lucid.py`, `crystal/feedback.py`, `stage5_interface.py`, `resources.py`, `labs/baselines.py`, `labs/experiments.py`, `tests/test_stage4_runtime.py` | all of the above |

**Build order is the package order, and packages 1 and 2 are a gate on the rest.** Package 2
contains the isolation property; packages 3–8 do not start until
`tests/test_stage4_optionality.py` passes. The lead's instruction is explicit and it is an
engineering judgement, not a ceremony: if Stage 4 cannot crash safely, nothing else about it
matters.

Each package is roughly 600–1200 lines of new code *including* its test file. Package 1 sits at the
top of that range because it carries the shared types plus the corpus; packages 4 and 7 sit near
1200 because their criteria are the ones with the most constructed cases.

`tests/test_stage4_boundary.py` (owned by `foundation`) implements, for Stage 4 only, the AST rules
that `tests/test_repository_structure.py` implements for Stages 0–2. Read that file for the
technique — `_research_importers` at `:124` and the `imported_modules` resolver — and **leave it
untouched.** The five rules:

1. Every module under `pocketsec/stage4/` imports only roots in `sys.stdlib_module_names` or
   `pocketsec` (ADR-0001, R1).
2. No module under `pocketsec/stage4/` imports any `pocketsec.stage*.research*` (ADR-0008, R2), and
   `pocketsec/stage4/research/` does not exist (ADR-0030).
3. No module under `pocketsec/stage4/` imports `pocketsec.stage3` (§2.5).
4. No module under `pocketsec/stage1/` or `pocketsec/stage2/` imports `pocketsec.stage4` (T7).
5. No dataclass field under `pocketsec/stage4/` has a lowercased name containing a
   `FORBIDDEN_AUTHORITY_FIELDS` token (T5), and `pocketsec/stage4/{causal,cbf,lucid}/` do not exist
   (ADR-0121).

A committed negative-test fixture accompanies rules 1–4, in the shape of
`RELATIVE_RESEARCH_IMPORTS` (`tests/test_repository_structure.py:150`): relative imports
(`from ..stage3 import x`, `from . import research`) must be caught, because they were invisible to
two checkers at once in Stage 2 (S2-AUTH-01).

---

## 6. Acceptance gate, as executable checks

Twelve checks, one per bullet of architecture §47, reproduced in `planning/PHASE_04_CLAUDE_CODE.md`.
Integration plan §5.1 fixes the count at **12**. Every `_check_*` runs the real subsystem; the only
two that read a file are G4.1 (which reads a replay-evidence artefact this wave produced) and G4.12
(which is *about* a document).

`Stage4GateContext.build()` runs the corpus and the pipeline **once** so twelve checks do not replay
it twelve times, following `pocketsec/stage1/gate.py:55`, `:69`.

| id | §47 criterion | executable check | met on synthetic data? |
|---|---|---|---|
| **G4.1** | Partial-observability and visibility models are empirically measured for supported telemetry sources | `measure_visibility()` replays the incident corpus through `SensorPath.EBPF` and `SensorPath.AUDITD` in the same run; `fit_visibility_model` from half the replays; assert the fitted `probability(signal, sensor)` matches the held-out replay frequency within ±0.05 for every pair with ≥20 occurrences; assert `probability()` is `None` for every pair with no evidence; assert `1.0` for all six `MANDATORY_SIGNALS`; assert `coverage()` is recorded. Evidence written to `results/stage4-visibility.json` with its `(corpus, count, seed)` provenance, and the check **refuses** evidence whose provenance differs from the split it just ran (ADR-0127's rule) | **NO** — see §6.1 |
| **G4.2** | CBF preserves the ground-truth world or an equivalent explanation in controlled ambiguous incidents | Run `LucidEngine` over `build_incident_corpus(count=60, seed=11)`; for each case assert `case.truth.mechanism_id` is in `{w.mechanism_id for w in field.worlds}` **or** a surviving world is `observationally_equivalent` to it at ε=`FUSION_EQUIVALENCE_EPSILON`. Report world-set recall and premature-collapse rate (fraction resolved `IDENTIFIED` before the discriminating signal was observed). PASS requires recall ≥ 0.9 **and** premature-collapse ≤ 0.1, **and** that single-world MAP (B1) does not achieve both at lower cost | yes, with §6.2's caveat |
| **G4.3** | System explicitly recognizes constructed non-identifiable cases | Run over `build_nonidentifiable_pairs(count=20, seed=17)`; assert every case returns `IdentifiabilityState.UNIDENTIFIABLE` with `discriminating_observations == ()`, and that `to_verdict()` is `Verdict.UNIDENTIFIABLE` with `abstained=True`. **Assert the system did not pick the more alarming world**: the leading world's consequence must not exceed the alternative's. Then run `build_resolvable_after_one_observation` and assert those return `INSUFFICIENT_EVIDENCE` (not `UNIDENTIFIABLE`) and resolve to `IDENTIFIED` after exactly one granted observation | yes |
| **G4.4** | Evidence Tension and Sensor Shadow behave correctly under dropped telemetry | Paired run per case: full telemetry vs `drop_sensor_path(case, SensorPath.EBPF)`. Assert (a) the shadow marks exactly the signals the drop made unobservable and nothing else; (b) tension rises on the world contradicted by conflicting evidence and does **not** rise from `UNKNOWN_ABSENCE`; (c) **`confidence` under the drop is ≤ confidence at full telemetry for every case, and the verdict never becomes more committal** — the whole point; (d) a world that full visibility would kill by absence survives the drop unchanged | yes |
| **G4.5** | At least one active sensing method reduces bytes/CPU versus always-on rich telemetry at comparable resolution quality | Same run, three configurations: `enable_active_sensing=True`, `enable_active_sensing=False`, and B3 `AlwaysOnRichTelemetry`. Report the **within-run ratios** of `telemetry_bytes` and `cpu_units`, with `/proc/loadavg`. PASS requires at least one `SensorAction` whose plan achieves world-set recall and non-identifiability accuracy within 0.02 of B3 at **strictly lower** bytes **and** cpu_units. If targeted sensing does not win, the check **FAILS and ADR-0037 records it** | yes (ratio); §6.2 caveat on "quality" |
| **G4.6** | Counterfactual stress identifies predefined spurious causal explanations | Construct, in `labs/incident_corpus.py`, five cases each carrying a **predefined spurious explanation** (a decoy ancestor with high ΔΦ that is not on the true chain). Assert `stress_world_adversarially` returns `spurious_detected=True` for each, that `REMOVE_CRITICAL_EVENT` collapses the spurious world and not the true one, and that `RENAME_SEMANTIC_PRESERVING` leaves `field.support_vector()` **bit-identical**. Assert a no-stress control would have kept all five | yes |
| **G4.7** | Typed Claim Graph enforces OBS/DER/INF/CF/EXT/UNK separation | Structural: assert `TypedClaim`'s union has exactly six members and `{kind_of(c) for c in members} == set(ClaimKind)`; assert all seven laundering attempts in §D4.13 raise `LaunderingAttempt`; assert `theory.unbound_terms() == ()`. Behavioural: over the whole corpus run, assert `graph.kinds_present()` contains at least one of each of OBS, DER, INF and UNK (a separation that never exercises a kind proves nothing) | yes — pure construction |
| **G4.8** | Authoritative output contains zero unsupported factual claims in the benchmark suite | For every `CBFResolutionV1` exported over the full corpus, assert `ClaimGraph.unsupported_authoritative() == ()`, that every authoritative claim's premise chain terminates in `ObservedClaim`s whose digests match `^sha256:[0-9a-f]{64}$`, that `amplification_violations() == ()`, and that no claim of kind INF/CF/EXT/UNK is in `authoritative`. Report the count; **target and threshold are both zero** | yes |
| **G4.9** | World count, graph size and reasoning time remain hard bounded | Run `build_world_flood(count=40, seed=23)` — an adversarial branch flood. Assert at every step: `len(field.worlds) ≤ max_worlds`; graph nodes ≤ `MAX_GRAPH_NODES`, edges ≤ `MAX_GRAPH_EDGES`; claims ≤ `MAX_CLAIMS_PER_GRAPH`; `budget.spend_report()["reasoning_units"] ≤ max_reasoning_units`; `field.state_bytes() ≤ MAX_INCIDENT_BYTES`. Assert **every** loss produced a `Truncation` and that the ground-truth world survived the flood. Wall-clock ms recorded beside `/proc/loadavg` as **observed, not asserted** (§2.8) | yes |
| **G4.10** | CBF/LUCID beats or complements simpler baselines on the measured Pareto frontier | `saturation_check` **first**; `DEGENERATE` ⇒ FAIL with the reason and no recorded comparison. Then `run_baselines` over all eight §7 baselines in one process; assert each beats the corpus base rate or the comparison is **refused, not reported**; compute `pareto_frontier`. PASS requires CBF/LUCID on the frontier **and** all nine OPTIONAL `CBF-F*` ids carrying a registered experiment id with a measured delta | **NO** — see §6.1 |
| **G4.11** | Stage 4 remains optional to core Stage 1–3 detection if it crashes | The ten-subsystem fault injection of D4.17, executed inside the gate: for each `Subsystem`, raise mid-incident and assert the Stage 1 `ScenarioResult` digest and the Stage 2/3 verdicts are unchanged, no exception escaped, one `DegradationRecord` was written with the matching `FALLBACKS` string, and the Stage 4 verdict is absent or non-committal and **never** `BENIGN`. Plus the T7 AST assertion | yes |
| **G4.12** | All novelty claims remain provisional until formal prior-art/patent review | `PriorArtLedger.load()`; assert an entry exists for `STAGE4_HYPOTHESIS` (H3) and for `STAGE4_SECONDARY` (H7); assert `docs/stage-4-findings.md` contains no token in `{novel, first, unprecedented, patent, breakthrough}` unless the matching entry's `literature_status != "NOT_REVIEWED"`; assert the file contains all five honesty-ledger headings (§11). Assert `experiments/registry.jsonl` is byte-identical before and after the gate run (§2.7) | yes |

### 6.1 The criteria that cannot be met on synthetic data, declared

**G4.1 — visibility "empirically measured for supported telemetry sources": NOT MET.**
The supported telemetry sources are eBPF, auditd, procfs, journald and LSM on a real Linux host.
This repository has no real telemetry: every corpus is synthetic (ADR-0010), and Stage 1's measured
cross-sensor equivalence of 20/20 (cited) was measured over the *replay* of a synthetic corpus
through two *simulated* sensor paths. What G4.1 can honestly measure is the **fitting and refusal
behaviour of the visibility model over the simulator's sensors** — that a fitted probability matches
a held-out replay frequency, that an unmeasured pair returns `None`, that a mandatory signal is never
marked blind. That is a real property of the code and it is worth measuring. It is **not** a
measurement of Linux sensor visibility, and `docs/stage-4-findings.md` must say so in the
`UNMEASURED` table with "what would measure it" = *paired eBPF/auditd collection on a real host with
ground-truth injected actions*. **The check therefore reports the simulator measurement as MEASURED
and the telemetry-source clause as UNMEASURED, and FAILS rather than passing on half a criterion** —
the same discipline Stage 3's G3.9 applied (`docs/stage-3-spec.md` §6.1).

**G4.10 — "beats simpler baselines": the comparison runs, the conclusion cannot be drawn.**
Two independent reasons, both already paid for in this repository:

1. **Synthetic corpora here produce only trivial or impossible tasks, never a middle band**
   (ADR-0010, from four corpora). The Stage 2 gate's own G2.2 reports
   `ORDER_FREE_BASELINE_TIES_BEST` with best 1.0 and median 0.6586 (cited). A frontier computed on a
   split that cannot separate mechanisms measures the split.
2. **The corpus author and the mechanism author are the same wave.** `GroundTruthWorld` labels the
   world each case came from, and `SecurityWorldV1.mechanism_id` is the vocabulary LUCID proposes
   from. World-set recall over hand-authored worlds is partly a measurement of the authoring. This
   confound does not exist for G4.7, G4.8, G4.9 or G4.11, which are construction and bound
   properties, and it is the reason those four are the criteria this wave can actually settle.

G4.10 therefore **reports the measured frontier and fails**, with ADR-0036 stating the result
whichever way it falls. If single-world MAP dominates, ADR-0036 recommends removing the multi-world
machinery. That is the honest outcome and this wave writes it without flinching.

**Two further clauses inside otherwise-passable criteria are UNMEASURED and must be declared:**

- G4.2's "or an equivalent explanation" rests on `observationally_equivalent(ε)`, and **ε is not
  measured** — it is a chosen constant. Report it as a parameter, not a finding.
- G4.5's "comparable resolution quality" is comparable *on an authored corpus*. The bytes/CPU ratio
  is a real within-run measurement; the quality equivalence is bounded by the same confound as
  G4.10.

### 6.2 What the gate will very likely report

Stated in advance so that a failing gate is not mistaken for a failed wave, and so that no one is
tempted to restate a criterion until it passes (ADR-0113, and the single most useful defect class
found in Stage 2: *four gate numbers were structurally incapable of coming out differently*).

Expected: **G4.7, G4.8, G4.9, G4.11 PASS** (construction and bound properties, settleable now).
**G4.1 and G4.10 FAIL as UNMEASURED by design.** G4.3, G4.4, G4.6, G4.12 should pass if the
mechanisms are built correctly. G4.2 and G4.5 are the genuine open questions, and either could
legitimately fail.

Before believing any figure this gate prints, ask the Stage 2 question: **what input would make it
come out differently?** A criterion that cannot fail is not a criterion. Each `_check_*` must name,
in its `detail` string, the number that decided it.

---

## 7. The baselines Stage 4 must beat

These are the dumbest things that could work, and they are the comparison, not a formality. All
eight live in `pocketsec/stage4/labs/baselines.py`, all stdlib, all run in the **same process** as
the mechanism they control.

| id | baseline | what it is | the metric the advanced component must win on |
|---|---|---|---|
| **B1** | `SingleWorldMAP` | Keep only the single most probable explanation. Never branch, never spawn, never fission. One world, updated by the same tension terms. | **The control for the entire multi-world machinery (D4.5, D4.12).** Competing worlds must achieve higher world-set recall **and** lower premature-collapse rate at comparable `cpu_units` and `state_bytes`. If B1 matches recall at lower cost, the CBF is rejected and ADR-0036 says so. Expect B1 to be strong on synthetic data. |
| **B2** | `NaiveAncestryAttribution` | Every ancestor of the highest-ΔΦ node, unweighted, no interventions. | **Responsibility Flux (D4.6).** Must reach equal *chain recall* at fewer nodes inspected. Stage 2's measured precedent: the causal spine reached 5.0 nodes at chain recall 0.3611 against naive ancestry's 19.75 at 1.0 — concision bought with recall, and that **did not meet the criterion** (ADR-0122, cited). Flux must beat that trade, not repeat it. |
| **B3** | `AlwaysOnRichTelemetry` | Collect every optional signal, for every lineage, for the whole incident. `ObservationLevel.HIGH_RESOLUTION` everywhere, no planning. | **Active sensing (D4.9).** G4.5. Must reach quality within 0.02 at strictly lower `telemetry_bytes` **and** `cpu_units`. This is literally "turn everything on all the time" and it is the control the architecture's low-overhead claim rests on. |
| **B4** | `PhiThresholdPlaybook` | A fixed decision tree over `phi(state).total` thresholds and `StateDelta.bitmask()`: resolve / escalate / ignore by table. Depth ≤ 4, no worlds, no claims. | **Incident resolution as a whole (D4.2, D4.8).** Must beat B4 on Resolution Efficiency (§40) = correctly resolved incidents / (cpu_units + telemetry_bytes + analyst evidence load, where evidence load = claims a human must read). B4 has near-zero cost, so this is a demanding bar. |
| **B5** | `FixedWindowCorrelation` | Group transitions in a 60 s window per lineage; score by count and max ΔΦ. §42's cheap operational baseline. | **The claim that incident understanding needs latent state at all.** Must beat B5 on world-set recall and on unsupported-claim count. |
| **B6** | `TwoStateHMM` | A 2-state (benign / compromised) hidden Markov chain over the corpus operation vocabulary, forward algorithm in pure Python, transition and emission tables counted from the training split. §42's probabilistic latent-state baseline, and §46's falsifier 1 names it by name. | **The CBF as a latent-state estimator.** If B6 reaches equivalent incident quality and attribution at materially lower cost, **falsifier F1 fires and CBF/LUCID is rejected.** This is the single most important baseline in the table. |
| **B7** | `InformationGainPlanner` | Choose the observation with maximum expected entropy reduction over the world support vector. Ignores consequence, ignores cost. §42's simpler sensing baseline. | **The Utility formula of §16 and the free-energy objective of §18.** §18 is explicit: "If this objective does not outperform simpler information-gain planning, it is removed." `enable_free_energy` defaults off and only a measured win over B7 turns it on (ADR-0038). |
| **B8** | `NoStage4` | Stage 1's Φ path and `ThreatPredictionV1` alone. Zero worlds, zero claims, zero sensing. | **Whether Stage 4 adds anything at all.** §42's "pure DTL" row is void — DTL is rejected (ADR-0010) and beating a 22.3 µs/event rejected model proves nothing, exactly as Stage 3 found for its own G3.9. The honest control is Stage 1, whose Φ-oracle reached 0.7484 PR-AUC with **zero parameters and ~0 µs/event** (cited). Stage 4 must add measurable resolution quality over it, or the stage reduces to Stage 1 plus bookkeeping. |

**Declared as UNMEASURED, with reasons, in the honesty ledger — not silently omitted:**

| §42 baseline | why it is not built |
|---|---|
| Dynamic Bayesian network | needs numerical linear algebra; ADR-0030 forbids numpy in Stage 4. A hand-rolled stdlib DBN would be a worse comparison than none, because a slow or wrong baseline flatters the mechanism (`MEMORY.md` trap 5: a detached projection scored 0.55 and 0.94 once fixed). |
| Tiny GNN | same reason. |
| Provenance graph + scoring, Orthrus-like attribution | external systems; not present in this repository and not reimplementable honestly at this scale. B2 and B5 cover the cheap end of the same axis and are named as *partial* substitutes, not equivalents. |
| LLM incident summarizer | no language model exists in this repository. D4.15 measures the **guard** (`validate_verbalization`), which is the part that matters for hallucination cost; whether a real tiny LM helps is UNMEASURED. |

Three rules on every comparison, each of which this project has paid to learn:

1. **Every baseline must beat the corpus base rate** (`Stage2Dataset.base_rate`, `dataset.py:101`)
   or the comparison is **refused, not reported**. A model below chance is a bug.
2. **Run the saturation guard first.** If best and median are within 0.01, or a pooled order-free
   control is within 0.02 of best, the result is `DEGENERATE` and nothing is recorded.
3. **Same run, same seed family, same process, `/proc/loadavg` recorded.** Only within-run ratios
   transfer off this host.

---

## 8. What would falsify this stage's central claim

**The central claim.** *Maintaining a bounded set of competing security worlds, with
visibility-aware negative evidence and cost-aware active sensing, resolves incidents with fewer
unsupported claims and at lower total cost than committing to a single best explanation.*

Ten falsifiers, from §46, each bound to the check that would fire it. **A fired falsifier is a
result, and it goes in an ADR from the 0030–0039 block.**

| # | falsifier | fires when | consequence |
|---|---|---|---|
| **F1** | A simpler Bayesian/HMM or fixed-window correlator reaches equivalent incident quality and attribution at materially lower cost | B6 or B5 matches CBF/LUCID's world-set recall and unsupported-claim count at lower `cpu_units` + `state_bytes` in G4.10 | **CBF/LUCID rejected.** ADR-0036. Recommend reducing Stage 4 to B6 plus the typed claim graph — which is the one component with independent value |
| **F2** | CBF true-world retention is poor despite high resource use | G4.2 world-set recall < 0.9 while `state_bytes` exceeds B1's | the world field is not paying for itself; ADR-0036 |
| **F3** | World birth causes hypothesis explosion under benign novelty | over `build_corpus(split="train")` (benign only), spawn count > 1 per 100 transitions, or `BirthRefusal.NOT_SECURITY_RELEVANT` never fires | §12's residual gate is not working. **Novelty is not maliciousness**; a spawn per anomaly is the failure |
| **F4** | Negative-evidence reasoning produces unsafe conclusions under sensor loss | G4.4(c) fails: any case where a dropped sensor *raises* confidence or makes the verdict more committal | **the most dangerous single failure available to this stage.** Blocks the phase; report BLOCKED |
| **F5** | Counterfactual interventions do not improve attribution or sensor planning | B2 matches flux's chain recall at fewer nodes **and** removing `enable_counterfactual` does not lower G4.5's discrimination | D4.6 is removed. Precedent: ADR-0122 rejected Stage 2's counterfactual credit on exactly this measurement |
| **F6** | Identifiability testing cannot distinguish unresolved cases reliably | G4.3 non-identifiability accuracy < 1.0 on constructed pairs, **or** any `UNIDENTIFIABLE` returned with a non-empty `discriminating_observations` | D4.8 is broken, not merely weak. `UNIDENTIFIABLE` is the one output this stage exists to produce correctly |
| **F7** | Active sensing does not reduce total telemetry cost at comparable security quality | G4.5 fails for every `SensorAction` | D4.9 removed; fall back to Stage 1 AOP unchanged. ADR-0037 |
| **F8** | Self-questioning does not catch meaningful errors beyond ordinary validation | every `Challenge.material` is `False` across the corpus, or removing `enable_self_questioning` changes no claim and no verdict | D4.11 removed as NOT_YET_JUSTIFIED. Note the distinction: **NOT-YET-JUSTIFIED is not REJECTED** — on a corpus with no headroom, "found nothing" is uninformative (ADR-0009's lesson) |
| **F9** | Stage 3 feedback destabilizes trusted Knowledge Cells | a single contradiction produces a `CellStressSignalV1` (i.e. `MIN_CONTRADICTIONS_FOR_STRESS` is not honoured), or stress signals are produced for cells whose boundary the incident never entered | D4.14 removed. **No stage may be permanently unquestionable (§27), and no stage may be destabilised by one observation either** |
| **F10** | CBF/LUCID exceeds Edge resource targets or materially increases false incidents | `ResourceSampler` incremental RSS > `STAGE4_NORMAL_INCREMENTAL_RSS_BYTES`, or peak > `STAGE4_PEAK_CEILING_BYTES`, or false incidents per host-day rise against B8 | the 2 GB host target is a hard constraint and Stage 1–3 must stay comfortable on the same machine (§44). Blocks the phase |

**The single cheapest falsification to run, and therefore the first:** F4, inside
`tests/test_stage4_visibility.py`. It needs one corpus case, two replays and one inequality. If a
dropped sensor can raise confidence, the stage is unsafe and nothing else is worth measuring.

**The single most likely to fire:** F1 or F2, in G4.10, for the reasons in §6.1. Plan the ADR now.

---

## 9. Honest limits — what this wave cannot prove

1. **No visibility measurement of real Linux telemetry.** Every sensor path is a replay of a
   synthetic corpus. G4.1's telemetry-source clause is UNMEASURED and the check fails on it.
2. **No detection result of any kind.** Every corpus in this repository is synthetic and four of
   them produced only trivial or impossible tasks (ADR-0010). PR-AUC, false incidents per host-day
   and detection latency are reportable as harness output and are **not** detection claims.
3. **The value of competing worlds cannot be settled here.** §6.1's authorship confound: the wave
   that authors `GroundTruthWorld` also authors `mechanism_id`. What *can* be settled is whether the
   machinery is correct, bounded, isolated and honest — G4.7, G4.8, G4.9, G4.11.
4. **"Comparable resolution quality" in G4.5 is comparable on an authored corpus.** The bytes/CPU
   ratio is real; the quality equivalence carries the same confound.
5. **No absolute timing figure is a device measurement.** Load on this host swung 1.88 → 3.04 in
   twenty minutes of idle observation, and a Stage 2 gate saw a 7× inflation at load 23–67 (cited).
   Only within-run ratios transfer.
6. **`ruff` and `mypy` have still never been run in this repository** (`MEMORY.md`, "Known gap").
   Lint and strict-type status across Stage 4's new modules is UNVERIFIED unless this wave installs
   them, and it must say which.
7. **`anytime_valid` is `False` for almost every world.** D4.10's e-process guarantee holds only for
   the one null this module constructs. Any world updated from a model score has `anytime_valid =
   False` and its e-value is a bookkeeping quantity, not a statistical guarantee.
8. **The tiny-LM verbalizer is unmeasured** because no local model exists. Only its guard is
   measured.
9. **Two §42 baselines (DBN, tiny GNN) cannot be built** under ADR-0030, and two more (provenance
   scoring, Orthrus) are not available. Four of the nine named comparisons are therefore absent, and
   B2/B5 are partial substitutes, not equivalents.
10. **Calibration will very likely be under-sampled.** `CalibrationReport.ece` returns `None` below
    50 samples per epoch, by design, and the corpus may not reach it. `calibration_id` then stays
    `None` — which is the honest answer, and is exactly what Stage 1 does today
    (`calibration_id=None`, cited).
11. **`ε` in `observationally_equivalent` and every `MIN_*` / threshold constant in §4 is a chosen
    parameter, not a measured one.** They are declared as parameters in the findings document. A
    threshold reported as a finding is a fabricated result.

---

## 10. ADRs — block 0030–0039, all ten assigned

Verified free this session. Every ADR uses `docs/adr/0000-adr-template.md` and keeps its **Options
considered** table with a *measured consequence* column. An ADR whose options table has no measured
column is a design note, not an ADR.

| ADR | title | required before |
|---|---|---|
| **0030** | Stage 4 ships no `research/` package and no third-party import | package 1's first merge |
| **0031** | The typed claim graph is six classes, not a tagged string; authoritative emission is OBS/DER-rooted only | package 3 |
| **0032** | Non-identifiability is `Verdict.UNIDENTIFIABLE`; Stage 4 mints no parallel vocabulary, and the state→verdict table is the contract | package 7 |
| **0033** | Bounded K, claim-graph size and reasoning work: the chosen constants, and why the primary reasoning bound is work units rather than milliseconds on a contended host | package 5 |
| **0034** | Stage 4 is optional: the §45 degradation contract, and what a Stage 4 failure may and may not change | package 2 |
| **0035** | Active sensing routes through Stage 1 AOP; Stage 4 builds no second observation planner and raises no AOP cap | package 7 |
| **0036** | Competing worlds versus single-world MAP — the measured verdict | gate run; written whichever way it falls |
| **0037** | Active sensing versus always-on rich telemetry — the measured verdict | gate run |
| **0038** | The security free-energy objective: retained or removed against information-gain planning (§18 mandates removal on a loss) | gate run |
| **0039** | The Stage 5 handoff is plain JSON with a canonical digest, and the export-time unsupported-claim walk | package 8 |

0030–0035 and 0039 are design decisions and land with their package. **0036, 0037 and 0038 are
measurement ADRs and must not be written before the measurement exists.** ADR-0125's rule applies:
a rejection branch needs a *reproduced* measurement, not a flag and a filename.

No number outside 0030–0039 may be used. If an eleventh decision is needed, it amends an existing
ADR in the block.

---

## 11. The honesty ledger `docs/stage-4-findings.md` must end with

Verbatim in structure, per integration plan §7. G4.12 asserts all five headings are present, and the
phase is **not complete** without them.

```markdown
## Honesty ledger

### MEASURED
| claim | value | how it was produced (module:function) | experiment id | synthetic? |
|---|---|---|---|---|

### UNMEASURED
| claim the architecture makes | why not measured | what would measure it | blocking? |
|---|---|---|---|

### REJECTED
| component | measured effect | verdict (REJECTED / NOT-YET-JUSTIFIED / RETRACTED) | ADR |
|---|---|---|---|

### RETRACTED
| retracted claim | where it was published | the defect | corrected value |
|---|---|---|---|

### NOT A DETECTION RESULT
```

Rows that must appear in `UNMEASURED` no matter how the wave goes, because §9 already establishes
them: real-telemetry visibility; the DBN and tiny-GNN baselines; provenance/Orthrus attribution
comparison; the tiny-LM verbalizer; any calibration whose ECE came back `None`; and every threshold
constant reported as a parameter.

Three distinctions the format exists to keep:

- **NOT-YET-JUSTIFIED is not REJECTED.** On a corpus with no headroom, "no measured benefit" cannot
  demonstrate absence of benefit. ADR-0009 got this right under pressure and two of the three
  flagged components later turned out to be actively harmful on a corpus that *did* have headroom.
- **RETRACTED is not deleted.** `docs/stage-2-dtl-findings.md:336` retracts its own headline result
  and keeps the superseded text beside the defect that produced it. That is the standard.
- **`None` never means zero** (ADR-0004).

---

## 12. Completion output

At the end of the wave, print exactly the nine items `planning/PHASE_04_CLAUDE_CODE.md` requires:
status (`COMPLETE | PARTIAL | BLOCKED`); implemented checklist IDs (the phase file has one line, so
report D4.1–D4.19 individually); files changed; tests run with exact results; benchmark and resource
results **actually measured**; unresolved defects and risks; architecture deviations and ADRs; the
exact `MEMORY.md` and `PROGRESS.md` updates; and the recommended next phase **without starting it**.

`PARTIAL` with a truthful gate is the expected and acceptable outcome. Integration plan §9 is
explicit that Waves 4 and 5 may not run in parallel, so Stage 5 does not begin in this session
under any circumstances.
