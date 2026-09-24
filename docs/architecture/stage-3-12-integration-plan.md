# Stage 3–12 integration plan — the build contract for ten implementation waves

- **Status:** Accepted as the build contract. Binding on every Stage 3–12 implementation wave.
- **Date:** 2026-09-24
- **Supersedes:** nothing. **Extends:** ADR-0001, ADR-0002, ADR-0003, ADR-0005, ADR-0007, ADR-0008, ADR-0010.
- **Next free ADR number:** **0011** (`docs/adr/0000-…` through `0010-…` exist).

## 0. What this document is, and the honesty rules it inherits

Stages 0, 1 and 2 exist as code. Stages 3–12 exist as architecture documents and
`planning/PHASE_03_CLAUDE_CODE.md` … `PHASE_12_CLAUDE_CODE.md` checklists, and **nothing else**.
Ten waves will now build them. This document settles the mechanical questions that ten
independent waves would otherwise answer ten different ways.

Three inherited rules bind every wave and are restated because they are the ones most likely to
be broken by a wave that is going well:

1. **A number you did not produce by running code in this session does not exist.** Write
   `UNMEASURED`. §7 gives the required format.
2. **Documentation existing is never evidence that code exists.** `planning/PROGRESS.md` already
   says this. Verify by reading `.py` files.
3. **Do not invent module names, classes or signatures.** Every type named in §3 below was read
   out of a `.py` file in this repository and is cited `path:line`. Every type named in §3 as
   *exposed* does **not** exist yet and is a name this contract assigns.

### Verified state of the repository, as read this session

| Fact | Evidence |
|---|---|
| Stage 0 implemented | `pocketsec/stage0/**` — 21 modules, `gate.py:75 run_gate()`, 9 checks |
| Stage 1 implemented | `pocketsec/stage1/**` — 30 modules, `gate.py:89 run_gate()`, 13 checks |
| Stage 2 **partial** | real code in `core_ids.py`, `dataset.py`, `encoder/ssir_encoder.py`, `research/` (7 modules) |
| Stage 2 has **eleven empty subpackages** | `stage2/{adaptation,cache,compile_candidates,counterfactual,credit,lattice,predictors,router,state,uncertainty}/__init__.py` contain no symbols; `encoder/` is the only non-empty one |
| Stage 2 has **no gate and no CLI** | no `pocketsec/stage2/gate.py`, no `pocketsec/stage2/cli.py`; `pyproject.toml:20-22` declares only `pocketsec-stage0` and `pocketsec-stage1` |
| Stages 3–12 have **zero** code | `find pocketsec -name "*.py"` returns nothing under `stage3`…`stage12` |
| 283 test functions across 14 test modules | `grep -c "^def test_" tests/*.py` |
| `ruff` / `mypy` have never been run | `planning/MEMORY.md`, "Known gap". Still UNVERIFIED. |

**Consequence for wave planning: Stage 2 is not a finished stage that Stage 3 sits on top of.**
Its eleven empty packages are D2.6–D2.15, which ADR-0010 says *should not be built as specified*.
§6 settles what Stage 3 compiles from instead.

---

## 1. Package layout

### 1.1 The invariant shape

Every stage N ∈ {3…12} gets exactly this skeleton, mirroring `stage0/` and `stage1/`:

```
pocketsec/stage<N>/
    __init__.py            # EMPTY. Every existing stage __init__.py is empty; no re-exports.
    core_ids.py            # versioned functional IDs + REQUIRED/OPTIONAL, copying stage2/core_ids.py
    gate.py                # run_gate() -> GateReport, one check per acceptance criterion
    cli.py                 # main(argv: Sequence[str] | None = None) -> int
    <subsystem>/           # one package per architectural subsystem, stdlib-only
        __init__.py        # EMPTY
        <module>.py
    labs/                  # corpora, adversarial suites, simulations — stdlib-only
        __init__.py
    research/              # ONLY for stages listed in §2.3. numpy permitted. Never imported by runtime.
        __init__.py
```

Rules that are not negotiable:

- `__init__.py` files stay **empty**. Consumers import from the leaf module
  (`from pocketsec.stage3.cells.schema import KnowledgeCellV1`). This is the existing convention in
  all 61 runtime modules and the reason `pocketsec/stage1/__init__.py` is empty.
- No stage creates a module outside `pocketsec/` (ADR-0002, `tests/test_repository_structure.py:62`).
- No stage creates a second `contracts/` Python package. New wire schemas register through
  `pocketsec.stage0.contracts.common.register_schema` (`common.py:49`) and live in the stage's own
  subsystem package.
- A subsystem package with no symbols in it is a **defect**, not a placeholder. Stage 2's eleven
  empty packages are the anti-pattern; do not reproduce it. Create the package in the commit that
  fills it.

### 1.2 The exact layout, per stage

**Stage 3 — AICT + CRYSTAL** (`core_ids.py` prefix `AICT-F01…`)

```
stage3/{invariants/{anti_unification.py,discovery.py},
        boundary/{index.py,pressure.py},
        cells/{schema.py,field.py,fission.py},
        bytecode/{isa.py,verifier.py,vm.py},
        synthesis/{operators.py,selector.py},
        oracles/{dual_oracle.py,counterexamples.py},
        promotion/{shadow.py,assurance.py,decay.py},
        melting/{partial.py,full.py},
        gc/controller.py,
        slot.py, labs/{crystal_corpus.py,boundary_evasion.py}, research/distillation_baselines.py}
```

**Stage 4 — CBF + LUCID** (`CBF-F01…`)

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

**Stage 5 — SAFE + AEGIS + SENTINEL** (`SAFE-F01…`) — **stdlib-only, no `research/`, ever**

```
stage5/{constitution/{invariants.py,schema.py},
        operators/{algebra.py,catalog.py,d3fend.py},
        safe/action_field.py,
        aegis/{planner.py,pareto.py,cone.py,shadow.py},
        sentinel/{kernel.py,monitors.py},
        authority/{tokens.py,capability.py},
        twin/response_twin.py,
        evidence/preservation_gate.py,
        executor/{transactional.py,lease.py,verify.py,residual.py},
        recovery/safe_state.py,
        memory/effectiveness.py,
        cells/response_cells.py,
        labs/{fifty_experiments.py,toctou.py,adversarial_load.py}}
```

**Stage 6 — HELIOS + MNEMOSYNE** (`HEL-F01…`)

```
stage6/{constitution/learning.py,
        capsule/{experience_capsule.py,quarantine.py},
        provenance/{ledger.py,trust.py},
        memory/{episodic.py,semantic.py,procedural.py,half_life.py,competition.py},
        plasticity/{field.py,masks.py},
        rehearsal/counterfactual.py,
        fossils/{store.py,lineage.py},
        chamber/evolution.py,
        consolidator/mnemosyne.py,
        shadow/{mind.py,canary.py,rollback.py},
        conservation/gate.py,
        homeostasis/{drift.py,poisoning.py},
        export/quantized_candidates.py,
        fleet/package.py,
        labs/{endurance.py,poison_suite.py}, research/{continual_baselines.py,evolution.py}}
```

**Stage 7 — ORPHEUS + HIVELOCK** (`ORPH-F01…`)

```
stage7/{constitution/collective.py,
        capsule/{knowledge_capsule.py,compiler.py},
        privacy/{distiller.py,ledger.py},
        identity/{peer.py,integrity.py,revocation.py},
        relevance/{epistemic_distance.py,gravity.py},
        hivelock/{ingress.py,quarantine.py},
        graph/{dependence.py,sybil.py},
        echo/inference.py,
        antibody/forge.py,
        reconstruct/partial_world.py,
        campaign/hypergraph.py,
        novelty/collective.py,
        falsifier/consensus.py,
        governor/communication.py,
        aggregation/secure.py,
        labs/{byzantine_suite.py,partition.py,sybil_sim.py}}
```

**Stage 8 — PROMETHEUS + ORACLE + FORGE** (`PROM-F01…`)

```
stage8/{constitution/discovery.py,
        residual/{observatory.py,priority_field.py},
        genome/{hypothesis.py,grammar.py},
        prometheus/generators.py,
        ecology/{population.py,lineage.py},
        oracle/{planner.py,information_gain.py},
        laboratory/{counterfactual.py,metamorphic.py},
        doppelganger/engine.py,
        challenger/adversarial.py,
        identifiability/gate.py,
        ledger/{theory.py,negative_results.py},
        reproducibility/gate.py,
        novelty/prior_art_audit.py,
        forge/{compiler.py,tournament.py,package.py},
        adapters/{stage6.py,stage7.py},
        sandbox/{boundary.py,integrity.py},
        labs/eighty_experiments.py, research/{generators.py,tournament_models.py}}
```

**Stage 9 — ONTOGENESIS** (`ONTO-F01…`)

```
stage9/{spec/mssc.py,
        genome/computational.py,
        laplace/{state_discovery.py,law_discovery.py},
        foundry/{primitives.py,promotion.py},
        chemistry/typed_ir.py,
        renormalization/laboratory.py,
        symmetry/{conservation.py,suite.py},
        geometry/{causal.py,phase.py},
        compression/msdl.py,
        chronos/forgetting_law.py,
        daedalus/synthesizer.py,
        genesis/{variation.py,speciation.py},
        gaia/qd_ecology.py,
        argus/adversary.py,
        runtime/homeostatic.py,
        observatory/convergence.py,
        successor/proof_carrying.py,
        harness/hardware_in_loop.py,
        labs/one_twenty_experiments.py, research/{search.py,genome_eval.py}}
```

**Stage 10 — AEGIS PRIME** (`PRIME-F01…`)

```
stage10/{spec/assurance_state.py,
         themis/{contracts.py,epistemic_types.py},
         evidence/{dag.py,certificate.py},
         mirror/differential.py,
         janus/shadow.py,
         paradox/{disagreement.py,boundary.py},
         atlas/failure_atlas.py,
         sentinel/monitor_compiler.py,
         checksum/{semantic.py,merkle.py},
         reproducibility/capsule.py,
         ledger/{prediction.py,time_machine.py},
         numerics/quantization.py,
         faults/injection.py,
         phoenix/{safe_state.py,rollback.py},
         compiler/assurance.py,
         independence/common_mode.py,
         labs/one_hundred_experiments.py}
```

**Stage 11 — ETERNA** (`ETER-F01…`)

```
stage11/{spec/lifecycle.py,
         identity/kernel.py,
         lineage/{dag.py,inheritance.py},
         debt/{assurance_debt.py,promotion.py},
         tempus/epoch.py,
         atlas/capability_surface.py,
         morpheus/{migration.py,adapters.py},
         nexus/compatibility.py,
         ark/{capsule.py,minimum_reconstruction_set.py},
         reconstruct/harness.py,
         anchor/{signing.py,rotation.py},
         succession/{mnemosyne.py,regression.py},
         hibernia/demand_paged.py,
         palimpsest/retention.py,
         requiem/retirement.py,
         chronicle/corpus.py,
         cassandra/obsolescence.py,
         janitor/storage.py,
         labs/one_twenty_experiments.py}
```

**Stage 12 — CONSTELLATION Ω** (`CONST-F01…`)

```
stage12/{protocol/{constitution.py,wire.py},
         atom/{knowledge_atom_v2.py,canonical.py},
         knowledge/{proof.py,falsification.py,negative.py},
         trustgraph/{graph.py,genealogy.py},
         quorum/independence.py,
         immune/{byzantine.py,poison.py},
         privacy/{veil.py,prism.py},
         shard/{store.py,merkle.py},
         resonance/convergence.py,
         causality/transportability.py,
         mosaic/composition.py,
         divergence/{monoculture.py,mendel.py},
         sanctum/sandbox.py,
         genesis/local_compiler.py,
         eclipse/isolation.py,
         attestor/rats_bridge.py,
         economy/{oracle.py,market.py,entropy.py},
         labs/{one_sixty_experiments.py,population_sim.py}}
```

---

## 2. Dependency boundary — ADR-0001 and ADR-0008 as a mechanical rule

### 2.1 The two rules, restated mechanically

**R1 (ADR-0001).** Every `.py` file under `pocketsec/` whose path does **not** start with a
prefix in the research allow-list may import only names whose root module is in
`sys.stdlib_module_names` or is `pocketsec`.

**R2 (ADR-0008).** No file under `pocketsec/` outside the research allow-list may contain an
`ast.Import` or `ast.ImportFrom` node naming a module that starts with `pocketsec.stage<N>.research`
— for **any** N. The boundary is one-directional: research may import runtime; runtime may never
import research.

### 2.2 The tests that enforce them — by name

| Rule | Enforcing test | File:line |
|---|---|---|
| R1 | `test_runtime_has_no_third_party_imports` | `tests/test_repository_structure.py:121` |
| R2 | `test_runtime_never_imports_research_code` | `tests/test_repository_structure.py:89` |
| R1 (declaration half) | `test_pyproject_declares_no_runtime_dependencies` | `tests/test_repository_structure.py:141` |
| weak companion — **do not rely on it** | `test_research_package_is_the_only_numpy_user` | `tests/test_repository_structure.py:111` |

**When asked "which existing test enforces the boundary", the answer is
`tests/test_repository_structure.py::test_runtime_has_no_third_party_imports` for the stdlib rule
and `::test_runtime_never_imports_research_code` for the one-directional rule.**

`test_research_package_is_the_only_numpy_user` asserts only `assert using_numpy` — that *at least
one* research module contains the substring `import numpy`. It is a substring match on file text,
not AST, and it checks no exclusivity. Its name overstates what it does. It is not the boundary.

### 2.3 The defect that blocks Wave 3, and the ADR that fixes it

`tests/test_repository_structure.py:73` reads:

```python
RESEARCH_PREFIX = "pocketsec/stage2/research/"
```

and `:86` independently hard-codes the same path a second time:

```python
return sorted((REPO_ROOT / "pocketsec" / "stage2" / "research").rglob("*.py"))
```

As written, `pocketsec/stage3/research/` is a **runtime** directory by R1's definition: a numpy
import in it fails `test_runtime_has_no_third_party_imports`. Widening the prefix is a change to
the ADR-0008 boundary, not a test edit.

**Decision.** **ADR-0011 is pre-assigned to this change and must be the first artifact of Wave 3.**
It replaces the literal with a single tuple that both helpers consume:

```python
RESEARCH_PREFIXES: tuple[str, ...] = (
    "pocketsec/stage2/research/",
    "pocketsec/stage3/research/",
    "pocketsec/stage6/research/",
    "pocketsec/stage8/research/",
    "pocketsec/stage9/research/",
)
```

and `_research_modules()` must be derived from `RESEARCH_PREFIXES`, not from a second literal, so
the hole described in `docs/architecture/interfaces/tests-and-tooling.md` Trap 5 cannot reopen.

### 2.4 Which stages may have a `research/` package — closed list

| Stage | `research/` | Reason |
|---|---|---|
| 3 | **yes** | distillation/compilation baselines need gradient descent to be strong (same argument as ADR-0008) |
| 4 | no | bounded-K world enumeration is combinatorial, not numerical; must run on the endpoint |
| 5 | **no, permanently** | privilege. A numpy import here is a supply-chain path into the executor |
| 6 | **yes** | continual-learning baselines and the evolution chamber train models |
| 7 | no | signing (`hashlib`/`hmac`), graph and counting work; the Sybil simulation is `stage7/labs/` |
| 8 | **yes** | discovery is explicitly off-endpoint (Phase 8 gate: "research cost is allowed to be high offline") |
| 9 | **yes** | architecture search is explicitly off-endpoint |
| 10 | no | assurance runs beside production; its overhead is the thing being measured |
| 11 | no | continuity is bookkeeping and cryptography |
| 12 | no | protocol, graph and simulation; the 100k-node population sim is `stage12/labs/` |

A wave that wants a `research/` package not on this list must write its own ADR and amend
`RESEARCH_PREFIXES`. It may not add the directory first and the ADR later.

### 2.5 The artifact rule that makes the boundary survivable

Training emits **plain data** — weights, codebooks, transition tables, bytecode — into
`models/experimental/` or `models/compiled/`. The stdlib runtime loads that data. The runtime
never holds a reference to a research class. Concretely: Stage 3's Cell VM
(`stage3/bytecode/vm.py`) loads a serialised cell package; it must never import
`pocketsec.stage2.research.dtl_conv.DTLConvModel` (`dtl_conv.py:145`) to consult a teacher at
runtime. Teacher consultation happens offline, in `stage3/research/`, and its result is a signed
artifact.

---

## 3. The seam between stages

Types marked ✔ exist and are cited. Types with no citation are **new names this contract assigns**;
a wave must create them at exactly the module path in §1.2 and register their schema id through
`register_schema` (`pocketsec/stage0/contracts/common.py:49`).

### 3.1 The substrate every stage may consume

| Type | Path:line |
|---|---|
| `SecurityEventV1`, `SecurityEventSequenceV1` ✔ | `stage0/contracts/security_event_v1.py:44`, `:107` |
| `ThreatPredictionV1`, `Verdict`, `ComputePath`, `EvidenceRelevance`, `NextEventExpectation` ✔ | `stage0/contracts/threat_prediction_v1.py:143`, `:66`, `:84`, `:98`, `:114` |
| `ModelSlot`, `validate_slot` ✔ | `stage0/contracts/model_slot.py:41`, `:57` |
| `EvidenceRef`, `ContractError`, `register_schema` ✔ | `stage0/contracts/common.py:125`, `:32`, `:49` |
| `run_benchmark`, `BenchmarkCase`, `BenchmarkResult` ✔ | `stage0/benchmark/harness.py:133`, `:43`, `:92` |
| `SequenceDataset`, `LabelledSequence` ✔ | `stage0/benchmark/dataset.py:53`, `:36` |
| `ResourceSampler`, `ResourceMetrics` ✔ | `stage0/benchmark/resource_metrics.py:103`, `:58` |
| `check_profile`, `ProfileReport`, `PROFILES` ✔ | `stage0/benchmark/profiles.py:85`, `:62`, `:36` |
| `SecurityMetrics`, `evaluate_scores` ✔ | `stage0/benchmark/security_metrics.py:178`, `:211` |
| `GateCheck`, `GateReport` ✔ | `stage0/gate.py:45`, `:56` |
| `SeedSet` ✔ | `stage0/repro/seeds.py:24` |
| `ExperimentRegistry.register`, `format_experiment_id` ✔ | `stage0/experiments/registry.py:138`, `stage0/experiments/ids.py:56` |
| `RawEventV1`, `EvidenceEvent`, `SensorPath` ✔ | `stage1/telemetry/raw_event_v1.py:56`, `:142`, `:41` |
| `SSIRTransitionV1`, `RepresentationLevel`, `TemporalContext` ✔ | `stage1/ssir/transition.py:82`, `:39`, `:49` |
| `Entity`, `SemanticBelief`, `SemanticProperty`, `EntityKind` ✔ | `stage1/ssir/entities.py:238`, `:118`, `:64`, `:34` |
| `Relation`, `RelationFamily`, `family_of` ✔ | `stage1/ssir/relations.py:19`, `:56`, `:95` |
| `SSIRCodec`, `LAYOUTS`, `LEVEL_FIELDS` ✔ | `stage1/ssir/codec.py:105`, `:45`, `:70` |
| `SecurityStateV1`, `StateDelta`, `DIMENSIONS` ✔ | `stage1/state/security_state.py:122`, `:181`, `:108` |
| `phi`, `delta_phi`, `PhiBreakdown`, `calibrate` ✔ | `stage1/state/potential.py:170`, `:195`, `:147`, `:237` |
| `NoveltyEngine`, `NoveltyTensor` ✔ | `stage1/novelty/engine.py:103`, `:46` |
| `CountMinSketch`, `StableBloomFilter`, `BoundedLRUCounter`, `EWMA` ✔ | `stage1/novelty/sketches.py:39`, `:97`, `:186`, `:244` |
| `EpochModel`, `Epoch`, `SystemIdentity`, `EpochDecision` ✔ | `stage1/epoch/model.py:136`, `:105`, `:55`, `:81` |
| `CausalMemory`, `CausalNode`, `CausalResolution`, `causal_signature` ✔ | `stage1/causal/memory.py:155`, `:83`, `:73`, `:47` |
| `AdaptiveObservationPolicy`, `AOPBudget`, `ObservationLevel`, `MANDATORY_SIGNALS` ✔ | `stage1/observation/policy.py:151`, `:60`, `:39`, `:47` |
| `AggregationPolicy`, `AggregationThresholds` ✔ | `stage1/aggregation/policy.py:163`, `:42` |
| `SemanticCompiler`, `EntityRegistry`, `OperationRule`, `classify_operation` ✔ | `stage1/compiler/semantic_compiler.py:69`, `entity_registry.py:78`, `rules.py:37`, `rules.py:275` |
| `Stage1Pipeline`, `ScenarioResult` ✔ | `stage1/pipeline.py:78`, `:47` |
| `SSIRSlotBase`, `StateCalculusSlot`, `NoveltyStatisticalSlot` ✔ | `stage1/slot.py:50`, `:104`, `:155` |
| `Behaviour`, `Scenario`, `build_corpus` ✔ | `stage1/labs/corpus.py:34`, `:45`, `:220` |
| `build_hard_corpus`, `build_long_horizon_corpus`, `build_ambiguous_corpus` ✔ | `stage1/labs/hard_corpus.py:249`, `longhorizon_corpus.py:170`, `ambiguous_corpus.py:268` |
| `run_guillotine`, `ParetoReport`, `LogisticProbe` ✔ | `stage1/guillotine/ablation.py:299`, `:145`, `features.py:129` |
| `run_adversarial_suite`, `AdversarialReport` ✔ | `stage1/labs/adversarial.py:322`, `:58` |
| `ExecutionPath`, `PATH_COST_UNITS`, `FunctionClass`, `CoreFunction` ✔ | `stage2/core_ids.py:43`, `:62`, `:36`, `:72` |
| `EncodedTransition`, `encode_ssir_transition`, `FEATURE_LAYOUT` ✔ | `stage2/encoder/ssir_encoder.py:143`, `:195`, `:94` |
| `Stage2Sample`, `Stage2Dataset`, `build_dataset` ✔ | `stage2/dataset.py:38`, `:72`, `:147` |
| research only: `DTLConvModel`, `SurpriseVector`, `TCNBaseline`, `PhiOracleBaseline`, `BASELINE_REGISTRY` ✔ | `stage2/research/dtl_conv.py:145`, `dtl.py:103`, `baselines.py:345`, `:552`, `:582` |

### 3.2 Per-stage seam

**Stage 3 — AICT + CRYSTAL**

- *Consumes:* `SSIRTransitionV1`, `SecurityStateV1`, `StateDelta`, `phi`/`delta_phi`,
  `Entity`/`SemanticProperty` (the anti-unification lattice at
  `stage3/invariants/anti_unification.py` generalises over `SemanticProperty`, **never** over
  `Entity.display_name` — ADR-0006/0007), `EncodedTransition`, `Stage2Sample`, `Stage2Dataset`,
  `ScenarioResult`, `ExecutionPath`. Offline only, inside `stage3/research/`: `DTLConvModel` as
  teacher oracle A.
- *Exposes:* `KnowledgeCellV1` (`stage3/cells/schema.py`, schema id
  `pocketsec.knowledge_cell.v1`), `KnowledgeField`, `BoundaryIndex`, `BoundaryPressureReport`,
  `Invariant`, `CellBytecode`/`CellISA`/`CellVerifier`/`CellVM`, `DualOracleVerdict`,
  `CounterexampleStore`, `AssuranceState`, `MeltReport`, and `CrystalSlot(ModelSlot)` returning
  `ThreatPredictionV1` with `compute_path=ComputePath.CHEAP_TRANSITION` for a cell hit.
- *Binding:* the architecture document's "Boundary Index → K17/K44/K219 → Cell Resolver → security
  state / evidence / escalation" (source doc line 166) binds to: `BoundaryIndex.lookup()` returns
  `KnowledgeCellV1 | None`; `CellVM.run()` returns a `StateDelta` plus
  `tuple[EvidenceRef, ...]`; escalation is an `EscalationDecision`
  (`stage1/observation/policy.py:93`), not a new type.

**Stage 4 — CBF + LUCID**

- *Consumes:* `SSIRTransitionV1`, `SecurityStateV1`, `CausalMemory`/`CausalNode` (worlds are
  hypotheses over the causal spine, `CausalMemory.spine()` at `memory.py:256`),
  `AdaptiveObservationPolicy` (active sensing issues AOP escalations, it does not invent a second
  observation path), `KnowledgeCellV1` and `ThreatPredictionV1`.
- *Exposes:* `SecurityWorldV1` (`stage4/worlds/world.py`), `CausalBeliefField`,
  `VisibilityModel`, `SensorShadow`, `EvidenceTension`, `TypedClaim` with the closed tag set
  `OBS | DER | INF | CF | EXT | UNK`, `ClaimGraph`, `IdentifiabilityVerdict`,
  `ResolutionHorizon`, `ObservationRequest`, `IncidentHypothesis`.
- *Binding:* "competing security worlds" binds to a bounded `tuple[SecurityWorldV1, ...]` with an
  explicit `max_worlds`. "Non-identifiable" is `Verdict.UNIDENTIFIABLE`
  (`threat_prediction_v1.py:66`) — **not a new enum**.

**Stage 5 — SAFE + AEGIS + SENTINEL**

- *Consumes:* `IncidentHypothesis`, `TypedClaim`, `ClaimGraph`, `SecurityWorldV1`,
  `SecurityStateV1`, `EvidenceRef`, `KnowledgeCellV1`. Reads `ThreatPredictionV1` **as evidence
  only**; a verdict is an input to planning, never an authorisation (ADR-0003).
- *Exposes:* `ResponseConstitution`, `MissionInvariant`, `DefensiveOperator` (the **only** type
  the executor accepts), `CapabilityToken`, `AuthorityGrant`, `ActionField`, `ResponsePlan`,
  `InterventionCone`, `ActionShadow`, `SentinelVerdict`, `EvidencePreservationVerdict`,
  `Lease`, `TransactionReceipt`, `InterventionResidual`, `SafeStatePlan`,
  `EffectivenessRecord`.
- *Binding:* "typed operator algebra" binds to a closed `DefensiveOperator` registry in
  `stage5/operators/catalog.py`. `stage5/executor/transactional.py` accepts
  `DefensiveOperator` **only** — no `str`, no `dict`, no field whose name appears in
  `FORBIDDEN_AUTHORITY_FIELDS` (`threat_prediction_v1.py:48`).

**Stage 6 — HELIOS + MNEMOSYNE**

- *Consumes:* everything stages 1–5 produce as *outcomes*: `ScenarioResult`,
  `SSIRTransitionV1`, `ThreatPredictionV1`, `TransactionReceipt`, `InterventionResidual`,
  `KnowledgeCellV1`, `EpochDecision`, `SystemIdentity`. Also `ProfileReport` so a promotion can be
  refused on resource grounds.
- *Exposes:* `ExperienceCapsuleV1`, `QuarantineVerdict`, `ProvenanceLedger`, `TrustRecord`,
  `EpisodicMemory`/`SemanticMemory`/`ProceduralMemory`, `EpistemicHalfLife`,
  `PlasticityField`, `PlasticityMask`, `KnowledgeFossil`, `KnowledgeLineageDAG`,
  `EvolutionChamber`, `Consolidation`, `ShadowMind`, `ConservationVerdict`,
  `CanaryReport`, `LearningRollback`, `QuantizedCandidate`.
- *Binding:* **this is the single admission gate for stages 7, 8, 9 and 12.**
  `QuarantineGateway.admit(capsule: ExperienceCapsuleV1) -> QuarantineVerdict` is the only
  function in the repository through which a foreign or research artifact may become trusted.
  "Epoch" binds to `Epoch` (`stage1/epoch/model.py:105`); Stage 6 does not define a second one.

**Stage 7 — ORPHEUS + HIVELOCK**

- *Consumes:* `KnowledgeCellV1`, `QuantizedCandidate`, `ExperienceCapsuleV1`,
  `KnowledgeLineageDAG`, `CausalNode`, `SSIRTransitionV1` semantics for distillation.
- *Exposes:* `KnowledgeCapsuleV1` (signed, wire-facing), `PeerIdentity`, `PrivacyLedger`,
  `LeakageMeasurement`, `EpistemicDistance`, `KnowledgeGravity`, `IngressVerdict`,
  `DependenceGraph`, `SybilReport`, `EchoInference`, `KnowledgeAntibody`,
  `PartialWorld`, `CampaignHypergraph`, `CollectiveNovelty`, `ConsensusFalsification`,
  `Revocation`, `CommunicationBudget`.
- *Binding:* `IngressVerdict` never promotes. Its terminal success state is "eligible for
  Stage 6", expressed as an `ExperienceCapsuleV1` handed to `QuarantineGateway.admit`.

**Stage 8 — PROMETHEUS + ORACLE + FORGE**

- *Consumes:* `ScenarioResult`, `ThreatPredictionV1` residuals, `ParetoReport`,
  `Stage2Dataset`, `SecurityMetrics`, `ResourceMetrics`, `Hypothesis`
  (`stage0/hypotheses.py:32`), `PriorArtLedger` (`stage0/prior_art.py:72`).
- *Exposes:* `DiscoveryConstitution`, `ResidualObservatory`, `PriorityField`,
  `HypothesisGenome`, `MechanismGrammar`, `HypothesisPopulation`, `ExperimentPlan`,
  `InformationGain`, `MetamorphicRelation`, `BenignDoppelganger`, `AdversarialChallenge`,
  `IdentifiabilityGate`, `TheoryLedger`, `NegativeResult`, `ReproducibilityVerdict`,
  `NoveltyAudit`, `DiscoveryPackageV1`, `TournamentResult`.
- *Binding:* "every hypothesis has explicit falsification conditions" binds to a required
  non-empty `HypothesisGenome.falsifiers: tuple[Falsifier, ...]`, validated in `__post_init__`
  the way `ThreatPredictionV1._validate_abstention` (`threat_prediction_v1.py:187`) validates.
  A `DiscoveryPackageV1` reaches an endpoint only as an `ExperienceCapsuleV1` through Stage 6.

**Stage 9 — ONTOGENESIS**

- *Consumes:* `DiscoveryPackageV1`, `TournamentResult`, `ParetoReport`, `ProfileReport`,
  `ResourceMetrics`, `CellBytecode`/`CellISA` (a discovered computation must compile to a form
  Stage 3's verifier can check), `DIMENSIONS` and `SemanticProperty` as the typed vocabulary a
  genome may reference.
- *Exposes:* `ComputationalGenomeV1`, `DiscoveredLaw`, `DiscoveredState`, `Primitive`,
  `PromotionVerdict`, `TypedIR`, `RenormalizationResult`, `SymmetryTest`,
  `ConservationTest`, `PhaseObservation`, `MSDLScore`, `ForgettingLaw`,
  `SynthesizedSystem`, `Speciation`, `QualityDiversityArchive`, `ArgusAttack`,
  `HomeostaticController`, `ProofCarryingSuccessorV1`, `HardwareMeasurement`.
- *Binding:* `ComputationalGenomeV1` must carry a declared `max_state_bytes` and
  `max_steps_per_event`; "bounded-state/loop/resource contracts" is not prose, it is two required
  integer fields the `TypedIR` verifier checks.

**Stage 10 — AEGIS PRIME**

- *Consumes:* `ProofCarryingSuccessorV1`, `KnowledgeCellV1`, `ThreatPredictionV1`,
  `TypedClaim`, `ClaimGraph`, `EvidenceRef`, `EnvironmentFingerprint`
  (`stage0/repro/environment.py:55`), `SeedSet`, `BenchmarkResult`, `SecurityMetrics`.
- *Exposes:* `AssuranceEnvelope`, `ThemisContract`, `EpistemicType`, `EvidenceDAG`,
  `AssuranceCertificateV1`, `DifferentialResult`, `ShadowDisagreement`,
  `BoundaryProbe`, `FailureAtlas`, `RuntimeMonitor`, `SemanticChecksum`,
  `MerkleRegression`, `ProvenanceCapsuleV1`, `PredictionLedger`,
  `QuantizationEnvelope`, `FaultInjection`, `SafeStatePhenotype`,
  `IndependenceReport`.
- *Binding:* "every production alert has a valid typed evidence path" binds to:
  every `ThreatPredictionV1` that Stage 10 certifies must resolve to a non-empty
  `EvidenceDAG` path terminating in `EvidenceRef` digests, **or** carry an explicit
  `AssuranceEnvelope` degradation. `AssuranceState` is Stage 3's type; Stage 10 extends it, it
  does not fork it.

**Stage 11 — ETERNA**

- *Consumes:* `AssuranceCertificateV1`, `AssuranceEnvelope`, `KnowledgeLineageDAG`,
  `KnowledgeFossil`, `ComputationalGenomeV1`, `ProofCarryingSuccessorV1`,
  `SystemIdentity`, `Epoch`, `ProvenanceCapsuleV1`, `SSIR_TRANSITION_V1_VERSION` and the
  `SCHEMA_REGISTRY` (`stage0/contracts/common.py:46`) as the compatibility surface.
- *Exposes:* `ComputationalIdentity`, `AncestryDAG`, `Inheritance`, `AssuranceDebt`,
  `TempusEpoch`, `CapabilityValiditySurface`, `Migration`, `Adapter`, `LossSemantics`,
  `CompatibilityContract`, `ArkCapsuleV1`, `MinimumReconstructionSet`,
  `ReconstructionDrill`, `SigningSuite`, `KeyRotation`, `SuccessionVerdict`,
  `HibernatedIntelligence`, `RetentionDecision`, `RetirementRecord`,
  `ObsolescenceRisk`, `StorageBudget`.
- *Binding:* "a descendant cannot silently inherit assurance it has not earned" binds to
  `Inheritance` carrying an `AssuranceDebt` that `PromotionController` refuses to clear
  without a fresh `AssuranceCertificateV1`.

**Stage 12 — CONSTELLATION Ω**

- *Consumes:* `KnowledgeCapsuleV1`, `PeerIdentity`, `DependenceGraph`,
  `DiscoveryPackageV1`, `ComputationalGenomeV1`, `ArkCapsuleV1`,
  `AssuranceCertificateV1`, `CellBytecode`.
- *Exposes:* `SecurityKnowledgeAtomV2`, `CanonicalForm`, `ProofPackage`,
  `FalsificationPackage`, `NegativeKnowledge`, `TrustGraph`, `EvidenceGenealogy`,
  `IndependenceVerdict`, `ByzantineReport`, `PoisonContainment`, `VeilTransform`,
  `PrismMeasurement`, `ShardStore`, `ConvergenceEvidence`,
  `TransportabilityVerdict`, `Composition`, `MonocultureReport`,
  `SanctumVerdict`, `LocalRecompilation`, `IsolationControl`, `AttestationBridge`,
  `ValidationSchedule`.
- *Binding:* `SanctumVerdict` is **not** a promotion. Local adoption is
  `LocalRecompilation` → `ExperienceCapsuleV1` → `QuarantineGateway.admit`. "Sovereignty Loss
  remains zero by construction" binds to import rule T3 in §4.

---

## 4. Trust / authority topology — as testable import rules

Each rule below is an AST check over `pocketsec/`, in the shape of
`test_runtime_never_imports_research_code` (`tests/test_repository_structure.py:89`). All seven live
in one new module, **`tests/test_stage_trust_topology.py`**, added in Wave 3 and extended (never
relaxed) by later waves. Each rule states an allow-list; anything else is an offender.

| ID | Rule | Invariant preserved |
|---|---|---|
| **T1** | No module under `pocketsec/stage5/` may import from `pocketsec/stage2/`, `stage3/research/`, `stage6/research/`, `stage8/`, `stage9/`, `stage12/`, or any `*/research/*`. Stage 5's only upstream imports are `stage0`, `stage1`, `stage4`, `stage3.cells`, `stage3.bytecode`. | only Stage 5 typed operators touch privilege; no research artifact reaches the executor |
| **T2** | No module under `pocketsec/stage7/`, `stage8/`, `stage9/` or `stage12/` may import anything under `pocketsec/stage5/`. | no collective/research path to response authority |
| **T3** | The only module that may import `pocketsec.stage7.*`, `pocketsec.stage8.forge.*`, `pocketsec.stage9.successor.*` or `pocketsec.stage12.*` **into** the trusted local path is `pocketsec/stage6/capsule/quarantine.py`. | no foreign/collective/research artifact reaches production without the Stage 6 quarantine path |
| **T4** | No module outside `pocketsec/stage5/executor/` may import `TransactionReceipt`'s producing function. `pocketsec/stage5/executor/transactional.py` may accept only `DefensiveOperator`; the test asserts its public entry point's annotated parameter type is exactly `DefensiveOperator`. | no arbitrary natural-language-to-privileged-shell path |
| **T5** | No module under `pocketsec/stage3/`…`stage12/` may define a class or dataclass field whose lowercased name contains any member of `FORBIDDEN_AUTHORITY_FIELDS` (`threat_prediction_v1.py:48`), except under `pocketsec/stage5/`. | no model output carries authority (ADR-0003, generalised past Stage 0) |
| **T6** | No module under `pocketsec/stage10/` may be imported by `stage1`…`stage9` or `stage11`/`stage12`. Assurance observes; it is never in a detection or response call path. | assurance cannot become load-bearing and then fail silently |
| **T7** | `pocketsec/stage4/`, `stage7/`, `stage8/`, `stage9/`, `stage10/`, `stage11/`, `stage12/` may not be imported by `pocketsec/stage1/` or `pocketsec/stage2/`. Stage 1–2 detection must run with every later stage absent. | "the endpoint remains useful with Stage 7–9 networking/research completely absent" (Phase 9 gate); "Stage 4 remains optional to core Stage 1–3 detection if it crashes" (Phase 4 gate) |

**T3 is the load-bearing one.** Express it as: collect every `Import`/`ImportFrom` under
`pocketsec/` naming a module in the untrusted set; assert the importing path is exactly
`pocketsec/stage6/capsule/quarantine.py`. A wave that needs another importer is asking to move the
quarantine boundary, which requires an ADR from its reserved block (§5.5).

---

## 5. Shared conventions

### 5.1 Gate module and CLI — copy `pocketsec/stage1/gate.py`'s shape

Required shape, verified against `stage1/gate.py`:

```python
# pocketsec/stage<N>/gate.py
from pocketsec.stage0.gate import GateCheck, GateReport   # stage1/gate.py:16

@dataclass
class Stage<N>GateContext:                                 # stage1/gate.py:55
    """One shared run, so K checks do not replay the corpus K times."""
    @classmethod
    def build(cls) -> Stage<N>GateContext: ...             # stage1/gate.py:69

def run_gate() -> GateReport:                              # stage1/gate.py:89
    ctx = Stage<N>GateContext.build()
    return GateReport(checks=(_check_one(ctx), ..., _check_k(ctx)))
```

Each `_check_*` returns a `GateCheck` built by **running the real subsystem**, never by reading a
document. The one exception in Stage 0 (`_check_objective_frozen`, `gate.py:92`, which greps a
spec file) is not to be copied.

CLI, verified against `stage0/cli.py:45` and `stage1/cli.py:41`:

```python
# pocketsec/stage<N>/cli.py
def main(argv: Sequence[str] | None = None) -> int:
```

with `--json` as a top-level flag, a required subparser (`dest="command", required=True`), a
`gate` subcommand always present, and `print()` allowed **only here** — every other runtime module
is covered by `test_no_debug_prints_outside_the_cli`
(`tests/test_repository_structure.py:152`).

Each stage adds `pocketsec-stage<N> = "pocketsec.stage<N>.cli:main"` to `[project.scripts]`
(`pyproject.toml:20-22`) and a step to the `gate` job of `.github/workflows/ci.yml` alongside the
existing Stage 0/Stage 1 steps, invoked as `python -m pocketsec.stage<N>.cli gate` with
`PYTHONHASHSEED: "0"`. **That job runs a bare `pip install -e .`, so a gate module must be
stdlib-only.** A gate that needs numpy cannot be a gate.

**Exact check counts**, one per acceptance criterion in the phase file, asserted in the stage's own
test module (never by editing a closed stage's count — `tests-and-tooling.md` §5.9):

| Stage | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 |
|---|---|---|---|---|---|---|---|---|---|---|
| checks | 13 | 12 | 15 | 13 | 11 | 12 | 10 | 10 | 10 | 10 |

**Stage 2 owes a gate.** It has none, and `planning/PROGRESS.md` records its gate as FAILED on
evidence from `tests/` and `results/` rather than from a `run_gate()`. Wave 3's first coding task
is `pocketsec/stage2/gate.py` with 13 checks (the thirteen criteria in
`planning/PHASE_02_CLAUDE_CODE.md`), which must report FAILED reproducibly. **A stage cannot be
declared failed by prose.**

### 5.2 Experiment ids and the hypothesis registry

Format is frozen: `PS-S<stage>-<YYYYMMDD>-<H#|BASE>-<slug>-<NNNN>`
(`stage0/experiments/ids.py:26`). `<NNNN>` is a **per-stage** counter — the registry shows
`PS-S1-…-0001`, `-0002` and `PS-S2-…-0001` … `-0006`, so Stage 3 starts at `0001`.

`format_experiment_id` (`ids.py:56`) validates the *shape* `H\d{1,2}` but **not** membership in
`HYPOTHESES` (`stage0/hypotheses.py:88`), which today holds H0–H8 only. Using `H9` today produces
a well-formed id backed by no hypothesis.

**Decision.** Each stage gets one new hypothesis, and adding it is gated:

| Stage | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 |
|---|---|---|---|---|---|---|---|---|---|---|
| hypothesis | H9 | H10 | H11 | H12 | H13 | H14 | H15 | H16 | H17 | H18 |

`tests/test_harness_and_gate.py:241` asserts `set(ledger.entries) == set(HYPOTHESES)`. Therefore
appending to `_HYPOTHESES` (`stage0/hypotheses.py:50`) **fails the suite** unless a matching entry
is added to `docs/prior-art/ledger.json` in the same commit. That coupling is a feature: a new
hypothesis cannot exist without a prior-art entry. **ADR-0012 is pre-assigned to this change**, and
it must add all ten hypotheses and all ten ledger entries at once, at
`literature_status: "NOT_REVIEWED"`. A wave may not silently reuse H8 ("Combined NERA
architecture") for unrelated work.

Existing hypotheses stay bound to their existing meaning. A Stage 3 experiment that is genuinely
testing H4 ("Neural-to-symbolic JIT compilation") uses `H4`; one testing Stage 3's own combined
design uses `H9`.

### 5.3 How to record a measurement

There is exactly one path, and no wave may add a second:

1. Wrap the model as a `ModelSlot` (`stage0/contracts/model_slot.py:41`) — one `predict()` from
   `SecurityEventSequenceV1` to `ThreatPredictionV1`. Stage 1 shows how
   (`stage1/slot.py:104`, `:155`).
2. Build a checksum-bound `SequenceDataset` (`stage0/benchmark/dataset.py:53`).
3. Call `run_benchmark(slot, dataset, case, *, experiment_id, seeds, synthetic_data, model_bytes)`
   (`stage0/benchmark/harness.py:133`). **`synthetic_data` is required and travels with the
   result.** Every corpus in this repository today is synthetic, so it is `True` until real
   telemetry exists.
4. Write the returned `BenchmarkResult.to_dict()` to
   `results/<experiment_id>.json`.
5. Append to the ledger with `ExperimentRegistry.register(...)`
   (`stage0/experiments/registry.py:138`) — append-only, digest-chained, no update or delete API.

A resource figure that did not come from `ResourceSampler`
(`stage0/benchmark/resource_metrics.py:103`) is UNMEASURED. A PR-AUC that did not come from
`evaluate_scores` (`security_metrics.py:211`) is UNMEASURED. **`results/*.json` is git-ignored
except `README.md`** (`tests-and-tooling.md` Trap 17), so a findings document must quote the
number inline; a reviewer cannot open the file.

### 5.4 Corpora and artifact stores

- Generators live in `pocketsec/stage<N>/labs/`, stdlib-only, following
  `stage1/labs/corpus.py`. They **reuse** `Behaviour` (`corpus.py:34`) and `Scenario`
  (`corpus.py:45`); a stage does not define a fifth scenario type.
- Every generator exports a `<NAME>_VERSION` string constant, as all four existing corpora do
  (`corpus.py:28`, `hard_corpus.py:40`, `longhorizon_corpus.py:35`, `ambiguous_corpus.py:45`),
  and that string is what `Stage2Dataset.corpus` / a benchmark's provenance records.
- Serialised, checksum-bound datasets go to `datasets/`; models to `models/experimental/` or
  `models/compiled/`; benchmark case definitions to `benchmarks/`; results to `results/`
  (ADR-0002). A new artifact directory is appended to `SPEC_DIRECTORIES`
  (`tests/test_repository_structure.py:14`) with a tracked `README.md`, so its absence is a test
  failure.
- **Mandatory, from `MEMORY.md`'s "corpus trap":** `Stage1Pipeline` carries lineage state across
  scenarios. A corpus that reuses process identities between sessions erases its own signal. Every
  new corpus must (a) use session-unique identities and (b) ship a test asserting median per-class
  ΔΦ is non-zero for both classes before any model is trained on it.

### 5.5 ADR numbering

Next free number is **0011**. Pre-assigned, and required before their stage's first merge:

- **ADR-0011** — generalise the ADR-0008 research boundary to `RESEARCH_PREFIXES` (§2.3).
- **ADR-0012** — add hypotheses H9–H18 plus their prior-art ledger entries (§5.2).

Reserved blocks, so ten parallel waves cannot collide:

| Stage | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 |
|---|---|---|---|---|---|---|---|---|---|---|
| ADR block | 0013–0022 | 0023–0032 | 0033–0042 | 0043–0052 | 0053–0062 | 0063–0072 | 0073–0082 | 0083–0092 | 0093–0102 | 0103–0112 |

Every ADR uses `docs/adr/0000-adr-template.md` and keeps its **Options considered** table with a
measured column. An ADR whose options table has no measured consequence column is a design note,
not an ADR.

### 5.6 Test file naming

`tests/test_stage<N>_<topic>.py`, lowercase, one topic per file — the convention every existing
module follows. Discovery is automatic (`testpaths = ["tests"]`, `pyproject.toml:28`); there is no
registration step and none is to be added. Shared builders come from `from conftest import ...`
(not `from tests.conftest import ...`).

Name each test after the invariant it protects, per `tests/test_authority_boundary.py:3-7`:
"deliberately written so that weakening the invariant means deleting a test whose name says what it
protects."

Three constraints that will bite:

- `[tool.mypy] strict = true` with `files = ["pocketsec", "tests"]` (`pyproject.toml:41-42`), and
  `ruff check pocketsec tests` (`ci.yml:34`) with `select = ["E","F","I","B","UP","SIM","RUF"]` at
  100 columns. New test code is strictly typed. Use a narrow `# type: ignore[...]`; do not add a
  per-module mypy override.
- A new pytest marker must be appended to `markers` (`pyproject.toml:30`) before use —
  `--strict-markers` turns a typo into zero tests run.
- The test suite itself imports numpy (`tests/test_stage2_foundation.py:10`) but numpy is declared
  in neither `dependencies` nor the `dev` extra. **The CI `test` job as written cannot pass.** A
  wave that needs research tests must fix this declaration; it is not an excuse to skip the tests.

---

## 6. What Stage 2's rejection means downstream — what Stage 3 compiles FROM

ADR-0010 rejects DTL. The measured basis, quoted:

| model | PR-AUC | µs/event | params |
|---|---|---|---|
| **tcn** | **1.0000** | **6.6** | 6,961 |
| dtl-conv | 1.0000 | 22.3 | 19,851 |
| mlp-pooled | 0.9415 | 3.2 | 4,657 |
| **phi-oracle** | **0.7484** | **0.0** | **0** |

The Stage 2 core is a **TCN** — causal dilated convolution plus max-over-time pooling — with
**DETACHED** auxiliary heads (ADR-0009: joint heads score 0.3333 against 1.0000 detached, a −0.67
defect that `w_detect=8.0` does not fix). The Φ-oracle reaches 0.7484 with zero parameters and no
measurable inference time, purely from Stage 1's lineage-scoped state calculus (ADR-0005).

`planning/PHASE_03_CLAUDE_CODE.md`'s gate says "Stage 2 DTL baseline is frozen and reproducibly
benchmarked before Stage 3 comparisons" and D3.8 asks for a dual oracle whose "Oracle A: DTL
predictive behaviour". **Both must be rebound, because DTL is rejected.**

### The decision

**Stage 3 compiles from the composition of Stage 1's state calculus and a frozen TCN — in that
order of primacy — and never from DTL.**

1. **Oracle A is the frozen TCN**, not DTL. Concretely: `TCNBaseline`
   (`stage2/research/baselines.py:345`) trained offline at a pinned seed and exported as data.
   `DTLConvModel` (`dtl_conv.py:145`) is retained only as the research vehicle for the detached
   head machinery, with its components defaulted off per ADR-0010.
2. **Oracle B is Stage 1's explicit invariants**, already in code:
   `phi`/`delta_phi` (`stage1/state/potential.py:170`, `:195`), the `INTERACTIONS` table
   (`potential.py:65`), `SecurityStateV1.join` monotonicity (`security_state.py:165`), and
   `StateDelta` (`security_state.py:181`).
3. **The first crystallization target is the Φ-oracle itself, not a neural region.** It is already
   a zero-parameter, zero-latency executable rule reaching 0.7484. A Knowledge Cell that reproduces
   `PhiOracleBaseline` (`baselines.py:552`) is the cheapest possible cell and the natural first
   `KnowledgeCellV1`. If AICT/CRYSTAL cannot compile a rule that is *already a rule*, the machinery
   is refuted before any neural region is attempted. **Make this Wave 3's falsification test, not
   its stretch goal.**
4. **Stage 3's compression claim changes shape.** "End-to-end average CPU/event is materially lower
   than pure DTL" is now trivially satisfiable and therefore meaningless: DTL costs 22.3 µs/event
   and is rejected. The honest bar is **lower than the TCN's 6.6 µs/event at 1.0000 PR-AUC on the
   same corpus** — against a floor of 3.2 µs (mlp-pooled) and 0.0 µs (Φ-oracle). A wave that
   reports "materially lower than DTL" has measured nothing.
5. **D2.6–D2.15 are not prerequisites and must not be built to unblock Stage 3.** ADR-0010: they
   "sit on top of a predictive core that has no measured reason to exist". Stage 3 therefore does
   **not** consume Behaviour Atoms, the transition lattice, Future Cones or the counterfactual twin.
   `Invariant` discovery runs directly over `SSIRTransitionV1` and `SecurityStateV1`; the
   `BoundaryIndex` keys on `SemanticProperty` masks and `StateDelta.bitmask`
   (`security_state.py:206`), not on an atom id. The eleven empty `stage2/*` packages stay empty
   until a corpus revives them.
6. **The blocker is honest and must be stated in every Stage 3 findings document.** ADR-0010: four
   synthetic corpora produced only trivial or impossible tasks, never a middle band; real telemetry
   is required before a predictive core can be judged. Stage 3 may therefore validate its
   *mechanism* (verifier soundness, boundary semantics, melt/rollback, bytecode bounds) on
   synthetic corpora, but it may **not** claim a compression or detection result that generalises.
   The mechanism is testable now; the value is not.

---

## 7. The honesty ledger — required section format

Every stage's findings document (`docs/stage-<N>-findings.md`) must end with this section,
verbatim in structure. A wave's phase is **not** complete without it, and the stage gate must
include a check that the file exists and contains all five headings.

```markdown
## Honesty ledger

### MEASURED
One row per number produced by running code in this session. No row without all five columns.

| claim | value | how it was produced (module:function) | experiment id | synthetic? |
|---|---|---|---|---|

### UNMEASURED
One row per thing the architecture document asserts that this wave did NOT measure.
Absence of a row is a claim that everything was measured.

| claim the architecture makes | why not measured | what would measure it | blocking? |
|---|---|---|---|

### REJECTED
One row per component removed, disproven, or reduced. Cite the measurement and the ADR.

| component | measured effect | verdict (REJECTED / NOT-YET-JUSTIFIED / RETRACTED) | ADR |
|---|---|---|---|

### RETRACTED
Results previously published in this repository that this wave withdraws, with the defect
that produced them. Never delete a retracted result; supersede it and keep the lineage.

| retracted claim | where it was published | the defect | corrected value |
|---|---|---|---|

### NOT A DETECTION RESULT
An explicit statement of which corpora are synthetic and what therefore cannot be concluded.
Required even when it is one sentence. If every corpus is synthetic, say so here.
```

Three distinctions this format exists to keep:

- **NOT-YET-JUSTIFIED is not REJECTED.** ADR-0009 got this right under pressure: three components
  showed no benefit on a *saturated* corpus, which cannot demonstrate benefit at all. They were
  flagged, retained and re-tested — and on the ambiguous corpus two of them turned out to be
  actively harmful (−0.115, −0.073). Collapsing the two categories would have lost that.
- **RETRACTED is not deleted.** `docs/stage-2-dtl-findings.md:336` retracts its own headline
  result and keeps the superseded text with the defect that produced it. That is the standard.
- **`None` never means zero.** ADR-0004: `recall_at_max_fpr` returning `None` where the honest
  answer is `0.0` conflates "not computable" with "scored zero".

---

## 8. Risk register — the ten ways this build produces false confidence

| # | Failure mode | Why it is likely here | Mechanical check that prevents it |
|---|---|---|---|
| 1 | **A stage is marked IMPLEMENTED because its architecture document and its empty packages exist.** | Stage 2 already has eleven empty subpackages that look like structure. `PROGRESS.md` warns about exactly this. | A gate check per stage: `test_stage<N>_has_no_empty_subpackages` — every package under `pocketsec/stage<N>/` must export at least one class or function, asserted by `ast` over each `__init__.py`'s sibling modules. Empty package ⇒ FAILED. |
| 2 | **A saturated corpus makes every component look justified.** | Two of four Stage 2 corpora saturated; five architectures tied at 0.9992, and a bag-of-features model that ignores order scored the same. | Before any ablation, run a **saturation check**: if the best and median models are within 0.01 PR-AUC, or if a pooled order-free baseline (`MLPBaseline`, `baselines.py:245`) is within 0.02 of the best, the gate check fails with `DEGENERATE` and the ablation result is not recorded. `ParetoReport.degenerate` (`stage1/guillotine/ablation.py:180`) is the precedent. |
| 3 | **A corpus leaks its own answer through vocabulary.** | It happened twice: the long-horizon corpus gave a bag-of-features model 1.0000 because attacks used interpreters benign traffic never used; the ambiguous corpus first leaked through event counts. | Every new corpus ships `test_<corpus>_carries_no_vocabulary_signal`: assert the per-operation count distributions match across classes within noise, and assert a pooled order-free baseline scores within 0.05 of the base rate. |
| 4 | **Lineage state carried across scenarios silently erases the signal.** | `Stage1Pipeline` carries state; reused process identities put every lineage at saturated privilege by session two, and the measured median ΔΦ was 0.00 for **both** classes. The resulting +0.042 "improvement" was retracted. | Every corpus test asserts session-unique identities and non-zero median per-class ΔΦ **before** any model is fitted. §5.4. |
| 5 | **A broken baseline flatters the new mechanism.** | The tiny Transformer computed Q/K/V from `.data`, detaching all three projections: 0.5502 → 0.9373 once reconnected. Full-batch training gave 30 gradient steps and pushed DTL *below* base rate. | Gate check `_baselines_beat_base_rate`: every baseline in `BASELINE_REGISTRY` (`baselines.py:582`) must score above the dataset's `base_rate` (`dataset.py:101`) or the comparison is refused, not reported. Plus a gradient check to ~1e-9 against finite differences for any new autodiff op. |
| 6 | **A research artifact reaches the endpoint through an import.** | Two dependency regimes in one package. `RESEARCH_PREFIX` is one hard-coded string, duplicated at `:86`, covering only Stage 2 (§2.3). | `test_runtime_has_no_third_party_imports` + `test_runtime_never_imports_research_code` + the `RESEARCH_PREFIXES` tuple from ADR-0011 driving **both** helpers. Plus T1/T3 in `tests/test_stage_trust_topology.py`. |
| 7 | **A model output becomes load-bearing authority three stages later** via a well-meant `suggested_action` or `response_hint` field. | ADR-0003 names this exact failure mode as the realistic one. Stages 4–12 introduce ~120 new types, each an opportunity. | Import rule **T5**: no dataclass field outside `pocketsec/stage5/` may contain a `FORBIDDEN_AUTHORITY_FIELDS` fragment. Plus **T4**: the executor's entry point accepts exactly `DefensiveOperator`. |
| 8 | **A component is retained because it is architecturally beautiful and never ablated.** | Every acceptance gate from Phase 3 to Phase 12 repeats "no surviving component lacks ablation-supported value", and Stage 2 needed four corpora to act on it. | A per-stage gate check enumerating `core_ids.py`'s `FunctionClass.OPTIONAL` functions and requiring each to name a recorded experiment id with a measured delta. An OPTIONAL function with no experiment id is `FAILED`, not `PENDING`. |
| 9 | **Formal-verification language is used for empirically-tested properties.** | Phase 3 and Phase 5 gates both carve this out explicitly: "all claims of formal verification are limited to properties actually proven"; "proven or explicitly downgraded to empirical claims". | The honesty ledger's MEASURED table requires a `how it was produced (module:function)` cell. A property with no prover module named there is an empirical claim and must be worded as one. A gate check greps stage docs for "proven", "verified", "formally" and fails unless each occurrence is within 3 lines of a prover module path. |
| 10 | **A synthetic result is read as a detection claim** — including by the wave that produced it, six weeks later. | ADR-0010: four corpora produced only trivial or impossible tasks, never a middle band; "synthetic data cannot settle this". Every number in this repository today is synthetic. | `run_benchmark` already requires `synthetic_data` explicitly (`harness.py:133`) and the flag travels into `BenchmarkResult`. Extend it: the honesty ledger's **NOT A DETECTION RESULT** section is a required heading, and each stage's gate asserts the findings document contains it. |

Two further failure modes worth naming, because they are already live and neither has a check:

- **`ruff` and `mypy` have never been run** (`planning/MEMORY.md`, "Known gap"). Lint and
  type status across 61 runtime modules is UNVERIFIED, and `strict = true` covers `tests/` too.
  Wave 3 must run both and report the count, or record `UNMEASURED` and say why.
- **Several existing tests assert the current measured state rather than a desired property**
  (`tests-and-tooling.md` Trap 12), so improving the system makes them fail. A wave that "fixes" one
  of those tests to make its own work pass has deleted a measurement. Re-measure and supersede
  instead.

---

## 9. Wave order

Fixed. Each wave ends with `PHASE <N> STATUS: COMPLETE | PARTIAL | BLOCKED`, the nine-item output
block from its phase file, and its honesty ledger.

| Wave | Stage | Hard prerequisite from an earlier wave |
|---|---|---|
| 3 | 3 | ADR-0011, ADR-0012, `pocketsec/stage2/gate.py` (13 checks, reporting FAILED), `tests/test_stage_trust_topology.py` with T1–T7 |
| 4 | 4 | Stage 3 `KnowledgeCellV1`, `CellVM`, `AssuranceState` |
| 5 | 5 | Stage 4 `TypedClaim`, `ClaimGraph`, `IncidentHypothesis`, `SecurityWorldV1` |
| 6 | 6 | Stage 5 `TransactionReceipt`, `InterventionResidual`; T3 in place |
| 7 | 7 | Stage 6 `QuarantineGateway.admit`, `ExperienceCapsuleV1` |
| 8 | 8 | Stage 6 admission; Stage 7 `KnowledgeCapsuleV1` (optional at runtime, required for the adapter) |
| 9 | 9 | Stage 8 `DiscoveryPackageV1`; Stage 3 `CellISA`/`CellVerifier` |
| 10 | 10 | Stage 9 `ProofCarryingSuccessorV1`; Stage 3 `AssuranceState` |
| 11 | 11 | Stage 10 `AssuranceCertificateV1`, `AssuranceEnvelope`; Stage 6 `KnowledgeLineageDAG` |
| 12 | 12 | Stage 7 `PeerIdentity`/`DependenceGraph`; Stage 11 `ArkCapsuleV1`; Stage 6 admission |

Waves 7 and 8 may run in parallel. Waves 4 and 5 may not: Stage 5 consumes Stage 4's typed claims
directly, and its acceptance gate requires "Stages 0–4 remain unchanged/frozen interfaces".
