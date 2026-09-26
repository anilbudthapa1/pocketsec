# Stage 9 — ONTOGENESIS — implementation contract

- **Status:** Accepted as the build contract for the Stage 9 wave. Binding on eight work packages
  and the integrator.
- **Date:** 2026-09-26
- **Source of truth:** `docs/architecture/sources/stage-09-ontogenesis.md` (architecture),
  `planning/PHASE_09_CLAUDE_CODE.md` (checklist, gate, STOP conditions),
  `docs/architecture/stage-3-12-integration-plan.md` (layout, seams, import rules). The project
  lead's Stage 9 guidance overrides the architecture where they conflict; each conflict is
  recorded where it applies.
- **ADR block:** 0080–0089 (lead's assignment; the integration plan's 0073–0082 block is
  superseded, as Stages 6 and 7 superseded theirs). `ls docs/adr | grep '^008'` returned nothing
  at spec time, so all ten numbers are free. §10 assigns every one of them. The integrator writes
  all ten before the gate is reported (lesson 10), and `tests/test_stage9_gate.py` asserts that
  every `ADR-00NN` cited under `pocketsec/stage9/` and in `docs/stage-9-*` resolves to a file.
- **What Stage 9 is, in one sentence.** It is a research search for the cheapest computation that
  does the security job. Its output is a *candidate*, never a deployed component.

---

## 0. What was measured before this contract was written

Every number below was produced by running code in this session. The probe scripts are in the
session scratchpad, not the repository. Each row records the load average. Timings were taken on a
shared, contended 8-core host with 16 GB of RAM. They are within-run comparisons, never device
figures.

| # | claim | value | command / module | loadavg (1/5/15) |
|---|---|---|---|---|
| M0.1 | Every upstream symbol this contract cites exists | **75 OK, 0 missing** (`importlib` + `inspect.getsourcelines` over the §3.1 table) | `verify_seam.py` | 3.45 5.71 6.90 |
| M0.2 | Φ-oracle AP on Stage 1's ambiguous corpus, eval seed 11, through `stage2.gate_measures.compile_split` and `max(step.features[73])` per session | count 60: **1.0000** (60 sessions, 4357 events, compile 4.57 s). count 120: **0.8495** (120, 8948, 19.02 s). count 240: **0.5975** (240, 17898, 40.0 s). Base rate 0.3333 at every size | `probe_phi.py` | 8.58 → 8.77 → 10.49 → 11.97 |
| M0.3 | Shuffled-label control for the same scores (20 label permutations) | count 60: AP 0.2727–0.4237, mean 0.3547. count 120: 0.2927–0.3962, mean 0.3402. count 240: 0.3050–0.4000, mean 0.3456 | `probe_phi.py` | same |
| M0.4 | Is division needed to express the Φ-oracle's *ranking*? | `max |ΔΦ|` (raw), `max ΔΦ` (signed) and `max features[73]` (squashed) give **identical AP at all three sizes**. The raw and squashed orderings are **rank-identical** (`True` at 60/120/240). The squashed *score values* need `x/(x+8)`, which needs division. The other aggregations are weak: `last` 0.4000/0.3527/0.3212, `mean` 0.6510/0.3548/0.2666 | `probe_phi.py` | same |
| M0.5 | Cost of the Φ-oracle as a direct Python loop (best of 5) | 0.1544 / 0.1243 / 0.1678 µs/event at count 60/120/240 | `probe_phi.py` | same (8.6–12.0) |
| M0.6 | Headroom: do simple *per-lineage* functions beat the Φ-oracle at count 240? (fit seed 3 / eval seed 11) | Φ-oracle **0.5897 / 0.5975**. Per-lineage Σ positive ΔΦ **0.7279 / 0.7680**. Per-lineage popcount(OR of state-delta mask) **0.7312 / 0.8111**. Per-lineage count of mask-raising events 0.3330 / 0.3464. Per-lineage max \|ΔΦ\| equals the Φ-oracle | `probe_simple.py` | 11.25 → 12.54 → 10.87 |
| M0.7 | Label-preserving scenario attacks, count 120 seed 11 (Φ-oracle / per-lineage OR-mask) | clean 0.8495 / 0.7943. Rename binaries **0.8672 / 0.8353**. Reorder across actors **identical to clean** (0.8495 / 0.7943). Timing stretch **identical to clean**. Drop 10% of events **0.7712 / 0.6951**. Compile 6.7–9.2 s per variant | `probe_argus.py` | 8.25 → 6.01 |
| M0.8 | Cost of a closure-list DAG interpreter with per-lineage registers (6 nodes) against the same function as a direct loop, count 120 | **0.849 µs/event against 0.093** (ratio 9.1x, same run) | `probe_interp.py` | 8.31 8.98 8.05 |
| M0.9 | What importing Stage 6's gateway drags in | `import pocketsec.stage6.capsule.quarantine` loads **27** `pocketsec.stage5.*` modules, including `stage5.executor.transactional`, `stage5.authority.tokens` and `stage5.operators.catalog`. `import pocketsec.stage6.resources` loads **0** | inline `sys.modules` diff | — |
| M0.10 | Can Stage 3's PCB ISA carry a Stage 9 phenotype? | `Op` has 22 members: `LOAD_STATE LOAD_SEM LOAD_REL LOAD_DELTA LOAD_CONST EQ NE LT GT IN_SET AND OR NOT COUNT_WINDOW SEEN_WITHIN TRANSITION UPDATE_PHI RAISE_OBSERVATION PRESERVE_EVIDENCE RETURN_STATE RETURN_RISK ABSTAIN`. It has **no division, no MAX, no per-lineage register and no arithmetic** | inline | — |
| M0.11 | Stage 8 | **0** `.py` files under `pocketsec/stage8/`, and `docs/stage-8-spec.md` does not exist. `pocketsec/stage9/` has 0 `.py` files and 7 empty, non-package directories (`argus chronos daedalus gaia genesis laplace ontogenesis`) | `find`, `ls` | — |
| M0.12 | Stage 2's registered frontier evidence | `load_frontier()` **accepts** `results/stage2-frontier.json`: ambiguous, count 60, seed 11. `phi-oracle 1.0, tcn 1.0, mlp-pooled 1.0`, `degenerate=True`, reason `ORDER_FREE_BASELINE_TIES_BEST`, experiment `PS-S2-20260924-H8-baseline-frontier-0019` (figures produced by the Stage 2 wave; this session only loaded and authenticated them) | `stage2.gate_evidence.load_frontier` | 3.02 5.42 6.77 |
| M0.13 | This host | `MemTotal: 16066696 kB`, `nproc` 8. **This host is not a 2 GB reference target** | `/proc/meminfo` | — |

These facts were read from code, not measured:

- `tests/test_repository_structure.py:73` is `RESEARCH_PREFIX = "pocketsec/stage2/research/"`,
  and `:86` hard-codes the Stage 2 research path a second time. ADR-0011 (`RESEARCH_PREFIXES`) was
  never written. As a result, a numpy import under `pocketsec/stage9/research/` fails
  `test_runtime_has_no_third_party_imports`, and the lead forbids editing that file.
- `pocketsec/stage0/hypotheses.py` holds H0–H8 only. ADR-0012 (H9–H18) was never written.

**What these measurements mean. Each point decides part of the design below.**

1. **The count-60 split is saturated, and a claimed win there is a measurement error.** The
   Φ-oracle reads 1.0000 at count 60 and 0.5975 at count 240 on the same generator and seed. On
   that split, nothing can beat it on quality, and the TCN only ties it (M0.12). Stage 9 uses
   count 60 for one purpose: to place the TCN and the Φ-oracle on the saturated Pareto plot and
   show the trap. **All search, selection and held-out evaluation runs on ambiguous count 240**
   (fit seed 3, held-out seed 11). That is the only split in the repository with measured headroom.
2. **Headroom exists at count 240, and it is author-confounded.** M0.6 shows that two one-register
   per-lineage functions beat the Φ-oracle by +0.14 to +0.21 AP on both seeds. Stage 1's ambiguous
   generator defines "malicious" as *one lineage performs the whole chain*
   (`ambiguous_corpus.py:201-265`). "Per-lineage OR of the state-delta mask" nearly restates that
   generator rule. If search finds it, that is correct, and it is also the corpus author's rule
   read back (lesson 6). The two functions are therefore **hand-designed baselines H1 and H2**
   (§7), written into this contract before any search runs, and the search must be compared with
   them.
3. **The language must express the incumbent first.** M0.4 shows the Φ-oracle's ranking needs no
   division, but its exact scores do. The IR therefore includes `DIV`, which Stage 3's bytecode
   lacked, so exact expressibility can be checked. M0.10 shows a Stage 9 phenotype cannot be
   lowered to PCB at all. DAEDALUS records that as a Stage 3 seam finding and does not work around
   it.
4. **Two of the four cheap attacks are inert against both reference scorers** (M0.7). ARGUS must
   report a firing count for every attack. An attack that changes no session score is INERT for
   that scorer and does not count toward lifecycle coverage.
5. **The only exit to Stage 6 transitively loads Stage 5** (M0.9). "No Stage 9 module reaches
   Stage 5" is therefore proven in three parts (§2.3): no direct import, a static import closure,
   and a single declared exit module. It cannot be proven by a whole-package closure.
6. **The interpreter costs about 9x a hand loop** (M0.8). Work units (WU) are the primary cost.
   Wall-clock figures are always reported as a ratio within one run, never as an absolute.
7. **Stage 8 does not exist** (M0.11). Stage 9 runs without it. Gate criterion G9.1 names
   "the strongest Stage-8 hand-designed baseline", so it is BLOCKED and fails. It is not
   re-worded into a pass (§6.1).

---

## 1. What Stage 9 must deliver

**Thesis, bound to code.** Every clause below is checkable:

> *A typed genome language in which every well-typed program terminates in a static number of
> work units and bounded bytes, and ill-typed programs cannot be constructed. That language
> provably expresses the Φ-oracle. On a split with headroom, an adversarially tested, cost-aware
> search over it is compared at equal work-unit budget with random search and exhaustive
> enumeration, and on held-out data with the Φ-oracle and two hand-written per-lineage rules. The
> search's output is a `ProofCarryingSuccessorV1` candidate that leaves Stage 9 only through
> `Stage6Exit.hand_over` → `QuarantineGateway.admit`. No Stage 9 module imports Stage 5, names a
> Stage 6 writer, or carries authority.*

The honest expected outcome, stated before measurement:

- On count 60, the minimum sufficient computation is the Φ-oracle. Rediscovering it is success.
- On count 240, the ≤2-node exhaustive space (§4.12) contains the Φ-oracle, H1-like and H2. The
  most likely result is that exhaustive enumeration ties or beats evolution, which would make
  evolution NOT-YET-JUSTIFIED. This is a prediction, not a result.

### 1.1 Checklist → deliverable → module → package

Every item of `planning/PHASE_09_CLAUDE_CODE.md` appears here. Checklist item NN is deliverable
D9.NN. Every path is under `pocketsec/stage9/`.

| # | deliverable | module(s) | core id | package |
|---|---|---|---|---|
| 01 | D9.1 MSSC formal research specification | `spec/mssc.py` + this document §4.1 | ONTO-F01 | genome |
| 02 | D9.2 Computational Genome schema | `genome/computational.py`, `genome/expressibility.py` | ONTO-F02 | genome |
| 03 | D9.3 LAPLACE state/law discovery engine | `laplace/state_discovery.py`, `laplace/law_discovery.py` | ONTO-F03 | laws |
| 04 | D9.4 Primitive Foundry + promotion gate | `foundry/primitives.py` (alphabet), `foundry/promotion.py` (gate) | ONTO-F04 | ir, laws |
| 05 | D9.5 Algorithmic Chemistry typed IR | `chemistry/typed_ir.py`, `chemistry/phenotype.py` | ONTO-F05 | ir |
| 06 | D9.6 Security Renormalization laboratory | `renormalization/laboratory.py` | ONTO-F06 | physics |
| 07 | D9.7 Symmetry/Conservation research suite | `symmetry/suite.py`, `symmetry/conservation.py` | ONTO-F07 | physics |
| 08 | D9.8 Causal Geometry/Phase Observatory benchmarks | `geometry/causal.py`, `geometry/phase.py` | ONTO-F08 | physics |
| 09 | D9.9 MSDL/Predictive Compression suite | `compression/msdl.py` | ONTO-F09 | physics |
| 10 | D9.10 CHRONOS memory/forgetting-law engine | `chronos/forgetting_law.py` | ONTO-F10 | laws |
| 11 | D9.11 DAEDALUS system synthesizer | `daedalus/synthesizer.py` | ONTO-F11 | successor |
| 12 | D9.12 GENESIS variation/speciation engine | `genesis/variation.py` (variation), `genesis/speciation.py` (speciation, morphogenesis) | ONTO-F12 | search, runtime |
| 13 | D9.13 GAIA QD ecology | `gaia/qd_ecology.py` | ONTO-F13 | search |
| 14 | D9.14 ARGUS architecture adversary | `argus/adversary.py` | ONTO-F14 | evaluation |
| 15 | D9.15 Homeostatic Runtime controller | `runtime/homeostatic.py` | ONTO-F15 | runtime |
| 16 | D9.16 Convergence/Law Observatory | `observatory/convergence.py` | ONTO-F16 | laws |
| 17 | D9.17 Proof-Carrying Successor Package | `successor/proof_carrying.py`, `successor/stage6_exit.py`, `successor/boundary.py` | ONTO-F17 | successor |
| 18 | D9.18 Hardware-in-loop benchmark harness | `harness/hardware_in_loop.py` | ONTO-F18 | runtime |
| 19 | D9.19 120-experiment falsification program | `labs/one_twenty_experiments.py` (catalogue of all 124 ids the architecture lists) | ONTO-F19 | runtime |
| 20 | D9.20 Final MSSC thesis report + Stage 1–9 reproducibility package | `harness/reproducibility.py` (manifest); report `docs/stage-9-findings.md` | ONTO-F20 | runtime, integrator |
| — | ONTOGENESIS meta-controller (architecture layer 9.1): the search loop | `ontogenesis/search.py` | ONTO-F12/F13 | search |
| — | fitness evaluation and splits (no deliverable number; everything depends on them) | `ontogenesis/fitness.py`, `labs/splits.py` | ONTO-F14 | evaluation |

### 1.2 The phase file's required test focus, bound

| phase-file focus | where it is tested |
|---|---|
| typed genome validation | `tests/test_stage9_ir.py` (IR type errors, loop/recursion/allocation refusals), `tests/test_stage9_genome.py` (schema, digest, declared bounds) |
| bounded-state/loop/resource contracts | `tests/test_stage9_ir.py` (static WU exactness, lineage eviction counted), `tests/test_stage9_search.py` (population/archive/cache/fossil bounds, WU budget), G9.7 |
| primitive ablation/reproduction | `tests/test_stage9_laws.py` (`promotion_gate` refusal reasons, convergence), G9.2 |
| search determinism metadata | `tests/test_stage9_search.py` (same seed → same digest sequence, `SearchRun.determinism_digest`) |
| ARGUS adversarial tests | `tests/test_stage9_argus.py`, G9.8 |
| hardware-in-loop resource measurement | `tests/test_stage9_runtime.py` (HIL record shape, `None` when unmeasured, reference-target check), G9.4 |
| successor rollback | `tests/test_stage9_successor.py` (install → rollback → byte-identical scores; tampered artefacts refused), G9.6 |
| baseline Pareto comparisons | `tests/test_stage9_genome.py` (dominance, hypervolume, `beats`), `tests/test_stage9_search.py` (strategy comparison verdict rule), G9.1 |

---

## 2. Repository rules this wave operates under

### 2.1 Layout: integration plan §1.2, amended (ADR-0080)

```
pocketsec/stage9/
    __init__.py            integrator; EMPTY (docstring only)
    core_ids.py            [genome]    ONTO-F01..F20
    gate.py, gate_*.py     integrator
    cli.py                 integrator
    spec/mssc.py                                [genome]
    genome/computational.py, expressibility.py  [genome]
    chemistry/typed_ir.py, phenotype.py         [ir]
    foundry/primitives.py                       [ir]
    foundry/promotion.py                        [laws]
    labs/splits.py                              [evaluation]
    labs/one_twenty_experiments.py              [runtime]
    argus/adversary.py                          [evaluation]
    ontogenesis/fitness.py                      [evaluation]
    ontogenesis/search.py                       [search]
    genesis/variation.py                        [search]
    genesis/speciation.py                       [runtime]
    gaia/qd_ecology.py                          [search]
    renormalization/laboratory.py               [physics]
    symmetry/suite.py, conservation.py          [physics]
    geometry/causal.py, phase.py                [physics]
    compression/msdl.py                         [physics]
    laplace/state_discovery.py, law_discovery.py [laws]
    chronos/forgetting_law.py                   [laws]
    observatory/convergence.py                  [laws]
    daedalus/synthesizer.py                     [successor]
    successor/proof_carrying.py, stage6_exit.py, boundary.py [successor]
    runtime/homeostatic.py                      [runtime]
    harness/hardware_in_loop.py, reproducibility.py [runtime]
```

Amendments to the integration plan layout, all recorded in ADR-0080:

- **No `research/` package and no numpy anywhere in Stage 9.** The plan permits one. The
  structural test cannot tell `stage9/research/` from runtime without editing
  `tests/test_repository_structure.py`, which is forbidden. Nothing in this contract needs
  gradient descent. The TCN appears only as registered Stage 2 evidence (M0.12). Precedent:
  ADR-0020, 0030, 0040, 0050, 0060. The plan's `research/{search.py,genome_eval.py}` become
  `ontogenesis/search.py` and `ontogenesis/fitness.py` (stdlib).
- **The seven pre-existing empty directories are filled, not deleted** (ADR-0121). `ontogenesis/`
  holds the meta-controller (architecture layer 9.1).
- **Added modules beyond the plan:** `chemistry/phenotype.py` (the interpreter),
  `genome/expressibility.py`, `labs/splits.py`, `ontogenesis/fitness.py`, `genesis/speciation.py`
  (moved from `genesis/` to runtime ownership), `successor/stage6_exit.py`,
  `successor/boundary.py`, `harness/reproducibility.py`. `compression/msdl.py` stays.
- Every subpackage `__init__.py` is **empty** (docstring allowed). Consumers import leaf modules.
  The owner of each directory's modules creates its `__init__.py` (§5 lists them).

### 2.2 Hard mechanical constraints

- `from __future__ import annotations`; a module docstring stating what the module is FOR;
  `@dataclass(frozen=True, slots=True)` with typed fields; explicit `__all__`; comments explain why.
  Read two existing modules (for example `stage2/compile_candidates/phi_oracle_candidate.py` and
  `stage3/bytecode/isa.py`) before writing.
- stdlib + `pocketsec` imports only (ADR-0001). No `print` outside `cli.py`.
- Files under 800 lines; functions under 50 lines; public APIs type-annotated; `mypy --strict`
  clean for new files (`uvx mypy` is the tool that runs on this host); `ruff` rules
  `E,F,I,B,UP,SIM,RUF` at 100 columns.
- Any new pytest marker is appended to `pyproject.toml` `markers` by the **integrator**. Packages
  use only the existing `slow` marker.
- **No field or class name under `pocketsec/stage9/` may contain a `FORBIDDEN_AUTHORITY_FIELDS`
  fragment** (`threat_prediction_v1.py:48`: `action remediation execute command shell kill
  quarantine block authorize authorization privilege sudo`). Watch `transaction` (contains
  `action`), `quarantine_*`, `blocked`, `privilege`. Coverage dimensions use `auth`, never
  `authorization`. `executable_artifacts` is legal (`executable` does not contain `execute`).
- No `eval`, `exec`, `compile`, `__import__`, `pickle`, `marshal`, `subprocess`, `socket` or
  `os.system`. `importlib.import_module` is allowed only in `core_ids.py` (lazy symbol resolution)
  and `labs/one_twenty_experiments.py` (runner resolution). `subprocess` is allowed only in the
  integrator's `gate*.py`, for G9.10's clean-process check. These are the three declared
  exemptions. `concurrent.futures.ProcessPoolExecutor` is allowed only in `labs/splits.py`.

### 2.3 Upstream imports: an allow-list, and the Stage 5 proof in three parts (ADR-0081)

| upstream module | names | Stage 9 files that may import them |
|---|---|---|
| `stage0.*` | any public name | any |
| `stage1.labs.corpus` | `Behaviour`, `Scenario`, `CORPUS_VERSION` | any |
| `stage1.labs.ambiguous_corpus` | `build_ambiguous_corpus`, `AMBIGUOUS_VERSION` | any |
| `stage1.pipeline` | `Stage1Pipeline`, `ScenarioResult` | any |
| `stage1.state.security_state` | `DIMENSIONS` | any |
| `stage1.ssir.relations` | `RelationFamily` | any |
| `stage1.novelty.sketches` | `CountMinSketch` | `chronos/forgetting_law.py` |
| `stage1.epoch.model` | `Epoch` | `successor/stage6_exit.py` |
| `stage2.dataset` | `Stage2Dataset`, `Stage2Sample`, `_encode` | any (`_encode` only in `labs/splits.py`; precedent `stage2/gate_measures.py:47`) |
| `stage2.encoder.ssir_encoder` | `EncodedTransition`, `FEATURE_WIDTH`, `GROUP_OFFSETS`, `ENCODER_VERSION`, `NEED_SIGNAL_INDICES` | any |
| `stage2.core_ids` | `FunctionClass` | `core_ids.py` |
| `stage2.compile_candidates.phi_oracle_candidate` | `PHI_ORACLE_SCORER`, `PHI_SQUASHED_FEATURE_INDEX`, `DeterministicScorerSpec`, `AGGREGATIONS` | any |
| `stage2.compile_candidates.candidate` | `forbidden_authority_keys` | `successor/proof_carrying.py` |
| `stage2.gate_measures` | `lineage_windows` | `genome/expressibility.py` |
| `stage2.gate_evidence` | `load_frontier`, `FrontierEvidence` | gate, cli, `harness/hardware_in_loop.py` |
| `stage2.gate_criteria` | `imported_modules` | `successor/boundary.py` |
| `stage2.labs.drift_corpus` | `build_drift_corpus`, `DRIFT_VERSION` | `laplace/law_discovery.py`, `harness/reproducibility.py` |
| `stage3.labs.ablation` | `saturation_guard` | `labs/splits.py` |
| `stage3.cells.operator` | `OperatorProgram`, `OperatorForm` | `daedalus/synthesizer.py` |
| `stage3.bytecode.verifier` | `verify` | `daedalus/synthesizer.py` |
| `stage3.bytecode.isa` | `Op` | `daedalus/synthesizer.py` |
| `stage6.resources` | `WorkMeter`, `WorkBudgetExceeded`, `loadavg` | any (holds no trusted state; ADR-0061 precedent) |
| `stage6.capsule.experience_capsule` | `capsule_from_scenario`, `SourceProvenance`, `SourceClass`, `LabelOrigin`, `ExperienceCapsuleV1` | `successor/stage6_exit.py` only |
| `stage6.capsule.quarantine` | `QuarantineGateway`, `QuarantineVerdict`, `QuarantineBucket` | `successor/stage6_exit.py`; gate/cli (lab gateway construction) |
| `stage6.provenance.ledger`, `stage6.fossils.lineage`, `stage6.memory.semantic` | `ProvenanceLedger`; `KnowledgeLineageDAG`; `genesis_state` | gate/cli only (constructing a lab gateway) |
| `stage4`, `stage5`, `stage7`, `stage8`, `stage10`–`stage12` | **nothing** | — |

The rule "no Stage 9 module reaches Stage 5" is proven by three AST rules in
`successor/boundary.py`, each also a test and a gate sub-check:

1. **Direct:** no `Import`/`ImportFrom` under `pocketsec/stage9/` names `pocketsec.stage5`
   (integration plan T2). Relative imports are resolved through
   `stage2.gate_criteria.imported_modules`.
2. **Closure:** a static import closure is built by AST over `pocketsec/`, following module-level
   and function-level imports. For every Stage 9 module *except* `successor/stage6_exit.py`,
   `gate*.py` and `cli.py`, the closure contains no `pocketsec.stage5.*`. For those three files,
   every path to `pocketsec.stage5.*` passes through `pocketsec.stage6.capsule.*`. This is the
   declared residual (M0.9), recorded in ADR-0081.
3. **One door:** `successor/stage6_exit.py` is the only Stage 9 file that contains an `.admit(`
   call or imports `QuarantineGateway`. It never names a Stage 6 writer
   (`promotion.*`, `chamber.*`, `shadow.*`, `consolidator.*`, `fossils.store`, `_install_trusted`,
   or any name in a Stage 6 module's `SEALED_NAMES`).

### 2.4 Other waves in this tree

Files under `pocketsec/stage<other>/`, `tests/test_stage<other>_*.py` and `docs/stage-<other>-*`
belong to other waves. Never edit, revert or delete them, and never run `git checkout`, `stash`,
`restore`, `clean` or `commit`. Do not edit `tests/test_repository_structure.py`: Stage 9's
boundary lives in `tests/test_stage9_boundary.py`. When the full suite runs, a failure in another
stage's test file is reported and not fixed. **Stage 8 is absent** (M0.11). Stage 9 consumes
nothing from it. If `docs/stage-8-spec.md` appears mid-wave, the integrator reads it and records
the named candidate interface in a findings note. No Stage 9 module imports `pocketsec.stage8`
in this wave.

### 2.5 The gate never writes the experiment ledger

`run_gate()` must not append to `experiments/registry.jsonl`. Registration is an explicit CLI
subcommand, `pocketsec-stage9 register`, owned by the integrator. That subcommand appends through
`ExperimentRegistry.register` (`stage0/experiments/registry.py:106`, method `:138`). Result
payloads go to `results/<experiment_id>.json`.
`tests/test_stage9_gate.py` asserts that the registry file's bytes are unchanged by `run_gate()`.

### 2.6 Hypothesis binding: no H15 is minted (ADR-0080)

`HYPOTHESES` holds H0–H8 (`stage0/hypotheses.py:88`), and ADR-0012 does not exist. Stage 9
experiment ids use existing hypotheses by meaning:

- `H5` ("adaptive state growth + minimisation"): search, MSSC and state sufficiency.
- `H6` ("hierarchical reversible forgetting"): CHRONOS.
- `BASE`: baselines and controls.

Format: `PS-S9-<YYYYMMDD>-<H5|H6|BASE>-<slug>-<NNNN>`, with a per-stage counter starting at `0001`.

### 2.7 Timing on a contended host

Every timing figure carries `loadavg` before and after, from `stage6.resources.loadavg`. Cost is
**work units first** (ADR-0033 precedent). A wall-clock figure is reported only as a ratio against
the Φ-oracle measured in the **same run**. An absolute µs figure is labelled
`host-contended, not a device measurement`. Incremental RSS is sampled peak minus start,
floored at 0.

---

## 3. The data seam

### 3.1 Consumed from Stages 0–6: every symbol exists (M0.1)

| symbol | path:line |
|---|---|
| `average_precision`, `recall_at_max_fpr`, `confusion_at_threshold` | `stage0/benchmark/security_metrics.py:92`, `:122`, `:73` |
| `ResourceSampler`, `ResourceMetrics` | `stage0/benchmark/resource_metrics.py:103`, `:57` |
| `check_profile`, `HOST_RAM_TARGET_BYTES` | `stage0/benchmark/profiles.py:85`, `:58` |
| `GateCheck`, `GateReport`, `REPO_ROOT` | `stage0/gate.py:44`, `:55`, `:33` |
| `SeedSet`, `EnvironmentFingerprint` | `stage0/repro/seeds.py:23`, `stage0/repro/environment.py:54` (`capture` at `:106`) |
| `ExperimentRegistry`, `format_experiment_id`, `parse_experiment_id` | `stage0/experiments/registry.py:106`, `ids.py:56`, `:75` |
| `register_schema`, `ContractError`, `EvidenceRef`, `digest_of_bytes`, `SCHEMA_REGISTRY` | `stage0/contracts/common.py:49`, `:32`, `:124`, `:116`, `:46` |
| `FORBIDDEN_AUTHORITY_FIELDS` | `stage0/contracts/threat_prediction_v1.py:48` |
| `Behaviour`, `Scenario`, `CORPUS_VERSION` | `stage1/labs/corpus.py:33`, `:44`, `:28` |
| `build_ambiguous_corpus`, `AMBIGUOUS_VERSION` | `stage1/labs/ambiguous_corpus.py:268`, `:45` |
| `Stage1Pipeline`, `ScenarioResult` | `stage1/pipeline.py:77`, `:46` |
| `DIMENSIONS`, `RelationFamily`, `CountMinSketch`, `Epoch` | `stage1/state/security_state.py:108`, `stage1/ssir/relations.py:56`, `stage1/novelty/sketches.py:39`, `stage1/epoch/model.py:104` |
| `Stage2Dataset`, `Stage2Sample`, `_encode` | `stage2/dataset.py:71`, `:37`, `:124` |
| `EncodedTransition`, `FEATURE_WIDTH` (=96), `GROUP_OFFSETS`, `ENCODER_VERSION`, `NEED_SIGNAL_INDICES` | `stage2/encoder/ssir_encoder.py:142`, `:95`, `:108`, `:45`, `:113` |
| `FunctionClass` | `stage2/core_ids.py:37` |
| `PHI_ORACLE_SCORER`, `PHI_SQUASHED_FEATURE_INDEX` (=73), `DeterministicScorerSpec`, `AGGREGATIONS` | `stage2/compile_candidates/phi_oracle_candidate.py:175`, `:65`, `:89`, `:84` |
| `forbidden_authority_keys` | `stage2/compile_candidates/candidate.py:102` |
| `compile_split`, `lineage_windows` | `stage2/gate_measures.py:178`, `:343` |
| `load_frontier`, `FrontierEvidence`, `FRONTIER_PATH` | `stage2/gate_evidence.py:187`, `:61`, `:56` |
| `imported_modules` | `stage2/gate_criteria.py:547` |
| `build_drift_corpus`, `DRIFT_VERSION` | `stage2/labs/drift_corpus.py:379`, `:82` |
| `MAX_WINDOW` (=64) | `stage2/state/window.py:75` |
| `saturation_guard` | `stage3/labs/ablation.py:183` |
| `OperatorProgram`, `OperatorForm`, `verify`, `Op` | `stage3/cells/operator.py:92`, `:79`, `stage3/bytecode/verifier.py:159`, `stage3/bytecode/isa.py:133` |
| `WorkMeter`, `WorkBudgetExceeded`, `loadavg` | `stage6/resources.py:137`, `:133`, `:181` |
| `QuarantineGateway` (`admit` at `:472`), `QuarantineVerdict`, `QuarantineBucket` | `stage6/capsule/quarantine.py:383`, `:173`, `:150` |
| `capsule_from_scenario`, `SourceProvenance`, `SourceClass`, `LabelOrigin`, `ExperienceCapsuleV1` | `stage6/capsule/experience_capsule.py:861`, `:426`, `:156`, `:166`, `:554` |
| `ProvenanceLedger`, `KnowledgeLineageDAG`, `genesis_state` | `stage6/provenance/ledger.py:139`, `stage6/fossils/lineage.py:209`, `stage6/memory/semantic.py:776` |

### 3.2 Upstream contracts quoted where they decide Stage 9's design

- `EncodedTransition` fields (`ssir_encoder.py:151-172`): `features: tuple[float, ...]` (96),
  `relation: int`, `relation_family: int`, `state_delta_mask: int`, `time_bucket: int`,
  `delta_phi: float` (raw, signed), `object_property_mask: int`, `epoch_id: int`,
  `actor_slot: int` (a session-local lineage index assigned by `dataset._encode` per
  `transition.actor.identity`, *not* an identity), `evidence: tuple[str, ...]` (never a feature).
  **These are the only inputs a genome may read** (`InputSource`, §4.5). `display_name` and
  identity never reach Stage 9 (ADR-0007).
- `PhiOracleBaseline` / `PHI_ORACLE_SCORER`: the score is `max` over the steps of
  `features[73] = |ΔΦ|/(|ΔΦ|+8)`. The sign slot, `features[74]`, is deliberately unread. At
  session level this equals `max` over lineages of the per-lineage `max`. That is exactly the
  genome in §4.2's `phi_oracle_genome()`.
- `QuarantineGateway.admit(capsule: ExperienceCapsuleV1) -> QuarantineVerdict` is the one door.
  It "never writes trusted state" (`quarantine.py:1-8`). Stage 6's candidate kinds are "exactly
  those with an executor" (ADR-0056). **No kind exists for a computational genome.** Stage 9
  therefore hands over the *evidence sessions* that justified a successor as
  `TRANSITION_EPISODE` capsules and records the verdict verbatim. Stage 6 cannot install a genome.
  That is blocker **B9-2** (§11), not something to work around.
- `WorkMeter.charge(units)` raises `WorkBudgetExceeded` *before* admitting the charge that crosses
  the budget (`resources.py:156`). Stage 9 charges before working, so no unpaid work is done.

### 3.3 Exposed to Stage 10 (and Stages 11/12): the names this contract assigns

The integration plan §3.2 names 19 exposed types. Each one binds as follows:

| plan name | concrete type | module |
|---|---|---|
| `ComputationalGenomeV1` | frozen dataclass, schema `pocketsec.computational_genome.v1` @ 1.0.0 | `genome/computational.py` |
| `DiscoveredLaw` | frozen dataclass | `laplace/law_discovery.py` |
| `DiscoveredState` | frozen dataclass | `laplace/state_discovery.py` |
| `Primitive` | frozen dataclass | `foundry/primitives.py` |
| `PromotionVerdict` | `StrEnum` (+ `PromotionDecision`) | `foundry/promotion.py` |
| `TypedIR` | alias: `TypedIR = IRProgram` | `chemistry/typed_ir.py` |
| `RenormalizationResult` | frozen dataclass | `renormalization/laboratory.py` |
| `SymmetryTest` | frozen dataclass | `symmetry/suite.py` |
| `ConservationTest` | frozen dataclass | `symmetry/conservation.py` |
| `PhaseObservation` | frozen dataclass | `geometry/phase.py` |
| `MSDLScore` | frozen dataclass | `compression/msdl.py` |
| `ForgettingLaw` | frozen dataclass | `chronos/forgetting_law.py` |
| `SynthesizedSystem` | frozen dataclass | `daedalus/synthesizer.py` |
| `Speciation` | frozen dataclass | `genesis/speciation.py` |
| `QualityDiversityArchive` | class | `gaia/qd_ecology.py` |
| `ArgusAttack` | alias: `ArgusAttack = ScenarioAttack \| LifecycleAttack` | `argus/adversary.py` |
| `HomeostaticController` | class | `runtime/homeostatic.py` |
| `ProofCarryingSuccessorV1` | frozen dataclass, schema `pocketsec.proof_carrying_successor.v1` @ 1.0.0 | `successor/proof_carrying.py` |
| `HardwareMeasurement` | frozen dataclass | `harness/hardware_in_loop.py` |

The integration plan's binding holds: `ComputationalGenomeV1` carries
`declared_max_state_bytes: int` and `declared_max_steps_per_event: int`, and the IR validator
refuses a genome whose declared figures understate the computed static bounds.

### 3.4 Every abstract term in the architecture, bound to a type

| architecture term | concrete binding |
|---|---|
| MSSC `C*` objective (§0) | `spec/mssc.py`: `ObjectiveVector` (worst-case AP ↑, WU/event ↓, state bytes ↓; DL reported), `MSSCConstraints`, `pareto_front` |
| DetectionQuality ≥ Qmin | `MSSCConstraints.q_min_margin` over base rate, on held-out **worst-case** AP |
| Robustness ≥ Rmin | `MSSCConstraints.r_min`: worst-case / clean AP |
| Calibration ≥ Kmin | `MSSCConstraints.k_min = None`: **UNMEASURED**. Scores are rankings; no calibrator exists. Never reported as met |
| Privacy ≥ Pmin | inputs are `EncodedTransition` fields only; identity is unreachable by construction (ADR-0007) |
| RAM ≤ B_ram, CPU ≤ B_cpu | `session_state_bytes_max ≤ ram_bytes_max`; `update_wu_per_event ≤ wu_per_event_max` |
| SafetyInvariants | IR validation passes, `ComputationContract.check` returns no violation, and boundary rules hold |
| Computational genome (§4, 14 fields) | `ComputationalGenomeV1`; the table in §4.2 maps each of the 14 fields |
| Primitive alphabet Π0 (§7) | `foundry/primitives.SEED_ALPHABET` (§4.4) |
| Typed reaction graph (§9) | `IRProgram`: a DAG in which argument indices are strictly less than the node index |
| Compound / motif / fossil (§9, §45) | macro `Primitive` (origin `PROMOTED`) / canonical subgraph / `ComputationalFossil` |
| Renormalization `R_k` (§11) | `CoarseGraining` enum + `coarse_grain()` |
| Symmetry group `G` (§13) | `Transformation` enum |
| Conserved quantity `Q` (§15) | `ConservedQuantity` (a named per-lineage genome) |
| Mechanism distance `d_c` (§18) | `mechanism_distance()`: bounded weighted edit distance |
| Order parameter `Ψ_t` (§20) | `OrderParameter` enum + `order_parameter_series()` |
| MSDL (§22) | `MSDLScore` |
| Memory law `M_{t+1}=F(...)` (§25) | register update programs + `MemoryFamily` |
| Learning law `θ_{t+1}=F(...)` (§29) | `AdaptationLaw` enum (outside the genome; the genome's own `learning_law` is `NONE` only, lesson 3) |
| Phenotype / species / niche (§35–37) | `Phenotype`, `NicheSpec`, `Speciation`, `PhenotypeCatalog` |
| Cognitive regimes Ω (§40) | `Regime` enum `{ADAPTIVE, REDUCED, REFLEX, SURVIVAL}`. Ω-research is **not representable** on the endpoint |
| CoverageVector (§56) | `CoverageVector`: 7 named floats |
| ComputationContract (§53) | `ComputationContract` |
| SuccessorPackage (§54) | `ProofCarryingSuccessorV1` |
| Hardware-in-loop (§52) | `HardwareMeasurement` |
| Work-unit budget | `stage6.resources.WorkMeter` |

---

## 4. Deliverables: modules, types, signatures, bounds

Every constant marked *chosen* is a parameter, not a measurement, and is listed again in §4.21.

### 4.1 D9.1 — MSSC formal research specification `[genome]`

```python
# pocketsec/stage9/spec/mssc.py
MSSC_STATEMENT: str   # the §0 objective restated with the bindings of §3.4, for the report
@dataclass(frozen=True, slots=True)
class MSSCConstraints:
    q_min_margin: float = 0.05        # held-out worst-case AP >= base_rate + margin   (chosen)
    r_min: float = 0.85               # worst_case_ap / clean_ap                        (chosen)
    k_min: float | None = None        # calibration: UNMEASURED, never satisfied silently
    ram_bytes_max: int = 65536        # per-session phenotype state                     (chosen)
    wu_per_event_max: int = 64        # static update WU                               (chosen)
DEFAULT_CONSTRAINTS: MSSCConstraints
@dataclass(frozen=True, slots=True)
class ObjectiveVector:
    worst_case_ap: float | None       # None = unmeasured; never dominates anything
    wu_per_event: int
    state_bytes: int                  # session_state_bytes_max from static bounds
    description_length_bits: float    # reported, NOT a dominance axis
def dominates(a: ObjectiveVector, b: ObjectiveVector) -> bool      # >= on all 3 axes, > on one
def pareto_front(points: Sequence[tuple[str, ObjectiveVector]]) -> tuple[str, ...]  # stable order
def hypervolume_2d(points: Sequence[ObjectiveVector], *, ap_ref: float, wu_ref: int) -> float
    # exact 2-D hypervolume over (AP above ap_ref, wu_ref - WU); points with None AP ignored
@dataclass(frozen=True, slots=True)
class MSSCVerdict:
    satisfied: bool | None            # None if any constraint is unmeasured AND none violated
    violations: tuple[str, ...]
    unmeasured: tuple[str, ...]       # always contains "calibration" while k_min is None
def check_constraints(vector: ObjectiveVector, *, clean_ap: float | None, base_rate: float,
                      constraints: MSSCConstraints = DEFAULT_CONSTRAINTS) -> MSSCVerdict
@dataclass(frozen=True, slots=True)
class BeatVerdict:
    beats: bool
    dimension: str | None             # "worst_case_ap" | "wu_per_event" | "state_bytes"
    detail: str
def beats(candidate: ObjectiveVector, baseline: ObjectiveVector, *, candidate_ok: bool,
          ap_margin: float = 0.02, cost_margin: float = 0.10) -> BeatVerdict
class MechanismVerdict(StrEnum): JUSTIFIED, NOT_YET_JUSTIFIED, REJECTED, UNMEASURED
@dataclass(frozen=True, slots=True)
class DetectorComparison:            # the ONE verdict record every compare_* returns (G9.9 reads it)
    mechanism: str                   # the core-id flag it decides, "module:CONSTANT"
    metric: str
    value: float | None
    controls: tuple[tuple[str, float | None], ...]
    verdict: MechanismVerdict
    fired: int                       # how many times the mechanism changed an outcome (0 => INERT)
    detail: str
```

`beats` implements criterion 1's literal wording: *better on one meaningful Pareto dimension*
(AP ≥ baseline + `ap_margin`, or WU or bytes ≤ baseline × (1 − `cost_margin`)), *without
violating another hard requirement* (`candidate_ok` = the candidate's `MSSCVerdict.violations`
is empty), *and* the candidate is not dominated by the baseline. Cost is an objective:
selection and reporting use `dominates`/`pareto_front`, never a weighted sum. MSDL's scalar
exists only as a measured alternative (§4.9).

### 4.2 D9.2 — Computational Genome schema `[genome]`

```python
# pocketsec/stage9/genome/computational.py
COMPUTATIONAL_GENOME_V1_ID = "pocketsec.computational_genome.v1"
COMPUTATIONAL_GENOME_V1_VERSION = register_schema(COMPUTATIONAL_GENOME_V1_ID, "1.0.0")
class LearningLaw(StrEnum):        NONE = "NONE"                    # only member with an executor
class RoutingLaw(StrEnum):         SINGLE_PATH = "SINGLE_PATH"
class DeploymentBackend(StrEnum):  USERSPACE_STDLIB = "USERSPACE_STDLIB"
class EvidenceSemantics(StrEnum):  WINNING_LINEAGE_LOCATORS = "WINNING_LINEAGE_LOCATORS"
@dataclass(frozen=True, slots=True)
class ComputationalGenomeV1:
    registers: tuple[RegisterSpec, ...]
    update: IRProgram                  # phase UPDATE; outputs[r] -> new value of register r
    readout: IRProgram                 # phase READOUT; one FLOAT output per lineage
    aggregation: SessionAggregation    # MAX | SUM | MEAN over lineage readouts
    lookup_table: tuple[float, ...]    # <= MAX_LOOKUP_ENTRIES, consumed by LOOKUP
    declared_max_state_bytes: int
    declared_max_steps_per_event: int
    min_events_for_score: int = 1      # fewer events -> abstain (score None)
    learning_law: LearningLaw = LearningLaw.NONE
    routing_law: RoutingLaw = RoutingLaw.SINGLE_PATH
    backend: DeploymentBackend = DeploymentBackend.USERSPACE_STDLIB
    evidence_semantics: EvidenceSemantics = EvidenceSemantics.WINNING_LINEAGE_LOCATORS
    macro_uses: tuple[str, ...] = ()   # promoted macro names used (already EXPANDED in programs)
    parent_digests: tuple[str, ...] = ()   # lineage, <= 4; excluded from `digest`
    mutation: str = ""                     # operator that produced it; excluded from `digest`
    schema_version: str = COMPUTATIONAL_GENOME_V1_VERSION
    # __post_init__: validate_program(update/readout, registers, SEED_ALPHABET) -> IRError on
    # any defect; static_bounds(...); refuse declared_* below the computed bounds
    # (IRError code DECLARED_BOUND_UNDERSTATED); refuse unknown enum values
    @property digest(self) -> str               # "sha256:" canonical JSON, lineage fields excluded
    @property bounds(self) -> StaticBounds
    @property observation_map(self) -> frozenset[tuple[InputSource, int]]
    def description_length_bits(self) -> float  # formula below
    def phenotype(self) -> Phenotype
    def to_dict(self) -> dict[str, Any]
    @classmethod from_dict(cls, payload: Mapping[str, Any]) -> ComputationalGenomeV1
        # exact keys; a payload "digest" must equal the recomputed one, else ContractError
def build_genome(*, registers, update, readout, aggregation, lookup_table=(),
                 alphabet: PrimitiveAlphabet = SEED_ALPHABET, min_events_for_score=1,
                 parent_digests=(), mutation="") -> ComputationalGenomeV1
    # expands macros through alphabet.expand; sets declared_* EXACTLY to the static bounds;
    # records macro_uses
ARCHITECTURE_FIELD_BINDING: Mapping[str, str]   # §4's 14 field names -> attribute/property
```

**All programs are stored with macros expanded, so every genome is validated against
`SEED_ALPHABET`.** A promoted primitive changes how the *search* proposes code and what
description length it pays. It never changes what the runtime executes (S9X-012 isolation).

`ARCHITECTURE_FIELD_BINDING` (tested: every key present and resolvable):
`state_space→registers`, `observation_map→observation_map`,
`primitive_alphabet→macro_uses` (+ `SEED_ALPHABET.digest`), `transition_law→update`,
`memory_law→registers` (ring length, precision) + `update`,
`forgetting_law→update` (DECAY/ring) + lineage eviction policy, `learning_law→learning_law`,
`uncertainty_law→min_events_for_score`, `readout_law→readout`+`aggregation`,
`routing_law→routing_law`, `resource_control_law→declared_max_state_bytes`+`declared_max_steps_per_event`,
`compression_law→registers[*].precision_bits`, `evidence_semantics→evidence_semantics`,
`deployment_backend→backend`.

**Description length (bits)**, deterministic: for each node, `log2(len(NodeKind))`, plus by kind
APPLY `log2(len(SEED_ALPHABET))` + Σ over args `log2(max(2, i))`; INPUT
`log2(len(InputSource))` (+ `log2(96)` for FEATURE); CONST 32; REG
`log2(max(2, len(registers)))` + `log2(max(2, ring))`. Add per register `2 + 6` bits (type +
precision), `log2(3)` for aggregation, and 32 per lookup entry. Then subtract, per `macro_uses`
entry, `(macro_node_count − 1) × mean_node_bits`.

```python
# pocketsec/stage9/genome/expressibility.py
@dataclass(frozen=True, slots=True)
class ExpressibilityResult:
    target: str
    expressible: bool
    exact: bool | None          # scores equal the reference within 1e-12 on every session
    rank_identical: bool | None
    sessions: int
    max_abs_error: float | None
    genome_digest: str | None
    reason: str                 # non-empty when not expressible or not exact
def phi_oracle_genome() -> ComputationalGenomeV1        # r0 FLOAT; update nodes (REG r0, INPUT FEATURE[73],
                                                        # APPLY MAX(0, 1)); readout (REG r0,); aggregation MAX.
                                                        # 3 WU/event. CANONICAL ORDER shared with
                                                        # enumerate_exhaustive(), so digests match
def phi_oracle_raw_genome() -> ComputationalGenomeV1    # r0' = MAX(r0, ABS(DELTA_PHI));
                                                        # readout DIV(r0, ADD(r0, CONST 8.0))
def deterministic_scorer_genome(spec: DeterministicScorerSpec) -> ComputationalGenomeV1
    # max -> MAX register; mean -> SUM+COUNT registers, readout DIV; last -> overwrite register
def order_free_control_genome() -> ComputationalGenomeV1   # SUM aggregation of per-lineage
    # sums of POPCOUNT(STATE_DELTA_MASK): order-free AND attribution-free (the saturation control)
def hand_designed_genomes() -> Mapping[str, ComputationalGenomeV1]
    # "H1": per-lineage sum of MAX(DELTA_PHI, CONST 0.0), aggregation MAX
    # "H2": update (REG r0 INT, INPUT STATE_DELTA_MASK, APPLY OR(0, 1)); readout (REG r0,
    #       APPLY POPCOUNT(0)); aggregation MAX - canonical order, so H2 is IN the exhaustive set
def reduced_tcn_genome(weights: Sequence[float], features: Sequence[int]) -> ComputationalGenomeV1
    # 1 channel, <= 4 input features, kernel 3 via RING(3) registers, ReLU = MAX(x, 0),
    # max-over-time register, linear readout. Proves the TCN OPERATOR FAMILY is expressible.
def reduced_tcn_reference(sample: Stage2Sample, weights, features) -> float   # plain Python reference
STAGE2_TCN_BOUND_NOTE: str   # the full Stage 2 TCN (hidden 24: 3*96*24 + ... > 6900 weights)
                             # exceeds MAX_CONSTANTS=32 and MAX_PROGRAM_NODES=32; NOT expressible
                             # within bounds. Arithmetic from architecture constants, not a measurement
def check_expressibility(dataset: Stage2Dataset) -> tuple[ExpressibilityResult, ...]
    # targets: "phi-oracle-squashed" (reference max(features[73]) AND PHI_ORACLE_SCORER over
    # stage2.gate_measures.lineage_windows, max over windows), "phi-oracle-raw",
    # "deterministic-scorer/<feature>/<aggregation>" for all 96 x 3, "reduced-tcn",
    # "order-free-control", "H1", "H2", "stage2-tcn-full" (expressible=False, reason=bound note)
```

`mean`/`last` scorers are defined per `LineageWindow` (the causal-root lineage, capped at
`MAX_WINDOW`=64), while genome lineages are keyed by `actor_slot`. Where the two partitions
differ, `exact=False` is **reported, not hidden**. The gate requires exactness only for the
Φ-oracle rows (G9.1 pre-condition).

### 4.3 D9.5 — Algorithmic Chemistry typed IR `[ir]`

```python
# pocketsec/stage9/chemistry/typed_ir.py
IR_VERSION = "pocketsec-onto-ir.1.0.0"
TypedIR = IRProgram                                   # the plan's exposed name
class IRType(StrEnum):      FLOAT, INT, BOOL          # INT is a 64-bit mask (& INT_MASK)
class InputSource(StrEnum): FEATURE, DELTA_PHI, STATE_DELTA_MASK, RELATION, RELATION_FAMILY,
                            TIME_BUCKET, OBJECT_PROPERTY_MASK, EPOCH_ID, LINEAGE_FIRST_EVENT
INPUT_TYPES: Mapping[InputSource, IRType]   # FEATURE/DELTA_PHI FLOAT; LINEAGE_FIRST_EVENT BOOL; rest INT
class NodeKind(StrEnum):    INPUT, CONST, REG, APPLY, PARAM    # PARAM only inside a MacroBody
class ProgramPhase(StrEnum): UPDATE, READOUT
@dataclass(frozen=True, slots=True)
class IRNode:
    kind: NodeKind
    type: IRType
    primitive: str = ""                  # APPLY
    args: tuple[int, ...] = ()           # APPLY; each arg index < this node's index
    source: InputSource | None = None    # INPUT
    index: int = 0                       # FEATURE index 0..95 | register | PARAM position
    lag: int = 0                         # REG: 0 .. ring-1
    value: float | int | bool | None = None   # CONST
@dataclass(frozen=True, slots=True)
class RegisterSpec:
    type: IRType
    ring: int = 1                        # 1..MAX_RING; >1 keeps the last `ring` values
    precision_bits: int = 64             # FLOAT quantised on write to this many mantissa bits (1..64)
    init: float | int | bool = 0
@dataclass(frozen=True, slots=True)
class IRProgram:
    phase: ProgramPhase
    nodes: tuple[IRNode, ...]
    outputs: tuple[int, ...]             # UPDATE: one per register; READOUT: exactly one FLOAT
class IRError(ContractError):
    code: str       # FORWARD_REFERENCE SELF_REFERENCE TYPE_MISMATCH UNKNOWN_PRIMITIVE ARITY
                    # NODE_BOUND REGISTER_BOUND RING_BOUND CONST_BOUND LOOKUP_BOUND FEATURE_INDEX
                    # INPUT_IN_READOUT PARAM_OUTSIDE_MACRO OUTPUT_TYPE OUTPUT_COUNT LAG_BOUND
                    # MACRO_CYCLE MACRO_DEPTH MACRO_SIZE DECLARED_BOUND_UNDERSTATED PRECISION_BOUND
    def __init__(self, code: str, detail: str) -> None
@dataclass(frozen=True, slots=True)
class ProgramReport:
    node_count: int; apply_count: int; work_units: int; dead_nodes: int
    inputs_read: frozenset[tuple[InputSource, int]]; primitives_used: frozenset[str]
    constants: int
@dataclass(frozen=True, slots=True)
class StaticBounds:
    update_wu_per_event: int             # sum of update-node WU (INPUT 1, REG 1, CONST 0, APPLY its WU)
    readout_wu_per_lineage: int
    max_steps_per_event: int             # == len(update.nodes)
    state_bytes_per_lineage: int         # sum(ring * VALUE_BYTES) + LINEAGE_OVERHEAD_BYTES
    session_state_bytes_max: int         # MAX_LINEAGES*per_lineage + side tables + scratch nodes*8
    session_wu_max: int                  # MAX_SESSION_EVENTS*update + (MAX_LINEAGES+evictions cap)*readout
def validate_program(program: IRProgram, registers: Sequence[RegisterSpec],
                     alphabet: PrimitiveAlphabet) -> ProgramReport          # raises IRError
def static_bounds(update: IRProgram, readout: IRProgram, registers: Sequence[RegisterSpec],
                  alphabet: PrimitiveAlphabet) -> StaticBounds
```

**Termination and memory are properties of the representation, not checks that happen to
pass.** A program is a tuple of nodes whose argument indices are strictly smaller than their own
index. It is a DAG, executed once per event in index order. There is no jump, loop or call node
kind, so every well-typed program executes exactly `len(nodes)` steps per event. A loop can only
be written as a forward or self reference, which is refused (`FORWARD_REFERENCE`,
`SELF_REFERENCE`). Recursion can only be written as a macro that references itself, which is
refused at `with_macro` (`MACRO_CYCLE`); inlining depth is capped (`MACRO_DEPTH`). Unbounded
allocation can only be written as a ring above `MAX_RING`, a constant table above its cap, or
more lineages than `MAX_LINEAGES`. The first two are refused at construction. The third is cut at
run time by LRU eviction, which is *counted* and whose bound is recorded in `SessionRun`.

### 4.4 D9.4 (alphabet half) — Primitive Foundry seed alphabet `[ir]`

```python
# pocketsec/stage9/foundry/primitives.py
class PrimitiveOrigin(StrEnum): SEED, PROMOTED
@dataclass(frozen=True, slots=True)
class MacroBody:
    params: tuple[IRType, ...]; nodes: tuple[IRNode, ...]; output: int   # nodes may use PARAM
@dataclass(frozen=True, slots=True)
class Primitive:
    name: str
    arg_types: tuple[IRType, ...]
    result_type: IRType
    work_units: int
    side_table: bool                     # FIRST_SEEN / RARE: per-session bounded table
    fn: Callable[..., float | int | bool] = field(compare=False, repr=False)
    origin: PrimitiveOrigin = PrimitiveOrigin.SEED
    macro: MacroBody | None = None
class PrimitiveAlphabet:
    def __init__(self, primitives: Iterable[Primitive]) -> None     # immutable afterwards
    @property digest(self) -> str
    def get(self, name: str) -> Primitive                           # IRError UNKNOWN_PRIMITIVE
    def names(self) -> tuple[str, ...]
    def with_macro(self, name: str, body: MacroBody) -> PrimitiveAlphabet   # NEW object; cycle/
        # depth/size checks; the receiver is unchanged
    def expand(self, program: IRProgram) -> IRProgram               # inline every macro
SEED_ALPHABET: PrimitiveAlphabet
```

`SEED_ALPHABET` (architecture Π0, §7) has 26 primitives. The table gives each one's type and WU.

| primitive | signature | WU | semantics |
|---|---|---|---|
| ADD SUB MUL MIN MAX | F,F→F | 1 | IEEE; results clamped to ±1e12 |
| DIV | F,F→F | 2 | `x / y`, `0.0` when `y == 0` (safe division; Stage 3 lacked it) |
| ABS | F→F | 1 | |
| CLIP01 | F→F | 1 | clamp to [0, 1] |
| LT GT | F,F→B | 1 | COMPARE family |
| EQ_I | I,I→B | 1 | COMPARE family |
| SELECT | B,F,F→F | 1 | `a if b else c` |
| B2F | B→F | 1 | 1.0 / 0.0 |
| AND OR XOR | I,I→I | 1 | bitwise on the 64-bit mask |
| NOT | I→I | 1 | `~x & INT_MASK` |
| SHIFT | I,I→I | 1 | left shift by `b % 64`, masked |
| POPCOUNT | I→F | 1 | |
| HASH | I→I | 2 | `(x * 2654435761) & 0xFFFF` |
| LOOKUP | I→F | 2 | `lookup_table[x % len]`, `0.0` if the table is empty |
| COUNT | B,F→F | 1 | `prev + (1.0 if b else 0.0)` |
| DECAY | F,F,F→F | 2 | `clip01(λ)·prev + x` |
| BIND | I,I→I | 1 | `a ^ rotl64(b, 1)` (HDC bind) |
| GRAPH_EDGE | I,I→I | 1 | `((a & 0xFF) << 8) \| (b & 0xFF)` |
| STATE_DELTA | I,I→B | 1 | bit `b % 9` of mask `a` (DIMENSIONS order) |
| TEMPORAL_WITHIN | I,I,I→B | 1 | `abs(a − b) <= c` |
| FIRST_SEEN | I→B | 4 | per-session table of `SIDE_TABLE_ENTRIES`, LRU, evictions counted |
| RARE | I→F | 4 | `1/(1+count)` in a per-session bounded counter, evictions counted |

`SUPERPOSE` is **not** added. For two binary operands it is identical to `OR`, and a duplicate
primitive is a catalogue richer than its consumer (lesson 3). Every primitive must fire at least
once, either in `tests/test_stage9_ir.py` or in a gate search. Any primitive that never appears in
an evaluated genome is listed `INERT_PRIMITIVES` in the findings.

### 4.5 D9.5 (interpreter) — Phenotype `[ir]`

```python
# pocketsec/stage9/chemistry/phenotype.py
class SessionAggregation(StrEnum): MAX, SUM, MEAN
@dataclass(frozen=True, slots=True)
class SessionInterventions:
    reset_at: int | None = None                  # ARGUS state-reset: clear all lineage state at event i
    forget: tuple[tuple[int, int], ...] = ()     # CHRONOS: (event index, actor_slot) deletions
@dataclass(frozen=True, slots=True)
class SessionRun:
    score: float | None          # None = abstained (events < min_events_for_score)
    work_units: int              # exactly events*update_wu + readouts*readout_wu
    events: int
    truncated_events: int        # beyond MAX_SESSION_EVENTS, counted, never processed
    lineages: int
    lineage_evictions: int       # LRU; an evicted lineage's readout is folded into the aggregate
    side_table_evictions: int
    state_bytes_peak: int        # accounted from live registers + side tables, <= static bound
    evidence: tuple[str, ...]    # EncodedTransition.evidence of the <= 8 most recent events that
                                 # changed the winning lineage's registers (MAX aggregation)
class Phenotype:
    def __init__(self, *, update: IRProgram, readout: IRProgram,
                 registers: Sequence[RegisterSpec], aggregation: SessionAggregation,
                 lookup_table: Sequence[float] = (), min_events_for_score: int = 1,
                 alphabet: PrimitiveAlphabet = SEED_ALPHABET) -> None   # validates; compiles to a
                 # flat tuple of (callable, arg slots) - no eval/exec
    @property bounds(self) -> StaticBounds
    @property digest(self) -> str
    def run_session(self, steps: Sequence[EncodedTransition], *, meter: WorkMeter | None = None,
                    interventions: SessionInterventions = SessionInterventions()) -> SessionRun
        # charges meter (events*update_wu) BEFORE running and each readout before computing it;
        # WorkBudgetExceeded propagates - never a partial score
    def run_dataset(self, dataset: Stage2Dataset, *, meter: WorkMeter | None = None
                    ) -> tuple[SessionRun, ...]
```

Lineage key: `EncodedTransition.actor_slot`. The table holds at most `MAX_LINEAGES`. A new
lineage evicts the least-recently-updated one. The evicted lineage's readout is computed (charged)
and folded into the aggregate, but its state is gone. If the lineage reappears it restarts from
`init`. This is deliberate, and it is the attack surface ARGUS's `lineage_table_flood` measures.
A register write quantises FLOAT values to `precision_bits` (round-half-even on the mantissa).
Execution is deterministic: no randomness and no hash-order dependence. Dict iteration is by
insertion order, and ties in MAX pick the lowest `actor_slot`.

### 4.6 D9.14 — ARGUS architecture adversary, and the evaluation substrate `[evaluation]`

```python
# pocketsec/stage9/labs/splits.py
SPLITS_VERSION = "stage9-splits.1.0.0"
CORPUS = "ambiguous"; HEADROOM_COUNT = 240; SATURATED_COUNT = 60; TRAIN_SEED = 3; HELDOUT_SEED = 11
MAX_COMPILE_WORKERS = 4
@dataclass(frozen=True, slots=True)
class SplitKey:
    corpus: str; count: int; seed: int; attack_id: str        # "clean" or an ArgusAttack id
    corpus_version: str; encoder_version: str; attack_version: str
@dataclass(frozen=True, slots=True)
class CompiledVariant:
    key: SplitKey
    dataset: Stage2Dataset
    content_digest: str                 # sha256 over (sample_id, label, actor_slot, relation,
                                        # state_delta_mask, delta_phi, features rounded 9dp)
    identities_reused_across_sessions: int     # must be 0 (corpus trap, MEMORY.md)
    median_peak_abs_dphi_by_class: tuple[float, float]   # (benign, malicious), both must be > 0
    compile_seconds: float
    loadavg_before: tuple[float, float, float]; loadavg_after: tuple[float, float, float]
    results: tuple[ScenarioResult, ...] = ()   # kept only when keep_results=True (serial path); the
                                               # Stage 6 exit needs ScenarioResult, not encodings
def compile_scenarios(scenarios: Sequence[Scenario], *, key: SplitKey,
                      keep_results: bool = False) -> CompiledVariant
    # one FRESH Stage1Pipeline; run_scenario(s, offset=i); stage2.dataset._encode(result, i)
def compile_variant(*, count: int, seed: int, attack_id: str = "clean",
                    keep_results: bool = False) -> CompiledVariant
def compile_variants(*, count: int, seed: int, attack_ids: Sequence[str],
                     workers: int = MAX_COMPILE_WORKERS) -> tuple[CompiledVariant, ...]
    # ProcessPoolExecutor; worker takes only (count, seed, attack_id); result digests equal serial
def dataset_digest(dataset: Stage2Dataset) -> str
@dataclass(frozen=True, slots=True)
class SaturationCheck:
    degenerate: bool; reason: str; phi_oracle_at_ceiling: bool
    stage3_verdict: dict[str, Any]      # stage3.labs.ablation.saturation_guard(...).to_dict()
def stage9_saturation(scores: Mapping[str, float | None], *, phi_oracle: float | None,
                      order_free: float | None) -> SaturationCheck
    # degenerate if Stage 3's guard says so, OR phi_oracle >= 0.99 (PHI_ORACLE_AT_CEILING)
```

```python
# pocketsec/stage9/argus/adversary.py
ARGUS_VERSION = "stage9-argus.1.0.0"
class ArgusSurface(StrEnum): DATA, INPUT, STATE, MODEL, SEARCH, RESOURCE, SENSORS, SUPPLY_CHAIN
@dataclass(frozen=True, slots=True)
class ScenarioAttack:                    # label-preserving, applied BEFORE Stage 1
    attack_id: str; surface: ArgusSurface; description: str; salt: int
    transform: Callable[[Scenario, random.Random], tuple[Behaviour, ...]] = field(compare=False)
    def apply(self, scenarios: Sequence[Scenario], *, seed: int) -> tuple[Scenario, ...]
        # rng = random.Random(seed * 1_000_003 + salt); name/label/technique preserved
SCENARIO_ATTACKS: tuple[ScenarioAttack, ...]   # the FITNESS attack set, in this order:
    # rename_binaries [INPUT]      execve "path" -> "/opt/x/<8 hex>" (consistent per original path)
    # reorder_across_actors [INPUT] swap adjacent behaviours of different pids, p=0.3
    # benign_duplicate_flood [INPUT] duplicate a behaviour in place, p=0.1
    # timing_stretch [SENSORS]     "_gap_ns" * U(0.2, 5.0), floored at 1
    # sensor_drop_10 [SENSORS]     drop each behaviour with p=0.1
    # lineage_table_flood [STATE]  insert 64 single-read behaviours ("read", path "/tmp/s9-flood")
    #   from 64 fresh actors at random positions; pid/start_time derived from sha256(scenario.name, k)
    #   so they are SESSION-UNIQUE (corpus trap: identities_reused_across_sessions must stay 0)
@dataclass(frozen=True, slots=True)
class LifecycleAttack:
    attack_id: str; surface: ArgusSurface; description: str
    runner: str                           # "module:function", resolved by the gate, not imported here
LIFECYCLE_ATTACKS: tuple[LifecycleAttack, ...]
    # constant_corruption [MODEL]        -> argus.adversary:constant_corruption
    # state_reset_midsession [STATE]     -> argus.adversary:state_reset_midsession
    # work_budget_starvation [RESOURCE]  -> argus.adversary:work_budget_starvation
    # tampered_genome [SUPPLY_CHAIN]     -> argus.adversary:tampered_genome
    # benchmark_contamination [SEARCH]   -> ontogenesis.fitness:contamination_attack
    # train_label_noise [DATA]           -> argus.adversary:train_label_noise
    # shuffled_label_search [SEARCH]     -> ontogenesis.search:run_shuffled_label_control
    # hypothesis_explosion [SEARCH]      -> gaia.qd_ecology:hypothesis_explosion
    # tampered_successor [SUPPLY_CHAIN]  -> successor.proof_carrying:tampered_successor
ArgusAttack = ScenarioAttack | LifecycleAttack
@dataclass(frozen=True, slots=True)
class ArgusFinding:
    attack_id: str; surface: ArgusSurface
    kind: str           # "MEASUREMENT" (fired = outcomes changed) | "DEFENCE" (fired = refusals;
                        # a defence must fire on EVERY trial: fired == total, else it FAILED)
    fired: int          # sessions whose score changed / refusals raised / ranks changed
    total: int          # sessions or trials examined
    inert: bool         # fired == 0
    metric_before: float | None; metric_after: float | None
    detail: str; measured_by: str
def attack_findings(genome: ComputationalGenomeV1, clean: CompiledVariant,
                    variants: Sequence[CompiledVariant]) -> tuple[ArgusFinding, ...]
    # sessions aligned by sample_id; a sample missing from a variant counts as fired
def constant_corruption(genome, dataset, *, seed: int) -> ArgusFinding   # +/-10% every CONST/lookup
def state_reset_midsession(genome, dataset) -> ArgusFinding              # reset_at = events // 2
def work_budget_starvation(genome, dataset) -> ArgusFinding              # budget = half the need;
    # fired = number of WorkBudgetExceeded raised; asserts no partial score was produced
def tampered_genome(genome) -> ArgusFinding          # 3 tamperings (op swap, arg -> forward ref,
    # digest kept) -> each must raise; fired = refusals
def train_label_noise(records_top: Sequence[tuple[ComputationalGenomeV1, FitnessRecord]],
                      train: EvaluationSuite, *, rate: float = 0.05, seed: int) -> ArgusFinding
    # re-rank the top 16 under 5% flipped train labels; fired = genomes whose rank moved,
    # detail names whether the winner changed
@dataclass(frozen=True, slots=True)
class FittestAttrition:
    examined: int; died: int; died_digests: tuple[str, ...]
def fittest_die_under_attack(records: Sequence[FitnessRecord], *, reference_worst_case: float,
                             top_k: int = 10, drop_tolerance: float = 0.05) -> FittestAttrition
    # top_k by CLEAN train AP; died := worst_case < reference (Φ-oracle's worst case on the same
    # suite) OR clean - worst_case > drop_tolerance
def coverage(findings: Sequence[ArgusFinding]) -> frozenset[ArgusSurface]   # non-inert only
```

```python
# pocketsec/stage9/ontogenesis/fitness.py
MAX_CACHE_ENTRIES = 4096
@dataclass(frozen=True, slots=True)
class EvaluationSuite:
    name: str; clean: CompiledVariant; attacked: tuple[CompiledVariant, ...]
    labels_override: tuple[int, ...] | None = None     # shuffled-label control
    @property base_rate(self) -> float
    @property labels(self) -> tuple[int, ...]
    @property events_total(self) -> int
    def with_shuffled_labels(self, seed: int) -> EvaluationSuite
    def with_label_noise(self, rate: float, seed: int) -> EvaluationSuite
@dataclass(frozen=True, slots=True)
class FitnessRecord:
    genome_digest: str; suite: str
    clean_ap: float | None
    variant_aps: tuple[tuple[str, float | None], ...]
    worst_case_ap: float | None; worst_variant: str
    wu_per_event: int; state_bytes: int; description_length_bits: float
    work_units_spent: int; constant_output: bool; lineage_evictions: int
    scores_digest: str                   # sha256 of the clean score vector
    def objective(self) -> ObjectiveVector
class EvaluationCache:                   # bounded LRU keyed (genome digest, suite name, labels digest)
    def __init__(self, capacity: int = MAX_CACHE_ENTRIES) -> None
    def get(self, key: tuple[str, str, str]) -> FitnessRecord | None
    def put(self, key: tuple[str, str, str], record: FitnessRecord) -> None
    @property hits(self) -> int; @property misses(self) -> int; @property evictions(self) -> int
def session_scores(genome: ComputationalGenomeV1, dataset: Stage2Dataset, *,
                   meter: WorkMeter | None = None) -> tuple[float | None, ...]
def evaluate(genome: ComputationalGenomeV1, suite: EvaluationSuite, *, meter: WorkMeter,
             cache: EvaluationCache | None = None) -> FitnessRecord
    # AP via stage0 average_precision; an abstained score (None) ranks as 0.0 and is counted;
    # worst_case_ap = min over clean + attacked; a cache hit charges 0 WU and is counted
@dataclass(frozen=True, slots=True)
class ContaminationReport:
    overlapping_sample_ids: int; overlapping_content: int; refused: bool
def contamination_check(train: EvaluationSuite, heldout: EvaluationSuite) -> ContaminationReport
def contamination_attack(train: EvaluationSuite, heldout: EvaluationSuite) -> ArgusFinding
    # copies 20 held-out sessions into train; the check must refuse (fired = 1)
```

**Fitness is worst-case over the attack set, not average.** Selection sees `worst_case_ap` on
train (clean + 6 scenario attacks). Winners are then re-evaluated on the **held-out** suite
(seed 11, clean + the same 6 attacks), which the search never saw. `contamination_check` must
report 0 overlap before any search runs. Otherwise the gate context refuses to build.

### 4.7 D9.12 (variation) — GENESIS `[search]`

```python
# pocketsec/stage9/genesis/variation.py
class VariationOperator(StrEnum):
    REPLACE, MERGE, SPLIT, FACTORIZE, SPARSIFY, SPECIALIZE, REMOVE, MOVE, COMPRESS,
    DEVELOPMENTAL, INSERT, CROSSOVER, MACRO_INSERT
@dataclass(frozen=True, slots=True)
class Mutation:
    operator: VariationOperator
    child: ComputationalGenomeV1 | None
    refused_reason: str                  # "" when child is not None
def random_genome(rng: random.Random, *, alphabet: PrimitiveAlphabet = SEED_ALPHABET,
                  max_registers: int = 3, max_depth: int = 3) -> ComputationalGenomeV1
    # the ONE generator shared by random search and the initial population
def mutate(genome: ComputationalGenomeV1, operator: VariationOperator, rng: random.Random, *,
           alphabet: PrimitiveAlphabet = SEED_ALPHABET) -> Mutation
def crossover(a: ComputationalGenomeV1, b: ComputationalGenomeV1, rng: random.Random) -> Mutation
def unique_utility(genome: ComputationalGenomeV1, node_index: int, suite: EvaluationSuite, *,
                   meter: WorkMeter) -> float | None
    # U(A) - U(A without node c) on worst-case train AP (architecture §33)
@dataclass(frozen=True, slots=True)
class OperatorStats:
    operator: VariationOperator; proposed: int; valid: int; improved_archive: int
```

Operator semantics, all type-preserving (an invalid child is refused and counted, never
repaired silently):

- **REPLACE:** swap a primitive for another with the same signature.
- **REMOVE** (subtractive): delete an APPLY node and rewire its consumers to a same-typed
  argument, or to a CONST.
- **INSERT:** wrap an operand in a new APPLY.
- **MERGE:** common-subexpression merge of identical nodes or identical registers.
- **SPLIT:** duplicate a shared node so its consumers can diverge.
- **FACTORIZE:** extract a repeated subexpression into a new register.
- **SPARSIFY:** replace an INPUT with CONST 0.
- **SPECIALIZE:** constant-fold.
- **COMPRESS:** halve `precision_bits` or decrement `ring`.
- **DEVELOPMENTAL:** change `aggregation`.
- **CROSSOVER:** exchange typed subtrees between two register updates.
- **MACRO_INSERT:** use a promoted macro, only when the alphabet has one.
- **MOVE:** always refused with `NO_ALTERNATIVE_BACKEND`, because `DeploymentBackend` has one
  member. MOVE is expected to be **INERT**, and that is reported.

### 4.8 D9.13 — GAIA QD ecology `[search]`

```python
# pocketsec/stage9/gaia/qd_ecology.py
WU_BINS = (2, 4, 8, 16, 32, 64); BYTES_BINS = (256, 1024, 4096, 16384, 65536); SIZE_BINS = (3, 6, 12, 24, 64)
# bins are upper edges; a value above the last edge goes in an overflow bin -> 7*6*2*6 = 504 cells max
QD_ARCHIVE_DEFAULT_ENABLED: bool = False          # False => single-cell archive (plain elitist GA)
FOSSIL_AVOIDANCE_DEFAULT_ENABLED: bool = False
MAX_FOSSILS = 2048; MAX_LINEAGE_RECORDED = 16
@dataclass(frozen=True, slots=True)
class NicheKey: wu_bin: int; bytes_bin: int; stateful: bool; size_bin: int
    # stateful := update reads a REG and writes it back through a non-identity APPLY
@dataclass(frozen=True, slots=True)
class Elite:
    genome: ComputationalGenomeV1; fitness: FitnessRecord; niche: NicheKey
    lineage: tuple[str, ...]; argus_failures_survived: int; inserted_at: int
class ArchiveOutcome(StrEnum): NEW_CELL, IMPROVED, REJECTED_WORSE, REJECTED_FOSSIL
class QualityDiversityArchive:
    def __init__(self, *, niches: bool = QD_ARCHIVE_DEFAULT_ENABLED) -> None
    def insert(self, genome: ComputationalGenomeV1, fitness: FitnessRecord, *,
               lineage: tuple[str, ...] = ()) -> tuple[ArchiveOutcome, Elite | None]
    def elites(self) -> tuple[Elite, ...]
    def pareto_elites(self) -> tuple[Elite, ...]
    def occupied(self) -> int
class FossilReason(StrEnum): DOMINATED, ARGUS_FAILURE, RESOURCE_FAILURE, INVALID
@dataclass(frozen=True, slots=True)
class ComputationalFossil:           # architecture §45, every field bound
    genome_hash: str; niche: NicheKey | None; ancestry: tuple[str, ...]
    mutation_history: tuple[str, ...]; reason_for_failure: FossilReason
    counterexample_signature: str | None; resource_failure: str | None
    security_regression: float | None; epochs_tested: tuple[int, ...]
class FossilStore:                   # bounded MAX_FOSSILS, oldest evicted and counted
    def add(self, fossil: ComputationalFossil) -> None
    def __contains__(self, genome_hash: str) -> bool
    @property evictions(self) -> int; @property avoided(self) -> int
def synergy(a: Sequence[float | None], b: Sequence[float | None], labels: Sequence[int]) -> float | None
    # AP(max of rank-normalised a,b) - AP(a) - AP(b)   (architecture §43)
def parasites(elite: Elite, suite: EvaluationSuite, *, meter: WorkMeter,
              tolerance: float = 0.005) -> tuple[int, ...]   # node indices with UniqueUtility <= tol
@dataclass(frozen=True, slots=True)
class DominanceReport: dominating_digest: str | None; cells_dominated: int; cells_occupied: int
def single_architecture_dominance(archive: QualityDiversityArchive) -> DominanceReport
def compare_qd(main: Sequence[SearchRun], niches: Sequence[SearchRun], heldout: EvaluationSuite
               ) -> DetectorComparison
    # JUSTIFIED iff median held-out worst-case AP delta >= +0.02 over the single-cell arm AND no
    # single elite dominates >= 90% of occupied cells (architecture §68 QD falsifier)
def hypothesis_explosion(archive_factory: Callable[[], QualityDiversityArchive]) -> ArgusFinding
    # offers 10x the cell count of distinct genomes; asserts occupied <= cell bound, counts rejections
```

### 4.9 The ONTOGENESIS meta-controller — `ontogenesis/search.py` `[search]`

```python
class SearchStrategy(StrEnum): EVOLUTIONARY, RANDOM, EXHAUSTIVE
SEARCH_BUDGET_WU: int = 96_000_000          # per (strategy, seed)   (chosen). Arithmetic, NOT a
    # measurement: one evaluation = 7 train variants x ~17.9k events x ~4-8 WU ~= 0.5-1.0M WU, so
    # ~100-190 evaluations; the 126-genome exhaustive set costs the same order. The gate reports
    # the true exhaustive spend next to the equal budget
SEARCH_SEEDS: tuple[int, ...] = (101, 202, 303)
MAX_POPULATION = 64; INITIAL_POPULATION = 32
SUBTRACTIVE_SHARE = 0.25                    # REMOVE drawn with this probability (architecture §33)
EVOLUTIONARY_SEARCH_DEFAULT_ENABLED: bool = False
SUBTRACTIVE_BIAS_DEFAULT_ENABLED: bool = False
EXHAUSTIVE_INPUTS: tuple[tuple[InputSource, int], ...] = (
    (FEATURE, 73), (FEATURE, 83), (FEATURE, 85), (FEATURE, 90), (DELTA_PHI, 0),
    (STATE_DELTA_MASK, 0), (RELATION_FAMILY, 0))
@dataclass(frozen=True, slots=True)
class SearchConfig:
    strategy: SearchStrategy; seed: int; budget_wu: int = SEARCH_BUDGET_WU
    niches: bool = QD_ARCHIVE_DEFAULT_ENABLED; fossil_avoidance: bool = FOSSIL_AVOIDANCE_DEFAULT_ENABLED
    subtractive: bool = SUBTRACTIVE_BIAS_DEFAULT_ENABLED
    label_shuffle_seed: int | None = None
    # defaults READ the module flags, so the gate's main arm is "everything optional off"
@dataclass(frozen=True, slots=True)
class SearchRun:
    config: SearchConfig
    evaluations: int; cache_hits: int; wu_spent: int; budget_exhausted: bool
    records: tuple[FitnessRecord, ...]           # every evaluated genome, bounded by MAX_RECORDS=8192
    genomes: tuple[ComputationalGenomeV1, ...]   # index-aligned with records
    archive_elites: tuple[Elite, ...]
    winner: int | None                           # index into records: max worst-case train AP
                                                 # among MSSC-constraint-satisfying genomes
    operator_stats: tuple[OperatorStats, ...]
    population_evictions: int; fossils_recorded: int; fossils_avoided: int
    determinism_digest: str                      # sha256 over the evaluated digest sequence
    rediscovered_phi: bool                       # some evaluated genome's TRAIN clean scores are
                                                 # rank-identical to phi_oracle_genome()'s
    wall_seconds: float; loadavg_before: tuple[float, float, float]; loadavg_after: tuple[float, float, float]
def enumerate_exhaustive() -> tuple[ComputationalGenomeV1, ...]
    # EXACTLY 126 genomes: one register; float register: r' = op(r, u(x)), op in {ADD,MAX,MIN},
    # x in the 5 float inputs with u in {id, ABS} plus the 2 INT inputs through POPCOUNT
    # (12 terms x 3 ops = 36), readout REG, aggregation in {MAX,SUM,MEAN} -> 108; INT register:
    # r' = op(r, x), op in {OR,XOR,AND}, x in the 2 INT inputs (6), readout POPCOUNT(REG),
    # 3 aggregations -> 18. Canonical node order: (REG r0, INPUT x[, APPLY u], APPLY op(0, last)).
    # Contains phi_oracle_genome() and H2 BY DIGEST; a test asserts both and the count 126.
def run_search(config: SearchConfig, train: EvaluationSuite) -> SearchRun
    # EVOLUTIONARY: 32 random genomes, then MAP-Elites loop: uniform elite -> operator (REMOVE with
    #   SUBTRACTIVE_SHARE if config.subtractive, else uniform over the rest; CROSSOVER 0.1) ->
    #   evaluate -> insert; stops when WorkBudgetExceeded is raised by the shared meter.
    # RANDOM: random_genome until the budget is exhausted.
    # EXHAUSTIVE: evaluate enumerate_exhaustive() once; wu_spent is its true cost (may be less
    #   than the equal budget - reported, not padded).
    # Never seeds the Φ-oracle or H1/H2 into any population.
def compare_arm(main: Sequence[SearchRun], arm: Sequence[SearchRun], heldout: EvaluationSuite, *,
                flag: str) -> DetectorComparison
    # seed-matched: subtractive arm -> winner WU/event at held-out worst-case AP within 0.01
    # (>= 10% lower on 3/3); fossil arm -> WU spent to reach the run's final best (>= 10% lower on
    # 3/3); niches arm is compared by gaia.qd_ecology.compare_qd
@dataclass(frozen=True, slots=True)
class WinnerReport:
    run: str; genome_digest: str; train_worst_case_ap: float | None
    heldout_worst_case_ap: float | None; heldout_clean_ap: float | None
    gap: float | None                  # train_worst_case - heldout_worst_case
    wu_per_event: int; state_bytes: int
def heldout_report(runs: Sequence[SearchRun], heldout: EvaluationSuite) -> tuple[WinnerReport, ...]
@dataclass(frozen=True, slots=True)
class StrategyComparison:
    verdict: MechanismVerdict
    per_seed_delta_vs_random: tuple[float | None, ...]
    delta_vs_exhaustive: tuple[float | None, ...]
    median_delta_vs_random: float | None; median_delta_vs_exhaustive: float | None
    exhaustive_wu: int; equal_budget_wu: int; detail: str
def compare_strategies(evolutionary: Sequence[SearchRun], random_runs: Sequence[SearchRun],
                       exhaustive: SearchRun, heldout: EvaluationSuite) -> StrategyComparison
    # metric: held-out worst-case AP of each run's winner.
    # JUSTIFIED iff median delta >= +0.02 vs random AND vs exhaustive, and delta > 0 on every
    # seed vs both; REJECTED iff either median delta <= -0.02; else NOT_YET_JUSTIFIED.
class NullVerdict(StrEnum): NULL_HELD, PRIOR_INFORMATIVE, LEAK_SUSPECTED
@dataclass(frozen=True, slots=True)
class ShuffledLabelControl:
    winner_digest: str | None; train_ap_on_shuffled: float | None; heldout_ap: float | None
    permutation_p_value: float | None            # 200 permutations of held-out labels, (1+k)/201
    prior_percentile: float | None               # winner's held-out AP among 64 unselected random genomes
    verdict: NullVerdict; detail: str
def run_shuffled_label_control(train: EvaluationSuite, heldout: EvaluationSuite, *,
                               seed: int = 101, shuffle_seed: int = 9) -> ShuffledLabelControl
    # NULL_HELD iff p > 0.05; PRIOR_INFORMATIVE iff p <= 0.05 but prior_percentile < 0.95
    # (the SEARCH SPACE, not the labels, is informative); LEAK_SUSPECTED otherwise
```

### 4.10 D9.6 — Security Renormalization laboratory `[physics]`

```python
# pocketsec/stage9/renormalization/laboratory.py
RENORMALIZATION_DEFAULT_ENABLED: bool = False
class CoarseGraining(StrEnum):
    R1_DROP_NOVELTY_TEMPORAL   # zero groups novelty_tensor, novelty_scalars, temporal
    R2_RELATION_TO_FAMILY      # zero relation_onehot; family kept
    R3_STATE_ONLY              # keep only state_delta_raised, state_delta_scalars, delta_phi
    R4_LINEAGE_EPISODE         # one summary step per lineage: OR mask, sum dphi, max features
def coarse_grain(dataset: Stage2Dataset, level: CoarseGraining) -> Stage2Dataset
def feature_bytes(level: CoarseGraining | None) -> int     # non-zeroed slots * 8, per event
@dataclass(frozen=True, slots=True)
class SemanticConservation:
    level: str; decision_agreement: float   # decisions at the FPR-0.05 threshold fitted on the
                                            # original representation's train scores, unchanged
    ap_before: float | None; ap_after: float | None; bytes_before: int; bytes_after: int
@dataclass(frozen=True, slots=True)
class CounterfactualDistinction:
    level: str; pairs: int; distinguished_before: int; distinguished_after: int
def semantic_conservation(label: str, *, train_scores_before: Sequence[float | None],
                          scores_before: Sequence[float | None], scores_after: Sequence[float | None],
                          labels: Sequence[int], bytes_before: int, bytes_after: int
                          ) -> SemanticConservation      # generic: ANY abstraction (G9.3)
def counterfactual_distinction(label: str, *, pair_scores_before: Sequence[float | None],
                               pair_scores_after: Sequence[float | None]) -> CounterfactualDistinction
    # pairs interleaved: index 2i malicious, 2i+1 its twin; distinguished := score(2i) > score(2i+1)
def attribution_counterfactuals(scenarios: Sequence[Scenario], *, seed: int
                                ) -> tuple[tuple[Scenario, Scenario], ...]
    # for each malicious scenario: a twin with the chain stages (behaviours whose "_gap_ns" >=
    # 300 s; routine gaps are <= 90 s, ambiguous_corpus.py:237/257) re-attributed to distinct other
    # actors - ONLY attribution changes. Twin label 0.
@dataclass(frozen=True, slots=True)
class RenormalizationResult:
    genome_digest: str; conservation: tuple[SemanticConservation, ...]
    counterfactual: tuple[CounterfactualDistinction, ...]
    fixed_point_level: str | None; fixed_point_iterations: int   # R applied until digest stable, <= 4
    random_drop_control_ap: float | None       # equal-byte random group drop
    verdict: MechanismVerdict; detail: str
def run_renormalization(genome: ComputationalGenomeV1, train: Stage2Dataset,
                        heldout: Stage2Dataset, pairs: Stage2Dataset, *, seed: int
                        ) -> RenormalizationResult
    # JUSTIFIED iff some level keeps held-out AP >= raw - 0.01 with >= 30% fewer feature bytes,
    # keeps every counterfactual distinction, AND beats the random-drop control by >= 0.02
```

### 4.11 D9.7 — Symmetry/Conservation research suite `[physics]`

```python
# pocketsec/stage9/symmetry/suite.py
SYMMETRY_BREAKING_DEFAULT_ENABLED: bool = False
class Transformation(StrEnum):
    ACTOR_SLOT_PERMUTATION   # permute actor_slot ids within a session (user/PID renaming)
    PATH_CLASS               # = rename_binaries variant
    TIME_TRANSLATION         # = timing_stretch variant
    BENIGN_REORDER           # = reorder_across_actors variant
    HOST_IDENTITY            # UNMEASURED: single synthetic host
    INTERPRETER_SUBSTITUTION # UNMEASURED: no interpreter alternatives in the corpus
    LEARNED                  # UNMEASURED (S9X-023): no symmetry learner is built
@dataclass(frozen=True, slots=True)
class SymmetryTest:
    transformation: str; sessions: int; score_changed: int
    max_abs_delta: float | None; invariant: bool | None      # None = UNMEASURED
def invariance(genome: ComputationalGenomeV1, clean: Stage2Dataset,
               transformed: Stage2Dataset | None, transformation: Transformation) -> SymmetryTest
def permute_actor_slots(dataset: Stage2Dataset, *, seed: int) -> Stage2Dataset
def symmetry_breaking_scores(genome, clean: Stage2Dataset, variants: Sequence[Stage2Dataset]
                             ) -> tuple[float, ...]     # B_G(x) = mean |score(x) - score(g(x))|
def compare_symmetry_breaking(genome, heldout_clean, heldout_variants) -> DetectorComparison
    # controls: rarity = max features[83] (Stage 1 novelty peak); Φ-oracle. JUSTIFIED iff >= max+0.02
```

```python
# pocketsec/stage9/symmetry/conservation.py
CONSERVATION_DEFAULT_ENABLED: bool = False
@dataclass(frozen=True, slots=True)
class ConservedQuantity: name: str; genome: ComputationalGenomeV1   # a per-lineage statistic
def candidate_quantities() -> tuple[ConservedQuantity, ...]
    # symbolic: popcount(OR mask), sum dphi, distinct relation families (OR of 1<<family), max novelty
    # projection: per feature group, the per-lineage mean of that group's first slot (13)
@dataclass(frozen=True, slots=True)
class ConservationTest:
    quantity: str; envelope: float | None       # benign-train 99th percentile of per-step |dQ|
    benign_violation_rate: float | None; malicious_violation_rate: float | None
    ap: float | None                            # session score = max per-step |dQ| / envelope
    noether_pair: str | None                    # the invariant transformation it was paired with
def conservation_search(train: Stage2Dataset, heldout: Stage2Dataset,
                        invariants: Sequence[SymmetryTest]) -> tuple[ConservationTest, ...]
def compare_conservation(tests, heldout) -> DetectorComparison
    # controls: Φ-oracle (S9X-030 simple statistic) and H2 (graph-motif baseline, S9X-031)
```

### 4.12 D9.8 — Causal Geometry/Phase Observatory benchmarks `[physics]`

```python
# pocketsec/stage9/geometry/causal.py
CAUSAL_GEOMETRY_DEFAULT_ENABLED: bool = False
MAX_MECHANISM_LENGTH = 64; MAX_PROTOTYPES = 32
@dataclass(frozen=True, slots=True)
class TransformationCosts:
    insert: float = 1.0; delete: float = 1.0; substitute_family: float = 1.0
    substitute_mask_bit: float = 0.5; transpose: float = 0.5
def mechanism_sequence(sample: Stage2Sample, actor_slot: int) -> tuple[tuple[int, int], ...]
    # (relation_family, state_delta_mask), truncated to MAX_MECHANISM_LENGTH
def mechanism_distance(a, b, costs: TransformationCosts = TransformationCosts()) -> float
    # bounded O(64x64) DP (Damerau-style transpose = "change causal ordering")
def build_benign_manifold(train: Stage2Dataset) -> tuple[tuple[tuple[int, int], ...], ...]
def geodesic_deviation(sample: Stage2Sample, manifold) -> float   # max over lineages of min distance
def pooled_knn_score(sample, train_benign_pooled, k: int = 5) -> float    # control
def compare_causal_geometry(train, heldout) -> DetectorComparison
    # controls: pooled-feature kNN (Euclidean, mean-pooled 96-d) and Φ-oracle. Isolation Forest:
    # NOT BUILT (it would be a second ML library in stdlib) -> recorded UNMEASURED
```

```python
# pocketsec/stage9/geometry/phase.py
PHASE_OBSERVATORY_DEFAULT_ENABLED: bool = False; PSI_WINDOW = 8
class OrderParameter(StrEnum): DPHI_VARIANCE, DPHI_AUTOCORR, TRANSITION_RATE, FAMILY_ENTROPY,
                               NOVELTY_ACCUMULATION
@dataclass(frozen=True, slots=True)
class PhaseObservation:
    parameter: str; ap: float | None; benign_false_transition_rate: float | None   # S9X-042
    precursor_lead_events: float | None     # median events between the first Ψ exceedance and
                                            # the first step with |dphi| >= 2.0 in malicious sessions
def order_parameter_series(sample: Stage2Sample, parameter: OrderParameter) -> tuple[float, ...]
def cusum_score(sample: Stage2Sample, drift: float = 0.5) -> float     # change-point control
def compare_phase(train, heldout) -> tuple[tuple[PhaseObservation, ...], DetectorComparison]
    # controls: CUSUM on dphi and Φ-oracle
```

### 4.13 D9.9 — MSDL/Predictive Compression suite `[physics]`

```python
# pocketsec/stage9/compression/msdl.py
MSDL_SELECTION_DEFAULT_ENABLED: bool = False; SURPRISE_DEFAULT_ENABLED: bool = False
LAMBDA_RUNTIME = 1.0; LAMBDA_FP = 8.0; LAMBDA_ADV = 100.0     # bits per unit (chosen)
ZDICT_MAX_BYTES = 32768
@dataclass(frozen=True, slots=True)
class MSDLScore:
    genome_digest: str; program_bits: float; residual_bits: float | None
    runtime_term: float; fp_term: float | None; adversarial_term: float | None; total: float | None
def msdl(genome: ComputationalGenomeV1, fitness: FitnessRecord, train: Stage2Dataset) -> MSDLScore
    # residual_bits = sum -log2 p(label | score) under a 1-D logistic fitted on train by 200 steps
    # of deterministic gradient descent (stdlib); fp_term = LAMBDA_FP * FP at the FPR-0.05 threshold
def compare_msdl_selection(runs: Sequence[SearchRun], heldout: EvaluationSuite) -> DetectorComparison
    # MSDL argmin vs Pareto choice (max train worst-case AP within the WU cap)
def compressor_surprise(sample: Stage2Sample, zdict: bytes) -> float          # zlib with zdict (S9X-046)
def build_zdict(train_benign: Sequence[Stage2Sample]) -> bytes               # <= ZDICT_MAX_BYTES
def probabilistic_surprise(sample, bigrams: Mapping[tuple[int, int], int]) -> float   # S9X-047
def nuisance_leakage(genome, dataset) -> float | None   # AP of the score for "length > median" (S9X-050)
def compare_surprise(train, heldout) -> DetectorComparison   # controls: features[83] max, Φ-oracle
```

### 4.14 D9.3 — LAPLACE state/law discovery engine `[laws]`

```python
# pocketsec/stage9/laplace/state_discovery.py
@dataclass(frozen=True, slots=True)
class StateAblation:
    register: int; ap_full: float | None; ap_without: float | None   # register frozen at init
    decisions_flipped: int; sessions: int; unique_utility: float | None
@dataclass(frozen=True, slots=True)
class PrecisionPoint: bits: int; ap: float | None; state_bytes: int; genome: ComputationalGenomeV1
@dataclass(frozen=True, slots=True)
class DiscoveredState:
    genome_digest: str; minimal_genome: ComputationalGenomeV1
    registers_kept: tuple[int, ...]; removed: tuple[int, ...]
    state_bytes: int; heldout_worst_case_ap: float | None
    redundant_pairs: tuple[tuple[int, int], ...]     # identical value sequences (S9X-006)
    reason: str
def state_sufficiency(genome, suite: EvaluationSuite) -> tuple[StateAblation, ...]       # S9X-005
def precision_sweep(genome, dataset, bits: Sequence[int] = (1, 2, 4, 8, 16, 32, 64)
                    ) -> tuple[PrecisionPoint, ...]                                     # S9X-002..004
def state_dimension_sweep(records: Sequence[FitnessRecord], genomes: Sequence[ComputationalGenomeV1]
                          ) -> tuple[tuple[int, float | None], ...]   # best worst-case AP per register count
def discover_minimal_state(genome, train: EvaluationSuite, heldout: EvaluationSuite) -> DiscoveredState
    # greedily remove registers whose removal flips no train decision; verify on held-out
```

```python
# pocketsec/stage9/laplace/law_discovery.py
LEARNING_LAW_SEARCH_DEFAULT_ENABLED: bool = False
class AdaptationLaw(StrEnum): NO_LEARNING, THRESHOLD_QUANTILE, EWMA_THRESHOLD, PROTOTYPE_INSERT
class LawKind(StrEnum): STATE, TRANSITION, ADAPTATION
@dataclass(frozen=True, slots=True)
class LawOutcome: law: str; benign_fp_rate: float | None; recall: float | None; updates_applied: int
@dataclass(frozen=True, slots=True)
class DiscoveredLaw:
    name: str; kind: LawKind; statement: str; experiment_id: str | None
    confidence: float; half_life_events: int; failure_domain: str
def evaluate_adaptation(law: AdaptationLaw, scores: Sequence[float | None],
                        labels: Sequence[int]) -> LawOutcome   # stream in scenario order, bounded window 256
def compare_learning_laws(genome, *, count: int = 120, seed: int = 11) -> DetectorComparison
    # on build_drift_corpus(count, seed) compiled through labs.splits.compile_scenarios;
    # control NO_LEARNING; JUSTIFIED iff FP lower by >= 0.02 at recall >= control's
@dataclass(frozen=True, slots=True)
class HostObjective: fn_weight: float; fp_weight: float; latency_weight: float; ram_weight: float
def apply_host_objective(objective: HostObjective, constraints: MSSCConstraints) -> MSSCConstraints
    # returns constraints UNCHANGED; raises ContractError if asked to relax one (S9X-068)
```

### 4.15 D9.10 — CHRONOS memory/forgetting-law engine `[laws]`

```python
# pocketsec/stage9/chronos/forgetting_law.py
LEARNED_FORGETTING_DEFAULT_ENABLED: bool = False
class MemoryFamily(StrEnum): EXACT_RING, EXPONENTIAL_DECAY, ACCUMULATE, SKETCH, PROTOTYPE, MULTISCALE
@dataclass(frozen=True, slots=True)
class ForgettingLaw:
    family: str; parameters: tuple[tuple[str, float], ...]; bytes_per_lineage: int
    heldout_worst_case_ap: float | None; utility_per_byte: float | None   # (AP - base_rate)/bytes
@dataclass(frozen=True, slots=True)
class DeletionReport:
    deletions: int; decisions_changed: int; negligible: bool        # changed <= 1% of deletions
    catastrophic: int     # malicious sessions pushed below the threshold (S9X-059)
def memory_family_genome(family: MemoryFamily, base: ComputationalGenomeV1) -> ComputationalGenomeV1
    # rebuilds the base genome's first register with the family's memory law; SKETCH uses a
    # per-session CountMinSketch over RELATION (stage1.novelty.sketches) as a side score
def evaluate_families(base, train: EvaluationSuite, heldout: EvaluationSuite) -> tuple[ForgettingLaw, ...]
def counterfactual_deletion(genome, dataset, *, seed: int, per_session: int = 1) -> DeletionReport
    # World A vs World B = M \ {m}: SessionInterventions.forget at a random (event, actor_slot)
def compare_forgetting(laws: Sequence[ForgettingLaw]) -> DetectorComparison
    # control EXACT_RING; JUSTIFIED iff >= 20% better utility/byte at worst-case AP within 0.01
```

### 4.16 D9.4 (gate half) + D9.16 — Primitive promotion, Convergence/Law Observatory `[laws]`

```python
# pocketsec/stage9/foundry/promotion.py
PRIMITIVE_FOUNDRY_DEFAULT_ENABLED: bool = False
PROMOTION_MIN_RUNS = 2; UNIQUE_CONTRIBUTION_MIN = 0.01; MAX_CANDIDATES = 64
class PromotionVerdict(StrEnum):
    PROMOTED, REFUSED_CONVERGENCE, REFUSED_ABLATION, REFUSED_ARGUS, REFUSED_NO_RESOURCE_BENEFIT,
    REFUSED_REPRODUCES_DSL, REFUSED_CROSS_EPOCH
@dataclass(frozen=True, slots=True)
class PrimitiveCandidate:
    canonical: str; body: MacroBody; runs_containing: int; runs_reachable: int
    unique_contribution: float | None; argus_survived: bool | None
    description_bits_saved: float; reproduces_seed: bool
@dataclass(frozen=True, slots=True)
class PromotionDecision: candidate: PrimitiveCandidate; verdict: PromotionVerdict; reasons: tuple[str, ...]
def canonical_subgraphs(genome: ComputationalGenomeV1, *, max_nodes: int = 3) -> frozenset[str]
    # connected APPLY subgraphs of 2..3 nodes; operands abstracted to typed holes; commutative args sorted
def reproduces_seed(body: MacroBody, *, trials: int = 256, seed: int = 0) -> bool
    # semantically equal to one Π0 primitive or to a projection on 256 random typed inputs
def promotion_gate(runs: Sequence[SearchRun], heldout: EvaluationSuite) -> tuple[PromotionDecision, ...]
    # order of refusal: convergence (< PROMOTION_MIN_RUNS of len(runs)), reproduces DSL, ablation
    # (replace the subgraph by its best single-primitive substitute in each containing winner:
    # held-out worst-case delta < UNIQUE_CONTRIBUTION_MIN), ARGUS (the winners containing it lose
    # > 0.05 under any attack), no DL saving, cross-epoch (drift corpus: None -> refused)
```

```python
# pocketsec/stage9/observatory/convergence.py
@dataclass(frozen=True, slots=True)
class Convergence: construct: str; runs_containing: int; runs_reachable: int; value: float | None
def convergence(runs: Sequence[SearchRun], construct: str) -> Convergence    # architecture §46
class LawStatus(StrEnum): CANDIDATE_LAW, REFUSED, UNMEASURABLE
@dataclass(frozen=True, slots=True)
class LawCandidate:              # architecture §47: all eight criteria, None = unmeasured
    construct: str; independent_rediscovery: bool | None; cross_host: bool | None
    cross_epoch: bool | None; unique_ablation: bool | None; argus_robust: bool | None
    resource_advantage: bool | None; beats_simple_baseline: bool | None; failure_domain: str
    status: LawStatus
def law_gate(candidates: Sequence[PromotionDecision], runs: Sequence[SearchRun]) -> tuple[LawCandidate, ...]
    # cross_host is ALWAYS None (single synthetic host) -> no construct can reach CANDIDATE_LAW;
    # status UNMEASURABLE, stated, never PROMOTED by omission
@dataclass(frozen=True, slots=True)
class LawConfidence: construct: str; confidence: float; unsupported_steps: int; half_life_steps: int
def decay_confidence(c: LawConfidence, *, steps: int, reproductions: int, contradictions: int,
                     lam: float = 0.01) -> LawConfidence      # architecture §48, clipped to [0, 1]
class Doctrine(StrEnum): SPARSITY_IS_CHEAPER, SPECIALIZATION_REDUCES_COST, LEARNED_STATE_BEATS_ENGINEERED,
                         MORE_TELEMETRY_HELPS
@dataclass(frozen=True, slots=True)
class DoctrineVerdict: doctrine: str; supported: bool | None; evidence: str
def meta_falsify(runs: Sequence[SearchRun], winners: Sequence[WinnerReport],
                 hand: Mapping[str, FitnessRecord]) -> tuple[DoctrineVerdict, ...]   # S9X-100..102
@dataclass(frozen=True, slots=True)
class Archaeology: regressing_operators: tuple[tuple[str, int], ...]; re_evolved: tuple[tuple[str, int], ...]
def archaeology(runs: Sequence[SearchRun]) -> Archaeology          # architecture §59
```

### 4.17 D9.11 — DAEDALUS system synthesizer `[successor]`

```python
# pocketsec/stage9/daedalus/synthesizer.py
@dataclass(frozen=True, slots=True)
class MetamorphicReport:
    sessions: int; deterministic: bool; actor_slot_permutation_invariant: bool | None
    specialization_preserves_scores: bool
@dataclass(frozen=True, slots=True)
class PcbLowering:
    expressible: bool; reason: str; unsupported: tuple[str, ...]   # IR ops/node kinds with no PCB Op
    verifier_report: dict[str, Any] | None                         # stage3 verify(...) when attempted
@dataclass(frozen=True, slots=True)
class SynthesizedSystem:
    genome_digest: str; specialized: ComputationalGenomeV1; phenotype_digest: str
    bounds: StaticBounds; unit_checks: tuple[tuple[str, bool], ...]
    metamorphic: MetamorphicReport; pcb: PcbLowering
def specialize(genome: ComputationalGenomeV1) -> ComputationalGenomeV1     # constant folding + dead-node
                                                                           # elimination; semantics-preserving
def lower_to_pcb(genome: ComputationalGenomeV1) -> PcbLowering
    # any REG node, MAX, MIN, DIV, arithmetic, POPCOUNT -> NOT expressible (M0.10), each reason named;
    # a register-free genome over STATE_DELTA/EQ_I/AND/OR/NOT only is lowered to an
    # OperatorProgram(form=BYTECODE) and passed to stage3.bytecode.verifier.verify
def synthesize(genome: ComputationalGenomeV1, sample_sessions: Stage2Dataset) -> SynthesizedSystem
    # architecture §31: type/resource validation -> IR -> specialization -> compile (Phenotype)
    # -> unit + metamorphic tests; ARGUS and hardware stay separate stages
```

### 4.18 D9.17 — Proof-Carrying Successor Package, the one exit, the boundary `[successor]`

```python
# pocketsec/stage9/successor/proof_carrying.py
PROOF_CARRYING_SUCCESSOR_V1_ID = "pocketsec.proof_carrying_successor.v1"
PROOF_CARRYING_SUCCESSOR_V1_VERSION = register_schema(PROOF_CARRYING_SUCCESSOR_V1_ID, "1.0.0")
MAX_COUNTEREXAMPLES = 64; MAX_REGISTRY = 64
@dataclass(frozen=True, slots=True)
class ComputationContract:            # architecture §53, every field bound
    max_rss: int                      # = session_state_bytes_max (phenotype-attributable bytes)
    max_cpu_window: int               # = session_wu_max (work units, not seconds)
    max_event_latency_us: float | None    # None = UNMEASURED (never a guess)
    max_queue: int                    # = MAX_SESSION_EVENTS
    required_sensors: tuple[str, ...] # InputSource names read
    failure_behavior: str             # "ABSTAIN_UNKNOWN"
    evidence_guarantee: str           # "WINNING_LINEAGE_LOCATORS"
    offline_guarantee: bool           # True: no file/network/process primitive exists
    forbidden_authority_edges: tuple[str, ...]   # sorted(FORBIDDEN_AUTHORITY_FIELDS)
    def check(self, genome: ComputationalGenomeV1) -> tuple[str, ...]   # violations, static
@dataclass(frozen=True, slots=True)
class RollbackArtifact: parent_genome: Mapping[str, Any]; parent_digest: str; parent_scores_digest: str
@dataclass(frozen=True, slots=True)
class ProofCarryingSuccessorV1:       # architecture §54, every field bound
    computational_genome: Mapping[str, Any]; genome_digest: str
    parent_lineage: tuple[str, ...]; mutation_set: tuple[str, ...]
    executable_artifacts: tuple[tuple[str, str], ...]      # ("phenotype", digest)
    contracts: ComputationContract
    measured_resources: Mapping[str, Any] | None           # HardwareMeasurement.to_dict()
    security_metrics: Mapping[str, float | None]           # heldout_worst_case_ap, heldout_clean_ap,
                                                           # train_worst_case_ap, gap, base_rate
    counterexample_suite: tuple[str, ...]                  # sample_ids flipped by the worst variant
    invariance_suite: tuple[Mapping[str, Any], ...]        # SymmetryTest dicts
    uncertainty_profile: Mapping[str, Any]                 # {"min_events_for_score", "calibration": None}
    failure_domains: tuple[str, ...]
    rollback_artifact: RollbackArtifact
    signatures: tuple[tuple[str, str], ...]                # ("sha256-content", digest): INTEGRITY, not
                                                           # authenticity (ADR-0088)
    synthetic_data: bool = True
    experiment_id: str | None = None
    schema_version: str = PROOF_CARRYING_SUCCESSOR_V1_VERSION
    # __post_init__: JSON-able payload; forbidden_authority_keys(payload) == (); genome_digest ==
    # recomputed; contracts.check(genome) == (); rollback parent_digest matches parent_genome;
    # signature digest == content digest
    def to_dict(self) -> dict[str, Any]
    @classmethod from_dict(cls, payload) -> ProofCarryingSuccessorV1
def build_successor(synth: SynthesizedSystem, *, train: FitnessRecord, heldout: FitnessRecord,
                    parent: ComputationalGenomeV1, parent_scores_digest: str,
                    counterexamples: Sequence[str], invariance: Sequence[SymmetryTest],
                    measured: HardwareMeasurement | None, experiment_id: str | None
                    ) -> ProofCarryingSuccessorV1
@dataclass(frozen=True, slots=True)
class InstallReceipt: slot: int; installed_digest: str; previous_digest: str | None
class CandidateRegistry:              # Stage 9's OWN lab registry; holds no production state
    def install(self, successor: ProofCarryingSuccessorV1) -> InstallReceipt   # bounded MAX_REGISTRY
    def active(self) -> ComputationalGenomeV1 | None
    def rollback(self, receipt: InstallReceipt) -> ComputationalGenomeV1       # re-installs the parent
def tampered_successor(successor: ProofCarryingSuccessorV1) -> ArgusFinding
    # 4 tamperings (metric edit, rollback parent edit, genome edit, signature edit) -> all refused
```

```python
# pocketsec/stage9/successor/stage6_exit.py   - THE ONLY STAGE 9 FILE THAT TOUCHES STAGE 6 CAPSULES
MAX_EXIT_CAPSULES = 8
@dataclass(frozen=True, slots=True)
class ExitReceipt:
    successor_digest: str; offered: int
    verdicts: tuple[tuple[str, str, tuple[str, ...]], ...]   # (capsule_id, bucket, reasons) VERBATIM
class Stage6Exit:
    def __init__(self, gateway: QuarantineGateway) -> None   # built by the caller (gate/lab), never here
    def hand_over(self, successor: ProofCarryingSuccessorV1, *, evidence: Sequence[ScenarioResult],
                  epoch: Epoch, sequence: int) -> ExitReceipt
        # <= MAX_EXIT_CAPSULES TRANSITION_EPISODE capsules via capsule_from_scenario with
        # SourceProvenance(source_class=DERIVED_INFERENCE, source_id="stage9-ontogenesis",
        # independence_group="stage9-" + digest[7:23], label_origin=NONE,
        # transformation_lineage=("stage9", "ontogenesis"), host_id="lab");
        # each passed to gateway.admit and NOTHING else; verdicts recorded, never reinterpreted
```

```python
# pocketsec/stage9/successor/boundary.py   - AST predicates shared by the test and gate G9.7/G9.10
def stage9_modules() -> tuple[Path, ...]
def direct_stage5_imports() -> tuple[str, ...]                 # rule 1 offenders "path:line"
def transitive_stage5_reach() -> tuple[str, ...]               # rule 2 offenders (module names)
def stage6_allow_list_offenders() -> tuple[str, ...]           # §2.3 table, module+name+file
def admit_call_sites() -> tuple[str, ...]                      # rule 3: must be exactly stage6_exit.py
def stage6_writer_names() -> tuple[str, ...]                   # rule 3 writer-name offenders
def authority_field_offenders() -> tuple[str, ...]             # T5 over stage9 class/field names
def dynamic_execution_offenders() -> tuple[str, ...]           # §2.2 banned calls, 2 exemptions
def numpy_or_research_offenders() -> tuple[str, ...]           # any numpy import; stage9/research exists
def earlier_stage_importers() -> tuple[str, ...]               # T7: stage0..6 importing stage7/8/9
def outside_importers_of_stage9() -> tuple[str, ...]           # T3: nothing outside stage9 imports it
```

### 4.19 D9.15 + D9.12 (speciation) — Homeostatic Runtime, speciation, morphogenesis `[runtime]`

```python
# pocketsec/stage9/runtime/homeostatic.py
HYSTERESIS_DEFAULT_ENABLED: bool = False
HYSTERESIS_STEPS = 5; HYSTERESIS_MARGIN = 0.10; MAX_DECISION_HISTORY = 256
class Regime(StrEnum): ADAPTIVE, REDUCED, REFLEX, SURVIVAL     # no RESEARCH member, by construction
REGIME_BUDGET_BYTES: Mapping[Regime, int]   # 600, 250, 100, 40 MiB (architecture §55)
REGIME_WU_CAP: Mapping[Regime, int]         # 64, 16, 8, 4 (chosen)
COVERAGE_DIMENSIONS = ("process", "auth", "persistence", "network", "file", "temporal", "semantic")
@dataclass(frozen=True, slots=True)
class CoverageVector:
    process: float; auth: float; persistence: float; network: float; file: float
    temporal: float; semantic: float
    basis: str = "STATIC_INPUT_READ"        # which inputs the phenotype reads, NOT measured recall
def coverage_of(genome: ComputationalGenomeV1) -> CoverageVector
    # DIMENSIONS -> dims: privilege, execution -> process; trust, credential, isolation -> auth;
    # persistence -> persistence; reachability -> network; modification, discovery -> file.
    # FEATURE[73]/DELTA_PHI read all 9 state dimensions. TIME_BUCKET/temporal group -> temporal.
    # actor/object semantics, OBJECT_PROPERTY_MASK -> semantic. RelationFamily EXECUTION/LOADING/
    # CONTROL -> process, FILESYSTEM -> file, NETWORK -> network, IDENTITY/AUTHORIZATION -> auth,
    # PACKAGING -> persistence.
@dataclass(frozen=True, slots=True)
class PhenotypeEntry:
    regime: Regime; genome: ComputationalGenomeV1; heldout_worst_case_ap: float | None
    wu_per_event: int; state_bytes: int; coverage: CoverageVector
@dataclass(frozen=True, slots=True)
class PhenotypeCatalog:
    entries: tuple[PhenotypeEntry, ...]     # at most one per Regime
    def for_regime(self, regime: Regime) -> PhenotypeEntry | None
def survival_entry() -> PhenotypeEntry      # phi_oracle_genome(); always available, zero-parameter
def build_catalog(pareto: Sequence[tuple[ComputationalGenomeV1, FitnessRecord]]) -> PhenotypeCatalog
    # per regime: best held-out worst-case AP with wu <= REGIME_WU_CAP; SURVIVAL = survival_entry()
@dataclass(frozen=True, slots=True)
class ResourceObservation: available_bytes: int; cpu_fraction: float; queue_depth: int
@dataclass(frozen=True, slots=True)
class RegimeDecision:
    step: int; regime: Regime; phenotype_digest: str; coverage: CoverageVector
    lost: tuple[str, ...]                   # coverage dims > 0 in ADAPTIVE, 0 in this regime
    uncertainty_penalty: float | None       # heldout AP(ADAPTIVE entry) - AP(this entry); None if unmeasured
    transitioned: bool; substituted: bool   # self-repair fallback happened
class HomeostaticController:
    def __init__(self, catalog: PhenotypeCatalog | None, *, hysteresis: bool = HYSTERESIS_DEFAULT_ENABLED) -> None
    def step(self, observation: ResourceObservation) -> RegimeDecision
        # down immediately; up only after HYSTERESIS_STEPS consecutive steps with margin when
        # hysteresis is on; a missing entry falls to the next lower regime; catalog None -> SURVIVAL
    def report_failure(self, regime: Regime) -> RegimeDecision   # self-repair (architecture §57)
    @property transitions(self) -> int
    def history(self) -> tuple[RegimeDecision, ...]              # bounded MAX_DECISION_HISTORY
def synthetic_resource_trace(*, steps: int = 400, seed: int = 0) -> tuple[ResourceObservation, ...]
    # sinusoid around the 250 MiB boundary + noise: the oscillation test. SIMULATED, labelled so
def degradation_trace() -> tuple[ResourceObservation, ...]
    # steps 700 -> 300 -> 120 -> 45 MiB available and back up, 20 steps each: visits every Regime
def compare_hysteresis(catalog: PhenotypeCatalog) -> DetectorComparison
    # JUSTIFIED iff >= 50% fewer transitions with <= 10% more time in a lower regime
```

```python
# pocketsec/stage9/genesis/speciation.py
MORPHOGENESIS_DEFAULT_ENABLED: bool = False
@dataclass(frozen=True, slots=True)
class NicheSpec:
    name: str; ram_bytes_max: int; wu_per_event_max: int
    allowed_inputs: frozenset[InputSource]; allowed_feature_groups: frozenset[str] | None
    measurable: bool; unmeasurable_reason: str
NICHES: tuple[NicheSpec, ...]
    # measurable: very_low_memory (bytes <= 4096), reflex (wu <= 4), sensor_limited (no novelty/
    # temporal/uncertainty groups; inputs DELTA_PHI, STATE_DELTA_MASK, RELATION, RELATION_FAMILY), full
    # unmeasurable (measurable=False): desktop, web_server, database, container_host, developer
    # - reason "single synthetic corpus with no host roles"
@dataclass(frozen=True, slots=True)
class Speciation:
    niche: str; species_digest: str | None; universal_digest: str
    species_heldout_worst_ap: float | None; universal_admissible: bool
    universal_heldout_worst_ap: float | None; verdict: str   # SPECIALIZATION_HELPS | UNIVERSAL_SUFFICES |
                                                             # NO_ADMISSIBLE_SPECIES | UNMEASURED
def admissible(genome: ComputationalGenomeV1, niche: NicheSpec) -> bool
def speciate(elites: Sequence[tuple[ComputationalGenomeV1, FitnessRecord]], heldout: EvaluationSuite
             ) -> tuple[Speciation, ...]
def morphogenesis(niche: NicheSpec, catalog_pool: Sequence[tuple[ComputationalGenomeV1, FitnessRecord]]
                  ) -> ComputationalGenomeV1 | None
    # developmental rule D*: best admissible PRE-VALIDATED genome; never synthesises code (§37)
def compare_morphogenesis(speciations: Sequence[Speciation]) -> DetectorComparison
    # JUSTIFIED iff >= 1 measurable niche gains >= 0.02 over the universal (when admissible) or
    # the universal is inadmissible there, with no technique recall drop; else rejected (§68)
```

### 4.20 D9.18, D9.19, D9.20 — hardware-in-loop, the experiment programme, reproducibility `[runtime]`

```python
# pocketsec/stage9/harness/hardware_in_loop.py
REFERENCE_TARGET_RAM_BYTES = 2 * 1024**3; REFERENCE_TOLERANCE = 1.10; HIL_REPETITIONS = 5
@dataclass(frozen=True, slots=True)
class HardwareMeasurement:
    genome_digest: str; host_mem_total_bytes: int | None; is_reference_target: bool | None
    events: int; wu_per_event: int
    peak_sampled_rss_bytes: int | None; incremental_rss_bytes: int | None   # max(0, peak - start)
    cpu_seconds_per_event: float | None; wall_us_per_event: float | None     # best of HIL_REPETITIONS
    phi_oracle_wall_us_per_event: float | None     # direct loop, SAME run
    ratio_to_phi_oracle: float | None
    cache_misses: None = None; wakeups: None = None; disk_writes: None = None   # UNMEASURED: no perf access
    event_loss: int = 0                             # replay, basis "REPLAY_NO_LOSS_POSSIBLE"
    loadavg_before: tuple[float, float, float] = (-1.0, -1.0, -1.0)
    loadavg_after: tuple[float, float, float] = (-1.0, -1.0, -1.0)
    measured_by: str = "pocketsec.stage9.harness.hardware_in_loop:measure_phenotype"
    def to_dict(self) -> dict[str, Any]
def host_mem_total_bytes() -> int | None                       # /proc/meminfo
def host_is_reference_target() -> bool | None                  # MemTotal <= 2 GiB * 1.10
def measure_phenotype(genome: ComputationalGenomeV1, dataset: Stage2Dataset) -> HardwareMeasurement
    # ResourceSampler around run_dataset; time.perf_counter + process_time
@dataclass(frozen=True, slots=True)
class ProxyCorrelation: spearman_wu_vs_wall: float | None; n: int
def proxy_vs_real(measurements: Sequence[HardwareMeasurement]) -> ProxyCorrelation    # S9X-111
def tcn_pareto_point() -> tuple[ObjectiveVector | None, str]
    # AP from stage2 load_frontier() (count 60 ONLY; refused evidence -> None + reason);
    # WU = 3*96*24 + 3*24 MACs/event from TCN architecture constants (ANALYTIC, labelled);
    # bytes = frontier model bytes if present else None
```

```python
# pocketsec/stage9/labs/one_twenty_experiments.py
class ExperimentStatus(StrEnum):
    RUN_BY_GATE, RUN_BY_CLI, NOT_BUILT, BLOCKED_REAL_TELEMETRY, BLOCKED_NO_2GB_TARGET,
    BLOCKED_STAGE8, BLOCKED_NO_SECOND_HOST
@dataclass(frozen=True, slots=True)
class S9Experiment: experiment_id: str; title: str; status: ExperimentStatus; runner: str; reason: str
S9_EXPERIMENTS: tuple[S9Experiment, ...]
    # EXACTLY 124 rows S9X-001..S9X-124 with the architecture §67 titles verbatim (the section is
    # headed "120-experiment" but lists 124 ids - recorded, not renumbered). runner = "module:function"
    # for RUN_* rows, "" otherwise with a non-empty reason
def resolve_runners() -> tuple[str, ...]      # unresolvable runners (importlib); () is the only pass
def status_counts() -> Mapping[str, int]
```

```python
# pocketsec/stage9/harness/reproducibility.py
@dataclass(frozen=True, slots=True)
class ReproducibilityManifest:
    environment: Mapping[str, Any]            # EnvironmentFingerprint.capture(seeds=...).to_dict()
    seeds: Mapping[str, int]; corpus_versions: Mapping[str, str]   # AMBIGUOUS, CORPUS, DRIFT versions
    encoder_version: str; schema_versions: Mapping[str, str]       # from SCHEMA_REGISTRY: genome,
                                                                   # successor, compile_candidate, capsule
    stage_gate_commands: tuple[str, ...]      # from pyproject [project.scripts], stage0..stage9
    split_digests: Mapping[str, str]          # SplitKey repr -> CompiledVariant.content_digest
    genome_digests: tuple[str, ...]; experiment_ids: tuple[str, ...]
    content_digest: str
def build_manifest(*, seeds: SeedSet, split_digests, genome_digests, experiment_ids) -> ReproducibilityManifest
def verify_manifest(manifest: ReproducibilityManifest, *, recompile: Sequence[str] = ()) -> tuple[str, ...]
    # recomputes content_digest; for named split keys, recompiles and compares digests
```

### 4.21 Parameters (every value chosen, not measured)

| name | value | where |
|---|---|---|
| `MAX_PROGRAM_NODES` / `MAX_REGISTERS` / `MAX_RING` / `MAX_CONSTANTS` / `MAX_LOOKUP_ENTRIES` | 32 / 8 / 8 / 32 / 32 | `chemistry/typed_ir.py` |
| `MAX_LINEAGES` / `MAX_SESSION_EVENTS` / `SIDE_TABLE_ENTRIES` | 16 / 4096 / 256 | `chemistry/typed_ir.py` |
| `VALUE_BYTES` / `LINEAGE_OVERHEAD_BYTES` / `SIDE_ENTRY_BYTES` | 8 / 64 / 16 | `chemistry/typed_ir.py` (Stage 3's `SLOT_BYTES = 8` precedent) |
| `MAX_MACRO_DEPTH` / `MAX_MACRO_NODES` | 2 / 8 | `chemistry/typed_ir.py` |
| `SEARCH_BUDGET_WU`, `SEARCH_SEEDS`, `INITIAL_POPULATION`, `MAX_POPULATION`, `SUBTRACTIVE_SHARE` | 96,000,000; (101, 202, 303); 32; 64; 0.25 | `ontogenesis/search.py` |
| `MAX_CACHE_ENTRIES` / `MAX_RECORDS` / `MAX_FOSSILS` | 4096 / 8192 / 2048 | fitness / search / gaia |
| MSSC `q_min_margin`, `r_min`, `ram_bytes_max`, `wu_per_event_max` | 0.05, 0.85, 65536, 64 | `spec/mssc.py` |
| verdict margins | +0.02 AP; 10% cost; 20% utility/byte; 50% transitions | the owning `compare_*` |
| MSDL lambdas | 1.0 / 8.0 / 100.0 | `compression/msdl.py` |
| regime budgets / WU caps | 600/250/100/40 MiB (architecture §55); 64/16/8/4 WU | `runtime/homeostatic.py` |
| FPR budget for all decision thresholds | 0.05 | every `decisions_*` computation |

### 4.22 Core ids `[genome]` (`core_ids.py`)

`Stage9Function(core_id, name, deliverable, function_class: FunctionClass, symbol: str,
ablation_flags: tuple[str, ...], controls: tuple[str, ...])`. `FunctionClass` is imported from
`stage2.core_ids`, not redefined. `STAGE9_FUNCTIONS` has 20 rows, ONTO-F01..F20 = D9.1..D9.20.
An OPTIONAL row with no flag is refused at import. `resolve_symbols()` resolves every `symbol` and
`ablation_flags` entry lazily with `importlib`, and `()` is the only passing answer.
`optional_flags()` returns the `(core_id, "module:CONSTANT", control)` triples that G9.9 reads.

| id | class | flags → control |
|---|---|---|
| F01 MSSC, F02 genome, F05 IR, F11 DAEDALUS, F14 ARGUS, F16 observatory, F17 successor, F18 HIL, F19 programme, F20 reproducibility | REQUIRED | — |
| F03 LAPLACE | OPTIONAL | `LEARNING_LAW_SEARCH_DEFAULT_ENABLED` → NO_LEARNING |
| F04 Foundry | OPTIONAL | `PRIMITIVE_FOUNDRY_DEFAULT_ENABLED` → seed alphabet |
| F06 renormalization | OPTIONAL | `RENORMALIZATION_DEFAULT_ENABLED` → raw representation + random drop |
| F07 symmetry/conservation | OPTIONAL | `SYMMETRY_BREAKING_DEFAULT_ENABLED` → rarity, Φ-oracle; `CONSERVATION_DEFAULT_ENABLED` → Φ-oracle, H2 |
| F08 geometry/phase | OPTIONAL | `CAUSAL_GEOMETRY_DEFAULT_ENABLED` → pooled kNN, Φ-oracle; `PHASE_OBSERVATORY_DEFAULT_ENABLED` → CUSUM, Φ-oracle |
| F09 MSDL | OPTIONAL | `MSDL_SELECTION_DEFAULT_ENABLED` → Pareto choice; `SURPRISE_DEFAULT_ENABLED` → novelty peak, Φ-oracle |
| F10 CHRONOS | OPTIONAL | `LEARNED_FORGETTING_DEFAULT_ENABLED` → EXACT_RING |
| F12 GENESIS | OPTIONAL | `EVOLUTIONARY_SEARCH_DEFAULT_ENABLED` → random + exhaustive; `SUBTRACTIVE_BIAS_DEFAULT_ENABLED` → no forced deletion; `MORPHOGENESIS_DEFAULT_ENABLED` → universal phenotype |
| F13 GAIA | OPTIONAL | `QD_ARCHIVE_DEFAULT_ENABLED` → single-cell elitist; `FOSSIL_AVOIDANCE_DEFAULT_ENABLED` → off |
| F15 homeostatic | REQUIRED (+flag) | `HYSTERESIS_DEFAULT_ENABLED` → no hysteresis |

**Every flag ships `False`.** Only the integrator may set a flag `True`, and only after a
measured JUSTIFIED verdict, cited in the findings and its ADR.

---

## 5. Work packages

| key | title | depends on | test file |
|---|---|---|---|
| `ir` | typed IR, seed alphabet, phenotype interpreter | — | `tests/test_stage9_ir.py` |
| `genome` | genome schema, expressibility, MSSC, core ids | ir | `tests/test_stage9_genome.py` |
| `evaluation` | splits, ARGUS, fitness | ir, genome | `tests/test_stage9_argus.py` |
| `search` | GENESIS variation, GAIA, ONTOGENESIS search | ir, genome, evaluation | `tests/test_stage9_search.py` |
| `physics` | renormalization, symmetry, conservation, geometry, phase, MSDL | ir, genome, evaluation | `tests/test_stage9_physics.py` |
| `laws` | LAPLACE, CHRONOS, promotion gate, convergence | ir, genome, evaluation, search | `tests/test_stage9_laws.py` |
| `successor` | DAEDALUS, successor package, Stage 6 exit, boundary | ir, genome, evaluation | `tests/test_stage9_successor.py`, `tests/test_stage9_boundary.py` |
| `runtime` | homeostatic runtime, speciation, HIL, experiment programme, reproducibility | ir, genome, evaluation, search | `tests/test_stage9_runtime.py` |

The integrator owns `pocketsec/stage9/__init__.py`, `gate.py` (+ any `gate_*.py`), `cli.py`,
`tests/test_stage9_gate.py`, `docs/stage-9-findings.md`, `docs/adr/0080…0089-*.md`, one line in
`pyproject.toml` (`pocketsec-stage9 = "pocketsec.stage9.cli:main"`), one step in
`.github/workflows/ci.yml`, and `PROGRESS.md`/`MEMORY.md` updates.

Package rules:

1. A package may **not** edit a file it does not own. A needed change to another package's API is
   reported to the integrator as a seam request.
2. A package whose upstream is not yet built writes against the signatures in §4. Its tests
   construct only its own types, or upstream types through their documented constructors.
3. Every test is named after the invariant it protects.
4. Every result type carries a firing count. A mechanism whose firing count is 0 on the gate run
   is reported INERT.
5. No package calls `ExperimentRegistry.register`.

---

## 6. Acceptance gate, as executable checks

`run_gate() -> GateReport` builds one `Stage9GateContext` and runs ten checks. The ten criteria
are those of `planning/PHASE_09_CLAUDE_CODE.md` §69, one check each, which is the integration plan
§5.1 count for Stage 9. The lead's non-negotiables are sub-clauses of these checks and are listed
inside them.

**Gate context (built once).**

1. Compile train (ambiguous 240, seed 3) and held-out (ambiguous 240, seed 11), each clean plus
   the 6 `SCENARIO_ATTACKS`, with `compile_variants(workers=4)`. Compile the saturated split
   (ambiguous 60, seed 11) clean.
2. Run `corpus_audit` (identities reused = 0, both per-class median peak |ΔΦ| > 0). Run
   `contamination_check` (0 overlap). If either fails, the context refuses to build and every
   check FAILS with the reason.
3. Run `check_expressibility` on the saturated split, and `stage9_saturation` on both splits
   with scores for Φ-oracle, H1, H2 and the order-free control.
4. Run the searches. The main EVOLUTIONARY arm uses `SearchConfig` defaults (every flag at its
   shipped `False`) × 3 seeds, alongside RANDOM × 3 and EXHAUSTIVE × 1. Three ablation arms each
   switch on one flag (`subtractive=True`, `fossil_avoidance=True`, `niches=True`), seed-matched,
   × 3 seeds. `compare_strategies` uses the main arm only, so no forking-paths choice of arm is
   made after the fact.
   `run_shuffled_label_control` runs once. Held-out winner reports are then computed.
5. Run the physics, laws, runtime and successor labs on the evolutionary winners (or, if the
   evolutionary arm is off, the best winner of any arm), and HIL on the Pareto set, the Φ-oracle,
   H1 and H2.

The gate does **not** register anything (§2.5). Estimated wall clock is UNMEASURED at spec time.
The integrator measures and records it with loadavg.

| id | criterion (verbatim §69) | executable check | met now? |
|---|---|---|---|
| **G9.1** | At least one Stage-9-discovered computation must beat the strongest Stage-8 hand-designed baseline on a meaningful Pareto dimension without violating another hard requirement. | **Pre-conditions, all required:** (a) `check_expressibility`: `phi-oracle-squashed` and `phi-oracle-raw` are `exact=True`; (b) the count-240 held-out split is not `degenerate` under `stage9_saturation`; (c) `run_shuffled_label_control().verdict != LEAK_SUSPECTED`; (d) `contamination_check` shows 0 overlap. **Measurement:** for each search winner, `beats(winner.heldout_objective, strongest_hand.heldout_objective, candidate_ok=check_constraints(...).violations == ())`, where `strongest_hand` = argmax held-out worst-case AP over {Φ-oracle genome, H1, H2}. TCN via `tcn_pareto_point()` is placed on the count-60 plot only. **Verdict:** Stage 8 is absent (M0.11), so the check reports `passed=False`, `BLOCKED_ON_STAGE8`, and carries the rebound verdict and the Pareto placement of Φ-oracle/TCN/H1/H2/winners in `detail`. | **No**: Stage 8 absent |
| **G9.2** | Every promoted primitive/law has independent-run reproduction and ablation evidence. | `promotion_gate(evolutionary_runs, heldout)` and `law_gate(...)`. PASS iff ≥ 1 candidate subgraph was examined (else FAIL `VACUOUS`), and every `PROMOTED` decision has `runs_containing ≥ PROMOTION_MIN_RUNS` and a non-None `unique_contribution ≥ UNIQUE_CONTRIBUTION_MIN`, and no `LawCandidate` has status `CANDIDATE_LAW` with any criterion `None`. The detail reports 0 laws promoted with `cross_host=None`. | Yes (on synthetic; laws structurally UNMEASURABLE) |
| **G9.3** | Every abstraction has semantic-conservation and counterfactual tests. | Abstractions are every `CoarseGraining` level, every `precision_sweep` level < 64 bits (`PrecisionPoint.genome`), and `DiscoveredState.minimal_genome`. For each, the gate calls `renormalization.laboratory.semantic_conservation` and `counterfactual_distinction` on the attribution-counterfactual pair dataset compiled this run. PASS iff every abstraction has both, with `pairs > 0`. The detail lists every abstraction that lost a distinction. | Yes |
| **G9.4** | Every phenotype has measured 2 GB target-machine resource data. | `measure_phenotype` for every catalog and Pareto phenotype. PASS iff every measurement has non-None RSS/CPU **and** `is_reference_target is True`. | **No**: this host has 16 GB (M0.13); all figures are measured and reported as non-reference |
| **G9.5** | Every resource-degradation mode exposes lost coverage and uncertainty. | Build `PhenotypeCatalog`. Drive `HomeostaticController` with `degradation_trace()` (labelled SIMULATED). PASS iff every `RegimeDecision` in a non-ADAPTIVE regime carries a `CoverageVector`, a `lost` tuple and a non-None `uncertainty_penalty`, and the controller made ≥ 1 transition into each regime (firing count). | Yes (simulated resources; coverage basis is static input read) |
| **G9.6** | Every successor is rollbackable. | For each winner: `synthesize` → `build_successor`. `CandidateRegistry.install` then `rollback`; the restored genome's held-out scores digest equals `rollback_artifact.parent_scores_digest`. `tampered_successor` refuses 4/4. `Stage6Exit.hand_over` is called on a lab gateway; `offered == capsules built`, and verdicts are recorded verbatim. | Yes (rollback within Stage 9's own lab registry; Stage 6 cannot install a genome, B9-2) |
| **G9.7** | All architecture-search artifacts remain outside direct production authority. | `successor/boundary.py`: `direct_stage5_imports() == ()`, `transitive_stage5_reach() == ()`, `admit_call_sites()` == exactly `successor/stage6_exit.py`, `stage6_writer_names() == ()`, `stage6_allow_list_offenders() == ()`, `authority_field_offenders() == ()`, `dynamic_execution_offenders() == ()`, `numpy_or_research_offenders() == ()`, `outside_importers_of_stage9() == ()`. Plus: no `QuarantineBucket` outcome was acted on (the receipt is the only consumer). | Yes |
| **G9.8** | ARGUS adversarial tests cover the ML/search/system lifecycle. | Run every `SCENARIO_ATTACKS` finding on each winner, H1, H2 and the Φ-oracle, and every `LIFECYCLE_ATTACKS` runner once. PASS iff `coverage(findings)` (non-inert only) == all 8 `ArgusSurface` members **and** every `DEFENCE` finding has `fired == total` (a tampering that was not refused fails the check). The detail reports every INERT attack, and `fittest_die_under_attack` (examined, died) per evolutionary run. | Yes (synthetic attacks authored by this wave, lesson 6) |
| **G9.9** | Novel physics-inspired mechanisms must beat simpler baselines or be removed. | For every `optional_flags()` triple: the owning `compare_*` returned a verdict this run. PASS iff no verdict is `UNMEASURED` and every flag whose verdict is not `JUSTIFIED` reads `False` from the module constant, read from code, never from a document. This includes `EVOLUTIONARY_SEARCH_DEFAULT_ENABLED` from `compare_strategies` (evolutionary search must beat random **and** exhaustive at equal budget, or it is NOT-YET-JUSTIFIED and off). | Yes |
| **G9.10** | The final endpoint remains useful with Stage 7–9 networking/research completely absent. | (a) `earlier_stage_importers() == ()` (T7). (b) A subprocess with a `sys.meta_path` finder that raises on `pocketsec.stage7/8/9` computes Φ-oracle held-out AP via `stage2.gate_measures.compile_split("ambiguous", count=240, seed=11)` and `max(features[73])`; it must equal the in-process figure to 1e-12 and exceed the base rate. (c) `HomeostaticController(None)` returns `SURVIVAL` with the Φ-oracle genome. | Yes |

### 6.1 The criteria that cannot be met here, declared

- **G9.1** needs Stage 8's hand-designed phenotype, which does not exist. The rebound comparison
  (Φ-oracle, H1, H2, TCN evidence) is measured and reported, but the check fails with
  `BLOCKED_ON_STAGE8`. Re-wording the criterion into a pass is forbidden.
- **G9.4** needs a 2 GB reference machine. This host is 16 GB (M0.13). Every figure is measured
  here and labelled non-reference; the check fails.
- **Laws (G9.2)** need cross-host reproduction. The corpus is one synthetic host, so
  `cross_host=None` for every construct and no law can be promoted. G9.2 can pass only on the
  primitive half, and says so.
- **Calibration (Kmin)** is UNMEASURED throughout. No Stage 9 score is calibrated.
- Nothing in this stage is a detection result. Every corpus is synthetic, generated by
  project-authored code, and the headroom split's label is the generator's attribution rule
  (M0.6).

---

## 7. The baselines Stage 9 must beat

| advanced component | the dumbest thing that could work | metric (held-out unless stated) | rule |
|---|---|---|---|
| any discovered computation (thesis) | **Φ-oracle** (`phi_oracle_genome`, 3 WU/event, 1 register); **H1** per-lineage Σ max(ΔΦ, 0); **H2** per-lineage popcount(OR mask) | Pareto (worst-case AP, WU/event, state bytes) | `beats` (§4.1) vs the strongest; reported on the count-240 Pareto plot |
| the saturated comparison | Φ-oracle vs TCN (registered evidence) on count 60 | AP at count 60 | a claim to beat the Φ-oracle there is refused as `PHI_ORACLE_AT_CEILING` |
| evolutionary search (GENESIS + GAIA) | **random search** over the same language at equal `SEARCH_BUDGET_WU`; **exhaustive enumeration** of the 126-genome ≤2-node space | held-out worst-case AP of each run's winner | §4.9 `compare_strategies`: JUSTIFIED only if it beats **both** |
| QD niches (MAP-Elites) | single-cell elitist archive (`niches=False`) | held-out worst-case AP of the winner; `single_architecture_dominance` | ≥ +0.02 median, and not one elite dominating ≥ 90% of occupied cells |
| subtractive bias / fossil avoidance | same search without them | WU/event of winner at AP within 0.01 / WU spent to reach the final best | ≥ 10% on 3/3 seeds |
| primitive foundry | the seed alphabet | promotion refusals; held-out AP with the enlarged alphabet | promoted only via §4.16; a promoted body that `reproduces_seed` is refused |
| renormalization | raw representation; equal-byte random group drop | AP, feature bytes, counterfactual distinctions | §4.10 |
| symmetry-breaking | rarity (max `features[83]`); Φ-oracle | AP | ≥ max + 0.02 |
| conservation / Noether heuristic | Φ-oracle (simple statistic); H2 (graph-motif) | AP | ≥ max + 0.02 |
| causal geometry | pooled-feature kNN; Φ-oracle | AP | ≥ max + 0.02 |
| phase observatory | CUSUM on ΔΦ; Φ-oracle | AP; benign false-transition rate | ≥ max + 0.02 |
| MSDL selection | Pareto choice | held-out worst-case AP of the chosen genome | ≥ +0.02 or equal at ≥ 10% less WU |
| algorithmic / probabilistic surprise | Stage 1 novelty peak; Φ-oracle | AP | ≥ max + 0.02 |
| CHRONOS learned forgetting | exact bounded ring | utility per retained byte at AP within 0.01 | ≥ 20% better |
| learning-law search | no learning | drift-corpus benign FP at recall ≥ control | FP ≥ 0.02 lower |
| speciation / morphogenesis | one universal phenotype | per measurable niche, held-out worst-case AP | §4.19 |
| homeostatic hysteresis | no hysteresis | transitions and time-in-lower-regime on the synthetic trace | ≥ 50% fewer transitions, ≤ 10% more time lower |
| the whole of Stage 9 ("no Stage9", §66) | Φ-oracle alone at 0 research cost | everything above | if no discovered computation beats H1/H2/Φ-oracle, §68's first falsifier fires |

Architecture §66 baselines that are **not built**, with reasons: LightGBM/XGBoost, GRU/LSTM,
tiny transformer and NAS/HW-NAS are third-party or numpy tooling, which is barred in Stage 9
(ADR-0080). The GRU/LSTM/transformer figures at count 60 exist in the registered frontier
evidence (M0.12) and are quoted from it, not re-measured. HDC/VSA as a separate model is not
built: `BIND`/`HASH` provide the HDC operators inside the language. The Stage-8 phenotype is
absent (G9.1). All are recorded as UNMEASURED rows in the findings.

---

## 8. What would falsify this stage's central claim

The central claim is: *minimum sufficient security computation is empirically discoverable by
typed, adversarially tested, cost-aware search, and that search is worth its research
complexity.* Any one of the following refutes it, and the gate must report it plainly:

1. **The hand rules match the frontier.** No search winner `beats` the strongest of
   {Φ-oracle, H1, H2} on held-out count 240 (§68 bullet 1, with H1/H2 standing in for the absent
   Stage 8). Stage 9 is then rejected on this corpus.
2. **Search is no better than trivial search.** Evolutionary search fails to beat random search
   or the 126-genome exhaustive enumeration at equal budget. Evolution is then NOT-YET-JUSTIFIED
   or REJECTED, and the exhaustive result is the answer.
3. **The winner learned the benchmark.** The shuffled-label search finds held-out AP significantly
   above chance *and* above the prior (`LEAK_SUSPECTED`). Or the train-vs-held-out gap of winners
   exceeds 0.10. Or winners die under ARGUS while the Φ-oracle survives.
4. **The language cannot express the incumbent.** `phi-oracle-squashed` is not exact. Nothing
   downstream is then admissible (the Stage 3 lesson).
5. **Every mechanism beyond the search loses to its control** (§7). The physics-inspired layer is
   then removed wholesale and the findings say so.
6. **The saturated split is used to claim a win.** Any count-60 comparison reported as a success
   is a measurement error by definition (§0 consequence 1).

---

## 9. Honest limits (author confound and synthetic data)

- The ground truth (ambiguous corpus), the attacks (ARGUS) and the hand baselines (H1, H2) are all
  authored within this project, and H1/H2 were written by the author of this contract after
  reading the generator. Search success at count 240 partly measures how well the language can
  restate the generator's rule. Properties proven by construction (termination, bounds, the
  import boundary, rollback identity) do not share this confound, and they are what this stage
  can establish most firmly.
- Φ-oracle AP swings 0.40 with corpus size alone (M0.2). Every quality figure is quoted with
  (corpus, count, seed).
- Timing is host-contended. WU and bytes are exact. µs figures are ratios within one run.
- No calibration, no real telemetry, no second host, no 2 GB target, no Stage 8.

---

## 10. ADRs to be written by the integrator (block 0080–0089)

| ADR | title (short) | decided by |
|---|---|---|
| 0080 | Stage 9 layout amendments: no research package, no numpy, `ontogenesis/` holds the search, no H15 (H5/H6/BASE) | this spec §2.1, §2.6 |
| 0081 | Search has no production authority: one exit (`successor/stage6_exit.py` → `QuarantineGateway.admit`), the allow-list, and the declared transitive Stage 5 residual | §2.3, M0.9 |
| 0082 | The genome language: a typed DAG, termination and memory by construction, `DIV` included, macros expanded before validation, expressibility checked first | §4.3–§4.5, M0.4 |
| 0083 | Fitness is worst-case over ARGUS scenario attacks; cost is an objective (Pareto), never a tiebreak or weighted sum | §4.1, §4.6 |
| 0084 | Corpus choice: ambiguous count 240 for search/held-out; count 60 is saturated and used only to show the trap; author confound declared | M0.2, M0.6 |
| 0085 | Evolutionary vs random vs exhaustive: the measured verdict (written after the gate run) | G9.9 |
| 0086 | Physics-inspired mechanisms: measured verdicts vs their controls (written after the gate run) | G9.9 |
| 0087 | Stage 8 absent: G9.1 blocked; the rebound set {Φ-oracle, H1, H2, TCN evidence} | M0.11 |
| 0088 | Successor package: digests are integrity not authenticity; rollback by parent genome; Stage 6 has no genome executor (B9-2) | §4.18 |
| 0089 | Hardware-in-loop: this host is not a 2 GB target; WU primary; `run_benchmark` not used because no SSIR→`SecurityEventSequenceV1` path exists for Stage 9 phenotypes (only `stage0/smoke.py` calls it); `ResourceSampler` directly, as Stages 5–7 did | §4.20, M0.13 |

Each ADR uses `docs/adr/0000-adr-template.md` and keeps an **Options considered** table with a
measured-consequence column.

---

## 11. Blockers and STOP conditions carried into the wave

- **B9-1 (Stage 8 absent):** G9.1 fails by construction. Reported, not worked around.
- **B9-2 (Stage 6 has no genome executor):** `Stage6Exit` hands over evidence capsules and records
  the verdicts, but nothing Stage 9 discovers can be installed by Stage 6 (ADR-0056). The lead
  decides whether Stage 6 gains a candidate kind. Stage 9 does not edit Stage 6.
- **B9-3 (no research package):** `RESEARCH_PREFIX` in `tests/test_repository_structure.py` covers
  Stage 2 only (ADR-0011 never written). If a later wave needs numpy in Stage 9, it must first get
  that ADR and that edit from the lead.
- **B9-4 (2 GB target absent):** G9.4 fails by construction on this host.
- **STOP** (report BLOCKED, do not guess) if: `phi-oracle-squashed` cannot be made exact in the IR;
  a Stage 9 module needs any Stage 5 name; the §2.3 transitive residual grows beyond
  `stage6.capsule.*`; the count-240 held-out split turns out degenerate under
  `stage9_saturation`; or a package would need to edit a file outside its ownership.

---

## 12. Errata recorded by the integration session (2026-09-26)

The contract above is kept as written. Where the built code differs, this list is the correction.
Each item names its reason; none weakens a check.

1. **§4.19 / §4.20 field names.** `ResourceObservation.cpu_fraction` is `cpu_share`, and
   `ReproducibilityManifest.stage_gate_commands` is `stage_gate_entrypoints`. The spec's own §2.2
   forbids `FORBIDDEN_AUTHORITY_FIELDS` fragments in Stage 9 class and field names (`fr-action`,
   `command`). ADR-0080.
2. **§4.4 alphabet size.** The table lists 29 primitives, and "26" in the prose is wrong.
   `SEED_ALPHABET` has 29, and `tests/test_stage9_ir.py` pins that count.
3. **§4.2 `check_expressibility(dataset, *, sessions=None)`.** Stage 2's `lineage_windows` needs
   SSIR transitions, which a `Stage2Dataset` does not carry. Without `sessions` every window-based
   reference is reported unmeasured (`exact=None`), never met.
4. **§4.9 `compare_arm`** is implemented in `gaia/qd_ecology.py` and re-exported from
   `ontogenesis/search.py`, which kept `search.py` under the 800-line limit.
5. **§4.9 verdict rule for a run with no MSSC-satisfying winner.** The rule has no UNMEASURED
   branch. A missing winner has no delta, so it cannot be "positive on every seed" and never
   counts as beating: the verdict is NOT_YET_JUSTIFIED unless a computable median is ≤ −0.02
   (REJECTED). UNMEASURED is reserved for the case where no run of any strategy produced a
   winner. ADR-0085.
6. **§2.3 allow-list.** The harness may also import `stage1.epoch.model.SystemIdentity`, because
   an `Epoch` and `genesis_state` both need the identity they bind. ADR-0081.
7. **§2.3 rule 2 contradicts §2.3's own table (BLOCKED, not fixed).** `genesis_state`,
   `ProvenanceLedger` and `KnowledgeLineageDAG`, granted to the harness for the lab gateway G9.6
   requires, reach `pocketsec.stage5.stage6_interface` through `stage6.memory.procedural`,
   bypassing `stage6.capsule`. The Stage 5 modules reached are the same set the capsule door
   reaches (measured, ADR-0081), but the rule as written fails. The lead decides.
8. **§2.1 `__init__.py`.** It is a lazy `__getattr__` surface (the Stage 6/7 shape): importing
   `pocketsec.stage9` imports nothing. It adds a fourth `import_module` exemption (the root
   `__init__.py` only). ADR-0080.
9. **§2.2 exemptions.** `subprocess` is used by `gate_isolation.py` (a `gate*.py` file, as
   declared).
10. **§6 G9.1 falsifier reading.** A winner whose digest equals a hand baseline (the exhaustive
    arm rediscovers the Φ-oracle) is reported as a rediscovery. Falsifier 1 is evaluated on
    winners that are not themselves hand baselines, and the literal reading is printed beside it.
