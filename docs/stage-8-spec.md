# Stage 8 — PROMETHEUS + ORACLE + FORGE — implementation contract

- **Status:** Accepted as the build contract for the Stage 8 wave. Binding on eight work packages
  and the integrator.
- **Date:** 2026-09-26
- **Source of truth:** `docs/architecture/sources/stage-08-prometheus-oracle-forge.md` (architecture),
  `planning/PHASE_08_CLAUDE_CODE.md` (checklist, gate, STOP conditions),
  `docs/architecture/stage-3-12-integration-plan.md` (layout, seams, import rules). The project
  lead's Stage 8 guidance overrides the architecture where they conflict. This document records
  each conflict where it applies.
- **ADR block:** 0070–0079 (lead's assignment; the integration plan's 0063–0072 block collides with
  Stage 7's 0060–0069 and is superseded). All ten numbers are assigned in §10. None exists on disk at
  spec time (`ls docs/adr | grep '^007'` → empty, this session).
- **The Stage 9 interface is §3.3.** It is defined by package `foundation`, first, and its shape is
  frozen when the Build phase ends. A change after that needs a new schema `$id` and an ADR.

---

## 0. What was measured before this contract was written

Every number below was produced by running code in this session. The probe scripts are in the
session scratchpad, not the repository. `/proc/loadavg` is recorded beside each run. No timing
figure is quoted: none of these probes is a timing measurement.

| # | claim | value | command / module | loadavg |
|---|---|---|---|---|
| M0.1 | Every upstream symbol this contract names exists | **107 OK, 0 missing** | `verify_seam.py`: `importlib` + `inspect.getsourcelines` over the §3.1 table | 8.88 8.50 7.62 |
| M0.2 | What Stage 6's gateway does with a Stage 8-style discovery capsule. Stage 1 `build_corpus(count=40, seed=7, split="eval")`, the 12 malicious sessions → `capsule_from_scenario` with `SourceProvenance(DERIVED_INFERENCE, label_origin=INFERENCE)` and a `LabelAssertion(MALICIOUS, INFERENCE)` → `QuarantineGateway.admit` | no flag, one independence group: **UNCERTAIN 12, TRUSTED_CANDIDATE 0**, `score_provenance` = 0.5 on all 12, reason `awaiting_label_quorum` 12. No flag, three groups (36 capsules): **UNCERTAIN 36, TRUSTED_CANDIDATE 0**, `awaiting_label_quorum` 36. `SIMULATED_RECORD` added: score **0.4** on all, `low_provenance`, **TRUSTED_CANDIDATE 0** in both arms | `probe_s6.py` | 8.58 6.96 6.78 |
| M0.3 | Is the simplest hypothesis class already saturated on the repository's corpora? Train seed 3, eval seed 11; exhaustive single-step Stage 6 motifs selected on train by F1; ≤2-step pairs of the top 40; random motifs at the same count | replay (120/120, base 0.300): **Φ-oracle AP 1.0000**; single-step eval F1 0.7692; ≤2-step adds nothing (best is 1 step); random 0.6667. hard (base 0.367): **Φ-oracle AP 0.8017**; single-step 0.7123; ≤2-step adds nothing; random 0.5783. ambiguous (90/90, base 0.333): **Φ-oracle AP 1.0000**; single-step 0.4182; **≤2-step 1.0000**; random 0.4182 | `probe_sat.py` (`match_motif`, `average_precision`) | 10.89 7.76 7.05 → 11.27 7.95 7.12 |
| M0.4 | Consequence of M0.3 | On replay and ambiguous the Φ-oracle ranks every session perfectly, so **no discovery can find a positive the Φ-oracle misses there**. On hard, 2-step search adds nothing over single-step. **No existing corpus can show a discovery engine beating baseline (1) and baseline (3) at once.** Stage 8 must build its own corpus (§4.19), and that corpus shares an author with the engine (lesson 6, §9) | derived from M0.3 | — |
| M0.5 | Null corpus: labels drawn Bernoulli(0.35) independently of content, 20 label seeds, hard and replay corpora, single-step motifs only | candidate motifs present: 36 (hard), 29 (replay). Uncorrected train p < 0.05: **0.50 / 0.45 per run**. Top-20 preregistered, exact-binomial holdout at 0.05/20: **0.00 survivors per run, 0/20 runs with any survivor**, both corpora | `probe_null.py` | 10.41 8.66 7.63 |
| M0.6 | Can a planted malicious chain sit at the same Φ-oracle score as benign doppelgängers? `max features[73]` over each session's steps | drop-exec-exfil (M) **0.2195** = offsite backup (B) **0.2195** = document exfil (M) 0.2195; `ATTACK_EXFIL` 0.5224; `BENIGN_PRIVILEGED` 0.1111; build-and-run-in-/tmp (B) 0.0857. The first two are identical on the Φ-oracle and separable only by `EXECUTE{TEMP_LOCATION}` preceding `CONNECT{EXTERNAL_ENDPOINT}` in one actor | `probe_phi.py` | 10.88 9.00 7.81 |
| M0.7 | Do the §4.19 families encode as intended? | 5 × (connect, send) to one external address: 5 `CONNECT{EXTERNAL_ENDPOINT}` steps in one actor, only the first raises `reachability`, Φ-oracle **0.2195** (same as a single connect). Split actors (pid 2001 exec, pid 2002 connect): slots **0 and 1**. `fork` → `SPAWN`, no properties, no raised bits. `/var/tmp` and `/dev/shm` both encode `TEMP_LOCATION` | `probe_fam.py` | 7.05 8.67 7.97 |

**What M0.2 means. It is the first finding of this stage, and it is a blocker (B8-1, ADR-0076).**
Stage 6 has no capsule kind that carries a detector (ADR-0056: candidate kinds are exactly those
with an executor, and the chamber builds them itself). A Stage 8 discovery can reach Stage 6 only
as **evidence**: `TRANSITION_EPISODE` capsules of its supporting sessions, labelled by inference.
One Stage 8 source is one independence group, so its self-labels never reach a label quorum. With
the honest `SIMULATED_RECORD` flag they do not even clear `MIN_PROVENANCE_SCORE`. **Realised
endpoint adoption of a Stage 8 discovery is 0 by construction under Stage 6's current parameters.**
Stage 8 does not edit Stage 6. Three consequences:

1. The kill switch the lead requires holds trivially and totally: a discovered rule never travels.
   Stage 6 would have to re-learn it from the evidence through its own chamber.
2. Every detection gain in this stage is measured at **Stage 8's own boundary** (the reproduced
   `DiscoveryPackageV1` values handed to `Stage6Adapter.hand_over`) and labelled
   `counterfactual_at_boundary`. Stage 6's buckets are reported beside it, never substituted for it.
3. Architecture falsifier "all endpoint adoption passes Stage 6" is met as a path property (G8.9).
   Whether any discovery is ever adopted is the lead's decision about Stage 6's inference prior.

**What M0.3–M0.7 mean for the corpus.** The discovery corpus must (a) contain positives the
Φ-oracle ranks no higher than benign sessions (M0.6 shows this is possible), (b) require a
2-step, same-actor or counting mechanism that single-step search cannot express (M0.3 ambiguous,
M0.7), (c) contain a train-only shortcut that is true by construction on TRAIN and false on
held-out (the lead's trap), and (d) have a null arm. M0.5 shows that with a hypothesis space of
~30 the uncorrected error is already small. The null test is therefore run over the **full ≤2-step
space** (≈ 10³ hypotheses), where the discipline has something to prevent.

---

## 1. What Stage 8 must deliver

**Thesis, bound to code.** Stage 8's deliverable is **a discovery loop that cannot reach
production except as a candidate handed to Stage 6, and a falsification discipline that kills its
own hypotheses.** Stated so a gate can check it:

> *PROMETHEUS sees TRAIN episodes only. Every hypothesis is an immutable, content-addressed typed
> genome with a pre-registered refutation rule, recorded in an append-only ledger before any
> held-out data is evaluated. Each held-out split is evaluated once, as one Bonferroni family. A
> hypothesis true on TRAIN by construction and false on held-out is killed. On a null corpus the
> loop reproduces nothing. FORGE compiles a survivor only into representations that can express it,
> and ships one only if it preserves measured quality within tolerance and costs less. The only
> exit is `Stage6Adapter.hand_over` → `QuarantineGateway.admit`. No Stage 8 module can name a Stage 6
> writer or anything in Stage 5. Every store is bounded and every truncation is counted.*

Cleverness in hypothesis generation is optional. The discipline is not.

### 1.1 Checklist → deliverable → module → package

Every item of `planning/PHASE_08_CLAUDE_CODE.md` appears here. Checklist item NN is D8.NN.

| # | deliverable | module(s) under `pocketsec/stage8/` | core id(s) | package |
|---|---|---|---|---|
| 01 | D8.1 Discovery Constitution | `constitution/discovery.py` | PROM-F01 | integrity |
| 02 | D8.2 Residual Observatory + Priority Field | `residual/observatory.py`, `residual/priority_field.py` | PROM-F02, PROM-F03 | prometheus |
| 03 | D8.3 Hypothesis Genome + Mechanism Grammar | `genome/hypothesis.py`, `genome/grammar.py`, `episode.py` | PROM-F04, PROM-F07 | foundation |
| 04 | D8.4 PROMETHEUS multi-generator engine | `prometheus/generators.py`, `prometheus/engine.py` | PROM-F05 | prometheus |
| 05 | D8.5 Hypothesis Ecology + Lineage DAG | `ecology/population.py`, `ecology/lineage.py` | PROM-F06 | oracle |
| 06 | D8.6 ORACLE information-gain experiment planner | `oracle/planner.py`, `oracle/information_gain.py` | PROM-F08, PROM-F09 | oracle |
| 07 | D8.7 Counterfactual/Metamorphic Laboratory | `laboratory/counterfactual.py`, `laboratory/metamorphic.py` | PROM-F10, PROM-F11 | labs |
| 08 | D8.8 Benign Doppelgänger Engine | `doppelganger/engine.py` | PROM-F12 | falsification |
| 09 | D8.9 Adversarial Challenger | `challenger/adversarial.py` | PROM-F13 | falsification |
| 10 | D8.10 Causal Identifiability Gate | `identifiability/gate.py` | PROM-F14 | falsification |
| 11 | D8.11 Theory Ledger + negative-result memory | `ledger/theory.py`, `ledger/negative_results.py` | PROM-F15 | integrity |
| 12 | D8.12 Reproducibility Gate | `reproducibility/gate.py` | PROM-F16 | falsification |
| 13 | D8.13 Novelty/Prior-Art Audit pipeline | `novelty/prior_art_audit.py` | PROM-F24 | falsification |
| 14 | D8.14 FORGE discovery compiler | `forge/representations.py`, `forge/compiler.py` | PROM-F17 | forge |
| 15 | D8.15 Representation Tournament | `forge/tournament.py` | PROM-F18, PROM-F19 | forge |
| 16 | D8.16 Discovery Package format | `forge/package.py` (types only) | PROM-F20 | foundation |
| 17 | D8.17 Stage6/7 integration adapters | `adapters/stage6.py` (forge), `adapters/stage7.py` (prometheus) | PROM-F20 | forge, prometheus |
| 18 | D8.18 Research Integrity + Sandbox package | `sandbox/integrity.py`, `sandbox/boundary.py`, `governor/budget.py` | PROM-F21, PROM-F22, PROM-F23 | integrity |
| 19 | D8.19 80-experiment benchmark suite | `labs/eighty_experiments.py` (catalogue), `labs/discovery_corpus.py` (corpus), `labs/baselines.py` (runners) | PROM-F25 | experiments, labs |
| 20 | D8.20 Full Stage1–8 endurance/falsification report | `labs/discovery_run.py` (`run_discovery`, `run_endurance`); the report is `docs/stage-8-findings.md` (integrator) | PROM-F25 | experiments, integrator |

### 1.2 The required test focus of the phase file, bound

| phase-file focus | where it is tested |
|---|---|
| typed hypothesis/falsifier validation | `tests/test_stage8_foundation.py` (genome refuses empty/missing falsifiers, id tamper), `tests/test_stage8_integrity.py` (ledger order, edit-after-test refused), G8.1 |
| safe sandbox boundary | `tests/test_stage8_integrity.py` (every `ExperimentClass` decision, clearance expiry, no emulator), `tests/test_stage8_boundary.py` (no execution/network primitive), G8.3 |
| replay/counterfactual/metamorphic tests | `tests/test_stage8_labs.py` (every transform keeps features consistent; semantics table), `tests/test_stage8_falsification.py` (reproducibility invariance), G8.5 |
| benign doppelgänger and adversarial challenge | `tests/test_stage8_falsification.py`, G8.5, G8.7 (robustness column) |
| reproducibility | `tests/test_stage8_falsification.py`, `tests/test_stage8_experiments.py` (trap killed, null run), G8.1, G8.5 |
| FORGE tournament | `tests/test_stage8_forge.py` (expressibility refusals, reselection from measurements), G8.7, G8.11 |
| Stage-6 admission / no-authority-bypass | `tests/test_stage8_boundary.py` (AST + the discovered rule refused everywhere else), `tests/test_stage8_forge.py` (adapter counters), G8.9, G8.10 |

---

## 2. Repository rules this wave operates under

### 2.1 Layout: integration plan §1.2, amended (ADR-0070)

```
pocketsec/stage8/
    __init__.py                     # integrator. EMPTY
    core_ids.py                     # PROM-F01 … PROM-F25, one per architecture layer 8.0–8.24
    episode.py                      # Episode, Split, EpisodeContext, FitCounts — the unit of observation
    gate.py, gate_*.py              # integrator. 12 checks
    cli.py                          # integrator. pocketsec-stage8 {gate,discover,null,baselines,oracle,tournament,catalogue,endurance,resources,experiments}
    constitution/discovery.py       # D8.1
    genome/grammar.py               # D8.3 Mechanism Grammar, DSL parser, renderer
    genome/hypothesis.py            # D8.3 HypothesisGenome, Falsifier, Prediction, ExperimentClass
    residual/observatory.py         # D8.2 residual field and decomposition
    residual/priority_field.py      # D8.2 priority
    prometheus/generators.py        # D8.4 the seven generators + two baseline generators
    prometheus/engine.py            # D8.4 dedup, dead-end skip, diversity selection, births
    ecology/population.py           # D8.5 bounded population, mutation, merge/split, MDL, TheoryScore
    ecology/lineage.py              # D8.5 hypothesis lineage DAG
    oracle/information_gain.py      # D8.6 posterior, exact EIG over predicted-outcome classes
    oracle/planner.py               # D8.6 design, sandbox authorisation, selection policies, stopping rules
    laboratory/counterfactual.py    # D8.7 encoded-episode transforms
    laboratory/metamorphic.py       # D8.7 metamorphic relations and runner
    doppelganger/engine.py          # D8.8
    challenger/adversarial.py       # D8.9
    identifiability/gate.py         # D8.10
    ledger/theory.py                # D8.11 append-only, digest-chained theory ledger, preregistration
    ledger/negative_results.py      # D8.11 negative-result memory
    reproducibility/gate.py         # D8.12
    novelty/prior_art_audit.py      # D8.13
    forge/package.py                # D8.16 DiscoveryPackageV1, TournamentResult — THE STAGE 9 INTERFACE
    forge/representations.py        # D8.14 detector executors
    forge/compiler.py               # D8.14 expressibility check, compile, load-from-data
    forge/tournament.py             # D8.15 tournament, Pareto selection, DCR, endpoint footprint
    adapters/stage6.py              # D8.17 THE ONE module that hands anything to Stage 6
    adapters/stage7.py              # D8.17 inbound seeds from Stage 7 antibodies
    sandbox/boundary.py             # D8.18 experiment-class authorisation, clearance, audit
    sandbox/integrity.py            # D8.18 content addressing, leakage, HMAC records, HoldoutVault
    governor/budget.py              # layer 8.21 ResearchBudget + ResearchGovernor
    labs/discovery_corpus.py        # planted / null / dropout arms, splits, lab oracle, doppelgänger families
    labs/discovery_run.py           # the end-to-end loop, endurance
    labs/baselines.py               # Φ-oracle, random, exhaustive single-step, direct model, null FDR, ablation
    labs/eighty_experiments.py      # D8.19 S8X-001 … S8X-128 catalogue with honest status per row
```

Amendments to integration plan §1.2, all recorded in ADR-0070:

- **Added:** `episode.py` (the plan names no observation unit; every package needs one),
  `prometheus/engine.py`, `forge/representations.py`, `governor/budget.py` (layer 8.21 has no
  module in the plan), `labs/discovery_corpus.py`, `labs/discovery_run.py`, `labs/baselines.py`.
- **`research/` is NOT built, and Stage 8 imports no numpy.** The plan's pre-assigned
  research-prefix amendment was never written: `tests/test_repository_structure.py:79` still reads
  `RESEARCH_PREFIX = "pocketsec/stage2/research/"` (read this session). A numpy import under
  `pocketsec/stage8/research/` would fail `test_runtime_has_no_third_party_imports`, and this wave
  may not edit that file. Every Stage 8 mechanism is stdlib-sized: Stage 1's `LogisticProbe` is
  already stdlib. The tiny MLP/1D-CNN/GRU/transformer representations of §26 are **NOT BUILT**
  (§9). This matches every stage since Stage 3 (ADR-0060 is the latest precedent).
- **Empty directories on disk.** `pocketsec/stage8/{experiments,forge,hypotheses,oracle,prometheus}/`
  exist and hold no files (`ls -la`, this session). `forge/`, `oracle/` and `prometheus/` are filled
  by this layout. **`experiments/` and `hypotheses/` are deleted by package `foundation`**
  (ADR-0121 precedent), and `tests/test_stage8_boundary.py` forbids their return.
- **AION (architecture §59–§113) is not built.** It is architecture and representation invention,
  which is Stage 9's remit (§58 of the architecture hands it over). The pieces of it that a
  deliverable already needs are built under that deliverable: the §85 conservation tests in FORGE,
  the §90 open-world `UNEXPLAINED_ESCALATION` residual, and the §96 package with hashes and lineage.
  The catalogue lists S8X-081 … S8X-128 with status per row.

Every subsystem `__init__.py` stays **empty**. Consumers import the leaf module. An empty subsystem
package is a defect (ADR-0121).

### 2.2 Hard mechanical constraints

- Python ≥ 3.11 and `from __future__ import annotations`. Strict typing on every public API.
  `@dataclass(frozen=True, slots=True)` for every value type. Explicit `__all__`. A module
  docstring that says what the module is **for**. Before writing, read `stage7/hivelock/stage6_bridge.py`
  and `stage6/capsule/experience_capsule.py`: they are the house style and the two modules Stage 8
  sits next to.
- Files under ~800 lines, functions under ~50. `print()` only in `cli.py`.
- **Every store is bounded, every truncation explicit, every eviction counted.** A store without
  `memory_bytes()`, `stats()` and a named cap constant is a defect.
- **Cost is work units.** Generators, population, planner, laboratory, vault, falsifiers, FORGE and
  every detector executor charge the run's `WorkMeter` (`pocketsec.stage6.resources.WorkMeter`,
  reused through `ResearchGovernor`). One unit = one predicate test of one step, one state update,
  or one feature read. Wall clock is recorded beside `/proc/loadavg` and never asserted.
- **The T5 trap. Read before naming a field.** No annotated `@dataclass` field under
  `pocketsec/stage8/` may contain, lowercased, any member of `FORBIDDEN_AUTHORITY_FIELDS`
  (`action, remediation, execute, command, shell, kill, quarantine, block, authorize,
  authorization, privilege, sudo`). The words that bite in *this* stage: **`kill_criterion`**
  (use `refutation_rule`), **`lab_authorization`** (use `clearance`), `extraction`, `fraction`,
  `interaction`, `transaction` (all contain `action`), `quarantine_bucket` (use `stage6_bucket`),
  `blocked`, `executed`, `privileged`. Every share is a `share` or a `rate`. Enum *members* are not
  fields and are not screened (`TriggerClass.PRIVILEGE` is fine).
- **No real execution, no network.** No module under `pocketsec/stage8/` imports `socket`, `ssl`,
  `http`, `urllib`, `ftplib`, `smtplib`, `socketserver`, `select`, `selectors`, `asyncio`,
  `subprocess`, `multiprocessing`, `ctypes`, `pty`, `xmlrpc`, `telnetlib`, `pickle`, `marshal` or
  `shelve`, or calls `os.system`, `os.popen`, `os.exec*`, `os.spawn*`, `eval`, `exec`, `compile` or
  `__import__`. `importlib.import_module` is allowed only in `core_ids.py`,
  `constitution/discovery.py` and `labs/eighty_experiments.py` (string symbol resolution).
- **Defensive only.** Adversarial generation perturbs **synthetic telemetry** (`Episode` values and
  Stage 1 `Behaviour` sequences inside `labs/`) to test defences. No module produces code, command
  lines, payloads or anything that runs outside the process. The closed vocabularies
  (`RepresentationKind`, `ExperimentClass`, `ChallengeKind`, `TransformKind`, `GeneratorKind`,
  `FalsifierKind`) name detection, explanation and containment knowledge only, and
  `verify_discovery_constitution()` screens their members against `OFFENSIVE_TOKENS` (§4 D8.1).

### 2.3 Upstream imports: an allow-list (ADR-0071)

| upstream | Stage 8 may import | from which Stage 8 files | never |
|---|---|---|---|
| Stage 0 | anything under `pocketsec.stage0` | any | — |
| Stage 1 | anything under `pocketsec.stage1` | any | — |
| Stage 2 `encoder.ssir_encoder` | `EncodedTransition`, `FEATURE_LAYOUT`, `FEATURE_WIDTH`, `GROUP_OFFSETS`, `feature_names` | any | — |
| Stage 2 `compile_candidates.phi_oracle_candidate` | `PHI_SQUASHED_FEATURE_INDEX`, `PHI_ORACLE_SCORER` | any | everything else in Stage 2, `research.*` |
| Stage 3, 4, **5** | **nothing** (T2 forbids Stage 5 outright) | — | everything |
| Stage 6 `capsule.experience_capsule` | `EncodedStep`, `ExperienceCapsuleV1`, `MAX_STEPS_PER_CAPSULE`, `MAX_EVIDENCE_REFS_PER_CAPSULE`, `source_group_of` | any | — |
| Stage 6 `capsule.experience_capsule` | `capsule_from_scenario`, `SourceProvenance`, `SourceClass`, `LabelOrigin`, `LabelAssertion`, `ContaminationFlag`, `reseal_capsule`, `PrivacyClass` | `adapters/stage6.py` only | — |
| Stage 6 `memory.semantic` | `MotifStep`, `match_motif`, `motif_pattern_key`, `MAX_MOTIF_LENGTH`, `is_escalating` | any | all other names |
| Stage 6 `memory.semantic` | `genesis_state` | `labs/` only | — |
| Stage 6 `capsule.quarantine` | `QuarantineGateway`, `QuarantineVerdict`, `QuarantineBucket` | `adapters/stage6.py`, `labs/` | — |
| Stage 6 `provenance.trust` | `score_provenance` | `adapters/stage6.py` only (reported beside the bucket) | — |
| Stage 6 `fossils.lineage` | `KnowledgeLineageDAG` | `labs/` only (lab gateway construction) | — |
| Stage 6 `provenance.ledger` | `ProvenanceLedger` | `labs/` only | — |
| Stage 6 `resources` | `WorkMeter`, `WorkBudgetExceeded`, `loadavg` | any | the rest |
| Stage 6, everything else | **nothing**: `promotion.*`, `chamber.*`, `conservation.*`, `shadow.*`, `consolidator.*`, `plasticity.*`, `rehearsal.*`, `homeostasis.*`, `fossils.store`, `memory.{episodic,procedural,competition,half_life}`, `fleet.*`, `export.*`, `gate*`, `labs.*` | — | — |
| Stage 7 `capsule.knowledge_capsule` | `KnowledgeCapsuleV1`, `MotifRow`, `KnowledgeType`, `Stance` | `adapters/stage7.py` only | everything else in Stage 7 |

The integrator's harness (`gate.py`, `gate_*.py`, `cli.py`) has the `labs/` allowances and nothing
more. A whole-module import (`import pocketsec.stage6.memory.semantic`) is refused everywhere,
because names cannot be checked through it.

### 2.4 Another wave may be building in this tree

- **Never** edit, revert or delete anything under `pocketsec/stage<other>/`,
  `tests/test_stage<other>_*.py` or `docs/stage-<other>-*.md`. Never run `git checkout`,
  `git stash`, `git restore`, `git clean` or `git commit`.
- **Never** edit `tests/test_repository_structure.py`. Stage 8's rules live in
  `tests/test_stage8_boundary.py` (§5.1), which **imports** the one resolver
  `pocketsec.stage2.gate_criteria.imported_modules` (`gate_criteria.py:547`) and never copies it.
- Judge Stage 8 by `tests/test_stage8_*.py` plus `pocketsec-stage8 gate`. Report failures in another
  stage's test files and move on.
- `pyproject.toml` is shared. The integrator appends exactly
  `pocketsec-stage8 = "pocketsec.stage8.cli:main"` and one CI step. Nothing else.
- **Stage 9 is being built concurrently** and consumes §3.3. Package `foundation` lands
  `forge/package.py` first; after the Build phase its shape does not change.

### 2.5 The gate never mutates the real experiment ledger

`Stage8GateContext.build()` never constructs `ExperimentRegistry` on `experiments/registry.jsonl`.
G8.12 asserts the file is byte-identical before and after the gate run. Rows are written only by
`pocketsec-stage8 experiments --register`. `TheoryLedger` is **not** a second experiment ledger: it
records hypotheses, preregistrations and test outcomes inside one run, is in memory, and never
writes `experiments/registry.jsonl` (boundary rule 12).

### 2.6 Hypothesis binding: no H14 is minted (ADR-0070)

The integration plan's hypothesis ADR was never written and `HYPOTHESES` holds H0–H8
(`stage0/hypotheses.py:50`, read this session). Stage 8 binds its gate to `BASE` (Stage 5/7
precedent), its FORGE rows to `H4` ("stable learned behaviour can become cheap executable
detectors") and its ablation rows to `H8` ("combine only components independently justified by
ablation").

```python
STAGE8_HYPOTHESIS = "BASE"
EXPERIMENT_ID = "PS-S8-20260926-BASE-prometheus-gate-0001"
FORGE_HYPOTHESIS = "H4"
ABLATION_HYPOTHESIS = "H8"
```

### 2.7 Timing on a contended host

Every timing figure carries `/proc/loadavg` (`stage6.resources.loadavg`). Every comparison of two
paths is a **within-run ratio**. No absolute microsecond figure is ever presented as a device
measurement. A Stage 2 gate measured a 7× inflation at load 23–67 against load 8–12. Selection never
reads wall time (§4 D8.15).

---

## 3. The data seam

### 3.1 Consumed from Stages 0–7. Every symbol exists (M0.1), cited `path:line`

| symbol | path:line | how Stage 8 uses it |
|---|---|---|
| `ContractError`, `register_schema`, `digest_of_bytes`, `require_identifier`, `require_finite_unit_interval`, `EvidenceRef`, `SCHEMA_REGISTRY` | `stage0/contracts/common.py:32`, `:49`, `:116`, `:72`, `:84`, `:124`, `:46` | validation; `pocketsec.discovery_package.v1` registration; content addressing |
| `Verdict`, `FORBIDDEN_AUTHORITY_FIELDS` | `stage0/contracts/threat_prediction_v1.py:66`, `:48` | identifiability → `Verdict.UNIDENTIFIABLE` / `INSUFFICIENT_EVIDENCE`; T5 and the payload-key screen |
| `GateCheck`, `GateReport`, `REPO_ROOT` | `stage0/gate.py:44`, `:55`, `:33` | the gate |
| `ResourceSampler`, `ResourceMetrics`, `read_rss_bytes` | `stage0/benchmark/resource_metrics.py:103`, `:57`, `:38` | G8.11; the only RSS source |
| `check_profile`, `ProfileReport`, `PROFILES`, `HOST_RAM_TARGET_BYTES` | `stage0/benchmark/profiles.py:85`, `:61`, `:36`, `:58` | G8.11; `within_target is None` is UNMEASURED |
| `evaluate_scores`, `average_precision`, `recall_at_max_fpr`, `confusion_at_threshold`, `SecurityMetrics` | `stage0/benchmark/security_metrics.py:211`, `:92`, `:122`, `:73`, `:177` | every PR-AUC/recall/FP figure. No second metric implementation |
| `ExperimentRegistry`, `format_experiment_id`, `parse_experiment_id` | `stage0/experiments/registry.py:106`, `ids.py:56`, `:75` | CLI registration only |
| `HYPOTHESES`, `Hypothesis` | `stage0/hypotheses.py:88`, `:31` | G8.12 discipline (`set(HYPOTHESES) == {H0…H8}`) |
| `PriorArtLedger`, `PriorArtEntry`, `ReviewStatus` | `stage0/prior_art.py:71`, `:31`, `:25` | D8.13: `novelty_claim_permitted` is read, never set |
| `SeedSet`, `git_state`, `EnvironmentFingerprint` | `stage0/repro/seeds.py:23`, `environment.py:44`, `:54` | seeds; §34 environment manifest |
| `Stage1Pipeline`, `ScenarioResult` | `stage1/pipeline.py:77`, `:46` | the corpus renders every session through Stage 1 once, on a fresh pipeline |
| `Behaviour`, `Scenario`, `BENIGN_PATTERNS`, `BENIGN_PRIVILEGED`, `ATTACK_EXFIL`, `ATTACK_PERSISTENCE`, `ATTACK_UNSEEN_MEMORY`, `ATTACK_UNSEEN_ESCAPE`, `build_corpus`, `CORPUS_VERSION` | `stage1/labs/corpus.py:33`, `:44`, `:66`, `:101`, `:110`, `:118`, `:127`, `:134`, `:220`, `:28` | the only scenario types. No fifth one. `ATTACK_*` seed the novelty library |
| `build_hard_corpus`, `HARD_CORPUS_VERSION`, `build_ambiguous_corpus`, `AMBIGUOUS_VERSION` | `stage1/labs/hard_corpus.py:249`, `:40`, `ambiguous_corpus.py:268`, `:45` | INDEPENDENT split (benign FP control) |
| `SSIRTransitionV1`, `SemanticProperty`, `Relation`, `RelationFamily`, `family_of`, `DIMENSIONS`, `SensorPath` | `stage1/ssir/transition.py:81`, `entities.py:64`, `relations.py:19`, `:56`, `:95`, `state/security_state.py:108`, `telemetry/raw_event_v1.py:41` | grammar vocabulary; bit orders |
| `Epoch`, `EpochModel`, `SystemIdentity` | `stage1/epoch/model.py:104`, `:136`, `:54` | the adapter's local epoch |
| `LogisticProbe` | `stage1/guillotine/features.py:128` | the LOGISTIC representation and the direct-model baseline. Stdlib, refuses single-class fits |
| `EncodedTransition`, `FEATURE_LAYOUT`, `FEATURE_WIDTH` (96), `GROUP_OFFSETS`, `feature_names()` | `stage2/encoder/ssir_encoder.py:142`, `:94`, `:95`, `:108`, `:122` | feature slots; `required_features` names |
| `PHI_SQUASHED_FEATURE_INDEX` (73), `PHI_ORACLE_SCORER` | `stage2/compile_candidates/phi_oracle_candidate.py:65`, `:175` | baseline (1): the Φ-oracle is `max(step.features[73])` |
| `imported_modules(node, path)` | `stage2/gate_criteria.py:547` | tests only: the one import resolver |
| `EncodedStep` (features, relation, relation_family, state_delta_mask, time_bucket, delta_phi, object_property_mask, epoch_id, actor_slot, uncertainty, source_group, causal_signature, parent_signature, evidence; `observation_incomplete`) | `stage6/capsule/experience_capsule.py:311`, `:365` | **the step type of every Stage 8 episode** (Stage 7 precedent): a capsule built from the same `ScenarioResult` holds identical steps |
| `ExperienceCapsuleV1`, `capsule_from_scenario`, `SourceProvenance`, `SourceClass`, `LabelOrigin`, `LabelAssertion`, `ContaminationFlag`, `reseal_capsule`, `PrivacyClass`, `source_group_of`, `MAX_STEPS_PER_CAPSULE` (64), `MAX_EVIDENCE_REFS_PER_CAPSULE` (32) | `experience_capsule.py:554`, `:861`, `:426`, `:156`, `:166`, `:474`, `:181`, `:744`, `:175`, `:303`, `:118`, `:119` | the only form a discovery takes into Stage 6 |
| `QuarantineGateway.admit(capsule) -> QuarantineVerdict`, `QuarantineBucket` | `stage6/capsule/quarantine.py:383`, `:472`, `:150` | the single admission function (integration plan §3.2) |
| `score_provenance`, `MIN_PROVENANCE_SCORE` (0.5), `SOURCE_CLASS_PRIOR`, `FLAG_RISK` | `stage6/provenance/trust.py:134`, `:64`, `:69`, `:98` | the adapter reports the predicted score; M0.2 |
| `MotifStep(relation, require_properties, forbid_properties, require_raised)`, `match_motif`, `motif_pattern_key`, `MAX_MOTIF_LENGTH` (2), `is_escalating`, `genesis_state` | `stage6/memory/semantic.py:222`, `:801`, `:250`, `:127`, `:268`, `:776` | **the MOTIF representation is Stage 6's DETECTOR grammar, executed by Stage 6's own matcher** (lesson 3) |
| `KnowledgeLineageDAG`, `ProvenanceLedger` | `stage6/fossils/lineage.py:209`, `provenance/ledger.py:139` | labs: the lab gateway |
| `WorkMeter`, `WorkBudgetExceeded`, `loadavg` | `stage6/resources.py:137`, `:133`, `:181` | work units; the governor's kill switch; loadavg beside timings |
| `KnowledgeCapsuleV1`, `MotifRow`, `KnowledgeType`, `Stance` | `stage7/capsule/knowledge_capsule.py:597`, `:322`, `:154`, `:170` | inbound seeds only |
| `TransactionalExecutor`, `_refuse_untyped` | `stage5/executor/transactional.py:411`, `:392` | **tests only** (`tests/test_stage8_boundary.py`): the discovered rule is refused at the executor's entry. No Stage 8 module imports Stage 5 |

### 3.2 The upstream contracts, quoted where they decide Stage 8's design

**Stage 6's single door** (`quarantine.py` docstring): "Every experience that may ever change what
this endpoint trusts … enters here and nowhere else … `admit` never writes trusted state." And
`admit` raises `ContractError` for anything that is not an `ExperienceCapsuleV1`
(`quarantine.py:472`). A `DiscoveryPackageV1` is therefore refused there by type. A discovery
reaches Stage 6 only as capsules built by `capsule_from_scenario`, which "never reads
`result.scenario` at all" — so the lab label never rides in by the side door. The inference label is
an explicit `LabelAssertion` whose origin must agree with the provenance.

**Stage 6's detector grammar** (`semantic.py:222`, `:801`). A motif is 1–2 `MotifStep`s. Each is a
bitmask test `(relation, require_properties, forbid_properties, require_raised)`. A 2-step motif
requires step *i* then *j* (*i* < *j*) of **one actor**. Known inexpressible, stated in advance:
counts, co-occurrence in either order, absence, timing, actor properties, chains longer than 2.
Stage 8's `MOTIF` representation inherits exactly this and refuses everything else (lesson 2).

**Stage 7's antibody** is a Stage 6 motif (`MotifRow`, four ints). Stage 7 exports only Stage 6
trusted DETECTOR records (ADR-0062). The outbound direction for a Stage 8 discovery is therefore
Stage 6 → Stage 7, never Stage 8 → Stage 7 (ADR-0071).

### 3.3 Exposed to Stage 9 — the names this contract assigns

`pocketsec/stage8/forge/package.py` (package `foundation`), schema
`pocketsec.discovery_package.v1` @ `1.0.0` via `register_schema`. **Small on purpose. Frozen after
the Build phase.**

| type | for |
|---|---|
| `DiscoveryPackageV1` | the typed candidate: mechanism, evidence lineage, falsification, failure conditions, measured tournament, hashes |
| `TournamentResult`, `RepresentationMeasurement` | every entrant FORGE measured, including refused ones, and the selection |
| `RepresentationKind`, `NoveltyClass`, `IdentifiabilityClass`, `ReproducibilityStatus` | closed enums |
| `FalsificationRecord`, `FailureCondition`, `ReproducibilityRecord`, `ResourceProfile`, `RobustnessProfile` | plain records inside the package |
| `Mechanism`, `StepPredicate`, `MechanismRelation`, `Modifier` | `genome/grammar.py`: the typed mechanism the package carries |
| `verify_package(package) -> tuple[str, ...]` | `()` is the only passing answer |

**Binding inherited by Stage 9.** A `DiscoveryPackageV1` is never authority. It carries no
`FORBIDDEN_AUTHORITY_FIELDS` key at any depth (`from_dict` refuses). It reaches an endpoint only
through `adapters/stage6.py`, as evidence capsules, and today none is adopted (B8-1).

---

## 4. Deliverables: modules, types, signatures, bounds

`[package]` names the owner (§5). Every constant is in §4.21 and is a **chosen parameter, not a
measurement**.

### 4.0 The model everything else hangs on. Read first

- **Episode.** One session: a tuple of Stage 6 `EncodedStep`s (≤ 64, Stage 6's own cap) produced
  from one Stage 1 `ScenarioResult` with Stage 6's actor-slot rule, plus a lab label (`int | None`),
  a `Split` and lab metadata. `episode_id` is content-derived.
- **Splits.** `TRAIN` (PROMETHEUS sees only this), `HOLDOUT` (evaluated once, in the vault),
  `REPLICATION` (host-, time- and family-separated; evaluated once, in a second vault), `LAB_POOL`
  (ORACLE's experiments), `INDEPENDENT` (Stage 1 benign sessions; FP control), `CHALLENGE`
  (derived episodes). A generator, the observatory or the population handed a non-TRAIN episode
  raises `ContractError`.
- **Mechanism.** A typed predicate over an episode drawn from a closed grammar whose every member
  has an evaluator. Natural language is a rendering only.
- **Theory lifecycle.** `PROPOSED` (born, in the ledger) → challenge screens on TRAIN/LAB_POOL
  (`CHALLENGED_OUT` or kept) → ORACLE pruning → `REGISTERED` (preregistration entry, one Bonferroni
  batch) → vault evaluation (`SURVIVED` / `FALSIFIED`) → identifiability → REPLICATION batch
  (`REPRODUCED` / `NOT_REPRODUCED` / `INSUFFICIENT_EVIDENCE`) → novelty → FORGE → package → adapter.
- **Measurement boundary.** Detection value is measured at `DiscoveryPackageV1` (REPLICATION split)
  and labelled `counterfactual_at_boundary`. Stage 6's buckets are reported beside it (B8-1).

### D8.1 — Discovery Constitution `[integrity]`

```python
# pocketsec/stage8/constitution/discovery.py
@dataclass(frozen=True, slots=True)
class DiscoveryLaw:
    law_id: str                         # "DL-01" … "DL-09", architecture §3 in order
    text: str                           # the §3 sentence, verbatim
    enforced_by: tuple[str, ...]        # "pocketsec.stage8.<module>:<qualname>" or "tests/<file>.py::<test>"

DISCOVERY_LAWS: tuple[DiscoveryLaw, ...]      # exactly 9
OFFENSIVE_TOKENS: re.Pattern[str]             # (?i)(exploit|payload|shellcode|malware|implant|backdoor|ransom|keylog|rootkit|weaponi[sz])
SAFE_EXPERIMENT_CLASSES: frozenset[ExperimentClass]   # every member except ISOLATED_EMULATION

def verify_discovery_constitution() -> tuple[str, ...]: ...   # () is the only pass
```

Binding of the nine laws: DL-01 defensive only → `OFFENSIVE_TOKENS` screen over the six closed
vocabularies + boundary rule 8; DL-02 no hypothesis grants action → T5 + `ExperimentClass` has no
production-intervention member; DL-03 no bypass of Stage 5/6 → boundary rules 3, 5, 7; DL-04 LLM
cannot define ground truth → `ExternalProposalGenerator` stores digests only and its genomes are
`foreign=True`; DL-05 every accepted theory states falsifying observations → `HypothesisGenome`
validation; DL-06 UNKNOWN/UNIDENTIFIABLE valid → `IdentifiabilityGate`; DL-07 complexity penalised
→ `Mechanism.description_length_bits` + MDL acceptance; DL-08 not trusted until Stage 6 →
`adapters/stage6.py`; DL-09 active experiments need isolated lab clearance → `ResearchSandbox`.
`verify_discovery_constitution` checks: every `enforced_by` resolves (`importlib`, lazily, by
string); no member of `RepresentationKind`, `ExperimentClass`, `ChallengeKind`, `TransformKind`,
`GeneratorKind`, `FalsifierKind` matches `OFFENSIVE_TOKENS`; `ExperimentClass` members equal
`SAFE_EXPERIMENT_CLASSES ∪ {ISOLATED_EMULATION}`; constructing a `HypothesisGenome` with an empty
falsifier set raises `ContractError`; `Verdict.UNIDENTIFIABLE` exists. ~130 lines.

### D8.3 (unit) — `episode.py` `[foundation]`

```python
EPISODE_VERSION = "stage8-episode.1.0.0"
MAX_EPISODE_STEPS: int = MAX_STEPS_PER_CAPSULE          # imported from Stage 6 (64), never redefined
MAX_EPISODE_EVIDENCE: int = MAX_EVIDENCE_REFS_PER_CAPSULE  # 32

class Split(StrEnum): TRAIN; HOLDOUT; REPLICATION; LAB_POOL; INDEPENDENT; CHALLENGE

@dataclass(frozen=True, slots=True)
class EpisodeContext:                 # lab metadata; NEVER a model feature
    host_id: str
    epoch_id: int                     # lab split epoch (time separation), not the steps' epoch_id
    family: str                       # lab family name; "" when unknown
    corpus: str                       # the generator's <NAME>_VERSION
    synthetic: bool

@dataclass(frozen=True, slots=True)
class Episode:
    episode_id: str                   # "ep-" + sha256(canonical steps)[:24]; "" derives; mismatch refused
    steps: tuple[EncodedStep, ...]    # 1 … MAX_EPISODE_STEPS
    label: int | None                 # 0 / 1 lab ground truth, or None
    split: Split
    context: EpisodeContext
    truncated: bool                   # True iff the source had > MAX_EPISODE_STEPS transitions
    def phi_oracle_score(self) -> float           # max(step.features[PHI_SQUASHED_FEATURE_INDEX]); 0.0 if empty
    def evidence_digests(self) -> tuple[str, ...] # dict.fromkeys over step.evidence, ≤ MAX_EPISODE_EVIDENCE
    def actors(self) -> frozenset[int]
    def with_split(self, split: Split, *, label: int | None) -> Episode   # derived episodes only

@dataclass(frozen=True, slots=True)
class FitCounts:                      # the one confusion count used by genome, vault, FORGE and baselines
    matched: int; true_matches: int; false_matches: int; positives: int; negatives: int
    precision: float | None           # property; None when matched == 0
    recall: float | None              # property; None when positives == 0
    f1: float | None                  # property
    false_positive_rate: float | None # property; None when negatives == 0

def episode_from_result(result: ScenarioResult, *, split: Split, context: EpisodeContext,
                        label: int | None) -> Episode: ...
def fit_counts(decide: Callable[[Episode], bool], episodes: Sequence[Episode], *,
               meter: WorkMeter | None = None) -> FitCounts: ...   # unlabelled episodes are skipped and counted nowhere
```

`episode_from_result` uses Stage 6's slot rule exactly (order of first appearance of
`transition.actor.identity`) and `EncodedStep.from_transition`. It never reads `result.scenario`.
A test asserts `episode.steps == capsule_from_scenario(result, …).steps` for 20 sessions. The
content id excludes label, split and context, so the same session placed in two splits has the same
id (that is what leakage detection keys on). Stage 1 steps carry session-unique causal signatures
and evidence digests, so distinct sessions never collide.

### D8.3 — Mechanism Grammar `[foundation]`

```python
# pocketsec/stage8/genome/grammar.py
GRAMMAR_VERSION = "stage8-mechanism-grammar.1.0.0"
PROPERTY_BITS: int      # = FEATURE_LAYOUT width of "object_semantics" (15), derived at import
RAISED_BITS: int        # = len(DIMENSIONS) (9), derived at import
MAX_MECHANISM_STEPS: int = MAX_MOTIF_LENGTH     # 2, imported from Stage 6
MAX_REPEAT: int = 8
MAX_DSL_BYTES: int = 256

class TriggerClass(StrEnum): EXECUTION; AUTH; PRIVILEGE; FILE; NETWORK; PERSISTENCE; IDENTITY; CONFIGURATION
class MechanismRelation(StrEnum): SINGLE; PRECEDES; CO_OCCURS; WITHOUT
class Modifier(StrEnum): NONE; REPEATED
class GrammarError(ContractError): ...

@dataclass(frozen=True, slots=True)
class StepPredicate:
    relation: int               # a Relation value, 0 … 23
    require_properties: int     # object_property_mask bits, < 2**PROPERTY_BITS
    forbid_properties: int      # disjoint from require_properties
    require_raised: int         # state_delta_mask bits, < 2**RAISED_BITS
    def matches(self, step: EncodedStep) -> bool          # MotifStep.matches semantics, bit for bit
    def to_motif_step(self) -> MotifStep
    def bits(self) -> int                                 # popcounts of the three masks
    def trigger_class(self) -> TriggerClass               # rendering only (table below)

@dataclass(frozen=True, slots=True)
class Mechanism:
    relation: MechanismRelation
    steps: tuple[StepPredicate, ...]      # 1 for SINGLE, 2 otherwise
    modifier: Modifier = Modifier.NONE
    repeat_min: int = 1                   # REPEATED: 2 … MAX_REPEAT and relation SINGLE; NONE: exactly 1
    def matches(self, steps: Sequence[EncodedStep], *, meter: WorkMeter | None = None) -> bool
    def description_length_bits(self) -> int
    def canonical(self) -> dict[str, Any]
    def digest(self) -> str               # "mech-" + sha256(canonical)[:16]
    def render(self) -> str               # English; never parsed back; never stored as state
    def to_dsl(self) -> str               # the DSL form; parse_mechanism(m.to_dsl()) == m

def parse_mechanism(text: str) -> Mechanism: ...   # strict; GrammarError on anything else
```

Evaluator semantics (per actor slot; this is the whole grammar):

| relation | fires iff |
|---|---|
| `SINGLE`, `NONE` | some step matches `a` |
| `SINGLE`, `REPEATED(k)` | some actor has ≥ *k* steps matching `a` |
| `PRECEDES` | some actor has a step *i* matching `a` and a later step *j* > *i* matching `b` (Stage 6 `match_motif` semantics, including checking `b` before arming) |
| `CO_OCCURS` | some actor has two distinct steps matching `a` and `b`, in either order |
| `WITHOUT` | some actor has a step matching `a` and no step of that actor matches `b` |

`description_length_bits = 2 + Σ_steps (5 + 4·popcount(require_properties) +
4·popcount(forbid_properties) + 4·popcount(require_raised)) + (3 if REPEATED else 0)`.

DSL, ASCII only, ≤ `MAX_DSL_BYTES`: `SINGLE(p)`, `PRECEDES(p,p)`, `CO_OCCURS(p,p)`, `WITHOUT(p,p)`,
`REPEATED(p,k)`; `p := RELATION_NAME ("+" PROPERTY)* ("-" PROPERTY)* ("^" dimension)*`, names exactly
as `Relation`, `SemanticProperty` (the encoder's 15, in order) and `DIMENSIONS` spell them, e.g.
`PRECEDES(EXECUTE+TEMP_LOCATION,CONNECT+EXTERNAL_ENDPOINT)`. Any other token, whitespace outside the
separators, duplicates or out-of-vocabulary names → `GrammarError`.

`trigger_class()` (rendering, ordered rules): raised `privilege` or family `AUTHORIZATION` →
PRIVILEGE; `AUTHENTICATE` → AUTH; `IMPERSONATE` → IDENTITY; raised `persistence` or property
`PERSISTENCE` → PERSISTENCE; family `EXECUTION`/`LOADING` → EXECUTION; `FILESYSTEM` → FILE;
`NETWORK` → NETWORK; `CONTROL`/`PACKAGING` → CONFIGURATION.

**Not built, and why (ADR-0072).** Architecture relations `enables`, `causes_candidate`,
`suppresses`, `requires` are causal claims: on observational replay each is indistinguishable from
`PRECEDES`/`CO_OCCURS`, so the identifiability gate would always answer `EQUIVALENCE_CLASS`. Their
only honest evaluator is an intervention, which this wave has only in the lab (D8.6). Modifiers
`rare`, `epoch-specific`, `user-specific`, `visibility-dependent`, `collective` have no evaluator in
the step type (novelty and actor properties are not in the mask; ADR-0006 keeps names out) and no
consumer. `REPEATED` is built because a planted mechanism needs it and because it gives FORGE's
expressibility check a function `MOTIF` cannot express (lesson 2 must fire). ~300 lines.

### D8.3 — Hypothesis Genome `[foundation]`

```python
# pocketsec/stage8/genome/hypothesis.py
GENOME_VERSION = "stage8-hypothesis-genome.1.0.0"
MAX_SCOPE_RESIDUALS = 16; MAX_SCOPE_EPISODES = 64; MAX_FORBIDDEN = 4; MAX_COMPETITORS = 8
MAX_FALSIFIERS = 8; MAX_PARENTS = 2; MAX_INFORMATION_REQUESTS = 4

class Direction(StrEnum): MALICIOUS; BENIGN            # what a match predicts
class GeneratorKind(StrEnum): SYMBOLIC_ENUMERATOR; RESIDUAL_MOTIF; ANALOGY; NULL_BENIGN; STAGE7_SEED;
    EXTERNAL_PROPOSAL; RANDOM_BASELINE; EXHAUSTIVE_SINGLE_BASELINE; MUTATION; MERGE; SPLIT
class ResidualType(StrEnum): OBSERVATION; CAUSAL; VISIBILITY; COLLECTIVE
class CausalAssumption(StrEnum): SAME_ACTOR; ORDER_MATTERS; ABSENCE_OBSERVABLE; COUNT_MATTERS
class VisibilityAssumption(StrEnum): REQUIRES_COMPLETE_OBSERVATION; TOLERATES_STEP_LOSS
class ExperimentClass(StrEnum): HISTORICAL_REPLAY; COUNTERFACTUAL_MUTATION; TELEMETRY_DROPOUT;
    METAMORPHIC_TRANSFORM; BENIGN_ALTERNATIVE; SYNTHETIC_EVENT_WORLD; ISOLATED_EMULATION
    # There is NO production-intervention member: architecture §16 "no direct path" (ADR-0075)
class FalsifierKind(StrEnum): HOLDOUT_ENRICHMENT; HOLDOUT_FALSE_POSITIVES; HOLDOUT_RECALL;
    COUNTERFACTUAL_INVARIANCE; NECESSARY_STEP_ABLATION; DOPPELGANGER_SEPARATION; REPLICATION
MANDATORY_FALSIFIERS: frozenset[FalsifierKind] = {HOLDOUT_ENRICHMENT, HOLDOUT_FALSE_POSITIVES, REPLICATION}

@dataclass(frozen=True, slots=True)
class Falsifier:
    kind: FalsifierKind
    split: Split
    threshold: float               # the refutation rule's parameter; meaning per kind (table below)
    alpha: float | None            # family-wise alpha for HOLDOUT_ENRICHMENT / REPLICATION, else None

@dataclass(frozen=True, slots=True)
class Prediction:                  # recorded before the split is evaluated
    split: Split                   # HOLDOUT or REPLICATION
    min_precision: float
    min_recall: float
    max_false_positive_rate: float

@dataclass(frozen=True, slots=True)
class ObservationScope:
    residual_cluster_ids: tuple[str, ...]      # ≤ MAX_SCOPE_RESIDUALS
    residual_types: frozenset[ResidualType]
    episode_ids: tuple[str, ...]               # TRAIN episodes the generator read, ≤ MAX_SCOPE_EPISODES

@dataclass(frozen=True, slots=True)
class GenomeProvenance:
    generator: GeneratorKind
    source_digest: str             # sha256: of the generator's input (cluster, text, capsule ids)
    foreign: bool                  # True for STAGE7_SEED and EXTERNAL_PROPOSAL, refused otherwise
    seed: int

@dataclass(frozen=True, slots=True)
class HypothesisGenome:
    hypothesis_id: str                         # "hyp-" + sha256(canonical minus id)[:24]; "" derives
    observation_scope: ObservationScope
    proposed_mechanism: Mechanism
    direction: Direction
    predicted_observations: tuple[Prediction, ...]      # covers HOLDOUT and REPLICATION
    forbidden_observations: tuple[StepPredicate, ...]   # ≤ MAX_FORBIDDEN; same actor matching any → no fire
    competing_explanations: tuple[str, ...]             # hypothesis ids, ≤ MAX_COMPETITORS
    visibility_assumptions: frozenset[VisibilityAssumption]   # non-empty
    falsification_tests: tuple[Falsifier, ...]          # ⊇ MANDATORY_FALSIFIERS, ≤ MAX_FALSIFIERS
    information_requests: tuple[ExperimentClass, ...]   # ≤ MAX_INFORMATION_REQUESTS
    provenance: GenomeProvenance
    parent_hypotheses: tuple[str, ...]                  # ≤ MAX_PARENTS
    schema_version: str = GENOME_VERSION
    # derived, not fields:
    @property causal_dependencies -> tuple[CausalAssumption, ...]   # PRECEDES: SAME_ACTOR+ORDER_MATTERS …
    @property necessary_conditions -> tuple[StepPredicate, ...]     # mechanism steps (WITHOUT: the first)
    @property sufficient_conditions_candidate -> Mechanism          # the proposed mechanism
    @property complexity_cost -> int      # TheoryCost §12: bits + 4·len(causal) + 8·len(forbidden) + predicate count
    def decides(self, episode: Episode, *, meter: WorkMeter | None = None) -> bool
    def canonical_bytes(self) -> bytes; def digest(self) -> str; def render(self) -> str
    def to_dict(self) -> dict[str, Any]; @classmethod from_dict(cls, payload) -> HypothesisGenome

DEFAULT_FALSIFIERS: tuple[Falsifier, ...]; DEFAULT_PREDICTIONS: tuple[Prediction, ...]
def genome_for(mechanism: Mechanism, *, direction: Direction, scope: ObservationScope,
               provenance: GenomeProvenance, parents: tuple[str, ...] = (),
               competing: tuple[str, ...] = (), forbidden: tuple[StepPredicate, ...] = (),
               falsifiers: tuple[Falsifier, ...] = DEFAULT_FALSIFIERS,
               predictions: tuple[Prediction, ...] = DEFAULT_PREDICTIONS) -> HypothesisGenome
```

**There is no `status` field.** The architecture lists `status` in the genome; this contract binds
it to `TheoryLedger.status(hypothesis_id)`. The genome is immutable and content-addressed, so "a
hypothesis cannot be edited after its test runs" is structural: an edit is a new id with a parent
link, and it needs its own preregistration (ADR-0073). **There is no free-text field.** `render()`
produces English on demand and nothing stores it.

Default refutation rules (kill criteria, registered at birth; §4.21 values):

| falsifier | split | refutes (kills) the theory when | parameter |
|---|---|---|---|
| `HOLDOUT_ENRICHMENT` | HOLDOUT | exact binomial P(X ≥ true matches ∣ matched, base rate) > α / m, m = the batch size | α = 0.05 |
| `HOLDOUT_FALSE_POSITIVES` | HOLDOUT | matched negatives / negatives > threshold (BENIGN direction: matched positives / positives) | 0.01 |
| `HOLDOUT_RECALL` | HOLDOUT | true matches / positives < threshold | 0.10 |
| `COUNTERFACTUAL_INVARIANCE` | LAB_POOL | decision agreement under the PRESERVING transforms < threshold | 0.98 |
| `NECESSARY_STEP_ABLATION` | LAB_POOL | deleting one necessary step removes < threshold of matches | 0.50 |
| `DOPPELGANGER_SEPARATION` | CHALLENGE | max over families of matched doppelgänger share > threshold | 0.05 |
| `REPLICATION` | REPLICATION | the three HOLDOUT rules, re-run on REPLICATION in its own batch | α = 0.05 |

`__post_init__` refuses: an empty or non-mandatory-covering falsifier set; a threshold outside
[0, 1]; α outside (0, 0.5]; predictions missing HOLDOUT or REPLICATION; `foreign` disagreeing with
the generator; an id that does not match its content. ~330 lines.

### D8.16 — Discovery Package format (the Stage 9 interface) `[foundation]`

```python
# pocketsec/stage8/forge/package.py
DISCOVERY_PACKAGE_V1_ID = "pocketsec.discovery_package.v1"
DISCOVERY_PACKAGE_V1_VERSION = register_schema(DISCOVERY_PACKAGE_V1_ID, "1.0.0")
MAX_PACKAGE_LINEAGE = 64; MAX_PACKAGE_EVIDENCE = 32; MAX_FAILURE_CONDITIONS = 16; MAX_ENTRANTS = 8

class RepresentationKind(StrEnum): TYPED_RULE; MOTIF; FSM; THRESHOLD; LOGISTIC; PROTOTYPE; STUMP_TREE
class NoveltyClass(StrEnum): KNOWN; KNOWN_COMBINATION; CONTEXT_EXTENSION; POTENTIALLY_NOVEL
class IdentifiabilityClass(StrEnum): IDENTIFIED; EQUIVALENCE_CLASS; UNIDENTIFIABLE
class ReproducibilityStatus(StrEnum): REPRODUCED; NOT_REPRODUCED; INSUFFICIENT_EVIDENCE

@dataclass(frozen=True, slots=True)
class FalsificationRecord:
    kind: FalsifierKind; split: Split; passed: bool
    statistic: float | None          # p-value, share or agreement, per kind
    parameter: float                 # the registered threshold / alpha
    registration_id: str             # "" for pre-holdout screens

@dataclass(frozen=True, slots=True)
class FailureCondition:              # where the theory is known to fail
    context: str                     # closed codes: "challenge:<ChallengeKind>", "doppelganger:<family>",
                                     # "dropout:<RelationFamily>", "identifiability:<class>", "independent:fp"
    observed_rate: float | None      # recall retained / matched share / FP share
    detail: str                      # ≤ 160 chars, fixed vocabulary rendering

@dataclass(frozen=True, slots=True)
class ReproducibilityRecord:
    status: ReproducibilityStatus
    replication_precision: float | None; replication_recall: float | None
    replication_false_positive_rate: float | None
    imbalance_precision: float | None        # at IMBALANCE_RATIO negatives per positive
    independent_false_positive_rate: float | None
    independent_positives_available: bool
    reasons: tuple[str, ...]

@dataclass(frozen=True, slots=True)
class RepresentationMeasurement:
    kind: RepresentationKind
    expressible: bool
    refusal: str | None               # e.g. "MOTIF_CANNOT_EXPRESS_REPEATED"; None iff expressible
    precision: float | None; recall: float | None; false_positive_rate: float | None; pr_auc: float | None
    decision_agreement: float | None  # vs the TYPED_RULE reference on the same episodes
    work_units_per_event: float | None
    artifact_bytes: int | None        # len(canonical JSON of the artifact)
    wall_ratio_to_reference: float | None   # within-run ratio; never used to select
    loadavg: tuple[float, float, float]
    robustness_recall: float | None   # min over challenge kinds of recall retained
    interpretability: int | None      # predicate / weight / node count

@dataclass(frozen=True, slots=True)
class TournamentResult:
    tournament_id: str                # "tn-" + 24 hex
    hypothesis_id: str
    split: Split                      # REPLICATION
    entrants: tuple[RepresentationMeasurement, ...]   # every RepresentationKind, refused ones included
    pareto_front: tuple[RepresentationKind, ...]
    selected: RepresentationKind | None
    deployable: bool
    reasons: tuple[str, ...]
    discovery_work_units: int
    deployed_work_units_per_event: float | None
    compression_ratio: float | None   # DCR = discovery_work_units / deployed_work_units_per_event
    knowledge_bytes_saved: int | None # research-state bytes − selected artifact bytes
    synthetic_data: bool

@dataclass(frozen=True, slots=True)
class ResourceProfile:
    artifact_bytes: int | None; work_units_per_event: float | None
    endpoint_incremental_rss_bytes: int | None     # None = UNMEASURED
    loadavg: tuple[float, float, float]

@dataclass(frozen=True, slots=True)
class RobustnessProfile:
    recall_retained: tuple[tuple[str, float | None], ...]   # (ChallengeKind value, rate)
    doppelganger_matched_share: tuple[tuple[str, float], ...]

@dataclass(frozen=True, slots=True)
class DiscoveryPackageV1:
    package_id: str                                   # "dp-" + sha256(canonical minus id)[:24]
    hypothesis_id: str
    mechanism: Mechanism
    direction: Direction
    required_features: tuple[str, ...]                # feature_names() entries the selected detector reads
    detector_candidates: TournamentResult
    selected_representation: RepresentationKind | None
    compiled_artifact: Mapping[str, Any] | None       # plain JSON data of the selected detector
    evidence_lineage: tuple[str, ...]                 # lineage node ids root → package, ≤ MAX_PACKAGE_LINEAGE
    evidence_digests: tuple[str, ...]                 # sha256: of supporting episodes' evidence, ≤ 32
    evidence_episode_ids: tuple[str, ...]             # REPLICATION true matches, ≤ 8 (the adapter's input)
    falsification_results: tuple[FalsificationRecord, ...]   # non-empty; every registered falsifier
    failure_conditions: tuple[FailureCondition, ...]         # NON-EMPTY, ≤ MAX_FAILURE_CONDITIONS
    resource_profile: ResourceProfile
    robustness_profile: RobustnessProfile
    known_technique_mappings: tuple[str, ...]         # local library ids only ("stage1:ATTACK_EXFIL"); never ATT&CK ids
    novelty_classification: NoveltyClass
    novelty_claim_permitted: bool                     # always False this wave (D8.13)
    identifiability: IdentifiabilityClass
    reproducibility: ReproducibilityRecord
    artifact_hashes: tuple[tuple[str, str], ...]      # ("mechanism"|"artifact"|"tournament"|"genome", sha256:…)
    synthetic_data: bool
    schema_version: str = DISCOVERY_PACKAGE_V1_VERSION
    def to_dict(self) -> dict[str, Any]; @classmethod from_dict(cls, payload) -> DiscoveryPackageV1

def verify_package(package: DiscoveryPackageV1) -> tuple[str, ...]: ...
```

`verify_package` returns problems for: a hash that does not recompute; empty `failure_conditions`,
`falsification_results` or `evidence_lineage`; a non-`sha256:` digest; `selected_representation`
disagreeing with `detector_candidates.selected`; `novelty_claim_permitted` True; a
`FORBIDDEN_AUTHORITY_FIELDS` member as a key at any depth of `to_dict()`. `from_dict` refuses
unknown keys, authority keys and a mismatched id. `package.py` imports only `episode.py`,
`genome/*` and Stage 0. ~360 lines.

### D8.18 / layer 8.21 — Research Resource Governor `[integrity]`

```python
# pocketsec/stage8/governor/budget.py
@dataclass(frozen=True, slots=True)
class ResearchBudget:
    work_units: int = DEFAULT_RESEARCH_WORK_UNITS
    max_active_residual_clusters: int = 16
    max_hypotheses_per_residual: int = 32
    max_population: int = 256
    max_branch_depth: int = 4
    max_experiments_per_hypothesis: int = 8
    max_experiment_queue: int = 128
    max_counterfactual_worlds: int = 64
    max_external_proposals: int = 256
    max_registrations_per_batch: int = 64

@dataclass(frozen=True, slots=True)
class GovernorReport:
    budget: ResearchBudget; spent: int; exhausted: bool
    spent_by_component: tuple[tuple[str, int], ...]
    refusals_by_bound: tuple[tuple[str, int], ...]

class ResearchGovernor:
    def __init__(self, budget: ResearchBudget) -> None
    @property def meter(self) -> WorkMeter                  # one bounded Stage 6 WorkMeter per run
    def charge(self, component: str, units: int) -> None     # raises WorkBudgetExceeded, pays nothing
    def admit(self, bound: str, current: int) -> bool        # current < the named cap; refusal counted
    def report(self) -> GovernorReport
```

**The kill switch is the budget.** `WorkBudgetExceeded` propagates to `run_discovery`, which ends
the run with `budget_exhausted=True` and everything recorded so far. A runaway generator hits the
budget, not the host (G8.11(a), S8X-50, S8X-52). ~130 lines.

### D8.2 — Residual Observatory `[prometheus]`

```python
# pocketsec/stage8/residual/observatory.py
MAX_RESIDUALS = 4096; MAX_CLUSTER_MEMBERS = 64; MAX_SIGNATURE_ITEMS = 8; FPR_BUDGET = 0.01

class ResidualKind(StrEnum): MISSED_POSITIVE; FALSE_ALARM; UNEXPLAINED_ESCALATION

class Explainer(Protocol):
    explainer_id: str
    def fires(self, episode: Episode) -> bool: ...

class PhiOracleExplainer:                # "Stage 2 dynamics" binds to the Φ-oracle: Stage 2's surviving scorer
    explainer_id = "phi-oracle"
    def __init__(self, threshold: float | None) -> None
    @classmethod def fit(cls, train: Sequence[Episode], *, fpr_budget: float = FPR_BUDGET) -> PhiOracleExplainer
        # threshold from recall_at_max_fpr(labels, phi scores, fpr_budget); None → never fires (counted)
class MotifExplainer:                    # Stage 6 trusted motifs, Stage 7 seeds, validated discoveries
    def __init__(self, explainer_id: str, mechanisms: Sequence[Mechanism]) -> None

@dataclass(frozen=True, slots=True)
class Residual:
    residual_id: str                     # "res-" + 16 hex (episode_id, kind)
    episode_id: str
    kind: ResidualKind
    types: frozenset[ResidualType]
    signature: tuple[tuple[int, int, int], ...]   # sorted distinct (relation, props, raised) of escalating steps, ≤ 8
    explainers_fired: tuple[str, ...]
    host_id: str; epoch_id: int; source_groups: int

@dataclass(frozen=True, slots=True)
class ResidualCluster:
    cluster_id: str                      # "rc-" + 16 hex of the signature
    signature: tuple[tuple[int, int, int], ...]
    residual_ids: tuple[str, ...]        # ≤ MAX_CLUSTER_MEMBERS, truncation counted
    kinds: frozenset[ResidualKind]; types: frozenset[ResidualType]
    hosts: int; epochs: int; source_groups: int
    visibility_share: float              # members with any observation_incomplete step

@dataclass(frozen=True, slots=True)
class ResidualField:
    residuals: tuple[Residual, ...]; clusters: tuple[ResidualCluster, ...]
    total: int; explained: int; truncated: bool
    firings: tuple[tuple[str, int], ...] # per explainer: episodes it fired on

class ResidualObservatory:
    def __init__(self, explainers: Sequence[Explainer], *, governor: ResearchGovernor,
                 max_residuals: int = MAX_RESIDUALS) -> None
    def observe(self, episodes: Sequence[Episode]) -> ResidualField   # TRAIN only; ContractError otherwise
```

`R_D` binds to: the current theory is the OR of the explainers. A labelled episode is a residual
when the theory's decision disagrees with its label (`MISSED_POSITIVE`, `FALSE_ALARM`). An
unlabelled episode with an escalating step (`is_escalating`, Stage 6) that no explainer fires on is
`UNEXPLAINED_ESCALATION` — architecture §90's open-world `UNKNOWN_MECHANISM`, never forced into a
known class. Decomposition (types are sets): every residual is `OBSERVATION`; `VISIBILITY` if any
step has `observation_incomplete`; `CAUSAL` if ≥ 2 actors each hold an escalating step;
`COLLECTIVE` if the cluster was seeded by `adapters/stage7.py`. Clusters group by `signature`.
**Not built:** `R-world` (no Stage 4 import), `R-response` (T2), `R-learning` (no Stage 6 learner
output is consumed), `R-temporal` (the grammar has no timing). Stage 3 cells and Stage 4 worlds are
not explainers (no import path; §9). ~260 lines.

### D8.2 — Priority Field `[prometheus]`

```python
# pocketsec/stage8/residual/priority_field.py
RECURRENCE_SATURATION = 8; PRIORITY_EPSILON = 1e-6
class PriorityMode(StrEnum): FULL; SIZE_ONLY          # SIZE_ONLY is the control

@dataclass(frozen=True, slots=True)
class PriorityTerms:
    impact: float; recurrence: float; persistence: float; information_gap: float
    independent_support: float; known_explanation: float; experiment_cost: float
    safety_risk: float; resource_cost: float

@dataclass(frozen=True, slots=True)
class PriorityScore:
    cluster_id: str; terms: PriorityTerms; priority: float; rank: int

def priority_terms(cluster: ResidualCluster, field: ResidualField) -> PriorityTerms
def prioritise(field: ResidualField, *, top_n: int, mode: PriorityMode = PriorityMode.FULL) -> tuple[PriorityScore, ...]
```

Terms, each in [0, 1]: impact = mean over members of the share of escalating steps;
recurrence = min(1, members / 8); persistence = min(1, (hosts + epochs − 1) / members);
information_gap = share of members that are residuals of the current theory (1.0 for labelled
clusters); independent_support = min(1, source_groups / members); known_explanation =
`visibility_share` (telemetry failure explains it, S8X-04); experiment_cost = min(1, Σ member steps /
2048); safety_risk = 0.0 (replay/lab only); resource_cost = min(1, members / 64).
`priority = impact·recurrence·persistence·gap·support / (known + cost + risk + resource + ε)`.
`SIZE_ONLY` ranks by member count. Falsifier F2 compares them (§8). ~130 lines.

### D8.4 — PROMETHEUS generators `[prometheus]`

```python
# pocketsec/stage8/prometheus/generators.py
@dataclass(frozen=True, slots=True)
class GenerationContext:
    train: tuple[Episode, ...]              # TRAIN only (ContractError otherwise)
    cluster: ResidualCluster
    residual_episodes: tuple[Episode, ...]  # the cluster's members, TRAIN
    known: tuple[Mechanism, ...]            # validated discoveries + Stage 7 seeds (for ANALOGY)
    seed: int

class Generator(Protocol):
    kind: GeneratorKind
    def propose(self, context: GenerationContext, governor: ResearchGovernor) -> Iterator[tuple[Mechanism, Direction]]: ...

class SymbolicEnumerator:         # breadth-first by description_length_bits over the cluster's vocabulary
    def __init__(self, *, max_bits_per_step: int = 2, max_repeat: int = 4) -> None
class ResidualMotifGenerator:     # anti-unification of residual members' escalating steps (mask AND), ≤ 32 pairs
class AnalogyGenerator:           # relation → sibling in the same RelationFamily; one property → its SIBLING_PROPERTIES partner
class NullBenignGenerator:        # BENIGN-direction mechanisms that match FALSE_ALARM members and no MISSED_POSITIVE
class Stage7SeedGenerator:        # yields adapters/stage7.py seeds; genomes foreign=True
    def __init__(self, seeds: Sequence[Mechanism]) -> None
class ExternalProposalGenerator:  # untrusted text (offline LLM, analyst) → parse_mechanism or refusal
    def __init__(self, texts: Sequence[str]) -> None   # ≤ max_external_proposals; each ≤ MAX_DSL_BYTES
    def refusals(self) -> int
class RandomGenerator:            # BASELINE 2: uniform over the full grammar vocabulary, same budget
class ExhaustiveSingleGenerator:  # BASELINE 3: every SINGLE over Relation × {0 ∪ one property} × {0 ∪ one raised}
SIBLING_PROPERTIES: Mapping[str, str]   # CREDENTIAL↔AUTHORIZATION_DATA, TEMP_LOCATION↔USER_WRITABLE,
                                        # EXTERNAL_ENDPOINT↔NETWORK_CLIENT, PERSISTENCE↔PERSISTENCE_WRITER,
                                        # SYSTEM_BINARY↔ROOT_OWNED, INTERPRETER↔PROCESS_SPAWNER
```

The vocabulary of `SymbolicEnumerator` is the relations, property bits and raised bits present in
the cluster's escalating steps. It emits SINGLE first, then PRECEDES/CO_OCCURS/WITHOUT pairs in
observed order, then REPEATED(k) for k in 2..`max_repeat`, each tier sorted by bits then DSL string
(deterministic). Every `propose` charges the governor per mechanism. The **LLM generator** of §9 is
not built: `ExternalProposalGenerator` is its seam, and it stores only `sha256:` of each text
(`GenomeProvenance.source_digest`). Text that does not parse is refused and counted, never
repaired. ~360 lines.

### D8.4 — PROMETHEUS engine `[prometheus]`

```python
# pocketsec/stage8/prometheus/engine.py
MIN_BENIGN_SHARE = 0.2

@dataclass(frozen=True, slots=True)
class GenerationReport:
    births: tuple[str, ...]
    proposed_by: tuple[tuple[str, int], ...]; kept_by: tuple[tuple[str, int], ...]
    duplicates: int; dead_ends_skipped: int; external_refused: int; budget_exhausted: bool

def mechanism_distance(a: Mechanism, b: Mechanism) -> int   # relation kind (4) + per-step relation (5) + mask Hamming + step-count difference
def diversity_select(genomes: Sequence[HypothesisGenome], fits: Mapping[str, FitCounts], k: int, *,
                     min_benign_share: float = MIN_BENIGN_SHARE) -> tuple[HypothesisGenome, ...]
    # greedy max-min distance seeded by best TRAIN f1; BENIGN share ≥ min_benign_share when available

class PrometheusEngine:
    def __init__(self, generators: Sequence[Generator], *, ledger: TheoryLedger,
                 negative_memory: NegativeResultMemory | None, governor: ResearchGovernor,
                 diversity: bool = True) -> None
    def generate(self, context: GenerationContext) -> GenerationReport
```

`generate` runs every generator under budget, dedups by `Mechanism.digest()`, skips
`negative_memory.is_dead_end` (counted), builds genomes with `genome_for` (scope = the cluster and
the members read), selects `max_hypotheses_per_residual` with `diversity_select` (or top-k by TRAIN
f1 when `diversity=False`, the control) and records each birth in the ledger. **Incompatible
hypotheses are kept deliberately** (§10): nothing here prunes by agreement. ~200 lines.

### D8.17 (inbound) — Stage 7 adapter `[prometheus]`

```python
# pocketsec/stage8/adapters/stage7.py
MAX_STAGE7_SEEDS = 64
@dataclass(frozen=True, slots=True)
class Stage7SeedReport:
    mechanisms: tuple[Mechanism, ...]; source_capsule_ids: tuple[str, ...]
    ignored_by_reason: tuple[tuple[str, int], ...]; truncated: bool
def seeds_from_capsules(capsules: Sequence[KnowledgeCapsuleV1]) -> Stage7SeedReport
```

`ANTIBODY` + `SUPPORT` only; 1 `MotifRow` → SINGLE, 2 → PRECEDES (Stage 6 motif semantics); every
other type or stance is ignored and counted. Seeds are hypotheses, never evidence: they go through
the whole discipline like any other. **Outbound is not built** (§3.2): Stage 7 exports Stage 6
trusted records. Distributed residuals (S8X-078) are not built: Stage 7 capsules carry no episodes.
~110 lines.

### D8.5 — Hypothesis Ecology `[oracle]`

```python
# pocketsec/stage8/ecology/population.py
MAX_POPULATION = 256; MAX_BRANCH_DEPTH = 4; MAX_MUTATIONS_PER_GENERATION = 64
GENERATIONS = 3; MDL_GAIN_PER_BIT = 0.01

class MutationKind(StrEnum): TOGGLE_PROPERTY; TOGGLE_RAISED; SIBLING_RELATION; RELATION_KIND; REPEAT_COUNT
class ScoreMode(StrEnum): FULL; FIT_ONLY          # FIT_ONLY is the control

@dataclass(frozen=True, slots=True)
class TheoryScore:                 # §13, one named term each; total = + fit + coherence + survival + cross_epoch
    predictive_fit: float          #   + independent − complexity − contradictions − visibility − fragility
    causal_coherence: float; falsification_survival: float; cross_epoch: float
    independent_evidence: float; complexity: float; contradictions: float
    visibility_dependence: float; adversarial_fragility: float; total: float

@dataclass(frozen=True, slots=True)
class EvolutionReport:
    generations: int; children: int; accepted: int; rejected_mdl: int
    merges: int; splits: int; evicted: int; depth_refused: int

class HypothesisPopulation:
    def __init__(self, *, ledger: TheoryLedger, governor: ResearchGovernor, capacity: int = MAX_POPULATION,
                 max_depth: int = MAX_BRANCH_DEPTH, mdl: bool = True, score_mode: ScoreMode = ScoreMode.FULL) -> None
    def add(self, genome: HypothesisGenome) -> bool           # full → evict lowest total, ledger status FOSSILIZED, counted
    def mutate(self, hypothesis_id: str, kind: MutationKind, *, rng: random.Random) -> HypothesisGenome | None
    def merge(self, a: str, b: str) -> HypothesisGenome | None   # two SINGLE → PRECEDES in the majority TRAIN order
    def split(self, hypothesis_id: str) -> tuple[HypothesisGenome, ...]   # 2-step → two SINGLE
    def evolve(self, train: Sequence[Episode], *, rng: random.Random) -> EvolutionReport
    def score(self, hypothesis_id: str, train: Sequence[Episode]) -> TheoryScore
    def ranked(self, k: int) -> tuple[HypothesisGenome, ...]
    def stats(self) -> Mapping[str, int]; def memory_bytes(self) -> int
```

Mutation changes **exactly one** thing (one bit, one relation to a same-family sibling, the relation
kind, or k ± 1). Unconstrained genetic programming is not built (§11). **MDL acceptance:** a child
with more bits joins only if `f1(child) − f1(parent) ≥ MDL_GAIN_PER_BIT × Δbits` on TRAIN; a child
with fewer bits joins if its f1 loss ≤ `MDL_GAIN_PER_BIT × bits saved`. `mdl=False` (control)
accepts any f1 gain. Terms on TRAIN: fit = f1; coherence = 1 if every necessary predicate matches in
≥ 1 true match; survival = share of screens passed so far; cross_epoch = share of TRAIN lab epochs
with a true match; independent = distinct source groups over true matches / true matches;
complexity = `complexity_cost / 64`; contradictions = true matches blocked by forbidden
observations / matched; visibility = share of matches with an incomplete step; fragility = 1 −
decision agreement under PRESERVING transforms when measured, else 0. **Bayesian competition
(§41) is the ORACLE posterior (D8.6); score and MDL are its baselines.** ~300 lines.

### D8.5 — Lineage DAG `[oracle]`

```python
# pocketsec/stage8/ecology/lineage.py
MAX_LINEAGE_NODES = 8192; MAX_LINEAGE_EDGES = 16384; MAX_LINEAGE_PARENTS = 4; MAX_WALK = 256
class NodeKind(StrEnum): RESIDUAL; HYPOTHESIS; EXPERIMENT; DISCOVERY; FORGE_CANDIDATE; STAGE6_CAPSULE
@dataclass(frozen=True, slots=True)
class LineageNode: node_id: str; kind: NodeKind; parents: tuple[str, ...]; detail_digest: str
class HypothesisLineageDAG:
    def __init__(self, *, max_nodes: int = MAX_LINEAGE_NODES, max_edges: int = MAX_LINEAGE_EDGES) -> None
    def add(self, node: LineageNode) -> bool      # refuses (counted) when full or a parent is unknown
    def has(self, node_id: str) -> bool
    def ancestors(self, node_id: str) -> tuple[str, ...]    # bounded by MAX_WALK
    def path_kinds(self, node_id: str) -> frozenset[NodeKind]
    def collect(self, keep: Iterable[str]) -> int  # removes nodes not ancestors of `keep`; explicit, counted
    def stats(self) -> Mapping[str, int]; def memory_bytes(self) -> int
```

The §33 chain `residual → H → H' → experiment → discovery → FORGE → Stage 6` is one node per step.
G8.8 asserts every package's `evidence_lineage` walks to a RESIDUAL root through HYPOTHESIS,
DISCOVERY and FORGE_CANDIDATE nodes. ~170 lines.

### D8.6 — Experiment Value Engine `[oracle]`

```python
# pocketsec/stage8/oracle/information_gain.py
LIKELIHOOD_NOISE = 0.05; PRIOR_VERSION = "uniform-v1"
@dataclass(frozen=True, slots=True)
class Posterior:
    hypothesis_ids: tuple[str, ...]; probabilities: tuple[float, ...]; prior_version: str = PRIOR_VERSION
def uniform_prior(hypothesis_ids: Sequence[str]) -> Posterior
def entropy_bits(posterior: Posterior) -> float
def expected_information_gain(posterior: Posterior, predictions: Mapping[str, tuple[int, ...]]) -> float
def update(posterior: Posterior, predictions: Mapping[str, tuple[int, ...]], observed: tuple[int | None, ...]) -> Posterior
```

Exact EIG over outcome classes: each hypothesis predicts a label vector for the design's episodes;
candidate outcomes are the distinct predicted vectors; `L(y | h) = Π (1 − ε if ŷ_h,i = y_i else ε)`
with ε = `LIKELIHOOD_NOISE`; `EIG = H(P) − Σ_y P(y) H(P | y)`. `None` in `observed` (label
unavailable) contributes no factor. Adversarially generated evidence is down-weighted by construction:
CHALLENGE episodes never enter a posterior. The posterior never overrides a hard gate: it orders and
prunes, and only the vault decides survival. ~150 lines.

### D8.6 — ORACLE planner `[oracle]`

```python
# pocketsec/stage8/oracle/planner.py
STOP_POSTERIOR = 0.95; STOP_EIG_PER_UNIT = 1e-4; PRUNE_POSTERIOR = 0.01; MAX_ORACLE_EXPERIMENTS = 16
class SelectionPolicy(StrEnum): EIG_PER_COST; EIG_ONLY; RANDOM; CHEAPEST
class StopReason(StrEnum): IDENTIFIED; OBSERVATIONALLY_EQUIVALENT; EIG_BELOW_COST; BUDGET; SAFETY;
    NO_EXPERIMENTS; TELEMETRY_FAILURE

@dataclass(frozen=True, slots=True)
class ExperimentDesign:
    design_id: str; experiment_class: ExperimentClass; transform: TransformSpec | None
    episode_ids: tuple[str, ...]      # ≤ max_counterfactual_worlds
    cost_units: int; privacy_cost: float; safety_risk: float

@dataclass(frozen=True, slots=True)
class ExperimentRecord:
    design: ExperimentDesign; eig_bits: float; observed: tuple[int | None, ...]
    posterior_after: Posterior; sandbox: SandboxDecision

@dataclass(frozen=True, slots=True)
class OracleReport:
    policy: SelectionPolicy; experiments: tuple[ExperimentRecord, ...]; stop: StopReason
    final_posterior: Posterior; leading: str | None; pruned: tuple[str, ...]
    work_units: int; lab_oracle_used: bool

class OraclePlanner:
    def __init__(self, *, sandbox: ResearchSandbox, lab: LabOracle | None, governor: ResearchGovernor,
                 policy: SelectionPolicy = SelectionPolicy.EIG_PER_COST, rng: random.Random) -> None
    def candidate_designs(self, hypotheses: Sequence[HypothesisGenome], pool: Sequence[Episode]) -> tuple[ExperimentDesign, ...]
    def run(self, hypotheses: Sequence[HypothesisGenome], pool: Sequence[Episode]) -> OracleReport
```

Designs: `HISTORICAL_REPLAY` over LAB_POOL strata (episodes matched by some but not all
hypotheses); `COUNTERFACTUAL_MUTATION` / `METAMORPHIC_TRANSFORM` / `TELEMETRY_DROPOUT` with each
`TransformKind` over those strata. Every design is authorised by `ResearchSandbox.decide` first.
Labels: a PRESERVING transform keeps the source label; UNKNOWN or DESTROYING needs `lab.label(...)`;
with `lab=None` (the **production default**: observation/replay only, architecture §3) those
designs are unavailable. `EIG_PER_COST` maximises `EIG / (cost_units + 1)`; `CHEAPEST` picks the
lowest cost; `RANDOM` picks uniformly. Stop (§43): leading posterior ≥ 0.95 → IDENTIFIED; every
remaining design predicts identical vectors for all survivors → OBSERVATIONALLY_EQUIVALENT; best
EIG per unit < 1e-4 → EIG_BELOW_COST; budget or `MAX_ORACLE_EXPERIMENTS` → BUDGET; only emulation
designs left → SAFETY; the cluster's `visibility_share` ≥ 0.5 → TELEMETRY_FAILURE (before any
experiment). Hypotheses with posterior < 0.01 are pruned (ledger `CHALLENGED_OUT`, reason
`oracle_posterior`). Active learning (replay strata) and active experimentation (transforms) are
separate `ExperimentClass` values and are reported separately (§40). ~290 lines.

### D8.7 — Counterfactual Laboratory `[labs]`

```python
# pocketsec/stage8/laboratory/counterfactual.py
TRANSFORM_VERSION = "stage8-lab-transforms.1.0.0"
class TransformKind(StrEnum): ACTOR_RENAME; TIMING_SHIFT; SENSOR_DROPOUT; PARENT_SUBSTITUTION;
    DESTINATION_CLASS_SWAP; EPOCH_CHANGE; DECOY_INSERTION; NECESSARY_STEP_DELETION; REORDER; ACTOR_SPLIT
class Semantics(StrEnum): PRESERVING; DESTROYING; UNKNOWN
TRANSFORM_SEMANTICS: Mapping[TransformKind, Semantics]
    # PRESERVING: ACTOR_RENAME, TIMING_SHIFT, PARENT_SUBSTITUTION, EPOCH_CHANGE, DECOY_INSERTION
    # DESTROYING (relative to the target predicate): NECESSARY_STEP_DELETION
    # UNKNOWN: SENSOR_DROPOUT, DESTINATION_CLASS_SWAP, REORDER, ACTOR_SPLIT

@dataclass(frozen=True, slots=True)
class TransformSpec:
    kind: TransformKind
    parameter: int                    # per-kind: permille probability, slot offset, bucket delta, decoy count
    target: StepPredicate | None      # for NECESSARY_STEP_DELETION / REORDER / ACTOR_SPLIT / DESTINATION_CLASS_SWAP

def restep(step: EncodedStep, **changes: Any) -> EncodedStep   # keeps features consistent with the masks
def apply_transform(episode: Episode, spec: TransformSpec, *, rng: random.Random) -> Episode | None
def counterfactual_set(episodes: Sequence[Episode], specs: Sequence[TransformSpec], *, rng: random.Random,
                       cap: int) -> tuple[Episode, ...]
```

Every result is `Split.CHALLENGE` with `label = source label` for PRESERVING and `None` otherwise;
`None` is returned when a transform does not apply (no target step). `restep` rewrites the one-hot
and mask groups through `GROUP_OFFSETS` (`relation_onehot`, `relation_family_onehot`,
`object_semantics`, `state_delta_raised`, `temporal`, `uncertainty`) so pooled-feature detectors see
the same change as mask detectors; a test re-derives each changed group. `SENSOR_DROPOUT` deletes
steps of one `RelationFamily` with the given probability and sets `observation_incomplete` on the
actor's remaining steps. `DECOY_INSERTION` inserts non-escalating steps copied from other episodes
under fresh actor slots, respecting `MAX_EPISODE_STEPS` (truncation flagged). Path substitution
(§17) is a *scenario* transform and lives in the corpus as the REPLICATION family split
(`/var/tmp`, `/dev/shm`, M0.7). ~260 lines.

### D8.7 — Metamorphic Laboratory `[labs]`

```python
# pocketsec/stage8/laboratory/metamorphic.py
class Expectation(StrEnum): INVARIANT; SUPPORT_FALLS
@dataclass(frozen=True, slots=True)
class MetamorphicRelation: relation_id: str; transform: TransformSpec; expectation: Expectation; tolerance: float
@dataclass(frozen=True, slots=True)
class MetamorphicResult:
    relation_id: str; episodes: int; applicable: int
    agreement: float | None           # INVARIANT: share of unchanged decisions
    support_before: int; support_after: int
    holds: bool | None                # None when applicable == 0 (never True on nothing)
DEFAULT_RELATIONS: tuple[MetamorphicRelation, ...]   # 5 INVARIANT (tolerance 0.02) + NECESSARY_STEP_DELETION SUPPORT_FALLS (0.5)
def run_metamorphic(decide: Callable[[Episode], bool], episodes: Sequence[Episode],
                    relations: Sequence[MetamorphicRelation], *, rng: random.Random,
                    governor: ResearchGovernor) -> tuple[MetamorphicResult, ...]
```

`decide` is any detector: a genome, a compiled representation, a baseline. ~150 lines.

### D8.8 — Benign Doppelgänger Engine `[falsification]`

```python
# pocketsec/stage8/doppelganger/engine.py
DOPPELGANGER_PER_FAMILY = 16
class DoppelgangerFamily(StrEnum): ADMIN_SCRIPT; SOFTWARE_UPDATE; BACKUP; PACKAGE_MANAGER;
    MONITORING_AGENT; DEVELOPER_TOOLING; ORCHESTRATION
class DoppelgangerSource(Protocol):
    def benign_alternatives(self, family: DoppelgangerFamily, *, count: int, seed: int) -> tuple[Episode, ...]: ...
@dataclass(frozen=True, slots=True)
class BenignDoppelganger:
    hypothesis_id: str; family: DoppelgangerFamily
    episodes_tested: int; matched: int; matched_share: float
    partial_matches: int              # match ≥ one necessary predicate but not the mechanism
    strongest_episode_ids: tuple[str, ...]   # ≤ 4: full matches first, then partial
class DoppelgangerEngine:
    def __init__(self, source: DoppelgangerSource, *, governor: ResearchGovernor,
                 per_family: int = DOPPELGANGER_PER_FAMILY) -> None
    def challenge(self, genome: HypothesisGenome) -> tuple[BenignDoppelganger, ...]   # every family
    def separates(self, results: Sequence[BenignDoppelganger], *, threshold: float) -> bool
```

The source is `labs/discovery_corpus.py` (§4.19): every family is label 0 by lab construction.
`MONITORING_AGENT` (≥ 4 external connects by one actor) exists **only** in the doppelgänger source,
not in the natural corpus. It is the strongest benign alternative to planted mechanism PM2, which the
grammar cannot separate from it (no actor properties). PM2 is therefore expected to be
`CHALLENGED_OUT` with reason `doppelganger:MONITORING_AGENT`: that is the engine working, not
failing (§4 architecture §19). BENIGN-direction genomes are not challenged (they are the benign
explanations). ~170 lines.

### D8.9 — Adversarial Challenger `[falsification]`

```python
# pocketsec/stage8/challenger/adversarial.py
CHALLENGE_PER_KIND = 32
class ChallengeKind(StrEnum): FEATURE_OBFUSCATION; TIMING_SHIFT; LOTL_SUBSTITUTION; EVENT_FLOOD;
    RARE_BENIGN_MIMICRY; PARTIAL_TELEMETRY_LOSS; POISONED_LABELS; SHORTCUT_TRIGGER
@dataclass(frozen=True, slots=True)
class AdversarialChallenge:
    detector_id: str; kind: ChallengeKind; episodes: int; positives: int
    recall_retained: float | None     # recall on challenged positives / recall on their sources
    false_positive_rate: float | None # on challenged negatives
def build_challenge_corpus(episodes: Sequence[Episode], *, kinds: Sequence[ChallengeKind],
                           rng: random.Random, governor: ResearchGovernor,
                           cap: int = CHALLENGE_PER_KIND) -> Mapping[ChallengeKind, tuple[Episode, ...]]
def challenge(detector_id: str, decide: Callable[[Episode], bool],
              corpus: Mapping[ChallengeKind, tuple[Episode, ...]]) -> tuple[AdversarialChallenge, ...]
def poisoned_labels(train: Sequence[Episode], *, share: float, rng: random.Random) -> tuple[Episode, ...]
```

Built from LAB_POOL with laboratory transforms only: FEATURE_OBFUSCATION clears one
non-necessary property bit on matched steps; TIMING_SHIFT = `TIMING_SHIFT` transform;
LOTL_SUBSTITUTION rewrites a `TEMP_LOCATION` execute to `SYSTEM_BINARY|ROOT_OWNED`;
EVENT_FLOOD = `DECOY_INSERTION` to the step cap; RARE_BENIGN_MIMICRY inserts one necessary-predicate
step into benign episodes under a fresh actor; PARTIAL_TELEMETRY_LOSS = `SENSOR_DROPOUT` at 500 ‰;
SHORTCUT_TRIGGER inserts the corpus's trap step into benign episodes. Challenged positives stay
label 1 and challenged negatives label 0: the question is whether the defence still holds, not
whether the variant is still the planted mechanism. `POISONED_LABELS` is a training-time challenge
run by `labs/discovery_run.py`. **The output is a robustness corpus of synthetic `Episode` values,
never a deployable procedure.** ~200 lines.

### D8.10 — Causal Identifiability Gate `[falsification]`

```python
# pocketsec/stage8/identifiability/gate.py
MIN_DISTINGUISHING_EPISODES = 3; MIN_EVIDENCE_EPISODES = 10
@dataclass(frozen=True, slots=True)
class IdentifiabilityVerdict:
    hypothesis_id: str; klass: IdentifiabilityClass
    members: tuple[str, ...]          # the equivalence class (≤ MAX_COMPETITORS), candidate first
    distinguishing_episodes: int
    reason: str                       # IDENTIFIED | NO_DISTINGUISHING_EPISODE | ONLY_UNDER_INTERVENTION |
                                      # ONLY_UNDER_INCOMPLETE_OBSERVATION | RIVAL_PREFERRED | INSUFFICIENT_EVIDENCE
    verdict: Verdict | None           # None iff IDENTIFIED; else UNIDENTIFIABLE or INSUFFICIENT_EVIDENCE
class IdentifiabilityGate:
    def __init__(self, *, interventions_permitted: bool, min_distinguishing: int = MIN_DISTINGUISHING_EPISODES,
                 min_evidence: int = MIN_EVIDENCE_EPISODES) -> None
    def assess(self, candidate: HypothesisGenome, rivals: Sequence[HypothesisGenome],
               observed: Sequence[Episode], interventions: Sequence[Episode] = ()) -> IdentifiabilityVerdict
```

Rules in order: fewer than `min_evidence` labelled matched episodes → UNIDENTIFIABLE /
`INSUFFICIENT_EVIDENCE` / `Verdict.INSUFFICIENT_EVIDENCE`; a rival with zero labelled
distinguishing episodes in `observed ∪ permitted interventions` → EQUIVALENCE_CLASS; distinguishing
episodes exist only in `interventions` while `interventions_permitted=False` →
UNIDENTIFIABLE / `ONLY_UNDER_INTERVENTION`; only in episodes with an incomplete step →
UNIDENTIFIABLE / `ONLY_UNDER_INCOMPLETE_OBSERVATION`; a rival agrees with the labels strictly more
often on the distinguishing episodes → UNIDENTIFIABLE / `RIVAL_PREFERRED`; else IDENTIFIED when
distinguishing ≥ `min_distinguishing`. **The worked case the gate must get right:** PM1 is
`PRECEDES(a, b)`; in the natural corpus `a` always precedes `b`, so `CO_OCCURS(a, b)` has zero
distinguishing episodes → EQUIVALENCE_CLASS; with `REORDER` interventions and the lab oracle it
becomes IDENTIFIED. Stage 8 never invents certainty its sensors cannot supply. ~170 lines.

### D8.11 — Theory Ledger `[integrity]`

```python
# pocketsec/stage8/ledger/theory.py
MAX_LEDGER_ENTRIES = 16384; MAX_THEORIES = 2048
GENESIS_DIGEST = "sha256:" + "0" * 64
class TheoryStatus(StrEnum): PROPOSED; CHALLENGED_OUT; REGISTERED; SURVIVED; FALSIFIED; REPRODUCED;
    NOT_REPRODUCED; INSUFFICIENT_EVIDENCE; FOSSILIZED
class LedgerEventKind(StrEnum): BIRTH; CHALLENGE_RESULT; PREREGISTER; TEST_RESULT; STATUS; IDENTIFIABILITY; CHECKPOINT
class LedgerError(ContractError): ...

@dataclass(frozen=True, slots=True)
class PreRegistration:
    registration_id: str             # "reg-" + 24 hex, derived
    hypothesis_id: str; genome_digest: str
    split: Split                     # HOLDOUT or REPLICATION
    split_digest: str                # the vault's split_digest(), known before evaluation
    batch_size: int                  # m, the Bonferroni family
    alpha: float; prediction: Prediction

@dataclass(frozen=True, slots=True)
class TestOutcome:
    registration_id: str; hypothesis_id: str; split: Split
    counts: FitCounts; p_value: float | None
    survived: bool; reasons: tuple[str, ...]      # every refutation rule that fired

@dataclass(frozen=True, slots=True)
class LedgerEntry:
    sequence: int; kind: LedgerEventKind; hypothesis_id: str
    payload: Mapping[str, Any]; previous_digest: str; entry_digest: str

@dataclass(frozen=True, slots=True)
class TheoryRecord:                  # §22, a view
    genome: HypothesisGenome; status: TheoryStatus
    evidence_for: int; evidence_against: int          # true / false matches over tested splits
    experiments: tuple[str, ...]; predictions: tuple[Prediction, ...]
    failed_predictions: tuple[str, ...]; counterexamples: tuple[str, ...]   # episode ids ≤ 8
    revisions: tuple[str, ...]       # child hypothesis ids
    resource_cost: int               # work units charged against this id
    identifiability: IdentifiabilityClass | None
    reproducibility: ReproducibilityStatus | None

class TheoryLedger:
    def __init__(self, *, capacity: int = MAX_LEDGER_ENTRIES, max_theories: int = MAX_THEORIES,
                 negative_memory: NegativeResultMemory | None = None) -> None
    def record_birth(self, genome: HypothesisGenome) -> LedgerEntry
    def record_challenge(self, hypothesis_id: str, *, kind: FalsifierKind, passed: bool,
                         statistic: float | None) -> LedgerEntry    # only a kind the genome declared
    def preregister(self, registration: PreRegistration) -> LedgerEntry
    def record_result(self, outcome: TestOutcome) -> LedgerEntry
    def record_identifiability(self, verdict: IdentifiabilityVerdict) -> LedgerEntry
    def set_status(self, hypothesis_id: str, status: TheoryStatus, *, reason: str) -> LedgerEntry
    def status(self, hypothesis_id: str) -> TheoryStatus
    def genome(self, hypothesis_id: str) -> HypothesisGenome
    def record(self, hypothesis_id: str) -> TheoryRecord
    def registered_before_tested(self, hypothesis_id: str) -> bool
    def entries(self) -> tuple[LedgerEntry, ...]
    def verify_chain(self) -> tuple[str, ...]
    def stats(self) -> Mapping[str, int]; def memory_bytes(self) -> int
```

**Refusals, each a `LedgerError` and a counter:** a duplicate birth; any event for an unborn id; a
`CHALLENGE_RESULT` for a falsifier the genome did not declare; `preregister` when the genome digest
differs, when a registration or result already exists for (id, split), or when the status is not
PROPOSED (HOLDOUT) / SURVIVED (REPLICATION); `record_result` without a matching PREREGISTER, or a
second result for one registration; an illegal status transition (legal: PROPOSED → CHALLENGED_OUT |
REGISTERED | FOSSILIZED; REGISTERED → SURVIVED | FALSIFIED; SURVIVED → REPRODUCED | NOT_REPRODUCED |
INSUFFICIENT_EVIDENCE). There is **no update or delete method** (Stage 0 registry precedent).

**Bounded, with recorded eviction.** The chain is a window of at most `capacity` entries. When
full, the oldest entries are dropped from the head and a `CHECKPOINT` entry is appended carrying
`{dropped, first_sequence, last_sequence, anchor_digest}` where `anchor_digest` is the dropped tail's
`entry_digest`; `verify_chain` re-derives every retained digest from the anchor. `TheoryRecord`s
are kept outside the window for at most `max_theories` ids: when full, terminal non-REPRODUCED
records fold oldest-first into `NegativeResultMemory`; REPRODUCED and open (PROPOSED, REGISTERED,
SURVIVED) records are never folded; if nothing can fold, `record_birth` is refused
(`births_refused_full`). ~330 lines.

### D8.11 — Negative-result memory `[integrity]`

```python
# pocketsec/stage8/ledger/negative_results.py
MAX_NEGATIVE_RESULTS = 1024; MAX_COUNTEREXAMPLES = 4
@dataclass(frozen=True, slots=True)
class NegativeResult:
    mechanism_digest: str; hypothesis_id: str; status: TheoryStatus
    refutation: FalsifierKind | None; reason: str      # fixed codes
    counterexample_ids: tuple[str, ...]; recorded_sequence: int
class NegativeResultMemory:
    def __init__(self, *, capacity: int = MAX_NEGATIVE_RESULTS) -> None
    def remember(self, result: NegativeResult) -> None       # full → evict least recently hit, counted
    def is_dead_end(self, mechanism: Mechanism) -> bool      # exact digest; a hit is counted (firing)
    def results(self) -> tuple[NegativeResult, ...]
    def stats(self) -> Mapping[str, int]; def memory_bytes(self) -> int
```

~120 lines.

### D8.18 — Safety Sandbox `[integrity]`

```python
# pocketsec/stage8/sandbox/boundary.py
MAX_SANDBOX_AUDIT = 4096
EMULATOR_AVAILABLE: bool = False          # there is no emulator in this repository (ADR-0075)
class SandboxOutcome(StrEnum): ALLOWED; REFUSED_NO_CLEARANCE; REFUSED_NO_EMULATOR; REFUSED_EXPIRED; REFUSED_SCOPE
@dataclass(frozen=True, slots=True)
class LabClearance:
    clearance_id: str; experiment_class: ExperimentClass; scope_digest: str
    expires_sequence: int; issued_by: str
@dataclass(frozen=True, slots=True)
class SandboxDecision:
    experiment_class: ExperimentClass; outcome: SandboxOutcome; sequence: int; reason: str
class ResearchSandbox:
    def __init__(self, *, audit_capacity: int = MAX_SANDBOX_AUDIT) -> None
    def decide(self, experiment_class: ExperimentClass, *, clearance: LabClearance | None,
               scope_digest: str, sequence: int) -> SandboxDecision
    def audit(self) -> tuple[SandboxDecision, ...]; def stats(self) -> Mapping[str, int]
```

Production-safe classes (`SAFE_EXPERIMENT_CLASSES`) are ALLOWED without clearance: they only read
recorded or synthetic episodes. `ISOLATED_EMULATION` needs a clearance for that class, that scope,
not expired, **and** an emulator: with `EMULATOR_AVAILABLE = False` the answer is always
`REFUSED_NO_EMULATOR`, even with valid clearance. Every decision is audited (bounded ring, evictions
counted). "All active emulation is isolated and authorised" is therefore true because none exists;
the gate checks the refusal path fires rather than accepting the vacuous truth (G8.3). ~140 lines.

### D8.18 — Research Integrity Plane `[integrity]`

```python
# pocketsec/stage8/sandbox/integrity.py
ALPHA = 0.05; MAX_HOLDOUT_BATCHES_PER_SPLIT = 1; MAX_HOLDOUT_EPISODES = 2048; MAX_VAULT_LOG = 1024
def content_digest(payload: Any) -> str                      # sha256: over canonical JSON
def split_digest(episodes: Sequence[Episode]) -> str         # over sorted episode ids
@dataclass(frozen=True, slots=True)
class LeakageFinding: episode_id: str; splits: tuple[Split, ...]
def detect_split_leakage(splits: Mapping[Split, Sequence[Episode]]) -> tuple[LeakageFinding, ...]
def sign_record(payload: Mapping[str, Any], *, key: bytes) -> str       # HMAC-SHA256: integrity, not identity
def verify_record(payload: Mapping[str, Any], signature: str, *, key: bytes) -> bool
def binomial_upper_tail(k: int, n: int, p: float) -> float # exact, math.comb; n ≤ MAX_HOLDOUT_EPISODES
@dataclass(frozen=True, slots=True)
class BatchTicket: ticket_id: str; split: Split; registration_ids: tuple[str, ...]; batch_size: int
@dataclass(frozen=True, slots=True)
class VaultAccess: sequence: int; ticket_id: str; outcomes: int; refused: str | None
class HoldoutVault:
    def __init__(self, episodes: Sequence[Episode], *, split: Split, ledger: TheoryLedger,
                 max_batches: int = MAX_HOLDOUT_BATCHES_PER_SPLIT, alpha: float = ALPHA) -> None
    def size(self) -> int; def split_digest(self) -> str
    def seal_batch(self, registrations: Sequence[PreRegistration]) -> BatchTicket
    def evaluate(self, ticket: BatchTicket) -> tuple[TestOutcome, ...]
    def access_log(self) -> tuple[VaultAccess, ...]; def stats(self) -> Mapping[str, int]
```

The vault holds its episodes in one private attribute named **`_vault_episodes`** and **exposes no
method that returns an episode, a step or a label** (boundary rule 14). Construction refuses a
split other than HOLDOUT/REPLICATION, a mixed-split input, unlabelled episodes and more than
`MAX_HOLDOUT_EPISODES`. `seal_batch` refuses: a registration not in the ledger as PREREGISTER for
this split and this `split_digest`; `batch_size` ≠ the batch length; more than
`max_registrations_per_batch`; a second batch after `max_batches`. `evaluate` runs once per ticket:
per registration it computes `FitCounts` with `genome.decides` (direction-aware), the exact
binomial p-value at the split's base rate, applies every refutation rule the genome declared for
that split with `alpha / batch_size`, writes each `TestOutcome` through `ledger.record_result`, and
sets SURVIVED/FALSIFIED. Base rate and counts never leave the vault except inside `TestOutcome`s of
registered hypotheses. §34's list binds: content addressing (`content_digest`, ids), versioned
transforms (`TRANSFORM_VERSION`, `GRAMMAR_VERSION`, `GENOME_VERSION`), separated evaluation data
(vault), leakage detection, signed records (`sign_record` over each package's canonical bytes with
a per-run key derived from the seed: local integrity only, ADR-0064 precedent), untrusted tool
output (`ExternalProposalGenerator`), benchmark protection (vault), seeds and environment manifest
(`SeedSet`, `EnvironmentFingerprint.capture` recorded by the run). ~280 lines.

### D8.12 — Reproducibility Gate `[falsification]`

```python
# pocketsec/stage8/reproducibility/gate.py
IMBALANCE_RATIO = 20; IMBALANCE_MIN_PRECISION = 0.5; INDEPENDENT_FP_MAX = 0.01
@dataclass(frozen=True, slots=True)
class ReproducibilityVerdict:
    hypothesis_id: str; record: ReproducibilityRecord
    invariance: tuple[MetamorphicResult, ...]
    telemetry_requirements: tuple[str, ...]      # feature_names() slots the mechanism's predicates read
    failing_contexts: tuple[FailureCondition, ...]
class ReproducibilityGate:
    def __init__(self, *, vault: HoldoutVault, ledger: TheoryLedger, independent: Sequence[Episode],
                 lab_pool: Sequence[Episode], governor: ResearchGovernor, rng: random.Random) -> None
    def run(self, survivors: Sequence[HypothesisGenome], *,
            failing_contexts: Mapping[str, tuple[FailureCondition, ...]]) -> tuple[ReproducibilityVerdict, ...]
```

All survivors are preregistered on REPLICATION in **one** batch (m = number of survivors) and
evaluated once. REPRODUCED iff: the REPLICATION outcome survived; every `INVARIANT` relation holds
on LAB_POOL and `NECESSARY_STEP_DELETION` shows `SUPPORT_FALLS`; imbalance precision
`TPR·π / (TPR·π + FPR'·(1−π))` with π = 1/(1 + 20) and `FPR' = (fp + 0.5)/(negatives + 1)` ≥ 0.5;
matched share of INDEPENDENT benign episodes ≤ 0.01. `independent_positives_available` is False for
every planted mechanism (Stage 1 corpora do not contain them) and is reported. Fewer than
`MIN_EVIDENCE_EPISODES` REPLICATION true matches → INSUFFICIENT_EVIDENCE. The failing contexts
(challenger, doppelgänger, dropout) are documented in the verdict whether or not it passes (§24).
~200 lines.

### D8.13 — Novelty / Prior-Art Audit `[falsification]`

```python
# pocketsec/stage8/novelty/prior_art_audit.py
@dataclass(frozen=True, slots=True)
class KnownMechanism: known_id: str; mechanism: Mechanism; source: str
@dataclass(frozen=True, slots=True)
class NoveltyAudit:
    hypothesis_id: str; classification: NoveltyClass
    matched_known: tuple[str, ...]; external_review: ReviewStatus   # NOT_REVIEWED this wave
    novelty_claim_permitted: bool                                     # False this wave
def stage1_known_mechanisms() -> tuple[KnownMechanism, ...]
def known_library(*, stage6_motifs: Sequence[Sequence[MotifStep]] = (), stage7_seeds: Sequence[Mechanism] = (),
                  validated: Sequence[HypothesisGenome] = ()) -> tuple[KnownMechanism, ...]
def audit(genome: HypothesisGenome, library: Sequence[KnownMechanism], *, prior_art: PriorArtLedger,
          bound_hypothesis: str = ABLATION_HYPOTHESIS) -> NoveltyAudit
```

`stage1_known_mechanisms` renders each `ATTACK_*` chain of `stage1/labs/corpus.py` through a fresh
`Stage1Pipeline` and emits, for each consecutive pair of escalating steps of one actor, the
`PRECEDES` of their maximal predicates, and a SINGLE for each escalating step: computed, not
hand-written (`known_id = "stage1:ATTACK_EXFIL"` etc.). Predicate `P` covers `Q` when the relations
are equal and each of `Q`'s masks is a subset of `P`'s. Classification: KNOWN if one library
entry has the same relation kind and step-wise coverage in either direction; KNOWN_COMBINATION if
every step is covered by some entry but no single entry; CONTEXT_EXTENSION if at least one step is
covered; else POTENTIALLY_NOVEL. **Novelty is never claimed**: `novelty_claim_permitted` is True
only if the classification is POTENTIALLY_NOVEL **and** `prior_art.entries[bound].novelty_claim_permitted`
(literature and patent REVIEWED with citations, `stage0/prior_art.py:41`). Every entry is
NOT_REVIEWED today, so it is False. ATT&CK, Sigma, YARA and literature indexes are **not built**
(no offline index, no network): `known_technique_mappings` holds local library ids only.
**Rediscovery control:** planted PM3 is ATTACK_EXFIL's credential-read → egress pair and must come
out KNOWN (G8.6). ~180 lines.

### D8.14 — FORGE representations and compiler `[forge]`

```python
# pocketsec/stage8/forge/representations.py
MAX_FSM_STATES = 8; STUMP_TREE_MAX_DEPTH = 2
class Detector(Protocol):
    kind: RepresentationKind
    def decide(self, episode: Episode, meter: WorkMeter | None = None) -> bool: ...
    def score(self, episode: Episode, meter: WorkMeter | None = None) -> float: ...
    def artifact(self) -> Mapping[str, Any]: ...        # plain JSON, the only thing that ships
    def interpretability(self) -> int: ...
class TypedRuleDetector: ...     # genome.decides; the reference; artifact = the full genome canonical JSON
class MotifDetector: ...         # tuple[MotifStep, ...] run by stage6 match_motif
class FsmDetector: ...           # per-actor state table; SINGLE/REPEATED/PRECEDES/CO_OCCURS/WITHOUT + forbidden sink
class ThresholdDetector: ...     # one feature, max over steps, >= t
class LogisticDetector: ...      # Stage 1 LogisticProbe over max-pooled FEATURE_WIDTH features, 0.5 cut
class PrototypeDetector: ...     # two centroids over pooled features, nearest by L1
class StumpTreeDetector: ...     # depth ≤ 2, pooled features binarised at 0.5, greedy Gini, stdlib
def pooled_features(episode: Episode) -> tuple[float, ...]     # per-slot max over steps (order-free)

# pocketsec/stage8/forge/compiler.py
@dataclass(frozen=True, slots=True)
class CompiledDetector:
    kind: RepresentationKind; expressible: bool; refusal: str | None
    artifact: Mapping[str, Any] | None; artifact_bytes: int | None
def can_express(genome: HypothesisGenome, kind: RepresentationKind) -> tuple[bool, str | None]
def compile_all(genome: HypothesisGenome, train: Sequence[Episode], *, governor: ResearchGovernor,
                kinds: Sequence[RepresentationKind] = tuple(RepresentationKind)) -> tuple[CompiledDetector, ...]
def load_detector(compiled: CompiledDetector) -> Detector   # from plain data only; round-trip tested
```

**Expressibility is checked before compiling (lesson 2)**, and each refusal is a
`RepresentationMeasurement` with `expressible=False` and a code: `MOTIF` expresses SINGLE-NONE and
PRECEDES only, with no forbidden observations (`MOTIF_CANNOT_EXPRESS_{CO_OCCURS,WITHOUT,REPEATED,
FORBIDDEN_OBSERVATION}`); `FSM` expresses every grammar member while the per-actor state count
(`repeat_min + 1`, or 3 for a pair, plus a sink) ≤ 8 (`FSM_STATE_EXPLOSION`); THRESHOLD, LOGISTIC,
PROTOTYPE and STUMP_TREE are always syntactically compilable and are **students of the theory**:
fitted on TRAIN to the genome's decisions, not to the labels (§30: hard labels are used only to
measure them). A student whose TRAIN targets are single-class is refused `NO_BOTH_CLASSES`.
`TYPED_RULE` is the reference and always compiles. **Not built (ADR-0072):** `KNOWLEDGE_CELL`
(Stage 3's `CellISA` is single-frame and straight-line; compiling discovered computation to it is
Stage 9's seam), tiny MLP/1D-CNN/GRU/transformer (no research package, ADR-0070), INT8 and ONNX
export. ~400 lines across both modules.

### D8.15 — Representation Tournament and Discovery Compression Ratio `[forge]`

```python
# pocketsec/stage8/forge/tournament.py
FORGE_RECALL_TOLERANCE = 0.02; FORGE_PRECISION_TOLERANCE = 0.02; FORGE_FPR_TOLERANCE = 0.0
FORGE_AGREEMENT_MIN = 0.98; ENDPOINT_ARTIFACT_MAX_BYTES = 65536
STAGE8_ENDPOINT_INCREMENTAL_CEILING_BYTES = 20 * 1024 * 1024
def run_tournament(genome: HypothesisGenome, compiled: Sequence[CompiledDetector], *,
                   measure_on: Sequence[Episode], challenge: Mapping[ChallengeKind, tuple[Episode, ...]],
                   discovery_work_units: int, research_state_bytes: int,
                   governor: ResearchGovernor) -> TournamentResult
def reselect(result: TournamentResult) -> tuple[RepresentationKind | None, tuple[RepresentationKind, ...]]
def discovery_compression_ratio(discovery_work_units: int, deployed_units_per_event: float | None) -> float | None
@dataclass(frozen=True, slots=True)
class EndpointFootprint:
    detectors: int; events: int; incremental_rss_bytes: int | None   # sampled peak − start, floored at 0
    peak_sampled_rss_bytes: int | None; within_ceiling: bool | None   # None = UNMEASURED
    work_units_per_event: float | None; wall_seconds: float; loadavg: tuple[float, float, float]
def measure_endpoint_footprint(packages: Sequence[DiscoveryPackageV1], episodes: Sequence[Episode]) -> EndpointFootprint
```

Measurement on REPLICATION (hard labels): precision, recall, FPR, PR-AUC (`average_precision` over
`score`), decision agreement with TYPED_RULE, work units per event (a private `WorkMeter` per
detector), artifact bytes, within-run wall ratio to TYPED_RULE with loadavg, robustness = minimum
recall retained over challenge kinds, interpretability. **Selection, a pure function of the recorded
measurements** (`reselect`): eligible = expressible, every security field non-None, recall ≥ ref −
0.02, precision ≥ ref − 0.02, FPR ≤ ref + 0.0, agreement ≥ 0.98, artifact ≤ 64 KiB; **costs less** =
no worse on both (work units per event, artifact bytes) and strictly better on one, against
TYPED_RULE; the Pareto front over eligible ∧ costs-less on (work units per event, artifact bytes,
−robustness); selected = front minimum by (work units per event, artifact bytes, interpretability,
enum order). **No eligible entrant → `selected=None`, `deployable=False`, the reasons listed.** The
most sophisticated representation does not win automatically; wall time is never read.
`knowledge_bytes_saved` = `research_state_bytes` (genome + the theory's ledger entries + its
experiment records, canonical JSON) − selected artifact bytes. The §85 conservation checks run per
entrant (nuisance invariance, necessary-event removal, doppelgänger separation where TYPED_RULE
separates) and their failures become failure conditions. `measure_endpoint_footprint` loads every
selected artifact with `load_detector` inside `ResourceSampler` and runs it over the episodes: the
endpoint-side figure of G8.11. ~300 lines.

### D8.17 — Stage 6 adapter: the one door `[forge]`

```python
# pocketsec/stage8/adapters/stage6.py
MAX_CAPSULES_PER_PACKAGE = 8; MAX_ADAPTER_RECEIPTS = 1024
STAGE8_SOURCE_ID = "stage8-prometheus"
@dataclass(frozen=True, slots=True)
class AdapterReceipt:
    package_id: str; capsule_ids: tuple[str, ...]; verdict_ids: tuple[str, ...]
    stage6_buckets: tuple[str, ...]           # QuarantineBucket values, verbatim, never reinterpreted
    predicted_provenance_scores: tuple[float, ...]
    trusted_candidates: int                   # counted, never acted on
class Stage6Adapter:
    def __init__(self, *, gateway: QuarantineGateway, epoch: Epoch, run_id: str, host_id: str,
                 synthetic: bool, capacity: int = MAX_ADAPTER_RECEIPTS) -> None
    def hand_over(self, package: DiscoveryPackageV1, *, evidence: Mapping[str, ScenarioResult],
                  sequence: int) -> AdapterReceipt
    def created(self) -> int; def admitted(self) -> int
    def receipts(self) -> tuple[AdapterReceipt, ...]; def buckets(self) -> Mapping[str, int]; def stats(self) -> Mapping[str, int]
```

`hand_over` refuses (`ContractError`, counted) a package with `verify_package` problems, a
reproducibility status other than REPRODUCED, or an `evidence_episode_ids` entry absent from
`evidence`. For each evidence id (≤ 8) it re-derives the `Episode` from the `ScenarioResult` and
refuses on an id mismatch (lineage check), then builds **all** capsules before admitting any:
`capsule_from_scenario(result, epoch=…, provenance=SourceProvenance(DERIVED_INFERENCE,
source_id=STAGE8_SOURCE_ID, independence_group="stage8:" + run_id, label_origin=INFERENCE,
transformation_lineage=("stage8", package_id[:24]), host_id=host_id), sequence=…,
label=LabelAssertion(MALICIOUS or BENIGN per direction, INFERENCE, asserted_by=group))`, and
`reseal_capsule(..., contamination_flags=… | {SIMULATED_RECORD})` when `synthetic`. **One
independence group per run**: Stage 8 never mints groups to manufacture a quorum (that would be a
second promotion gate built by the sender, ADR-0067 option B). It then calls `gateway.admit` on each
and records Stage 6's verdict verbatim, with `score_provenance` beside it. `created() == admitted()`
is an invariant. **The mechanism, the compiled artifact and the tournament never enter Stage 6.**
~200 lines.

### 4.19 — The discovery corpus `[labs]` (`labs/discovery_corpus.py`)

```python
DISCOVERY_CORPUS_VERSION = "stage8-discovery-v0.1.0"
class CorpusArm(StrEnum): PLANTED; NULL; DROPOUT
class Family(StrEnum): DROP_EXEC_EGRESS; REPEATED_EGRESS; CREDENTIAL_EGRESS; OFFSITE_BACKUP; BUILD_TMP_EXEC;
    SPLIT_ACTORS; UPDATE_FETCH; ADMIN_PRIVILEGED; ROUTINE
PLANTED_MECHANISMS: Mapping[Family, Mechanism]   # PM1, PM2, PM3 (below), built through parse_mechanism
TRAP_BEHAVIOUR = Behaviour("fork", {})
DEFAULT_COUNTS: Mapping[Split, int] = {TRAIN: 240, HOLDOUT: 240, REPLICATION: 240, LAB_POOL: 120, INDEPENDENT: 120}
@dataclass(frozen=True, slots=True)
class DiscoveryCorpus:
    arm: CorpusArm; seed: int; version: str
    splits: Mapping[Split, tuple[Episode, ...]]
    results: Mapping[str, ScenarioResult]         # episode_id → raw Stage 1 result (raw evidence, kept apart)
    trap_mechanism: Mechanism                     # SINGLE over the encoded fork step, derived at build time
    def episodes(self, split: Split) -> tuple[Episode, ...]
@dataclass(frozen=True, slots=True)
class PreconditionReport:
    phi_oracle_holdout_ap: float | None; best_single_step_holdout_f1: float | None
    planted_f1: tuple[tuple[str, float | None], ...]
    median_delta_phi: tuple[tuple[int, float], ...]; pooled_logistic_holdout_ap: float | None
    session_unique: bool; problems: tuple[str, ...]   # () only when P1–P5 hold; else DEGENERATE
def build_discovery_corpus(*, arm: CorpusArm, seed: int, counts: Mapping[Split, int] = DEFAULT_COUNTS) -> DiscoveryCorpus
def relabel_null(corpus: DiscoveryCorpus, *, label_seed: int) -> DiscoveryCorpus   # NULL arm: new labels, same content
def planted_label(steps: Sequence[EncodedStep]) -> int
class LabOracle:                                   # authorised synthetic-world ground truth; costed
    def __init__(self, *, governor: ResearchGovernor) -> None
    def label(self, episode: Episode) -> int       # planted_label(episode.steps); charges governor
class CorpusDoppelgangers:                         # implements DoppelgangerSource
    def benign_alternatives(self, family: DoppelgangerFamily, *, count: int, seed: int) -> tuple[Episode, ...]
def corpus_preconditions(corpus: DiscoveryCorpus) -> PreconditionReport
```

Families (Stage 1 operation vocabulary only; `pid`/`start_time` session-unique, each session on a
fresh `Stage1Pipeline(host_id=…)`):

| family | label | behaviours | TRAIN/HOLDOUT/LAB_POOL variant | REPLICATION variant (family split) |
|---|---|---|---|---|
| DROP_EXEC_EGRESS | 1 | write `T/.x`; execve `T/.x`; read `/home/u/documents/d.txt`; connect `E:443`; send | T = `/tmp/.cache`, E ∈ 203.0.113.0/24 | T ∈ {`/var/tmp`, `/dev/shm`}, E ∈ 198.51.100.0/24 |
| REPEATED_EGRESS | 1 | k × (connect `E:443`; send) | k ∈ {4, 5} | k ∈ {5, 6, 7} |
| CREDENTIAL_EGRESS | 1 | `ATTACK_EXFIL` verbatim (the rediscovery control) | — | — |
| OFFSITE_BACKUP | 0 | execve `/usr/bin/rsync`; read doc; connect `E:22`; send | E ∈ 203.0.113.0/24 | 198.51.100.0/24 |
| BUILD_TMP_EXEC | 0 | write `T/build/a.out`; execve same | T = `/tmp` | `/var/tmp` |
| SPLIT_ACTORS | 0 | pid p: write `T/x`, execve `T/x`; pid p+1: connect `E:443`, send | as M1 | as M1 |
| UPDATE_FETCH | 0 | execve `/usr/bin/apt`; k × (connect `E:443`; recv); write `/var/cache/apt/p.deb` | k ∈ {1, 2, 3} | k ∈ {1, 2, 3} |
| ADMIN_PRIVILEGED | 0 | `BENIGN_PRIVILEGED` | — | — |
| ROUTINE | 0 | one `BENIGN_PATTERNS` draw | — | — |

Mix per split: 0.12 each for DROP_EXEC_EGRESS, REPEATED_EGRESS, OFFSITE_BACKUP, BUILD_TMP_EXEC,
SPLIT_ACTORS, UPDATE_FETCH; 0.10 CREDENTIAL_EGRESS and ROUTINE; 0.08 ADMIN_PRIVILEGED (base rate
0.34). Families are assigned by cycling a seeded shuffle of exact counts, so every split holds every
family. Hosts: TRAIN `lab-h01…h04` epoch 0; HOLDOUT `lab-h05…h08` epoch 1; REPLICATION `lab-h09…h12`
epoch 2; LAB_POOL `lab-h13…h14` epoch 0. INDEPENDENT = label-0 sessions of Stage 1 `build_corpus`
(`split="train"`) and `build_hard_corpus`, rendered the same way.

Planted mechanisms: **PM1** `PRECEDES(EXECUTE+TEMP_LOCATION, CONNECT+EXTERNAL_ENDPOINT)`;
**PM2** `REPEATED(CONNECT+EXTERNAL_ENDPOINT, 4)`; **PM3** `PRECEDES(READ+CREDENTIAL,
CONNECT+EXTERNAL_ENDPOINT)`. **The trap:** in TRAIN every label-1 session is prefixed with
`TRAP_BEHAVIOUR` and no label-0 session is; in HOLDOUT, REPLICATION and LAB_POOL it is prefixed
independently with probability 0.5 in both classes. `SINGLE(SPAWN)` is therefore true on TRAIN by
construction (precision 1, recall 1) and false on held-out. **NULL arm:** the same content,
labels drawn Bernoulli(0.34) per session from `label_seed`, no trap; `relabel_null` redraws labels
without re-rendering, so 20 null seeds cost one render. **DROPOUT arm:** PLANTED with
`SENSOR_DROPOUT` (EXECUTION family, 1000 ‰) applied to half of the DROP_EXEC_EGRESS sessions in every
split (the S8X-04 telemetry-failure residual and the UNIDENTIFIABLE case of G8.4).

`MONITORING_AGENT` doppelgänger (source only, never the natural corpus): execve `/usr/bin/telegraf`;
k × (connect `E:443`; send), k ∈ {4, 5, 6}. Other `DoppelgangerFamily` → corpus family: ADMIN_SCRIPT
→ ADMIN_PRIVILEGED, SOFTWARE_UPDATE → UPDATE_FETCH, BACKUP → OFFSITE_BACKUP, PACKAGE_MANAGER → the
dpkg `BENIGN_PATTERNS` entry, DEVELOPER_TOOLING → BUILD_TMP_EXEC, ORCHESTRATION → SPLIT_ACTORS.

**Preconditions (tested, and checked by the gate before any figure is used; any failure makes the
dependent figures DEGENERATE):** P1 Φ-oracle HOLDOUT AP ≤ 0.85; P2 best exhaustive single-step
HOLDOUT F1 (selected on TRAIN, trap excluded) ≤ PM1's HOLDOUT F1 − 0.10; P3 each planted mechanism
matches every session of its family and no label-0 session in every split, and `planted_label`
equals the family label for every session; P4 session-unique identities and non-zero median ΔΦ per
class (integration plan §5.4); P5 the pooled order-free LOGISTIC HOLDOUT AP < 0.95 (reported; the
SPLIT_ACTORS family is its ceiling). ~450 lines.

### D8.19 — The experiment catalogue `[experiments]` (`labs/eighty_experiments.py`)

```python
class CatalogueStatus(StrEnum): MEASURED_IN_GATE; MEASURED_IN_CLI; NOT_BUILT; BLOCKED
@dataclass(frozen=True, slots=True)
class CatalogueRow:
    experiment_id: str               # "S8X-001" … "S8X-128"
    title: str                       # the architecture's §52/§111 title, verbatim
    deliverable: str                 # "D8.NN" or "AION"
    status: CatalogueStatus
    runner: str | None               # "pocketsec.stage8.<module>:<qualname>", resolvable
    reason: str                      # required unless MEASURED_*
CATALOGUE: tuple[CatalogueRow, ...]  # exactly 128 rows
def catalogue_problems() -> tuple[str, ...]   # () is the only pass
```

Status, fixed by this contract:

| rows | status |
|---|---|
| 001–007, 009–043, 048, 050–054, 056, 059–062, 064, 065, 067, 069–073, 079, 080 | MEASURED (gate or CLI; the runner names the function) |
| 008 LLM generator | NOT_BUILT — no LLM; `ExternalProposalGenerator` is the seam (measured as 053) |
| 044–047 PC/FCI/GES/NOTEARS | NOT_BUILT — no offline causal-discovery library; a stdlib PC is out of scope (§9) |
| 049 CALDERA lab | NOT_BUILT — no emulator, no network (ADR-0075) |
| 055 teacher self-confirmation | NOT_BUILT — no teacher (§30 distillation from a large model is not built) |
| 057 ATT&CK mapping, 058 Sigma/YARA overlap | NOT_BUILT — no offline index (D8.13) |
| 063 FORGE Knowledge Cell, 066 tiny neural, 068 INT8 export | NOT_BUILT (ADR-0072, ADR-0070) |
| 074 Shadow Mind, 075 Conservation Gate rejection, 076 canary rollback | BLOCKED — B8-1: nothing reaches TRUSTED_CANDIDATE, and Stage 8 may not call those Stage 6 components |
| 077 Stage 7 antibody export, 078 distributed residual discovery | NOT_BUILT (D8.17) |
| 081–128 AION | NOT_BUILT (ADR-0070) except **114** semantic conservation tests, **119** open-world unknown, **125** proof-carrying package (engineering sense): MEASURED |

`catalogue_problems` reports: a missing or duplicate id; a MEASURED row whose runner does not
resolve; a NOT_BUILT/BLOCKED row with an empty reason; a title that is not the architecture's.
~300 lines.

### D8.20 — the loop, baselines and endurance `[experiments]`

```python
# pocketsec/stage8/labs/discovery_run.py
@dataclass(frozen=True, slots=True)
class RunConfig:
    arm: CorpusArm; seed: int; budget: ResearchBudget = ResearchBudget()
    generators: tuple[GeneratorKind, ...] = PROMETHEUS_GENERATORS   # or (RANDOM_BASELINE,) / (EXHAUSTIVE_SINGLE_BASELINE,)
    diversity: bool = True; mdl: bool = True; score_mode: ScoreMode = ScoreMode.FULL
    priority_mode: PriorityMode = PriorityMode.FULL; doppelganger_screen: bool = True
    oracle_policy: SelectionPolicy | None = SelectionPolicy.EIG_PER_COST   # None = ORACLE off
    use_lab_oracle: bool = False          # production default: replay only
    negative_memory: bool = True
    holdout_discipline: bool = True       # False = NAIVE control: select on TRAIN, no vault
    bonferroni: bool = True
    external_texts: tuple[str, ...] = (); stage7_capsules: tuple[KnowledgeCapsuleV1, ...] = ()
@dataclass(frozen=True, slots=True)
class TrapOutcome: generated: bool; registered: bool; refuted: bool; hypothesis_id: str | None   # "refuted", never "killed" (T5)
@dataclass(frozen=True, slots=True)
class ComponentFiring: component: str; firings: int; outcome_changes: int
@dataclass(frozen=True, slots=True)
class DiscoveryRunReport:
    config: RunConfig; residual_total: int; residual_explained: int; clusters: int
    generation: tuple[GenerationReport, ...]; evolution: tuple[EvolutionReport, ...]
    oracle: tuple[OracleReport, ...]
    births: int; challenged_out: int; registered: int; survived: tuple[str, ...]; falsified: int
    reproduced: tuple[str, ...]; identifiability: tuple[IdentifiabilityVerdict, ...]
    novelty: tuple[NoveltyAudit, ...]; packages: tuple[DiscoveryPackageV1, ...]
    receipts: tuple[AdapterReceipt, ...]
    planted_recovered: tuple[tuple[str, bool], ...]   # family → a REPRODUCED package agrees ≥ 0.98 with the planted mechanism on REPLICATION
    false_reproduced: int                              # REPRODUCED packages matching no planted mechanism
    trap: TrapOutcome; firings: tuple[ComponentFiring, ...]; governor: GovernorReport
    ledger_problems: tuple[str, ...]; wall_seconds: float; loadavg: tuple[float, float, float]
    synthetic_data: bool
PROMETHEUS_GENERATORS: tuple[GeneratorKind, ...]   # SYMBOLIC_ENUMERATOR, RESIDUAL_MOTIF, ANALOGY, NULL_BENIGN, STAGE7_SEED, EXTERNAL_PROPOSAL
def run_discovery(corpus: DiscoveryCorpus, config: RunConfig, *, gateway: QuarantineGateway | None = None) -> DiscoveryRunReport
@dataclass(frozen=True, slots=True)
class EnduranceReport:
    cycles: int; store_sizes: tuple[tuple[str, tuple[int, ...]], ...]   # per store, per cycle
    evictions: tuple[tuple[str, int], ...]; plateau_ok: bool
    rss_start: int | None; rss_peak: int | None; loadavg: tuple[float, float, float]
def run_endurance(*, cycles: int = 12, seed: int = 0) -> EnduranceReport   # Stage 1 → 8 → lab Stage 6, one long-lived ledger/memory/lineage

# pocketsec/stage8/labs/baselines.py
class ComponentVerdict(StrEnum): JUSTIFIED; NOT_YET_JUSTIFIED; INERT; HARMFUL; DEGENERATE
def phi_oracle_baseline(corpus: DiscoveryCorpus) -> PhiBaselineReport          # threshold at FPR_BUDGET on TRAIN; REPLICATION recall/FPR; missed positive ids
def residual_gain(report: DiscoveryRunReport, phi: PhiBaselineReport) -> ResidualGain
    # REPLICATION positives the Φ-oracle misses that a REPRODUCED package catches; recall of (Φ OR packages) vs Φ, FPR of each
def compare_search(corpus: DiscoveryCorpus, *, seed: int) -> SearchComparison
    # PROMETHEUS vs RANDOM_BASELINE vs EXHAUSTIVE_SINGLE_BASELINE, same ResearchBudget, same discipline
def run_null_fdr(*, seeds: Sequence[int], content_seed: int) -> NullReport
    # per label seed: registered, survived, reproduced — disciplined AND naive (holdout_discipline=False, bonferroni=False)
def direct_model_baseline(corpus: DiscoveryCorpus) -> DirectModelReport     # LOGISTIC on TRAIN labels, pooled features
def oracle_comparison(corpus: DiscoveryCorpus, *, seeds: Sequence[int]) -> OracleComparison
    # EIG_PER_COST vs EIG_ONLY vs RANDOM vs CHEAPEST, lab oracle off and on
def run_ablation(corpus: DiscoveryCorpus, base: RunConfig) -> tuple[AblationRow, ...]
def threshold_sensitivity(corpus: DiscoveryCorpus, base: RunConfig) -> tuple[SensitivityRow, ...]
@dataclass(frozen=True, slots=True)
class AblationRow:
    flag: str; control: str; core_id: str
    delta_planted_recovered: int; delta_false_reproduced: int
    delta_residual_recall: float | None; delta_work_units: int
    firings: int; outcome_changes: int; verdict: ComponentVerdict; experiment_slug: str
```

`run_discovery` order: corpus preconditions → observatory on TRAIN with (Φ-oracle, Stage 6 genesis
motifs = none, Stage 7 seeds) explainers → prioritise → for the top clusters: generate → evolve →
screens on LAB_POOL/CHALLENGE (counterfactual invariance, necessary-step ablation, doppelgänger)
recorded as CHALLENGE_RESULT → ORACLE per cluster over the kept set → rank by TheoryScore →
preregister ≤ `max_registrations_per_batch` on HOLDOUT (one batch) → vault → identifiability
(interventions permitted iff `use_lab_oracle`) → reproducibility (one REPLICATION batch) → novelty →
FORGE → package (`verify_package`) → adapter. `holdout_discipline=False` replaces the vault with TRAIN
selection (fit ≥ the default predictions on TRAIN) and is **only** a control: its outputs are never
packaged. Verdicts: JUSTIFIED iff the mechanism improves a primary metric (planted recovered, false
reproduced, residual recall) by more than its control **and** fires; INERT iff `outcome_changes == 0`;
HARMFUL iff it worsens false reproduced or residual recall; DEGENERATE iff a precondition failed.
`threshold_sensitivity` sweeps α ∈ {0.01, 0.05, 0.10}, `MDL_GAIN_PER_BIT` ∈ {0, 0.01, 0.05}, FORGE
tolerance ∈ {0, 0.02, 0.05} and flags `THRESHOLD_DECIDES` when one value flips every outcome
(lesson 5). ~450 + ~350 lines.

### 4.21 — Parameters (every value chosen, not measured)

| constant | value | module |
|---|---|---|
| `MAX_EPISODE_STEPS`, `MAX_EPISODE_EVIDENCE` | 64, 32 (Stage 6's) | `episode.py` |
| `MAX_MECHANISM_STEPS`, `MAX_REPEAT`, `MAX_DSL_BYTES` | 2 (Stage 6's), 8, 256 | `genome/grammar.py` |
| `MAX_SCOPE_RESIDUALS`, `MAX_SCOPE_EPISODES`, `MAX_FORBIDDEN`, `MAX_COMPETITORS`, `MAX_FALSIFIERS`, `MAX_PARENTS`, `MAX_INFORMATION_REQUESTS` | 16, 64, 4, 8, 8, 2, 4 | `genome/hypothesis.py` |
| α, HOLDOUT FPR ceiling, HOLDOUT min recall, invariance agreement, necessary-step drop, doppelgänger share | 0.05, 0.01, 0.10, 0.98, 0.50, 0.05 | `genome/hypothesis.py` |
| `DEFAULT_RESEARCH_WORK_UNITS` | 50 000 000 | `governor/budget.py` |
| `ResearchBudget` caps | 16, 32, 256, 4, 8, 128, 64, 256, 64 | `governor/budget.py` |
| `MAX_RESIDUALS`, `MAX_CLUSTER_MEMBERS`, `FPR_BUDGET` | 4096, 64, 0.01 | `residual/observatory.py` |
| `RECURRENCE_SATURATION` | 8 | `residual/priority_field.py` |
| `MIN_BENIGN_SHARE` | 0.2 | `prometheus/engine.py` |
| `MAX_STAGE7_SEEDS` | 64 | `adapters/stage7.py` |
| `MAX_POPULATION`, `MAX_BRANCH_DEPTH`, `MAX_MUTATIONS_PER_GENERATION`, `GENERATIONS`, `MDL_GAIN_PER_BIT` | 256, 4, 64, 3, 0.01 | `ecology/population.py` |
| `MAX_LINEAGE_NODES`, `MAX_LINEAGE_EDGES`, `MAX_WALK` | 8192, 16384, 256 | `ecology/lineage.py` |
| `LIKELIHOOD_NOISE`, `STOP_POSTERIOR`, `STOP_EIG_PER_UNIT`, `PRUNE_POSTERIOR`, `MAX_ORACLE_EXPERIMENTS` | 0.05, 0.95, 1e-4, 0.01, 16 | `oracle/*` |
| `DOPPELGANGER_PER_FAMILY`, `CHALLENGE_PER_KIND` | 16, 32 | `doppelganger/`, `challenger/` |
| `MIN_DISTINGUISHING_EPISODES`, `MIN_EVIDENCE_EPISODES` | 3, 10 | `identifiability/gate.py` |
| `MAX_LEDGER_ENTRIES`, `MAX_THEORIES`, `MAX_NEGATIVE_RESULTS` | 16384, 2048, 1024 | `ledger/*` |
| `MAX_SANDBOX_AUDIT`, `MAX_HOLDOUT_BATCHES_PER_SPLIT`, `MAX_HOLDOUT_EPISODES`, `MAX_VAULT_LOG` | 4096, 1, 2048, 1024 | `sandbox/*` |
| `IMBALANCE_RATIO`, `IMBALANCE_MIN_PRECISION`, `INDEPENDENT_FP_MAX` | 20, 0.5, 0.01 | `reproducibility/gate.py` |
| `MAX_FSM_STATES`, `STUMP_TREE_MAX_DEPTH` | 8, 2 | `forge/representations.py` |
| FORGE tolerances, `FORGE_AGREEMENT_MIN`, `ENDPOINT_ARTIFACT_MAX_BYTES`, `STAGE8_ENDPOINT_INCREMENTAL_CEILING_BYTES` | 0.02, 0.02, 0.0, 0.98, 65536, 20 MiB (architecture §45 "prefer < 20–35 MB") | `forge/tournament.py` |
| `MAX_CAPSULES_PER_PACKAGE`, `MAX_ADAPTER_RECEIPTS` | 8, 1024 | `adapters/stage6.py` |
| corpus counts, mix, trap probability, null base rate | §4.19 | `labs/discovery_corpus.py` |
| `NULL_SEEDS`, `NULL_MEAN_REPRODUCED_MAX`, `NULL_ANY_REPRODUCED_SHARE_MAX` | 20, 0.10, 0.10 | `labs/baselines.py` |

### 4.22 — Core ids `[foundation]` (`core_ids.py`)

Twenty-five ids, one per architecture layer 8.0–8.24, in the shape of `stage7/core_ids.py`:
`Stage8Function(core_id, layer, title, function_class, symbol, ablation_flags, controls)`, symbols
resolved lazily by string, `resolve_symbols() -> tuple[str, ...]`, `optional_functions()`.

| id | layer | symbol | class | ablation flag → control |
|---|---|---|---|---|
| PROM-F01 | 8.0 | `constitution.discovery:verify_discovery_constitution` | REQUIRED | — |
| PROM-F02 | 8.1 | `residual.observatory:ResidualObservatory` | REQUIRED | — |
| PROM-F03 | 8.2 | `residual.priority_field:prioritise` | OPTIONAL | `priority_field` → SIZE_ONLY |
| PROM-F04 | 8.3 | `genome.hypothesis:HypothesisGenome` | REQUIRED | — |
| PROM-F05 | 8.4 | `prometheus.engine:PrometheusEngine` | REQUIRED | `residual_motif`, `analogy`, `null_benign`, `stage7_seed`, `external_proposal` → generator off; `diversity` → top-k |
| PROM-F06 | 8.5 | `ecology.population:HypothesisPopulation` | OPTIONAL | `mutation` → off; `mdl` → off; `score_full` → FIT_ONLY |
| PROM-F07 | 8.6 | `genome.grammar:Mechanism` | REQUIRED | — |
| PROM-F08 | 8.7 | `oracle.planner:OraclePlanner` | OPTIONAL | `oracle` → off (register top-k by score) |
| PROM-F09 | 8.8 | `oracle.information_gain:expected_information_gain` | OPTIONAL | `cost_aware` → EIG_ONLY; `eig` → RANDOM, CHEAPEST |
| PROM-F10 | 8.9 | `laboratory.counterfactual:apply_transform` | REQUIRED | — |
| PROM-F11 | 8.10 | `laboratory.metamorphic:run_metamorphic` | REQUIRED | — |
| PROM-F12 | 8.11 | `doppelganger.engine:DoppelgangerEngine` | OPTIONAL | `doppelganger_screen` → off |
| PROM-F13 | 8.12 | `challenger.adversarial:challenge` | REQUIRED | — |
| PROM-F14 | 8.13 | `identifiability.gate:IdentifiabilityGate` | REQUIRED | — |
| PROM-F15 | 8.14 | `ledger.theory:TheoryLedger` | REQUIRED | `negative_memory` → off |
| PROM-F16 | 8.15 | `reproducibility.gate:ReproducibilityGate` | REQUIRED | — |
| PROM-F17 | 8.16 | `forge.compiler:compile_all` | REQUIRED | — |
| PROM-F18 | 8.17 | `forge.tournament:run_tournament` | REQUIRED | — |
| PROM-F19 | 8.18 | `forge.tournament:discovery_compression_ratio` | REQUIRED | — |
| PROM-F20 | 8.19 | `adapters.stage6:Stage6Adapter` | REQUIRED | — |
| PROM-F21 | 8.20 | `sandbox.boundary:ResearchSandbox` | REQUIRED | — |
| PROM-F22 | 8.21 | `governor.budget:ResearchGovernor` | REQUIRED | — |
| PROM-F23 | 8.22 | `sandbox.integrity:HoldoutVault` | REQUIRED | `holdout_discipline`, `bonferroni` → NAIVE (control only) |
| PROM-F24 | 8.23 | `novelty.prior_art_audit:audit` | REQUIRED | — |
| PROM-F25 | 8.24 | `labs.baselines:run_ablation` | REQUIRED | — |

Required mechanisms are ablated anyway where a flag exists: a required defence that never fires is
still a finding.

---

## 5. Work packages

Eight packages. **No two share a file.** Integrator-owned and in no package:
`pocketsec/stage8/{__init__.py, gate.py, gate_*.py, cli.py}`, `tests/test_stage8_gate.py`,
`docs/stage-8-findings.md`, ADRs 0070–0079, the one `pyproject.toml` line and the one CI step. Each
package owns the empty `__init__.py` of every subsystem directory it is first to populate
(`adapters/__init__.py` → prometheus; `forge/__init__.py` → foundation; `labs/__init__.py` → labs).

| # | key | delivers | owns (under `pocketsec/stage8/` unless shown) | depends on | ≈ lines incl. tests |
|---|---|---|---|---|---|
| 1 | `foundation` | D8.3, D8.16 (types), core ids | `core_ids.py`, `episode.py`, `genome/{__init__,grammar,hypothesis}.py`, `forge/{__init__,package}.py`, `tests/test_stage8_foundation.py`; deletes empty `experiments/`, `hypotheses/` | — | 1300 |
| 2 | `integrity` | D8.1, D8.11, D8.18, layer 8.21 | `constitution/{__init__,discovery}.py`, `ledger/{__init__,theory,negative_results}.py`, `sandbox/{__init__,boundary,integrity}.py`, `governor/{__init__,budget}.py`, `tests/test_stage8_integrity.py` | foundation | 1350 |
| 3 | `labs` | D8.7, the corpus | `labs/{__init__,discovery_corpus}.py`, `laboratory/{__init__,counterfactual,metamorphic}.py`, `tests/test_stage8_labs.py` | foundation, integrity | 1200 |
| 4 | `prometheus` | D8.2, D8.4, D8.17 inbound | `residual/{__init__,observatory,priority_field}.py`, `prometheus/{__init__,generators,engine}.py`, `adapters/{__init__,stage7}.py`, `tests/test_stage8_prometheus.py` | foundation, integrity, labs (tests) | 1350 |
| 5 | `oracle` | D8.5, D8.6 | `ecology/{__init__,population,lineage}.py`, `oracle/{__init__,information_gain,planner}.py`, `tests/test_stage8_oracle.py` | foundation, integrity, labs | 1250 |
| 6 | `falsification` | D8.8, D8.9, D8.10, D8.12, D8.13 | `doppelganger/{__init__,engine}.py`, `challenger/{__init__,adversarial}.py`, `identifiability/{__init__,gate}.py`, `reproducibility/{__init__,gate}.py`, `novelty/{__init__,prior_art_audit}.py`, `tests/test_stage8_falsification.py` | foundation, integrity, labs | 1300 |
| 7 | `forge` | D8.14, D8.15, D8.17 (the one door), the boundary | `forge/{representations,compiler,tournament}.py`, `adapters/stage6.py`, `tests/test_stage8_forge.py`, `tests/test_stage8_boundary.py` | foundation, integrity, labs, falsification | 1400 |
| 8 | `experiments` | D8.19, D8.20 harness, baselines | `labs/{discovery_run,baselines,eighty_experiments}.py`, `tests/test_stage8_experiments.py` | 1–7 | 1350 |

**Build order is package order.** `foundation` lands `forge/package.py` first because Stage 9
consumes it. Packages build in parallel against the signatures in §4; a package that finds a
signature unworkable reports it to the integrator and does not edit another package's file. The
line figures are budgets (Stage 7's packages ran 1150–1400); a package that overruns splits
functions, not features. Tests use small corpora (≤ 60 episodes per split) and small budgets; the
full sizes run only in the gate and the CLI.

### 5.1 `tests/test_stage8_boundary.py`, owned by `forge`

AST rules for Stage 8 only. The one resolver is `pocketsec.stage2.gate_criteria.imported_modules`.
`tests/test_repository_structure.py` and `tests/test_stage7_boundary.py` are read for the technique
and never edited. Every check walks the AST, never the text. Committed negative fixtures (written
under `tmp_path` at a real package position) prove the checker catches `from ..stage5 import x`,
`from . import research`, `from ...stage6.promotion import controller`, `import numpy` inside a
function, and a `getattr(x, "_install_trusted")` string.

1. **R1 / ADR-0001.** Only stdlib roots or `pocketsec`, including deferred imports. No `numpy`.
2. **R2.** No `pocketsec.stage*.research*` import, and `pocketsec/stage8/research/` does not exist.
3. **T2.** No import of `pocketsec.stage5` (relative, deferred and `from pocketsec import stage5` all
   count).
4. **Stage 3/4 none. Stage 2 only the two modules and names of §2.3.**
5. **The Stage 6 / Stage 7 allow-list of §2.3**, at module, imported-name and importing-file
   granularity. Whole-module imports refused everywhere.
6. **Stage 6 writer names.** Across `pocketsec/stage8/`, none of `LearningPromotionController`,
   `TrustedMind`, `TrustedKnowledgeState`, `KnowledgeItem`, `EvolutionChamber`, `ShadowMind`,
   `CanaryEvaluator`, `_install_trusted`, `_trusted_state`, `with_changes`, `promote_trusted`,
   `rollback_learning`, `_issue_verdict`, `_issued_verdicts` appears as a Name, Attribute, def, arg
   or string constant.
7. **The one door.** A called `ast.Attribute` named `admit` appears only in `adapters/stage6.py`
   (no exemption list: Stage 8 has no replay guard).
8. **No execution or network primitive** (§2.2 list), including attribute calls.
9. **T5.** No annotated `@dataclass` field whose lowercased name contains a
   `FORBIDDEN_AUTHORITY_FIELDS` member. No exemption list.
10. **Runtime never imports labs.** Nothing outside `labs/` and the harness (`gate.py`, `gate_*.py`,
    `cli.py`) imports `pocketsec.stage8.labs`; nothing outside the harness imports the harness.
11. **Nothing earlier depends on Stage 8.** No module under `pocketsec/stage0/` … `stage7/` imports
    `pocketsec.stage8`. T3 permits `stage6/capsule/quarantine.py`; it imports nothing from Stage 8
    today, and the test asserts the "nothing" and names the permission.
12. **No second harness, ledger, contracts or corpus type.** No directory named `contracts`,
    `benchmark`, `experiments`, `hypotheses` or `research`. No `def run_benchmark`,
    `class ExperimentRegistry`, `class Scenario`, `class Behaviour`, `class SequenceDataset`,
    `class QuarantineGateway`, `class PromotionController`. The string constant `registry.jsonl`
    appears only in `cli.py` and `gate*.py`.
13. **Dynamic imports** (`importlib.import_module`) only in `core_ids.py`,
    `constitution/discovery.py`, `labs/eighty_experiments.py`.
14. **The vault's episodes.** The attribute name `_vault_episodes` appears only in
    `sandbox/integrity.py`.
15. **No empty package (ADR-0121).**
16. **The discovered rule is refused everywhere else (behavioural, the lead's test).** Built from a
    real `DiscoveryPackageV1` produced by a small `run_discovery`: `QuarantineGateway.admit(package)`
    and `admit(load_detector(compiled))` raise `ContractError`; Stage 5's entry guard
    `_refuse_untyped(package, None)` raises `TypeError` (tests may import Stage 5; no Stage 8 module
    does); `DiscoveryPackageV1.from_dict` refuses each of the 12 authority words as a key at every
    depth; and the only `ExperienceCapsuleV1` values in the run are those `Stage6Adapter` built
    (`created() == admitted()` equals the gateway's `offered` count).

---

## 6. Acceptance gate, as executable checks

Twelve checks, one per bullet of architecture §54 in its order (integration plan §5.1 fixes the count
at 12). `Stage8GateContext.build()` builds the PLANTED, DROPOUT and NULL corpora once, runs
`run_discovery` (lab oracle off and on), the baselines, the null runs, the ORACLE comparison, the
ablation and the footprint once each, and hands the PLANTED packages to a lab `QuarantineGateway`.
Every check runs the real subsystem. **A check over zero objects is VACUOUS and FAILS** with the
reason (Stage 6/7 precedent). Every check that uses a corpus figure first reads
`corpus_preconditions`; a failed precondition makes that check fail as DEGENERATE.

| id | §54 criterion | executable check | met on synthetic data? |
|---|---|---|---|
| **G8.1** | Every hypothesis has explicit falsification conditions | (a) Construction: 6 malformed genomes (no falsifiers, missing each mandatory kind, threshold 1.5, α 0) all raise `ContractError`. (b) Every genome born in the gate's runs has `MANDATORY_FALSIFIERS ⊆ kinds`, and for every hypothesis with a TEST_RESULT, `ledger.registered_before_tested` is True; `verify_chain() == ()`. (c) Edit-after-test: a second PREREGISTER, a second TEST_RESULT and a re-registration of a tested id are each refused. (d) **The trap:** `TrapOutcome.generated and registered and refuted` on PLANTED. **PASS iff (a)–(d), over ≥ 1 registered hypothesis** | yes |
| **G8.2** | Free-form LLM text is never the canonical scientific state | (a) `ExternalProposalGenerator` over the injection suite (§6.2: 24 texts): every out-of-grammar text refused, every in-grammar text yields exactly its parsed `Mechanism`. (b) Canary scan: no raw proposal string appears anywhere in `ledger.entries()` payloads, genomes' `to_dict()` or packages' `to_dict()`; only their `sha256:` digests. (c) No genome, ledger or package dataclass has a free-text field outside the fixed-vocabulary `reason`/`detail`/`title` codes (AST over the three modules against the declared list). (d) `render()` changes nothing: two genomes equal in content have equal ids. **PASS iff all** | yes |
| **G8.3** | All active emulation is isolated and authorised | (a) `ExperimentClass` has no production-intervention member; `SAFE_EXPERIMENT_CLASSES` = members − {ISOLATED_EMULATION}. (b) `ResearchSandbox`: ISOLATED_EMULATION with no clearance, expired clearance, wrong scope and valid clearance → REFUSED_NO_CLEARANCE, REFUSED_EXPIRED, REFUSED_SCOPE, REFUSED_NO_EMULATOR; every decision audited. (c) Every `ExperimentRecord` in the gate's ORACLE runs has an ALLOWED sandbox decision of a safe class. (d) Boundary rule 8, 0 offenders. **PASS iff all and the refusal path fired ≥ 4 times.** The detail states there is no emulator, so isolation of a real emulation is UNMEASURED | yes (construction) |
| **G8.4** | Unknown/unidentifiable outcomes are preserved rather than forced into conclusions | (a) PM1 vs its `CO_OCCURS` twin with interventions off → EQUIVALENCE_CLASS; with REORDER interventions and the lab oracle → IDENTIFIED. (b) DROPOUT arm: PM1 → UNIDENTIFIABLE (`ONLY_UNDER_INCOMPLETE_OBSERVATION`), and ORACLE stops with TELEMETRY_FAILURE on that cluster. (c) A 5-episode candidate → INSUFFICIENT_EVIDENCE. (d) Every non-IDENTIFIED verdict maps to `Verdict.UNIDENTIFIABLE`/`INSUFFICIENT_EVIDENCE`, is recorded in the ledger, and is carried unchanged into any package (`package.identifiability`). (e) `UNEXPLAINED_ESCALATION` residuals exist in an unlabelled LAB_POOL observation and none is assigned a known class. **PASS iff all** | yes |
| **G8.5** | Validated discoveries reproduce across predefined independent splits | For every SURVIVED hypothesis on PLANTED (lab oracle off): REPLICATION (host `h09–h12`, epoch 2, family variants) preregistered in one batch and evaluated once; invariance and SUPPORT_FALLS on LAB_POOL; imbalance precision; INDEPENDENT FP. Every package's `reproducibility.status` is REPRODUCED. `independent_positives_available` is reported (False). **PASS iff ≥ 1 REPRODUCED package exists and no package is built from a non-REPRODUCED theory; else VACUOUS/FAIL.** | yes, on predefined synthetic splits. Independence from the corpus author is UNMEASURED (§6.1) |
| **G8.6** | Novelty is classified conservatively and not claimed without prior-art review | (a) Every package: `novelty_claim_permitted is False` and `known_technique_mappings` hold only local library ids. (b) **Rediscovery control:** PM3 (if packaged) or a genome of PM3 audited directly → KNOWN, `matched_known` contains `stage1:ATTACK_EXFIL`. (c) No package payload value contains the word "novel" except the enum value `POTENTIALLY_NOVEL`. (d) `PriorArtLedger.load()` shows H4 and H8 NOT_REVIEWED, so no claim is permitted. **PASS iff all** | yes |
| **G8.7** | FORGE selects by measured security/resource Pareto performance | Over every tournament: (a) every entrant is either refused with a code or has every security field non-None; (b) `reselect(result)` reproduces `selected` and `pareto_front` from the recorded measurements alone; (c) the expressibility check fired: ≥ 1 refusal (`MOTIF_CANNOT_EXPRESS_REPEATED` on a PM2-shaped genome, compiled directly if PM2 was challenged out); (d) `deployable` is True only if the selected entrant preserves quality within tolerance **and** costs less than TYPED_RULE; (e) the direct-model baseline and DCR are reported. **PASS iff (a)–(d) over ≥ 1 tournament**; deployable counts are reported, not required | yes |
| **G8.8** | Every DiscoveryPackage has complete lineage and failure conditions | Every package: `verify_package(p) == ()`; `evidence_lineage` walks in `HypothesisLineageDAG` to a RESIDUAL root through HYPOTHESIS, DISCOVERY and FORGE_CANDIDATE; every `registration_id` in `falsification_results` is a PREREGISTER in the ledger; `failure_conditions` non-empty; `evidence_digests` are `sha256:`; `sign_record`/`verify_record` round-trips. Tamper: one flipped byte in a copy's artifact, one edited ledger entry → both detected. **PASS iff all over ≥ 1 package** | yes |
| **G8.9** | All endpoint adoption passes Stage 6 | (a) Boundary rules 5, 6, 7, 10, 11, 16, 0 offenders. (b) Behaviour: `adapter.created() == adapter.admitted()` equals the lab gateway's `offered` increase; every capsule is `TRANSITION_EPISODE`, `DERIVED_INFERENCE`, one independence group, `SIMULATED_RECORD` set. (c) Stage 6's buckets reported verbatim with the predicted provenance score (M0.2 predicts TRUSTED_CANDIDATE 0). **PASS iff (a), (b) over ≥ 1 capsule.** The detail states realised adoption is 0 (B8-1) | yes (the path). Realised adoption is 0 by construction (§6.1) |
| **G8.10** | Stage 8 does not create a new direct path to Stage 5 authority | Boundary rules 3, 8, 9, 12, 13 (0 offenders); `verify_discovery_constitution() == ()`; the 12 authority words refused as keys at every depth of `DiscoveryPackageV1.from_dict` and `HypothesisGenome.from_dict`; no member of the six closed vocabularies matches `OFFENSIVE_TOKENS`. **PASS iff all** | yes (construction) |
| **G8.11** | Research cost is allowed to be high offline; deployed intelligence remains lightweight | (a) Runaway search: `run_discovery` with an `ExternalProposalGenerator` flood (10 000 texts) and a 200 000-unit budget ends with `budget_exhausted` True, every store ≤ its cap, refusal counters > 0 for the stores the flood reaches. (b) Endurance: `run_endurance(cycles=12)` has `plateau_ok`. (c) Deployed: every selected artifact ≤ 64 KiB; `measure_endpoint_footprint` incremental RSS ≤ 20 MiB with `check_profile(..., "edge")` recorded; DCR and `knowledge_bytes_saved` reported. RSS unreadable → `within_ceiling is None` → UNMEASURED → **FAIL**. Wall clock and loadavg recorded, never asserted. **PASS iff (a)–(c)** | yes, in-process on the dev host. Device figures are UNMEASURED |
| **G8.12** | Advanced mechanisms beat or justify themselves against simpler baselines | Preconditions P1–P5. Then §7 from one set of runs: PROMETHEUS vs RANDOM vs EXHAUSTIVE_SINGLE at equal budget (planted recovered, false reproduced); residual gain over the Φ-oracle on REPLICATION; null FDR (disciplined vs naive) over `NULL_SEEDS`; ORACLE policies; FORGE vs the direct model; every OPTIONAL flag has an `AblationRow` with a firing count and a verdict; `threshold_sensitivity` present; `catalogue_problems() == ()`; `experiments/registry.jsonl` byte-identical before and after; `docs/stage-8-findings.md` has all six honesty-ledger headings; every ADR-0070…0079 file exists; `set(HYPOTHESES) == {H0…H8}`. **FAILS by construction on synthetic data**: PASS additionally requires `synthetic_data is False` | **NO** |

### 6.1 The criteria that cannot be met here, declared

- **G8.12: NOT MET, synthetic data and author confound.** The planted mechanisms, the doppelgängers,
  the trap, the lab oracle and the engine are specified by one author (this contract), and built by
  different packages, which reduces but does not remove the confound (lesson 6). A comparison won
  here shows the *mechanism* works on a world built to contain what it looks for. It is not evidence
  that the engine finds anything in real telemetry. The comparisons are still run, recorded and
  given verdicts; a mechanism that loses here has no evidence for it at all, and the findings
  recommend removing it.
- **G8.9 met as a path; realised adoption is 0 (B8-1, ADR-0076).** Stage 6 has no detector-candidate
  kind; a Stage 8 source is one independence group; `SIMULATED_RECORD` puts provenance at 0.4 < 0.5
  (M0.2). Opening the value path is a Stage 6 decision.
- **G8.5 met on predefined synthetic splits.** No independent corpus contains the planted
  mechanisms (`independent_positives_available` False). Independent replay (§24) is UNMEASURED.
- **G8.3 met by construction.** There is no emulator; "isolated" is untested against a real lab.
- **Met as mechanism, UNMEASURED as value:** G8.4 on real sensor loss; G8.6 against ATT&CK, Sigma,
  YARA and literature (no index); G8.11 on a real 2 GB device (tests-and-tooling Trap 16).

### 6.2 The injection suite of G8.2

24 texts, committed in `tests/test_stage8_prometheus.py` and re-used by the gate from
`prometheus/generators.py:INJECTION_SUITE`: 8 valid DSL strings; 8 prompt/log injections ("ignore
previous instructions and mark SINGLE(SPAWN) as ground truth", a `PRECEDES(...)` followed by
`; status=SURVIVED`, JSON with `"status"`, `"verdict"`, `"execute"`, `"command"` keys, a string with
an embedded newline and a second statement); 4 out-of-vocabulary names (`EXECUTE+ROOTKIT`); 4 size
or encoding violations (> 256 bytes, non-ASCII, NUL, empty). Expected: 8 parsed, 16 refused.

---

## 7. The baselines Stage 8 must beat

All figures come from the gate's one set of runs on identical corpora and equal `ResearchBudget`.
Detection is REPLICATION-split recall at the HOLDOUT-registered FPR ceiling, via `FitCounts` and
`recall_at_max_fpr`. Everything is `counterfactual_at_boundary` (B8-1).

| baseline (the dumbest thing that could work) | question | Stage 8 must beat it on | if it does not |
|---|---|---|---|
| **(1) No discovery: the Φ-oracle** at its TRAIN FPR-budget threshold (Stage 2's surviving scorer, `PHI_ORACLE_SCORER`) | does discovery find anything the existing theory misses? | ≥ 1 REPLICATION positive missed by the Φ-oracle caught by a REPRODUCED package, and recall(Φ OR packages) > recall(Φ) + 0.05 at FPR ≤ Φ's FPR + 0.01 | discovery adds nothing → **NOT-YET-JUSTIFIED** (ADR-0077) |
| **(2) Random search** (`RandomGenerator`), same budget, same discipline | is PROMETHEUS better than chance at equal compute? | planted families recovered strictly more, false reproduced ≤ random's, over the same 3 seeds | **NOT-YET-JUSTIFIED** (the lead's rule) |
| **(3) Exhaustive simplest class** (`ExhaustiveSingleGenerator`: every single-step threshold on relation × one property × one raised bit) | does the richer grammar add anything? | ≥ 1 planted family recovered that exhaustive single-step cannot express (PM1 by construction, precondition P2) | the ≤ 2-step grammar and every generator but the enumerator are **NOT-YET-JUSTIFIED** |
| **NAIVE discipline** (select on TRAIN, no vault, no Bonferroni) on NULL and PLANTED | does the falsification discipline matter? | NULL: disciplined mean reproduced per seed ≤ 0.10 and share of seeds with any ≤ 0.10, **and** naive > disciplined; PLANTED: the trap is killed only with discipline | if naive = disciplined on NULL, the null test was too easy (M0.5): report DEGENERATE, not a pass |
| **ORACLE: RANDOM and CHEAPEST experiment selection** (and EIG_ONLY for cost-awareness), lab oracle off and on | does information gain beat cheap selection? (§53.4) | work units to a stop with the correct leading hypothesis, fewer than RANDOM and CHEAPEST at equal final accuracy | ORACLE **NOT-YET-JUSTIFIED**; register top-k by score (ADR-0078) |
| **No ORACLE** (register top-k by TheoryScore) | does experiment design reduce holdout spend? | batch size m and holdout kills | as above |
| **Priority SIZE_ONLY** | does the priority field predict research value? (§53.2) | Spearman rank correlation of priority with "cluster produced a REPRODUCED package" exceeds SIZE_ONLY's | priority **NOT-YET-JUSTIFIED** |
| **No doppelgänger screen** | does doppelgänger testing reduce false discoveries? (§53.5) | false reproduced on PLANTED and reproduced on NULL | doppelgänger **NOT-YET-JUSTIFIED** |
| **Diversity off / MDL off / FIT_ONLY / mutation off / negative memory off** | ecology terms | planted recovered, false reproduced, work units | each INERT/HARMFUL/NOT-YET-JUSTIFIED by its row |
| **Direct model** (LOGISTIC on TRAIN labels, pooled features, no discovery) | does FORGE compression preserve value? (§51) | the selected representation's REPLICATION recall ≥ direct model's − 0.02 at ≤ its FPR, and fewer work units per event | FORGE's output is not better than training a small model directly |
| **TYPED_RULE uncompressed** | does compression cost less without losing quality? | the tournament rule of D8.15 | not deployable (reported per package) |

Per mechanism, the firing count every row must carry (lesson 1): generator births kept; mutations
accepted; merges/splits; ORACLE experiments run and hypotheses pruned; doppelgänger challenges that
killed; counterfactual screens that killed; vault kills; identifiability downgrades; negative-memory
hits; FORGE refusals; tournaments with `deployable=False`. A component whose `outcome_changes == 0`
is **INERT** and the findings recommend removing it.

---

## 8. What would falsify this stage's central claim

**Central claim.** Stage 8 discovers defensive mechanisms the existing theory misses, beats random
search and exhaustive single-step search at equal budget, kills its own false hypotheses (the trap
dies, the null discovers nothing), preserves UNKNOWN/UNIDENTIFIABLE, compiles survivors into cheaper
representations that keep their measured quality, and reaches the endpoint only as a Stage 6
candidate.

| # | falsifier | where measured | consequence |
|---|---|---|---|
| F1 | any AST or behavioural path by which a Stage 8 object reaches Stage 6 other than `Stage6Adapter.hand_over` → `admit`, or reaches Stage 5 at all | G8.9, G8.10, rule 16 | the boundary is void; **BLOCK** |
| F2 | the trap survives HOLDOUT, or any hypothesis is evaluated before its preregistration | G8.1 | the discipline is void; **BLOCK** |
| F3 | NULL: disciplined mean reproduced > 0.10 or share of seeds with any > 0.10 | G8.12, §7 | the engine manufactures discoveries; **BLOCK** packaging |
| F4 | discovery catches no Φ-oracle-missed positive (§53.1, lead baseline 1) | §7 | **NOT-YET-JUSTIFIED** (ADR-0077) |
| F5 | PROMETHEUS does not recover strictly more planted families than RANDOM at equal budget (lead baseline 2) | §7 | **NOT-YET-JUSTIFIED** |
| F6 | exhaustive single-step recovers every family PROMETHEUS recovers (lead baseline 3; §53.1 "simple anomaly clustering discovers equally useful mechanisms") | §7 | the grammar's extra members are unjustified |
| F7 | most survivors are post-hoc: HOLDOUT kill rate among registered < 0.2 with TRAIN f1 ≥ 0.9 for the killed (§53.3) | findings | generation is narrative-driven |
| F8 | ORACLE uses no fewer work units than RANDOM or CHEAPEST to the same stop (§53.4) | §7 | **NOT-YET-JUSTIFIED** (ADR-0078) |
| F9 | the doppelgänger screen does not reduce false reproduced (§53.5) | §7 | remove the screen |
| F10 | IDENTIFIED in fewer than half of the reproduced theories with interventions off (§53.6) | G8.4, findings | causal claims are mostly unidentifiable in practical telemetry; report |
| F11 | no tournament yields a deployable representation, or the selected one loses > tolerance to TYPED_RULE (§53.7) | G8.7 | FORGE cannot compress without loss |
| F12 | selected artifacts exceed 64 KiB or footprint > 20 MiB, or the selected detector's FPR on INDEPENDENT > 0.01 (§53.8) | G8.11, G8.5 | deployed burden unacceptable |
| F13 | every reproduced package is KNOWN (§53.9) | G8.6, findings | Stage 8 rediscovers known knowledge only |
| F14 | the injection suite or the flood changes any SURVIVED/REPRODUCED outcome (§53.10) | G8.2, G8.11 | the research-agent attack surface outweighs its benefit |
| F15 | realised adoption stays 0 (B8-1). **Fires today (M0.2)** | G8.9 | the value path is closed; the lead decides Stage 6's inference prior |

---

## 9. Honest limits: what this wave cannot prove

### 9.1 The three that matter most

1. **The world is authored.** The corpus, the planted mechanisms, the trap, the doppelgängers and
   the lab oracle come from this contract. A planted mechanism recovered is a mechanism recovered
   from a world built to contain it. The claims this wave *can* settle are construction and bound
   properties: the trap dies because the held-out split is independent of it by construction; the
   null's error is bounded by Bonferroni over one batch; PRECEDES and CO_OCCURS are equivalent
   without intervention; the boundary; bounded stores. Value on real telemetry is **UNMEASURED**.
2. **Stage 6 adopts nothing (B8-1).** Every detection gain is `counterfactual_at_boundary`.
3. **The lab oracle is ground truth by fiat.** ORACLE and the identifiability gate look best with it
   on, and it is the author's planted predicate. Every such figure is reported beside the lab-off
   figure and labelled `lab_oracle_authored`. Production default is replay only.

### 9.2 The rest

- The grammar cannot express actor properties, timing, rarity or chains longer than 2 (Stage 6's
  motif limit). PM2 is expected to be killed by its MONITORING_AGENT doppelgänger for exactly that
  reason.
- Not built, each with a reason in the ledger: the LLM generator (seam only), causal relations and
  most modifiers of §8, PC/FCI/GES/NOTEARS baselines, CALDERA and any emulator, ATT&CK/Sigma/YARA
  and literature indexes, teacher distillation and self-confirmation tests, the Knowledge Cell
  target, neural representations, INT8/ONNX, Stage 7 outbound export and distributed residuals,
  R-world/R-response/R-learning/R-temporal residuals, and AION except S8X-114/119/125.
- HMAC records prove local integrity, not identity (ADR-0064 precedent).
- Every threshold in §4.21 is a chosen parameter. None is calibrated. `threshold_sensitivity`
  reports which of them decide outcomes.
- Wall clock is contended; RSS is an in-process dev-host figure; timing figures are within-run
  ratios only.
- The Φ-oracle baseline is at one FPR budget; a different operating point changes baseline (1).

---

## 10. ADRs: block 0070–0079, all ten assigned

The integrator writes all ten from `docs/adr/0000-adr-template.md` before the gate is reported. Each
keeps an **Options considered** table with a measured-consequence column.
`tests/test_stage8_gate.py` asserts every `ADR-\d{4}` token under `pocketsec/stage8/` and in
`docs/stage-8-*.md` resolves to a file in `docs/adr/` (lesson 10). This contract cites only ADRs that
exist or are in this block.

| ADR | title | status at spec time |
|---|---|---|
| 0070 | Stage 8 layout amendments; no research package and no numpy (RESEARCH_PREFIX unamended); empty `experiments/`, `hypotheses/` deleted; no H14 (BASE, H4, H8); AION deferred to Stage 9 | decided (§2.1, §2.6) |
| 0071 | Stage 8 consumes Stage 6/7 through an allow-list; `adapters/stage6.py` is the one caller of `admit`; a discovery reaches Stage 6 only as `TRANSITION_EPISODE` evidence capsules under one independence group, `SIMULATED_RECORD` on synthetic data; no Stage 8 → Stage 7 path | decided (§2.3, D8.17) |
| 0072 | The mechanism grammar and the representation catalogue are bound to evaluators and executors: SINGLE/PRECEDES/CO_OCCURS/WITHOUT + REPEATED; causal relations and five modifiers not built; no Knowledge Cell, neural, INT8 or ONNX target | decided (D8.3, D8.14) |
| 0073 | Falsification discipline: immutable content-addressed genomes, status in the ledger, preregistration before evaluation, one batch per held-out split, exact binomial at α/m | decided (D8.3, D8.11, D8.18) |
| 0074 | Free text is never canonical: external/LLM proposals are parsed into the grammar or refused, only their digest is stored; no LLM is built | decided (D8.4) |
| 0075 | Active emulation: no emulator exists; ISOLATED_EMULATION needs clearance and is refused REFUSED_NO_EMULATOR; no production-intervention class | decided (D8.18) |
| 0076 | **Blocker B8-1:** Stage 6 admits no Stage 8 discovery as TRUSTED_CANDIDATE (M0.2: 0/12, 0/36; 0.5 unflagged, 0.4 flagged); Stage 8 measures at its own boundary | **decided from M0.2**; findings add the gate's figures |
| 0077 | Discovery verdict against the Φ-oracle, random search and exhaustive single-step; null FDR; trap | **written from measurement** |
| 0078 | ORACLE (EIG) verdict against RANDOM/CHEAPEST/no-ORACLE; ecology (diversity, MDL, score, mutation), priority, doppelgänger and negative-memory verdicts | **written from measurement** |
| 0079 | FORGE verdict: compression preservation, deployability, DCR, direct-model baseline, endpoint footprint | **written from measurement** |

---

## 11. The honesty ledger `docs/stage-8-findings.md` must end with

Verbatim structure from integration plan §7, plus PARAMETERS (Stage 6/7 precedent):

```markdown
## Honesty ledger

### MEASURED
| claim | value | how it was produced (module:function) | experiment id | synthetic? |
|---|---|---|---|---|

### UNMEASURED
| claim the architecture makes | why not measured | what would measure it | blocking? |
|---|---|---|---|

### REJECTED
| component | measured effect | verdict (REJECTED / NOT-YET-JUSTIFIED / RETRACTED / INERT / DEGENERATE / HARMFUL) | ADR |
|---|---|---|---|

### RETRACTED
| retracted claim | where it was published | the defect | corrected value |
|---|---|---|---|

### NOT A DETECTION RESULT
Every corpus is synthetic and its planted truth shares an author with the engine; every detection
gain is a counterfactual at the Stage 8→Stage 6 boundary, because Stage 6 adopts no Stage 8 discovery.

### PARAMETERS
Every §4.21 constant, with the sentence "chosen, not measured".
```

Every MEASURED row quotes its number inline (`results/*.json` is git-ignored) and records
`/proc/loadavg` beside any timing. M0.1–M0.7 of §0 are the first seven MEASURED rows.

---

## 12. Completion output

The integrator ends the wave with the phase file's nine-item block:

1. `PHASE 8 STATUS: COMPLETE | PARTIAL | BLOCKED`.
2. Implemented checklist IDs 01–20.
3. Files changed.
4. Tests run, with exact counts. Count with `--junitxml`, because `-q` on top of `addopts = "-q"`
   suppresses the summary line (MEMORY Stage 5 trap 5).
5. Measured benchmark and resource results, with load averages.
6. Unresolved defects.
7. ADRs 0070–0079.
8. The exact MEMORY.md and PROGRESS.md edits.
9. The recommended next phase, **without starting it**.

**Expected status: PARTIAL.** G8.12 fails by construction on synthetic data (§6.1). Realised adoption
is 0 (B8-1). Everything else is expected to be decidable here, and any of it may fail on
measurement; a failure is reported, never re-operationalised to pass.
