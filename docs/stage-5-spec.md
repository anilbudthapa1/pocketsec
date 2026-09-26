# Stage 5 — SAFE + AEGIS + SENTINEL — implementation specification

- **Status:** the implementation contract for Wave 5. Binding on all eight work packages.
- **Date:** 2026-09-25
- **Architecture source of truth:** `docs/architecture/sources/stage-05-safe-aegis-sentinel.md`
- **Build contract:** `docs/architecture/stage-3-12-integration-plan.md`
- **Phase checklist and gate:** `planning/PHASE_05_CLAUDE_CODE.md`
- **ADR block:** **0040–0049 only.** Verified free this session:
  `ls docs/adr/ | grep -cE '^00(3|4)[0-9]-'` → `0`.
- **Gate check count:** **15**, fixed by integration plan §5.1.
- **Findings document the integrator must write:** `docs/stage-5-findings.md`.

---

## 0. Measurement status of this document

Every claim in this document is one of three things, and the reader may hold me to the label.

**MEASURED — produced by running code in this session.**

| claim | value | how it was produced | load average at the time |
|---|---|---|---|
| Every type Stage 5 consumes from Stages 0–4 exists and resolves | **83 of 83 symbols OK, 0 missing**, exit 0 | the §3.0 verification script, run as `PYTHONPATH=. python3 verify_seam.py` | `8.77 7.08 7.50` (`/proc/loadavg`) |
| ADR numbers 0030–0049 are unused | `0` files | `ls docs/adr/ \| grep -cE '^00(3\|4)[0-9]-'` | — |
| `pocketsec/stage5/` contains no Python | `0` files | `find pocketsec/stage5 -name '*.py' \| wc -l` | — |
| No Stage 5 test file exists | `0` | `ls tests \| grep -c stage5` | — |
| `docs/stage-5-spec.md` did not exist before this document | `ls: cannot access 'docs/stage-5*'` | `ls docs/stage-5*` | — |
| Experiment-id grammar accepts a `BASE` hypothesis for stage 5 | `PS-S5-20260925-BASE-safe-gate-0001` | `format_experiment_id(stage=5, hypothesis='BASE', slug='safe-gate', sequence=1)` (`stage0/experiments/ids.py:56`) | — |
| `PROFILES` names three targets; `edge` is 104857600 B agent RSS | printed verbatim | `pocketsec.stage0.benchmark.profiles.PROFILES` | — |
| `HYPOTHESES` holds H0–H8 only | 9 entries, no H9+ | read from `stage0/hypotheses.py:50-84` | — |
| All five upstream schema ids Stage 5 pins are at version `1.0.0` | `security_event_sequence.v1`, `threat_prediction.v1`, `ssir_transition.v1`, `knowledge_cell.v1`, `cbf_resolution.v1` → all `1.0.0` | read from `SCHEMA_REGISTRY` after importing the five modules | `0.91 1.44 2.96` |
| `IDENTIFIABILITY_MARGIN` | `0.15` | `stage4/identifiability/resolution.py:65` | — |
| `MANDATORY_SIGNALS` / `DIMENSIONS` sizes | 6 / 9 | `stage1/observation/policy.py:47`, `stage1/state/security_state.py:108` | — |
| Stage 4 has **no** `gate.py` or `cli.py` yet | `sed: can't read pocketsec/stage4/gate.py` | direct read | — |

**DESIGN — assigned by this document.** Every module path, type name, field, signature and bound in
§4 is a name this contract assigns. None of it exists yet. An engineer who finds a better name may
not use it: eight packages are building in parallel and the names are the interface.

**UNMEASURED — stated as such, never guessed.** Every performance figure, every collateral rate,
every rollback reliability number, every Action Shadow calibration. §9 is the complete list. A
figure that could not be measured is `None` in data and `UNMEASURED` in prose. Not a plausible
number.

**No timing figure in this document is a device measurement.** Load on this host was 8.77 while the
seam script ran. A Stage 2 gate run measured the *same* two code paths at 122.48/647.23 µs/event at
load 8–12 and 855.31/3040.63 µs/event at load 23–67 — a 7× inflation (`planning/MEMORY.md`). Only
**within-run ratios** transfer off this host, and every ratio is recorded beside `/proc/loadavg`.

---

## 1. What Stage 5 is for, stated so no engineer mistakes it

Stage 5 is the **only** stage that touches privilege. Stages 1–4 produce beliefs; Stage 5 acts.

Every invariant this project has accumulated exists to constrain this stage. A defect here is not a
bug, it is a vulnerability. **Treat the security boundary as the deliverable and the cleverness as
optional.**

The objective is not maximum intervention. It is **minimum sufficient, authorized, reversible and
verifiable intervention** (architecture §1). The system must be able to choose NO ACTION, and
choosing it must be a first-class, tested outcome rather than an error path.

### 1.1 What Stage 5 will probably turn out to be worth, and why that is fine

Two completed stages set the expectation. Stage 2 returned **zero** justified learned mechanisms
across thirteen gate criteria and rejected its own core (ADR-0010). Stage 3 rejected its own
compilation vehicle: ADR-0021 is titled *"the Knowledge Cell format loses to the rule it wraps"*.

The likely Stage 5 outcome, stated in advance so a failing gate is not mistaken for a failed wave:

- **The safety machinery will hold and can be settled here.** Typed operators, no-shell-path,
  SENTINEL independence, target identity, capability scope, lease expiry, evidence ordering,
  bounded fan-out — these are *construction* properties. They are provable or testable now, on
  synthetic data, and they are what this wave can actually deliver.
- **The elaborate planning machinery will probably not beat the fixed playbook.** The Counterfactual
  Response Twin, the Intervention Cone, the Pareto/regret selector and the multi-world evaluation
  must beat a static `if Φ > t: suspend the process` table on **measured** collateral and
  effectiveness, inside the simulated host model. If they do not, ADR-0048 says so and recommends
  removing them. That is the correct outcome, not a failure of the wave.
- **Rollback reliability against a real Linux host cannot be measured here at all.** §6.1 and §9.

---

## 2. Repository rules this wave operates under

### 2.1 Layout — integration plan §1.2, extended here

Integration plan §1.2 fixes the Stage 5 skeleton. This document extends it with six modules the
§1.1 skeleton requires (`core_ids.py`), that the architecture's own §39 layer list requires
(`assurance/`, `governor.py`), or that the seam and measurement conventions of Stages 3 and 4
require (`resources.py`, `stage6_interface.py`, `theory.py`). **Nothing else is added, and no
package may create a module not listed here.**

```
pocketsec/stage5/
    __init__.py                     # integrator. EMPTY or a lazy public surface; never a re-export chain
    core_ids.py                     # SAFE-F01 … SAFE-F24, REQUIRED/OPTIONAL + ablation flag
    theory.py                       # the formal statement of §§3,7,10,11,23,26 with every term bound
    governor.py                     # D5.23 Resource Governor — caps, spend, prune, escalate
    resources.py                    # §43 budget + ResourceSampler measurement; loadavg
    stage6_interface.py             # ResponseRecordV1 — the ONLY artefact Stage 6 sees
    gate.py                         # integrator. 15 checks
    cli.py                          # integrator. pocketsec-stage5 {gate,plan,execute,recover,resources,experiments,handoff}
    constitution/{invariants.py,schema.py}
    operators/{algebra.py,catalog.py,d3fend.py}
    host/simulated.py               # the SIMULATED host model — labelled as such, everywhere
    authority/{capability.py,tokens.py}
    sentinel/{kernel.py,monitors.py}
    evidence/preservation_gate.py
    safe/action_field.py
    twin/response_twin.py
    aegis/{cone.py,shadow.py,pareto.py,planner.py,human_contract.py}
    executor/{identity.py,journal.py,transactional.py,lease.py,verify.py,residual.py}
    recovery/safe_state.py
    memory/effectiveness.py
    cells/response_cells.py
    assurance/properties.py
    labs/{response_corpus.py,baselines.py,fifty_experiments.py,toctou.py,adversarial_load.py}
```

Every `__init__.py` under a subsystem package stays **empty**. Consumers import the leaf module:
`from pocketsec.stage5.operators.catalog import CATALOG`. That is the convention in all 61 existing
runtime modules. **An empty subsystem package is a defect, not a placeholder** (ADR-0121); create
the package in the same change that fills it. `pocketsec/stage5/response/` exists on disk today as
an empty directory and is **not** in this layout: the package that first needs to touch it deletes
it, exactly as ADR-0121 deleted `stage2/{atoms,dtl,prediction}/`.

### 2.2 Stage 5 ships **no** `research/` package, ever — ADR-0040

Integration plan §2.4 says "**no, permanently** — privilege. A numpy import here is a supply-chain
path into the executor." This is not a budget decision that a later wave may revisit; it is the
reason the executor's trusted computing base is small. `pocketsec/stage5/research/` must not exist,
and `tests/test_stage5_boundary.py` asserts its absence.

### 2.3 Hard mechanical constraints

- Python ≥ 3.11 (running 3.14.7). `from __future__ import annotations` in every module.
- **Stdlib only.** Permitted imports: roots in `sys.stdlib_module_names`, and `pocketsec`.
- Files under ~800 lines; functions under ~50 lines; type-annotate every public API.
- Module docstring states what the module is **for**. Frozen slotted dataclasses with typed fields.
  Explicit `__all__`. Comments explain *why*, not *what*. Read `pocketsec/stage4/worlds/world.py`
  and `pocketsec/stage4/stage5_interface.py` before writing a line.
- Every bound is a **named module constant**, never a literal at a use site. §4.9 collects them.
- `print()` only in `cli.py` (`tests/test_repository_structure.py:152`).
- `[tool.mypy] strict = true` covers `pocketsec` **and** `tests`. `ruff` selects
  `E,F,I,B,UP,SIM,RUF` at 100 columns. Neither has ever been run in this repository
  (`MEMORY.md`, "Known gap") — this wave runs both and reports the counts, or records UNMEASURED
  and says why.

### 2.4 The authority-field trap, and Stage 5's unique position in it

Trust rule **T5** forbids any dataclass field under `pocketsec/stage3/`…`stage12/` whose lowercased
name contains a member of `FORBIDDEN_AUTHORITY_FIELDS` (`threat_prediction_v1.py:48`:
`action remediation execute command shell kill quarantine block authorize authorization privilege
sudo`) — **except under `pocketsec/stage5/`**.

Stage 5 is the exemption. That is exactly why it is dangerous. The exemption means the *test* will
not catch a smuggled authority field here, so three rules replace it and each is enforced by
construction:

1. **A field may name an action only if its type is a closed enum or a catalog-bound object.**
   `DefensiveOperator.spec` is an `OperatorSpec` that must be identical (`is`) to a `CATALOG` member.
   There is no `str` field anywhere in Stage 5 whose value selects an operator.
2. **No field anywhere in Stage 5 holds a command, a command fragment, a template string with a
   substitution, or free text that reaches a system call.** `ArgvAtom` (§4.2) is the only type from
   which an argument vector is assembled, and its two members are a frozen literal and a closed
   enum field selector.
3. **`GrantSource` has exactly two members, `POLICY` and `HUMAN`.** There is no `MODEL` member and
   no way to add one without editing a closed enum, which `tests/test_stage5_boundary.py` pins by
   value.

### 2.5 Stage 5 imports Stage 4 through exactly one module — ADR-0045

Trust rule T1 permits Stage 5 to import `stage0`, `stage1`, `stage4`, `stage3.cells` and
`stage3.bytecode`. This document narrows the Stage 4 half to **one module**:

```python
from pocketsec.stage4.stage5_interface import CBFResolutionV1, IncidentHypothesis, InformationGap
```

Three reasons, and the third is operational:

1. Stage 4's own seam docstring makes the argument: *"Stage 4 will be redesigned. ADR-0036 may
   recommend deleting the multi-world machinery outright. A handoff that carries `SecurityWorldV1`
   instances couples Stage 5's lifetime to Stage 4's class names; a handoff that carries rows of
   strings and floats survives the redesign."* (`stage4/stage5_interface.py:16-23`.)
2. `CBFResolutionV1.to_dict()` performs the refusals — laundered claim kinds, dangling citations,
   unsupported authoritative rows, Stage 4 class-name leakage. Consuming the typed objects directly
   would route around checks Stage 4 built for Stage 5's benefit.
3. **Another wave is building Stage 4 in this working tree right now.** Stage 4 has no `gate.py` and
   no `cli.py` (measured, §0). Coupling to eleven Stage 4 modules means eleven chances to be broken
   mid-build by work Stage 5 must not touch.

`tests/test_stage5_boundary.py` asserts that the *only* `pocketsec.stage4.*` module imported
anywhere under `pocketsec/stage5/` is `pocketsec.stage4.stage5_interface`.

### 2.6 Another wave is building in this tree

- **Never** edit, revert or delete anything under `pocketsec/stage4/`, `tests/test_stage4_*.py` or
  `docs/stage-4-*.md`. Never run `git checkout`, `git stash`, `git restore`, `git clean` or
  `git commit`.
- **Never** edit `tests/test_repository_structure.py`. Read it for the technique
  (`_research_importers` at `:124`, and the shared resolver `imported_modules` at
  `stage2/gate_criteria.py:547`), then leave it alone. Stage 5's boundary checks live in
  `tests/test_stage5_boundary.py`.
- When the full suite is run, failures in `tests/test_stage4_*.py` are that wave's
  work-in-progress. **Report them and move on.** Judge Stage 5 by `tests/test_stage5_*.py` plus
  `pocketsec-stage5 gate`.
- `pyproject.toml` is shared. Stage 5 appends exactly one line,
  `pocketsec-stage5 = "pocketsec.stage5.cli:main"`, and adds one CI step. It does not reformat the
  file, and it does not add `pocketsec-stage4` on the other wave's behalf.

### 2.7 A gate must never mutate the real experiment ledger

`experiments/registry.jsonl` is append-only and digest-chained. `Stage5GateContext.build()` uses a
temporary registry path; **G5.15 asserts `experiments/registry.jsonl` is byte-identical before and
after the gate run.** Measurement rows that belong in the ledger are written by
`pocketsec-stage5 experiments`, not by the gate.

### 2.8 Hypothesis binding — no H11 is minted

Integration plan §5.2 pre-assigns H11 to Stage 5 via ADR-0012, **which was never written**.
`HYPOTHESES` holds H0–H8 (measured, §0), and `tests/test_harness_and_gate.py:241` asserts
`set(ledger.entries) == set(HYPOTHESES)`, so appending H11 fails the suite unless a matching
prior-art entry lands in the same commit — in a Stage 0 file another wave may be editing.

Stage 3 bound to `H4` and Stage 4 to `H3`/`H7`. **Stage 5 binds to neither: it mints no hypothesis
and uses `BASE`.**

```python
# pocketsec/stage5/gate.py
STAGE5_HYPOTHESIS = "BASE"          # the grammar's own token for "not a learning hypothesis"
EXPERIMENT_ID = "PS-S5-20260925-BASE-safe-gate-0001"
```

This is the honest binding, not a dodge. H0–H8 are hypotheses about *learned representation and
compute*. Stage 5's claims are about authority, reversibility and verification — properties of a
control boundary, not of a model. `format_experiment_id(stage=5, hypothesis='BASE', …)` is valid
(MEASURED, §0), and `<NNNN>` is a per-stage counter, so Stage 5 starts at `0001`.

G5.15 therefore checks the *novelty discipline* rather than a ledger row for a hypothesis that does
not exist: §49's nine research-construct names must not appear in `docs/stage-5-findings.md`
alongside a novelty word without a reviewed prior-art entry. §6 states the check exactly.

---

## 3. The data seam

### 3.0 The verification script

Run this before writing code. It is the proof that every type in §3.1 exists, and it is how the
§0 MEASURED row was produced.

```bash
cd /home/anil/Documents/Research/pocketsec
PYTHONPATH=. python3 - <<'PY'
import inspect
TARGETS = [
    ("pocketsec.stage0.contracts.common",
     ["EvidenceRef","ContractError","register_schema","digest_of_bytes","require_identifier",
      "require_finite_unit_interval","require_non_negative_int"]),
    ("pocketsec.stage0.contracts.threat_prediction_v1",
     ["ThreatPredictionV1","Verdict","ComputePath","FORBIDDEN_AUTHORITY_FIELDS"]),
    ("pocketsec.stage0.gate", ["GateCheck","GateReport","REPO_ROOT"]),
    ("pocketsec.stage0.benchmark.resource_metrics", ["ResourceSampler","ResourceMetrics"]),
    ("pocketsec.stage0.benchmark.profiles", ["check_profile","ProfileReport","PROFILES"]),
    ("pocketsec.stage0.experiments.registry", ["ExperimentRegistry"]),
    ("pocketsec.stage0.experiments.ids", ["format_experiment_id"]),
    ("pocketsec.stage0.prior_art", ["PriorArtLedger"]),
    ("pocketsec.stage0.hypotheses", ["HYPOTHESES"]),
    ("pocketsec.stage1.state.security_state", ["SecurityStateV1","StateDelta","DIMENSIONS"]),
    ("pocketsec.stage1.state.potential", ["phi","delta_phi","PhiBreakdown"]),
    ("pocketsec.stage1.epoch.model", ["Epoch","SystemIdentity","EpochDecision"]),
    ("pocketsec.stage1.observation.policy",
     ["ObservationLevel","MANDATORY_SIGNALS","EscalationDecision"]),
    ("pocketsec.stage1.telemetry.raw_event_v1", ["SensorPath"]),
    ("pocketsec.stage3.cells.schema",
     ["KnowledgeCellV1","AssuranceLevel","CellPhase","HardConstraint","ConstraintKind"]),
    ("pocketsec.stage4.stage5_interface",
     ["CBFResolutionV1","IncidentHypothesis","InformationGap","CBF_RESOLUTION_V1_ID",
      "MAX_HYPOTHESES_PER_RESOLUTION","MAX_GAPS_PER_RESOLUTION","seam_violations"]),
]
missing = []
for mod_name, names in TARGETS:
    mod = __import__(mod_name, fromlist=["*"])
    for name in names:
        obj = getattr(mod, name, None)
        if obj is None:
            missing.append(f"{mod_name}.{name}"); print("MISSING", mod_name, name); continue
        try:
            where = f"{inspect.getsourcefile(obj)}:{inspect.getsourcelines(obj)[1]}"
        except Exception:
            where = f"{mod.__file__}:<constant>"
        print("OK", f"{mod_name}.{name}", "->", where)
print("MISSING COUNT:", len(missing))
PY
cat /proc/loadavg
```

### 3.1 Consumed from Stages 0–4 — every type below exists, cited `path:line`

Line numbers were produced by `inspect` in this session, not read out of a document.

| type | path:line | what Stage 5 uses it for |
|---|---|---|
| `EvidenceRef` | `stage0/contracts/common.py:124` | the only way evidence crosses a Stage 5 boundary. `store`/`locator`/`digest`, digest matching `^sha256:[0-9a-f]{64}$` |
| `ContractError` | `stage0/contracts/common.py:32` | every Stage 5 validation failure. Stage 5 defines **no** new base exception |
| `register_schema` | `stage0/contracts/common.py:49` | registers Stage 5's five new schema ids (§3.3). The sanctioned path; Stage 5 creates no second `contracts/` package |
| `digest_of_bytes` | `stage0/contracts/common.py:116` | `sha256:<hex>` for identity digests, evidence bundles, journal payloads, token MACs |
| `require_identifier`, `require_finite_unit_interval`, `require_non_negative_int` | `:72`, `:84`, `:78` | field validation in `__post_init__`. Stage 5 writes no parallel validators |
| `ThreatPredictionV1`, `Verdict`, `ComputePath` | `stage0/contracts/threat_prediction_v1.py:142`, `:66`, `:84` | **evidence only.** A verdict is an input to planning, never an authorisation (ADR-0003) |
| `FORBIDDEN_AUTHORITY_FIELDS` | `stage0/contracts/threat_prediction_v1.py:48` | the token set `tests/test_stage5_boundary.py` and `stage6_interface.py` screen against |
| `GateCheck`, `GateReport`, `REPO_ROOT` | `stage0/gate.py:44`, `:55` | the 15-check gate |
| `ResourceSampler`, `ResourceMetrics` | `stage0/benchmark/resource_metrics.py:103`, `:57` | **the only** source of a resource figure. Anything else is UNMEASURED |
| `check_profile`, `ProfileReport`, `PROFILES` | `stage0/benchmark/profiles.py:85`, `:61` | §43 budget check. `ProfileReport.within_target` is `None`, never `True`, when nothing was measured |
| `run_benchmark`, `BenchmarkCase`, `BenchmarkResult` | `stage0/benchmark/harness.py:133`, `:42`, `:91` | the one measurement path. `synthetic_data=True` is mandatory and travels with the result |
| `SequenceDataset`, `LabelledSequence` | `stage0/benchmark/dataset.py:52`, `:35` | checksum-bound datasets for any benchmarked comparison |
| `ExperimentRegistry`, `format_experiment_id` | `stage0/experiments/registry.py:106`, `ids.py:56` | append-only digest-chained ledger. Stage 5 builds no second ledger |
| `PriorArtLedger`, `HYPOTHESES` | `stage0/prior_art.py:71`, `stage0/hypotheses.py:50` | G5.15. Stage 5 **appends to neither** |
| `SecurityStateV1`, `StateDelta`, `DIMENSIONS` | `stage1/state/security_state.py:121`, `:180`, `:108` | host security state in a `HostSnapshot`; `StateDelta.bitmask()` keys effectiveness memory and the B2 playbook |
| `phi`, `delta_phi`, `PhiBreakdown` | `stage1/state/potential.py:170`, `:195`, `:146` | the **fixed-playbook baseline's entire input** (B2), and the hysteresis controller's signal. Φ is never reported as a bare number |
| `Epoch`, `SystemIdentity`, `EpochDecision` | `stage1/epoch/model.py:104`, `:54`, `:80` | epoch-conditions effectiveness memory and response-cell melting. Stage 5 defines **no second epoch type** |
| `ObservationLevel`, `MANDATORY_SIGNALS`, `EscalationDecision` | `stage1/observation/policy.py:39`, `:47`, `:92` | `O0_OBSERVE` operators raise observation through Stage 1's AOP; Stage 5 builds no second observation planner and never disables a mandatory signal |
| `SensorPath` | `stage1/telemetry/raw_event_v1.py:41` | evidence provenance on a preserved bundle |
| `KnowledgeCellV1`, `AssuranceLevel`, `CellPhase`, `HardConstraint`, `ConstraintKind` | `stage3/cells/schema.py:232`, `:68`, `:84`, `:113`, `:99` | `ResponseCellV1` **reuses** `HardConstraint`, `CellPhase` and `AssuranceLevel`. It does not fork them |
| `CBFResolutionV1` | `stage4/stage5_interface.py:484` | **the only artefact Stage 5 sees from Stage 4.** Fields quoted below |
| `IncidentHypothesis` | `stage4/stage5_interface.py:346` | `mechanism_id`, `support`, `consequence`, `uncertainty`, `claim_ids`, `evidence_refs` |
| `InformationGap` | `stage4/stage5_interface.py:285` | `signal`, `why_it_matters`, `would_discriminate`, `affordable` — **a question, never an instruction** |
| `MAX_HYPOTHESES_PER_RESOLUTION = 16`, `MAX_GAPS_PER_RESOLUTION = 8` | `stage4/stage5_interface.py:92`, `:94` | the upstream bound Stage 5's action field must respect |
| `seam_violations`, `CBF_RESOLUTION_V1_ID` | `stage4/stage5_interface.py:212`, `:85` | the technique `stage6_interface.py` copies for its own seam |
| `imported_modules` | `stage2/gate_criteria.py:547` | **imported by `tests/test_stage5_boundary.py` only, never by runtime.** The one implementation of import resolution in this repository; relative imports were invisible to two checkers at once (S2-AUTH-01) and copying it is how that hole stayed open in neither |

### 3.2 The upstream contract, quoted

`CBFResolutionV1` (`stage4/stage5_interface.py:484-502`) is the whole input surface:

```python
resolution_id: str
incident_id: str
epoch_id: int
verdict: Verdict
identifiability: str                          # an IdentifiabilityState member value, as a string
hypotheses: tuple[Mapping[str, Any], ...]     # plain rows: mechanism_id/support/consequence/
                                              # uncertainty/claim_ids/evidence_digests
consequence_distribution: Mapping[str, float]
claim_graph: Mapping[str, Any]
evidence_lineage: tuple[Mapping[str, str], ...]
uncertainty: float
shadow: Mapping[str, Any]
information_gaps: tuple[Mapping[str, Any], ...]
truncations: tuple[Mapping[str, Any], ...]
degradations: tuple[Mapping[str, Any], ...]
interface_version: str = CBF_RESOLUTION_V1_VERSION
```

Five facts about it that change Stage 5's design:

1. **`identifiability` is a string, not an enum.** Stage 5 must not import
   `IdentifiabilityState`. It compares against a closed frozenset of the member values it
   understands and treats every other value as `UNKNOWN` — the fail-closed reading. Constant:
   `UNDERSTOOD_IDENTIFIABILITY` in `safe/action_field.py`.
2. **`hypotheses` are plain mappings, not `IncidentHypothesis` objects.** `to_dict()` flattens
   `evidence_refs` to `evidence_digests: list[str]`. Stage 5 reads digests, and an
   `EvidenceRef` is reconstructed only from `evidence_lineage`, which carries `store`/`locator`/
   `digest`. A candidate whose evidence digest has no lineage row is **refused**, not defaulted.
3. **`verdict` is evidence.** A `Verdict.MALICIOUS` at `confidence=0.99` and one at `0.01` must
   reach the **same** authority decision. G5.4 tests exactly this.
4. **`truncations` and `degradations` are non-empty in the interesting cases.** A resolution that
   lost worlds, or whose Stage 4 subsystem degraded, raises Action Shadow — it does not raise
   confidence. `safe/action_field.py` adds `len(truncations) + len(degradations)` to the shadow's
   `unmodelled_dependencies` term.
5. **`information_gaps` are questions.** `InformationGap.why_it_matters` is prose that Stage 4
   already refused to let read as an instruction (`IMPERATIVE_TOKENS`,
   `stage4/stage5_interface.py:189`). Stage 5 may use a gap to select an `O0_OBSERVE` operator by
   matching `signal` against a **closed** signal→operator table. It may never parse the prose.

### 3.3 Exposed to Stage 6 — the names this contract assigns

Integration plan §3.2 says Stage 6 consumes `TransactionReceipt` and `InterventionResidual`, and
§3.1 names Stage 5's exposed set. Five new schema ids register through `register_schema`:

| schema id | type | module |
|---|---|---|
| `pocketsec.response_constitution.v1` | `ResponseConstitution` | `constitution/invariants.py` |
| `pocketsec.capability_token.v1` | `CapabilityToken` | `authority/tokens.py` |
| `pocketsec.response_cell.v1` | `ResponseCellV1` | `cells/response_cells.py` |
| `pocketsec.transaction_receipt.v1` | `TransactionReceipt` | `executor/transactional.py` |
| `pocketsec.response_record.v1` | `ResponseRecordV1` | `stage6_interface.py` |

`ResponseRecordV1` is the **only** artefact Stage 6 sees, and it is plain JSON with a canonical
digest, copying `stage4/stage5_interface.py` including its refusals:

- **No key may name a Stage 5 class.** `FORBIDDEN_SEAM_TOKENS` holds
  `defensiveoperator, operatorspec, capabilitytoken, sentinelkernel, sentinelverdict,
  transactionalexecutor, rollbackjournal, responsetwin, interventioncone, actionshadow,
  aegisplanner, leaseregistry, hysteresiscontroller, effectivenessmemory, responsecellfield,
  safestateplanner, evidencepreservationgate, simulatedhost`.
  **Deliberately absent**, and the omission is documented in the module as Stage 4's is:
  `lease` (`lease_id`, `lease_ttl_seconds`), `residual` (`residual_distance`), `receipt`
  (`receipt_id`), `operator` (`operator_id` — the catalog key *is* the payload), `shadow`
  (`shadow_score`). Banning those would mean no record could cross the seam at all.
- **No authority-named key**, screened against `FORBIDDEN_AUTHORITY_FIELDS` — with the four
  deliberate, enumerated exceptions Stage 5 cannot express without:
  `operator_id`, `operator_class`, `authority`, `rollback_operator_id`. Every other token is
  refused, and the exception list is a module constant `SEAM_AUTHORITY_EXEMPTIONS` with a test
  asserting it has exactly four members. An exemption list that can grow silently is the trap.
- **No unverified outcome may be exported as verified.** `to_dict()` raises if any row has
  `outcome == "COMMITTED_VERIFIED"` while its `postconditions` contain a `satisfied is None`.
- **`simulated` is a required, non-defaulted boolean on every row**, and `to_dict()` raises if it
  is `False` while `host_kind != "REAL"`. A record produced against the simulator cannot be
  exported as a real-host record by omission.

`ResponseRecordV1` fields: `record_id`, `incident_id`, `epoch_id`, `resolution_id` (the
`CBFResolutionV1` it answers), `plan_decision`, `receipts: tuple[Mapping[str, Any], ...]`,
`residuals`, `effectiveness_rows`, `melt_reports`, `leases_expired`, `sentinel_denials`,
`monitor_findings`, `governor_spend`, `host_kind`, `simulated`, `truncations`, `interface_version`.

---

## 4. Deliverables

Each deliverable names its work package in `[brackets]`, its exact module paths, its public types
with fields and types, its public functions with signatures, and its bounds. **No placeholders, no
TBD.** Where the architecture uses an abstract term, the binding to a Python type is given.

### D5.1 — Response Constitution + mission invariant schema `[foundation]`

```python
# pocketsec/stage5/constitution/invariants.py
RESPONSE_CONSTITUTION_V1_ID = "pocketsec.response_constitution.v1"
RESPONSE_CONSTITUTION_V1_VERSION = register_schema(RESPONSE_CONSTITUTION_V1_ID, "1.0.0")

class AuthorityClass(StrEnum):
    """§14. Ordered; comparison is by `AUTHORITY_ORDER`, never by string."""
    A0 = "A0"   # read-only observation
    A1 = "A1"   # bounded evidence preservation
    A2 = "A2"   # local fully reversible intervention
    A3 = "A3"   # local disruptive intervention
    A4 = "A4"   # host-wide containment
    A5 = "A5"   # administrator-only
    AX = "AX"   # prohibited autonomous action

AUTHORITY_ORDER: Mapping[AuthorityClass, int]   # A0=0 … A5=5, AX=99
MAX_AUTONOMOUS_AUTHORITY: AuthorityClass = AuthorityClass.A2

class ConstitutionalLaw(StrEnum):
    """§2, one member per bullet. Ten members, closed."""
    NO_CONFIDENCE_GRANTS_AUTHORITY = "NO_CONFIDENCE_GRANTS_AUTHORITY"
    NO_NATURAL_LANGUAGE_TO_PRIVILEGE = "NO_NATURAL_LANGUAGE_TO_PRIVILEGE"
    NO_ACTION_EXCEEDS_DECLARED_SCOPE = "NO_ACTION_EXCEEDS_DECLARED_SCOPE"
    UNKNOWN_IS_NOT_PERMISSION = "UNKNOWN_IS_NOT_PERMISSION"
    UNVERIFIABLE_IS_NOT_COMPLETE = "UNVERIFIABLE_IS_NOT_COMPLETE"
    IRREVERSIBLE_NEEDS_HIGHER_AUTHORITY = "IRREVERSIBLE_NEEDS_HIGHER_AUTHORITY"
    EVIDENCE_PRECEDES_INTERVENTION = "EVIDENCE_PRECEDES_INTERVENTION"
    NO_ACTION_IS_ALWAYS_AVAILABLE = "NO_ACTION_IS_ALWAYS_AVAILABLE"
    FAILURE_MUST_NOT_STOP_MONITORING = "FAILURE_MUST_NOT_STOP_MONITORING"
    NO_OFFENSIVE_BEHAVIOUR = "NO_OFFENSIVE_BEHAVIOUR"

class ConstitutionDecision(StrEnum):
    PERMITTED = "PERMITTED"
    REFUSED = "REFUSED"
    HUMAN_REQUIRED = "HUMAN_REQUIRED"

@dataclass(frozen=True, slots=True)
class ConstitutionVerdict:
    decision: ConstitutionDecision
    laws_invoked: tuple[ConstitutionalLaw, ...]
    detail: str

@dataclass(frozen=True, slots=True)
class ResponseConstitution:
    laws: tuple[ConstitutionalLaw, ...]
    max_autonomous_authority: AuthorityClass
    prohibited_operator_classes: frozenset[OperatorClass]   # {O7_DESTRUCTIVE}
    policy_version: str
    schema_version: str = RESPONSE_CONSTITUTION_V1_VERSION

    def __post_init__(self) -> None: ...
    # refuses: a law set that is not exactly `set(ConstitutionalLaw)`; a
    # max_autonomous_authority above A2; O7 absent from prohibited classes.
    def digest(self) -> str
    def permits(self, *, operator_class: OperatorClass, authority: AuthorityClass,
                reversibility: Reversibility, has_rollback: bool,
                autonomous: bool) -> ConstitutionVerdict
    def to_dict(self) -> dict[str, Any]

FROZEN_CONSTITUTION: ResponseConstitution   # the module-level instance; policy_version "1.0.0"
```

**The constitution is data with no configuration path.** `ResponseConstitution.__post_init__`
refuses any instance that is weaker than `FROZEN_CONSTITUTION`: the law tuple must be the complete
enum, `max_autonomous_authority` may not exceed `A2`, and `O7_DESTRUCTIVE` must be prohibited. A
caller therefore cannot construct a permissive constitution and hand it to SENTINEL. This is the
first of the *by construction* properties in §4.8.

```python
# pocketsec/stage5/constitution/schema.py
MAX_MISSION_INVARIANTS: int = 64
MAX_SUBJECT_LENGTH: int = 128

class InvariantKind(StrEnum):
    """§24, one member per bullet. Eight members, closed."""
    CRITICAL_SERVICE = "CRITICAL_SERVICE"                  # subject = unit name; never autonomously interrupted
    ADMIN_RECOVERY_ACCESS = "ADMIN_RECOVERY_ACCESS"        # subject = unit/session; must stay reachable
    EVIDENCE_RETENTION = "EVIDENCE_RETENTION"              # subject = signal name; bound = seconds
    BOUNDARY_NOT_CROSSED = "BOUNDARY_NOT_CROSSED"          # subject = namespace/cgroup id
    MAX_AUTONOMOUS_DOWNTIME = "MAX_AUTONOMOUS_DOWNTIME"    # bound = seconds
    MAX_CONTAINMENT_DURATION = "MAX_CONTAINMENT_DURATION"  # bound = seconds
    FORBIDDEN_KERNEL_MODIFICATION = "FORBIDDEN_KERNEL_MODIFICATION"
    HOST_LOCAL_SCOPE = "HOST_LOCAL_SCOPE"

@dataclass(frozen=True, slots=True)
class MissionInvariant:
    invariant_id: str
    kind: InvariantKind
    subject: str                # "" only for the four kinds that are host-global
    bound_seconds: int | None   # required for the three bounded kinds, None otherwise
    detail: str

@dataclass(frozen=True, slots=True)
class InvariantViolation:
    invariant_id: str
    kind: InvariantKind
    subject: str
    detail: str

@dataclass(frozen=True, slots=True)
class MissionInvariantSet:
    invariants: tuple[MissionInvariant, ...]

    def __post_init__(self) -> None: ...   # bound at MAX_MISSION_INVARIANTS; ids unique
    def violations(self, *, operator: DefensiveOperator, lease_ttl_seconds: int,
                   snapshot: HostSnapshot) -> tuple[InvariantViolation, ...]
    def critical_units(self) -> frozenset[str]
    def required_evidence(self) -> frozenset[str]
    def to_dict(self) -> dict[str, Any]
    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> MissionInvariantSet

DEFAULT_MISSION_INVARIANTS: MissionInvariantSet   # 9 invariants; the labs corpus uses these
```

`violations()` is a **total** function over `InvariantKind`: a `match` with no `case _` fallthrough,
so adding a member to the enum without handling it is a type error under `mypy --strict`. That is
the construction behind "mission invariants are machine-enforced" (G5.8).

**Bounds:** ≤ 64 invariants, subject ≤ 128 chars, `MissionInvariantSet` state ≤ 16 KiB
(`MAX_INVARIANT_SET_BYTES = 16384`, asserted in `__post_init__` over `to_dict()`'s canonical bytes).

### D5.23 — Resource Governor `[foundation]`

```python
# pocketsec/stage5/governor.py
class WorkKind(StrEnum):
    CANDIDATE_GENERATION = "CANDIDATE_GENERATION"
    WORLD_EVALUATION = "WORLD_EVALUATION"
    TWIN_STEP = "TWIN_STEP"
    CONE_NODE = "CONE_NODE"
    DEPENDENCY_WALK = "DEPENDENCY_WALK"
    SENTINEL_CHECK = "SENTINEL_CHECK"
    HOST_CALL = "HOST_CALL"

@dataclass(frozen=True, slots=True)
class ResourceBudget:
    """§34's hard caps, as integers. Work units, never milliseconds: this host's load
    swung 8→67 between two runs of one gate, so a millisecond cap would be a random
    number generator (MEMORY.md, and §2.8)."""
    max_candidate_actions: int = 16
    max_worlds_per_action: int = 8
    max_cone_depth: int = 3
    max_cone_branches_per_node: int = 4
    max_dependency_nodes: int = 64
    max_twin_nodes: int = 64
    max_work_units: int = 4096
    max_concurrent_leases: int = 4
    max_rollback_journal_bytes: int = 262144
    max_autonomous_actions_per_window: int = 8
    window_seconds: int = 3600

STAGE5_BUDGET: ResourceBudget = ResourceBudget()

class BudgetExhausted(ContractError):
    """Raised on overspend. Callers prune or escalate; nothing relaxes a safety constraint."""

@dataclass(frozen=True, slots=True)
class PruneRecord:
    what: str
    identifier: str
    reason: str

class ResourceGovernor:
    def __init__(self, budget: ResourceBudget = STAGE5_BUDGET) -> None
    def spend(self, kind: WorkKind, units: int = 1) -> None        # raises BudgetExhausted
    def remaining(self) -> int
    def would_exceed(self, kind: WorkKind, units: int) -> bool
    def prune(self, candidates: Sequence[CandidateAction]) -> tuple[
        tuple[CandidateAction, ...], tuple[PruneRecord, ...]]
    def rate_limited(self, *, recent_action_times: Sequence[int], now: int) -> bool
    def spend_report(self) -> Mapping[str, int]
    def escalation(self) -> str | None
```

`prune()` is **deterministic and safety-monotone**: it drops the highest-`irreversibility`,
highest-`shadow` candidates first, never the observe-only candidate, and it **never** drops the
`NO_ACTION` option. Every drop emits a `PruneRecord`. Truncation is explicit, per the bounded-state
invariant. On exhaustion the caller escalates (`PlanDecision.ESCALATE`); **it does not widen a cap.**

### D5.6 — Authority + capability-token plane `[foundation]`

```python
# pocketsec/stage5/authority/capability.py
class GrantSource(StrEnum):
    """Two members. There is no MODEL member, and adding one is a closed-enum edit
    that tests/test_stage5_boundary.py pins by value (§2.4 rule 3, ADR-0003)."""
    POLICY = "POLICY"
    HUMAN = "HUMAN"

@dataclass(frozen=True, slots=True)
class AuthorityGrant:
    authority: AuthorityClass
    granted_by: GrantSource
    policy_version: str
    subject_operator_id: str
    detail: str

AUTHORITY_BY_OPERATOR_CLASS: Mapping[OperatorClass, AuthorityClass]
# O0->A0, O1->A1, O2->A2, O3->A2, O4->A3, O5->A4, O6->A5, O7->AX  (§5's autonomy column)

AUTONOMY_BY_OPERATOR_CLASS: Mapping[OperatorClass, Autonomy]

class Autonomy(StrEnum):
    POLICY_ELIGIBLE = "POLICY_ELIGIBLE"       # O0, O1
    STRICT_GATE = "STRICT_GATE"               # O2, O3
    APPROVAL_USUAL = "APPROVAL_USUAL"         # O4
    HUMAN_BY_DEFAULT = "HUMAN_BY_DEFAULT"     # O5, O6
    NEVER_AUTONOMOUS = "NEVER_AUTONOMOUS"     # O7

def required_authority(spec: OperatorSpec) -> AuthorityClass
def autonomy_of(spec: OperatorSpec) -> Autonomy
def escalates(granted: AuthorityClass, required: AuthorityClass) -> bool
def autonomy_permitted(spec: OperatorSpec, constitution: ResponseConstitution) -> bool
```

`required_authority` reads `AUTHORITY_BY_OPERATOR_CLASS`, a total mapping over `OperatorClass`; a
module-level `assert set(AUTHORITY_BY_OPERATOR_CLASS) == set(OperatorClass)` makes an unmapped class
an import-time failure. That is the construction behind "authority non-escalation" (§4.8, P4).

```python
# pocketsec/stage5/authority/tokens.py
CAPABILITY_TOKEN_V1_ID = "pocketsec.capability_token.v1"
CAPABILITY_TOKEN_V1_VERSION = register_schema(CAPABILITY_TOKEN_V1_ID, "1.0.0")

MAX_SPENT_NONCES: int = 256          # bounded endpoint state; eviction is FIFO and EXPLICIT
NONCE_BYTES: int = 16
MAX_TOKEN_LIFETIME_SECONDS: int = 900

class TokenVerdict(StrEnum):
    VALID = "VALID"
    BAD_MAC = "BAD_MAC"
    EXPIRED = "EXPIRED"
    NOT_YET_VALID = "NOT_YET_VALID"
    REPLAYED = "REPLAYED"
    UNKNOWN_SIGNER = "UNKNOWN_SIGNER"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    NONCE_EVICTED = "NONCE_EVICTED"   # honest: the bound was reached, so replay cannot be excluded

@dataclass(frozen=True, slots=True)
class CapabilityToken:
    """§15. The executor has no standing permission; it receives only this."""
    action_id: str
    incident_id: str
    operator_id: str
    target_digest: str            # identity_digest(ProcessIdentity) — the SAME function the
                                  # executor uses to digest the live target (§4.9 key-space rule)
    authority: AuthorityClass
    valid_from: int
    expiry: int
    max_duration_seconds: int
    rollback_required: bool
    policy_version: str
    nonce: str                    # 32 lowercase hex chars
    signer: str
    mac: str                      # hmac-sha256 hex over canonical_bytes()
    schema_version: str = CAPABILITY_TOKEN_V1_VERSION

    def canonical_bytes(self) -> bytes        # excludes `mac`; sorted keys; no float
    def to_dict(self) -> dict[str, Any]
    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> CapabilityToken

class TokenStore:
    """Mints and redeems. Single-use by construction: redeem() consumes the nonce."""
    def __init__(self, *, key: bytes, signer: str, clock: Clock,
                 max_spent_nonces: int = MAX_SPENT_NONCES) -> None
    def mint(self, *, grant: AuthorityGrant, operator: DefensiveOperator,
             action_id: str, ttl_seconds: int) -> CapabilityToken
    def redeem(self, token: CapabilityToken, *,
               operator: DefensiveOperator) -> TokenVerdict
    def spent_count(self) -> int
    def evictions(self) -> int
```

`mint()` refuses when `escalates(grant.authority, required_authority(operator.spec))`, when
`ttl_seconds > MAX_TOKEN_LIFETIME_SECONDS`, when the operator's spec is not a `CATALOG` member, and
when `grant.granted_by is GrantSource.HUMAN` is required by `autonomy_of(spec)` but the grant is
`POLICY`. `redeem()` compares with `hmac.compare_digest`, then checks `token.target_digest ==
operator.target.identity.digest()` and `token.operator_id == operator.spec.operator_id` — a token is
bound to *one* operator against *one* identity.

**The honest limit, stated in the type:** `MAX_SPENT_NONCES` is 256, so a token whose nonce was
evicted returns `NONCE_EVICTED`, which the executor treats as a **refusal**, not as `VALID`.
Fail-closed on a bound, rather than an unbounded set that pretends to perfect replay resistance.

**Bounds:** ≤ 256 spent nonces, token lifetime ≤ 900 s, token canonical bytes ≤ 1 KiB.

### D5.5 — Typed Defensive Operator Algebra `[operators]`

This deliverable is the security boundary. §6's rule — *forbidden:* `{"command": "some shell
string"}` — is made structural here.

```python
# pocketsec/stage5/operators/algebra.py
class OperatorClass(IntEnum):
    """§5. IntEnum because O-classes are ordered by consequence and compared."""
    O0_OBSERVE = 0
    O1_PRESERVE = 1
    O2_REVERSIBLE_RESTRICT = 2
    O3_SUSPEND = 3
    O4_LOCAL_REVOKE = 4
    O5_SERVICE_CONTAINMENT = 5
    O6_DISRUPTIVE = 6
    O7_DESTRUCTIVE = 7

class Reversibility(StrEnum):
    FULLY_REVERSIBLE = "FULLY_REVERSIBLE"
    REVERSIBLE_WITH_STATE = "REVERSIBLE_WITH_STATE"
    DEGRADED = "DEGRADED"
    IRREVERSIBLE = "IRREVERSIBLE"

class EvidenceEffect(StrEnum):
    PRESERVES = "PRESERVES"
    NEUTRAL = "NEUTRAL"
    DEGRADES_VOLATILE = "DEGRADES_VOLATILE"
    DESTROYS = "DESTROYS"

class TargetKind(StrEnum):
    PROCESS = "PROCESS"
    SERVICE = "SERVICE"
    SESSION = "SESSION"
    SOCKET = "SOCKET"
    HOST = "HOST"

class TargetField(StrEnum):
    """The closed set of values that may be substituted into an argument vector.
    Every member resolves to an int or to a validated identifier on the target —
    never to free text (§2.4 rule 2)."""
    PID = "PID"
    UID = "UID"
    UNIT_NAME = "UNIT_NAME"
    SOCKET_ID = "SOCKET_ID"
    SESSION_ID = "SESSION_ID"

@dataclass(frozen=True, slots=True)
class LiteralAtom:
    value: str            # must match ^[A-Za-z0-9._/-]{1,64}$ — no spaces, no shell metacharacters
@dataclass(frozen=True, slots=True)
class FieldAtom:
    field: TargetField
ArgvAtom = LiteralAtom | FieldAtom

@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    """§17. A pid is not an identity."""
    pid: int
    start_time_ticks: int
    uid: int
    executable_digest: str | None      # sha256:... where available; None is a real answer
    cgroup_id: str | None
    namespace_id: str | None

    def canonical_bytes(self) -> bytes
    def digest(self) -> str            # digest_of_bytes(canonical_bytes())

@dataclass(frozen=True, slots=True)
class TargetScope:
    kind: TargetKind
    subject: str                       # unit name / session id / socket id; validated identifier
    host_local: bool = True            # a False here is refused by the constitution (HOST_LOCAL_SCOPE)

@dataclass(frozen=True, slots=True)
class ProcessTarget:
    identity: ProcessIdentity
    scope: TargetScope

class PreconditionKind(StrEnum):
    TARGET_EXISTS = "TARGET_EXISTS"
    TARGET_IDENTITY_MATCHES = "TARGET_IDENTITY_MATCHES"
    TARGET_NOT_CRITICAL = "TARGET_NOT_CRITICAL"
    ROLLBACK_STATE_CAPTURED = "ROLLBACK_STATE_CAPTURED"
    EVIDENCE_PRESERVED = "EVIDENCE_PRESERVED"
    NO_ACTIVE_LEASE_ON_TARGET = "NO_ACTIVE_LEASE_ON_TARGET"
    SERVICE_HAS_RESTART_SEMANTICS = "SERVICE_HAS_RESTART_SEMANTICS"

@dataclass(frozen=True, slots=True)
class OperatorSpec:
    """A frozen catalog entry. Constructible ONLY inside operators/catalog.py."""
    operator_id: str
    operator_class: OperatorClass
    target_kind: TargetKind
    argv_template: tuple[ArgvAtom, ...]
    rollback_operator_id: str | None
    reversibility: Reversibility
    evidence_effect: EvidenceEffect
    authority: AuthorityClass
    preconditions: tuple[PreconditionKind, ...]
    postconditions: tuple[PostconditionKind, ...]
    max_duration_seconds: int
    d3fend_technique_id: str                     # "UNMAPPED" unless a snapshot verifies it
    catalog_token: object = None                 # see below

    def __post_init__(self) -> None: ...
    # 1. raises unless `catalog_token is _CATALOG_TOKEN` (a module-private object in
    #    operators/catalog.py). An OperatorSpec cannot be built anywhere else.
    # 2. raises if reversibility is not IRREVERSIBLE and rollback_operator_id is None.
    # 3. raises if evidence_effect is DESTROYS and operator_class < O6.
    # 4. raises if authority != required_authority-by-class for operator_class.
    # 5. raises if any LiteralAtom.value fails the metacharacter pattern.

@dataclass(frozen=True, slots=True)
class DefensiveOperator:
    """**The only type the executor accepts.** §45: "Only typed operators reach privilege."
    There is no constructor path from a string, a model output, a text field, an LLM, a
    config value or a deserialised payload to an instance of this class, because `spec`
    must be a CATALOG member by identity and CATALOG entries cannot be built elsewhere."""
    spec: OperatorSpec
    target: ProcessTarget
    incident_id: str
    ttl_seconds: int
    evidence_refs: tuple[EvidenceRef, ...]

    def __post_init__(self) -> None: ...
    # 1. raises ContractError unless `any(self.spec is entry for entry in CATALOG.values())`
    #    — identity, not equality: a structurally-equal forged spec is refused.
    # 2. raises unless target.scope.kind is spec.target_kind.
    # 3. raises unless 0 < ttl_seconds <= spec.max_duration_seconds.
    # 4. raises unless target.scope.host_local.
    def argv(self) -> tuple[str, ...]
    def rollback(self) -> DefensiveOperator | None
    def to_dict(self) -> dict[str, Any]

def assemble_argv(template: Sequence[ArgvAtom], target: ProcessTarget) -> tuple[str, ...]
    """The ONLY place an argument vector is produced. A `match` over ArgvAtom with no
    fallthrough; FieldAtom resolves through a closed TargetField table returning
    `str(int)` or a re-validated identifier. There is no format string, no join into a
    single string, and no caller may pass a template that did not come from a
    CATALOG entry's `argv_template`."""

def no_arbitrary_command_path(package_root: Path) -> tuple[str, ...]
    """AST proof, exported so the gate and the boundary test share one implementation.
    Walks every module under `package_root` and returns `path:lineno` for each of:
    an import of `subprocess`, `os.system`, `os.popen`, `pty`, `shlex` used with
    `shell=True`, a call to `eval`, `exec` or `compile`, an f-string or `%`/`.format()`
    whose result flows into `assemble_argv` or a name containing `argv`/`cmd`/`command`,
    and any `str.join` over an `argv` name. Empty tuple is the property."""
```

```python
# pocketsec/stage5/operators/catalog.py
_CATALOG_TOKEN: object = object()      # module-private. The only way to build an OperatorSpec.
MAX_CATALOG_ENTRIES: int = 32

CATALOG: Mapping[str, OperatorSpec]    # MappingProxyType; 14 entries
CATALOG_BY_CLASS: Mapping[OperatorClass, tuple[str, ...]]

def spec(operator_id: str) -> OperatorSpec          # KeyError -> ContractError
def rollback_spec(operator_id: str) -> OperatorSpec | None
def autonomous_ids(constitution: ResponseConstitution) -> tuple[str, ...]
```

The fourteen entries, and **every one has a handler in `host/simulated.py`**:

| operator_id | class | argv_template | rollback | reversibility | evidence | authority |
|---|---|---|---|---|---|---|
| `OBSERVE_PROCESS_METADATA` | O0 | `[L("procfs.read"), F(PID)]` | — | FULLY_REVERSIBLE | PRESERVES | A0 |
| `HASH_EXECUTABLE` | O0 | `[L("digest.executable"), F(PID)]` | — | FULLY_REVERSIBLE | PRESERVES | A0 |
| `TRACE_PROCESS_BOUNDED` | O0 | `[L("trace.bounded"), F(PID)]` | `STOP_TRACE` | FULLY_REVERSIBLE | PRESERVES | A0 |
| `STOP_TRACE` | O0 | `[L("trace.stop"), F(PID)]` | — | FULLY_REVERSIBLE | NEUTRAL | A0 |
| `SNAPSHOT_PROCESS_STATE` | O1 | `[L("snapshot.process"), F(PID)]` | — | FULLY_REVERSIBLE | PRESERVES | A1 |
| `PRESERVE_VOLATILE_EVIDENCE` | O1 | `[L("preserve.volatile"), F(PID)]` | — | FULLY_REVERSIBLE | PRESERVES | A1 |
| `RESTRICT_LOCAL_SOCKET` | O2 | `[L("socket.restrict"), F(SOCKET_ID)]` | `RELEASE_LOCAL_SOCKET` | FULLY_REVERSIBLE | NEUTRAL | A2 |
| `RELEASE_LOCAL_SOCKET` | O2 | `[L("socket.release"), F(SOCKET_ID)]` | — | FULLY_REVERSIBLE | NEUTRAL | A2 |
| `SUSPEND_PROCESS` | O3 | `[L("process.suspend"), F(PID)]` | `RESUME_PROCESS` | FULLY_REVERSIBLE | DEGRADES_VOLATILE | A2 |
| `RESUME_PROCESS` | O3 | `[L("process.resume"), F(PID)]` | — | FULLY_REVERSIBLE | NEUTRAL | A2 |
| `REVOKE_LOCAL_SESSION` | O4 | `[L("session.revoke"), F(SESSION_ID)]` | — | DEGRADED | NEUTRAL | A3 |
| `CONSTRAIN_SERVICE` | O5 | `[L("service.constrain"), F(UNIT_NAME)]` | `RELEASE_SERVICE` | REVERSIBLE_WITH_STATE | NEUTRAL | A4 |
| `RELEASE_SERVICE` | O5 | `[L("service.release"), F(UNIT_NAME)]` | — | FULLY_REVERSIBLE | NEUTRAL | A4 |
| `TERMINATE_PROCESS` | O6 | `[L("process.terminate"), F(PID)]` | — | IRREVERSIBLE | DEGRADES_VOLATILE | A5 |

**`OperatorClass.O7_DESTRUCTIVE` has zero catalog entries, and a test asserts
`CATALOG_BY_CLASS[OperatorClass.O7_DESTRUCTIVE] == ()`.** §5's "not autonomous" becomes "not
expressible". This is §4.8's property P5.

**Stage 3's lesson, made a test.** Stage 3 shipped seven of eight operator forms with no
interpreter and measured nothing (ADR-0027). Therefore:
`test_every_catalog_entry_has_a_host_handler` asserts `set(CATALOG) == set(HOST_HANDLERS)` in both
directions, and `test_every_rollback_operator_is_itself_in_the_catalog` asserts every non-None
`rollback_operator_id` is a `CATALOG` key. **Do not define a catalog richer than the executor built
for it.**

**And the other Stage 3 lesson:** before building the representation, check the thing it must express
is expressible. `test_catalog_expresses_every_architecture_operator_example` asserts one catalog
entry per non-empty cell of architecture §5's "Operator examples" column, and
`test_catalog_expresses_the_architecture_section_6_example` builds §6's exact allowed ActionObject
(`SUSPEND_PROCESS`, target pid, target identity hash, ttl, rollback `RESUME_PROCESS`, incident) as a
`DefensiveOperator` and asserts every field of §6's example maps to a field of the result.

**Bounds:** ≤ 32 catalog entries; `argv_template` ≤ 8 atoms; `LiteralAtom.value` ≤ 64 chars matching
`^[A-Za-z0-9._/-]{1,64}$`; `max_duration_seconds` ≤ 900.

### D5.16 — D3FEND adapter `[operators]`

```python
# pocketsec/stage5/operators/d3fend.py
UNMAPPED: str = "UNMAPPED"
D3FEND_ID_PATTERN = re.compile(r"^D3-[A-Z]{2,7}$")
D3FEND_SNAPSHOT_PATH: Path = REPO_ROOT / "baselines" / "d3fend-technique-ids.json"
D3FEND_RELEASE: str | None = None      # None until a real snapshot is committed

@dataclass(frozen=True, slots=True)
class D3FENDSnapshot:
    release: str
    technique_names: Mapping[str, str]   # id -> published name
    source_note: str
    def __post_init__(self) -> None: ...  # every key must match D3FEND_ID_PATTERN

@dataclass(frozen=True, slots=True)
class D3FENDMapping:
    operator_id: str
    technique_id: str
    technique_name: str
    release: str
    def __post_init__(self) -> None: ...
    # raises unless technique_id matches the pattern AND is present in the loaded
    # snapshot AND release == snapshot.release. There is no path to a mapping
    # without a snapshot.

def load_snapshot(path: Path = D3FEND_SNAPSHOT_PATH) -> D3FENDSnapshot | None
def mapping_for(operator_id: str) -> D3FENDMapping | None      # None means UNMAPPED
def mapped_fraction() -> float
def unmapped_operator_ids() -> tuple[str, ...]
```

**Policy, and it is not negotiable: a wrong external identifier is worse than an absent one.** No
D3FEND id is written into this repository from memory. Every catalog entry ships
`d3fend_technique_id = "UNMAPPED"`. A mapping becomes possible only when a dated snapshot from a
real D3FEND release is committed to `baselines/d3fend-technique-ids.json` with its provenance in
`source_note`; until then `load_snapshot()` returns `None`, `mapped_fraction()` returns `0.0`, and
the findings document records D3FEND coverage as **0 of 14 mapped, 14 UNMAPPED**. No network access
is assumed in this environment, so the expected outcome is exactly that.

**D3FEND is vocabulary, never a decision oracle** — MITRE says so itself (§28). Enforced by AST:
`test_no_privileged_module_imports_d3fend` asserts that no module under `pocketsec/stage5/sentinel/`,
`executor/`, `authority/` or `constitution/` imports `pocketsec.stage5.operators.d3fend`.

### D5.4 — SENTINEL independent constraint kernel `[sentinel]`

```python
# pocketsec/stage5/sentinel/kernel.py
SENTINEL_KERNEL_VERSION: str = "sentinel-1.0.0"

class Decision(StrEnum):
    PASS = "PASS"
    DENY = "DENY"

class DenyReason(StrEnum):
    """§4's verification list, one member per bullet, plus the fail-closed members."""
    SCHEMA = "SCHEMA"
    SIGNATURE_VERSION = "SIGNATURE_VERSION"
    AUTHORITY = "AUTHORITY"
    SCOPE = "SCOPE"
    TARGET_IDENTITY = "TARGET_IDENTITY"
    PRECONDITION = "PRECONDITION"
    MISSION_INVARIANT = "MISSION_INVARIANT"
    EVIDENCE_PRESERVATION = "EVIDENCE_PRESERVATION"
    ROLLBACK_MISSING = "ROLLBACK_MISSING"
    EXPIRY = "EXPIRY"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    FORBIDDEN_COMBINATION = "FORBIDDEN_COMBINATION"
    CONSTITUTION = "CONSTITUTION"
    KERNEL_FAULT = "KERNEL_FAULT"          # a check raised. Fail closed.
    MISSING_INPUT = "MISSING_INPUT"        # a required input was None. Fail closed.

CHECK_ORDER: tuple[str, ...]               # 13 named checks, evaluated in this order

@dataclass(frozen=True, slots=True)
class SentinelVerdict:
    decision: Decision
    reasons: tuple[DenyReason, ...]
    detail: str
    operator_id: str
    target_digest: str
    evaluated_checks: tuple[str, ...]
    kernel_version: str = SENTINEL_KERNEL_VERSION
    def __post_init__(self) -> None: ...
    # raises if decision is DENY with an empty `reasons`, or PASS with a non-empty one,
    # or if `evaluated_checks` != CHECK_ORDER when decision is PASS. A PASS that did not
    # run every check is not a PASS.
    def to_dict(self) -> dict[str, Any]

FORBIDDEN_COMBINATIONS: frozenset[frozenset[str]]
# e.g. {SUSPEND_PROCESS, REVOKE_LOCAL_SESSION} on one incident within MIN_DWELL; and
# {CONSTRAIN_SERVICE} on a unit in MissionInvariantSet.critical_units().

class SentinelKernel:
    """§4. Deliberately simpler than AEGIS, small enough for exhaustive testing.

    Independence by construction:
      * `__init__` takes exactly three parameters. There is no parameter, attribute,
        module constant or environment variable through which a plan, a score, a
        confidence, a verdict or a bypass can enter.
      * The module defines no name matching
        `force|override|bypass|skip|disable|enable|dry_run|trust|unsafe` —
        asserted by AST in tests/test_stage5_sentinel.py and again in the gate.
      * `verify` catches BaseException from every individual check and converts it to
        DENY/KERNEL_FAULT. A kernel that crashes denies; it never abstains.
      * A None in any required argument is DENY/MISSING_INPUT, not a skipped check.
    """
    def __init__(self, *, constitution: ResponseConstitution,
                 invariants: MissionInvariantSet, clock: Clock) -> None

    def verify(self, operator: DefensiveOperator, token: CapabilityToken, *,
               evidence: EvidencePreservationVerdict,
               observed_identity: ProcessIdentity | None,
               snapshot: HostSnapshot,
               journal_bytes: int,
               active_leases: int,
               recent_action_times: Sequence[int],
               concurrent_operator_ids: frozenset[str]) -> SentinelVerdict
```

The thirteen checks of `CHECK_ORDER`, each a private method returning
`tuple[DenyReason, ...]`: `schema`, `signature_version`, `constitution`, `authority`, `scope`,
`target_identity`, `preconditions`, `mission_invariants`, `evidence_preservation`,
`rollback_expiry`, `resource_limits`, `forbidden_combinations`, `lease_capacity`.

**The test that the gate runs, and that the lead named:** for **every** operator in `CATALOG`, with
the planner maximally in favour (a plan whose `expected_security_delta` is maximal and whose
`uncertainty` is 0.0, and a `Verdict.MALICIOUS` at `confidence=1.0` in the resolution), SENTINEL's
veto still holds when any one of its thirteen inputs is made non-compliant. And the four ways a
kernel is *not* independent are each tested:

1. **a flag** — `test_sentinel_module_defines_no_bypass_name` (AST over the module).
2. **a None** — `test_sentinel_denies_on_missing_input`, one case per optional-looking argument.
3. **a missing config** — `test_sentinel_cannot_be_built_from_a_weaker_constitution`: a
   `ResponseConstitution` with a shortened law tuple raises in `ResponseConstitution.__post_init__`
   before the kernel exists.
4. **an exception** — `test_sentinel_denies_when_a_check_raises`, monkeypatching each of the
   thirteen checks in turn and asserting `DENY` with `KERNEL_FAULT`, thirteen times.

And the structural one: `test_sentinel_kernel_init_has_exactly_three_parameters` reads
`inspect.signature(SentinelKernel.__init__)` and asserts the keyword-only parameter name set is
exactly `{"constitution", "invariants", "clock"}`.

**SENTINEL shares no state with the planner.** `test_sentinel_shares_no_mutable_state_with_aegis`
asserts, by AST, that no module under `pocketsec/stage5/sentinel/` imports anything under
`pocketsec/stage5/aegis/`, `safe/`, `twin/`, `memory/` or `cells/`, and that `SentinelKernel` holds
no attribute whose type is defined in those packages.

### D5.10 — Evidence Preservation Gate `[sentinel]`

```python
# pocketsec/stage5/evidence/preservation_gate.py
MAX_BUNDLE_BYTES: int = 65536
MAX_VOLATILE_SIGNALS: int = 16

class PreservationDecision(StrEnum):
    PRESERVED = "PRESERVED"
    REFUSED_WOULD_DESTROY = "REFUSED_WOULD_DESTROY"
    EXCEPTION_GRANTED = "EXCEPTION_GRANTED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

@dataclass(frozen=True, slots=True)
class PreActionBundle:
    """§13's PRE-ACTION BUNDLE, field for field."""
    incident_id: str
    evidence_refs: tuple[EvidenceRef, ...]
    volatile_preserved: tuple[str, ...]
    pre_action_state: Mapping[str, Any]        # process/service/session snapshot rows
    rationale_claim_ids: tuple[str, ...]
    policy_version: str
    component_versions: Mapping[str, str]      # action/policy/kernel/catalog versions
    rollback_state: Mapping[str, Any]
    integrity_digest: str                      # digest over canonical bytes of all of the above
    def canonical_bytes(self) -> bytes
    def to_dict(self) -> dict[str, Any]
    @classmethod
    def build(cls, *, incident_id: str, operator: DefensiveOperator,
              resolution: CBFResolutionV1, snapshot: HostSnapshot,
              rollback_state: Mapping[str, Any]) -> PreActionBundle

@dataclass(frozen=True, slots=True)
class EvidencePreservationVerdict:
    decision: PreservationDecision
    bundle: PreActionBundle | None
    destroyed_signals: tuple[str, ...]
    unpreservable_signals: tuple[str, ...]
    exception_authority: AuthorityClass | None
    detail: str
    def __post_init__(self) -> None: ...
    # raises if decision is PRESERVED with a None bundle, or EXCEPTION_GRANTED with a
    # None exception_authority, or if exception_authority is below A5.

@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    required_signals: frozenset[str]
    volatile_signals: frozenset[str]
    uniquely_necessary: frozenset[str]     # destroying one of these is refused outright
    retention_seconds: int

DEFAULT_RETENTION: RetentionPolicy

class EvidencePreservationGate:
    def __init__(self, *, policy: RetentionPolicy, invariants: MissionInvariantSet) -> None
    def evaluate(self, *, operator: DefensiveOperator, resolution: CBFResolutionV1,
                 snapshot: HostSnapshot, rollback_state: Mapping[str, Any],
                 exception: AuthorityGrant | None = None
                 ) -> EvidencePreservationVerdict
```

**The gate runs before the action, never after.** Enforced by construction, not by ordering
discipline: `TransactionalExecutor._commit()` takes `bundle: PreActionBundle` as a **required,
non-optional positional parameter**. There is no way to reach COMMIT without a bundle, and the only
producer of a bundle is this gate. §4.8's property P9.

`evaluate()` returns `REFUSED_WOULD_DESTROY` when
`operator.spec.evidence_effect in {DEGRADES_VOLATILE, DESTROYS}` and the signals that would be lost
intersect `policy.uniquely_necessary` — and **the refusal is recorded**: the executor writes a
`TransactionReceipt` with `outcome=Outcome.REFUSED_EVIDENCE` and the verdict's
`destroyed_signals`, which flows into `ResponseRecordV1.sentinel_denials`. A refusal that leaves no
trace is a refusal nobody can audit.

`EXCEPTION_GRANTED` requires an `AuthorityGrant` at `A5` from `GrantSource.HUMAN`. A policy grant
cannot open it.

**Bounds:** bundle canonical bytes ≤ 64 KiB (`MAX_BUNDLE_BYTES`); ≤ 16 volatile signals; a bundle
over budget truncates `pre_action_state` rows with an explicit `truncations` entry and **never**
truncates `evidence_refs` or `rollback_state` — it fails instead.

### D5.22 — Adversarial Response Defense monitors `[sentinel]`

Architecture §33 names eleven attack families and says *"Each attack family has a required
regression test."* Eight are runtime-observable and become monitors; three are covered by
construction elsewhere and are cross-referenced rather than duplicated.

```python
# pocketsec/stage5/sentinel/monitors.py
MAX_MONITOR_HISTORY: int = 64

class MonitorId(StrEnum):
    SELF_DOS_INDUCTION = "SELF_DOS_INDUCTION"
    CRITICAL_PROCESS_BAITING = "CRITICAL_PROCESS_BAITING"
    ACTION_OSCILLATION = "ACTION_OSCILLATION"
    CANDIDATE_EXPLOSION = "CANDIDATE_EXPLOSION"
    ROLLBACK_SABOTAGE = "ROLLBACK_SABOTAGE"
    DEPENDENCY_POISONING = "DEPENDENCY_POISONING"
    FALSE_CERTAINTY = "FALSE_CERTAINTY"
    EXECUTOR_FAULT_BURST = "EXECUTOR_FAULT_BURST"

class Severity(StrEnum):
    INFO = "INFO"
    ESCALATE = "ESCALATE"
    HALT_AUTONOMY = "HALT_AUTONOMY"

@dataclass(frozen=True, slots=True)
class MonitorFinding:
    monitor: MonitorId
    fired: bool
    severity: Severity
    detail: str
    observed_value: float | int
    threshold: float | int

class ResponseDefenseMonitors:
    """Bounded ring buffers only; MAX_MONITOR_HISTORY entries per monitor."""
    def __init__(self, *, invariants: MissionInvariantSet, budget: ResourceBudget) -> None
    def observe_plan(self, plan: ResponsePlan, resolution: CBFResolutionV1) -> tuple[MonitorFinding, ...]
    def observe_receipt(self, receipt: TransactionReceipt) -> tuple[MonitorFinding, ...]
    def halted(self) -> bool
    def findings(self) -> tuple[MonitorFinding, ...]
```

| §33 attack | where it is defended | the regression test |
|---|---|---|
| self-denial-of-service induction | `SELF_DOS_INDUCTION` monitor + `MAX_AUTONOMOUS_DOWNTIME` invariant | `labs/adversarial_load.py::self_dos_suite` |
| critical-process baiting | `MissionInvariantSet.critical_units()` refusal in SENTINEL | `test_sentinel_refuses_a_baited_critical_unit` |
| log/prompt action injection | **by construction**: `ArgvAtom`, catalog identity, `no_arbitrary_command_path` | `test_a_string_cannot_reach_the_executor` |
| PID reuse / target substitution | `ProcessIdentity.digest()` + `revalidate()` in COMMIT | `labs/toctou.py::pid_reuse_suite` |
| TOCTOU between plan and execution | revalidation inside COMMIT (D5.11) | `labs/toctou.py::toctou_suite` |
| capability-token replay | `TokenStore.redeem` single-use nonce | `test_a_redeemed_token_is_replayed` |
| rollback sabotage | `ROLLBACK_SABOTAGE` monitor + journal digest chain | `labs/adversarial_load.py::rollback_sabotage_suite` |
| dependency poisoning | `DEPENDENCY_POISONING` monitor; unknown deps raise shadow | `test_poisoned_dependency_raises_shadow_not_confidence` |
| action oscillation | `HysteresisController` + `ACTION_OSCILLATION` monitor | `test_hysteresis_stops_thrashing` |
| candidate-action explosion | `ResourceGovernor.prune` + `CANDIDATE_EXPLOSION` | `labs/adversarial_load.py::candidate_flood` |
| false Stage-4 certainty designed to trigger containment | `FALSE_CERTAINTY` monitor **and** the confidence-invariance property | `test_confidence_099_and_001_reach_the_same_authority` |

`FALSE_CERTAINTY` fires when a resolution presents `uncertainty <= 0.01` while
`len(truncations) + len(degradations) > 0`, or while two hypotheses have `support` within
`IDENTIFIABILITY_MARGIN`. A resolution that claims certainty it cannot have raises Action Shadow and
**never** raises authority.

---

### The simulated host model `[operators]` — labelled as such, everywhere

This module is the reason §6.1 can be honest. It is **not** a deliverable of its own; it is the
substrate D5.11, D5.13 and D5.14 are measured against, and its existence changes what those
measurements mean.

```python
# pocketsec/stage5/host/simulated.py
SIMULATED_HOST_VERSION: str = "stage5-simulated-host-v0.1.0"

class HostKind(StrEnum):
    SIMULATED = "SIMULATED"
    REAL = "REAL"          # no implementation exists in this repository, deliberately

class ProcessState(StrEnum):
    RUNNING = "RUNNING"
    SUSPENDED = "SUSPENDED"
    EXITED = "EXITED"

@dataclass(frozen=True, slots=True)
class ProcessRow:
    identity: ProcessIdentity
    state: ProcessState
    unit: str | None
    session_id: str | None
    socket_ids: tuple[str, ...]
    children: tuple[int, ...]
    volatile_signals: tuple[str, ...]      # what is observable now and lost if the process dies

@dataclass(frozen=True, slots=True)
class ServiceRow:
    unit: str
    running: bool
    constrained: bool
    restartable: bool
    depends_on: tuple[str, ...]
    healthy: bool

@dataclass(frozen=True, slots=True)
class HostSnapshot:
    """Read-only. The planner, the twin and the cone see ONLY this; they never see the
    HostAdapter, so no planning code can mutate the host even by accident."""
    host_kind: HostKind
    at: int
    processes: tuple[ProcessRow, ...]
    services: tuple[ServiceRow, ...]
    sessions: tuple[str, ...]
    restricted_sockets: frozenset[str]
    security_state: SecurityStateV1
    host_version: str = SIMULATED_HOST_VERSION
    def process(self, pid: int) -> ProcessRow | None
    def identity(self, pid: int) -> ProcessIdentity | None
    def service(self, unit: str) -> ServiceRow | None
    def to_dict(self) -> dict[str, Any]

class HostAdapter(Protocol):
    """The privileged surface. Exactly four methods, all taking typed arguments."""
    @property
    def host_kind(self) -> HostKind: ...
    def snapshot(self) -> HostSnapshot: ...
    def observe_identity(self, pid: int) -> ProcessIdentity | None: ...
    def apply(self, operator: DefensiveOperator, argv: tuple[str, ...]) -> HostEffect: ...

@dataclass(frozen=True, slots=True)
class HostEffect:
    applied: bool
    changed: tuple[str, ...]
    failure: HostFailure | None
    evidence_lost: tuple[str, ...]
    collateral_units: tuple[str, ...]

class HostFailure(StrEnum):
    TARGET_GONE = "TARGET_GONE"
    PERMISSION = "PERMISSION"
    ENFORCEMENT_SILENTLY_FAILED = "ENFORCEMENT_SILENTLY_FAILED"
    DEPENDENCY_RESTART = "DEPENDENCY_RESTART"
    ROLLBACK_UNAVAILABLE = "ROLLBACK_UNAVAILABLE"

@dataclass(frozen=True, slots=True)
class FaultProfile:
    """Deterministic fault injection, seeded. Every probability is a PARAMETER of the
    simulator, not a measurement of anything."""
    seed: int
    enforcement_failure_rate: float = 0.0
    rollback_failure_rate: float = 0.0
    pid_reuse_rate: float = 0.0
    dependency_restart_rate: float = 0.0
    attacker_adapts: bool = False

HOST_HANDLERS: Mapping[str, Callable[[SimulatedHost, DefensiveOperator], HostEffect]]

class SimulatedHost:
    """`host_kind` is SIMULATED and there is no constructor argument that changes it."""
    def __init__(self, *, processes: Sequence[ProcessRow], services: Sequence[ServiceRow],
                 sessions: Sequence[str], security_state: SecurityStateV1,
                 faults: FaultProfile, clock: Clock) -> None
    @property
    def host_kind(self) -> HostKind                  # returns HostKind.SIMULATED, always
    def snapshot(self) -> HostSnapshot
    def observe_identity(self, pid: int) -> ProcessIdentity | None
    def apply(self, operator: DefensiveOperator, argv: tuple[str, ...]) -> HostEffect
    def advance(self, seconds: int) -> None          # the attacker/environment steps here
    def reap(self, pid: int, *, reuse_pid_for: ProcessIdentity | None = None) -> None
```

Three rules that make this honest rather than self-congratulatory:

1. **`SimulatedHost.host_kind` is a property returning a constant.** There is no flag, no
   subclass and no argument that makes a simulated host claim to be real.
   `test_simulated_host_cannot_claim_to_be_real` asserts it.
2. **Every `TransactionReceipt` carries `host_kind` and `simulated: bool`, both required and
   non-defaulted**, and `ResponseRecordV1.to_dict()` raises on the inconsistent combination (§3.3).
3. **A number produced by this simulator is a property of this simulator.** Rollback reliability,
   collateral rate and time-to-effect measured here are reported as
   `simulated_rollback_success`, `simulated_collateral_per_1000`, `simulated_time_to_effect_units`
   — names that carry the caveat into every table — and real-host rollback reliability is recorded
   **UNMEASURED**. ADR-0046. §6.1 and §9.1.

There is deliberately **no** `RealHost` class, not even a stub. A stub would be the thing someone
fills in under deadline pressure. Implementing one is Stage 5's follow-on work and needs its own
ADR outside this block.

### D5.11 — Transactional privileged executor `[executor]`

```python
# pocketsec/stage5/executor/identity.py
class Clock(Protocol):
    def now(self) -> int: ...          # monotonic whole seconds

class ManualClock:
    """A clock that does NOT advance on its own. Every expiry test uses it (§4.8 P7)."""
    def __init__(self, at: int = 0) -> None
    def now(self) -> int
    def advance(self, seconds: int) -> None

class SystemClock:
    def now(self) -> int               # time.monotonic_ns() // 1_000_000_000

def identity_digest(identity: ProcessIdentity) -> str
    """THE key-space function. `CapabilityToken.target_digest`, `TransactionReceipt.
    target_digest`, `Lease.target_digest`, `EffectivenessRecord` context keys and the
    journal's action key are ALL produced by this one function. §4.9's key-space rule."""

class IdentityRevalidation(StrEnum):
    MATCH = "MATCH"
    EXITED = "EXITED"
    PID_REUSED = "PID_REUSED"
    EXECUTABLE_CHANGED = "EXECUTABLE_CHANGED"
    UID_CHANGED = "UID_CHANGED"
    UNOBSERVABLE = "UNOBSERVABLE"

def revalidate(expected: ProcessIdentity,
               observed: ProcessIdentity | None) -> IdentityRevalidation
    """`None` observed is EXITED, never MATCH. A differing `start_time_ticks` at the same
    pid is PID_REUSED. A differing `executable_digest` where both are non-None is
    EXECUTABLE_CHANGED. Where `expected.executable_digest` is None and the observed one is
    not, the result is UNOBSERVABLE — an absence of evidence is not a match."""

ACTIONABLE_REVALIDATIONS: frozenset[IdentityRevalidation] = frozenset({IdentityRevalidation.MATCH})
```

```python
# pocketsec/stage5/executor/journal.py
MAX_JOURNAL_BYTES: int = 262144
MAX_JOURNAL_ENTRIES: int = 512

@dataclass(frozen=True, slots=True)
class JournalEntry:
    action_id: str
    phase: Phase
    at: int
    operator_id: str
    target_digest: str
    payload_digest: str
    previous_digest: str        # chain, as ExperimentRegistry chains
    entry_digest: str

@dataclass(frozen=True, slots=True)
class JournalTruncation:
    what: str
    identifier: str
    reason: str
    bytes_dropped: int

class RollbackJournal:
    """Append-only, digest-chained, BOUNDED. On overflow it refuses a new action rather
    than evicting rollback state for a live lease — evicting it would turn a reversible
    intervention into a permanent one, which is the failure mode §18 exists to prevent."""
    def __init__(self, *, max_bytes: int = MAX_JOURNAL_BYTES,
                 max_entries: int = MAX_JOURNAL_ENTRIES) -> None
    def append(self, *, action_id: str, phase: Phase, at: int, operator: DefensiveOperator,
               payload: Mapping[str, Any]) -> JournalEntry
    def rollback_state(self, action_id: str) -> Mapping[str, Any] | None
    def release(self, action_id: str) -> None          # only after FINALIZE with no live lease
    def bytes_used(self) -> int
    def full(self) -> bool
    def verify_chain(self) -> tuple[str, ...]          # () is the property
    def truncations(self) -> tuple[JournalTruncation, ...]
```

```python
# pocketsec/stage5/executor/transactional.py
TRANSACTION_RECEIPT_V1_ID = "pocketsec.transaction_receipt.v1"
TRANSACTION_RECEIPT_V1_VERSION = register_schema(TRANSACTION_RECEIPT_V1_ID, "1.0.0")

class Phase(StrEnum):
    PREPARE = "PREPARE"
    COMMIT = "COMMIT"
    VERIFY = "VERIFY"
    ROLLBACK = "ROLLBACK"
    FINALIZE = "FINALIZE"

class Outcome(StrEnum):
    COMMITTED_VERIFIED = "COMMITTED_VERIFIED"
    COMMITTED_UNVERIFIED = "COMMITTED_UNVERIFIED"
    ROLLED_BACK = "ROLLED_BACK"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"
    REFUSED_SENTINEL = "REFUSED_SENTINEL"
    REFUSED_EVIDENCE = "REFUSED_EVIDENCE"
    REFUSED_IDENTITY = "REFUSED_IDENTITY"
    REFUSED_TOKEN = "REFUSED_TOKEN"
    REFUSED_JOURNAL_FULL = "REFUSED_JOURNAL_FULL"
    ESCALATED = "ESCALATED"

@dataclass(frozen=True, slots=True)
class PhaseRecord:
    phase: Phase
    at: int
    ok: bool
    detail: str

@dataclass(frozen=True, slots=True)
class TransactionReceipt:
    """§16's immutable ResponseRecord. The type Stage 6 consumes (integration plan §3.2)."""
    receipt_id: str
    action_id: str
    incident_id: str
    resolution_id: str
    operator_id: str
    operator_class: OperatorClass
    target_digest: str
    outcome: Outcome
    phases: tuple[PhaseRecord, ...]
    sentinel_verdict: SentinelVerdict
    token_verdict: TokenVerdict
    identity_revalidation: IdentityRevalidation
    evidence_bundle_digest: str | None
    lease_id: str | None
    postconditions: tuple[PostconditionResult, ...]
    verification: VerificationOutcome | None
    residual: InterventionResidual | None
    rollback_attempted: bool
    rollback_succeeded: bool | None            # None means not attempted; never False-by-default
    host_kind: HostKind
    simulated: bool
    work_units: int
    loadavg: tuple[float, float, float]
    epoch_id: int
    schema_version: str = TRANSACTION_RECEIPT_V1_VERSION

    def __post_init__(self) -> None: ...
    # raises if outcome is COMMITTED_VERIFIED while any postcondition.satisfied is not True;
    # raises if outcome is COMMITTED_* while sentinel_verdict.decision is DENY;
    # raises if rollback_attempted is False while rollback_succeeded is not None;
    # raises if simulated is True while host_kind is REAL, and vice versa;
    # raises if `phases` is not a prefix-ordered subsequence of Phase's declaration order.
    def to_dict(self) -> dict[str, Any]

class TransactionalExecutor:
    """§35's minimal privileged executor. No ML, no LLM, no hypothesis generation, no
    network-facing API — asserted by AST in tests/test_stage5_boundary.py.

    `execute` is the ONLY public entry point and its first parameter is annotated exactly
    `DefensiveOperator`. Trust rule T4 asserts that annotation by reading
    `typing.get_type_hints(TransactionalExecutor.execute)`."""
    def __init__(self, *, kernel: SentinelKernel, host: HostAdapter,
                 journal: RollbackJournal, gate: EvidencePreservationGate,
                 governor: ResourceGovernor, leases: LeaseRegistry,
                 probe: PostconditionProbe, clock: Clock) -> None

    def execute(self, operator: DefensiveOperator, token: CapabilityToken, *,
                resolution: CBFResolutionV1) -> TransactionReceipt

    def _prepare(self, operator: DefensiveOperator, token: CapabilityToken, *,
                 resolution: CBFResolutionV1) -> tuple[PreActionBundle, SentinelVerdict]
    def _commit(self, operator: DefensiveOperator, bundle: PreActionBundle) -> HostEffect
    def _verify(self, operator: DefensiveOperator) -> tuple[PostconditionResult, ...]
    def _rollback(self, operator: DefensiveOperator, bundle: PreActionBundle) -> bool
    def _finalize(self, receipt: TransactionReceipt) -> None
```

**The protocol, and where the TOCTOU defence actually lives (§16, §17).**

```
PREPARE   governor.spend(HOST_CALL)
          token = store.redeem(token, operator=operator)     -> not VALID ⇒ REFUSED_TOKEN
          bundle = gate.evaluate(...)                        -> not PRESERVED/EXCEPTION ⇒ REFUSED_EVIDENCE
          journal.append(PREPARE, payload=bundle.to_dict())  -> full ⇒ REFUSED_JOURNAL_FULL
          verdict = kernel.verify(...)                       -> DENY ⇒ REFUSED_SENTINEL
COMMIT    observed = host.observe_identity(operator.target.identity.pid)
          if revalidate(expected, observed) not in ACTIONABLE_REVALIDATIONS: REFUSED_IDENTITY
          effect = host.apply(operator, operator.argv())
VERIFY    results = probe.probe(operator, host)
          outcome = verification_outcome(results)
          if outcome in {INEFFECTIVE, DIVERGENT}: ROLLBACK
ROLLBACK  rollback = operator.rollback(); apply; re-probe; record success as True/False
FINALIZE  receipt written; journal.release only when no live lease references the action
```

**The revalidation is inside `_commit`, immediately before `host.apply`, in the same function, with
no intervening await, callback or lock release.** `test_identity_is_revalidated_inside_commit`
asserts by AST that within `_commit`'s body the call to `revalidate` precedes the call to
`host.apply` and that no other call sits between them. A comment cannot satisfy this test.

**The race, built and run** (`labs/toctou.py`): `SimulatedHost.reap(pid, reuse_pid_for=other)` is
called between `_prepare` and `_commit` through a `FaultProfile(pid_reuse_rate=1.0)` hook. Assert
`outcome is Outcome.REFUSED_IDENTITY`, that `host.apply` was never called (the simulated host counts
calls), and that the wrong process is untouched in the post-snapshot. Four variants: EXITED,
PID_REUSED, EXECUTABLE_CHANGED, UID_CHANGED.

**Bounds:** one in-flight transaction per executor instance (`_active: str | None`, and a second
`execute` while one is active raises); journal ≤ 256 KiB / 512 entries; ≤ 4 concurrent leases;
≤ 8 autonomous actions per 3600 s window.

### D5.12 — Lease + hysteresis controller `[executor]`

```python
# pocketsec/stage5/executor/lease.py
MAX_CONCURRENT_LEASES: int = 4
MAX_RENEWALS: int = 3
MAX_LEASE_LIFETIME_SECONDS: int = 3600
DEFAULT_LEASE_TTL_SECONDS: int = 300

@dataclass(frozen=True, slots=True)
class Lease:
    """§18. Expiry is a PURE FUNCTION of the data, so a lease is expired whether or not
    anybody asked. The sweep is what performs the rollback; the expiry is what is true."""
    lease_id: str
    action_id: str
    incident_id: str
    operator_id: str
    target_digest: str
    granted_at: int
    ttl_seconds: int
    maximum_lifetime_seconds: int
    renewals: int
    rollback_operator_id: str | None
    def expires_at(self) -> int
    def hard_deadline(self) -> int
    def expired(self, now: int) -> bool
    def to_dict(self) -> dict[str, Any]

class LeaseDenialReason(StrEnum):
    CAPACITY = "CAPACITY"
    MAX_RENEWALS = "MAX_RENEWALS"
    HARD_DEADLINE = "HARD_DEADLINE"
    NO_RENEWAL_EVIDENCE = "NO_RENEWAL_EVIDENCE"
    NO_ROLLBACK_OPERATOR = "NO_ROLLBACK_OPERATOR"
    UNKNOWN_LEASE = "UNKNOWN_LEASE"

@dataclass(frozen=True, slots=True)
class LeaseDenial:
    reason: LeaseDenialReason
    detail: str

@dataclass(frozen=True, slots=True)
class RenewalEvidence:
    """A renewal needs evidence, not a timer. §18: "expire by design unless evidence
    justifies renewal"."""
    resolution_id: str
    supporting_claim_ids: tuple[str, ...]
    leading_support: float
    def sufficient(self, *, min_support: float) -> bool

@dataclass(frozen=True, slots=True)
class LeaseExpiry:
    lease: Lease
    at: int
    rollback_operator_id: str | None
    rolled_back: bool | None       # None until the sweeper's executor call returns

class LeaseRegistry:
    def __init__(self, *, clock: Clock, max_concurrent: int = MAX_CONCURRENT_LEASES) -> None
    def grant(self, *, operator: DefensiveOperator, action_id: str,
              ttl_seconds: int) -> Lease | LeaseDenial
    def renew(self, lease_id: str, *, evidence: RenewalEvidence,
              now: int) -> Lease | LeaseDenial
    def release(self, lease_id: str) -> None
    def active(self, now: int) -> tuple[Lease, ...]
    def expired(self, now: int) -> tuple[Lease, ...]
    def tick(self, now: int) -> tuple[LeaseExpiry, ...]      # the EXPLICIT sweep
    def leases_on(self, target_digest: str) -> tuple[Lease, ...]

class LeaseSweeper:
    """Drives `tick` and executes each expiry's rollback. Owned by the CLI and the gate;
    there is no implicit sweep hidden inside another call path, because "expiry checked
    only when something else happens to call in" is a permanent change with an optimistic
    docstring."""
    def __init__(self, *, registry: LeaseRegistry, executor: TransactionalExecutor,
                 tokens: TokenStore, clock: Clock) -> None
    def sweep(self, *, now: int) -> tuple[LeaseExpiry, ...]
```

**The expiry test, with the clock the lead named.** `ManualClock` never advances on its own.

- `test_a_lease_is_expired_by_data_not_by_a_call`: grant at t=0 with ttl=300; `clock.advance(301)`;
  assert `lease.expired(clock.now())` is `True` **before any registry method is called**.
- `test_the_sweep_rolls_back_every_expired_lease`: two leases; advance past both; `sweep()` returns
  two `LeaseExpiry` rows with `rolled_back is True`, and the simulated host shows both targets
  restored.
- `test_a_lease_without_a_rollback_operator_is_never_granted`: `grant` returns
  `LeaseDenial(NO_ROLLBACK_OPERATOR)` for an operator whose `rollback_operator_id` is `None` and
  whose class is ≥ O2. An unrollbackable restriction cannot be leased.
- `test_the_hard_deadline_beats_renewal`: three successful renewals, then a fourth is
  `MAX_RENEWALS`; separately, a renewal that would cross `hard_deadline()` is `HARD_DEADLINE` even
  with perfect evidence.
- `test_no_sweep_means_the_lease_is_still_expired_and_the_host_is_still_changed` — the honest
  negative: without a sweeper, expiry is true and the host is **not** restored. That is the failure
  this design makes visible rather than hiding, and the gate's G5.6 requires the sweeper to be
  wired.

```python
# same file
@dataclass(frozen=True, slots=True)
class HysteresisPolicy:
    """§19. enter > exit, strictly, and __post_init__ raises otherwise."""
    enter_threshold: float
    exit_threshold: float
    min_dwell_seconds: int
    cooldown_seconds: int
    max_action_cycles: int
    escalate_after_rollbacks: int

DEFAULT_HYSTERESIS = HysteresisPolicy(
    enter_threshold=6.0, exit_threshold=3.0, min_dwell_seconds=120,
    cooldown_seconds=300, max_action_cycles=3, escalate_after_rollbacks=2)

class ControlDecision(StrEnum):
    ACT = "ACT"
    HOLD = "HOLD"
    RELEASE = "RELEASE"
    ESCALATE = "ESCALATE"

class HysteresisController:
    def __init__(self, *, policy: HysteresisPolicy, clock: Clock) -> None
    def decide(self, *, target_digest: str, phi_total: float, now: int,
               active_lease: Lease | None) -> ControlDecision
    def note_outcome(self, receipt: TransactionReceipt) -> None
    def cycles(self, target_digest: str) -> int
```

The thresholds are **chosen parameters, not measured values**, and the findings document must say
so. `enter_threshold=6.0` sits between Stage 1's measured benign Φ mean of 0.62 and malicious 9.46
(`MEMORY.md`); that is a *defensible* choice, not a fitted one, and calling it fitted would be a
fabricated result.

### D5.13 — Post-action verification + Intervention Residual `[outcome]`

```python
# pocketsec/stage5/executor/verify.py
class PostconditionKind(StrEnum):
    """§20. Command success is not security success, so the last five members are about
    the incident and the host, not about the call returning."""
    PROCESS_SUSPENDED = "PROCESS_SUSPENDED"
    PROCESS_RESUMED = "PROCESS_RESUMED"
    SOCKET_RESTRICTED = "SOCKET_RESTRICTED"
    SOCKET_RELEASED = "SOCKET_RELEASED"
    SERVICE_CONSTRAINED = "SERVICE_CONSTRAINED"
    SERVICE_RELEASED = "SERVICE_RELEASED"
    SESSION_REVOKED = "SESSION_REVOKED"
    EVIDENCE_PRESENT = "EVIDENCE_PRESENT"
    TRAJECTORY_REDUCED = "TRAJECTORY_REDUCED"
    SERVICE_HEALTH_ACCEPTABLE = "SERVICE_HEALTH_ACCEPTABLE"
    OBSERVATION_RETAINED = "OBSERVATION_RETAINED"
    ATTACKER_PATH_UNCHANGED = "ATTACKER_PATH_UNCHANGED"
    ROLLBACK_STILL_POSSIBLE = "ROLLBACK_STILL_POSSIBLE"

@dataclass(frozen=True, slots=True)
class PostconditionResult:
    kind: PostconditionKind
    satisfied: bool | None        # None == UNVERIFIABLE. ADR-0004's rule: None is not False.
    observed: str
    detail: str

class VerificationOutcome(StrEnum):
    EFFECTIVE = "EFFECTIVE"
    INEFFECTIVE = "INEFFECTIVE"
    DIVERGENT = "DIVERGENT"
    UNVERIFIABLE = "UNVERIFIABLE"

class PostconditionProbe:
    """Lives on the privileged side (§35: "postcondition probe"). Reads the host; never
    writes it."""
    def __init__(self, *, invariants: MissionInvariantSet) -> None
    def probe(self, operator: DefensiveOperator, host: HostAdapter, *,
              before: HostSnapshot, resolution: CBFResolutionV1
              ) -> tuple[PostconditionResult, ...]

def verification_outcome(results: Sequence[PostconditionResult]) -> VerificationOutcome
    """EFFECTIVE only when every result is True. INEFFECTIVE when the operator's own
    state postcondition is False. DIVERGENT when the state postcondition is True but a
    health/observation/attacker-path postcondition is False — the action worked and made
    things worse. UNVERIFIABLE when any required result is None and none is False:
    "An action that cannot be verified cannot be considered successfully completed" (§2)."""
```

```python
# pocketsec/stage5/executor/residual.py
class ResidualComponent(StrEnum):
    PROCESS_STATE = "PROCESS_STATE"
    SERVICE_STATE = "SERVICE_STATE"
    COMMUNICATION = "COMMUNICATION"
    SECURITY_STATE = "SECURITY_STATE"
    EVIDENCE_VISIBILITY = "EVIDENCE_VISIBILITY"
    RECOVERY_CAPABILITY = "RECOVERY_CAPABILITY"

class ResidualCause(StrEnum):
    NONE = "NONE"
    ENFORCEMENT_FAILURE = "ENFORCEMENT_FAILURE"
    HIDDEN_DEPENDENCY = "HIDDEN_DEPENDENCY"
    ATTACKER_ADAPTATION = "ATTACKER_ADAPTATION"
    MODEL_ERROR = "MODEL_ERROR"
    UNATTRIBUTABLE = "UNATTRIBUTABLE"

@dataclass(frozen=True, slots=True)
class InterventionResidual:
    """§21. IR(A) = distance(predicted post-action state, observed post-action state).
    The type Stage 6 consumes (integration plan §3.2)."""
    action_id: str
    distance: float                                   # normalised to [0,1]
    components: Mapping[ResidualComponent, float]
    attribution: ResidualCause
    predicted_digest: str
    observed_digest: str
    detail: str
    def to_dict(self) -> dict[str, Any]

MATERIAL_RESIDUAL: float = 0.25

def intervention_residual(*, prediction: TwinPrediction, observed: HostSnapshot,
                          effect: HostEffect, action_id: str) -> InterventionResidual
    """Distance is a per-component normalised Hamming/ratio mix over the six families,
    averaged. Attribution is a total `match` over a decision table: an
    ENFORCEMENT_SILENTLY_FAILED HostFailure ⇒ ENFORCEMENT_FAILURE; a service the twin did
    not model that changed ⇒ HIDDEN_DEPENDENCY; a new process/socket on the incident's
    lineage after the action ⇒ ATTACKER_ADAPTATION; a modelled node whose predicted value
    was simply wrong ⇒ MODEL_ERROR; anything else non-zero ⇒ UNATTRIBUTABLE."""

def residual_feedback(residual: InterventionResidual) -> Mapping[str, Any]
    """Plain JSON rows for `ResponseRecordV1.residuals`. §21 says residual is fed back to
    Stage 4 CBF and Stage 3 CRYSTAL; Stage 5 does NOT call into those stages — it emits
    rows, and Stage 6's quarantine path decides what becomes trusted. T2/T3."""
```

**`UNATTRIBUTABLE` must be a reachable outcome and a test asserts it fires.** A residual
decomposition that always finds a cause is a decomposition that explains noise.

### D5.14 — Safe-State Recovery Planner `[outcome]`

```python
# pocketsec/stage5/recovery/safe_state.py
MAX_RECOVERY_STEPS: int = 8

@dataclass(frozen=True, slots=True)
class SafeStateManifold:
    """§23's M_safe, as a predicate over a snapshot rather than a binary health flag."""
    invariants: MissionInvariantSet
    required_observation: frozenset[str]
    blocked_trajectory_signals: frozenset[str]

class ManifoldStatus(StrEnum):
    INSIDE = "INSIDE"
    OUTSIDE_RECOVERABLE = "OUTSIDE_RECOVERABLE"
    OUTSIDE_UNRECOVERABLE = "OUTSIDE_UNRECOVERABLE"

@dataclass(frozen=True, slots=True)
class ManifoldVerdict:
    status: ManifoldStatus
    violated: tuple[InvariantViolation, ...]
    missing_observation: tuple[str, ...]
    recovery_path_exists: bool
    detail: str

def in_manifold(snapshot: HostSnapshot, manifold: SafeStateManifold, *,
                leases: Sequence[Lease]) -> ManifoldVerdict

class RecoveryAction(StrEnum):
    CONTINUE = "CONTINUE"
    ROLLBACK_STEP = "ROLLBACK_STEP"
    ESCALATE = "ESCALATE"
    HALT = "HALT"

@dataclass(frozen=True, slots=True)
class RecoveryStep:
    step_index: int
    operator: DefensiveOperator
    expects: tuple[PostconditionKind, ...]
    on_failure: RecoveryAction
    observe_seconds: int

@dataclass(frozen=True, slots=True)
class SafeStatePlan:
    plan_id: str
    incident_id: str
    steps: tuple[RecoveryStep, ...]
    manifold: SafeStateManifold
    def __post_init__(self) -> None: ...   # bound at MAX_RECOVERY_STEPS; step_index dense from 0

@dataclass(frozen=True, slots=True)
class RecoveryReport:
    plan_id: str
    steps_attempted: int
    steps_succeeded: int
    final_status: ManifoldStatus
    receipts: tuple[TransactionReceipt, ...]
    halted_at: int | None
    detail: str
    simulated: bool

class SafeStatePlanner:
    def __init__(self, *, manifold: SafeStateManifold, catalog: Mapping[str, OperatorSpec],
                 governor: ResourceGovernor) -> None
    def plan(self, *, contained: Sequence[Lease], snapshot: HostSnapshot,
             incident_id: str) -> SafeStatePlan

def execute_recovery(plan: SafeStatePlan, *, executor: TransactionalExecutor,
                     tokens: TokenStore, grant: AuthorityGrant,
                     resolution: CBFResolutionV1) -> RecoveryReport
```

**Recovery restores one bounded capability at a time and observes** (§22). `execute_recovery` runs
step *i*, probes, and only then plans step *i+1*'s eligibility; on a failed `expects` it takes the
step's `on_failure` action. It does not restore everything at once, and
`test_recovery_is_incremental_not_wholesale` asserts the host shows at most one changed capability
between consecutive probes.

**`OUTSIDE_UNRECOVERABLE` is a real, reachable answer** — a containment whose rollback operator is
gone from the journal, or whose service lost `restartable`. The test asserts it fires and that
`RecoveryAction.ESCALATE` follows. A recovery planner that always finds a path has not been tested.

### D5.15 — Local Effectiveness Memory `[outcome]`

```python
# pocketsec/stage5/memory/effectiveness.py
MAX_EFFECTIVENESS_RECORDS: int = 256
MIN_SAMPLES_FOR_RATE: int = 8
RESIDUAL_BUCKETS: int = 5

def context_key(*, epoch_id: int, mechanism_id: str, target_kind: TargetKind) -> str
    """THE key function. The planner queries with this and the memory writes with this —
    one function, one key space. Stage 2 lost a whole result to a join between two key
    spaces that could never match (S2-FC-01), and Stage 3 shipped the same class of
    defect; §4.9 makes the structural-identity test mandatory."""

@dataclass(frozen=True, slots=True)
class EffectivenessRecord:
    """§27's EffectStats, field for field."""
    context: str
    operator_id: str
    epoch_id: int
    n: int
    verified_security_effect: int
    no_effect: int
    collateral: int
    rollback_attempts: int
    rollback_successes: int
    time_to_effect_units: tuple[int, ...]       # bounded ring, MAX_TIME_SAMPLES = 16
    residual_buckets: tuple[int, ...]           # length RESIDUAL_BUCKETS
    def effect_rate(self) -> float | None            # None below MIN_SAMPLES_FOR_RATE
    def collateral_rate(self) -> float | None
    def simulated_rollback_success(self) -> float | None
    def to_dict(self) -> dict[str, Any]

class LearningSource(StrEnum):
    """§31's table, as an enum rather than prose."""
    OFFLINE_REPLAY = "OFFLINE_REPLAY"
    LAB_SANDBOX = "LAB_SANDBOX"
    PRODUCTION_OBSERVATION = "PRODUCTION_OBSERVATION"
    HUMAN_APPROVED_ACTION = "HUMAN_APPROVED_ACTION"
    AUTONOMOUS_LOW_IMPACT = "AUTONOMOUS_LOW_IMPACT"

ALLOWED_LEARNING: Mapping[LearningSource, frozenset[OperatorClass]]
# OFFLINE_REPLAY: every class (planning only, no execution)
# LAB_SANDBOX: O0..O6
# PRODUCTION_OBSERVATION: O0, O1        (effect estimation without disruptive exploration)
# HUMAN_APPROVED_ACTION: every class actually executed under a HUMAN grant
# AUTONOMOUS_LOW_IMPACT: O0, O1, O2, O3 only — inside the validated SAFE envelope

class EffectivenessMemory:
    """Bounded to MAX_EFFECTIVENESS_RECORDS with explicit LRU eviction and a
    TruncationRecord per eviction. Epoch-conditioned: a record is never merged across
    epochs, because "safe last epoch" is not evidence after a system change."""
    def __init__(self, *, max_records: int = MAX_EFFECTIVENESS_RECORDS) -> None
    def observe(self, receipt: TransactionReceipt, *, source: LearningSource,
                mechanism_id: str) -> None
    def record(self, *, context: str, operator_id: str) -> EffectivenessRecord | None
    def rollback_reliability(self, *, operator_id: str, epoch_id: int) -> float | None
    def meets_threshold(self, *, operator_id: str, epoch_id: int,
                        threshold: float) -> bool | None
    def evictions(self) -> int
    def rows(self) -> tuple[Mapping[str, Any], ...]

AUTONOMOUS_ROLLBACK_THRESHOLD: float = 0.98
```

`observe()` **refuses** a receipt whose `operator_class` is not in `ALLOWED_LEARNING[source]` —
raising, not silently dropping. That is §31's "PocketSec does not learn high-impact responses by
trial-and-error on production systems" as code.

`meets_threshold` returns `None` below `MIN_SAMPLES_FOR_RATE`, and **`None` blocks autonomy**. G5.7
reads it: an operator proposed as autonomous with fewer than 8 observed rollbacks is not eligible.
`AUTONOMOUS_ROLLBACK_THRESHOLD = 0.98` is a **chosen** threshold; the *measured* rate against a real
host is UNMEASURED (§6.1, ADR-0046).

### D5.17 — Response Knowledge Cells + melting `[outcome]`

```python
# pocketsec/stage5/cells/response_cells.py
RESPONSE_CELL_V1_ID = "pocketsec.response_cell.v1"
RESPONSE_CELL_V1_VERSION = register_schema(RESPONSE_CELL_V1_ID, "1.0.0")

MAX_RESPONSE_CELLS: int = 64
MIN_VERIFIED_EFFECTS_TO_CRYSTALLIZE: int = 5
MIN_DISTINCT_EPOCHS_TO_CRYSTALLIZE: int = 2

@dataclass(frozen=True, slots=True)
class ResponseCellV1:
    """§29. "A response cell is stricter than a detection cell." It reuses Stage 3's
    HardConstraint, CellPhase and AssuranceLevel rather than forking them."""
    cell_id: str
    incident_invariant: str                 # the stable mechanism_id + StateDelta.bitmask signature
    operator_id: str
    target_kind: TargetKind
    authority: AuthorityClass
    mission_invariant_ids: tuple[str, ...]
    rollback_operator_id: str | None
    postconditions: tuple[PostconditionKind, ...]
    verified_effect_n: int
    simulated_rollback_success: float | None
    constraints: tuple[HardConstraint, ...]         # stage3/cells/schema.py:113
    epochs: frozenset[int]
    phase: CellPhase                                # stage3/cells/schema.py:84
    assurance: AssuranceLevel                       # stage3/cells/schema.py:68
    version: int
    parent_cell_id: str | None
    schema_version: str = RESPONSE_CELL_V1_VERSION
    def __post_init__(self) -> None: ...
    # raises if authority exceeds MAX_AUTONOMOUS_AUTHORITY while phase is ACTIVE;
    # raises if rollback_operator_id is None and operator_class >= O2;
    # raises if postconditions is empty — a cell with no verifier is a wish.
    def to_dict(self) -> dict[str, Any]

class MeltTrigger(StrEnum):
    """§30, one member per trigger."""
    DEPENDENCY_DRIFT = "DEPENDENCY_DRIFT"
    SERVICE_EPOCH_CHANGE = "SERVICE_EPOCH_CHANGE"
    RESIDUAL_INCREASE = "RESIDUAL_INCREASE"
    COLLATERAL_INCREASE = "COLLATERAL_INCREASE"
    ROLLBACK_DEGRADATION = "ROLLBACK_DEGRADATION"
    AUTHORITY_POLICY_CHANGE = "AUTHORITY_POLICY_CHANGE"

class MeltScope(StrEnum):
    PARTIAL = "PARTIAL"
    FULL = "FULL"

@dataclass(frozen=True, slots=True)
class ResponseMeltReport:
    cell_id: str
    triggers: tuple[MeltTrigger, ...]
    scope: MeltScope
    demoted_to: CellPhase
    detail: str
    def to_dict(self) -> dict[str, Any]

class ResponseCellField:
    def __init__(self, *, max_cells: int = MAX_RESPONSE_CELLS) -> None
    def crystallize(self, *, memory: EffectivenessMemory, context: str,
                    operator_id: str, invariants: MissionInvariantSet,
                    epoch_id: int) -> ResponseCellV1 | None
    def lookup(self, *, incident_invariant: str,
               epoch_id: int) -> ResponseCellV1 | None
    def melt(self, cell_id: str, *, triggers: Sequence[MeltTrigger]) -> ResponseMeltReport
    def observe_epoch(self, decision: EpochDecision) -> tuple[ResponseMeltReport, ...]
    def state_bytes(self) -> int
```

`crystallize` returns `None` unless `verified_effect_n >= 5`, the record spans
`>= 2` distinct epochs, rollback succeeded every time it was attempted, and the operator's authority
is ≤ `A2`. **Stage 2's G2.13 hit exactly the two-epoch wall — "distinct_epochs 1 < 2, so NOTHING was
exported" — and the honest expectation is that Stage 5's corpus will too.** §6.1 declares it rather
than lowering the bar. Lowering it would make a response cell crystallizable from a single epoch's
evidence, which is the automation-without-questioning failure §30 exists to prevent.

`lookup` is keyed by `incident_invariant` and **the key spaces must be structurally identical**:
`test_cell_lookup_key_matches_the_crystallization_key` asserts the string
`crystallize` stores equals the string a planner's `lookup` builds for the same incident, for 20
corpus cases. §4.9.

---

### D5.2 — SAFE Action Field engine `[field]`

```python
# pocketsec/stage5/safe/action_field.py
MAX_CANDIDATES: int = 16                  # == ResourceBudget.max_candidate_actions
UNDERSTOOD_IDENTIFIABILITY: frozenset[str] = frozenset(
    {"IDENTIFIED", "SEPARABLE", "UNPLANNED", "INSUFFICIENT_EVIDENCE", "UNIDENTIFIABLE", "UNKNOWN"})
RULED_OUT_SUPPORT: float = 0.05
GAP_TO_OBSERVE_OPERATOR: Mapping[str, str]   # closed signal -> O0 operator_id table

@dataclass(frozen=True, slots=True)
class CandidateAction:
    """§3's A_j, field for field. `operator` is the typed operator; there is no
    string anywhere in this dataclass that selects behaviour."""
    candidate_id: str
    operator: DefensiveOperator
    world_applicability: frozenset[str]           # mechanism_ids from the resolution
    expected_security_delta: float                # [0,1]
    expected_operational_delta: float             # [0,1], cost
    evidence_effect: EvidenceEffect
    reversibility: Reversibility
    rollback_operator_id: str | None
    authority: AuthorityClass
    verification_predicates: tuple[PostconditionKind, ...]
    lease_ttl_seconds: int
    uncertainty: float
    shadow: ActionShadow
    scope_size: int                               # processes+services+sessions touched
    evidence_loss: tuple[str, ...]
    def __post_init__(self) -> None: ...
    # raises if verification_predicates is empty: §2's "an action that cannot be
    # verified cannot be considered successfully completed" is enforced at generation,
    # not discovered at VERIFY.
    def to_dict(self) -> dict[str, Any]

@dataclass(frozen=True, slots=True)
class FieldTruncation:
    what: str
    identifier: str
    reason: str

@dataclass(frozen=True, slots=True)
class ActionField:
    incident_id: str
    resolution_id: str
    candidates: tuple[CandidateAction, ...]
    truncations: tuple[FieldTruncation, ...]
    def __post_init__(self) -> None: ...   # bound at MAX_CANDIDATES
    def observe_only(self) -> tuple[CandidateAction, ...]
    def state_bytes(self) -> int

def generate_action_field(resolution: CBFResolutionV1, snapshot: HostSnapshot, *,
                          constitution: ResponseConstitution,
                          invariants: MissionInvariantSet,
                          governor: ResourceGovernor,
                          memory: EffectivenessMemory,
                          cells: ResponseCellField,
                          twin: ResponseTwin) -> ActionField
    """Candidate generation is CONSTRAINED, not open-ended (§3). The generator is a
    cross-product of (catalog entries whose `target_kind` matches an entity the
    resolution actually names) x (targets named by the resolution's evidence lineage),
    filtered by the constitution and the mission invariants, pruned by the governor.
    There is no search, no sampling and no language model.

    An `InformationGap` may add an O0 candidate ONLY through GAP_TO_OBSERVE_OPERATOR —
    a closed dict lookup on `gap.signal`. The prose in `why_it_matters` is never parsed."""

class IdentifiabilityOutcome(StrEnum):
    ACTIONABLE = "ACTIONABLE"
    NOT_IDENTIFIABLE = "NOT_IDENTIFIABLE"
    RESIDUAL_ACCEPTED = "RESIDUAL_ACCEPTED"

@dataclass(frozen=True, slots=True)
class RiskAcceptancePolicy:
    accept_residual_below_support: float
    accepted_operator_classes: frozenset[OperatorClass]   # {O0, O1} by default
    policy_version: str

@dataclass(frozen=True, slots=True)
class ResponseIdentifiability:
    outcome: IdentifiabilityOutcome
    harmful_worlds: tuple[str, ...]
    unruled_out: tuple[str, ...]
    detail: str

def check_response_identifiability(candidate: CandidateAction, resolution: CBFResolutionV1,
                                  *, truth: HarmModel,
                                  policy: RiskAcceptancePolicy) -> ResponseIdentifiability
    """§7, as an execution constraint rather than a warning label. For every hypothesis
    row where this candidate causes unacceptable harm, that hypothesis must have
    `support <= RULED_OUT_SUPPORT` OR the policy must explicitly accept the residual.
    Otherwise NOT_IDENTIFIABLE, and the planner may not choose the candidate."""

@dataclass(frozen=True, slots=True)
class HarmModel:
    """Which (mechanism_id, operator_class) pairs are unacceptable. A closed table in
    labs/response_corpus.py for the corpus, and a mission-invariant-derived table at
    runtime. Never inferred from a model score."""
    unacceptable: frozenset[tuple[str, OperatorClass]]
    def harms(self, mechanism_id: str, spec: OperatorSpec) -> bool
```

**NO ACTION is always available.** `generate_action_field` never returns an empty field: when every
intervention is refused, the field contains the `OBSERVE_PROCESS_METADATA` candidate and the
truncation rows explaining every refusal, and the planner returns `PlanDecision.NO_ACTION`.
`test_an_all_unsafe_incident_yields_no_action_not_an_exception` asserts it — §2's law
`NO_ACTION_IS_ALWAYS_AVAILABLE` made reachable.

**Minimum Effective Intervention (§11)** is not a scalar here. It is the objective vector D5.9
minimises: `scope_size`, `reversibility`, `evidence_loss`, `shadow.score`,
`expected_operational_delta`, subject to `expected_security_delta >= required_reduction` and the hard
constraints. The §11 formula appears in `theory.py` with each term bound to the field above; there is
no place in the code where those six numbers are summed into one, because §12 says AEGIS removes
dominated actions *first*.

### D5.7 — Counterfactual Response Twin `[field]`

```python
# pocketsec/stage5/twin/response_twin.py
MAX_TWIN_NODES: int = 64
MAX_TWIN_DEPTH: int = 2
MAX_TWIN_BYTES: int = 20480

class StateFamily(StrEnum):
    """§8's seven state families, exactly."""
    PROCESS = "PROCESS"
    SERVICE = "SERVICE"
    SESSION = "SESSION"
    COMMUNICATION = "COMMUNICATION"
    SECURITY = "SECURITY"
    EVIDENCE = "EVIDENCE"
    RECOVERY = "RECOVERY"

@dataclass(frozen=True, slots=True)
class TwinNode:
    family: StateFamily
    node_id: str
    attributes: Mapping[str, str]        # str->str only; no floats, no nesting
    observed: bool                       # False => it is an assumption, and it raises shadow

@dataclass(frozen=True, slots=True)
class TwinState:
    nodes: tuple[TwinNode, ...]
    edges: tuple[tuple[str, str], ...]
    def __post_init__(self) -> None: ...   # bound at MAX_TWIN_NODES; canonical bytes <= MAX_TWIN_BYTES
    def node(self, node_id: str) -> TwinNode | None
    def digest(self) -> str
    def to_dict(self) -> dict[str, Any]

@dataclass(frozen=True, slots=True)
class TwinPrediction:
    candidate_id: str
    world_id: str
    before: TwinState
    predicted: TwinState
    unknown_dependencies: tuple[str, ...]
    predicted_degradation: float          # [0,1]
    evidence_lost: tuple[str, ...]
    recovery_state_needed: tuple[str, ...]
    truncated: bool
    def to_dict(self) -> dict[str, Any]

class ResponseTwin:
    """"Intentionally narrow. It models only state relevant to a proposed intervention"
    (§8). Narrowness is structural: `_reachable` walks at most MAX_TWIN_DEPTH edges from
    the target, and the governor is charged one TWIN_STEP per node."""
    def __init__(self, *, snapshot: HostSnapshot, governor: ResourceGovernor) -> None
    def project(self, target: ProcessTarget) -> TwinState
    def predict(self, candidate: CandidateAction, *, world_id: str) -> TwinPrediction
    def unknown_dependencies(self, target: ProcessTarget) -> tuple[str, ...]
```

**Unknown dependencies raise Action Shadow and may make autonomous execution ineligible** (§8) —
they never raise predicted benefit. `predict` marks every node it could not observe
(`observed=False`) and every service whose `depends_on` names a unit absent from the snapshot; both
feed `ActionShadow.unmodelled_dependencies`.

**The twin's honest ceiling, stated in the module docstring:** it predicts the *simulated* host. Its
prediction error against a real host is UNMEASURED. What the corpus can measure is
`TwinPrediction` versus the simulator's own post-action state — which is a measurement of internal
consistency, and is reported as `simulated_twin_prediction_error`.

### D5.8 — Intervention Cone + Action Shadow engine `[field]`

```python
# pocketsec/stage5/aegis/cone.py
MAX_CONE_DEPTH: int = 3
MAX_CONE_BRANCHES_PER_NODE: int = 4
MAX_CONE_NODES: int = 32

class Branch(StrEnum):
    """§9's seven branches, exactly."""
    INTENDED_SECURITY_EFFECT = "INTENDED_SECURITY_EFFECT"
    ATTACKER_ADAPTATION = "ATTACKER_ADAPTATION"
    SERVICE_DEGRADATION = "SERVICE_DEGRADATION"
    EVIDENCE_LOSS = "EVIDENCE_LOSS"
    PERSISTENCE_TRIGGERED_RESTART = "PERSISTENCE_TRIGGERED_RESTART"
    ROLLBACK_PATH = "ROLLBACK_PATH"
    UNKNOWN = "UNKNOWN"                       # the Action Shadow branch

class AdaptationKind(StrEnum):
    """§25. ONLY observed/learned adaptations; no unrestricted game-theoretic search."""
    PROCESS_REPLACEMENT = "PROCESS_REPLACEMENT"
    ALTERNATE_DESTINATION = "ALTERNATE_DESTINATION"
    PERSISTENCE_RESTART = "PERSISTENCE_RESTART"
    SESSION_MIGRATION = "SESSION_MIGRATION"

@dataclass(frozen=True, slots=True)
class AdaptationModel:
    observed: frozenset[AdaptationKind]
    observation_counts: Mapping[AdaptationKind, int]
    def likely(self, kind: AdaptationKind, *, min_observations: int = 1) -> bool

@dataclass(frozen=True, slots=True)
class ConeNode:
    node_id: str
    parent_id: str | None
    branch: Branch
    depth: int
    probability: float | None          # None where nothing measured it. Never 0.5 as a stand-in.
    state: TwinState | None
    detail: str

@dataclass(frozen=True, slots=True)
class InterventionCone:
    candidate_id: str
    world_id: str
    nodes: tuple[ConeNode, ...]
    truncations: tuple[FieldTruncation, ...]
    def __post_init__(self) -> None: ...   # depth <= MAX_CONE_DEPTH; nodes <= MAX_CONE_NODES
    def branch_nodes(self, branch: Branch) -> tuple[ConeNode, ...]
    def worst_leaf_degradation(self) -> float
    def rollback_reachable(self) -> bool

def build_intervention_cone(candidate: CandidateAction, *, world_id: str,
                            twin: ResponseTwin, adaptations: AdaptationModel,
                            governor: ResourceGovernor) -> InterventionCone
```

```python
# pocketsec/stage5/aegis/shadow.py
SHADOW_AUTONOMY_CEILING: float = 0.35          # a CHOSEN parameter, not a measured one
SHADOW_HUMAN_CEILING: float = 0.70

class AutonomyEligibility(StrEnum):
    ELIGIBLE = "ELIGIBLE"
    OBSERVE_ONLY = "OBSERVE_ONLY"
    HUMAN_REQUIRED = "HUMAN_REQUIRED"

@dataclass(frozen=True, slots=True)
class ActionShadow:
    """§10. AS(A) = unmodelled dependencies + uncertain side effects + unobservable
    post-action effects. Three counted terms and one normalised score, so the score can
    always be decomposed back into what produced it — Φ's rule (§D5.1's PhiBreakdown
    precedent)."""
    candidate_id: str
    unmodelled_dependencies: int
    uncertain_side_effects: int
    unobservable_effects: int
    upstream_truncations: int          # len(resolution.truncations) + len(degradations)
    score: float                       # [0,1]
    components: Mapping[str, float]
    def to_dict(self) -> dict[str, Any]

def estimate_action_shadow(candidate_id: str, *, prediction: TwinPrediction,
                           cone: InterventionCone, snapshot: HostSnapshot,
                           resolution: CBFResolutionV1) -> ActionShadow

def shadow_gate(shadow: ActionShadow, *, spec: OperatorSpec) -> AutonomyEligibility
    """"High Action Shadow pushes the action toward observe/defer/human approval even when
    predicted security benefit is large" (§10). The function takes NO benefit argument,
    so benefit structurally cannot override shadow."""

@dataclass(frozen=True, slots=True)
class ShadowCalibration:
    n: int
    buckets: tuple[tuple[float, float, int], ...]   # (shadow_lo, mean_residual, count)
    rank_correlation: float | None                  # None below MIN_CALIBRATION_SAMPLES
    detail: str

MIN_CALIBRATION_SAMPLES: int = 30

def calibrate_shadow(pairs: Sequence[tuple[ActionShadow, InterventionResidual]]
                     ) -> ShadowCalibration
    """Returns rank_correlation=None below MIN_CALIBRATION_SAMPLES. **If shadow does not
    rank-correlate with measured residual, it cannot gate autonomy**, falsifier F3 fires
    and ADR-0048 records it. `None` is not zero and is not a pass (ADR-0004)."""
```

### D5.3 — AEGIS planner `[aegis]`

```python
# pocketsec/stage5/aegis/planner.py
class PlanDecision(StrEnum):
    ACT = "ACT"
    OBSERVE = "OBSERVE"
    DEFER = "DEFER"
    ESCALATE = "ESCALATE"
    NO_ACTION = "NO_ACTION"
    ROLLBACK = "ROLLBACK"

@dataclass(frozen=True, slots=True)
class PlannerConfig:
    """Every OPTIONAL core id names its flag HERE. An ablation is a flag the gate sets,
    never a code edit nobody dares make (stage4/core_ids.py's precedent)."""
    enable_multi_world: bool = True           # SAFE-F04 ... the B7 control
    enable_twin: bool = True                  # SAFE-F04
    enable_cone: bool = True                  # SAFE-F05
    enable_shadow_gate: bool = True           # SAFE-F06
    enable_regret: bool = True                # SAFE-F07
    enable_pareto: bool = True                # SAFE-F08 ... False => scalar utility, the B6 control
    enable_hysteresis: bool = True            # SAFE-F18 ... False => the B8 control
    enable_effectiveness_memory: bool = True  # SAFE-F20
    enable_response_cells: bool = True        # SAFE-F21
    selector: Selector = Selector.PARETO_THEN_POLICY
    required_risk_reduction: float = 0.30
    def as_ablation_key(self) -> str

@dataclass(frozen=True, slots=True)
class RejectionRecord:
    candidate_id: str
    reason: str                # a closed vocabulary: see REJECTION_REASONS
    detail: str

REJECTION_REASONS: frozenset[str]   # {"DOMINATED","NOT_IDENTIFIABLE","SHADOW","AUTHORITY",
                                    #  "MISSION_INVARIANT","EVIDENCE","HYSTERESIS","BUDGET",
                                    #  "NO_ROLLBACK","INSUFFICIENT_BENEFIT","RELIABILITY"}

@dataclass(frozen=True, slots=True)
class ResponsePlan:
    plan_id: str
    incident_id: str
    resolution_id: str
    decision: PlanDecision
    chosen: CandidateAction | None
    frontier: tuple[CandidateAction, ...]
    rejected: tuple[RejectionRecord, ...]
    human_contract: HumanDecisionContract | None
    selector: Selector
    config_key: str
    work_units: int
    truncations: tuple[FieldTruncation, ...]
    loadavg: tuple[float, float, float]
    def __post_init__(self) -> None: ...
    # raises if decision is ACT with chosen None; raises if decision is ACT while
    # chosen.authority exceeds MAX_AUTONOMOUS_AUTHORITY; raises if decision is
    # ESCALATE/DEFER with human_contract None — an escalation with no decision structure
    # is a notification, and §32 asks for the structure.
    def to_dict(self) -> dict[str, Any]

class AegisPlanner:
    """UNPRIVILEGED (§35). It cannot mint a token, cannot touch a HostAdapter and cannot
    import the executor. tests/test_stage5_boundary.py asserts by AST that no module under
    pocketsec/stage5/aegis/, safe/ or twin/ imports authority.tokens, executor.* or
    host.simulated's SimulatedHost class (the read-only HostSnapshot is permitted)."""
    def __init__(self, *, config: PlannerConfig, constitution: ResponseConstitution,
                 invariants: MissionInvariantSet, governor: ResourceGovernor,
                 memory: EffectivenessMemory, cells: ResponseCellField,
                 hysteresis: HysteresisController, harm: HarmModel) -> None

    def plan(self, resolution: CBFResolutionV1, snapshot: HostSnapshot, *,
             now: int, active_leases: Sequence[Lease]) -> ResponsePlan
```

**The confidence-invariance property, which G5.4 tests.** `plan()` reads
`resolution.verdict` and per-hypothesis `support`/`uncertainty` **only** to compute
`world_applicability`, `expected_security_delta` and `ActionShadow`. The authority decision —
whether `decision is ACT` versus `ESCALATE`, and which `AuthorityClass` is required — is a function
of `operator.spec.operator_class`, the constitution, the mission invariants, the capability grant and
the measured `rollback_reliability` **alone**. `test_confidence_099_and_001_reach_the_same_authority`
takes one corpus case, emits two resolutions differing only in the hypotheses' `support` values
(0.99 vs 0.01 on the leading world) and asserts the two plans' `chosen.authority`,
`decision`-authority class and `human_contract.approval_required` are identical. What may differ:
`expected_security_delta`, the frontier ordering, and the shadow score.

```python
# pocketsec/stage5/aegis/human_contract.py
MAX_CONTRACT_BYTES: int = 8192

@dataclass(frozen=True, slots=True)
class WorldEffect:
    mechanism_id: str
    support: float
    predicted_security_effect: str        # from a CLOSED vocabulary, not free text
    predicted_operational_effect: str
    harmful: bool

@dataclass(frozen=True, slots=True)
class HumanDecisionContract:
    """§32, heading for heading. Every field is derived from typed data by a pure
    function; nothing here is generated text, and there is no model in this module."""
    proposal_operator_id: str
    proposal_target_digest: str
    world_effects: tuple[WorldEffect, ...]
    expected_benefit: float
    collateral_units: tuple[str, ...]
    action_shadow: float
    evidence_preserved: tuple[str, ...]
    rollback_operator_id: str | None
    lease_ttl_seconds: int
    approval_required: bool
    approval_reason: str                  # from CLOSED APPROVAL_REASONS
    safer_alternative_id: str | None
    def render(self) -> str                # deterministic; <= MAX_CONTRACT_BYTES
    def to_dict(self) -> dict[str, Any]

APPROVAL_REASONS: frozenset[str]
def build_contract(plan_candidates: Sequence[CandidateAction], chosen: CandidateAction | None,
                   *, resolution: CBFResolutionV1, constitution: ResponseConstitution,
                   shadow_eligibility: AutonomyEligibility) -> HumanDecisionContract
```

`render()` is pure and deterministic: `test_render_is_deterministic` calls it twice and compares
bytes; `test_contract_carries_no_free_text` asserts every string field is either a catalog id, a
digest or a member of a closed vocabulary. **The human sees the decision structure, not an AI
recommendation** (§32), and the structure is typed so that it cannot become one.

### D5.9 — Pareto / regret selector `[aegis]`

```python
# pocketsec/stage5/aegis/pareto.py
class Objective(StrEnum):
    """§12's nine dimensions, exactly."""
    SECURITY_BENEFIT = "SECURITY_BENEFIT"                    # maximise
    WORST_WORLD_SECURITY_BENEFIT = "WORST_WORLD_SECURITY_BENEFIT"   # maximise
    COLLATERAL = "COLLATERAL"                                # minimise
    SCOPE = "SCOPE"                                          # minimise
    IRREVERSIBILITY = "IRREVERSIBILITY"                      # minimise
    EVIDENCE_LOSS = "EVIDENCE_LOSS"                          # minimise
    ACTION_SHADOW = "ACTION_SHADOW"                          # minimise
    DOWNTIME = "DOWNTIME"                                    # minimise
    VERIFICATION_LATENCY = "VERIFICATION_LATENCY"            # minimise

MAXIMISED: frozenset[Objective]
IRREVERSIBILITY_SCALE: Mapping[Reversibility, float]         # 0.0, 0.25, 0.6, 1.0
EVIDENCE_LOSS_SCALE: Mapping[EvidenceEffect, float]          # 0.0, 0.0, 0.5, 1.0

@dataclass(frozen=True, slots=True)
class ObjectiveVector:
    values: Mapping[Objective, float]
    def __post_init__(self) -> None: ...   # every Objective present; every value finite in [0,1]
    def to_dict(self) -> dict[str, float]

@dataclass(frozen=True, slots=True)
class ScoredCandidate:
    candidate: CandidateAction
    objectives: ObjectiveVector
    per_world_loss: Mapping[str, float]

def score(candidate: CandidateAction, *, cones: Mapping[str, InterventionCone],
          resolution: CBFResolutionV1) -> ScoredCandidate

def dominates(left: ObjectiveVector, right: ObjectiveVector) -> bool
def pareto_frontier(scored: Sequence[ScoredCandidate]) -> tuple[ScoredCandidate, ...]

def regret(candidate: ScoredCandidate, *, world_id: str,
           all_candidates: Sequence[ScoredCandidate]) -> float
    """§26. Regret(A,W) = Loss(A,W) - Loss(best admissible action in hindsight, W).
    "Admissible" means: passes the constitution, the invariants and the shadow gate for
    that world. An inadmissible action is not a hindsight benchmark."""

def minimax_regret(scored: Sequence[ScoredCandidate],
                   world_ids: Sequence[str]) -> ScoredCandidate | None
def scalar_utility(scored: Sequence[ScoredCandidate],
                   weights: Mapping[Objective, float]) -> ScoredCandidate | None
    """The B6 control, deliberately in the same module and exercised by the same tests, so
    the comparison runs in one process on one corpus."""

class Selector(StrEnum):
    PARETO_THEN_POLICY = "PARETO_THEN_POLICY"
    MINIMAX_REGRET = "MINIMAX_REGRET"
    SCALAR_UTILITY = "SCALAR_UTILITY"

DEFAULT_WEIGHTS: Mapping[Objective, float]   # for SCALAR_UTILITY only; documented as arbitrary
def select(scored: Sequence[ScoredCandidate], *, selector: Selector,
           world_ids: Sequence[str]) -> tuple[ScoredCandidate | None, tuple[RejectionRecord, ...]]
```

`DEFAULT_WEIGHTS` exists **only** to make the B6 baseline runnable, and its docstring says so:
"these weights are arbitrary, which is §12's entire argument for removing dominated actions before
scalarising. They are not a tuned parameter and no result may be attributed to their values."

### D5.18 — Formal / empirical assurance package `[benchmarks]`

```python
# pocketsec/stage5/assurance/properties.py
class AssuranceKind(StrEnum):
    PROVEN_BY_CONSTRUCTION = "PROVEN_BY_CONSTRUCTION"
    TESTED = "TESTED"
    UNMEASURED = "UNMEASURED"

VERIFICATION_WORDS: frozenset[str] = frozenset({"proven", "verified", "formally", "guaranteed"})

@dataclass(frozen=True, slots=True)
class ExecutorProperty:
    property_id: str
    statement: str
    kind: AssuranceKind
    construction: str        # "module.py:Symbol" — REQUIRED for PROVEN_BY_CONSTRUCTION
    mutation: str            # what to delete to make it fail — REQUIRED for PROVEN_BY_CONSTRUCTION
    test_name: str           # "tests/test_x.py::test_y" — REQUIRED for TESTED
    why_not: str             # REQUIRED for UNMEASURED
    def __post_init__(self) -> None: ...
    # PROVEN_BY_CONSTRUCTION with an empty `construction` or `mutation` raises.
    # TESTED with an empty `test_name` raises.
    # TESTED or UNMEASURED whose `statement` contains a VERIFICATION_WORDS member raises:
    #   the word "verified" may not describe a property whose only evidence is that no
    #   test broke it.
    # UNMEASURED with an empty `why_not` raises.

EXECUTOR_PROPERTIES: tuple[ExecutorProperty, ...]

def proven() -> tuple[ExecutorProperty, ...]
def tested() -> tuple[ExecutorProperty, ...]
def unmeasured() -> tuple[ExecutorProperty, ...]
def counts() -> Mapping[str, int]
def unearned_verification_language(text: str) -> tuple[str, ...]
    """Every occurrence of a VERIFICATION_WORDS member in `text` that is not within three
    lines of a `construction` path named in EXECUTOR_PROPERTIES. Stage 3's gate does the
    same thing (gate.py `_verification_claims_are_bounded`), and copying the technique is
    the point."""
```

**The fourteen properties, and the honest split.** The target enumeration; the *count* is whatever
the wave measures, and a property that fails to be provable is moved to TESTED rather than described
as proven.

| id | property | kind | construction / test |
|---|---|---|---|
| P1 | the executor's entry point accepts exactly `DefensiveOperator` | PROVEN BY CONSTRUCTION | annotation + `DefensiveOperator.__post_init__` catalog-identity check + T4 AST assertion. Mutation: delete the identity check ⇒ a forged spec is accepted |
| P2 | no `subprocess`, `os.system`, `os.popen`, `eval`, `exec` or `compile` anywhere under `pocketsec/stage5/` | PROVEN BY CONSTRUCTION | `no_arbitrary_command_path()` over the package. Mutation: add `import subprocess` to any module ⇒ the function returns a row |
| P3 | no string reaches argument assembly | PROVEN BY CONSTRUCTION | `ArgvAtom = LiteralAtom \| FieldAtom`; `assemble_argv`'s total `match`; `LiteralAtom`'s metacharacter pattern. Mutation: add a `str` member to `ArgvAtom` ⇒ `mypy --strict` fails on the non-exhaustive match |
| P4 | authority cannot escalate | PROVEN BY CONSTRUCTION | `AUTHORITY_BY_OPERATOR_CLASS` total over `OperatorClass` with an import-time assert; `GrantSource` has no `MODEL`. Mutation: remove one mapping ⇒ `ImportError` |
| P5 | `O7_DESTRUCTIVE` is not expressible | PROVEN BY CONSTRUCTION | zero catalog entries; `_CATALOG_TOKEN`-gated construction. Mutation: add an O7 entry ⇒ `ResponseConstitution.permits` refuses and the count test fails |
| P6 | SENTINEL has no bypass | PROVEN BY CONSTRUCTION | three-parameter `__init__`; AST absence of `force\|override\|bypass\|skip\|disable\|dry_run`; fail-closed `except BaseException`. Mutation: add a `bypass` kwarg ⇒ the signature test fails |
| P7 | lease expiry is a pure function of the lease | PROVEN BY CONSTRUCTION | `Lease.expired(now)` reads only frozen fields. Mutation: read a registry attribute inside `expired` ⇒ the `ManualClock` test that never calls the registry fails |
| P8 | COMMIT is unreachable without a preservation bundle | PROVEN BY CONSTRUCTION | `_commit(self, operator, bundle: PreActionBundle)` — required positional. Mutation: default it to `None` ⇒ `mypy --strict` and the ordering test fail |
| P9 | every `TransactionReceipt` states whether its host was simulated | PROVEN BY CONSTRUCTION | required non-defaulted `host_kind` + `simulated`, cross-checked in `__post_init__` and again in `ResponseRecordV1.to_dict` |
| P10 | the rollback protocol restores the pre-action state | **TESTED** | `tests/test_stage5_executor.py::test_rollback_restores_the_pre_action_snapshot`, plus fault injection at `rollback_failure_rate` ∈ {0.0, 0.1, 0.5}. **Inside the simulated host only** |
| P11 | a redeemed capability token cannot be redeemed again | **TESTED** | `tests/test_stage5_authority.py::test_a_redeemed_token_is_replayed`. Bounded by `MAX_SPENT_NONCES=256`, so the property is "within the last 256 tokens", and the statement says so |
| P12 | target identity is revalidated immediately before the host call | **TESTED** (AST-assisted) | `test_identity_is_revalidated_inside_commit` + the four TOCTOU races. Not called proven: the AST check constrains `_commit`'s body, not every possible future call graph |
| P13 | evidence lineage survives every transaction | **TESTED** | `test_every_receipt_resolves_to_a_digest_in_the_bundle`, over the whole corpus |
| P14 | rollback reliability against a real Linux host | **UNMEASURED** | `why_not`: no real host, no real telemetry, no `RealHost` implementation exists by design (ADR-0046). What would measure it: paired containment/restore drills on an instrumented Linux host with injected ground-truth actions |
| P15 | security effectiveness of any operator | **UNMEASURED** | `why_not`: every corpus is synthetic and the harm model is authored by the same wave (§6.1, §9) |

**Target: 9 PROVEN BY CONSTRUCTION, 4 TESTED, 2 UNMEASURED.** Stage 3's ADR-0022 is titled *"five
properties proven, four only tested"*; ADR-0042 records Stage 5's real counts, whatever they are.
**The word "verified" is not used for any of P10–P15.**

### D5.19 — 50-experiment benchmark and ablation corpus `[benchmarks]`

```python
# pocketsec/stage5/labs/response_corpus.py
RESPONSE_CORPUS_VERSION: str = "stage5-response-corpus-v0.1.0"
MAX_CASE_PROCESSES: int = 24

@dataclass(frozen=True, slots=True)
class GroundTruthResponse:
    """What the corpus author declares. Named `truth` so no reader mistakes it for a
    measurement of a real host."""
    harmful_operator_ids: frozenset[str]
    sufficient_operator_ids: frozenset[str]
    critical_units: frozenset[str]
    uniquely_necessary_evidence: frozenset[str]
    true_mechanism_id: str
    benign_admin: bool

@dataclass(frozen=True, slots=True)
class ResponseCase:
    case_id: str
    resolution: CBFResolutionV1
    host: SimulatedHost
    truth: GroundTruthResponse
    harm: HarmModel
    invariants: MissionInvariantSet
    ambiguous: bool

def build_response_corpus(*, count: int, seed: int) -> tuple[ResponseCase, ...]
def build_ambiguous_pairs(*, count: int, seed: int) -> tuple[tuple[ResponseCase, ResponseCase], ...]
def build_critical_service_baits(*, count: int, seed: int) -> tuple[ResponseCase, ...]
def build_toctou_cases(*, count: int, seed: int) -> tuple[ResponseCase, ...]
def build_evidence_destroying_cases(*, count: int, seed: int) -> tuple[ResponseCase, ...]
def build_action_flood(*, count: int, seed: int) -> tuple[ResponseCase, ...]
def build_two_epoch_corpus(*, count: int, seed: int) -> tuple[ResponseCase, ...]
```

**The ambiguous pair is the corpus's whole point.** Each pair is a benign-administrator case and a
compromised case whose `CBFResolutionV1` carries **byte-identical `claim_graph` and
`evidence_lineage`** and two hypotheses within `IDENTIFIABILITY_MARGIN` of each other. A
single-world planner (B7) must commit to one and is wrong half the time; a multi-world planner can
return `NO_ACTION` or an `O0`/`O1` candidate. **If multi-world does not reduce collateral on these
pairs, falsifier F2 fires** and ADR-0048 says so.

Three corpus honesty tests are mandatory, each from a defect this project has already paid for:

- `test_response_corpus_uses_session_unique_identities` — the corpus trap: Stage 1 carries lineage
  state across scenarios, and reused process identities silently erase the signal (median ΔΦ 0.00 for
  both classes; the resulting +0.042 was retracted). Assert every `ProcessIdentity` across the corpus
  is unique in `(pid, start_time_ticks)`.
- `test_response_corpus_carries_no_operator_vocabulary_signal` — the vocabulary leak, which happened
  twice in Stage 2. Assert the multiset of `harmful_operator_ids` and `sufficient_operator_ids`
  overlaps across the ambiguous/unambiguous split, so a bag-of-operators control cannot win for free.
- `test_ambiguous_pairs_are_indistinguishable_from_the_resolution_alone` — assert
  `pair[0].resolution.claim_graph == pair[1].resolution.claim_graph` and that the two differ **only**
  in `truth`. If a planner can tell them apart from the resolution, the pair does not test ambiguity.

```python
# pocketsec/stage5/labs/baselines.py
@dataclass(frozen=True, slots=True)
class BaselineOutcome:
    baseline_id: str
    actions_taken: int
    collateral_incidents: int
    mission_invariant_violations: int
    evidence_violations: int
    incidents_contained: int
    incidents_missed: int
    simulated_rollback_successes: int
    simulated_rollback_attempts: int
    work_units: int
    human_escalations: int
    def collateral_per_1000(self) -> float | None
    def to_dict(self) -> dict[str, Any]

def no_automated_response(cases, **_: Any) -> BaselineOutcome        # B1
def fixed_playbook(cases, **_: Any) -> BaselineOutcome               # B2
def simple_if_then_containment(cases, **_: Any) -> BaselineOutcome   # B3
def always_isolate(cases, **_: Any) -> BaselineOutcome               # B4
def d3fend_lookup_only(cases, **_: Any) -> BaselineOutcome           # B5
def single_scalar_utility(cases, **_: Any) -> BaselineOutcome        # B6
def single_world_planner(cases, **_: Any) -> BaselineOutcome         # B7
def no_hysteresis(cases, **_: Any) -> BaselineOutcome                # B8
def human_only(cases, **_: Any) -> BaselineOutcome                   # B9
BASELINES: Mapping[str, Callable[..., BaselineOutcome]]
def run_baselines(cases: Sequence[ResponseCase]) -> Mapping[str, BaselineOutcome]
def pareto_frontier_of(outcomes: Mapping[str, BaselineOutcome]) -> tuple[str, ...]
```

**Every baseline runs through the real `TransactionalExecutor`, the real `SentinelKernel` and the
real `SimulatedHost`, in the same process and the same run.** A baseline that bypasses SENTINEL
would be measuring a different system and would flatter AEGIS — `MEMORY.md` trap 5: a broken
baseline scored 0.55 and 0.94 once fixed. The baselines differ **only** in which candidate they
choose and whether they lease. §7 states what each must lose on.

```python
# pocketsec/stage5/labs/fifty_experiments.py
STAGE5_EXPERIMENTS_VERSION: str = f"stage5-experiments-v0.1.0+{RESPONSE_CORPUS_VERSION}"

class BlockedReason(StrEnum):
    """Closed, because an open reason field is where "we did not get to it" hides
    behind "it is blocked"."""
    NEEDS_REAL_HOST = "NEEDS_REAL_HOST"
    NEEDS_REAL_TELEMETRY = "NEEDS_REAL_TELEMETRY"
    NEEDS_D3FEND_SNAPSHOT = "NEEDS_D3FEND_SNAPSHOT"
    NEEDS_TWO_EPOCHS = "NEEDS_TWO_EPOCHS"
    NEEDS_NUMPY_FORBIDDEN_HERE = "NEEDS_NUMPY_FORBIDDEN_HERE"

@dataclass(frozen=True, slots=True)
class ExperimentSpec:
    experiment_id: str          # "S5X-01" … "S5X-50", architecture §41 verbatim
    title: str
    deliverable: str
    runnable: bool
    blocked_reason: BlockedReason | None
    metric: str
    def __post_init__(self) -> None: ...   # runnable and blocked_reason are mutually exclusive

EXPERIMENTS: tuple[ExperimentSpec, ...]     # exactly 50, ids S5X-01..S5X-50 dense
def runnable_experiments() -> tuple[ExperimentSpec, ...]
def blocked_experiments() -> tuple[ExperimentSpec, ...]

@dataclass(frozen=True, slots=True)
class AblationRow:
    core_id: str
    flag: str
    metric: str
    with_value: float | None
    without_value: float | None
    delta: float | None
    verdict: str            # JUSTIFIED | NOT_YET_JUSTIFIED | HARMFUL | UNMEASURED
    experiment_id: str

def run_ablation(cases: Sequence[ResponseCase], *, flag: str) -> AblationRow
def saturation_check(outcomes: Mapping[str, BaselineOutcome]) -> tuple[bool, str]
    """Runs BEFORE any ablation is recorded. Returns DEGENERATE when the best and median
    baselines are within SATURATION_EPSILON on the primary metric, or when
    `always_isolate` or `no_automated_response` ties the best — a task that a degenerate
    control solves cannot show that any component helps (MEMORY.md trap 9, ADR-0120)."""

SATURATION_EPSILON: float = 0.01
PRIMARY_METRIC: str = "collateral_per_1000_at_equal_containment"
```

Architecture §41's fifty ids map one-to-one onto `EXPERIMENTS`. Expected blocked set, declared up
front: **S5X-21, S5X-22, S5X-23** (suspend/resume, local restriction, service containment *labs* —
they run against the simulator, so they are `runnable` but their *result* is simulator-bound and
§6.1 says so), **S5X-35** rollback fault injection (runnable in-simulator; real-host reliability
`NEEDS_REAL_HOST`), **S5X-36/37** safe-state recovery and staged restoration (`NEEDS_REAL_HOST` for
the claim, runnable for the mechanism), **S5X-39** epoch-conditioned effectiveness
(`NEEDS_TWO_EPOCHS`), **S5X-40** D3FEND adapter (`NEEDS_D3FEND_SNAPSHOT`), **S5X-48** operational
availability benchmark (`NEEDS_REAL_HOST`). Everything else is runnable, and the count of each goes
in the findings.

```python
# pocketsec/stage5/resources.py
STAGE5_COMPONENTS: tuple[str, ...]        # the seven §43 rows
STAGE5_NORMAL_INCREMENTAL_RSS_BYTES: int = 52428800      # 50 MB, §43's upper "prefer" bound
STAGE5_PEAK_CEILING_BYTES: int = 115343360               # 110 MB, §43's initial ceiling
STAGE5_PROFILE: str = "edge"

@dataclass(frozen=True, slots=True)
class Stage5ResourceReport:
    peak_rss_bytes: int | None
    incremental_rss_bytes: int | None
    component_bytes: Mapping[str, int | None]
    within_target: bool | None            # None when nothing was measured. NEVER True.
    profile: ProfileReport | None
    loadavg: tuple[float, float, float]
    detail: str

def loadavg() -> tuple[float, float, float]
def component_bytes(**components: object) -> Mapping[str, int | None]
def measure_stage5_resources(cases: Sequence[ResponseCase]) -> Stage5ResourceReport
def unmeasured_stage5_resources(reason: str) -> Stage5ResourceReport
```

Only `ResourceSampler` produces a byte figure. `unmeasured_stage5_resources` exists so that a failed
measurement produces an honest `None`-filled report rather than a plausible number.

---

### D5.20 — Final Stage 5 falsification report `[integrator]`

`docs/stage-5-findings.md`. Not owned by any work package: it is written by the integrator from the
packages' measured output plus the gate run, and it is the artefact the phase is judged by.

Required structure, and G5.15 checks the last part of it:

1. **The headline, whichever way it fell.** If F1 fired, the first sentence says the fixed playbook
   matched or beat SAFE/AEGIS and names the numbers. Stage 3 did this — ADR-0021 is titled *"the
   Knowledge Cell format loses to the rule it wraps"* — and it is the standard.
2. **The sentence §11 requires**, about real-host rollback reliability being UNMEASURED.
3. **Per-falsifier disposition**, one row per F1–F10: fired / did not fire / could not be evaluated,
   with the measurement and the ADR.
4. **The assurance table's three counts** from `assurance.properties.counts()`, with the word
   "verified" absent from every TESTED and UNMEASURED statement.
5. **The gate result verbatim**, every check's detail line, `/proc/loadavg` beside every timing.
6. **The fifty-experiment disposition**: runnable count, blocked count, and one `BlockedReason` per
   blocked row.
7. **The six honesty-ledger headings of §11**, verbatim in structure.

### `core_ids.py` — SAFE-F01 … SAFE-F24 `[foundation]`

The §1.1 skeleton requires it and the ablation machinery depends on it. Copy the shape of
`pocketsec/stage4/core_ids.py:58-90` exactly: a `FunctionClass` StrEnum (`REQUIRED`/`OPTIONAL`), a
frozen `CoreFunction` dataclass with `core_id`, `architecture_id`, `name`, `purpose`,
`function_class`, `deliverable` and `ablation_flag`, and a `__post_init__` that **raises if a
REQUIRED id names a flag or an OPTIONAL id does not** — "an optional mechanism with no off switch
cannot be ablated".

```python
# pocketsec/stage5/core_ids.py
SAFE_INTERFACE_ID = "pocketsec.safe_interface.v1"
SAFE_INTERFACE_VERSION = register_schema(SAFE_INTERFACE_ID, "1.0.0")

CORE_IDS: Mapping[str, CoreFunction]    # exactly 24: SAFE-F01 … SAFE-F24
REQUIRED_IDS: tuple[str, ...]
OPTIONAL_IDS: tuple[str, ...]
ABLATION_FLAGS: Mapping[str, str]       # core_id -> PlannerConfig field name
PINNED_UPSTREAM_SCHEMAS: Mapping[str, str]   # the five schema id -> version pairs G5.1 asserts
def core_function(core_id: str) -> CoreFunction
```

The twenty-four map one-to-one onto architecture §38's `S5-F01 … S5-F24`, keeping the rename
auditable exactly as Stage 4 kept `LUC-F*` → `CBF-F*`:

| core id | §38 function | class | ablation flag |
|---|---|---|---|
| SAFE-F01 | `generate_safe_action_field` | REQUIRED | — |
| SAFE-F02 | `bind_target_identity` | REQUIRED | — |
| SAFE-F03 | `check_response_identifiability` | REQUIRED | — |
| SAFE-F04 | `build_counterfactual_twin` | OPTIONAL | `enable_twin` |
| SAFE-F05 | `build_intervention_cone` | OPTIONAL | `enable_cone` |
| SAFE-F06 | `estimate_action_shadow` | OPTIONAL | `enable_shadow_gate` |
| SAFE-F07 | `calculate_action_regret` | OPTIONAL | `enable_regret` |
| SAFE-F08 | `construct_pareto_frontier` | OPTIONAL | `enable_pareto` |
| SAFE-F09 | `check_mission_invariants` | REQUIRED | — |
| SAFE-F10 | `preserve_evidence` | REQUIRED | — |
| SAFE-F11 | `sentinel_verify` | REQUIRED | — |
| SAFE-F12 | `issue_capability_token` | REQUIRED | — |
| SAFE-F13 | `prepare_transaction` | REQUIRED | — |
| SAFE-F14 | `commit_typed_action` | REQUIRED | — |
| SAFE-F15 | `verify_postconditions` | REQUIRED | — |
| SAFE-F16 | `calculate_intervention_residual` | OPTIONAL | `enable_residual` |
| SAFE-F17 | `rollback_transaction` | REQUIRED | — |
| SAFE-F18 | `manage_action_lease` | OPTIONAL | `enable_hysteresis` |
| SAFE-F19 | `plan_safe_recovery` | REQUIRED | — |
| SAFE-F20 | `update_effectiveness_memory` | OPTIONAL | `enable_effectiveness_memory` |
| SAFE-F21 | `crystallize_response_cell` | OPTIONAL | `enable_response_cells` |
| SAFE-F22 | `melt_response_cell` | OPTIONAL | `enable_response_cells` |
| SAFE-F23 | `map_d3fend_knowledge` | OPTIONAL | `enable_d3fend` |
| SAFE-F24 | `export_response_record` | REQUIRED | — |

**Ten OPTIONAL ids, and G5.14 requires an `AblationRow` with a measured non-`None` delta for every
one of them.** Stage 2's G2.12 read "1 of 12 OPTIONAL core ids carries a registered JUSTIFIED
ablation" after the defect-repair wave fixed a check that had been a bare row count. Stage 5's
equivalent check joins `AblationRow.core_id` to `OPTIONAL_IDS` and reads each row's verdict — it
does not count rows.

Nine flags are `PlannerConfig` fields (§D5.3) and `enable_d3fend` / `enable_residual` are added
there too, so **every** ablation is a flag the gate sets rather than a code edit.

`REQUIRED` here means *the response loop cannot run without it*, which is why F17 (rollback) and F19
(recovery) are REQUIRED even though their real-host value is UNMEASURED: an executor with no rollback
path is not a safer executor, it is an unbounded one.


## 4.9 The constant table, and two rules that bind every package

Every bound in one place. **A literal at a use site is a defect**; import the constant.

| constant | value | module |
|---|---|---|
| `MAX_AUTONOMOUS_AUTHORITY` | `A2` | `constitution/invariants.py` |
| `MAX_MISSION_INVARIANTS` / `MAX_INVARIANT_SET_BYTES` | 64 / 16384 | `constitution/schema.py` |
| `max_candidate_actions` / `MAX_CANDIDATES` | 16 | `governor.py` / `safe/action_field.py` |
| `max_worlds_per_action` | 8 | `governor.py` |
| `MAX_TWIN_NODES` / `MAX_TWIN_DEPTH` / `MAX_TWIN_BYTES` | 64 / 2 / 20480 | `twin/response_twin.py` |
| `MAX_CONE_DEPTH` / `MAX_CONE_BRANCHES_PER_NODE` / `MAX_CONE_NODES` | 3 / 4 / 32 | `aegis/cone.py` |
| `max_dependency_nodes` | 64 | `governor.py` |
| `max_work_units` | 4096 | `governor.py` |
| `MAX_CONCURRENT_LEASES` | 4 | `executor/lease.py` |
| `MAX_RENEWALS` / `MAX_LEASE_LIFETIME_SECONDS` / `DEFAULT_LEASE_TTL_SECONDS` | 3 / 3600 / 300 | `executor/lease.py` |
| `MAX_JOURNAL_BYTES` / `MAX_JOURNAL_ENTRIES` | 262144 / 512 | `executor/journal.py` |
| `max_autonomous_actions_per_window` / `window_seconds` | 8 / 3600 | `governor.py` |
| `MAX_SPENT_NONCES` / `MAX_TOKEN_LIFETIME_SECONDS` | 256 / 900 | `authority/tokens.py` |
| `MAX_BUNDLE_BYTES` / `MAX_VOLATILE_SIGNALS` | 65536 / 16 | `evidence/preservation_gate.py` |
| `MAX_CATALOG_ENTRIES` | 32 | `operators/catalog.py` |
| `MAX_RECOVERY_STEPS` | 8 | `recovery/safe_state.py` |
| `MAX_EFFECTIVENESS_RECORDS` / `MIN_SAMPLES_FOR_RATE` | 256 / 8 | `memory/effectiveness.py` |
| `MAX_RESPONSE_CELLS` / `MIN_VERIFIED_EFFECTS_TO_CRYSTALLIZE` / `MIN_DISTINCT_EPOCHS_TO_CRYSTALLIZE` | 64 / 5 / 2 | `cells/response_cells.py` |
| `MAX_MONITOR_HISTORY` | 64 | `sentinel/monitors.py` |
| `MAX_CONTRACT_BYTES` | 8192 | `aegis/human_contract.py` |
| `SHADOW_AUTONOMY_CEILING` / `SHADOW_HUMAN_CEILING` / `MIN_CALIBRATION_SAMPLES` | 0.35 / 0.70 / 30 | `aegis/shadow.py` |
| `AUTONOMOUS_ROLLBACK_THRESHOLD` | 0.98 | `memory/effectiveness.py` |
| `MATERIAL_RESIDUAL` | 0.25 | `executor/residual.py` |
| `RULED_OUT_SUPPORT` | 0.05 | `safe/action_field.py` |
| `SATURATION_EPSILON` | 0.01 | `labs/fifty_experiments.py` |
| `STAGE5_NORMAL_INCREMENTAL_RSS_BYTES` / `STAGE5_PEAK_CEILING_BYTES` | 52428800 / 115343360 | `resources.py` |

**Every threshold in this table is a chosen parameter, not a measured one**, and the findings
document lists them under a `PARAMETERS` heading. A threshold reported as a finding is a fabricated
result.

**Rule A — the key-space rule, mandatory in three places.** Two waves have now shipped a defect where
two key spaces were joined that could never match (S2-FC-01; and Stage 3 repeated the class). Every
keyed lookup in Stage 5 ships a test asserting the two key spaces are **structurally identical**:

| key | producer | consumer | test |
|---|---|---|---|
| `identity_digest(ProcessIdentity)` | `CapabilityToken.target_digest`, `Lease.target_digest`, `TransactionReceipt.target_digest`, journal action key | `TokenStore.redeem`, `LeaseRegistry.leases_on`, `SentinelKernel._target_identity` | `test_every_target_key_space_is_identity_digest` — for 20 corpus actions, assert all five strings are equal |
| `context_key(epoch_id, mechanism_id, target_kind)` | `EffectivenessMemory.observe` | `AegisPlanner` / `EffectivenessMemory.record` | `test_effectiveness_write_key_equals_the_planner_read_key` |
| `incident_invariant` | `ResponseCellField.crystallize` | `ResponseCellField.lookup` | `test_cell_lookup_key_matches_the_crystallization_key` |

**Rule B — a check must exercise the mechanism it names.** Both prior stages shipped gate checks that
passed by asserting a type existed. Every `_check_*` in `gate.py` must call at least one function
that performs work and must be able to fail on an input that exists: `test_every_gate_check_can_fail`
constructs, per check, one deliberately non-compliant fixture and asserts the check reports FAILED.
A check for which no failing input can be constructed is deleted and replaced.

---

## 5. Work packages

Eight packages. **No two share a file.** `pocketsec/stage5/{__init__.py, gate.py, cli.py}`,
`docs/stage-5-findings.md`, the ten ADR files, `pyproject.toml` and `.github/workflows/ci.yml` are
**integrator-owned** and appear in no package.

| # | key | delivers | owns (repo-relative, all under `pocketsec/stage5/` unless shown) | depends on |
|---|---|---|---|---|
| 1 | `foundation` | D5.1, D5.6, D5.23 | `core_ids.py`, `constitution/invariants.py`, `constitution/schema.py`, `authority/capability.py`, `authority/tokens.py`, `governor.py`, `tests/test_stage5_foundation.py`, `tests/test_stage5_boundary.py` | — |
| 2 | `operators` | D5.5, D5.16, the simulated host | `operators/algebra.py`, `operators/catalog.py`, `operators/d3fend.py`, `host/simulated.py`, `tests/test_stage5_operators.py` | foundation |
| 3 | `sentinel` | D5.4, D5.10, D5.22 | `sentinel/kernel.py`, `sentinel/monitors.py`, `evidence/preservation_gate.py`, `labs/adversarial_load.py`, `tests/test_stage5_sentinel.py` | foundation, operators |
| 4 | `executor` | D5.11, D5.12 | `executor/identity.py`, `executor/journal.py`, `executor/transactional.py`, `executor/lease.py`, `labs/toctou.py`, `tests/test_stage5_executor.py` | foundation, operators, sentinel |
| 5 | `outcome` | D5.13, D5.14, D5.15, D5.17 | `executor/verify.py`, `executor/residual.py`, `recovery/safe_state.py`, `memory/effectiveness.py`, `cells/response_cells.py`, `tests/test_stage5_outcome.py` | foundation, operators, executor |
| 6 | `field` | D5.2, D5.7, D5.8 | `safe/action_field.py`, `twin/response_twin.py`, `aegis/cone.py`, `aegis/shadow.py`, `tests/test_stage5_field.py` | foundation, operators, outcome |
| 7 | `aegis` | D5.3, D5.9 | `aegis/planner.py`, `aegis/pareto.py`, `aegis/human_contract.py`, `tests/test_stage5_aegis.py` | foundation, executor, outcome, field |
| 8 | `benchmarks` | D5.18, D5.19 | `theory.py`, `assurance/properties.py`, `resources.py`, `stage6_interface.py`, `labs/response_corpus.py`, `labs/baselines.py`, `labs/fifty_experiments.py`, `tests/test_stage5_benchmarks.py` | all of the above |

D5.20 — the final falsification report — is `docs/stage-5-findings.md`, written by the integrator
from the packages' measured output plus the gate run.

**Build order is package order, and packages 1–4 are a gate on the rest.** Packages 1–4 carry the
entire security boundary. **Packages 5–8 do not start until `tests/test_stage5_foundation.py`,
`tests/test_stage5_boundary.py`, `tests/test_stage5_operators.py`, `tests/test_stage5_sentinel.py`
and `tests/test_stage5_executor.py` all pass.** This is an engineering judgement, not ceremony: if a
string can reach the executor, or SENTINEL can be bypassed, or a pid can be substituted between plan
and act, nothing that packages 5–8 measure is worth reading.

Each package is roughly **600–1200 lines of new code including its test file**. Packages 2, 4 and 8
sit at the top of that range (the catalog plus the host model; the executor plus the lease
controller; the corpus plus fifty experiment rows). Package 7 sits near the bottom — give that
engineer the ablation write-up as well if they finish early.

### 5.1 `tests/test_stage5_boundary.py` — owned by `foundation`

Implements, for Stage 5 only, the AST rules that `tests/test_repository_structure.py` implements for
Stages 0–2. Read that file for the technique — `_research_importers` at `:124` and the shared
resolver `imported_modules` (`stage2/gate_criteria.py:547`, imported, never copied) — and **leave it
untouched.** Nine rules:

1. **R1 / ADR-0001.** Every module under `pocketsec/stage5/` imports only roots in
   `sys.stdlib_module_names` or `pocketsec`.
2. **R2 / ADR-0008 + ADR-0040.** No module under `pocketsec/stage5/` imports any
   `pocketsec.stage*.research*`, and **`pocketsec/stage5/research/` does not exist.**
3. **T1.** The only `pocketsec.stage4.*` module imported anywhere under `pocketsec/stage5/` is
   `pocketsec.stage4.stage5_interface` (§2.5, ADR-0045). No module imports `pocketsec.stage2.*`,
   `pocketsec.stage6`…`stage12`, or anything under `stage3` except `stage3.cells` and
   `stage3.bytecode`.
4. **T4.** `typing.get_type_hints(TransactionalExecutor.execute)["operator"] is DefensiveOperator`,
   exactly — not a union, not `object`, not a string. And no module outside
   `pocketsec/stage5/executor/` and `pocketsec/stage5/recovery/` imports
   `TransactionalExecutor`.
5. **P2 / no-shell.** `no_arbitrary_command_path(REPO_ROOT / "pocketsec" / "stage5") == ()`.
6. **Planner is unprivileged (§35).** No module under `aegis/`, `safe/`, `twin/` or `cells/` imports
   `authority.tokens`, `executor.transactional`, `executor.journal`, or the name `SimulatedHost`
   (`HostSnapshot`, `HostRow` types are permitted — they are read-only data).
7. **SENTINEL is independent.** No module under `sentinel/` imports anything under `aegis/`, `safe/`,
   `twin/`, `memory/` or `cells/`; and the `sentinel/` package defines no name matching
   `(?i)force|override|bypass|skip|disable|dry_?run|unsafe|trust_me`.
8. **No second contracts package, no second ledger, no second harness.** `pocketsec/stage5/` contains
   no directory named `contracts`, `benchmark`, `experiments` or `research`, and no module defines a
   function named `run_benchmark` or a class named `ExperimentRegistry`.
9. **No empty package (ADR-0121).** Every directory under `pocketsec/stage5/` containing an
   `__init__.py` has at least one sibling module exporting at least one name, asserted by `ast`. And
   `pocketsec/stage5/response/` does not exist.

A committed negative-test fixture accompanies rules 1–3 and 5, in the shape of
`RELATIVE_RESEARCH_IMPORTS` (`tests/test_repository_structure.py:150`): the checker must catch
`from ..stage2 import x`, `from . import research` and `from ...stage4.worlds import world`, because
relative imports were invisible to two checkers at once in Stage 2 (S2-AUTH-01) and numpy could reach
the endpoint with CI green.

---

## 6. Acceptance gate, as executable checks

Fifteen checks, one per bullet of architecture §45, reproduced in
`planning/PHASE_05_CLAUDE_CODE.md`. Integration plan §5.1 fixes the count at **15**. Every
`_check_*` runs the real subsystem; the only two that read a file are G5.13 (whose subject is the
assurance table *and* runs each mutation) and G5.15 (whose subject is a document).

`Stage5GateContext.build()` runs the corpus, the planner, the executor and the baselines **once**, so
fifteen checks do not replay them fifteen times — `pocketsec/stage1/gate.py:55`, `:69`.

| id | §45 criterion | executable check | met on synthetic data? |
|---|---|---|---|
| **G5.1** | Stages 0–4 remain unchanged / frozen interfaces | Resolve all 83 seam symbols of §3.1 through `importlib` and assert each exists; assert `SCHEMA_REGISTRY[...]` version strings for `pocketsec.security_event_sequence.v1`, `pocketsec.threat_prediction.v1`, `pocketsec.ssir_transition.v1`, `pocketsec.knowledge_cell.v1` and `pocketsec.cbf_resolution.v1` equal the values pinned in `core_ids.py`; assert by AST that the only Stage 4 module Stage 5 imports is `stage5_interface`; assert `HYPOTHESES` keys are exactly `H0…H8` and `experiments/registry.jsonl` is byte-identical before and after this gate run. **It does not diff Stage 4's source**, because another wave is editing it (§2.6) | yes |
| **G5.2** | Only typed operators reach privilege | Four clauses. (a) `typing.get_type_hints(TransactionalExecutor.execute)["operator"] is DefensiveOperator`. (b) `executor.execute("SUSPEND_PROCESS", token)` and each of `dict`, `SimpleNamespace`, a structurally-identical forged `OperatorSpec`, and a `DefensiveOperator` whose `spec` is a deep copy of a catalog entry, **each raise** — `ContractError` or `TypeError`, never a silent coercion; the forged-spec case is the one that matters, because equality would have let it through and identity does not. (c) `OperatorSpec(...)` outside `catalog.py` raises on the `_CATALOG_TOKEN` check. (d) `no_arbitrary_command_path()` returns `()`. Reports the count of refused constructions: **target 5 of 5** | yes — pure construction |
| **G5.3** | SENTINEL can independently deny every action regardless of planner output | For **every** one of the 14 catalog operators, build a plan with maximal planner favour (`expected_security_delta=1.0`, `uncertainty=0.0`, resolution `Verdict.MALICIOUS` at `support=1.0`), then run 13 sub-cases per operator, each making exactly one SENTINEL input non-compliant, and assert `DENY` with the matching `DenyReason` — `14 × 13 = 182` denials, all required. Then the four independence cases: bypass-name AST absence; `None` in each optional-looking argument ⇒ `MISSING_INPUT`; a weakened `ResponseConstitution` raising at construction; each of the 13 checks monkeypatched to raise ⇒ `KERNEL_FAULT`. PASS requires **182 + 4 groups all denying** and `SentinelKernel.__init__`'s keyword-only parameter set `== {"constitution","invariants","clock"}` | yes — pure construction |
| **G5.4** | No model / LLM / text field can grant authority or construct arbitrary privileged commands | (a) The confidence-invariance test: 20 corpus cases, each emitted twice with leading support 0.99 and 0.01, asserting identical `chosen.authority`, required authority class and `approval_required`; report **20 of 20 identical**. (b) `GrantSource` has exactly two members and neither is `MODEL`. (c) Every `CandidateAction`/`DefensiveOperator` field is screened: no field whose value is a free string selects behaviour — asserted by constructing an operator from a resolution whose `claim_graph` text contains `"operator_id": "TERMINATE_PROCESS"` and every `IMPERATIVE_TOKENS` word, and asserting the generated field contains no O6 candidate. (d) `mint()` refuses a `POLICY` grant for an operator whose `autonomy_of` is `HUMAN_BY_DEFAULT` or stricter | yes |
| **G5.5** | Target identity is revalidated immediately before intervention | AST: within `_commit`'s body, the `revalidate` call precedes `host.apply` with no call between them. Behavioural: the four `labs/toctou.py` races (EXITED, PID_REUSED, EXECUTABLE_CHANGED, UID_CHANGED) at `pid_reuse_rate=1.0`, asserting `Outcome.REFUSED_IDENTITY`, `host.apply` call count unchanged, and the substituted process untouched in the post-snapshot. Plus `test_every_target_key_space_is_identity_digest` over 20 actions. PASS requires **4 of 4 races refused and 0 wrong-target applications** | yes |
| **G5.6** | Every autonomous intervention is scoped, expiring, observable and rollback-aware | For every receipt in the corpus run with `outcome in {COMMITTED_*}` and `operator_class >= O2`: assert a `Lease` exists with a non-`None` `rollback_operator_id`, `ttl_seconds <= spec.max_duration_seconds`, `target_digest` equal to the receipt's, and at least one `PostconditionKind` probed. Then, under `ManualClock`: advance past every TTL, run `LeaseSweeper.sweep()`, assert every lease expired, every rollback executed, and the simulated host restored to its pre-action snapshot digest. Assert `active(now) == ()` afterwards. PASS requires **100% of ≥O2 receipts leased and 100% of expired leases swept** | yes (in-simulator) |
| **G5.7** | Every autonomous operator meets a predefined rollback reliability threshold | `EffectivenessMemory.meets_threshold(operator_id, epoch_id, AUTONOMOUS_ROLLBACK_THRESHOLD)` for every operator in `autonomous_ids(FROZEN_CONSTITUTION)`; a `None` (fewer than 8 samples) **fails, it does not pass**. Reports `simulated_rollback_success` per operator with its `n`, and reports real-host reliability as **UNMEASURED**. **This check FAILS by construction** while `host_kind is SIMULATED`: `_check_rollback_reliability` asserts `report.host_kind is HostKind.REAL` for the criterion to be met | **NO** — §6.1 |
| **G5.8** | Evidence and mission invariants are machine-enforced | (a) `build_evidence_destroying_cases`: for each, assert the gate returns `REFUSED_WOULD_DESTROY`, the executor's outcome is `REFUSED_EVIDENCE`, **the refusal is recorded** in the receipt and in `ResponseRecordV1.sentinel_denials`, and the host is unchanged. (b) `build_critical_service_baits`: assert `MISSION_INVARIANT` denial for every bait, and that `MissionInvariantSet.violations` is a total match (a synthetic new `InvariantKind` member makes `mypy --strict` fail — asserted by a committed fixture, not by running mypy). (c) Over the whole corpus: **mission-invariant violations 0 and evidence-preservation violations 0; both targets are zero and a single violation fails the check.** (d) An `EXCEPTION_GRANTED` requires an `A5` `HUMAN` grant; a `POLICY` grant at `A5` is refused | yes |
| **G5.9** | Multi-world evaluation demonstrably reduces collateral in ambiguous incidents | `saturation_check` **first**; `DEGENERATE` ⇒ FAIL with the reason and nothing recorded. Then run `build_ambiguous_pairs(count=30, seed=17)` through the full planner and through B7 `single_world_planner` in the same process, and compare `collateral_per_1000` at equal `incidents_contained`. PASS requires the multi-world planner strictly lower on collateral **and** no worse on containment. Reports both numbers with `/proc/loadavg` | **NO** — §6.1 |
| **G5.10** | Post-action verification detects ineffective or divergent actions | Inject, through `FaultProfile`, `enforcement_failure_rate=1.0` (the host reports success and changes nothing) and assert `verification_outcome` is `INEFFECTIVE` and a rollback ran; then `dependency_restart_rate=1.0` (the state postcondition holds, a dependency service dies) and assert `DIVERGENT` and a rollback ran. Then assert a case where a required probe is unobservable yields `UNVERIFIABLE` with `satisfied is None` — **not `False`** — and that the receipt's outcome is `COMMITTED_UNVERIFIED`, never `COMMITTED_VERIFIED`. Reports detection rate: **target 100% of injected faults detected** | yes |
| **G5.11** | Safe recovery is demonstrated after containment | Contain 20 cases, then `SafeStatePlanner.plan` + `execute_recovery`; assert `final_status is ManifoldStatus.INSIDE` for every case whose truth says recovery is possible, that each step restored at most one capability between probes, and that the `OUTSIDE_UNRECOVERABLE` cases escalate rather than looping. **The check asserts `report.simulated is False` for the criterion to be met, and therefore FAILS** while only the simulated host exists | **NO** — §6.1 |
| **G5.12** | Resource and action fan-out remain bounded under adversarial load | `labs/adversarial_load.py` runs `build_action_flood(count=40, seed=23)` plus the candidate-flood and self-DoS suites. Assert at every step: `len(field.candidates) <= MAX_CANDIDATES`; cone depth ≤ 3 and nodes ≤ 32; twin nodes ≤ 64; `journal.bytes_used() <= MAX_JOURNAL_BYTES`; `len(leases.active(now)) <= 4`; autonomous actions in the window ≤ 8; `governor.spend_report()["total"] <= max_work_units`. Assert **every** loss emitted a truncation or a `PruneRecord`, and that `BudgetExhausted` escalated rather than widening a cap. Then `measure_stage5_resources`: incremental RSS ≤ 50 MB, peak ≤ 110 MB via `ResourceSampler`; `within_target is None` if unmeasured and the check then reports UNMEASURED, **never PASS**. Wall-clock recorded beside `/proc/loadavg` as **observed, not asserted** | yes |
| **G5.13** | At least the safety-critical executor properties targeted for formal verification are proven or explicitly downgraded to empirical claims | Enumerate `EXECUTOR_PROPERTIES`; assert each `PROVEN_BY_CONSTRUCTION` names a `construction` path that resolves to a real symbol **and** a `mutation`, and **run each mutation**: apply it in a temporary copy of the package (or monkeypatch the named symbol) and assert the property's test now fails. A "proven" property whose mutation does not break anything is downgraded to `TESTED` and the check FAILS until the table says so. Assert every `TESTED`/`UNMEASURED` statement contains no `VERIFICATION_WORDS` member, every `UNMEASURED` has a `why_not`, and `unearned_verification_language(docs/stage-5-findings.md)` is `()`. Reports the three counts | yes |
| **G5.14** | Advanced mechanisms survive ablation against simpler playbooks / controllers | `saturation_check` first. Then `run_baselines` over all nine §7 baselines in one process on one corpus, and `run_ablation` for each of the nine `PlannerConfig` flags. PASS requires: the full planner on the `pareto_frontier_of` the baselines on `(collateral_per_1000, incidents_contained, work_units)`; **and** every OPTIONAL `SAFE-F*` core id carrying an `AblationRow` with a **measured** non-`None` delta and a registered experiment id. A flag whose delta is `None` is `UNMEASURED` and fails; a negative delta is `HARMFUL` and the mechanism is defaulted off with an ADR | yes (in-simulator; §6.1's caveat on what it means) |
| **G5.15** | No external novelty claim is made before literature / patent review | Assert `set(HYPOTHESES) == {"H0"…"H8"}` and `set(PriorArtLedger.load().entries) == set(HYPOTHESES)` — Stage 5 appended to neither (§2.8). Assert `docs/stage-5-findings.md` exists, contains all five honesty-ledger headings, and contains no token in `{novel, novelty, first, unprecedented, patent, breakthrough, state-of-the-art}` within 3 lines of any §49 construct name (`SAFE, AEGIS, SENTINEL, Action Shadow, Intervention Cone, Response Identifiability, Safe-State Manifold, Intervention Residual`) unless the same paragraph contains the literal string `no novelty claim`. Assert `mapped_fraction() == 0.0` **or** a committed `D3FENDSnapshot` with a real release string exists — an invented technique id fails here (ADR-0047). Assert `experiments/registry.jsonl` byte-identical | yes |

### 6.1 The criteria that cannot be met on synthetic data, declared

**G5.7 — "every autonomous operator meets a predefined rollback reliability threshold": NOT MET, and
the check is written to fail rather than to pass on a simulator.**

This is the hardest honest problem in the stage and the lead named it. Rollback reliability is a
property of a *Linux host*: whether `SIGCONT` actually resumes a process whose parent has died,
whether a cgroup restriction releases cleanly, whether a systemd unit returns to its prior state
after `RELEASE_SERVICE`. This repository has no real host, no real telemetry, and — deliberately —
no `RealHost` implementation. **Do not simulate a kernel and then report the simulation's success
rate as rollback reliability.** `SimulatedHost` decides whether a rollback succeeds by consulting
`FaultProfile.rollback_failure_rate`, a number this wave chose. Measuring against it measures the
choice.

What G5.7 *can* honestly report, and does: `simulated_rollback_success` per operator with its sample
count, over a declared `FaultProfile`, as a property of the protocol's *handling* of failure — that
a failed rollback produces `Outcome.ROLLBACK_FAILED`, escalates, and does not report success.
**The criterion itself reports UNMEASURED and the check FAILS**, with `why_not` = "no real host" and
"what would measure it" = *paired containment/restore drills on an instrumented Linux host with
injected ground-truth actions, across ≥8 repetitions per operator per kernel version*. ADR-0046.

**G5.11 — "safe recovery is demonstrated after containment": the mechanism is demonstrated, the
criterion is not.** Same reason, same discipline: `_check_safe_recovery` asserts
`report.simulated is False` and therefore fails. The staged-restoration *mechanism* — one capability
at a time, probe between steps, escalate on `OUTSIDE_UNRECOVERABLE` — is real code that real tests
exercise, and that is worth having. "Recovery works on a Linux host" is not a claim this wave may
make.

**G5.9 — "multi-world evaluation demonstrably reduces collateral": the comparison runs, the
conclusion cannot be generalised.** Three independent reasons, all already paid for in this
repository:

1. **The harm model is authored by the same wave as the planner.** `GroundTruthResponse.
   harmful_operator_ids` and `HarmModel.unacceptable` are hand-written tables, and "collateral" is
   defined by them. A planner that avoids collateral is partly a measurement of the authoring. This
   confound does not exist for G5.2, G5.3, G5.4, G5.5, G5.6, G5.8, G5.10, G5.12 or G5.13, which are
   construction and bound properties — and those nine are the criteria this wave can actually settle.
2. **Synthetic corpora in this repository produce only trivial or impossible tasks, never a middle
   band** (ADR-0010, across four corpora). The Stage 2 gate's G2.2 reports
   `ORDER_FREE_BASELINE_TIES_BEST` with best 1.0 and median 0.6586. `saturation_check` runs first
   precisely so a degenerate split produces `DEGENERATE` and no recorded comparison.
3. **`support` in an ambiguous pair is a number this wave wrote into a fixture.** Whether Stage 4
   would produce two worlds within `IDENTIFIABILITY_MARGIN` on real telemetry is unknown, and Stage
   4's own spec declares its world-recall measurement confounded for the same reason.

**Two further clauses inside otherwise-passable criteria are UNMEASURED and must be declared:**

- **G5.14's ablation is a fair comparison inside the simulator and nothing more.** Because every
  baseline and the full planner run against the *same* `SimulatedHost` with the *same*
  `FaultProfile`, the simulator biases all ten arms equally, so "the twin beats the fixed playbook"
  is a real, falsifiable, within-model result. It is **not** evidence that the twin helps on a Linux
  host. Both sentences go in the findings.
- **G5.12's resource figures are real bytes from `ResourceSampler` and contended wall-clock.** The
  byte figures transfer; the millisecond figures do not (§2.8). `within_target` is `None`, never
  `True`, when nothing was measured.

**Expected gate outcome, stated in advance so a failing gate is not mistaken for a failed wave:**
**G5.7 and G5.11 FAIL by construction. G5.9 very likely FAILS or reports `DEGENERATE`. G5.14 is the
genuine unknown.** Nine to eleven of fifteen is the honest expectation, and a gate reporting 15/15
should be treated as evidence that a check cannot fail (Rule B, §4.9) rather than as success.

---

## 7. The baselines Stage 5 must beat

These are the dumbest things that could work, and they are the comparison, not a formality. All nine
live in `pocketsec/stage5/labs/baselines.py`, all stdlib, all running through the **real** SENTINEL,
the **real** executor and the **same** `SimulatedHost`, in one process and one run.

| id | baseline | what it is | the metric the advanced component must win on |
|---|---|---|---|
| **B1** | `no_automated_response` | Observe and record. Never act. The `act-never` degenerate bound. | **The whole stage.** §44: "Active response causes more operational harm than recommendation-only mode" is a falsifier. Active response must achieve strictly higher `incidents_contained` at **zero** `mission_invariant_violations`. If B1 has fewer collateral incidents *and* comparable containment, Stage 5 is not justified as an actor and reduces to a recommender. |
| **B2** | `fixed_playbook` | **The competent-sysadmin control the lead named.** A static table: `if phi(state).total > 6.0 and StateDelta.bitmask() & PRIVILEGE: SUSPEND_PROCESS on the highest-ΔΦ lineage`. Depth ≤ 3, no worlds, no twin, no cone, no Pareto, no lease. Roughly 40 lines. | **The control for D5.2, D5.3, D5.7, D5.8 and D5.9 together.** The SAFE Action Field, the Counterfactual Response Twin, the Intervention Cone and the Pareto/regret selector must beat it on `collateral_per_1000` at equal-or-better `incidents_contained`, with `mission_invariant_violations` 0 for both. **If they do not, ADR-0048 reports the machinery as not justified and recommends removing it.** This is the single most important row in the table. |
| **B3** | `simple_if_then_containment` | One rule per `mechanism_id`, read from a dict, ignoring host context, uncertainty and mission invariants. | **Context-awareness.** The full planner must show that reading the snapshot, the invariants and the identifiability state reduces collateral. B3 is B2 plus a mechanism vocabulary and nothing else. |
| **B4** | `always_isolate` | `SUSPEND_PROCESS` on the leading lineage of every incident, unconditionally. The `act-always` degenerate bound. | **Collateral bound.** B4 defines the top of the collateral axis and the top of the containment axis. Any mechanism not strictly inside the (containment, collateral) box defined by B1 and B4 has added nothing. Reported as the frontier's endpoint, never as a competitor. |
| **B5** | `d3fend_lookup_only` | Choose the operator whose `d3fend_technique_id` maps to the resolution's mechanism, and act. **With no snapshot committed, every operator is UNMAPPED, so B5 degenerates to "no candidate" and acts never.** | **The ontology-versus-decision baseline (§28).** Its degeneracy *is* the result: an external ontology that maps nothing cannot prioritise anything, which is exactly MITRE's own statement about D3FEND. Reported as `UNMAPPED, 0 actions`, not as a loss. |
| **B6** | `single_scalar_utility` | `scalar_utility(scored, DEFAULT_WEIGHTS)` — one weighted sum over the nine objectives, chosen instead of the Pareto frontier. | **D5.9's Pareto/regret machinery (§12).** The frontier-then-policy selector must produce strictly lower `collateral_per_1000` at equal containment. §12's argument is that arbitrary weights hide trade-offs; if the arbitrary weights match, the argument is unsupported and ADR-0048 says so. |
| **B7** | `single_world_planner` | **The lead's mandated single-world control.** Act on the highest-`support` hypothesis only. No counterfactual twin, no intervention cone, no per-world regret. Same catalog, same SENTINEL, same leases. | **D5.7, D5.8 and multi-world evaluation (G5.9).** Measured on `build_ambiguous_pairs`, where a benign-admin world and a compromised world carry identical evidence. B7 must commit; the full planner may refuse. Metric: `collateral_per_1000` at equal `incidents_contained`. **Expect B7 to be strong** — it was for Stage 4's B1 equivalent, and Stage 2's zero-parameter Φ-oracle beat four learned models. |
| **B8** | `no_hysteresis` | Immediate action on every threshold crossing. No `min_dwell_seconds`, no cooldown, no lease, no `max_action_cycles`. The control for D5.12. | **The lease/hysteresis controller (§19).** Metric: `actions_taken` at equal `incidents_contained`, plus the `ACTION_OSCILLATION` monitor's fire count. The controller must take strictly fewer actions and must not lose containment. **If hysteresis does not reduce action count on a corpus with belief that fluctuates around the threshold, ADR-0049 reports it as not justified.** |
| **B9** | `human_only` | Every candidate escalates; a scripted "analyst" approves the truth-optimal action after a fixed delay. §40's operational-benefit baseline. | **Whether autonomy is worth anything.** Metric: `human_escalations` avoided at zero `mission_invariant_violations`. §42's "human approvals avoided safely" is the number, and "safely" means the violation counts stay at zero. B9 is the upper bound on correctness and the lower bound on autonomy. |

**Declared UNMEASURED, with reasons, in the honesty ledger — not silently omitted:**

| §40 baseline | why it is not built |
|---|---|
| RL response planner | needs gradient descent, and ADR-0040 forbids numpy in Stage 5 permanently — a research package here is a supply-chain path into the executor. A hand-rolled stdlib policy-gradient learner would be a *worse* comparison than none: `MEMORY.md` trap 5 — a detached projection scored 0.55 and 0.94 once fixed, and a broken baseline flatters the mechanism. §31 already says RL response systems are "a research baseline, not the default production architecture". |
| "Model-free safe controller" as a *learned* controller | same reason. B2 and B8 cover the model-free end deterministically and are named as *partial* substitutes, not equivalents. |
| Real-world commercial EDR playbooks | not present in this repository and not reimplementable honestly at this scale. B2 is the honest stand-in and is described as "what a competent sysadmin would write in an afternoon", not as an industry baseline. |

Three rules on every comparison, each of which this project has paid to learn:

1. **Run `saturation_check` first.** If the best and median baselines are within
   `SATURATION_EPSILON`, or if `always_isolate` or `no_automated_response` ties the best, the result
   is `DEGENERATE` and **nothing is recorded** (ADR-0120, `MEMORY.md` trap 9).
2. **Every baseline runs through the real SENTINEL and the real executor.** A baseline that bypasses
   the kernel measures a different system.
3. **Same run, same seed family, same process, `/proc/loadavg` recorded.** Only within-run ratios
   transfer off this host (§2.8).

---

## 8. What would falsify this stage's central claim

**The central claim.** *Converting an uncertain causal belief field into the smallest typed,
authority-bounded, expiring, evidence-preserving and post-verified defensive change produces less
operational harm, at comparable containment, than either acting on the single most likely explanation
or following a static playbook — and the safety envelope that makes this possible is enforced by
construction rather than by policy.*

Ten falsifiers, from architecture §44, each bound to the check that fires it. **A fired falsifier is
a result, and it goes in an ADR from the 0040–0049 block.**

| # | falsifier | fires when | consequence |
|---|---|---|---|
| **F1** | Static playbooks match AEGIS on security outcome and collateral at materially lower complexity | G5.14: B2 `fixed_playbook` reaches `incidents_contained` within 1 case of the full planner at `collateral_per_1000` no higher, at lower `work_units` | **SAFE/AEGIS's planning machinery is not justified.** ADR-0048 recommends removing the twin, the cone and the Pareto selector and shipping the playbook behind SENTINEL. **This is the most likely falsifier to fire**, and the honest outcome is a Stage 5 that is a small typed executor plus a table |
| **F2** | The response twin cannot predict enough operational consequence to affect decisions | `run_ablation(flag="enable_twin")` delta is `0.0`, or `simulated_twin_prediction_error` exceeds `MATERIAL_RESIDUAL` on more than half the corpus | D5.7 removed; `enable_twin` defaults `False`. ADR-0048. Note the distinction: on a corpus with no headroom, "found nothing" is `NOT_YET_JUSTIFIED`, **not** `REJECTED` (ADR-0009's lesson, and two Stage 2 components turned out to be actively harmful only on the third corpus) |
| **F3** | Action Shadow cannot be calibrated sufficiently to gate autonomy | `calibrate_shadow` returns `rank_correlation is None` (fewer than 30 pairs) or a correlation below 0.3 | `shadow_gate` cannot gate autonomy on evidence; `enable_shadow_gate` stays on as a **conservative heuristic explicitly labelled uncalibrated**, and the findings say the ceiling is a chosen parameter. ADR-0048 |
| **F4** | Pareto/regret planning does not reduce unnecessary disruption | B6 `single_scalar_utility` matches the frontier selector on collateral at equal containment | D5.9 reduces to a weighted sum; ADR-0048. §12's central argument is unsupported |
| **F5** | SENTINEL cannot remain small and independent enough to meaningfully reduce the trusted computing base | `sentinel/kernel.py` + `sentinel/monitors.py` + `evidence/preservation_gate.py` exceed 900 lines combined, or the boundary test finds any import from `aegis/`/`safe/`/`twin/`, or G5.3's 182 denials are not all achievable | **Blocks the phase.** §35's trusted-computing-base argument is the reason the architecture separates the kernel at all. Report BLOCKED |
| **F6** | Rollback reliability is insufficient for an operator proposed as autonomous | G5.7: any operator in `autonomous_ids()` whose `simulated_rollback_success` is below `AUTONOMOUS_ROLLBACK_THRESHOLD`, **or** whose sample count is below `MIN_SAMPLES_FOR_RATE` | that operator leaves `autonomous_ids()`. **And note: G5.7 already fails for every operator on real-host grounds (§6.1), so F6's in-simulator variant is the weaker statement** |
| **F7** | Active response causes more operational harm than recommendation-only mode | B1 `no_automated_response` shows lower `collateral_per_1000` **and** `incidents_contained` within 1 case of the full planner | **Stage 5 is not justified as an actor.** ADR-0048 recommends recommendation-only mode as the default and autonomy as opt-in per operator. This is a legitimate and possibly correct outcome |
| **F8** | Response Knowledge Cells become stale faster than they save compute or decision effort | over `build_two_epoch_corpus`, more cells melt than are crystallized, or median cell lifetime is below one epoch | D5.17 removed. Precedent: ADR-0021 — Stage 3's Knowledge Cell format lost to the rule it wrapped. **Expect this to fire, because `MIN_DISTINCT_EPOCHS_TO_CRYSTALLIZE=2` may mean zero cells crystallize at all** (Stage 2's G2.13: "distinct_epochs 1 < 2, so NOTHING was exported") |
| **F9** | Local effectiveness memory overfits and degrades safety across epochs | a cell or an autonomy decision justified by pre-epoch statistics survives an `EpochDecision` and then produces a `mission_invariant_violation` or a `collateral` event | D5.15's autonomy input is removed; memory becomes reporting-only. **A safety regression across epochs blocks the phase** |
| **F10** | Stage 5 violates the Stage 0 resource envelope | `ResourceSampler` incremental RSS > 50 MB or peak > 110 MB, or Stages 1–4 no longer fit the 2 GB host target alongside it | **Blocks the phase.** The 2 GB target is a hard architectural constraint (`MEMORY.md`) |

**The cheapest falsification to run, and therefore the first:** F5's boundary half, inside
`tests/test_stage5_boundary.py`. It needs no corpus, no host and no measurement — nine AST rules over
a package. If the planner can reach the token store, or a string can reach the executor, the stage is
unsafe and nothing else is worth measuring. **Run it in package 1, before the catalog exists.**

**The most likely to fire:** F1, in G5.14, for §6.1's reasons. Plan ADR-0048 now, and write it
whichever way the measurement falls.

**One falsifier deliberately absent from the architecture's list, added here:** if `no_shell` or the
typed-operator property can be broken by any of G5.2's five constructions, the phase is **BLOCKED**,
not failed. A privilege-boundary defect is not a negative result about a mechanism; it is a
vulnerability in the only stage that touches privilege.

---

## 9. Honest limits — what this wave cannot prove

### 9.1 The one that matters most

**Nothing in this wave is a measurement of a Linux host.** `SimulatedHost` is a dictionary of
`ProcessRow` and `ServiceRow` objects with a seeded fault profile. It decides whether
`SUSPEND_PROCESS` works, whether a rollback succeeds, whether a dependency restarts and whether
evidence is lost — all from numbers this wave wrote. **A number produced by a simulator you also
wrote is a property of your simulator.**

Therefore, in the findings document and in the gate output:

- rollback reliability, containment effectiveness, collateral rate, time-to-effect and recovery
  success against a real host are **UNMEASURED**;
- every in-simulator figure is named `simulated_*` so the caveat travels with the number into every
  table that quotes it;
- `TransactionReceipt.host_kind` and `.simulated` are required, non-defaulted fields, and
  `ResponseRecordV1.to_dict()` raises on the inconsistent combination, so a simulated record cannot
  become a real one by omission three stages later.

ADR-0046 records this, and it is the ADR to read first.

### 9.2 The rest

1. **No real telemetry, anywhere.** Every corpus in this repository is synthetic, and four Stage 2
   corpora produced only trivial or impossible tasks, never a middle band (ADR-0010). Containment
   rates, collateral rates and missed-containment counts are harness output, **not** detection or
   response results.
2. **The harm model and the planner share an author.** `HarmModel.unacceptable` and
   `GroundTruthResponse` are hand-written tables, and "collateral" means "what those tables say".
   G5.9's and G5.14's outcome-quality axes carry that confound; the construction and bound criteria
   (G5.2–G5.6, G5.8, G5.10, G5.12, G5.13) do not, and they are what this wave can settle.
3. **`support` values in ambiguous pairs are fixtures.** Whether real telemetry yields two worlds
   within `IDENTIFIABILITY_MARGIN` is unknown; Stage 4 declares the same confound on its own side.
4. **Every threshold in §4.9 is a chosen parameter.** `SHADOW_AUTONOMY_CEILING = 0.35`,
   `AUTONOMOUS_ROLLBACK_THRESHOLD = 0.98`, `MATERIAL_RESIDUAL = 0.25`, `RULED_OUT_SUPPORT = 0.05`,
   the hysteresis thresholds, the nine `DEFAULT_WEIGHTS`. None is fitted. A threshold reported as a
   finding is a fabricated result, and the findings document lists them under `PARAMETERS`.
5. **Action Shadow calibration will very likely return `None`.** `MIN_CALIBRATION_SAMPLES = 30`
   requires 30 committed actions with measured residuals in one run; the corpus may not reach it.
   `None` is the honest answer and is not a pass (ADR-0004: `None` never means zero).
6. **Response cells will very likely crystallize zero times.** `MIN_DISTINCT_EPOCHS_TO_CRYSTALLIZE`
   is 2 and Stage 2's detection corpus had one epoch. `build_two_epoch_corpus` exists to give the
   mechanism a chance; if it still yields nothing, that is F8 and it is reported, not worked around
   by lowering the bound.
7. **Token replay resistance is bounded at 256 nonces.** Beyond that window, `NONCE_EVICTED` is
   returned and treated as a refusal. The property is "no replay within the last 256 tokens", and
   P11's statement says exactly that. An unbounded nonce set would violate the bounded-state
   invariant, so this is a deliberate trade, stated rather than hidden.
8. **`executable_digest` is `None` in the corpus for most processes.** Real executable hashing needs a
   real filesystem. `revalidate` therefore returns `UNOBSERVABLE` rather than `MATCH` in those cases,
   which is the fail-closed reading — but it means the *strongest* identity binding the architecture
   asks for (§17's "executable identity/hash where available") is exercised on fixtures, not on files.
9. **Namespace and cgroup identity are strings in a fixture.** `BOUNDARY_NOT_CROSSED` is enforced
   against those strings. Whether the check corresponds to a real namespace boundary is UNMEASURED.
10. **No timing figure is a device measurement.** Load on this host was 8.77 while the seam script
    ran, and a Stage 2 gate saw 7× inflation at load 23–67. Only within-run ratios transfer, every
    ratio is recorded beside `/proc/loadavg`, and `work_units` — not milliseconds — is the primary
    cost metric everywhere in this stage for exactly that reason.
11. **D3FEND coverage is expected to be 0 of 14.** No network access is assumed, so no snapshot can
    be fetched, so every operator is `UNMAPPED`. That is the correct outcome: a wrong external
    identifier is worse than an absent one (ADR-0047).
12. **`ruff` and `mypy` have never been run in this repository** (`MEMORY.md`, "Known gap"). Lint and
    strict-type status across Stage 5's ~30 new modules is UNVERIFIED unless this wave installs them,
    and the findings must say which of the two ran and the exact counts.
13. **Stage 4 is being built concurrently.** `pocketsec/stage4/stage5_interface.py` exists and every
    symbol Stage 5 needs from it resolves today (MEASURED, §0), but Stage 4 has no gate and its own
    spec says ADR-0036 may delete its multi-world machinery. If `CBFResolutionV1` changes shape
    mid-wave, Stage 5 reports **BLOCKED** on a required prior-stage contract rather than editing
    Stage 4 (phase file STOP condition 1).
14. **The eleventh §33 attack family — "false Stage-4 certainty designed to trigger containment" — is
    tested against a fixture we construct.** A real adversary shaping a real Stage 4's belief field is
    outside what this wave can build.
15. **There is no `RealHost`, not even a stub.** A stub is the thing someone fills in under deadline
    pressure. Implementing one, and the privilege-drop, seccomp and capability analysis it needs, is
    follow-on work requiring its own ADR outside the 0040–0049 block.

---

## 10. ADRs — block 0040–0049, all ten assigned

Verified free this session: `ls docs/adr/ | grep -cE '^00(3|4)[0-9]-'` → `0`. **No number outside
0040–0049 may be used.** If an eleventh decision is needed it amends an existing ADR in the block.
Every ADR uses `docs/adr/0000-adr-template.md` and keeps its **Options considered** table with a
*measured consequence* column. An ADR whose options table has no measured column is a design note,
not an ADR.

| ADR | title | required before |
|---|---|---|
| **0040** | Stage 5 ships no `research/` package, no numpy and no third-party import — permanently, because this is the privileged stage | package 1's first merge |
| **0041** | The executor accepts exactly one type; `OperatorSpec` is catalog-only by construction and an argument vector is assembled from a closed `ArgvAtom` union, never formatted from a string | package 2 |
| **0042** | SENTINEL is independent by construction: three constructor parameters, no bypass name, fail-closed on a missing input and on a raising check — and the property counts of the assurance table, stated honestly | package 3 |
| **0043** | Target identity is a `ProcessIdentity` tuple and `identity_digest` is the single key space; revalidation happens inside `_commit`, immediately before the host call | package 4 |
| **0044** | Leases expire as a pure function of the lease against an injected clock, and the rollback is performed by an explicit `LeaseSweeper` rather than incidentally by another call path | package 4 |
| **0045** | Stage 5 consumes Stage 4 only through `CBFResolutionV1`; no live Stage 4 object crosses the seam, and `ResponseRecordV1` is the only artefact Stage 6 sees | packages 1 and 8 |
| **0046** | The host is a simulated model. Rollback reliability, containment effectiveness and recovery success measured against it are properties of the simulator; against a real host they are UNMEASURED, and G5.7/G5.11 fail rather than pass | package 2, and restated in the findings |
| **0047** | D3FEND is vocabulary, never a decision oracle: a mapping requires a committed dated snapshot, everything else is `UNMAPPED`, and no privileged module may import the adapter | package 2 |
| **0048** | **measurement** — SAFE/AEGIS (twin, cone, Pareto/regret, multi-world) versus the fixed playbook and the single-world planner: the measured verdict | gate run; written whichever way it falls |
| **0049** | **measurement** — the lease/hysteresis controller versus immediate action: the measured verdict | gate run |

0040–0047 are design decisions and land with their package. **0048 and 0049 are measurement ADRs and
must not be written before the measurement exists.** ADR-0125's rule applies and it was learned the
hard way: *a rejection branch needs a reproduced measurement, not a flag and a filename.* Stage 2's
G2.6 passed for a whole wave on two hardcoded flags plus a `docs/adr/*.md` filename, and the cone it
declared "removed" was running on every deep event and supplying 0.45 of the abstention weight.

**Note on the block.** Integration plan §5.5 assigned Stage 5 the block 0033–0042. The project lead
reassigned it to **0040–0049**, and Stage 4's spec has taken 0030–0039. The lead's assignment
governs. Both blocks are currently empty on disk, so there is no collision either way, but a Stage 5
ADR numbered 0033–0039 would collide with Stage 4's wave and must not be written.

---

## 11. The honesty ledger `docs/stage-5-findings.md` must end with

Verbatim in structure, per integration plan §7. G5.15 asserts all five headings are present, and the
phase is **not complete** without them. Stage 5 adds a sixth, `PARAMETERS`, because §4.9's table of
chosen thresholds is the most likely thing in this stage to be misread as a finding.

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

### PARAMETERS
Every threshold, weight and bound this wave CHOSE rather than measured. One row each.

| constant | value | module | why this value | measured? |
|---|---|---|---|---|
```

Three distinctions the format exists to keep, restated because Stage 5 will need all three:

- **NOT-YET-JUSTIFIED is not REJECTED.** ADR-0009 got this right under pressure: three components
  showed no benefit on a *saturated* corpus, which cannot demonstrate benefit at all. They were
  flagged, retained and re-tested — and on the ambiguous corpus two turned out to be actively harmful
  (−0.115, −0.073). Collapsing the categories would have lost that.
- **RETRACTED is not deleted.** `docs/stage-2-dtl-findings.md:336` retracts its own headline result
  and keeps the superseded text with the defect that produced it. That is the standard.
- **`None` never means zero** (ADR-0004). A rollback reliability of `None` is "fewer than 8 samples",
  not "0.0". A `satisfied is None` postcondition is "unverifiable", not "failed". A
  `within_target is None` is "not measured", not "over budget".

Additionally, the findings document must contain, near the top, the sentence the lead required:
**"Rollback reliability against a real Linux host is UNMEASURED. Every rollback figure in this
document was produced by a simulated host model this wave wrote, and is a property of that
simulator."**

---

## 12. Completion output

At the end of the wave, print:

1. `PHASE 5 STATUS: COMPLETE | PARTIAL | BLOCKED`
2. implemented checklist IDs (01–20 ↔ D5.1–D5.20);
3. files/modules changed, integrator-owned files named separately;
4. tests run and exact results — `PYTHONHASHSEED=0 python -m pytest -q tests/test_stage5_*.py`
   counts, plus the full-suite result with **Stage 4's failures listed as another wave's
   work-in-progress and not counted against Stage 5**;
5. `python -m pocketsec.stage5.cli gate` verbatim: `GATE: PASSED|FAILED (n)`, exit code, and every
   check's one-line detail, with `/proc/loadavg` recorded beside every timing figure;
6. benchmark/resource results actually measured, every simulator-bound figure named `simulated_*`;
7. unresolved defects and risks;
8. architecture deviations and the ADRs written (0040–0049 only), with 0048/0049 stating the measured
   verdict whichever way it fell;
9. the exact `MEMORY.md` and `PROGRESS.md` updates;
10. the recommended next phase — **without starting it** (phase file STOP condition).

**The expected honest status is `PARTIAL`.** G5.7 and G5.11 fail by construction on real-host
grounds; G5.9 likely fails or reports `DEGENERATE`; F1 and F8 are likely to fire. A wave that reports
`COMPLETE` with 15/15 should re-read §4.9's Rule B before believing it.

**Report `BLOCKED`, not `PARTIAL`, if:** `CBFResolutionV1` changes shape mid-wave; any of G5.2's five
forged-construction cases succeeds; SENTINEL cannot achieve all 182 denials; F5, F9 or F10 fires; or
completing the work would require silently changing this specification.
