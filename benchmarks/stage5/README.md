# benchmarks/stage5/ — the Stage 5 measurement scripts

Every figure in `docs/stage-5-findings.md` §M (the measurement wave) was produced by one of
these scripts, run from the repository root as

```
PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage5/<script>.py [--record EXPERIMENT_ID]
```

Without `--record` a script only prints. With it, the script writes
`results/<EXPERIMENT_ID>.json` (git-ignored, integration plan §5.3) and appends one
digest-chained row to `experiments/registry.jsonl` through `ExperimentRegistry.register`.
The registry refuses a reused id, so each id can be recorded exactly once.

**Why outside `pocketsec/stage5/`.** Each script needs something the stage's own rules
forbid inside the package: naming the executor (T4), importing a Stage 4 module other than
`stage5_interface` (T1), launching a process (P2), or loosening the Action Shadow ceiling
for a sensitivity sweep, which is a safety lever that must not ship in the privileged stage.
The package never imports these scripts.

**Why not `run_benchmark`.** It requires a `ModelSlot` from `SecurityEventSequenceV1` to
`ThreatPredictionV1`. Stage 5 consumes a `CBFResolutionV1` plus a host and emits
transaction receipts; wrapping it as a detector would invent an encoding. The scripts use
the harness's own instruments instead: `ResourceSampler`, `check_profile("edge")`,
`ExperimentRegistry`.

**Every corpus is synthetic and every host is `SimulatedHost`.** Nothing here is a
measurement of a Linux host.

| script | experiment id | what it measures |
|---|---|---|
| `gate_record.py --record` | PS-S5-20260925-BASE-safe-gate-0001 | the gate, registering the id `gate.py` cites |
| `arms.py` | PS-S5-20260926-BASE-arms-counter-corpora-0002 | every arm on C1-C4, cold and primed, CPU per case |
| `corpus_audit.py` | PS-S5-20260926-BASE-corpus-audit-0003 | playbook label leak, G5.9 infeasibility, rule 1 |
| `shadow_gate.py` | PS-S5-20260926-BASE-shadow-gate-0004 | Action Shadow constancy and ceiling sensitivity |
| `ablation_primed.py` | PS-S5-20260926-BASE-ablation-primed-0005 | leave-one-out of every planner flag, cold and primed |
| `stage4_seam.py` | PS-S5-20260926-BASE-stage4-seam-0006 | Stage 4's real exports through Stage 5 |
| `longlived_bounds.py 600` | PS-S5-20260926-BASE-longlived-bounds-0007 | one long-lived executor stack: bounds and liveness |
| `component_rss.py --repeats 3` | PS-S5-20260926-BASE-component-rss-0008 | the two §43 rows the gate leaves UNMEASURED |
| `hysteresis_isolated.py` | PS-S5-20260926-BASE-hysteresis-isolated-0009 | the hysteresis controller on three Phi traces |
| `b7_identifiability.py` | PS-S5-20260926-BASE-b7-identifiability-0010 | why B7 is not a single-world control |

The counter-corpora C2 and C4 are package code (`pocketsec/stage5/labs/counter_corpora.py`,
tested by `tests/test_stage5_counter_corpora.py`), because they are scenarios, not
measurement tools.
