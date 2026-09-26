# benchmarks/stage6/ — the Stage 6 measurement scripts

Every figure in `docs/stage-6-findings.md` Part M (the measurement wave) was produced by
one of these scripts, run from the repository root as

```
PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage6/<script>.py [...] [--record EXPERIMENT_ID]
```

Without `--record` a script only prints. With it, the script writes
`results/<EXPERIMENT_ID>.json` (git-ignored) and appends one digest-chained row to
`experiments/registry.jsonl` through `ExperimentRegistry.register`. The registry refuses a
reused id. **Run recording scripts one at a time**: `register()` reads the chain tail and
then appends, so two concurrent writers can fork the chain, and a concurrent write also
makes `tests/test_stage6_gate.py::test_the_gate_never_writes_the_experiment_registry` fail
for a reason that is not the gate's (observed once in the measurement session).

**Why outside `pocketsec/stage6/`.** Several scripts run the learner under a *diagnostic*
configuration the package must never ship (`_common.genesis_threshold` patches the genesis
THRESHOLD for every learner at once; the package constant is never edited), and the
rollback script uses `gate_rig`, which only `gate*.py`/`cli.py` may import inside the
package. The package never imports these scripts.

**Why not `run_benchmark`.** It needs a `ModelSlot` from `SecurityEventSequenceV1` to
`ThreatPredictionV1`; a Stage 6 learner scores Stage 1 encoded steps of a compiled session,
and re-encoding raw events inside `predict` would run a second Stage 1 pipeline whose
lineage state carries across sessions (MEMORY.md corpus trap). The scripts use the
harness's own instruments instead: `ResourceSampler`, `check_profile("edge")`,
`average_precision`/`recall_at_max_fpr`, `ExperimentRegistry`.

**Every corpus is synthetic** (`synthetic_data=True` on every row).

| script | experiment id | what it measures |
|---|---|---|
| `learnability.py --spm 16 64 --threshold default 0.6` | PS-S6-20260926-H6-learnability-0002 | every §7 learner + Stage 6 + Stage 6 with all OPTIONAL mechanisms off, 4 configurations |
| `refusal_census.py --spm 16 64 --threshold default 0.6` | PS-S6-20260926-H6-refusal-census-0003 | every chamber-issued candidate: items carried, fate, failing check with its measured value |
| `slow_drip.py --epochs 2 4 8` | PS-S6-20260926-H6-slow-drip-0004 | data / 1-group label / 2-group label drips over many corroborated epochs |
| `slow_drip.py --epochs 2 4 8 --threshold 0.6` | PS-S6-20260926-H6-slow-drip-diag-0005 | the same at the diagnostic threshold |
| `poison_diag.py` | PS-S6-20260926-H6-poison-suite-0006 | the eleven spec arms x 4 learners x (1,4,16), recorded |
| `poison_diag.py --threshold 0.6` | PS-S6-20260926-H6-poison-suite-diag-0007 | the same at the diagnostic threshold |
| `flood.py --capsules 20000` | PS-S6-20260926-H6-flood-bounds-0008 | every store under a 20 000-capsule unseen-signature flood; post-flood probe |
| `rollback_stress.py --promotions 45 --regressions 30` | PS-S6-20260926-H6-rollback-stress-0009 | byte-identical restore, canary/probation action, rollback depth |
| `resources_compare.py --spm 16 --repeats 3` | PS-S6-20260926-H6-resources-compare-0010 | CPU and RSS per learner, fresh process each |
| `horizon.py --cycles 15` | PS-S6-20260926-H6-horizon-0011 | per-store growth over 180 synthetic months |
| `candidate_quality.py --spm 16 64 --threshold default 0.6` | PS-S6-20260926-H6-candidate-quality-0012 | held-out FP/recall of every candidate the gates refused |
| `horizon.py --cycles 24` | PS-S6-20260926-H6-horizon-long-0013 | per-store growth over 288 synthetic months (do the caps bind?) |
| `candidate_quality.py --spm 16 --threshold default 0.6` (v2: adds AP, recall@FPR and baselines' operating points) | PS-S6-20260926-H6-candidate-quality-v2-0014 | is a baseline's FP 0.0 precision, or alerting on nothing? |

The gate and its ablation rows are registered by the stage's own CLI,
`pocketsec-stage6 experiments --register` (PS-S6-20260926-H6-helios-gate-0001 and
PS-S6-20260926-H8-ablation-0001..0010).
