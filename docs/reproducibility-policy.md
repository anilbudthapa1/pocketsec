# D0.6 — Reproducibility and result-retention policy

**Status:** operational for Stage 0. Binding on Stages 1–12.

A PocketSec result is a claim about security quality *and* resource cost. A
claim that cannot be re-derived is not a result; it is an anecdote. This policy
is the minimum that makes re-derivation possible, and most of it is enforced in
code rather than by review.

## 1. What every result must carry

`BenchmarkResult` embeds all of the following. None is optional.

| Field | Source | Enforced by |
|---|---|---|
| Master seed + derived component seeds | `SeedSet` | required argument to `run_benchmark` |
| Python version, implementation, platform, kernel, machine, CPU count | `EnvironmentFingerprint.capture` | captured automatically |
| Git commit and dirty flag | `git_state()` | captured automatically |
| `PYTHONHASHSEED` | environment | captured automatically |
| Dataset name, version, **measured** SHA-256, item/event counts | `SequenceDataset` | checksum verified at load |
| Slot name and model **state** version | `ModelSlot` | required by the protocol |
| Synthetic-vs-real flag | caller | required argument to `run_benchmark` |
| Host facts (RAM, CPU, kernel) | `HostFacts.capture` | captured automatically |

## 2. Seeds

One master seed per experiment. Every component seed is derived from it by
SHA-256 (`SeedSet.derive`), so:

- a run replays from a single integer;
- two components never accidentally share a random stream;
- adding a new component never shifts existing seeds.

`PYTHONHASHSEED` cannot be set after interpreter start. `SeedSet.apply()` does
not pretend otherwise — the fingerprint records whether it was set, and
`EnvironmentFingerprint.caveats` says so explicitly when it was not.

## 3. Datasets

Every dataset load declares a name, a version and an expected SHA-256.
`SequenceDataset.load_jsonl` computes the digest and **refuses to proceed** on a
mismatch. Results over different bytes are not comparable, so the failure is
hard rather than a warning.

Splits must be leakage-resistant. The Stage 0 fixture achieves this by
construction: `unseen_technique` items use an attack chain that appears nowhere
in the training split.

## 4. When a result is *not* reproducible

`EnvironmentFingerprint.is_reproducible` is true only when the git commit is
recorded **and** the tree was clean. Otherwise the result is still recorded —
but `caveats` names the reason, and it must not be quoted as a reproducible
measurement. Deleting such a result is worse than labelling it.

## 5. Synthetic data

`run_benchmark` requires `synthetic_data` explicitly; it is never inferred. The
flag travels into the result record and into the registry entry. Fair-comparison
rule 7: synthetic performance is labelled synthetic and never presented as
real-world detection quality.

The Stage 0 smoke fixture is trivially separable by construction. Its perfect
scores demonstrate that the harness runs. They say **nothing** about detection
quality and must never be cited as if they did.

## 6. Unmeasurable figures

Where a platform cannot supply a metric (no `/proc`, no `smaps_rollup`), the
field is `null` and named in `ResourceMetrics.unavailable`.
`ProfileReport.within_target` returns `None` — not `True` — when nothing could
be measured. An unmeasured target is not a met target.

## 7. Result retention

- Experiment ids are immutable and never reused (`PS-S<stage>-<date>-<hyp>-<slug>-<seq>`).
- The registry at `experiments/registry.jsonl` is **append-only**. It exposes no
  update and no delete.
- Each entry is digest-chained to its predecessor, so editing history breaks the
  chain from that point forward. `verify_integrity()` detects it and the Stage 0
  gate runs that check.
- Refuted experiments, counterexamples, negative results and rollback
  information are retained. Stage 0 hard rule: do not delete prior research
  artifacts. A refuted experiment is the ledger working correctly.

## 8. Tuning discipline

Do not tune against the untouched final test set. Threshold and hyperparameter
selection happen on a development split; the operating point applied to held-out
data is the one the false-positive budget already selected on the development
distribution.
