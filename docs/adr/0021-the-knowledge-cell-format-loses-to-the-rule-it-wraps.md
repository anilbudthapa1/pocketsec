# ADR-0021 — The Knowledge Cell format loses to the rule it wraps

- **Status:** Accepted
- **Date:** 2026-09-25
- **Stage:** 3
- **Deciders:** Stage 3 integrator
- **Supersedes / superseded by:** none

## Context

Stage 3's first crystallisation target is Stage 1's Φ-oracle: a zero-parameter
rule that Stage 2 exports as a first-class `CandidateKind.DETERMINISTIC_SCORER`
(ADR-0118). Compiling something already free is the honest test of whether the
Knowledge Cell machinery adds anything over what it wraps.

Measured this session, one run, drift corpus `count=60`, fit seed 3, eval seed
11, base rate 0.2833, `/proc/loadavg` first figure 16.45:

| id | baseline | PR-AUC | µs/event | bytes |
|---|---|---|---|---|
| B3 | `PhiOracleUnchanged` | 1.0000 | 15.16 | 269 |
| S3 | Knowledge Cell path | 0.2833 | 26.10 | 7,848 |

Within-run ratios, the only transferable form: **2.16×** the time and **29.17×**
the bytes, at PR-AUC exactly equal to the base rate while B3 reaches 1.0000.

Corroborated independently: `shadow_execute` over 256 claimed frames recorded
**133** dual-oracle divergences for the same cell, and `promote_cell` refused it
`REFUSED_HARD_CONSTRAINT` — it is not security-equivalent to what it replaces.

A second measurement from the `bytecode` package: `CellVM.run` costs 2.9×–4.9×
`_execute()` across two runs, because `verify()` runs in full on every event, and
15.6×–18.9× a handwritten function computing the identical verdict.

## Decision

**Falsifier F1 fires.** The `KnowledgeCellV1` format is **rejected for
deterministic scorers.** Stage 3 does not crystallise this class of knowledge.
The verify-first contract is **not** weakened to recover the cost: it is what the
safety story rests on, and the honest report is that it is expensive. A later
wave wanting the cost back must argue it explicitly — verify once at promotion,
execute many times — not by deleting the call.

`RESIDUAL_MICRO_MODEL` is deliberately absent from `OperatorForm`. §13 lists it
as the fallback "only when symbolic/executable compression fails"; it would need
a weights blob and a numpy producer, and ADR-0020 forbids both. This is a
recorded decision, not an oversight.

## Options considered

| Option | Security cost | Resource cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|---|
| A: report the rejection | none | none | none | 2.16× time, 29.17× bytes, PR-AUC at base rate | **chosen** |
| B: keep the format, drop verify-first | **high** — no safety argument left | ~0.2–0.3× of the VM cost | lower | verification is 2.9–4.9× of execution, so this is where the cost is | the contract is the safety story |
| C: keep the format, report cost as UNMEASURED | none | none | none | the cost *was* measured; calling it unmeasured would be a lie | dishonest |

## Consequences

**Accepted costs.** Stage 3's headline mechanism does not earn its keep on this
class of knowledge. G3.9 FAILS and says why.

**Bounded state.** The measured 7,848 B per cell is far inside `MAX_FIELD_BYTES`
(20 MB); the rejection is on the *ratio*, not on an absolute ceiling.

**Reversibility.** Nothing is deleted. The cell format, the VM and the verifier
all remain and are exercised by the gate; what is rejected is the claim that they
beat the Φ-oracle.

**Authority.** No change.

## Verification

`pocketsec-stage3 gate` criterion G3.9 (FAIL, with the ratios in its detail);
`pocketsec-stage3 baselines`; `tests/test_stage3_runtime.py`.

## Prior art

No novelty claim. `docs/prior-art/ledger.json`, entry H4.

---

## Amendment — 2026-09-25, Stage 3 measurement wave

Added rather than rewritten: nothing above is deleted. Stage 3's reserved ADR
block is exhausted (`docs/stage-3-findings.md`, "ADR status"), so the two records
this session's measurements call for are made here and there instead of taking a
new number.

### What was re-measured

Three independent gate runs this session, drift corpus, `count=60`, fit seed 3,
eval seed 11, base rate 0.2833, synthetic data, registered as
`PS-S3-20260925-H4-crystal-gate-0001` and `-cell-path-constant-0002`:

| figure | in the decision above | measured this session |
|---|---|---|
| cell path µs/event vs B3 | 2.16× at `loadavg` 16.45 | 1.60× at `loadavg` 4.36; 1.59× at 6.06 |
| cell path CPU s/event vs B3 | not measured | 1.55× at `loadavg` 6.57, over 40,800 events |
| cell path bytes vs B3 | 29.17× | 29.17×, unchanged (deterministic) |
| `CellVM.run` vs `_execute` | 2.9×–4.9× | 4.06×, inside that band — **both withdrawn, see Correction 3** |
| `CellVM.run` vs "a handwritten Python function" | 15.6×–18.9× | **producer not found in the repository**; 235.05× against a handwritten `clamp01` returning a bare float — **also withdrawn, see Correction 3** |

The direction of every ratio holds. The cost half of the decision stands.

### Correction 1 — the claim is narrower than the title

The quality half does not stand as worded. `CellPathBaseline` returns the constant
**1.0** on all 60 evaluation sessions, benign and malicious alike, so its PR-AUC
equals the base rate *by construction* and measures no discriminative capacity;
`PhiOracleUnchanged` separates the classes with no overlap (benign 0.2000–0.2195,
malicious 0.3333–0.5224). The cause is structural and this ADR's own evidence base
already contains it: `pocketsec/stage3/bytecode/isa.py` defines no division
opcode, so `|ΔΦ| / (|ΔΦ| + 8)` is inexpressible and the closest admissible program
is `clamp01(ΔΦ)`, which saturates on every session here.

What is therefore measured is that **the one operator form with an interpreter
cannot express this target function, and costs 1.59–1.60× and 29.17× to return a
constant.** `CellVM` executes `BYTECODE` and abstains on the other seven forms
(ADR-0027), and `LOOKUP_TABLE` — the form baseline B1 shows would reach PR-AUC
1.0000 on this split at 925 B — has no executor. The title "the Knowledge Cell
format loses to the rule it wraps" claims more than that. The decision to stop
crystallising deterministic scorers with `BYTECODE` is unchanged; the scope of the
rejection should be read as `BYTECODE`, not the cell format, until a
`LOOKUP_TABLE` executor exists and that row is measured.

### Correction 2 — the boundary-key claim cited into this ADR is withdrawn

`pocketsec/stage3/labs/cell_path.py` stated, and this ADR's evidence base relied
on, that a boundary over all nine `DIMENSIONS` expands to 4096 index keys and is
refused at `MAX_KEYS_PER_CELL = 64`, and that a global rule therefore cannot be
crystallised as one cell. Measured directly:

| declared dimensions | index keys claimed | accepted by `BoundaryIndex` |
|---|---|---|
| 1 | 8 | yes |
| 2 | 8 | yes |
| 3 | 8 | yes |
| 4 | 8 | yes |
| 9 | 8 | yes |

`CellBoundary.keys` folds the declared dimensions into one union delta mask. This
is the same defect class already retracted for threat case T7, whose repair was
not propagated to `labs/cell_path.py`. The docstrings have been corrected in
place; the structural conclusion is **withdrawn as unsupported**. It may be true
for other reasons; it is not true for this one.

### Verification

`python -m pocketsec.stage3.cli gate` (exit 1, FAILED 5 of 13, three runs);
`python -m pocketsec.stage3.cli baselines`; `tests/test_stage3_*.py` 429 pass;
`results/PS-S3-20260925-H4-cell-path-constant-0002.json`.

### Correction 3 — the two bytecode ratios had no producer, and neither reproduced

Added by the Stage 3 defect-repair wave, 2026-09-25.

Two rows of the re-measurement table above were themselves unsourced, which is the
defect the table exists to correct:

- **"2.9×–4.9×" is not a band any file reports.** The row cited it as if
  `pocketsec/stage3/bytecode/verifier.py` published it. That file records two
  *points across a code change* — 10.18× while `run()` decoded twice and 2.93×
  after it stopped — and the string "4.9" appears nowhere in the repository. The
  citation is **withdrawn**, and so is "4.06×, inside that band": a number
  validated against a band nothing produced is validated against nothing.
- **235.05× and 4.06× had no producer either.** A reader could not reproduce them,
  which is what `docs/stage-3-findings.md`'s own Corrections table forbids.

The producer now exists: `pocketsec/stage3/bytecode/cost.py:measure_vm_cost`, run
by `python -m pocketsec.stage3.cli vmcost`, payload at
`results/PS-S3-20260925-H4-vm-cost-split-0005.json`. Five repeats of the identical
procedure in one process, 512 drift-corpus frames, best-of-7 each, `loadavg`
23.96/19.72/15.01 before and 23.26/19.71/15.05 after:

| figure | measured range over five repeats |
|---|---|
| `CellVM.run` / `CellVM._execute` | **2.77×–7.06×** |
| `CellVM.run` / handwritten `clamp01` | **388.51×–640.54×** |

**What this does and does not change.** Option B in the table above — "keep the
format, drop verify-first" — was rejected on the reasoning that verification is
where the cost is. That direction is confirmed: verification dominates execution on
every repeat, and it is rejected on the safety argument anyway, so the decision is
untouched. What changes is that the *magnitude* is a range from a named producer at
a stated load, not a point, and the phrase "verification is 2.9–4.9× of execution"
in Option B's row should be read as "verification dominates execution; the measured
multiple on a contended host ranged 2.77×–7.06×".

The control returns a bare float rather than a `CellResult` — no evidence, no
delta, no abstention — so the second row is a floor on what the answer costs, not a
like-for-like substitute for the VM. `cost.py` carries the control's source in its
own report so a reader does not have to take the label on trust.
