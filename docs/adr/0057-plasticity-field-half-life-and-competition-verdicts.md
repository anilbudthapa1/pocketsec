# ADR-0057 — Plasticity field, epistemic half-life and memory competition: INERT or DEGENERATE on the only corpus, none justified

- **Status:** Accepted (measurement)
- **Date:** 2026-09-26
- **Stage:** 6
- **Deciders:** Stage 6 integrator
- **Supersedes / superseded by:** none

> Measurement ADR. Every figure below is from `python -m pocketsec.stage6.cli gate` (G6.13)
> run in the integration session that wrote this file, loadavg 4.3-5.3 during the ablation.

## Context

Spec §7 names a simple control for each OPTIONAL mechanism, and Rule C requires a firing
count on the real run before any delta is read. `run_ablation` on the 12-month endurance
timeline (seed 11) produced:

| core id | mechanism | control | metric | full | ablated | delta | firing | verdict |
|---|---|---|---|---|---|---|---|---|
| HEL-F07 | epistemic half-life | LRU order | F1 retention | 0.0 | 0.0 | 0.0 | 0 | INERT |
| HEL-F08 | plasticity field | uniform mask | mean recall | 0.0 | 0.0 | 0.0 | 3 | DEGENERATE |
| HEL-F10 | memory competition | NEWEST_WINS | FP rate | 1.0 | 1.0 | 0.0 | 0 | INERT |
| HEL-F25 | melt/retire by half-life | LRU retire | F1 retention | 0.0 | 0.0 | 0.0 | 0 | INERT |

The endurance preconditions are DEGENERATE (E3: NeverUpdate's F1 retention collapses to
0.0 at M09, so NaiveFinetune cannot fall 0.10 below it at M12; E4 holds). A retention delta
on a DEGENERATE corpus is not evidence either way.

## Decision

1. HEL-F07, HEL-F10 and HEL-F25 are **INERT**: they never changed an outcome on the real run.
   The findings recommend removing them unless a corpus on which they fire is built.
2. HEL-F08 fired (3 field-only freezes) but its delta is read on a DEGENERATE corpus:
   **NOT YET JUSTIFIED**. The endurance package additionally measured that with the field on,
   the chamber returned `None` on 5 of 5 spawns: the field blocks learning more than it
   protects anything on this corpus.
3. None of the four is removed in this wave: removal is a code change the project lead
   decides, and the flags (`StageSixConfig`) already allow running without them.

## Options considered

| Option | Measured consequence | Why not chosen |
|---|---|---|
| A. Report them as working | deltas 0.0, firing 0 for three | would be a claim with nothing behind it |
| B. REJECT now | delta 0.0 on a DEGENERATE corpus | ADR-0125: a rejection needs a reproduced measurement with headroom |
| **C. INERT / NOT YET JUSTIFIED, removal recommended (chosen)** | — | — |

## Verification

Gate G6.13 detail lists each row; `tests/test_stage6_endurance.py::test_every_ablation_row_obeys_rule_c`.
