# ADR-0026 — Guided Boundary Pressure is removed on the measured comparison

- **Status:** Accepted
- **Date:** 2026-09-25
- **Stage:** 3
- **Deciders:** Stage 3 integrator
- **Supersedes / superseded by:** none

## Context

The architecture gate's own wording for this criterion is "Boundary Pressure
finds counterexamples missed by naive random replay, **or it is removed**". D3.4
built a guided walk that climbs the divergence gradient one axis at a time, and
`random_replay_control` as the mandated control.

Measured this session, same budget **cap** (256 probes — the spends differ, see the
correction below), same seed family (11), same run, same frame lattice.
`perturbed_frame` is pure, so both strategies address exactly the same set of
reachable frames and any difference is a difference in search:

| strategy | probes spent | counterexample classes |
|---|---|---|
| guided | 49 | 12 |
| random replay | 256 | 12 |

- classes found by guided and missed by random replay: **none**
- classes found by random replay and missed by guided: **none**

### Correction, 2026-09-25 — the "strict superset" is withdrawn

The table above previously read 14 classes for random replay and named two
classes it found that guided missed:
`EVIDENCE_ABLATION:NEVER_DOWNGRADE_CONSEQUENCE` and
`EVIDENCE_ABLATION:TEACHER_UNAVAILABLE`. **Those two classes did not exist.**

`random_replay_control` drew a subset of axes per probe and then credited a
counterexample class to **every axis it drew** — including axes where
`perturbed_frame` returned `None` and no perturbation was applied. Every one of
the eight corpus seeds carries exactly one `EvidenceRef`, and
`perturbed_frame(..., EVIDENCE_ABLATION, step)` cannot move such a frame at all,
so 0 of 64 EVIDENCE_ABLATION perturbations were ever applied and both classes
were minted for frames whose evidence tuple was never altered. Guided, which
correctly skips an unmovable axis, could not mint them.

With attribution corrected — only the axes a probe actually moved are credited —
the two strategies find **the same 12 classes** and neither set is a superset of
the other. Re-measured through the gate after the fix (`python -m
pocketsec.stage3.cli gate`, G3.4 detail, loadavg 9.14/10.26/8.60): guided spent
49 probes finding 12 classes; random replay spent 256 probes finding 12; both
difference sets empty.

The **decision below is unchanged** — guided found nothing random replay missed,
which is what G3.4 turns on — but the recorded reason for it was false and is
withdrawn. Two further wording corrections go with it:

- "same budget (256 probes)" is a shared **cap**, not a shared spend. Guided
  spends 49 because it exhausts `AXIS_ORDER x MAX_STEPS_PER_AXIS`, not its
  budget (`budget_exhausted=false`); random replay spends all 256, 5.2x the
  oracle evaluations. The comparison is equal-cap, and `pressure.py`, `cli.py`
  and G3.4's detail now say so.
- Most of both runs' divergences are frozen-snapshot **key misses**, not oracle
  disagreements: 42 of guided's 49 probes and 222 of random's 256 came back
  `TEACHER_UNAVAILABLE`. Those are now reported as `unmeasured_probes` and
  excluded from the §37 boundary-quality counts.

## Decision

**Falsifier F3 fires.** Guided Boundary Pressure is **removed** as the default
search. `random_replay_control` is the retained strategy;
`apply_boundary_pressure(strategy=GUIDED)` and `compare_strategies` stay in the
tree because they are the evidence for this decision and because deleting a
measurement's apparatus is how a result becomes unreproducible. `CrystalConfig.strategy`
selects the search and defaults to `RANDOM_REPLAY`; `AssuranceState.pressure` may
be filled from either strategy. (This paragraph previously asserted that "nothing
in the promotion path depends on guided search". That was false when written — see
the second correction below.)

## Options considered

| Option | Security cost | Resource cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|---|
| A: remove guided as the default, keep it as evidence | none | 256 random probes | lower | guided finds no class random replay misses (12 vs 12) | **chosen** |
| B: keep guided as the default | none | fewer probes (49) | higher | finds the same 12 classes, and flatters `predictive_stability` (see below) | the criterion says "or it is removed" |
| C: raise guided's budget until it wins | none | higher | higher | untested; and an equal-cap comparison is the criterion | tuning until a mechanism wins is not a measurement |

### Correction, 2026-09-25 — "nothing in the promotion path depends on guided search" was false

`crystal/pipeline.py` hard-coded `strategy=PressureStrategy.GUIDED` in the only
pressure call in the crystallisation loop, and `CrystalConfig` had no way to
select anything else. So this ADR recorded a removal that no code implemented —
the Stage 2 lesson inverted — and the dependency was not cosmetic: the guided
report feeds `_resolution_from_run`, whose `predictive_stability` and
`counterfactual_consistency` are exactly what `crystallization_allowed` reads
before `PROMOTED`.

The direction of the error flattered the cell. `_walk_axes` breaks out of an axis
on its first divergence, so later divergences on that axis are excluded while the
non-diverging steps before it stay in the denominator. Measured inside the real
pipeline, same region, same seed, same budget:

Measured this session on the gate's own Φ-oracle cell and corpus (eval seed 11,
eight in-region seeds, one process, loadavg 17.25/12.33/9.52 before and
17.47/12.46/9.58 after), `predictive_stability = 1 - divergences/probes_run`:

| seed / budget cap | guided | random replay |
|---|---|---|
| 11 / 256 | 0.0204 (49 probes, 48 divergent, 42 unmeasured) | 0.0039 (256 probes, 255 divergent, 222 unmeasured) |
| 13 / 64 | 0.0204 (49 probes, 48 divergent, 42 unmeasured) | 0.0000 (64 probes, 64 divergent, 57 unmeasured) |
| 14 / 64 | 0.0204 (49 probes, 48 divergent, 42 unmeasured) | 0.0000 (64 probes, 64 divergent, 57 unmeasured) |

Guided reads higher on every row. The gap is small here only because this cell
diverges on almost every probe either way; the point is the sign, which is
consistent, and that most of both columns is snapshot key misses rather than
disagreement.

`CrystalConfig.strategy` now exists and **defaults to
`PressureStrategy.RANDOM_REPLAY`**, which is what this ADR decided. Nothing
promotes under either strategy on the shipped corpus, so no promotion decision
flips today; the point is that the default is now the retained strategy rather
than the removed one.

## Consequences

**Accepted costs.** The guided walk's smaller probe count (49 vs 256) is given
up. That was its only measured advantage and the criterion does not ask about it.

**Bounded state.** `budget <= 4096` probes either way; unchanged.

**Reversibility.** The guided implementation is retained and exercised by
`pocketsec-stage3 pressure`, so a later wave can re-measure it against a
different cell or corpus without rewriting it.

**Authority.** No change.

## Verification

Gate criterion G3.4 (FAIL, with both class sets, both spends and both
`unmeasured_probes` counts in its detail); `pocketsec-stage3 pressure`;
`tests/test_stage3_knowledge_boundary.py`, including
`test_random_replay_is_not_credited_for_an_axis_it_could_not_move` and
`test_crystal_config_defaults_to_the_retained_strategy`.

## Prior art

No novelty claim. `docs/prior-art/ledger.json`, entry H4.
