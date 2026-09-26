# ADR-0081 — Search has no production authority: one exit, an allow-list, and the declared Stage 5 residual (with a measured contradiction)

- **Status:** Accepted, with one clause BLOCKED pending the lead (Decision 5)
- **Date:** 2026-09-26
- **Stage:** 9
- **Deciders:** Stage 9 integrator (decided at spec time, `docs/stage-9-spec.md` §2.3; clause 5 found and measured in the integration session)
- **Supersedes / superseded by:** none

> Authority-boundary ADR. It fixes the only path by which anything Stage 9 finds can leave
> Stage 9, and records a contradiction inside spec §2.3 that the gate exposes.

## Context

Stage 9 searches for computations. Its output must never become production state without Stage
6's quarantine, validation and promotion boundary (the lead's first non-negotiable; ADR-0061 is
the Stage 7 precedent). Spec measurement M0.9 (not re-measured here) found that importing
`pocketsec.stage6.capsule.quarantine` loads Stage 5 modules at run time. So "no Stage 9 module
reaches Stage 5" cannot be proven by a whole-package closure, and spec §2.3 splits it into
three AST rules.

## Decision

1. **Direct:** no Stage 9 import names `pocketsec.stage5` (`boundary.direct_stage5_imports`).
2. **Closure:** a static import closure over `pocketsec/` (module- and function-level imports).
   For every Stage 9 module except `successor/stage6_exit.py`, `gate*.py` and `cli.py`, the
   closure holds no `pocketsec.stage5.*`. For those files every path to Stage 5 must pass through
   `pocketsec.stage6.capsule.*` (`boundary.transitive_stage5_reach`).
3. **One door:** `successor/stage6_exit.py` is the only file with an `.admit(` call. It never
   names a Stage 6 writer, and it records each `QuarantineVerdict` verbatim. The integrator
   added an AST rule, `gate_criteria.bucket_readers()`: no other Stage 9 file names
   `QuarantineBucket` or reads `.bucket`, so no outcome can be acted on anywhere else.
4. **Allow-list** (spec §2.3, `boundary.STAGE9_ALLOW`), plus two integrator deviations. The
   harness may import `stage1.epoch.model.SystemIdentity`, because an `Epoch` and
   `genesis_state` both need the identity they bind. It may also import `QuarantineGateway` to
   construct a lab gateway, but it may never call `.admit`.
5. **The measured contradiction (BLOCKED).** Spec §2.3's table grants the harness
   `ProvenanceLedger`, `KnowledgeLineageDAG` and `genesis_state` for building a lab gateway, and
   G9.6 requires `Stage6Exit.hand_over` on that gateway. All three Stage 6 modules reach Stage 5
   *without* passing through `stage6.capsule`:
   `gate_exit -> stage6.memory.semantic -> stage6.memory.procedural -> stage5.stage6_interface`.
   Rule 2 as written therefore fails on `gate.py`, `gate_labs.py`, `gate_exit.py` and `cli.py`.
   This session measured, with `boundary`'s own import graph, that the Stage 5 reach of the
   harness equals that of `stage6.capsule.quarantine`: `{pocketsec.stage5,
   pocketsec.stage5.stage6_interface}` plus five names inside the latter, 7 entries each, and
   the harness's set is a subset. Only the *route* differs, not *what* is reached.
   Spec §11 lists "the transitive residual grows beyond `stage6.capsule.*`" as a STOP condition,
   so the rule is **not** loosened. `tests/test_stage9_boundary.py::test_every_boundary_rule_holds_on_the_real_tree[transitive_stage5_reach]`
   fails and G9.7 fails, both naming the path. The lead chooses between:
   (a) restating rule 2 for the harness as "the harness's Stage 5 reach is a subset of
   `stage6.capsule.quarantine`'s", which the measurement above satisfies; or
   (b) Stage 6 exposing a lab-gateway factory under `stage6.capsule`, so the harness imports
   nothing else from Stage 6.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Whole-package closure: no Stage 9 module may reach Stage 5 | none | low | unsatisfiable: the one exit must import `stage6.capsule.quarantine` (spec M0.9) | cannot be met by any exit |
| B. Three rules with a declared residual (chosen) | residual limited to the exit and the harness | medium | on the real tree 10 of 11 predicates are `()`; rule 2 fails on 4 harness files via `stage6.memory.semantic` (this session) | chosen, clause 5 blocked |
| C. Loosen rule 2 so the gate passes | a checker edited to pass its own gate | low | would turn G9.7 green | forbidden: STOP condition, and "never loosen an assertion" |
| D. Drop the lab gateway from the gate | none | low | G9.6 would lose its exit hand-over, which the spec requires | trades a measured contradiction for an unmeasured criterion |
| E. Reach `genesis_state` through a dynamic import or a subprocess the AST cannot see | an unproven path | low | the rule would pass vacuously | evasion, not a boundary |

## Consequences

**Accepted costs.** G9.7 and one boundary test fail until the lead decides clause 5. They are
reported as failing, not hidden.

**Bounded state.** None changed.

**Reversibility.** Option (a) is a one-rule change in `successor/boundary.py`, with its test.
Option (b) is a Stage 6 change the Stage 6 owner makes.

**Authority.** No Stage 9 module writes trusted state. The runtime path (everything except the
exit and the harness) reaches no Stage 5 module. The exit and the harness reach exactly
`stage5.stage6_interface`, the module Stage 5 publishes for Stage 6.

## Verification

`tests/test_stage9_boundary.py`, gate check G9.7 (11 predicates plus the untouched-ledger
clause), `pocketsec-stage9 boundary`.

## Prior art

ADR-0061 (Stage 7's allow-list and single bridge).
