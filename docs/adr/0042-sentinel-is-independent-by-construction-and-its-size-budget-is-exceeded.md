# ADR-0042 — SENTINEL is independent by construction; its trusted-surface size budget is exceeded; the assurance table reads 8 / 5 / 2

- **Status:** Accepted for the independence construction and the assurance counts.
  **Proposed** (awaiting the project lead) for the F5 size budget, which this ADR does not
  amend.
- **Date:** 2026-09-26
- **Stage:** 5
- **Deciders:** Stage 5 integrator (the sentinel package built the kernel)
- **Supersedes / superseded by:** none

## Context

The lead: SENTINEL must be able to deny every action regardless of planner output; it must
not share state or a code path with the planner, and it must not be constructible in a mode
where it is bypassed — tested against a flag, a `None`, a missing config and an exception.

Measured this session by `pocketsec-stage5 gate`, G5.3: **182 of 182** required denials
(14 catalog operators × 13 single-input mutations, planner maximally in favour at support 1.0
and uncertainty 0.0); 14/14 compliant baselines pass; the four independence groups (no
bypass name in `sentinel/`, `None` in each of the nine inputs ⇒ `MISSING_INPUT`, a weaker
`ResponseConstitution` is unconstructable, each of the 13 checks monkeypatched to raise ⇒
`KERNEL_FAULT`) all hold; `SentinelKernel.__init__`'s keyword-only parameter set is exactly
`{constitution, invariants, clock}`.

**Falsifier F5's size clause fires.** Spec §8: F5 fires when `sentinel/kernel.py` +
`sentinel/monitors.py` + `evidence/preservation_gate.py` exceed 900 lines combined. Measured
this session: **1323** physical lines by `wc -l` (517 + 374 + 432), and **948** lines that
carry code once blank lines, comment-only lines and docstrings are excluded (counted with
`tokenize` + `ast` over the three files; 366 + 259 + 323). Both readings exceed 900. F5's two
substantive clauses hold: no module under `sentinel/` imports `aegis/`, `safe/`, `twin/`,
`memory/` or `cells/`, and all 182 denials are achieved. Spec §12 says a fired F5 reports the
phase **BLOCKED**. It is reported that way.

## Decision

1. The independence construction stands as built and is not relaxed: three keyword-only
   constructor parameters; no escape-hatch name; any `None` input ⇒ `DENY/MISSING_INPUT`
   before any check runs; any raising check ⇒ `DENY/KERNEL_FAULT`; no import of the planner
   packages.
2. Four readings that differ from the obvious one, recorded because each changes what a
   reader can assume:
   - `_check_authority` requires the token's class to be **exactly** the catalog's class for
     the operator (less is escalation; more is a capability wider than the action).
   - `_check_constitution` denies on `REFUSED` but not on `HUMAN_REQUIRED`: SENTINEL cannot
     observe a human's approval, and `TokenStore.mint` already refuses a `POLICY` grant where
     a human is required. Denying on it would make the human path unreachable.
   - Duration invariants are applied to **every** operator class, not only the foundation's
     class thresholds.
   - **Integrator fix:** the EVIDENCE_RETENTION arm of `MissionInvariantSet.violations` now
     takes `preserved`, and SENTINEL passes the signals of the pre-action bundle it is itself
     handed — only when the evidence gate *accepted* that bundle. Before this, MI-04 denied
     every `SUSPEND_PROCESS` on a target carrying `process_memory_map` while the evidence
     gate refused every target that did not carry it, so no `DEGRADES_VOLATILE` operator was
     reachable under the default invariants (reported by three packages). Planning-side
     callers keep the fail-closed default (`preserved=frozenset()`).
3. **The F5 budget is not amended here.** Re-reading it as logical lines (948) still
   exceeds 900. Whether to raise the budget, or to cut the monitors or the §13 bundle out of
   the trusted surface, is a decision about the security argument itself and belongs to the
   project lead. Until then the phase status is BLOCKED on F5.
4. **The assurance table's counts are 8 PROVEN_BY_CONSTRUCTION, 5 TESTED, 2 UNMEASURED**
   (`assurance.properties.counts()`). P3 (no string reaches argument assembly) was targeted
   as proven and is recorded TESTED, because its stated mutation — add `str` to the
   `ArgvAtom` union — left its test passing; the runtime guard is the `isinstance` check
   before the match, and the construction's own detector would be `mypy --strict`.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Amend F5 to count logical lines only | none directly; weakens a falsifier after it fired | trivial | 948 > 900 — still fires | does not even pass, and amending a falsifier after it fires is the move this project forbids |
| B. Delete monitors / bundle code to reach 900 | removes specified, tested behaviour from the TCB | medium | not attempted | deleting behaviour to pass a size falsifier is not a legitimate fix |
| **C. Keep the construction, report F5 fired, leave the budget to the lead (chosen)** | none | none | phase reported BLOCKED | — |
| D. Keep MI-04 as a standalone veto | none claimed | none | every `DEGRADES_VOLATILE` operator unreachable under `DEFAULT_MISSION_INVARIANTS` (measured by the executor package: `REFUSED_SENTINEL` on `MISSION_INVARIANT`) | the invariant's own message is "lost *before it was preserved*"; SENTINEL already holds the bundle |

## Consequences

**Accepted costs.** The kernel's trusted surface is 5% (logical) to 47% (physical) over its
budget.

**Bounded state.** The kernel holds three slots and no history; monitor history is bounded
at `MAX_MONITOR_HISTORY = 64`.

**Reversibility.** The MI-04 reading is one parameter; removing it restores the old veto.

**Authority.** SENTINEL reads no confidence, support or planner verdict (ADR-0003).

## Verification

- `pocketsec-stage5 gate`, G5.3 and G5.13 details.
- `tests/test_stage5_sentinel.py` (the 182-case matrix, the four independence cases, the
  ratchet `test_the_sentinel_trusted_surface_stays_inside_its_ratchet`).
- `tests/test_stage5_gate.py::test_sentinel_counts_only_an_accepted_bundle_as_preservation`
  and `tests/test_stage5_outcome.py::test_default_invariants_refuse_a_suspension_that_would_lose_evidence`
  (rewritten to the three readings the fix defines).
- `tests/test_stage5_gate.py::test_every_mutation_edit_breaks_its_named_test` — for each of
  the 8 proven rows, the named test passes on an unmutated scratch copy and fails on the
  mutated one (8/8 this session). The gate runs the same mutations in-process
  (`gate_measured.mutation_results`), because P2 forbids a process launcher in the package:
  8/8 hold unmutated and fail mutated.

## Prior art

No novelty claim is made.

## Fix-wave addendum — 2026-09-26, Stage 5 fix wave

The title's "8 / 5 / 2" and Decision 4 are kept as the record of what the integrator
counted. **The table now reads 6 PROVEN_BY_CONSTRUCTION, 7 TESTED, 2 UNMEASURED**
(`assurance.properties.counts()`, printed by G5.13 in this wave's gate run):

- **P1 downgraded to TESTED** (finding F5-honesty). Its construction was named as
  `TransactionalExecutor.execute`, but the annotation is never type-checked by any gate, and
  its mutation edited `DefensiveOperator.__post_init__`, not the entry. A verifier deleted
  `_refuse_untyped` in a scratch copy and the named test stayed green, because it accepted
  `AttributeError`. The named test now demands a `TypeError`/`ContractError` raised by
  `_refuse_untyped` itself, with zero host calls, and `SENSITIVITY_EDITS['P1']` deletes the
  guard; the out-of-package run shows the test then fails.
- **P2 downgraded to TESTED** (finding S5-SEC-09). The scan was a lexical denylist that
  returned no row for `import os as o; o.system(...)`, `posix.system`,
  `__import__('subprocess')`, `getattr(os, 'system')` or `import asyncio`. The scan (now
  `operators/command_path.py`, re-exported from `algebra.py`) catches each of those, with a
  planted fixture per form in `tests/test_stage5_operators.py`. It still cannot decide where
  `importlib.import_module(name)` with a computed name leads, and four Stage 5 modules use
  that, so absence of a launcher is a tested property.
- **P6 re-grounded.** Its mutation used to add a fourth `__init__` keyword and its test
  counted the keywords. The mutation now inserts a module-level switch that makes `_run`
  return PASS before any check (the verifier's scenario), and the named test is the
  182-case denial matrix. SENTINEL also now reads its checks off its own class. It denies
  `KERNEL_FAULT` when `CHECK_ORDER` has been rebound, emptied or duplicated, and a PASS
  verdict can no longer be built over a rebound order (finding F4). G5.3 gained a
  shape-based switch rule (`gate_construction.sentinel_switches`: a module-level
  bool/None binding, a `global`, or a read of `globals()`, `environ` or `getenv` in the
  trusted surface). A flag spelled `ENFORCING` passed the name regex and fails this rule.

**The in-process G5.13 run is retracted as mutation evidence** (finding F2). Decision 4's
Verification bullet says "8/8 hold unmutated and fail mutated". Each of those probes read
the surface its own patch edited. A verifier deleted the executor entry guard and added a
disabling flag to SENTINEL, and the run still printed 8/8. G5.13 now lives in
`gate_assurance.py`. It probes each row's behaviour through the real code path: impostors at
a real executor, the 182-case matrix, O7 construction by every route, expiry under a
`ManualClock`, an evidence-destroying action at a real executor, and receipt construction.
The detail line names it a self-consistency check. The verifier's scenario, replayed
in-process by `tests/test_stage5_gate.py::test_g5_13_fails_when_the_entry_guard_is_deleted_and_sentinel_is_switched_off`,
now fails G5.13 with P1 and P6 named. The source-level evidence is the out-of-package
test. It passed for all 8 edits this wave (6 mutation, 2 sensitivity), each with an
unmutated control.

**The trusted-surface ratchet is now exceeded as well as the budget.** The inherited
security fixes (F1/F3/F4 of the earlier fix batch) had already taken the three files to
1358 physical lines against the ratchet's 1330, and this wave's F4 check adds 12, for
1370 in total. `test_the_sentinel_trusted_surface_stays_inside_its_ratchet` fails and has
not been loosened. Raising the ratchet, or cutting the surface, remains the lead's
decision, together with the budget.
