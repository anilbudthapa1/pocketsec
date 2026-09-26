# ADR-0044 — Leases expire as a pure function of the lease against an injected clock; an explicit `LeaseSweeper` performs the rollback

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 5
- **Deciders:** Stage 5 integrator (the executor package built it)
- **Supersedes / superseded by:** none

## Context

"A lease that does not actually expire, or whose expiry is only checked when something else
happens to call in, is a permanent change with an optimistic docstring. Test expiry under a
clock that does not advance on its own."

Measured this session by `pocketsec-stage5 gate`, G5.6, on the 10 hostile cases of
`build_response_corpus(count=20, seed=11)`: **10** autonomous ≥O2 containments committed;
**10/10** leased with a named rollback operator, `ttl_seconds <= max_duration_seconds`, the
receipt's target digest and at least one probed postcondition; under a `ManualClock` advanced
past every hard deadline, `LeaseSweeper.sweep()` expired and rolled back **10/10** and left
`active(now)` empty; the host's capability signature was restored to the pre-action snapshot
**10/10**. All against `SimulatedHost`.

## Decision

1. `Lease.expired(now)` reads only the lease's frozen fields and its argument. Renewal
   re-bases `granted_at` and shortens `maximum_lifetime_seconds` by the same amount, so the
   hard deadline is invariant across renewals.
2. Only `LeaseSweeper` rolls an expired lease back, and nothing else in Stage 5 calls
   `LeaseRegistry.tick`. There is no implicit sweep.
3. The lease is granted at the end of PREPARE, after SENTINEL passes and before COMMIT; a
   lease denial ends the transaction `ESCALATED`.
4. Restoration operators (`RESTORATION_OPERATOR_IDS`, now derived once in
   `operators/catalog.py` and imported by the lease registry, the probe, the host model and
   the baselines) are not leased: an undo has no undo.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Check expiry when the next action arrives | a quiet host keeps a containment forever | low | the P7 mutation (expiry waits for a registry flag) makes the pure-expiry probe fail | this is the failure the lead named |
| B. Background timer thread | non-deterministic; untestable under a clock that does not move | medium | not built | cannot be tested the way the lead required |
| **C. Pure expiry + explicit sweeper (chosen)** | a caller must run the sweeper | low | 10/10 expired and rolled back under `ManualClock` | — |

## Consequences

**Accepted costs.** Only one leased containment per target can exist at a time
(`NO_ACTIVE_LEASE_ON_TARGET` plus the kernel's lease *count*), so a multi-step recovery
cannot be produced wholly through the executor; the outcome package's incrementality test
applies the second containment directly and says so.

**Bounded state.** `MAX_CONCURRENT_LEASES = 4`; max active leases observed in the gate run: 1.

**Reversibility.** The sweep *is* the reversal path.

**Authority.** A rollback the authority plane will not authorise autonomously is recorded
`rolled_back=None` and surfaced, never forced.

## Verification

- G5.6 in `pocketsec-stage5 gate`.
- `tests/test_stage5_executor.py::test_a_lease_is_expired_by_data_not_by_a_call`,
  `tests/test_stage5_gate.py::test_g5_6_fails_when_the_sweeper_does_nothing`, and the P7
  mutation (in-process and out-of-package).

## Prior art

No novelty claim is made.

## Measurement addendum — 2026-09-26, Stage 5 measurement wave

Appended, not rewritten. Measured on ONE long-lived executor stack (one kernel, journal,
token store, lease registry, governor, memory) serving 600 hostile `SUSPEND_PROCESS` actions,
each on its own simulated host, `ManualClock` (`benchmarks/stage5/longlived_bounds.py 600`,
PS-S5-20260926-BASE-longlived-bounds-0007). The gate never measures this: `build_rig` builds
a fresh stack per case.

1. **Nothing schedules the sweeper.** The only callers of `LeaseSweeper.sweep` are
   `gate_runtime.py` and `labs/baselines.py`. With no sweep, 2 of 2 committed containments
   were still in force on their hosts after the clock passed every hard deadline, while the
   lease data read "expired" (`leases_expired_by_data` 2, `active` 0). Expiry is data;
   undoing the change needs a caller that does not exist outside the gate and the labs.
2. **The journal is bounded and then permanently refuses.** With a sweep after every action,
   82 actions commit and the next 518 of 600 are `REFUSED_JOURNAL_FULL`: journal entries
   are never compacted (`RollbackJournal.release` drops rollback state only), so it sits at
   258224 B / 492 entries against 262144 B / 512 forever. Fail-safe — no unbounded growth,
   no eviction of live rollback state — but a deployed stack stops responding after about
   82 contain-and-rollback cycles. Without sweeps SENTINEL refuses 241 actions on
   `PRECONDITION` + `FORBIDDEN_COMBINATION`, and the journal fills at action 250.
3. **Bounds held**: spent nonces capped at 256 with evictions counted (426 by action 600),
   traced Python heap 422692 B over start at action 300 and 425320 B at action 600.

Neither (1) nor (2) is fixed here; both change privileged code and are for the lead.
