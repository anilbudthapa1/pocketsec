# ADR-0043 — Target identity is a `ProcessIdentity` tuple; `identity_digest` is the single key space; revalidation happens inside `_commit`, immediately before the host call

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 5
- **Deciders:** Stage 5 integrator (the executor package built it)
- **Supersedes / superseded by:** none

## Context

"A pid is not an identity." The lead expected the TOCTOU requirement to be implemented as a
comment, and asked for the race to be built. `labs/toctou.py` builds it: `RacingHost`
substitutes the target on the *second* `observe_identity` call — after PREPARE's check and
before COMMIT's — so the only thing that can refuse is the executor's own revalidation.

Measured this session by `pocketsec-stage5 gate`, G5.5:

- AST: in `TransactionalExecutor._commit`, the call `revalidate` is immediately followed by
  `self._host.apply`, with no call between them.
- **4 of 4** races refused (`EXITED`, `PID_REUSED`, `EXECUTABLE_CHANGED`, `UID_CHANGED`, each
  `REFUSED_IDENTITY`), **0** `host.apply` calls during them, the substitute untouched.
- §4.9 Rule A: on **20/20** committed corpus actions, the token, the SENTINEL verdict, the
  receipt, the lease and the journal entries all name the target by one string —
  `identity_digest(ProcessIdentity)`.

## Decision

1. Identity is `ProcessIdentity(pid, start_time_ticks, uid, executable_digest, cgroup_id,
   namespace_id)`, and `identity_digest` is the only key any Stage 5 component uses for a
   target.
2. `_commit` revalidates immediately before `host.apply`, stores the answer on an attribute
   rather than passing it through a helper (a helper is a call), and returns a constant
   no-effect on refusal. `_rollback` revalidates too: a rollback onto a recycled pid resumes
   a stranger.
3. `revalidate` reads an asymmetric absence of `executable_digest` (either side) and a
   differing non-`None` cgroup/namespace as `UNOBSERVABLE`, which refuses. Where both
   digests are `None` the strongest binding is not exercised — stated, not hidden.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. pid only | acts on a recycled pid | none | would fail PID_REUSED and EXECUTABLE_CHANGED | a pid is not an identity |
| B. Revalidate in PREPARE only | a window between the kernel's check and the act | low | the lab's race fires on the second observation precisely to catch this | leaves the TOCTOU window open |
| **C. Tuple identity, revalidated inside `_commit` (chosen)** | none known | low | 4/4 refused, 0 wrong-target applies | — |

## Consequences

**Accepted costs.** `executable_digest` is `None` for most corpus processes (no real
filesystem), so the executable binding is exercised on fixtures only (§9.2 item 8).

**Bounded state.** None added.

**Reversibility.** Not applicable; this is the refusal path.

**Authority.** None.

## Verification

- G5.5 in `pocketsec-stage5 gate`; `pocketsec-stage5 toctou`.
- `tests/test_stage5_executor.py::test_identity_is_revalidated_inside_commit`,
  `tests/test_stage5_gate.py::test_g5_5_fails_when_revalidation_always_matches`.

## Prior art

No novelty claim is made.
