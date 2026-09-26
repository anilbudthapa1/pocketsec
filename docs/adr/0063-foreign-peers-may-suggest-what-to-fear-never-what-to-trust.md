# ADR-0063 — Foreign peers may suggest what to fear, never what to trust: no foreign normality; contests only reduce mass; foreign revocation only as self-retraction

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 7
- **Deciders:** project lead (the rule); Stage 7 integrator (its binding to code, `docs/stage-7-spec.md` §4.0, D7.1, D7.7, D7.10, D7.16, §10; written after the measurement and review-fix sessions)
- **Supersedes / superseded by:** none

> Authority-boundary ADR. It fixes which *direction* foreign knowledge may push a host. It is
> the tenth law of the Collective Constitution (`CollectiveLaw.NO_FOREIGN_NORMALITY`).

## Context

A foreign claim can push a receiver in two directions. "This pattern is malicious" adds a
candidate detector. The receiver can test it against its own benign history, and if it is
wrong the cost is a false positive that local validation catches (ECHO step 2, `LOCAL_FP`).
"This pattern is normal", "this host is clean" or "stop detecting this" removes protection.
The receiver cannot test that claim locally. The attack it hides has, by definition, not been
seen here. A poisoned baseline is the classic way to blind an anomaly detector.

Revocation has the same asymmetry. A retraction removes knowledge. If any peer could retract
anything, one peer could withdraw every antibody the fleet shares, or reach into the host's own
local knowledge.

The architecture (§3) lists eight laws for foreign knowledge. The lead added two: local
sovereignty, and this one.

## Decision

1. **No foreign normality.** No `KnowledgeType` asserts normality, a baseline or a benign
   verdict (ADR-0062 lists the five). No wire key may carry a verdict, label or baseline, and
   `WIRE_STRING_SHAPES` admits no string such as `BENIGN`. The Stage 6 → 7 export
   (`capsule.compiler.invariants_from_learning_record`) takes DETECTOR rows only, and only
   `ACTIVE`, `simulated: false` rows. Baseline and normality rows are never exported.
2. **Contests only reduce mass.** `Stance.CONTEST` exists on `ANTIBODY` only. In ECHO a contest
   enters one inequality, `support_mass ≥ contest_ratio × contest_mass`. It can keep a key from
   becoming `ELIGIBLE` and cannot make anything eligible or trusted. Contest clusters use
   falsification weight 1.0. The one counter-statement a peer can make is "that fires on my
   benign traffic", never "that is safe".
3. **Foreign revocation only as self-retraction.** `RevocationPlane.submit` accepts a foreign
   `REVOCATION` iff its ground is `SELF_RETRACTION`, the target is a known foreign capsule, and
   the key owner, the target's contributor, the sender and the claimed contributor are all the
   same pseudonym. Otherwise it refuses with a named reason:
   - `foreign_claims_local_ground`: a foreign capsule claiming `LOCAL_EVIDENCE`;
   - `local_sovereignty`: a target that is a `LOCAL_CAPSULE` node or in `local_keys()`;
   - `unknown_target`: nothing changes;
   - `not_contributor`: a third party. It may still CONTEST, which only reduces mass.
   Only `revoke_locally`, on this host's own evidence, may revoke any known node.
4. **At the ingress** (stage `SUSPICION`), an ANTIBODY `CONTEST` or a `REVOCATION` that touches
   a key or capsule in `local_keys()` is refused `local_sovereignty` before it reaches ECHO or
   the revocation plane. A `REVOCATION` is routed to the bounded revocation inbox, never to the
   pool.
5. **An accepted revocation marks and never deletes.** The target and its descendants become
   `SUSPECT`, and `reinstate` restores the DAG digest exactly.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Accept foreign baselines or "benign" verdicts, weighted by trust | one colluding or poisoned peer can blind a detector on every receiver; the receiver cannot test the claim | medium | not built | the claim is untestable locally; trust weighting is itself a slow-poisoning target (spec D7.8) |
| B. Contests as full negative votes that can mark a key benign | a contesting Sybil cluster could whitelist a pattern | low | not built | turns a counter-statement into foreign normality |
| **C. Contests reduce support mass only (chosen)** | a contest can suppress a true antibody (below) | none | contest mass is INERT on acceptance: firing 0 in the gate, and switching it off changed neither true nor poison acceptance in 7 of 7 `echo_refusals.py` cases (findings §M.5.1, §M.5.2) | — |
| D. Any peer may revoke any foreign capsule | one peer withdraws the fleet's knowledge | low | not built | revocation is untrusted input until verified (architecture §24) |
| **E. Foreign revocation only as self-retraction (chosen)** | the retractor can suppress keys it touched (residual below) | medium | G7.9: a real signed `SELF_RETRACTION` marked exactly the target and its descendants, changed 0 non-descendants, reinstated byte-identically; FALSE_REVOCATION arm 80 judged, 0 accepted (findings §M.1; descendant count 8 after §R.1's fix, 15 before) | — |

## Consequences

**Accepted costs.**
- **Suppression through contests.** Contests are the one foreign channel that can lower
  detection. Under BYZANTINE_SUPPRESS at share 0.4, ECHO's recall at FPR 0.01 was 0.571 against
  VALIDATION_FILTER's 0.786 (corpus 7, 4 receivers, findings §M.3). No aggregator reached the
  poison break level on that arm, because it carries no poison.
- **Suppression through self-retraction (known residual, pinned by a test).** ECHO's suspect
  mark is keyed on the antibody key, not on the contribution. A contributor that supported an
  ELIGIBLE key and then retracts its own capsule moves the whole key to `SUSPECT`, including
  other clusters' support (`lineage/cross_host.py` docstring; findings Appendix A §A.4).
- **Benign knowledge is local only.** A receiver's benign history is its own `BenignRing`. In
  the labs that ring comes from lab ground truth, which is optimistic. A poisoned local benign
  ring is UNMEASURED (spec §9.2).
- **The only foreign negative channel is currently INERT.** If contest mass is removed, as
  ADR-0069 recommends, peers keep no way to warn of a false positive. The direction rule still
  holds, because removing contests cannot create trust. Local validation remains the defence
  against false positives.

**Measured, whole-fleet** (G7.1(c), 64 independent-root peers against each of 4 receivers,
findings §M.1 and §M.6): revocations of a local-origin antibody refused `local_sovereignty`
1024/1024; SUPPORT for a rule that fires on local benign traffic ended `CHALLENGED` at 4/4
receivers and was never bridged; contests of a locally confirmed antibody refused at ingress
1024/1024. The fleet is simulated and the adversaries share an author with the defences, so
these are construction properties, not claims about a real fleet.

**Bounded state.** The ingress revocation inbox holds at most `MAX_REVOCATION_INBOX = 256`
entries (chosen parameter). The rule itself adds no store.

**Reversibility.** Removing contests (ADR-0069's recommendation) keeps this ADR intact. Adding
any type or stance that asserts normality reverses it and needs a new ADR that supersedes this
one.

**Authority.** This ADR removes authority from foreign peers. No collective outcome, however
unanimous, can lower a local defence or revoke local knowledge.

## What would reopen this decision

- A way for the receiver to verify a foreign normality claim locally, for example attested
  telemetry from a host whose identity is bound (ADR-0064 records that none exists).
- Measured evidence that suppression via contests or self-retraction costs more detection than
  the false positives contests prevent. Today contests change no acceptance on the measured arms.
- A per-contribution suspect mark that removes the self-retraction residual. That would amend
  point 3, not reverse it.

## Verification

- `tests/test_stage7_foundation.py::test_no_knowledge_type_can_assert_normality` (the law's bound
  test in `COLLECTIVE_CONSTITUTION`).
- `tests/test_stage7_sovereignty.py::test_a_unanimous_fleet_cannot_change_a_local_decision`,
  `::test_revocation_marks_exactly_the_descendants`.
- `tests/test_stage7_echo.py::test_contests_reduce_but_never_create`;
  `tests/test_stage7_ingress.py::test_local_key_contest_refused`,
  `::test_revocation_never_enters_pool`.
- Gate G7.1(c) and G7.9. `verify_collective_constitution()` resolves `NO_FOREIGN_NORMALITY` →
  `capsule.knowledge_capsule:KnowledgeType`.
- This session: the Stage 7 suite ran 397 tests, 0 failures (see ADR-0061, Verification).

## Prior art

None claimed. Baseline poisoning of anomaly detectors is a known attack class; this ADR claims no
novelty for refusing it.
