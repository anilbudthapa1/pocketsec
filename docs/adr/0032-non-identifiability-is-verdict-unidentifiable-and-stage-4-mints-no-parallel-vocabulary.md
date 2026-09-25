# ADR-0032 — Non-identifiability is `Verdict.UNIDENTIFIABLE`, and the state-to-verdict table is the contract

- **Status:** Accepted
- **Date:** 2026-09-25
- **Stage:** 4
- **Deciders:** Stage 4 integrator
- **Supersedes / superseded by:** none

## Context

The failure mode Stage 4 exists to prevent is confident single-world storytelling, and the
output that prevents it is a refusal to name one world when the evidence cannot. That output
has to be a first-class result, not an error, and it has to be legible to a consumer that
knows nothing about Stage 4.

Stage 1 already ships the vocabulary. `Verdict` is
`BENIGN SUSPICIOUS MALICIOUS UNKNOWN UNIDENTIFIABLE INSUFFICIENT_EVIDENCE`, and
`NON_COMMITTAL_VERDICTS` is `{UNKNOWN, UNIDENTIFIABLE, INSUFFICIENT_EVIDENCE}` with
`ThreatPredictionV1._validate_abstention` enforcing that `abstained=True` is legal only with
one of those three. A parallel Stage 4 enum would have to be mapped at the seam, and the
mapping is where the refusal would quietly become a `SUSPICIOUS`.

`IdentifiabilityState` is a *separate* concept and is Stage 4's own:
`IDENTIFIED | UNIDENTIFIABLE | INSUFFICIENT_EVIDENCE | UNKNOWN`. It answers "can this evidence
name one world" over a belief field. `Verdict` answers "what do we tell the system". The two
are not the same question and the table between them is the contract.

**What was measured this session**, over `build_nonidentifiable_pairs(count=20, seed=17)` and
`build_resolvable_after_one_observation(count=20, seed=17)`:

| property | measured |
|---|---|
| constructed non-identifiable pairs returning `IdentifiabilityState.UNIDENTIFIABLE` | **20/20** |
| of those, `discriminating_observations == ()` | **20/20** |
| of those, `to_verdict()` is `Verdict.UNIDENTIFIABLE` with `abstains()` | **20/20** |
| of those, the leading world's consequence does **not** exceed the alternative's | **20/20** |
| resolvable cases returning `INSUFFICIENT_EVIDENCE` rather than `UNIDENTIFIABLE` | **20/20** |
| those reaching `IDENTIFIED` after exactly one granted observation | **20/20** |

G4.3 passes. It is the one substantive cognition criterion this stage meets.

## Decision

**Stage 4 defines no parallel verdict vocabulary. `IdentifiabilityVerdict.to_verdict()` is
the single mapping, and "have not looked" is never reported as "cannot be resolved".**

1. **`UNIDENTIFIABLE` is a success state.** A system that always names a culprit is not doing
   causal reasoning. It is reported with `abstained=True`, which the Stage 0 contract only
   permits alongside a non-committal verdict.
2. **`plan=None` yields `INSUFFICIENT_EVIDENCE`, never `UNIDENTIFIABLE`.** Not having looked
   is not the same as having looked and found nothing, and a planner that failed to run must
   not be able to certify an incident as unresolvable. This is the distinction G4.3 measures
   and it is the reason the criterion has two case families instead of one.
3. **An unlisted mechanism never maps to `BENIGN`.** `to_verdict()` branches on whether the
   leading world's mechanism is malicious, benign or ambiguous, which a world id alone cannot
   say — so `IdentifiabilityVerdict` carries `leading_mechanism_id: str | None = None` beyond
   the spec's eight fields, and with `None` the `IDENTIFIED` row maps to `SUSPICIOUS`, never
   to `BENIGN`. Pinned by `test_an_unlisted_mechanism_never_maps_to_benign`.
4. **The non-alarming choice is the default.** Among contenders inside the margin the leader
   is the *least alarming* one (`_least_alarming`). G4.3 asserts the consequence inequality on
   every constructed pair, because "returns UNIDENTIFIABLE" would otherwise be satisfiable by
   a system that had already decided the worst case and then abstained about it.
5. **`StopReason.NON_IDENTIFIABLE` is recordable.** The enum carried the value but nothing in
   the spec's API could set it; non-identifiability is decided over the whole field by
   `test_identifiability`, not by one world's e-value, so `SequentialEvidence.stopped(reason)`
   exists to record that decision. `update()` on a stopped accumulator raises rather than
   silently returning `self`.

## Options considered

| Option | Security cost | Resource cost | Complexity | Why not chosen |
|---|---|---|---|---|
| **A. Reuse `Verdict`, keep `IdentifiabilityState` as the internal question, one mapping** (chosen) | lowest: 20/20 on every clause, and `abstained=True` is contract-checked at the Stage 0 boundary | none | low | — |
| B. A Stage 4 `CBFVerdict` enum mapped at the seam | **high**: the mapping is where a refusal becomes a commitment, and a mapping is exactly the kind of code that gets "fixed" to produce a more useful answer | none | higher | The vocabulary already exists and Stage 1 ships it. Stage 3 took the same route for its own verdicts |
| C. Report `UNKNOWN` for both non-identifiability and not-having-looked | moderate: the two are operationally different — one says "gather this specific observation", the other says "no observation separates these" — and collapsing them loses the actionable half | none | lower | G4.3's whole content is that distinction. Collapsing it would make the criterion unfailable |
| D. Report the most alarming surviving world when the margin is too small | **highest**: this is the confident single-world storytelling the stage exists to prevent, wearing a safety justification | none | lower | Refused. The consequence inequality is asserted on all 20 constructed pairs |
| E. Let `plan=None` yield `UNIDENTIFIABLE` | **high**: a planner that crashed would certify the incident unresolvable, so a Stage 4 failure would produce a *stronger* claim | none | lower | Contradicts ADR-0034 directly: a failure may only widen uncertainty |

## Consequences

**Accepted costs.** Consumers see three non-committal verdicts where one would be simpler, and
have to know that `UNIDENTIFIABLE` means "no affordable observation separates the survivors"
while `INSUFFICIENT_EVIDENCE` means "one exists, here it is". That is the information a
responder needs and it is the reason the distinction is kept.

One narrower consequence, named because it is a place the rule bites: the identifiability
`UnknownClaim` is emitted **only** when the field holds more than one world. "No affordable
observation separates the survivors" is a statement about a choice between alternatives;
asserting it over a single-world field would be a manufactured unknown, which is as dishonest
as a manufactured certainty.

**Bounded state.** None added. `IdentifiabilityVerdict` is a frozen record with bounded
`material_alternatives` and `discriminating_observations`.

**Reversibility.** `to_verdict()` is one function and one table. A change to it needs this ADR
amended, because it is the contract.

**Authority.** No, and this ADR reduces the surface: the most committal thing Stage 4 can
produce under ambiguity is `SUSPICIOUS`, and under any subsystem failure it is non-committal
by ADR-0034.

## Verification

- `python -m pocketsec.stage4.cli gate` — G4.3 reports all six ratios above, and names what
  input would make it come out differently.
- `tests/test_stage4_resolution.py` — the state-to-verdict table row by row, including
  `test_an_unlisted_mechanism_never_maps_to_benign`.
- `pocketsec/stage4/labs/nonidentifiable.py` — the constructed pairs are built to be genuinely
  non-identifiable by design: two worlds explaining identical observations with no
  discriminating observable reachable.
- `tests/test_stage4_foundation.py::test_the_corpus_expectation_vocabulary_matches_the_identifiability_enum`
  pins the corpus's `EXPECTED_STATES` to the enum, so the two cannot drift.

## Prior art

No novelty claim is made. Identifiability is a standard concept in causal inference and in
system identification; Stage 4 asserts nothing about priority. Ledger bindings are H3 and H7,
both `NOT_REVIEWED`.


## Amendment — 2026-09-26, review-fix wave (S4-REV-03, S4-REV-05, S4-FC-06)

Three cases in which `test_identifiability` reported more than the evidence held are closed.

1. **A plan that was not wired to look.** The planner refuses "no observation policy", "sensor cost
   unmeasured" and "cost total not positive" only *after* an action has cleared the discrimination
   threshold, so those refused actions are exactly the ones that would separate the worlds. A plan
   whose only reasons are these (`active_plan.NOT_ATTEMPTED_REASONS`) now yields
   `INSUFFICIENT_EVIDENCE`, never `UNIDENTIFIABLE`. Every engine the labs and the flood build now
   carries Stage 1's AOP.
2. **The UNKNOWN family.** The lifecycle names the first novel world `unresolved_novel_mechanism`
   and every later one `unresolved_novel_mechanism.<sha12>`; only the first was recognised. A field
   of any of them is now `UNKNOWN`, and a leading UNKNOWN-family world is `UNKNOWN`, never
   `SUSPICIOUS` — no new vocabulary is minted; the table gains a polarity that maps to the existing
   `Verdict.UNKNOWN`.
3. **A lone world.** With no runner-up the margin was the constant 1.0, so a world at log-odds -32
   was `IDENTIFIED` and `MALICIOUS`. The margin is now the world's own support against its
   complement (`2*share - 1`, share from the geometry), and a lone world below the margin is
   `INSUFFICIENT_EVIDENCE`.
