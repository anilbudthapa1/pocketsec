# ADR-0066 — Secure aggregation is an off-by-default pairwise-masking prototype that aborts on dropout and claims no guarantee beyond hiding inputs from an honest-but-curious aggregator

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 7
- **Deciders:** Stage 7 integrator (decided at spec time, `docs/stage-7-spec.md` D7.17, §7, §10; written after the measurement and review-fix sessions)
- **Supersedes / superseded by:** none

> Claim-scoping ADR for an optional component (ORPH-F18). ADR-0069 carries its ablation verdict
> (HARMFUL, keep off); this ADR records what the component is and what it does not claim.

## Context

Architecture §28 lists optional secure aggregation, so that the per-round population counts
feeding collective novelty (D7.14) need not be visible per host to whoever sums them. The
standard construction (Bonawitz et al.) has three layers: pairwise masks that cancel in the sum,
key agreement to set up the pair keys, and Shamir secret sharing so a dropped participant's
masks can be recovered.

The standard library has no Diffie–Hellman or X25519 (ADR-0001), and hand-rolling key agreement
is out of scope. Shamir-based recovery is a second protocol with its own failure modes.

There is also a structural conflict. Stage 7's Sybil defence works by inspecting each
contributor: clustering identities, clamping per cluster, dropping what a dependence graph
merges. Masking exists to prevent exactly that per-client inspection.

## Decision

1. `aggregation/secure.py` implements **the masking layer only**. Each pair of participants
   derives the same per-round vector from a shared key (HMAC-SHA256 in counter mode). The lower
   id adds it and the higher id subtracts it, modulo `MODULUS = 2**32`. An aggregator that
   receives every masked vector learns the total and nothing else about any one vector, under
   the assumption that the pair keys are secret.
2. **Pair keys are simulated and pre-provisioned** by the caller. Whoever provisions them can
   unmask everyone. Real key agreement is UNMEASURED.
3. **Any deviation aborts the round with no total**: a missing participant (dropout), an
   unexpected or duplicate participant, a vector from the wrong round, or vectors of unequal
   length. A partial sum would be
   uniformly random garbage presented as a count (§43, "abort round; no partial unsafe update").
   Dropout recovery is not built.
4. **Off by default.** `SECURE_AGGREGATION_ENABLED = False`, and no runtime path in Stage 7
   calls the module. Only the labs (S7X-19, S7X-20, S7X-47 and the ORPH-F18 ablation) and the
   tests exercise it.
5. **The only claim:** the aggregator sees only the sum, from an honest-but-curious aggregator,
   under the simulated key assumption. Not claimed: authentication of participants,
   malicious-aggregator detection, dropout tolerance, any differential-privacy property, or
   robustness to Byzantine or Sybil inputs.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. No secure aggregation; plaintext sum with a per-cluster clamp | the aggregator sees each host's counts | none | inflation 1.0 (total / true) under SYBIL_FORGED_ROOTS, the control below | kept as the default: this is what runs when the module is off |
| **B. Masking layer only, off by default (chosen)** | hides inputs, and also hides Sybil inflation | low (235 lines) | inflation 9.0 under the same arm; ablation delta **+8.000**, verdict HARMFUL (findings §M.5.1) | — |
| C. Full Bonawitz (key agreement plus Shamir recovery) | would still block per-client inspection | high; hand-rolled DH is out of scope | not built | ADR-0001; a hand-rolled key agreement is its own vulnerability |
| D. Masking plus a clamp inside the protocol | a participant can submit any value; the sum hides who lied | high | not built | clamping a masked value needs range proofs, which do not exist here |

## Consequences

**Measured.** The ORPH-F18 ablation (`labs/privacy_attacks.py:secure_sum_ablation`) uses the
round-0 senders of a SYBIL_FORGED_ROOTS fleet (16 Sybils per root). Two honest hosts saw a
pattern and every Sybil claims it. The masked sum gives a novelty-count inflation (total ÷ true
count) of **9.0**. The plaintext sum with a per-cluster clamp over a real `DependenceGraph`
gives **1.0**. Re-run this session on corpus seed 7, fleet seed 0:
`secure_sum_ablation(build_fleet_corpus(seed=7), seed=0)` →
`('novelty-count inflation (total / true) under SYBIL_FORGED_ROOTS', 9.0, 1.0, 1, True)`,
loadavg 2.70. That is the gate's +8.000 delta, verdict **HARMFUL** (findings §M.5.1; ADR-0069:
keep off). The firing count is 1: one round summed.

**Accepted costs.**
- **Privacy against the aggregator costs robustness against Sybils.** Under masking the receiver
  cannot clamp, cluster or drop one Sybil's inflated counts. That is why the module is off.
- **No malicious-aggregator detection.** An aggregator that alters the total is caught only if a
  participant cross-checks it out of band. S7X-47 records it as undetected (declared).
- **No authentication.** A masked vector names its participant, and nothing proves the name.
- **Any dropout loses the round.** In a real fleet with churn, rounds would abort often. The
  abort rate on a real network is UNMEASURED.
- **The flag is declarative.** `SECURE_AGGREGATION_ENABLED` is read by no runtime code; only
  `tests/test_stage7_sovereignty.py` asserts it is `False`. "Off" is enforced by the absence of
  any runtime caller, not by a check of the flag. A future caller must consult the flag and
  write an ADR that supersedes this one.
- The component is also INERT for its intended purpose today: no runtime code releases
  population counts at all (ADR-0065; findings §R.5).

**Bounded state.** At most `MAX_PARTICIPANTS = 256` participants and `MAX_VECTOR_LEN = 1024`
coordinates per round; pair keys of at least `MIN_PAIR_KEY_BYTES = 16` bytes. All chosen
parameters. The module keeps no state between rounds.

**Reversibility.** It is off and has no runtime caller, so deleting it or leaving it is a
one-module change. ADR-0069 recommends keeping it off.

**Authority.** None. It sums integers.

## What would reopen this decision

- A key-agreement primitive admitted under an amendment to ADR-0001, which would make real pair
  keys (and then dropout recovery) buildable.
- A robust secure-aggregation construction that allows per-cluster clamping or verified input
  ranges under masking, measured against the +8.000 inflation above.
- A runtime population-count release (ADR-0065), without which the module protects nothing.
- A real fleet in which aggregator curiosity, not Sybil inflation, is the dominant threat.

## Verification

- `tests/test_stage7_sovereignty.py::test_secure_sum_is_exact_and_aborts_on_dropout` asserts
  `SECURE_AGGREGATION_ENABLED is False`, an exact sum, a fresh mask every round, and aborts with
  no total for a missing participant (`missing_participant`), an unexpected or duplicate one and
  a wrong round (`wrong_round`).
- `labs/seventy_two_experiments.py:run_secure_aggregation` (S7X-19 exact, S7X-20 dropout, S7X-47
  tampered total).
- The ORPH-F18 ablation row in G7.11 (`labs/byzantine_suite.py`, control "plaintext sum +
  per-root clamp").
- This session: `grep -rn "aggregation.secure\|aggregate_masked\|mask_vector" pocketsec` finds
  callers only in `labs/` (plus the `core_ids` symbol-table string); the Stage 7 suite ran 397
  tests, 0 failures (see ADR-0061, Verification).

## Prior art

Bonawitz et al., "Practical Secure Aggregation for Privacy-Preserving Machine Learning" (CCS
2017). Only the masking layer is reproduced. No novelty is claimed.
