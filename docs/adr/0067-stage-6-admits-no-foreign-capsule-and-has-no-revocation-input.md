# ADR-0067 — Blockers B7-1 and B7-2: Stage 6 admits no foreign capsule and has no revocation input; Stage 7 measures at its own boundary

- **Status:** Proposed (measurement). The remedy is the lead's decision: it needs a Stage 6 change,
  which Stage 7 may not make.
- **Date:** 2026-09-26
- **Stage:** 7
- **Deciders:** Stage 7 measurement session (numbers); project lead (remedy)
- **Supersedes / superseded by:** none

> Measurement ADR. Every figure below was produced in the 2026-09-26 measurement session and
> is quoted with its command in `docs/stage-7-findings.md` §M. The fleet is simulated
> in-process and every corpus is synthetic. None of this is a detection result.

## Context

The lead's rule for Stage 7 is that foreign knowledge reaches local trusted state only through
Stage 6's quarantine → validation → promotion boundary. Stage 7 must not build a second
promotion gate and must not edit Stage 6.

Stage 6 scores provenance as `prior × visibility × (1 − max flag risk)`. For a foreign capsule
that is `SOURCE_CLASS_PRIOR[FOREIGN_HOST] (0.2) × ≤1 × (1 − FLAG_RISK[FOREIGN_ORIGIN] (0.6))`,
which is at most 0.08. That is below `MIN_PROVENANCE_SCORE = 0.5`
(`pocketsec/stage6/provenance/trust.py`). The spec predicted this before any code existed
(M0.2: 0 of 40 foreign capsules reached TRUSTED_CANDIDATE).

**Measured this session:**

| what | value | command |
|---|---|---|
| Bridged `ExperienceCapsuleV1` handed to `QuarantineGateway.admit` over the gate's 60 suite runs | 2254 built = 2254 admitted = 2254 offered | `PYTHONHASHSEED=0 python -m pocketsec.stage7.cli --json gate` (G7.1) |
| Stage 6 bucket for those 2254 | UNCERTAIN 2254, TRUSTED_CANDIDATE **0** | same (G7.1(b), G7.8) |
| Poison antibodies ECHO bridged into Stage 6, by arm (4 default receivers, corpus seed 7) | COLLUSION_TIMING share 0.2: 4 decisions → 16 capsules; share 0.3: 4 → 28. SYBIL_ADAPTIVE S=4..128: 4 decisions each → 12–27 capsules. Every one UNCERTAIN, 0 TRUSTED_CANDIDATE | `benchmarks/stage7/fraction_sweep.py --corpus-seed 7 --seed 0` |
| Stage 6-side rollback of a revoked capsule | UNMEASURED: Stage 6 exposes no revocation input. Stage 7 computes the targeted Stage 6 capsule set (6 of 6 in G7.9) and cannot act on it | gate G7.9 |

## Decision

1. Stage 7 measures its defences at **its own output boundary**: the antibodies ECHO marks
   ELIGIBLE and the bridge hands to `admit`. Stage 6's buckets are reported beside that figure
   and never substituted for it.
2. Every Stage 7 detection gain is labelled `counterfactual_at_boundary`. It describes what a
   receiver *would* detect if the antibodies Stage 7 delivered were installed. On-host realised
   collective detection is **0 by construction** under Stage 6's current constants.
3. "How much adversarial knowledge reaches promotion" is **identically 0 at every adversary
   share**, so it is VACUOUS as a robustness metric. The findings report it as a fact about
   Stage 6, not as evidence that Stage 7's defences work.
4. Stage 7 does not change Stage 6 constants and does not add a revocation input to Stage 6.

## Options considered

| Option | Security cost | Resource cost | Complexity | Why not chosen |
|---|---|---|---|---|
| A. Measure at Stage 7's boundary and report Stage 6's buckets beside it (chosen) | none | none | none | — |
| B. Stage 7 raises its capsules' provenance so Stage 6 admits them | defeats the only door: foreign data would be setting its own trust | none | low | This is a second promotion gate built by the sender. The lead forbids it |
| C. Edit Stage 6's `SOURCE_CLASS_PRIOR[FOREIGN_HOST]` or `FLAG_RISK[FOREIGN_ORIGIN]` | opens the value path. Stage 7 has **no** measured case where opening it is safe (see ADR-0068: the shipped ECHO bridges poison on two arms) | none | low | Not Stage 7's decision, and another wave owns Stage 6 |
| D. Report "0 poison promoted" as a robustness win | none | none | none | It holds for 0 honest items too. A criterion that cannot fail is not a criterion (Stage 2 lesson 10) |

## Consequences

**Accepted costs.** Stage 7 delivers no realised detection value on any host until Stage 6
changes. Every "gain" in the findings is counterfactual.

**What opening the door would let through, measured.** On the synthetic arms the shipped ECHO
bridged poison into Stage 6 on COLLUSION_TIMING (share 0.2–0.3) and SYBIL_ADAPTIVE (≥ 4
identities). Stage 6's `UNCERTAIN` bucket is what stopped it. Revising the foreign prior would
turn Stage 7's poison acceptance on those arms into a Stage 6 candidate stream. Stage 6's
downstream canary and probation would then be the only remaining defence.

**Bounded state.** No change.

**Reversibility.** Nothing to reverse. If the lead revises the Stage 6 prior, the realised
figures become measurable and this ADR is superseded.

**Authority.** None. No Stage 7 path gains authority, and none reaches Stage 5 (G7.2: 0
offenders, 372 of 372 injections refused).

## Verification

- `pocketsec-stage7 gate`: G7.8 fails VACUOUS and names B7-1. G7.1(b) reports the bucket
  histogram.
- `benchmarks/stage7/fraction_sweep.py` prints `stage6_poison` per run.

## Prior art

None claimed.
