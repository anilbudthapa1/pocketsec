# ADR-0084 — Corpus choice: ambiguous count 240 for search and held-out; count 60 is saturated and used only to show the trap; the author confound is declared

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 9
- **Deciders:** Stage 9 integrator (decided at spec time from spec M0.2 and M0.6; re-measured by the gate in the integration session)
- **Supersedes / superseded by:** none

> Measurement-contract ADR. It fixes which split may answer a Stage 9 question.

## Context

Synthetic corpora saturate (ADR-0010; lesson 11). The spec author measured the zero-parameter
Φ-oracle on Stage 1's ambiguous corpus (eval seed 11) at AP 1.0000 at count 60, 0.8495 at count
120 and 0.5975 at count 240 (M0.2, not re-measured here except where stated). They also found
that two one-register per-lineage rules beat it at count 240 (M0.6). Those two rules became the
hand baselines H1 and H2 *before* any search ran.

The gate re-measured, in this session (`pocketsec-stage9 gate`, reference step, 2026-09-26):

| split | Φ-oracle AP | `stage9_saturation` |
|---|---|---|
| ambiguous count 60, seed 11 | 1.0000 | **degenerate**: `PHI_ORACLE_AT_CEILING` |
| ambiguous count 240, seed 11 (held-out, clean) | 0.5975 | not degenerate |

Held-out worst-case AP over clean + 6 attacks on count 240: Φ-oracle 0.5975, H1 0.6256, H2
0.5980. The registered Stage 2 frontier (count 60) has the TCN at AP 1.0000, tying the Φ-oracle
(`degenerate=True`, `ORDER_FREE_BASELINE_TIES_BEST`).

## Decision

1. **All search, selection and held-out evaluation run on ambiguous count 240**: train seed 3,
   held-out seed 11, each clean plus the six `SCENARIO_ATTACKS`. It is the only split in the
   repository with measured headroom.
2. **Count 60 is compiled for two purposes only:** the expressibility precondition (the Φ-oracle
   must be *exact* there), and the saturated Pareto plot that places the TCN evidence next to the
   Φ-oracle. On that split a claim to beat the Φ-oracle is a measurement error by definition (spec
   §8.6), and `stage9_saturation` refuses it.
3. **The corpus audit runs before any fitness figure** (identities reused across sessions = 0, both
   per-class median peak |ΔΦ| > 0), and so does the contamination check (0 train/held-out overlap,
   by sample id and by content). Either failure refuses the whole gate context. Both held on the
   gate run.
4. **Author confound, declared.** The ambiguous generator labels a session malicious when *one
   lineage performs the whole chain*. H2 (per-lineage popcount of the OR'd state-delta mask) nearly
   restates that rule, and H1 is its ΔΦ analogue. ARGUS's attacks and this contract were written by
   the same project. A search success at count 240 partly measures how well the language restates
   the generator. Properties proven by construction (termination, bounds, the import boundary,
   rollback identity) do not share this confound.

## Options considered

| Option | Security cost | Complexity | Measured consequence (this session) | Why not chosen |
|---|---|---|---|---|
| A. Search on count 60 | a ceiling split cannot rank anything | low | Φ-oracle AP 1.0000; `stage9_saturation` degenerate | a win there is a measurement error |
| B. Search on count 120 | less headroom | low | not re-measured here (spec M0.2: 0.8495) | 240 has more headroom |
| C. Ambiguous count 240, seeds 3/11 (chosen) | author-confounded | medium | Φ-oracle 0.5975 held-out, not degenerate; audit and contamination clean | chosen |
| D. Build a new corpus for Stage 9 | a second author-confounded generator | high | none | adds a confound without removing one |

## Consequences

**Accepted costs.** One synthetic corpus, one host, one generator. Every figure carries (corpus,
count, seed). Nothing here is a detection result.

**Bounded state.** Compiling 2 × 7 variants of 240 sessions holds about 1.3 GB in the gate process
on this 16 GB host (resident size read with `ps` during the run). That is offline research cost,
not endpoint cost.

**Reversibility.** A new corpus needs this ADR superseded.

**Authority.** None.

## Verification

Gate G9.1 preconditions (b) and (d); `tests/test_stage9_evaluation.py`; `pocketsec-stage9 gate`
evidence `references`.

## Prior art

ADR-0010, ADR-0120 (corpus degeneracy guard).
