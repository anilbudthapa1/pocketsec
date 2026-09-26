# ADR-0087 — Stage 8's hand-designed baseline is not consumable: G9.1 is blocked, and the rebound comparison set is {Φ-oracle, H1, H2, TCN evidence}

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 9
- **Deciders:** Stage 9 integrator (decided at spec time, `docs/stage-9-spec.md` M0.11, §6.1, §11 B9-1; revisited in the integration session, when Stage 8 began landing)
- **Supersedes / superseded by:** none

> Gate-criterion ADR. It records why G9.1 cannot pass here and what it measures instead.

## Context

G9.1 reads verbatim: "At least one Stage-9-discovered computation must beat the strongest
Stage-8 hand-designed baseline on a meaningful Pareto dimension without violating another hard
requirement." At spec time Stage 8 did not exist (M0.11: 0 `.py` files, no spec).

During the Stage 9 integration session another wave was building Stage 8 in the same tree.
This session read what had landed, without importing it:

- `docs/stage-8-spec.md` §3.3 names the Stage 9 interface: `pocketsec/stage8/forge/package.py`,
  schema `pocketsec.discovery_package.v1` @ 1.0.0, with `DiscoveryPackageV1`, its enums and
  records, and `verify_package(package) -> tuple[str, ...]`. The file exists and defines those
  names (`DiscoveryPackageV1` at `package.py:579`, `verify_package` at `:765`).
- A `DiscoveryPackageV1` carries a discovered *mechanism* (a typed rule, motif, FSM, threshold,
  logistic, prototype or stump tree) measured on **Stage 8's own discovery corpus**. It is not
  a hand-designed baseline, and it is not on the ambiguous corpus Stage 9 searches.
- Stage 8's hand-designed baselines (`labs/baselines.py`: `phi_oracle_baseline`,
  `direct_model_baseline`, …) are Stage 8 lab functions outside the named interface, and run on
  Stage 8's corpus.
- Spec §2.4: "No Stage 9 module imports `pocketsec.stage8` in this wave." The Stage 9 allow-list
  refuses every Stage 8 name.

## Decision

1. **G9.1 fails with `BLOCKED_ON_STAGE8`.** It is not re-worded into a pass. The check still
   measures and prints everything the criterion would need, so the verdict can be re-read once
   Stage 8 exposes a consumable baseline:
   - pre-conditions (a) Φ-oracle exact in the IR, (b) count-240 held-out not degenerate, (c)
     shuffled-label null not LEAK_SUSPECTED, (d) zero train/held-out overlap;
   - for every search winner, `beats(winner_heldout, strongest_hand_heldout,
     candidate_ok=...)`, where the strongest hand baseline is the argmax held-out worst-case AP
     over {Φ-oracle, H1, H2};
   - the Pareto placement of the Φ-oracle, H1, H2 and every winner on held-out count 240, and the
     TCN from registered Stage 2 frontier evidence on count 60 only (the saturated split, where
     any claimed win is a measurement error).
2. **The rebound set is {Φ-oracle, H1, H2, TCN evidence}.** H1 (per-lineage Σ max(ΔΦ, 0)) and
   H2 (per-lineage popcount of the OR'd state-delta mask) were written into the spec before any
   search ran (M0.6). They are author-confounded: H2 nearly restates the ambiguous generator's
   label rule.
3. The spec's §8 falsifier 1 ("the hand rules match the frontier") is evaluated against the
   rebound set and printed in G9.1's detail.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Pass G9.1 on the rebound set | a criterion re-worded into a pass | low | would hide B9-1 | forbidden (spec §6.1) |
| B. Import Stage 8's `labs/baselines.py` | Stage 9 depending on another wave's unfrozen lab code, on another corpus | medium | not measured: spec §2.4 forbids the import | outside the named interface and the allow-list |
| C. Consume `DiscoveryPackageV1` | none | medium | a discovered mechanism is not a hand-designed baseline, and it is measured on a different corpus | not what G9.1 names |
| D. Fail G9.1 as BLOCKED and carry the rebound comparison (chosen) | none | low | the rebound rows print on every gate run (docs/stage-9-findings.md) | chosen |

## Consequences

**Accepted costs.** G9.1 fails on every run until Stage 8 exposes a hand-designed baseline in a
form Stage 9 can express or consume, and the lead grants the import.

**Bounded state.** None.

**Reversibility.** When Stage 8 freezes an interface for its baselines, a new allow-list row and
this ADR's successor can wire G9.1 to it.

**Authority.** None.

## Verification

Gate check G9.1; `tests/test_stage9_gate.py::test_g9_1_is_blocked_on_stage8_whatever_the_search_found`.

## Prior art

None claimed.
