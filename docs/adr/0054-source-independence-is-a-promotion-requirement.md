# ADR-0054 — Source independence is a promotion requirement because Stage 2's gate promotes single-source repetition across epochs

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 6
- **Deciders:** Stage 6 integrator
- **Supersedes / superseded by:** none

## Context

`AdaptationSample` carries no source. Spec §0 measured that Stage 2's buffer + controller
promote one attacker lineage's escalation-free staging step once it spans two corroborated
epochs: 40 offers in epoch 0, 200 in epoch 1 -> **3 promotions**.

## Decision

Before `PromotionController.promote` is called, the gateway refuses a pattern observed from
fewer than `MIN_INDEPENDENT_GROUPS` (3) independence groups, with reason
`single_source_repetition`. Groups are counted per (Stage 2 `pattern_key`, meaning digest), so
one attacker cannot borrow groups earned by unrelated behaviour on the same relation.
Threat labels need `MIN_INDEPENDENT_LABEL_GROUPS` (2) asserting groups; teachers never count.

## Options considered

| Option | Measured consequence | Why not chosen |
|---|---|---|
| A. Stage 2 alone | 3 single-source promotions (§0) | the hole this ADR closes |
| B. Count per bare `pattern_key` | an attacker reuses legitimate groups on the same relation | weaker than C |
| **C. Independence per (pattern, meaning) track (chosen)** | P1 through `admit`: single-source refusals > 0, admissions 0 (G6.1(b)) | — |

## Consequences

Known limit, stated in the spec (§9.2): independence groups are hashed lineages. Fork-spray
(arm P1b: `MIN_INDEPENDENT_GROUPS + 1` short-lived children) attacks exactly this; its result
is in `docs/stage-6-findings.md`. A causal-root grouping is not built.

**Measured in the integration session — the check is defeated by repetition across
sessions.** The identity hashed into `source_group` is the actor's pid and start time, so an
attacker whose staging job runs once per session is a *new* independence group every
session. Arm P1 as the endurance package built it (one lineage per session, which is how a
real repeated job looks) offered 96 poisoned capsules at x16 through one gateway and minted
**6 CandidateAdmissions** from them with 11-16 "independent" groups; P1b (fork-spray) minted
the same 6 (G6.4 detail). The exact spec §0 probe (one lineage for all 240 offers) is refused
completely: 25 `single_source_repetition` refusals, 0 admissions, against 3 admissions with
the check off (G6.1(b)). The check therefore closes exactly the hole §0 measured and no wider
one: repetition of one *process* is refused, repetition of one *attacker* across process
lifetimes is not. Stage 6 still promoted 0 poisoned items on P1/P1b, but it also promoted 0
clean ones (accept-nothing equivalence, F10), so the later gates are not shown to be what held.

## Verification

`tests/test_stage6_gateway.py::test_single_source_repetition_across_corroborated_epochs_is_never_admitted`,
`::test_the_single_source_attack_is_real_without_the_independence_check`; gate G6.1(b), G6.4, G6.9.
