# ADR-0062 — Knowledge types are those with a consumer (DRIFT_NOTICE and MODEL_DELTA refused); FedAvg reduces to MEAN on stance vectors; FedProx and personalised FL do not apply to a parameter-free learner; §14's graded match is reduced to boolean `match_motif`

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 7
- **Deciders:** Stage 7 integrator (decided at spec time, `docs/stage-7-spec.md` §4.2 D7.2, D7.9, D7.11, §10; written after the measurement and review-fix sessions)
- **Supersedes / superseded by:** none

> Contract ADR. It fixes the wire vocabulary of `KnowledgeCapsuleV1` and says which
> architecture constructs Stage 7 does not build, and why. Stage 2 lesson 3 applies
> throughout: a representation with no consumer is not built.

## Context

Architecture §5 lists seven knowledge types. Two of them have nothing in this repository that
could consume them:

- **`DRIFT_NOTICE`** carries context only. Epoch context already rides on every capsule
  (`epoch_context.software_epoch`, `epoch_context.visibility`), so a separate drift notice
  would repeat it.
- **`MODEL_DELTA`** needs something to apply a delta to. Stage 6's learner is parameter-free
  (ADR-0050: the neural continual-learning families are "UNMEASURED — not applicable to a
  parameter-free learner"). A delta type with no applier is only an attack surface: it is the
  carrier for architecture experiments S7X-48 (model replacement) and S7X-49 (backdoor adapter).

The same fact shapes the federated-learning baselines. FedAvg averages model parameters.
Stage 7 exchanges no parameters; what it can average is the per-identity stance on each
antibody key (+1 SUPPORT, −1 CONTEST, 0 silent). FedProx and personalised FL modify how a
parameter vector is fitted, so they have no object here.

Architecture §14 defines a graded match score, a product of structural similarity, causal
consistency, context compatibility, local evidence support and a visibility adjustment. The
only consumer of an antibody is a Stage 6 DETECTOR motif, and Stage 6's `match_motif` is
boolean: a motif is 1–2 `MotifStep` bitmask tests, and a 2-step motif requires step *i* then
*j* (*i* < *j*) within one actor (`stage6/memory/semantic.py`). A graded score would have no
graded consumer. Stage 6 ADR-0056 set the same rule for candidate kinds ("exactly those with
an executor").

## Decision

1. **`KnowledgeType` has exactly five members, each with a named consumer:**

   | type | consumer (runtime) |
   |---|---|
   | `ANTIBODY` | ECHO (`EchoEngine.offer`) → `Stage6Bridge.hand_over` → Stage 6 quarantine |
   | `NOVELTY` | `CollectiveNoveltyEngine.observe` (advisory) |
   | `CAMPAIGN_FRAGMENT` | `CampaignHypergraph.add_fragment` / reconstructor (advisory) |
   | `NEGATIVE_EVIDENCE` | consensus falsifier, as a `NegativeClaim` (§19) |
   | `REVOCATION` | `RevocationPlane.submit`, via the ingress's revocation inbox |

   `DRIFT_NOTICE` and `MODEL_DELTA` are **refused as unknown types** at parse time. S7X-48 and
   S7X-49 are catalogued `REFUSED_BY_CONSTRUCTION` with the note "no MODEL_DELTA knowledge type".
   No member asserts normality (ADR-0063).
2. **`Aggregator.MEAN` is FedAvg's aggregation rule applied to stance vectors.** It is the FedAvg
   baseline for every Stage 7 comparison. **FedProx and personalised FL are not applicable** and
   are recorded as UNMEASURED ("no model parameters exist"), never as passed or beaten.
3. **The antibody match is boolean.** `antibody.forge.matches` delegates to Stage 6's
   `match_motif` and never reimplements it. §14's terms are bound as follows:
   `structural_similarity × causal_consistency` is `match_motif`; `context_compatibility` is
   ECHO's relevance floor; `local_evidence_support` is `LocalValidation`;
   `visibility_adjustment` is `NOT_OBSERVABLE`. The graded product is not built. Architecture
   §37's per-cluster `local_validation_c` is applied once, as a gate (ECHO step 2), which for
   0/1 outcomes is the same as a per-cluster factor.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. All seven architecture types | `MODEL_DELTA` opens model replacement and backdoor adapters (S7X-48/49) with nothing to apply them to | +2 types, +2 consumers to invent | not built | lesson 3: no consumer; one type is pure attack surface |
| **B. Five types, each with a consumer (chosen)** | S7X-48/49 refused by construction | — | parse refuses `DRIFT_NOTICE`, `MODEL_DELTA` and every spelling of normality (`test_no_knowledge_type_can_assert_normality`) | — |
| C. Build a FedProx or personalised-FL baseline | none | high | not built | no parameter vector exists to regularise or personalise |
| **D. MEAN on stances as FedAvg (chosen)** | none | none | without local validation MEAN recall@FPR 0.01 is 0.000 with no adversary (corpus 7, 4 receivers: 14/14 positives but 11/60 benign fire), same as MAJORITY, MEDIAN and TRIMMED_MEAN (findings §M.2) | — |
| E. §14's graded match score | none directly | medium | not built | its only consumer, a Stage 6 DETECTOR, is boolean; a graded score would be a second, diverging definition of an antibody |
| **F. Boolean `match_motif` (chosen)** | none | none | the corpora are saturated in favour of transfer: the oracle motif transfers at recall 1.0 and FP 0 on both corpus seeds, so precondition P5 reads `DEGENERATE_IN_FAVOUR` (findings §M.0) | — |

## Consequences

**Accepted costs.**
- **The antibody grammar is Stage 6's, exactly.** It cannot express counts, timing or chains
  longer than `MAX_MOTIF_LENGTH = 2` steps. Any attack whose discriminating signal is one of
  those is inexpressible as Stage 7 knowledge. This was stated before any code existed
  (spec §3.2) and is not measured here.
- **"Has a consumer" is not "is exercised".** `NOVELTY` has a runtime consumer, but honest fleet
  traffic carries no NOVELTY capsule and no runtime code calls `observe_population`, so
  collective novelty fires 0 times on the fabric path and its ablation is INERT (findings §R.5).
- **The FedAvg baseline is weak by construction.** It averages identities, so it is bought by
  whoever mints identities, and it has no local validation. Every identity aggregator scores
  0.000 on the gate set with no adversary, because honest antibodies fire on the receiver's own
  benign traffic (non-IID), not because of poison (findings §M.2, §M.11 item 3). The informative
  baselines are ROOT_QUORUM+LV and VALIDATION_FILTER (ADR-0068).
- FedProx and personalised FL remain in the UNMEASURED ledger (findings, Honesty ledger).
- A later stage that introduces a parameterised learner must add a type, a consumer and an ADR
  together. It cannot reuse `MODEL_DELTA` by name, because unknown types are refused.

**Bounded state.** Unchanged. The refusal happens during `KnowledgeCapsuleV1.from_bytes`, after
the `MAX_KNOWLEDGE_CAPSULE_BYTES = 4096` size check and before any consumer sees the capsule.

**Reversibility.** Adding a type is a schema change: a new `KnowledgeType` member, a new
`EXPORT_FIELD_TABLE` review (ADR-0065) and, because the schema version is
`pocketsec.knowledge_capsule.v1` @ `1.0.0`, a version bump. Removing a type narrows what peers
may send and needs no migration.

**Authority.** This ADR removes a path. With no `MODEL_DELTA`, no foreign object can change a
model on this host. No authority moves.

## What would reopen this decision

- A Stage 6 (or later) learner with parameters. `MODEL_DELTA`, FedProx and personalised FL
  would then have an object, and each would need a consumer and its own measurement.
- A consumer for drift context that per-capsule `epoch_context` cannot serve.
- Stage 6 adopting a graded motif score. §14's product would then have a graded consumer.
- Evidence, on a non-synthetic corpus, that attacks Stage 7 must share depend on counts, timing
  or chains longer than 2 steps.

## Verification

- `tests/test_stage7_foundation.py::test_no_knowledge_type_can_assert_normality` (asserts the
  five members and refuses `DRIFT_NOTICE` and `MODEL_DELTA` as `unknown KnowledgeType`).
- `pocketsec/stage7/labs/seventy_two_experiments.py`: S7X-48 and S7X-49 rows are
  `REFUSED_BY_CONSTRUCTION`; `catalogue_problems()` is checked by G7.11.
- `pocketsec/stage7/aggregation/robust.py`: `Aggregator.MEAN` semantics (spec D7.9).
- `pocketsec/stage7/antibody/forge.py:matches` calls `stage6.memory.semantic.match_motif`.
- This session: the Stage 7 suite ran 397 tests, 0 failures (see ADR-0061, Verification).

## Prior art

None claimed. McMahan et al. (FedAvg), Li et al. (FedProx) and the personalised-FL family are
named as baselines only; none is claimed to be beaten, because none applies.
