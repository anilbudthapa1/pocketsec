# ADR-0071 — Stage 8 consumes Stages 6 and 7 through an allow-list; `adapters/stage6.py` is the one caller of `admit`

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 8
- **Deciders:** Stage 8 integrator (spec §2.3, D8.17; two declared deviations recorded in the integration session)
- **Supersedes / superseded by:** none

> Authority-boundary ADR.

## Context

A discovery loop that can name a Stage 6 writer, or reach Stage 5, has production authority
whatever its documentation says. Stage 6 has no capsule kind that carries a detector
(ADR-0056), so a Stage 8 discovery can reach Stage 6 only as **evidence**. Stage 7 exports only
Stage 6 trusted DETECTOR records (ADR-0062), so the outbound path for a discovery is Stage 6 →
Stage 7, never Stage 8 → Stage 7.

## Decision

1. Stage 8 imports upstream names only from the spec §2.3 allow-list, at module, name and
   importing-file granularity; whole-module imports of Stage 6/7 are refused; nothing from
   Stages 3, 4 or 5.
2. `adapters/stage6.py` is the one module that calls `QuarantineGateway.admit`. A discovery
   reaches Stage 6 only as `TRANSITION_EPISODE` evidence capsules built by
   `capsule_from_scenario`, `DERIVED_INFERENCE`, one independence group per run
   (`stage8:<run_id>`), label origin `INFERENCE`, and `SIMULATED_RECORD` on synthetic data.
   The mechanism, compiled artifact and tournament never enter Stage 6.
3. No Stage 8 → Stage 7 path. `adapters/stage7.py` is inbound only (antibodies as seeds).
4. **Declared deviations** (integration session): (a) rule 7 exempts `x.admit("<ResearchBudget
   bound>", n)` by call shape, because the spec's own `ResearchGovernor.admit(bound, current)`
   (D8.18) is a called `.admit`; Stage 6's `admit(capsule)` raises `ContractError` on a string.
   (b) The harness (`gate*.py`, `cli.py`) may import `pocketsec.stage2.gate_criteria:imported_modules`
   so G8.9/G8.10 run the boundary checker in-gate (Stage 7 precedent).
5. The rule-16 behaviours that need `gateway.admit(package)` or Stage 5's `_refuse_untyped` are
   tested in `tests/test_stage8_boundary.py`; the gate cannot run them without itself breaking
   rules 3 and 7, and says so in G8.9's detail.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Hand Stage 6 the `DiscoveryPackageV1` | a second promotion path | low | refused by type: `admit` raises `ContractError` for a non-capsule (`test_rule16_the_gateway_refuses_…`) | Stage 6 has one door and one input type |
| B. Mint one independence group per package to reach label quorum | Stage 8 manufacturing its own quorum | low | not built | a second promotion gate built by the sender (ADR-0067 option B) |
| **C. Evidence capsules, one group per run, one door (chosen)** | none; Stage 6 decides everything | medium | spec M0.2: 0/12 and 0/36 TRUSTED_CANDIDATE; the gate reports its own figures in G8.9 | — |
| D. Stage 8 → Stage 7 export | a research artifact leaving the host untrusted-by-construction | medium | not built | Stage 7 exports only Stage 6 trusted records |

## Consequences

**Accepted costs.** Realised adoption is 0 (ADR-0076). Every detection gain is
`counterfactual_at_boundary`.

**Bounded state.** Receipts ≤ `MAX_ADAPTER_RECEIPTS` (1024), capsules ≤ 8 per package.

**Reversibility.** Stage 6 owns everything it admits.

**Authority.** None moves toward Stage 8; this ADR removes a path.

## Verification

`tests/test_stage8_boundary.py` rules 4–7, 10, 11, 16; G8.9; G8.10.

## Prior art

No novelty claim.

## Amendment 2026-09-27 — fix wave: the one door checks the ledger and the evidence, not the package

- **Status of this amendment:** Accepted. The text above is kept; block 0070–0079 is full.

### What was found (S8-AUTH-01, S8-LIN-06)

The door checked only that a package agreed with itself. Reproduced by the reviewer and pinned
by this wave's tests: (1) a MALICIOUS package naming 8 label-0 REPLICATION sessions its mechanism
never matched was admitted as 8 MALICIOUS/INFERENCE capsules; (2) `verify_package` accepted status
REPRODUCED beside a failed REPLICATION record; (3) the same package handed over by 6 adapters
(6 run ids, so 6 independence groups) into one gateway admitted 48 capsules, i.e. Stage 8 alone
could supply Stage 6's two-group label quorum for a session. And a Stage 6 exception part-way
through a hand-over left the capsules already admitted with no receipt, so no lineage.

### Decision

1. `Stage6Adapter` takes the run's `TheoryLedger` (required). REPRODUCED is the ledger's status of
   `package.hypothesis_id`, and the package's genome digest, mechanism and direction must be the
   ledger's (`refused_not_in_ledger`, `refused_ledger_not_reproduced`, `refused_ledger_mismatch`).
2. Each evidence session must re-derive to its id (as before), be matched by the package's
   mechanism (`refused_evidence_not_matched`), carry the lab label of the package's direction
   (`refused_evidence_label`), and list only digests the package lists (`refused_evidence_digest`).
   `discovery_run` therefore names as evidence only the REPLICATION matches whose digests fit the
   package's 32 (at most 8 sessions).
3. `verify_package` refuses status REPRODUCED beside a failed REPLICATION record.
4. Per gateway (weakly keyed, at most `MAX_HANDED_EVIDENCE` = 65 536 sessions, evictions counted),
   a session handed over by one independence group is refused to any other
   (`refused_evidence_other_run`). The same group repeating is not a new vote and is allowed.
5. If Stage 6 raises mid-hand-over, a partial receipt for what was admitted is recorded
   (`partial_hand_overs`) and the error re-raised; `created` counts capsules offered, so
   `created != admitted` then, loudly. `discovery_run` records a door refusal in
   `package_problems` and continues; it is the door working, not a crash.

### Options considered (amendment)

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Trust the package's self-consistency | mislabelled INFERENCE votes reach Stage 6 | none | 8 wrong capsules admitted (case 1) | the door's promises were false |
| B. Sign packages with a key the adapter verifies | still the package's own claim | medium | not done | a signature does not make evidence match a mechanism |
| **C. Check the ledger and re-check the evidence (chosen)** | none | low | cases 1-3 refused, nothing admitted | — |

### Not fixed

A cross-gateway, cross-process record of handed sessions needs Stage 6-side state; the record is
per gateway object in one process.

## Verification (amendment)

`tests/test_stage8_forge.py::test_s8_auth_01_*`, `test_s8_lin_06_*`; `tests/test_stage8_boundary.py`
rule 16 (the fixture now earns REPRODUCED through two vault batches).
