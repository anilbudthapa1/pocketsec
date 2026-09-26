# ADR-0060 — Stage 7 layout amendments; no research package; no H13 is minted (BASE for the gate, H8 for ablation rows)

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 7
- **Deciders:** Stage 7 integrator (decided at spec time, `docs/stage-7-spec.md` §2.1, §2.6, §10; written after the measurement and review-fix sessions)
- **Supersedes / superseded by:** amends the Stage 7 rows of `docs/architecture/stage-3-12-integration-plan.md` §1.2 (layout) and §5.2 (hypothesis H13). Superseded by: none

> Layout and bookkeeping ADR. It records where Stage 7's code lives and which hypothesis its
> experiments bind to. It makes no detection claim.

## Context

The integration plan (§1.2) laid Stage 7 out as `hivelock/{ingress.py,quarantine.py}`,
`identity/{peer.py,integrity.py,revocation.py}` and `labs/{byzantine_suite.py,partition.py,sybil_sim.py}`,
among others. Four things in that layout did not fit the lead's Stage 7 rules:

1. **`hivelock/quarantine.py`.** The lead's rule is "do not build a second promotion gate". A
   Stage 7 module named `quarantine` invites exactly that. What Stage 7 needs is the handoff *to*
   Stage 6's quarantine.
2. **Two modules named `revocation.py`.** Key revocation (D7.4) and capsule revocation (D7.16)
   are different things. The plan had a home for the first and none for the second.
3. **Deliverables with no module.** D7.16 (cross-host lineage), architecture §22 (contextual
   trust) and §32/§43/layer 7.20 (the composition root, failure isolation and offline mode) had
   no file in the plan.
4. **An empty `collective/` directory.** At spec time `pocketsec/stage7/{collective,hivelock,orpheus,privacy,trust}/`
   existed as empty directories (spec §2.1). ADR-0121 says an empty package directory is a defect.

Separately, the plan (§5.2) gives each stage one new hypothesis (H13 for Stage 7) and
pre-assigns ADR-0012 to add H9–H18 together with their prior-art ledger entries. ADR-0012 was
never written. `HYPOTHESES` holds H0–H8 (checked this session:
`python -c "from pocketsec.stage0.hypotheses import HYPOTHESES; print(list(HYPOTHESES))"` →
`['H0', …, 'H8']`), and `tests/test_harness_and_gate.py` couples that table to
`docs/prior-art/ledger.json`. Stage 6 met the same gap and bound to existing ids (ADR-0055);
Stage 5 bound its gate to `BASE`.

The plan's §2.4 already lists Stage 7 as "no" for a `research/` package: signing, graph and
counting work need no numpy.

## Decision

1. **Layout** (spec §2.1, as built):
   - `hivelock/quarantine.py` becomes **`hivelock/stage6_bridge.py`**. The name says what it is:
     the one module that hands anything to Stage 6. It builds no gate of its own (ADR-0061).
   - `identity/revocation.py` is folded into `identity/integrity.py` (key register, rotate,
     revoke). Capsule revocation lives in `lineage/cross_host.py`.
   - **Added:** `lineage/cross_host.py` (D7.16), `trust/contextual.py` (§22), `orpheus/fabric.py`
     (§32, §43, layer 7.20), `labs/fleet_corpus.py`, `labs/simulated_fleet.py` (the plan's
     `labs/sybil_sim.py`, renamed because it simulates honest peers too and the lead requires
     `simulated_*` names), `labs/campaign_sim.py`, `labs/privacy_attacks.py`,
     `labs/seventy_two_experiments.py`.
   - **`collective/` is deleted** (ADR-0121) and must not return. The other four empty
     directories are filled by this layout.
   - Subsystem `__init__.py` files re-export nothing; consumers import leaf modules.
     `pocketsec/stage7/__init__.py` may be a lazy surface (the `stage6/__init__.py` shape), never
     an eager re-export chain.
2. **No `research/` package and no numpy** under `pocketsec/stage7/`.
3. **No H13 is minted.** The gate binds to **`BASE`**
   (`STAGE7_HYPOTHESIS = "BASE"`, `EXPERIMENT_ID = "PS-S7-20260926-BASE-orpheus-gate-0001"`).
   Ablation rows and measurement rows bind to **`H8`** ("Combine only components independently
   justified by ablation"), which is what a Stage 7 ablation row tests. `HYPOTHESES` stays H0–H8.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Keep `hivelock/quarantine.py` as the plan names it | a second quarantine inside Stage 7 is one refactor from a second promotion gate | same | not built | the lead forbids a second promotion gate; the name would say the opposite of what the module may do |
| **B. `hivelock/stage6_bridge.py` plus the added modules (chosen)** | none; the one door is named and AST-checked (ADR-0061) | +5 modules against the plan | boundary rules 5, 6, 7, 10, 11 report 0 offenders (findings §M.1, G7.1) | — |
| C. Keep the empty `collective/` directory | none directly | none | — | ADR-0121: an empty package directory is a defect |
| D. Mint H13 and its prior-art entry | none | edits the Stage 0 hypothesis table and ledger | not done | that change belongs to ADR-0012, which no wave has written; a wave may not add one hypothesis alone (plan §5.2) |
| **E. Gate → `BASE`, ablation → `H8` (chosen)** | none | none | 28 Stage 7 rows registered: 1 `BASE`, 27 `H8` (`experiments/registry.jsonl`, counted this session) | — |
| F. Bind the gate to `H8` as well | none | none | — | the gate checks boundary and bound properties, not "combine only justified components"; binding it to H8 would overstate what H8 has shown |

## Consequences

**Accepted costs.**
- Stage 7 has no hypothesis of its own. Its central claim (spec §8) is tracked by the gate under
  `BASE`, and the ablation evidence under `H8`. The plan warns that a wave "may not silently
  reuse H8 for unrelated work"; this ADR is the non-silent record, and the reuse is limited to
  rows that are ablations or measurements of Stage 7 components.
- The layout differs from the plan's §1.2. A reader of the plan will not find
  `hivelock/quarantine.py`, `identity/revocation.py` or `labs/sybil_sim.py`.
- One open defect touches the labs separation this layout depends on (findings §R.8,
  S7-AUTH-04): `core_ids.resolve_symbols`, a runtime surface, resolves table row 22
  (`labs.byzantine_suite:run_byzantine_suite`) with `importlib`, so boundary rule 10 ("runtime
  never imports labs") has one declared runtime path. It is left open because fixing it moves a
  public function into the harness.

**Not decided here.** `constitution/collective.py` says `COLLECTIVE_EXCHANGE_ENABLED` is off by
default and that "ADR-0060 records who may turn it on". This ADR does not decide that. It records
only the facts in the code. `COLLECTIVE_EXCHANGE_ENABLED = False`. `OrpheusFabric(exchange_enabled=…)`
defaults to it, and `Stage6Bridge(exchange_enabled=…)` has no default. Turning exchange on is a
constructor argument supplied by whoever builds the fabric. ADR-0068 recommends shipping with
exchange off. Who may turn it on is still undecided.

**Bounded state.** No change. This ADR moves no store.

**Reversibility.** Renaming files back is mechanical, but `tests/test_stage7_boundary.py` and
`gate_boundary.py` name `hivelock/stage6_bridge.py` as the one door, so a rename must move that
constant too. Minting H13 later means writing ADR-0012 and then re-registering the Stage 7 rows
under it; the existing `BASE`/`H8` rows stay in the append-only ledger.

**Authority.** None. Nothing moves closer to execution authority.

## What would reopen this decision

- ADR-0012 being written and H9–H18 added: Stage 7's rows would then re-bind to H13.
- A Stage 7 component that needs numpy or an offline solver would need its own ADR amending
  plan §2.4, and a `research/` package outside the runtime import graph.
- A second module that needs to reach Stage 6 would reopen the one-door layout (ADR-0061).

## Verification

- `tests/test_stage7_boundary.py::test_no_stage7_package_is_empty_and_collective_is_gone`
  (`gate_boundary.DELETED_DIRECTORIES = ("collective",)`).
- `tests/test_stage7_boundary.py::test_stage7_never_imports_research_code_and_ships_no_research_package`.
- G7.11's discipline clause (`gate_measured._discipline`) checks `set(HYPOTHESES) == {H0…H8}` and
  that `experiments/registry.jsonl` is byte-identical across a gate run.
- `pocketsec/stage7/gate.py`: `STAGE7_HYPOTHESIS = "BASE"`, `ABLATION_HYPOTHESIS = "H8"`.
- This session: `ls pocketsec/stage7/collective pocketsec/stage7/research` → both absent;
  `grep -rl numpy pocketsec/stage7` → no file.

## Prior art

None claimed. Precedents inside this repository: ADR-0055 (Stage 6 mints no hypothesis),
ADR-0121 (empty package directory), ADR-0050 and ADR-0040 (no research package).
