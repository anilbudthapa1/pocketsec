# ADR-0061 — Stage 7 consumes Stage 6 through a module-and-name allow-list; the bridge is the only caller of `QuarantineGateway.admit`; foreign knowledge enters Stage 6 only through `fleet.package` rewrites

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 7
- **Deciders:** Stage 7 integrator (decided at spec time, `docs/stage-7-spec.md` §2.3, §7.16, §10; written after the measurement and review-fix sessions)
- **Supersedes / superseded by:** none

> Authority-boundary ADR. It fixes the only path by which anything Stage 7 holds can reach
> Stage 6. It says nothing about whether that path carries value; ADR-0067 records that
> today it carries none.

## Context

Stage 7 is where foreign knowledge arrives, so its import graph *is* its security boundary.
Integration plan rule T3 says the only module that may import Stage 7 into the trusted local
path is `stage6/capsule/quarantine.py`. The lead's Stage 7 rules add: foreign knowledge reaches
local trusted state only through Stage 6's quarantine → validation → promotion boundary; Stage 7
must not build a second promotion gate; Stage 7 must not edit Stage 6.

Stage 6 already has a foreign-import path, `stage6/fleet/package.py`. Its docstring states
three foreign claims that it **rewrites instead of trusting**: every step's `source_group`
becomes the hash of the fleet group, every step's `epoch_id` becomes the local epoch, and the
label origin becomes `WEAK`. `package_to_capsules` raises `FleetDisabledError` unless
`enabled=True`. A second Stage 7 import path would duplicate the code most worth having once.

Stage 6 was being built by another wave while Stage 7 was written. Stage 7 therefore had to
name the Stage 6 symbols it depends on precisely enough that a move is detected, not silently
worked around.

Stage 6's `resources.WorkMeter`, `WorkBudgetExceeded` and `loadavg` are outside the Stage 6
spec's named interface. Stage 7 needs a work meter (cost is counted in work units, ADR-0033
precedent) and `/proc/loadavg` beside every timing.

## Decision

1. **Allow-list at module, name and importing-file granularity** (spec §2.3, encoded as
   `gate_boundary.STAGE6_ALLOW`):

   | Stage 6 module | names | Stage 7 files that may import them |
   |---|---|---|
   | `capsule.experience_capsule` | `EncodedStep`, `ExperienceCapsuleV1`, `PrivacyClass`, `SECRET_PATTERN`, `source_group_of` | any |
   | `memory.semantic` | `MotifStep`, `match_motif`, `motif_pattern_key`, `MAX_MOTIF_LENGTH`, `context_id_for` | any |
   | `memory.semantic` | `genesis_state` | `labs/` only |
   | `export.learning_record` | `LearningRecordV1` | `capsule/compiler.py` only |
   | `fleet.package` | `KnowledgePackageV1`, `KNOWLEDGE_PACKAGE_V1_VERSION`, `sign_package`, `verify_package`, `package_to_capsules` | `hivelock/stage6_bridge.py` only |
   | `fleet.package` | `MIN_KEY_BYTES` | `identity/integrity.py`, `hivelock/stage6_bridge.py` |
   | `capsule.quarantine` | `QuarantineGateway`, `QuarantineVerdict`, `QuarantineBucket` | `hivelock/stage6_bridge.py`, `labs/` |
   | `fossils.lineage` | `KnowledgeLineageDAG` | `hivelock/stage6_bridge.py` (calls only `.has`), `labs/` |
   | `provenance.ledger` | `ProvenanceLedger` | `labs/` only |
   | `resources` | `WorkMeter`, `WorkBudgetExceeded`, `loadavg` | any |

   Every other Stage 6 module and name is refused, including every writer (`promotion.*`,
   `chamber.*`, `shadow.*`, `consolidator.*`, `fossils.store` and the rest). A whole-module
   `import pocketsec.stage6.x` is refused everywhere, because names cannot be checked through
   it. The integrator's harness (`gate.py`, `gate_*.py`, `cli.py`) gets the `labs/` allowances
   and nothing more. Stages 3, 4 and 5 are refused outright.
2. **One door.** Within Stage 7, `hivelock/stage6_bridge.py` is the only module that calls
   `QuarantineGateway.admit`. It passes each `ExperienceCapsuleV1` to `admit` and to no other
   Stage 6 function, records Stage 6's verdict verbatim, and never inspects, overrides, retries
   or reinterprets it. `TRUSTED_CANDIDATE` is counted, never acted on.
3. **Only through `fleet.package` rewrites.** The bridge builds no `ExperienceCapsuleV1` by
   hand. For each supporting dependence cluster of an `ELIGIBLE` ECHO decision it builds one
   `KnowledgePackageV1`, signs it with `HMAC(bridge_secret, cluster_id)`, verifies it against
   its own derived keyring (local integrity only, ADR-0064), and converts it with
   `package_to_capsules(…, enabled=exchange_enabled)`. Stage 6's three rewrites therefore apply
   to everything Stage 7 hands over, and Stage 6's independence group `fleet:s7c-<cluster>` is
   Stage 7's dependence cluster. With exchange off, `FleetDisabledError` propagates and nothing
   is built or admitted.
4. **The recorded deviation.** `stage6.resources.WorkMeter`, `WorkBudgetExceeded` and `loadavg`
   are admitted although they are outside Stage 6's named interface. They hold no trusted state:
   `WorkMeter` is a per-instance counter (`_budget`, `_spent`) that Stage 7 constructs itself,
   and `loadavg` reads `/proc/loadavg`. A second work meter would be the duplication the
   repository forbids.
5. If a Stage 6 name on this list moves, the Stage 7 package that needs it reports a blocker.
   It does not edit Stage 6.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Import Stage 6 freely, review by hand | any Stage 7 module could name a Stage 6 writer; nothing mechanical stops it | lowest | — | a boundary enforced by review alone is not a boundary |
| B. Module-level allow-list only | a permitted module leaks every name in it, including `genesis_state` to runtime code | low | — | too coarse: `memory.semantic` holds both the matcher Stage 7 needs and state constructors it must not use outside labs |
| **C. Module + name + importing-file allow-list, AST-checked (chosen)** | none known; residual below | medium (`gate_boundary.py`, 579 lines) | 0 offenders on rules 5, 6, 7, 10, 11 (G7.1) and 3, 8, 9, 12 (G7.2) (findings §M.1, §R.1) | — |
| D. Stage 7 hand-builds `ExperienceCapsuleV1` values | a second import path that could skip the source-group, epoch and `WEAK` rewrites | medium | not built | duplicates `fleet.package` and weakens it |
| E. Stage 7 raises its capsules' provenance so Stage 6 admits them | the sender sets its own trust | low | not built | a second promotion gate built by the sender (ADR-0067, option B) |
| F. A Stage 7 work meter | none | low | not built | duplicates `stage6.resources.WorkMeter` |

## Consequences

**Accepted costs.**
- **The door is open and the room is closed.** Stage 6 scores every foreign capsule at most
  `0.2 × 1 × (1 − 0.6) = 0.08`, below `MIN_PROVENANCE_SCORE = 0.5` (ADR-0067). The gate's 60
  suite runs built 2254 `ExperienceCapsuleV1`, passed 2254 to `admit`, and the lab gateways
  were offered 2254; Stage 6 put all 2254 in `UNCERTAIN` and 0 in `TRUSTED_CANDIDATE`
  (findings §M.1, G7.1 and G7.8). Everything Stage 7 hands over stops there. Stage 7 cannot
  change that under this ADR.
- Stage 7 depends on 24 distinct (module, name) pairs from 8 Stage 6 modules. Two allow-listed
  names are never imported: `memory.semantic.context_id_for` and `motif_pattern_key` (AST count,
  this session). A rename of any of the 24 in Stage 6 breaks Stage 7's import and must be
  reported, not patched.
- Stage 6 exposes no revocation or re-evaluation input (B7-2, ADR-0067). The one door only
  opens inward, so Stage 7 can compute which Stage 6 capsules a revocation targets (6 of 6 in
  G7.9) but cannot act on them.
- **Residuals of the AST proof** (findings §R.6): rules 3, 5, 6 and 8 see import statements and
  literal names only. Rule 12 now flags `__import__`, `eval`, `exec`, `compile`,
  `import_module` and `pickle`/`marshal`/`shelve`, with four declared exemptions
  (`gate_boundary.DYNAMIC_IMPORT_EXEMPTIONS`). A `getattr` on a module object obtained some
  other way is still invisible to AST.
- **Rule 7 is not literally "one `.admit` call".** `hivelock/ingress.py` calls
  `self._replay.admit(capsule)` and `labs/seventy_two_experiments.py` calls `admit` on a local
  `ReplayGuard()`. Both are `ReplayGuard.admit`, not Stage 6's, and both are declared
  exemptions in `tests/test_stage7_boundary.py` (a receiver provably bound to a replay guard).
  The stronger guarantee is rule 5: no Stage 7 runtime module but the bridge can import
  `QuarantineGateway` at all.
- Outside Stage 7, Stage 6's own modules (`stage6/gate_measured.py`,
  `stage6/gate_construction.py`, `stage6/labs/endurance.py`) and `benchmarks/stage6/flood.py`
  call `gateway.admit`. This ADR constrains Stage 7 only.

**Bounded state.** The bridge adds at most `MAX_BRIDGE_CAPSULES_PER_DECISION = 8` capsules per
decision, at most `MAX_BRIDGE_EVIDENCE_REFS = 32` evidence refs per item, and a receipt ring of
`MAX_BRIDGE_LINKS = 4096` with evictions counted (chosen parameters, not measurements).

**Reversibility.** The allow-list is one table (`gate_boundary.STAGE6_ALLOW`) mirrored from spec
§2.3. Widening it requires editing that table and this ADR together.

**Authority.** This ADR narrows authority. Stage 7 cannot name a Stage 6 writer (rule 6) or
anything in Stage 5 (T2, rule 3). G7.2's wire-key fuzz refused 372 of 372 authority-word
injections, and the AUTHORITY_INJECTION arm pooled 0 of 384 deliveries (findings §M.1).

## What would reopen this decision

- Stage 6 moving or renaming a listed name, or offering a named interface for work metering.
- Stage 6 adding a revocation or re-evaluation input (closes B7-2): the bridge would need a
  second, outward call, and this ADR would be amended to name it.
- The lead revising Stage 6's foreign prior (B7-1): the door would then carry candidates, and
  the poison stream measured at Stage 7's boundary (ADR-0067, ADR-0068) would reach Stage 6.
- Any Stage 7 need to read Stage 6 trusted state directly. The answer under this ADR is no.

## Verification

- `tests/test_stage7_boundary.py`: `test_stage7_imports_upstream_only_through_the_allow_list`,
  `test_the_allow_list_permits_exactly_the_seams_it_must`,
  `test_no_stage7_module_names_a_stage6_writer`, `test_the_bridge_is_the_one_door_to_admit`,
  `test_the_admit_exemption_is_exactly_one_receiver_in_one_file`, and the negative fixtures in
  `test_a_boundary_violation_is_caught_whatever_its_form`.
- Gate G7.1 (rules 5, 6, 7, 10, 11; `created == admitted == offered`) and G7.2 (rules 3, 8, 9, 12).
- This session: `python -m pytest tests/test_stage7_*.py -p no:cacheprovider --junitxml=…` ran
  397 tests, 0 failures, 0 errors, 0 skipped (56.3 s; loadavg 3.78 at start, 2.93 at end).
- `grep -rn "\.admit(" pocketsec/stage7` → three call sites: the bridge's `self._gateway.admit`
  and the two `ReplayGuard.admit` exemptions above.

## Prior art

None claimed.
