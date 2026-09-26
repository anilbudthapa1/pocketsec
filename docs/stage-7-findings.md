# Stage 7 — ORPHEUS + HIVELOCK — findings (D7.20)

- **Date:** 2026-09-26
- **Status: PARTIAL.** `pocketsec-stage7 gate` FAILS 5 of 11 (G7.4, G7.5, G7.8, G7.10,
  G7.11). This session re-ran the gate and reproduced every deciding figure from the
  integration session (§M.1).
- **Central claim: NOT SUPPORTED on the value half. The boundary half holds.**
  - **The boundary half holds.** No test run in this session found a path around Stage 6's
    quarantine or into Stage 5. No unanimous fleet changed a local decision. Those parts of the
    claim hold as construction and bound properties.
  - **The value half is not supported.** That half says Stage 7 lets a host gain detection from
    other hosts' knowledge, that Sybil influence scales with roots, and that poison acceptance
    stays below MEDIAN's. The measurements:
    - ECHO beats MEDIAN on robustness.
    - ECHO loses detection to trivial local-validation baselines on every arm and share
      measured.
    - Under Byzantine poison at share 0.1–0.6, ECHO's gain over *no sharing* is **0.000**.
  - The lead's rule requires both: beat no-sharing on detection **and** beat median on
    robustness. ECHO meets only the second, so it is **NOT-YET-JUSTIFIED** (ADR-0068). The
    configuration recommended for shipping is **the boundary only, with exchange off**.
- **Nothing here is a detection result.**
  - The fleet is simulated in-process and every corpus is synthetic.
  - Stage 6 admits no foreign capsule (B7-1, ADR-0067), so every detection figure is
    `counterfactual_at_boundary`.
  - Adversaries, defences and ground truth share one author (lesson 6).
  - The fleet corpus is `DEGENERATE_IN_FAVOUR` of sharing (precondition P5).
- **Authorship.** This document is written by the measurement session: §M, Appendix B, and
  ADR-0067, ADR-0068 and ADR-0069. It builds on the integration session's report, which is kept
  verbatim as Appendix A. This session re-measured every figure in that report.
- **Timing.** Other waves contend for this host. Every timing below carries `/proc/loadavg`,
  and only within-run ratios transfer. No absolute time is a device figure.

---

## R. Review-fix session (2026-09-26): what the confirmed review findings changed

This section was written by the session that fixed the Stage 7 review findings (S7-R1..R10,
S7-AUTH-01..09, F1..F8, R7-1..R7-7). It **supersedes** the figures it names in §M and in
Appendix A. Those passages are kept as they were, with a `[corrected: §R.n]` marker where a
statement turned out to be false. Every figure below was produced in this session by the
command named beside it. Every regression test named here **failed** when its fix was
switched off (a scratch plugin re-created each pre-fix behaviour, one at a time; the plugin
is not in the repository) and passes with the fix.

### R.1 The gate after the fixes

`python -m pocketsec.stage7.cli gate` (no hash seed), loadavg 13.59 9.34 6.47 at start and
7.18 11.91 11.54 at the end: **FAILED (5), 6/11**. The same five criteria fail as before
(G7.4, G7.5, G7.8, G7.10, G7.11), so the status line at the top is unchanged. Figures that
moved:

| figure | before (§M) | after | why |
|---|---|---|---|
| G7.2 rules evaluated | 3, 8, 9 | 3, 8, 9, **12** (0 offenders) | new rule 12: dynamic import / code execution (R.6) |
| G7.8 ELIGIBLE decisions with complete ancestry | 3648/3648 | 3228/3228 | decision ids are now stable per (key, status, evidence) instead of per round (R.2); the count is of DISTINCT decisions |
| G7.9 descendants of the retracted capsule | 15 | 8 | same cause: the per-round duplicate ECHO_DECISION nodes are gone; stage6_capsule_ids still 6 = 6 |
| G7.5(b) honest cross-root merges | 216/881 = 0.245 | 250/984 = 0.254 | gravity no longer drops merged clusters' capsules (R.3), so more honest peers reach the graph |
| G7.4 MEDIAN amplification, SYBIL_DECLARED_ROOT S=1 / S=128 | 0.591 / 6.909 | 0.553 / 13.794 | same cause: more Sybil capsules are pooled for the identity aggregators; ECHO stays 0.000 at every S |
| G7.7 property inference | distilled 0.163, raw 0.198, "chance 0.667", "200 trials" | distilled **0.182** (chance **0.727**, 22 hosts), raw **0.208** (chance 0.667, 24 hosts), both exhaustive | R.5 |
| G7.10 churn | plateau failed on lineage only; keyring refused 727 | plateau fails on **graph 616 → 918, peers 616 → 918, lineage 1191 → 1831** (middle-third → last-third peak); keyring refused 0 | R.4 |
| G7.10 incremental RSS | 44 392 448 B | 47 960 064 B (load 14.48) | contended host; not comparable across runs |
| gravity ablation | NOT_YET_JUSTIFIED, firing 287 | **INERT, firing 0** | R.3 |
| collective_novelty / differential_privacy ablation | JUSTIFIED (firing 64 / 58) | **INERT (fabric firing 0)** | R.5 |
| ECHO_PROBATION_ROUNDS flip share ×0.5 / ×2 | 0 / 0 ("inert") | **0.444 / 0.333** | R.5 |

Detection and robustness figures of G7.11 did not move: gain over no sharing 0.571 at share 0
and 0.000 under BYZANTINE_POISON 0.2; ECHO 0.571 against ROOT_QUORUM+LV 0.786; true acceptance
at share 0 ECHO 0.545 against MEDIAN 1.000. **The ECHO verdict (NOT-YET-JUSTIFIED, ADR-0068)
stands.**

### R.2 ECHO counted evidence it should not have (all HIGH, all fixed)

| finding | defect | fix | regression test (`tests/test_stage7_review_fixes.py`) |
|---|---|---|---|
| S7-R1 | a capsule retracted BEFORE its key's first ELIGIBLE round kept its full mass (only a decision node could carry the suspect mark) | the fabric hands ECHO a lineage-liveness predicate; a contribution whose node is not LIVE is excluded every round, whatever the order, and counts again if reinstated | `test_retraction_before_eligibility_removes_the_contribution`, `test_reinstated_contribution_counts_again` |
| S7-AUTH-01, R7-1 | ECHO never read `expiry_round` or the keyring: expired capsules and revoked keys kept supporting a key forever | `_Contribution` carries `key_id` and `expiry_round`; expired contributions are dropped (a key left with none closes); a contribution whose key no longer verifies (REVOKED, or ROTATED past grace, or reclaimed) is excluded | `test_expired_contributions_stop_counting_and_close_the_key`, `test_revoked_signing_keys_stop_counting_in_echo` |
| S7-R2, R7-3 (slots) | 64 first-come slots per key: same-cluster Sybils that add no mass locked out every later CONTEST | a full key evicts one surplus identity from its largest (cluster, stance) group when that group is at least two larger than the newcomer's; independent groups of one are never evicted | `test_sybil_slot_squatters_cannot_lock_out_contests` |
| S7-AUTH-02, R7-3 (keys) | 1024 first-come keys, never evicted: one key-holder could end all sharing on a host | a cluster may hold at most `MAX_KEYS_PER_OPENER` = 128 keys open (a parameter, chosen, not measured), and keys close when their contributions expire | `test_one_key_holder_cannot_own_the_key_table` |
| S7-R3 | relaying the host's own (REFUSED local_origin) antibody farmed trust | a REFUSED or SUSPECT key confirms nobody | `test_relaying_the_hosts_own_knowledge_farms_no_trust` |
| S7-R4, S7-AUTH-08 | sovereignty covered only keys held at construction; `publish()` added the capsule id, never the antibody key | the published antibody key joins the live sovereignty view that both ingress and ECHO read; a publish whose key would not fit the bounded set is refused, never evicted | `test_an_antibody_published_after_startup_is_sovereign` |
| R7-2 | an unchanged ELIGIBLE key added one lineage node per round (the id hashed the round), flooding the descendant walk | the decision id hashes (key, status, evidence grouping) only; an unchanged decision is one node | `test_an_unchanged_eligible_key_is_one_lineage_node` |

### R.3 Gravity counted dependence twice, and without that it never fires (R7-5)

Gravity multiplied by 1/cluster size although ECHO's cluster cap already gives a cluster one
term. At epistemic distance 0 and a self-reported validation of 0.875, a merged honest cluster
of 18 or more members fell below `VALIDATION_FLOOR` = 0.05 (0.875 / 18 < 0.05) and lost every
capsule to METADATA_ONLY; any distance makes the threshold smaller. The
fabric now passes assessed-ness (1.0, or 0.0 for an UNASSESSED peer) instead of 1/size, and
`FabricComponents.gravity_enabled` makes ADR-0069's "default off" a configuration change
(`test_a_merged_honest_cluster_still_reaches_echo`).

**Measured consequence (the gate in R.1): gravity's firing fell from 287 to 0.** Every one of
the 287 triage decisions the earlier sessions reported came from the double-counted term.
Gravity is **INERT** on this corpus. It is left on (the code default) because turning it off
is a decision for the lead; the recommendation is to remove it or default it off.

### R.4 The keyring never reclaimed a dead key, so churn "plateaued" by refusing (R7-4)

`Keyring.register` now reclaims the oldest record that can never verify again (REVOKED, or
ROTATED past grace); live keys are never evicted and a reclaimed id can never be registered
again (a fixed-size Bloom filter, fail-closed). The replay guard prunes entries of expired
capsules and of keys that no longer verify. Tests:
`test_keyring_reclaims_dead_records_but_never_reuses_an_id`,
`test_churn_keyring_no_longer_refuses_and_the_plateau_rule_still_sees_a_leak`.

**What churn measures now.** The earlier "bounded by refusal" figures (§M.8: 727 / 4140 /
9262 / 41 814 keyring refusals) described a receiver that had stopped admitting anyone. In the
gate's 720-round churn the keyring now refuses **0**, and the peer table and dependence graph
grow **616 → 918** toward their caps of 1024, with lineage **1191 → 1831**. The graph never
evicts (a documented anti-laundering choice): once it reaches its cap every newcomer is
UNASSESSED with independence 0, and so gravity 0. **That lock is not fixed** (known defect, R.8).

**The plateau rule had to change, and this is a definition change.** The old rule (any
last-third peak above the middle-third peak) was met only because the full keyring froze
every store. A live, stationary store fluctuates and failed it by chance (replay_seen 14 → 15
on the test's 45-round run). The rule is now: a store is growing when its last-third peak
exceeds its middle-third peak by more than its own largest one-round change in the middle
third (`labs.partition.unplateaued`). The regression test pins that a synthetic +1-per-round
leak is still flagged and a bounded fluctuating store is not.

### R.5 Measurements that claimed more than they showed

- **ECHO_PROBATION_ROUNDS is not inert (S7-R7).** The sensitivity metric compared only each
  key's last status; probation moves the first-ELIGIBLE round, which is the one round the
  fabric bridges. The metric now also compares that round. Gate: **0.444 at ×0.5 (probation
  1) and 0.333 at ×2 (probation 3)**. Other rows moved with the richer metric: MASS_FLOOR
  0.389 / 0.333, TRUST_PRIOR 0.333 / 0.389, CONTEST_RATIO 0.0 / 0.167. Still inert: CLUSTER_CAP
  and RELEVANCE_FLOOR. CLUSTER_CAP cannot bind by construction (S7-R6): mass is trust ×
  relevance × survival, each at most 1, so `min(1.0, mass)` is always the mass; its ablation
  measures max-over-members against sum-over-identities, not the cap
  (`test_threshold_sensitivity_sees_a_moved_handoff_round`).
- **Collective novelty and DP are INERT on the fabric path (F4).** Both probes ignore the
  corpus and run a hand-built window of 4 novel and 4 common patterns, in which the local-only
  control flags every common pattern by definition. No runtime code calls
  `observe_population`, and honest fleet traffic carries no NOVELTY capsule, so on the fabric
  path they fire **0** times (`fabric_novelty_firing`, gate R.1). The ablation now judges them
  by that firing: **INERT**. The toy figures stay in the metric text, labelled TOY. DP is in
  any case a trade-off, not a win: the count-membership advantage falls from 1.000 to 0.435 at
  ε = 1.0 while novel recall falls from 1.000 to 0.141 (G7.7 (e)). The previous JUSTIFIED
  verdicts for both are withdrawn (`test_collective_novelty_is_inert_on_the_fabric_path`).
- **Property inference was resampling noise with a wrong chance (F8).** The "200 trials" were
  with-replacement draws of n deterministic leave-one-out predictions. The attack is now
  exhaustive leave-one-host-out. Corpus seed 7, 24 hosts, 40 episodes
  (`privacy_attacks.property_inference`, load 3.58): **distilled 20/22 = 0.909 (chance 16/22 =
  0.727, advantage 0.182); raw steps 21/24 = 0.875 (chance 0.667, advantage 0.208).** In
  accuracy the distilled export classifies the undisclosed property at least as well as raw
  steps. The earlier "leaks a little less than raw" reading is withdrawn
  (`test_property_inference_is_exhaustive_with_its_own_chance`).
- **G7.3 could not see a fabric that damaged local state (F2).** The digest re-derived local
  outputs from the static corpus and read only the benign ring. It now also digests the
  validator's full state (`LocalValidator.state_digest`), its verdict on every local rule and on
  one probe per relation, the sovereignty key set, and every non-LIVE LOCAL_CAPSULE node. A
  fabric that wipes the validator each round now makes the digests differ; the honest run is
  still identical at 4/4 (`test_offline_equivalence_sees_a_fabric_that_damages_the_validator`).
- **G7.5(c) cannot fail (S7-R5, F7).** Nothing in the runtime calls `EchoEngine.record_outcome`,
  so trust only ever receives confirmations and reliability cannot fall below the prior
  without a refutation. The gate's detail now says so; the clause is a construction property,
  not evidence. The refutation half of the asymmetric trust update is unreachable in the fabric.

### R.6 The AST boundary proof had gaps (S7-AUTH-03, F1)

Rules 3, 5, 6 and 8 see only import statements and literal names. **Rule 12** now flags
`__import__`, `eval`, `exec`, `compile`, `import_module` and `pickle`/`marshal`/`shelve` in every
Stage 7 file, except four declared (file, function) sites that import only names from a literal
table or a validated pattern (`gate_boundary.DYNAMIC_IMPORT_EXEMPTIONS`). The real tree has 0
offenders; G7.2 evaluates it. Rule 7's fresh-`ReplayGuard` exemption no longer applies in a file
that rebinds the name `ReplayGuard`. Residual: `getattr` on a module object reached some other
way is still invisible to AST. Tests: `test_rule_12_*`, `test_a_shadowed_replay_guard_exempts_no_admit_call`.

### R.7 Statements in this document corrected without new code

- **"Beat median on robustness: met" (F3).** The suite's MEDIAN takes the median over
  non-silent voters and has no quorum: with no contests it accepts a key one identity supports.
  It is weaker than MAJORITY and not a Byzantine-robust median in any useful sense. ECHO beating
  it is a weak result; ECHO against ROOT_QUORUM+LV (§M.4 (3)) is the informative comparison.
- **"reconstruction JUSTIFIED +0.900 recall" (F5).** The control is a hard-coded 0.0 ("no
  reconstruction detects nothing"), not the named baseline `count_threshold_join`, and the
  firing count is the number of detected campaigns. The gain over `count_threshold_join` was
  not measured in this session: UNMEASURED here.
- **"time-to-detect 2.833 rounds for ECHO against 4.429 for CENTRAL_FEED" (S7-R9, F6).** It is
  set by constants: `FEED_LAG_ROUNDS = 4` puts every feed acceptance at 4 or later and ECHO's
  probation puts it at 2 or later. It averages only over accepted keys (survivorship) and the
  spec's "at equal FP" condition is not checked. It is not evidence about discovery speed.
  `FEED_LAG_ROUNDS` is a chosen parameter.
- **Receiver-count dependence of detection (S7-R8).** Detection pools every receiver's scores
  into one recall at FPR ≤ 0.01, so the false positives allowed grow with the number of benign
  items: below 100 benign items a single false positive exceeds 0.01. The review counted 60
  benign items for 4 receivers and 360 for 24 (not re-counted in this session). The 4- and
  24-receiver runs are therefore scored at different effective thresholds.
- **Memory figures at pressure 0 (R7-7).** G7.10's RSS and §M.8's "~3.2 MB receiver, flat" were
  taken with the ECHO, graph and lineage stores at pressure 0 (the gate prints the pressure
  row). They are not a bound on the stores' own caps.
- **The residual identifier screen is a shape check (S7-AUTH-09).** A HEX-encoded path fits the
  commitment and root shapes and would pass both the screen and the canary scan; the
  distiller's docstring now says so.

### R.8 Known defects left open, with the reason

| finding | why not fixed here |
|---|---|
| R7-4 (graph half) | `DependenceGraph` never evicts, deliberately (evicting would let a Sybil launder its history by idling), and a union-find cannot drop a member without a rebuild. Under churn the graph now fills (918/1024 after 720 rounds) and then every newcomer is UNASSESSED. Needs a design decision, not a patch |
| S7-AUTH-04 | `core_ids.resolve_symbols` (public runtime surface) imports `labs.byzantine_suite` for table row 22; fixing it moves a public function to the harness and changes the constitution's resolver. Rule 12 exempts `_import_problem` by declaration, so rule 10 ("runtime never imports labs") still has this runtime path |
| S7-AUTH-06 | per-peer inbound byte caps are keyed on the unauthenticated transport label, so garbage can spend a round's inbound budget before integrity is checked. A fix needs authenticated sender binding before budgeting, a governor redesign |
| S7-AUTH-07 | `falsification_weight` multiplies by a self-reported survival rate that rewards lying. It is INERT in the gate (firing 0); ADR-0069 already recommends removing it. Left on to keep the shipped configuration unchanged; recommendation: remove |
| R7-6 | every `infer` re-evaluates each key under all 8 ablations to fill `firing`, charging the WorkMeter; not changed (it is how every firing count in this document was produced) |
| S7-R10 | per-round `firing` counts cannot register a mechanism whose effect is to block eligibility while probation ≥ 1; the suite already uses whole-run replays (`_decisions_changed`) for its verdicts; the per-round counter's docstring is unchanged |

---

## M.0 How this was measured

**Harness.** Detection results go through Stage 0's `run_benchmark`
(`benchmarks/stage7/_common.py`):
- Each aggregator's set of accepted antibodies becomes one `AntibodySetSlot`.
- The dataset is the receivers' held-out episodes: every benign episode, plus every attack of a
  family the receiver never saw locally.
- The dataset is written as a checksum-bound JSONL of Stage 0 stub sequences (Stage 1 gate
  precedent).
- The slot looks up each episode's already-encoded Stage 1 steps by id and never re-encodes.
  That avoids the lineage-carry-over corpus trap.
- `synthetic_data=True` is set on every row.
- The harness's resource figures describe the *whole process* that simulates the fleet. Its
  edge profile therefore reads `False`/`None` (peak process RSS reached 644 MB in the
  24-receiver sweep). These are **not** Stage 7 endpoint figures; §M.8 isolates the endpoint
  numbers.

**Scripts.** Everything lives in `benchmarks/stage7/`, following the Stage 5/6 precedent. The
package never imports these scripts.

| script | what it does |
|---|---|
| `fraction_sweep.py` | Runs every aggregator on identical pools, across every arm and every share or Sybil count, through `run_benchmark` |
| `paired_detection.py` | Counts discordant episodes between methods |
| `config_grid.py` | Replays identical traffic under different ECHO flag configurations |
| `echo_refusals.py` | Shows why ECHO refuses keys that the baselines accept |
| `resources.py` | Flood and scale runs under Stage 0's sampler, plus the CPU ratio |
| `linkability.py` | Anonymity sets of the exported coarse context |
| `summarise.py` | Builds tables from the JSON outputs |
| `register.py` | The explicit ledger write |

**Corpora.**
- Stage 7's own `labs/fleet_corpus.py`, at the gate's corpus seed **7** (24 hosts × 40 episodes)
  and at seed **11**. It is built from Stage 1's scenario vocabulary with session-unique process
  identities (P2).
- Preconditions P1–P4 PASS on both seeds.
- P5 is `DEGENERATE_IN_FAVOUR` on both seeds. The oracle motif transfers at recall 1.0 and
  FP 0, so *any* sharing looks good against no sharing.

**Receivers.** Two receiver sets were used:

| receiver set | corpus 7 (positives / benign) | corpus 11 (positives / benign) |
|---|---|---|
| the gate's 4 (`default_receivers`) | 14 / 60 | 12 / 60 |
| all 24 hosts | 81 / 360 | 74 / 360 |

The gate's n is small (14 positives on corpus 7). The 24-receiver runs check whether its
orderings survive at larger n. They do (§M.2).

**Registered.** Nine rows were written to `experiments/registry.jsonl` as an explicit act. Each
payload is in `results/<id>.json` (git-ignored):
- PS-S7-20260926-H8-fraction-sweep-default-0002
- PS-S7-20260926-H8-fraction-sweep-all-c7-0003
- PS-S7-20260926-H8-fraction-sweep-all-c11-0004
- PS-S7-20260926-H8-echo-config-grid-c7-0005
- PS-S7-20260926-H8-echo-config-grid-c11-0006
- PS-S7-20260926-H8-resources-scale-0007
- PS-S7-20260926-H8-linkability-c7-0008
- PS-S7-20260926-H8-linkability-c11-0009
- PS-S7-20260926-H8-echo-refusals-0010

The gate and its ablation rows are registered separately by `pocketsec-stage7 experiments
--register` (§M.9).

## M.1 The gate, re-run

**Run.** `PYTHONHASHSEED=0 /usr/bin/time -v python -m pocketsec.stage7.cli --json gate` ran
15:35:05–15:53:17 AEST. loadavg was 7.10 at the start and 19.69 at the end. It exited 1, with
**6/11** criteria met.

**Reproduction.** Every deciding figure equals the integration session's (Appendix A §A.1),
with three exceptions:
- incremental RSS was 44 421 120 B (the integration session measured 44 470 272 and
  44 511 232 B);
- the timings;
- the registry clause, which read **True** this time.

**Whole-process RSS.** The gate *process* peaked at **290 992 kB** maximum RSS
(`/usr/bin/time`). That process holds the corpus, the simulation state of 60 suite runs and the
lab Stage 6 gateways. It is not an endpoint figure. It is reported because it is the only
whole-process number.

| id | result | deciding figure (this session) |
|---|---|---|
| G7.1 | PASS | 0 boundary offenders. 2254 bridged = 2254 admitted = 2254 offered. Stage 6 buckets {UNCERTAIN: 2254}. Unanimous fleet (64 independent roots × 4 receivers): revocations refused 1024/1024; locally-FP support CHALLENGED at 4/4 and never bridged; contests refused 1024/1024; authority payloads refused 1024/1024 |
| G7.2 | PASS | 0 offenders. Wire-key fuzz: 372 of 372 refused. AUTHORITY_INJECTION: 384 deliveries, 0 pooled |
| G7.3 | PASS | Local-output digest identical at 4/4 receivers across absent, OFFLINE+flood, crashing, DISABLED and corrupt keyring. Faults fired (4 crash failures; 487–490 offline drops) |
| G7.4 | FAIL | SYBIL_ADAPTIVE: ECHO amplification 4.590–12.467 against a bound of 2.0. DECLARED and FORGED: 0.000 at every S |
| G7.5 | FAIL | Honest cross-root false merges **216/881 = 0.245** against a bound of 0.05. Rare role 1/1 against majority 5/8 |
| G7.6 | PASS | 69 SUPPORTED worlds. False campaign rate 0.000 against `count_threshold_join`'s 1.000. H0–H4 each explained 8–10 benign worlds. 4 SUPPRESSION cases were never detected |
| G7.7 | PASS | 0 canary hits (2553 blobs × 3177 needles). Membership advantage 0.000 against raw 1.000. Property advantage 0.163 against raw 0.198 (chance 0.667). DP curve has 4 ε points. SIEM oracle: recall 0.750, with 1303 raw strings exposed |
| G7.8 | FAIL | VACUOUS: 0 TRUSTED_CANDIDATE of 2254 (B7-1) |
| G7.9 | PASS | SELF_RETRACTION marked exactly the target and its 15 descendants; 0 non-descendants changed; reinstate was byte-identical. FALSE_REVOCATION: 80 judged, 0 accepted |
| G7.10 | FAIL | Churn plateau fails: lineage 1003 → 1243 from the middle to the last third. Incremental RSS 44 421 120 B, within the ceiling |
| G7.11 | FAIL | By construction (synthetic). Registry byte-identical: True. Detection gain 0.571 at share 0 and **0.000** at BYZANTINE_POISON 0.2 |

## M.2 Does sharing add detection? Against no sharing and the dumbest aggregators

Setup: `fraction_sweep.py`, arm NONE, share 0, scored through `run_benchmark`. Each cell is
recall at FPR 0.01 on locally-unseen families, with (true positives / positives, false positives
/ benign) in brackets.

| method | corpus 7, 4 receivers | corpus 7, 24 receivers | corpus 11, 24 receivers |
|---|---|---|---|
| NO_SHARING | 0.000 (0/14, 0/60) | 0.086 (7/81, 0/360) | 0.162 (12/74, 0/360) |
| MAJORITY / MEAN (FedAvg's rule) / MEDIAN / TRIMMED_MEAN, **no local validation** | **0.000** (14/14, **11/60**) | **0.000** (81/81, 44/360) | **0.000** (74/74, 45/360) |
| MEDIAN+LV = TRIMMED_MEAN+LV = VALIDATION_FILTER = ROOT_QUORUM(+LV) | 0.786 (11/14, 0/60) | 0.901 (73/81, 0/360) | 0.905 (67/74, 0/360) |
| **ECHO (shipped)** | **0.571** (8/14, 0/60) | **0.728** (59/81, 0/360) | **0.432** (32/74, 0/360) |

Three results follow.

1. **Without local validation, sharing is worse than useless on a non-IID fleet, even with no
   adversary.**
   - Every identity aggregator accepts honest antibodies that fire on the receiver's own benign
     traffic. On corpus 7 with 4 receivers, 11 of 60 benign episodes fire.
   - That breaks the FP budget, so recall at FPR 0.01 is 0.000.
   - The dumbest robust aggregators lose to non-IID data alone, not to poison.
   - FedAvg's rule reduces to MEAN on stances (ADR-0062). FedProx and personalised FL are
     UNMEASURED because no model parameters exist.
2. **Local validation is the whole detection effect.**
   - Any rule that adds local validation reaches the same ceiling.
   - VALIDATION_FILTER ("take anything that validates locally") ties MEDIAN+LV and ROOT_QUORUM
     on every episode.
   - `paired_detection.py` finds 0 discordant episodes between ROOT_QUORUM and
     VALIDATION_FILTER on all four receiver sets.
3. **ECHO catches a strict subset of what the trivial rule catches.**

   | corpus, receivers | ECHO | VALIDATION_FILTER | caught only by ECHO | caught only by VALIDATION_FILTER | exact sign test p |
   |---|---|---|---|---|---|
   | 7, 4 | 8/14 | 11/14 | 0 | 3 | 0.25 |
   | 7, 24 | 59/81 | 73/81 | 0 | 14 | 1.2e-4 |
   | 11, 4 | 3/12 | 10/12 | 0 | 7 | 0.016 |
   | 11, 24 | 32/74 | 67/74 | 0 | 35 | 5.8e-11 |

   Episodes from one host are not independent draws, so these p-values describe these corpora
   only. The direction is the same in all four sets and never reverses.

**Saturation check (lesson 9).**
- No method reaches 1.000 on any receiver set. Every local-validation rule tops out between
  0.786 and 0.905.
- The task is therefore not saturated *among sharing methods*, and ECHO's deficit is a real
  difference on this corpus.
- The comparison *against NO_SHARING* is degenerate in favour of sharing (P5): any sharing
  method that validates locally wins it.

## M.3 The adversary sweep: how much poison gets through as the adversary share rises

**Definitions.**
- Poison acceptance: the number of (receiver, poison key) pairs accepted divided by the number
  offered. This is the suite's definition, measured at Stage 7's output boundary.
- Break point: the smallest share at which acceptance reaches 0.5 or more. On Sybil arms the
  share is the adversary's identity share.
- Sweep: shares 0.1–0.6 in steps of 0.1, and S = 1..128 identities per adversary root.

The figures below are for corpus 7 with 4 receivers. `summarise.py` gives the same break points
on corpus 7 and corpus 11 with 24 receivers, except in one cell marked in the table.

| arm (the lead's attack) | MEDIAN | MEDIAN+LV | TRIMMED_MEAN / TRIMMED_MEAN+LV | VALIDATION_FILTER | ROOT_QUORUM+LV | **ECHO** |
|---|---|---|---|---|---|---|
| SYBIL_DECLARED_ROOT (a) | 0.04 (S=1) | 0.04 | 0.04 | 0.04 | none | **none** |
| SYBIL_FORGED_ROOTS (a) | 0.04 | 0.04 | 0.04 | 0.04 | none | **none** |
| SYBIL_ADAPTIVE (a) | 0.04 | 0.04 | 0.04 | 0.04 | 0.077 (S=2) | **0.143 (S=4)** |
| BYZANTINE_POISON (b) | 0.1 | none | 0.1 / none | none | none | none |
| BYZANTINE_LATENT_POISON (b) | 0.1 | 0.1 | 0.1 | 0.1 | none | **none** |
| SLOW_POISON (c) | 0.1 | 0.1 | 0.1 | 0.1 | 0.1 (none on corpus 7 with 24 receivers) | **none** |
| COLLUSION_TIMING (d) | 0.1 | 0.1 | 0.1 | 0.1 | 0.1 | **0.2** |
| BYZANTINE_SUPPRESS | none | none | none | none | none | none |

**The collusion break is not monotone (arm d).** ECHO's COLLUSION_TIMING poison acceptance by
share:

| receivers | 0.1 | 0.2 | 0.3 | 0.4–0.6 |
|---|---|---|---|---|
| corpus 7, 4 receivers | 0/4 | 4/4 | 4/4 | 0/4 |
| corpus 7, 24 receivers | 8/24 | 22/24 | 22/24 | 0/24 |

A break point of 0.2 therefore understates the arm, because acceptance is not monotone in share.
The mechanism was not diagnosed.

**Slow poison leaks a little at scale.** With 24 receivers, ECHO accepted:
- 2/24 SLOW_POISON pairs at shares 0.1 and 0.2 on corpus 7;
- 1/24 at 0.2 and 5/24 at 0.3 on corpus 11.

That is below the break level, but it is not 0.

**How much reaches Stage 6, and promotion.** The bridge's receipts, filtered to poison keys.
Each cell reads *poison decisions bridged → Stage 6 capsules created*:

| arm | corpus 7, 4 receivers | corpus 7, 24 receivers | corpus 11, 24 receivers |
|---|---|---|---|
| COLLUSION_TIMING 0.1 | — | 8 → 16 | — |
| COLLUSION_TIMING 0.2 / 0.3 | 4 → 16 / 4 → 28 | 22 → 88 / 22 → 154 | 22 → 88 / 22 → 154 |
| SLOW_POISON 0.1 / 0.2 / 0.3 | — | 2 → 4 / 2 → 4 / — | — / 1 → 2 / 5 → 10 |
| SYBIL_ADAPTIVE S=2 | — | 1 → 2 | 6 → 12 |
| SYBIL_ADAPTIVE S=4..128 | 4 → 12–27 | 22 → 66–134 | 22 → 66–124 |

Every one of those capsules landed in Stage 6's **UNCERTAIN** bucket; none was
TRUSTED_CANDIDATE. **Adversarial knowledge reaching promotion is 0 at every share, and so is
honest knowledge** (B7-1). As a robustness figure it is VACUOUS (ADR-0067). The defence doing
the work is Stage 6's foreign prior, not Stage 7.

**Detection under attack.** Recall at FPR 0.01, corpus 7, 4 receivers, scored through
`run_benchmark`. "(FP 4)" means 4 false positives broke the FP budget.

| arm, share | NO_SHARING | MEDIAN+LV | VALIDATION_FILTER | ROOT_QUORUM (graph clusters) | ROOT_QUORUM (declared roots) | **ECHO** |
|---|---|---|---|---|---|---|
| BYZANTINE_POISON 0.1–0.6 | 0.000 | 0.786 | 0.786 | **0.000** | 0.786 | **0.000** |
| BYZANTINE_LATENT_POISON 0.1–0.6 | 0.000 | 0.000 (FP 4) | 0.000 (FP 4) | 0.786 | 0.000 (FP 4) | 0.571 |
| SLOW_POISON 0.1–0.3 | 0.000 | 0.000 (FP 4) | 0.000 | 0.786 | 0.000 | 0.786 |
| COLLUSION_TIMING 0.2–0.3 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 (FP 4) |
| BYZANTINE_SUPPRESS 0.4 | 0.000 | 0.357 | 0.786 | 0.786 | 0.357 | 0.571 |
| SYBIL_FORGED_ROOTS S≥2 | 0.000 | 0.000 | 0.000 | 0.786 | 0.000 (FP 4) | 0.571 |
| SYBIL_ADAPTIVE S≥4 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 (FP 4) |

The 24-receiver runs on both corpora keep every ordering in this table. ADR-0068 gives both.

## M.4 The lead's rule, applied

**1. Beat no-sharing on detection: failed.**
- At share 0, ECHO does beat no-sharing: 0.571 against 0.000 on the gate set, and 0.728 against
  0.086 on corpus 7 with 24 receivers. But the comparison is DEGENERATE_IN_FAVOUR of sharing,
  and ECHO loses it to the trivial VALIDATION_FILTER.
- At BYZANTINE_POISON shares 0.1–0.6, the gain is **0.000** on all three receiver sets.
- Spec §7 requires a gain of at least 0.10 at share 0 *and* at share 0.2.

**2. Beat median on robustness: met.** [corrected: §R.7 — against a MEDIAN with no quorum, which
accepts a key one identity supports; a weak baseline.]
- ECHO's break point is strictly above MEDIAN's and MEDIAN+LV's on every Sybil arm, and at least
  as high on every Byzantine arm.
- On LATENT and SLOW poison, ECHO holds acceptance at 5/24 or less, where MEDIAN+LV takes 22/24.

**3. Against ROOT_QUORUM+LV (the control for ECHO's extra terms): ECHO loses detection.**
- ECHO is more robust on SLOW_POISON, COLLUSION_TIMING 0.1 and SYBIL_ADAPTIVE S=2.
- ECHO **loses detection** on NONE, LATENT, SUPPRESS and FORGED, and is equal on SLOW.
- Spec §7's rule for this case: "ECHO's extra terms are NOT-YET-JUSTIFIED; reduce ECHO". The
  config grid (§M.5) shows *which* extra term does the damage.

**Verdict.**
- ECHO is NOT-YET-JUSTIFIED (ADR-0068).
- Stage 7's value claim is not supported on this evidence.
- The best measured configuration for shipping is the boundary only, with exchange off.

## M.5 Does each component earn its existence?

### M.5.1 The gate's ablation (this session's run; identical to the integration session's)

Registered by `experiments --register` as PS-S7-20260926-H8-ablation-0001..0017. That run had no
hash seed and reproduced every row.

| flag | firing | delta | verdict |
|---|---|---|---|
| epistemic_distance | 6 | −0.273 true acceptance | HARMFUL |
| gravity | 287 | 0.000 | NOT_YET_JUSTIFIED [corrected: §R.3 — every one of the 287 came from a double-counted term; firing is 0 without it: INERT] |
| dependence_clustering | 95 | −10.093 amplification | JUSTIFIED |
| cluster_cap | 14 | −9.927 amplification | JUSTIFIED [corrected: §R.5 — the cap cannot bind; this measures max-over-members against sum-over-identities] |
| contextual_trust | **0** | 0.000 | INERT |
| falsification_weight | **0** | 0.000 | INERT |
| contest_mass | **0** | 0.000 | INERT |
| probation | 1 | 0.000 | NOT_YET_JUSTIFIED (measured on COLLUSION_TIMING only; see M.5.2) |
| local_validation | 10 | 0.000 poison on BYZANTINE_POISON 0.2 | NOT_YET_JUSTIFIED. The row is uninformative because ECHO accepts nothing on that arm anyway. Measured on the identity aggregators instead (§M.2, §M.3), local validation is the whole detection effect: MEDIAN → MEDIAN+LV moves the share-0 FP from 11/60 to 0 and the BYZANTINE_POISON break from 0.1 to none, so it is **JUSTIFIED** |
| epistemic_distance_auc (F6) | 214 | AUC 0.430 against role equality's 0.418 | NOT_YET_JUSTIFIED (corpus 7; 0.823 on corpus 11, §M.5.2) |
| antibody_minimisation | 31 | 0.000 | NOT_YET_JUSTIFIED |
| reconstruction | 18 | +0.900 recall | JUSTIFIED [corrected: §R.7 — against a hard-coded 0.0 control, not count_threshold_join] |
| collective_novelty | 64 | −1.000 | JUSTIFIED [corrected: §R.5 — a corpus-free toy; fabric-path firing 0: INERT] |
| hypergraph | 18 | 0.000 | NOT_YET_JUSTIFIED |
| falsifier | 22 | −1.000 false campaign rate | JUSTIFIED |
| secure_aggregation | 1 | +8.000 count inflation | HARMFUL |
| differential_privacy | 58 | −0.610 | JUSTIFIED [corrected: §R.5 — toy, fabric firing 0: INERT; and a utility trade-off, not a win] |

### M.5.2 Every ECHO flag across every arm (new this session)

The gate ablates each flag on **one** arm only. This session tested the flags across all arms.

`config_grid.py` replays identical recorded traffic under four configurations, across all 55
(arm, share) cases:

| configuration | flags on |
|---|---|
| `full` | the shipped `EchoConfig()` |
| `no_distance` | shipped, with epistemic distance off |
| `req+probation` | clustering, cap, local validation and probation only |
| `required` | clustering, cap and local validation only |

`echo_refusals.py` replays seven cases with one flag switched off at a time.

**Epistemic distance is HARMFUL everywhere it was measured.**
- Switching it off gives detection at least as high and poison acceptance no higher than the
  shipped ECHO, in **55 of 55 cases on corpus 7 and 55 of 55 on corpus 11**. Recall is strictly
  higher in 39 cases on each corpus.
- Examples:

  | case | shipped ECHO | distance off |
  |---|---|---|
  | NONE, corpus 7 (recall) | 0.571 | 0.786 |
  | NONE, corpus 11 (recall) | 0.250 | 0.667 |
  | LATENT_POISON 0.2, corpus 7 (recall; poison 0 for both) | 0.571 | 0.786 |
  | SYBIL_ADAPTIVE S=4 (amplification; same break point) | 8.212 | 6.174 |

- Every foreign true key that MEDIAN+LV accepts and ECHO does not ends `INSUFFICIENT` with the
  reason `below_mass_floor` (`echo_refusals.py`). That is 3 keys at share 0 and 9 keys (all of
  them) at BYZANTINE_POISON 0.1.
  - Switching distance off recovers all 3 at share 0.
  - It recovers only 1 of the 9 under BYZANTINE_POISON (true acceptance 0.091). That collapse
    comes from the dependence graph together with probation (below), not from distance.
- As a **predictor**, D_E is unstable across seeds. Falsifier F6 is the AUC of −D_E predicting
  local usefulness:
  - corpus 7: **0.430**, against 0.418 for role equality, so F6 fires;
  - corpus 11: **0.823**, against 0.580 for role equality.

  The weight hurts detection on both seeds.

**Probation: the gate's single-arm verdict is wrong. It is a trade-off.**
- It is the only mechanism that stops latent poison. On BYZANTINE_LATENT_POISON 0.1–0.6, poison
  acceptance is 1.000 without it and **0.000** with it. This holds in the shipped config and
  with every other optional term off.
- The horizon check gives the same result at 12, 24 and 36 rounds. Without probation the poison
  is accepted in round 0; with it, never. The effect is not a delay past the end of the run.
- It costs 1 of 11 true keys at share 0 (true acceptance 0.636 → 0.545).
- It also drives the accept-nothing collapse under BYZANTINE_POISON. Recall is 0.786 for
  `required` against 0.214 for `req+probation` on corpus 7, and 0.833 against 0.083 on
  corpus 11.
- The gate's ablation should include the LATENT_POISON arm.

**Contextual trust and contest mass are INERT on acceptance.**
- In `echo_refusals.py`, switching either off changed neither true nor poison acceptance in any
  of the 7 cases.
- Contextual trust moved amplification only, in 3 cases.
- Falsification weight is INERT in the gate, because the adversaries report perfect survival.
- **All three should be removed.**

**Dependence clustering is justified for Sybil resistance but harmful to detection under
poison.** The clean control is ROOT_QUORUM with the graph's clusters against ROOT_QUORUM with
declared roots.
- With the graph, ROOT_QUORUM blocks forged-root Sybils (S ≥ 2) and latent poison, and reduces
  slow poison.
- With the graph, BYZANTINE_POISON becomes accept-nothing: ROOT_QUORUM's recall falls from 11/14
  to 0/14, and from 73/81 to 7/81 with 24 receivers.
- The cause is the graph merging honest peers once adversaries appear. It already merges 24.5 %
  of honest cross-root pairs at share 0 (G7.5(b)), and BIRTH_CO_TIMING merges rise under attack.
- This false-merge rate is the single most consequential defect measured here.

**Gravity is NOT_YET_JUSTIFIED.** [corrected: §R.3 — INERT once its double-counted dependence
term is removed.] It triaged 287 capsules on corpus 7 and 296 on corpus 11, and
lost 0 true keys on both. Because the bound is 0, the result cannot be told apart from
"validate everything".

**Threshold sensitivity (gate).** Share of ECHO decisions that flip when a threshold is halved
or doubled:

| threshold | ×0.5 | ×2 |
|---|---|---|
| MASS_FLOOR | 0.167 | 0.333 |
| TRUST_PRIOR | 0.333 | 0.167 |
| VALIDATION_FLOOR (triage) | 0.113 | 0.128 |
| CLUSTER_CAP, CONTEST_RATIO, RELEVANCE_FLOOR, ECHO_PROBATION_ROUNDS | 0 | 0 |

[corrected: §R.5 — the metric compared only final statuses and could not see probation. With the
first-ELIGIBLE round compared too: ECHO_PROBATION_ROUNDS 0.444 / 0.333, CONTEST_RATIO 0.0 /
0.167, MASS_FLOOR 0.389 / 0.333, TRUST_PRIOR 0.333 / 0.389; CLUSTER_CAP and RELEVANCE_FLOOR stay
0 / 0.]

- The last four are inert on the swept arms. No threshold flips every decision.
- Halving MASS_FLOOR raises share-0 true acceptance from 0.545 to 0.818 and still holds
  LATENT_POISON 0.2 at 0 poison. It lets SLOW_POISON 0.2 through at 0.250.

## M.6 Local sovereignty (the lead's whole-fleet test)

G7.1(c) in this session's gate put 64 independent-root peers against each of 4 receivers (256
peers), all agreeing against the local host.

| attempt | result |
|---|---|
| (i) revoke a local-origin antibody | refused `local_sovereignty` 1024/1024; the antibody stays live |
| (ii) SUPPORT a rule that fires on local benign traffic | CHALLENGED at 4/4 receivers; never ELIGIBLE, never bridged |
| (iii) CONTEST a locally confirmed antibody | refused at ingress 1024/1024; local state intact at 4/4 |
| (iv) authority-keyed payloads | refused at SCHEMA 1024/1024 |
| (v) Stage 6 buckets of anything bridged in the unanimous arms | nothing was bridged |

**Offline behaviour (G7.3).** [corrected: §R.5 — this digest could not see a fabric that damaged
the validator; it now digests the fabric-reachable local state too, and is still identical at
4/4.] The local-output digest is identical at 4/4 receivers in five
conditions:
- the fabric absent;
- offline under a flood;
- crashing every round;
- disabled;
- with a corrupt keyring, which moves the fabric to DISABLED.

**Static checks.** The AST boundary rules (G7.1(a), G7.2) report 0 offenders, and
`tests/test_stage7_boundary.py` passed in this session (§M.9).

These are construction and test properties of the code as it stands. They make no claim about
a real network.

## M.7 Privacy: what leaves the host, by field, and what it leaks

**What leaves.** The wire format is exactly `privacy/distiller.py:EXPORT_FIELD_TABLE`: 38 key
paths. G7.7(b) checked that the emitted fields equal this table for all 5 knowledge types. By
class:

| class | fields |
|---|---|
| PROTOCOL | `schema_id`, `schema_version`, `capsule_id`, `knowledge_type`, `stance`, `key_id`, `signature` (an HMAC: proves key possession, **not host identity**, ADR-0064), `sequence` (**reveals this host's export volume**), `created_round`, `expiry_round`, `parent_capsules`, `privacy_class`, `revocation_ground`, `revocation_target`, `attack_mappings` (always empty), `provenance_commitment.aggregation_decision` |
| SEMANTIC_CLASS | `semantic_invariant` (relation id and property bitmasks only; no path, name, address, uid, pid, time or count), `compact_feature_signature`, `causal_motif` |
| PSEUDONYM | `provenance_commitment.contributor` (HMAC(host_secret, scope); by design it **links every capsule one host sends in one scope**), `provenance_commitment.provenance_root`, `independence_group` |
| COMMITMENT | `provenance_commitment.evidence_commitments` (keyed HMACs of evidence digests) |
| COARSE_CONTEXT | `source_context_sketch.role`, `source_context_sketch.family_profile` (a 4-level share per relation family), `epoch_context.software_epoch` (an **unkeyed** hash of kernel id + package digest, so it can be inverted by dictionary for a known set of images), `epoch_context.visibility`, `time_window` (rounds), `observability.*` |
| SELF_REPORTED_COUNT | `validation_summary.*`, `falsification_summary.*` |

Raw telemetry, paths, user names, addresses and evidence digests do not leave. G7.7(a) searched
2553 distinct exported blobs for 3177 raw strings, canaries and Stage 1 digests and found
**0 hits**.

**Measured leakage (gate G7.7, 200 trials each).**
- **Membership inference:** distilled advantage **0.000**, against 1.000 for the raw-steps
  control.
- **Property inference:** distilled advantage **0.163**, against 0.198 for raw steps (chance
  0.667). The distilled representation leaks the property almost as much as raw steps do.
  [corrected: §R.5 — resampling noise over 22 and 24 hosts with one chance for both rows.
  Exhaustive: distilled 20/22 = 0.909 (chance 0.727), raw 21/24 = 0.875 (chance 0.667).]
- **DP on population counts:**

  | ε | novelty recall | count-membership advantage |
  |---|---|---|
  | 0.1 | 0.000 | 0.105 |
  | 0.5 | 0.000 | 0.175 |
  | 1.0 | 0.141 | 0.435 |
  | 2.0 | 0.641 | 0.755 |
  | exact counts (no noise) | 1.000 | 1.000 |

  - No ε gives both useful recall and low advantage.
  - The RNG is seeded, so the curve is **not private**. It measures the utility/advantage
    trade-off and gives no guarantee.

**The coarse context is a quasi-identifier (new this session).** `linkability.py` runs over the
capsules the simulated hosts actually export. Ignoring the pseudonym, it counts how many hosts
share each (role, family_profile) pair:

| corpus | exporting hosts | capsules | distinct (role, family_profile) | hosts singled out (anonymity set of 1) | distinct software_epoch |
|---|---|---|---|---|---|
| 7 | 22 | 31 | 15 | **10 / 22** | 4 over 24 hosts (the generator gives one image per role) |
| 11 | 22 | 36 | 13 | **8 / 22** | 4 |

- The exported coarse context alone singles out 36–45 % of exporting hosts in a 24-host fleet.
- The generator has only 4 software images. A real fleet with more images would make
  `software_epoch` a stronger identifier, not a weaker one. That follows from the field's
  definition; it was not measured.
- **"Nothing host-identifying leaves the host" is therefore not supported** for the
  coarse-context fields on this corpus.
- Differential privacy covers only count releases. No k-anonymity is applied to the sketch.

## M.8 Resource cost and bounds

| figure | value | loadavg | note |
|---|---|---|---|
| Gate G7.10: incremental RSS (sampled peak − start, floored at 0), FLOOD at 1000 identities plus scale to 10 000 peers | **44 421 120 B** | 4.19 11.15 12.26 | Within the 120 MiB ceiling and under the 55 MiB normal target. **Includes the simulator's own objects**, so it over-counts Stage 7 |
| Gate process maximum RSS (`/usr/bin/time -v`) | 290 992 kB | 7.10 → 19.69 | Whole gate process; not an endpoint figure |
| `resources.py`: the same flood, then scale to 10k / 30k / **100k** offered peers | peak sampled RSS 405 090 304 B; incremental **355 151 872 B**; within ceiling **False**; edge profile "agent_rss 386.3 MB > 100 MB target" | 14.85 15.23 14.55 | Mostly the harness; see the attribution below |
| Peer table under 10k / 30k / 100k offered peers | held at **1024**; refused 8976 / 28976 / 96928 | same | Bounded |
| Receiver store bytes (`fabric.memory_bytes()`), 10k / 30k offered, **production keyring** (`MAX_KEYS` 1024) | 3 175 663 B / 3 339 772 B | 16.11 / 14.56 | Flat: bounded |
| The same with the **lab** keyring (`capacity = n + 64`, as `run_scale` builds it) | 10 338 832 B / 22 582 541 B (keyring 5.4 MB → 17.1 MB) | 16.08 / 9.40 | Grows with n because of how the lab is built |
| RSS of the simulated *senders* alone (10k / 30k `_Peer` objects) | +18 800 640 B / +36 671 488 B | — | Simulator, not receiver |
| CPU per delivered capsule, full fabric (ingress, graph, ECHO, bridge and lab Stage 6, **plus simulating and signing the senders' traffic**) | 3.14 ms (503 deliveries, 1.579 s CPU) | 14.85 | An upper bound on receiver cost |
| Within-run ratio: full-fabric CPU / MEDIAN+LV CPU on the same pools | **≈ 302×** | 14.85 | MEDIAN+LV includes its cached local validation. Only this ratio transfers |
| Message flood (56 042 deliveries from 1000 identities in 4 rounds) | Governor refused 44 590 (round bytes), 3516 (per-peer bytes), 4000 (oversize); no store over cap; keyring at cap (1024 offered = 1024) | 4.19 | The message flood hits the governor, not the stores |
| Churn: lineage peak (cap 16 384) at 720 / 2160 / 4320 / 18 000 rounds | 1243 / 2683 / 4843 / **16 384** (2139 evictions at 18 000) | 16.4 / 16.1 / 14.3 / 5.4 | Grows about 0.9 nodes per round with **no plateau before the cap**. At the cap it evicts the oldest leaves: bounded, but never settles |
| Keyring refusals under churn (same four run lengths) | 727 / 4140 / 9262 / 41 814 | same | Bounded by refusal [corrected: §R.4 — a full keyring that never reclaimed dead keys; the receiver had stopped admitting anyone. After the fix: 0 refusals in the gate's 720-round churn] |

**Where the 355 MB comes from.** It is mostly the harness, not Stage 7:
- The scale run builds 100 000 simulated senders in the same process.
- `run_scale` deliberately gives the lab keyring `n + 64` slots.
- Per-store accounting shows the receiver itself stays at about 3.2–3.3 MB with the production
  keyring.

RSS cannot separate the two inside one process, so the 355 MB is a **harness** figure. Stage 7's
own endpoint RSS at 100k offered peers is **UNMEASURED**; measuring it needs a receiver-only
process fed from outside. Note also that `memory_bytes()` is a `sys.getsizeof` estimate, not RSS.

**Bounds, summarised.**
- Every store stayed at or under its cap during the flood.
- The peer table and graph held at 1024 against 100 000 offered peers.
- The keyring refuses keys past 1024. [corrected: §R.4 — it now reclaims dead (revoked or expired-rotated) records first; only 1024 LIVE keys fill it.]
- The lineage DAG is bounded by eviction at 16 384 and does not plateau below that.
- A flood of peers hits the peer-table and keyring bounds, and a flood of messages hits the
  governor. Neither came near the 2 GB envelope in-process.

**Harness trap: the lab flood cannot exceed about 1100 identities.**
- `simulated_receiver` provisions keys in directory order.
- The receiver's *own* key sits at position 915 of 1024 with 1000 identities, 1003 of 1124 with
  1100, and 1808 of 2024 with 2000.
- At 2000 identities the ring is full before the receiver's own key is reached. Building the
  receiver then raises `only an ACTIVE registered key can sign`.
- The gate's 1000 identities offer exactly 1024 keys, so the gate's flood never overflows the
  keyring.

This is a lab ordering artefact. The design question it raises, whether the keyring should
reserve a slot for its own key, is for the integrator.

## M.9 Tests and registration

- **Tests.** `python -m pytest tests/test_stage7_*.py -p no:cacheprovider --junitxml=…` ran
  **373 tests: 0 failures, 0 errors, 0 skipped** (154.17 s, load 16.14 → 18.87). This session
  did not run the full repository suite.
- **Registration.** `python -m pocketsec.stage7.cli experiments --register` ran 16:53:20–17:00:38
  AEST at loadavg 0.60 → 2.00.
  - It re-ran the gate without a hash seed. Result: FAILED (5); the same five criteria; 6/11.
  - It registered PS-S7-20260926-BASE-orpheus-gate-0001 and 17 ablation rows,
    PS-S7-20260926-H8-ablation-0001..0017.
  - The ledger integrity check (`ExperimentRegistry.verify_integrity`) reports no problems
    after all 28 Stage 7 rows (93 lines).
- **Contention, measured.** The same gate took 18:12.66 wall and 910.08 s user CPU at load
  7.10 → 19.69, but 7:17.64 wall and 437.33 s user CPU at load 0.60 → 2.00. That is a 2.5×
  wall and 2.1× CPU inflation on this host, for identical work. It is why no absolute timing
  in this document transfers. Maximum RSS was 290 992 kB and 291 000 kB respectively.
- **Correction.** PS-S7-20260926-H8-echo-refusals-0010's `median_lv_true_accepted` field
  counted the receiver's own local keys (14 against 11 offered). -v2-0011 re-ran the script with
  that count fixed (9/11); every other figure is identical. Both rows stay in the ledger.

## M.10 What would change this conclusion

- **A non-synthetic multi-host corpus.** The conclusion would change on a corpus where the
  baselines without local validation do not blow the FP budget, and where ECHO (or ECHO without
  distance) keeps a detection gain of at least 0.10 under Byzantine poison. Today every corpus
  is synthetic and P5 is DEGENERATE_IN_FAVOUR.
- **Fixing the dependence graph's false merges.**
  - At 24.5 % honest cross-root merges, the graph drives the BYZANTINE_POISON collapse of both
    ECHO and ROOT_QUORUM.
  - With the graph fixed, that detection loss might disappear. That would flip the "beat
    no-sharing at 0.2" clause.
  - It would have to be re-measured.
- **An identity authority that binds provenance roots.** That would close SYBIL_ADAPTIVE, which
  today breaks every variant at S = 4.
- **The lead revising Stage 6's foreign prior (B7-1).**
  - Realised detection would become measurable.
  - Today's measured poison stream on COLLUSION_TIMING and SYBIL_ADAPTIVE would then reach
    Stage 6 as candidates (§M.3).
- **An adversary not written by the defender.**
  - Every robustness win here is against attacks written by the same author as the defence
    (lesson 6).
  - Latent poison stopped by probation is the clearest case. An adversary who knows the hold
    length could plausibly time around it. That is UNMEASURED.
- **A third corpus seed disagreeing.**
  - The two corpus seeds agree on every ordering reported here.
  - The F6 AUC does *not* agree across them (0.430 against 0.823), so a third seed could move
    the distance-as-predictor question either way.
  - The distance-as-weight harm held on both seeds.

## M.11 Defects and traps this session found

These are for the integrator. This session edited nothing in `pocketsec/`.

1. The gate's ablation tests probation on one arm only (COLLUSION_TIMING, where every
   configuration accepts the poison) and calls it NOT_YET_JUSTIFIED. On LATENT_POISON it is the
   only defence.
2. The suite's `ROOT_QUORUM` uses the dependence graph's clusters, so it is not a declared-roots
   control. The declared-root control (`ROOT_QUORUM_DECLARED` in `fraction_sweep.py`) is what
   isolates the graph.
3. The plain identity aggregators score 0.000 because of non-IID false positives, not because
   of poison. A reader of the break-point table alone would miss that.
4. The lab flood breaks its own receiver above about 1100 identities (§M.8).
5. `run_benchmark`'s edge-profile check reads the whole simulating process. For a fleet
   simulation it says nothing about the endpoint.
6. The coarse context singles out 36–45 % of hosts (§M.7). That contradicts "nothing
   host-identifying leaves" for those fields.
7. The COLLUSION_TIMING break is not monotone in share (§M.3).

---

## Appendix A — the integration session's report (preserved verbatim; headings demoted)

This is `docs/stage-7-findings.md` as the integration session left it (written 15:32 AEST, 2026-09-26). Only its headings were demoted so this document has one honesty ledger. Every deciding figure in §A.1–§A.3 was reproduced by this session's gate run (§M.1). Where this session's measurements supersede a statement below, the RETRACTED table at the end says so; the text itself is not edited.

**Original title:** Stage 7 — ORPHEUS + HIVELOCK — findings (D7.20)

- **Date:** 2026-09-26
- **Status:** PARTIAL. `pocketsec-stage7 gate` FAILS 5 of 11 (G7.4, G7.5, G7.8, G7.10, G7.11).
  Spec §6.1 predicted three of those failures (G7.4 adaptive arm, G7.8, G7.11). G7.5 and G7.10
  fail on figures nobody predicted, and both are findings.
- **Source of every number:** `PYTHONHASHSEED=0 python -m pocketsec.stage7.cli gate`, run
  2026-09-26 14:23:30–14:45:15 AEST. The load average was 5.26 at the start and 9.52 at the end,
  and 8.82/15.47/14.33 during the suite.
- **Reproduced:** `python -m pocketsec.stage7.cli gate` (no hash seed) reproduced every figure,
  15:16:52–15:32:21 AEST at load 23.57 start / 11.05 end. Only three things differed:
  - incremental RSS, 44 511 232 B;
  - wall times;
  - the registry clause. In the first run a concurrent Stage 6 registration broke that clause
    (the ledger was written at 14:24:20, inside the run). In the reproduction it read True.
- **Timing figures:** wall clock is an observation beside the load average, never a device
  figure.

**Not a detection result.** The fleet is simulated in-process and the corpus is synthetic. Stage
6 admits no foreign capsule, so every detection gain below is `counterfactual_at_boundary`. The
adversaries, the defences and the ground truth share one author (lesson 6).

### A.1 What the gate settled

| id | result | the figure that decided it |
|---|---|---|
| G7.1 | PASS | 0 boundary offenders (rules 5, 6, 7, 10, 11). Over 60 suite runs the bridges built 2254 `ExperienceCapsuleV1`, handed 2254 to `admit`, and the lab gateways were offered 2254. With 64 unanimous independent-root peers against each of 4 receivers: revocations refused `local_sovereignty` 1024/1024; locally-FP support ended CHALLENGED at 4/4 receivers; contests refused 1024/1024; authority payloads refused at SCHEMA 1024/1024 |
| G7.2 | PASS | 0 offenders (rules 3, 8, 9). The wire-key fuzz made 372/372 injections and every one was refused. Unmodified controls round-trip 5/5. AUTHORITY_INJECTION pooled 0 of 384 |
| G7.3 | PASS | The local-output digest is identical across absent, OFFLINE+flood, crashing, DISABLED and corrupt-keyring at 4/4 receivers. The injected faults fired (4 crash failures each; 487–490 offline drops each) |
| G7.4 | **FAIL** | ECHO amplification was 0.000 at every S on DECLARED_ROOT and FORGED_ROOTS. On SYBIL_ADAPTIVE it was 4.590–12.467 against a 2.0 bound. MAJORITY/MEDIAN/MEAN reached 6.909 at S ≥ 32 on DECLARED/FORGED and 16.136 on ADAPTIVE at S = 128 |
| G7.5 | **FAIL** | (b) The dependence graph merged honest peers of different true roots in **216/881 = 24.5%** of pairs (bound 5%). (a) Rare-role eligibility was 1/1 against 5/8 for the majority role. The rare side holds one object, so it is too small to mean anything. (c) 0/12 violations |
| G7.6 | PASS | 69 SUPPORTED worlds, every one with 6 evaluated tests. False campaign rate 0.000 against `count_threshold_join` 1.000. True recall was 1.0 on TRUE_CAMPAIGN_2/4/10. H0–H4 each explained 8–10 benign worlds |
| G7.7 | PASS | 0 canary/digest hits over 2553 distinct exported blobs × 3177 needles. Field table exact for all 5 types. Membership: distilled advantage 0.000 against a raw control of 1.000. Property: distilled 0.163 against a raw control of 0.198 (chance 0.667). DP curve has 4 ε points |
| G7.8 | **FAIL** | Lineage clauses hold: 3648/3648 ELIGIBLE decisions ancestry-complete, and 2254/2254 bridged capsules have a Stage 6 node with a VERDICT child. But **0 TRUSTED_CANDIDATE**: all 2254 went UNCERTAIN, so "promoted" holds over zero objects (B7-1) |
| G7.9 | PASS | A real signed SELF_RETRACTION on a suite lineage marked exactly the target and its 15 descendants and changed 0 non-descendants. It moved exactly the key beneath to SUSPECT, named 6/6 Stage 6 capsule ids, and reinstate restored the digest byte for byte. FALSE_REVOCATION: 80 judged, 0 accepted |
| G7.10 | **FAIL** | Incremental RSS was 44 470 272 B, within the 120 MiB ceiling and under the 55 MiB normal target. The edge profile's `model_bytes` is UNMEASURED: Stage 7 ships no model, and the Stage 5 precedent is not to write 0. **The churn plateau failed** (§3). The scale run at 10 000 peers refused 8976 and held the table at 1024 |
| G7.11 | **FAIL** | Fails by construction (`synthetic is True`). The §7 comparisons are in §2 |

### A.2 Against the baselines (spec §7)

- **NO_SHARING.** The gain at share 0 is **0.571** (recall 0.0 → 0.571; FP 0.000 against 0.000).
  At **BYZANTINE_POISON share 0.2 the gain is 0.000**. The corpus is DEGENERATE_IN_FAVOUR (P5).
- **ECHO becomes accept-nothing under a small adversary.** Rerun outside the gate, same seed:
  under BYZANTINE_POISON at share 0.1, ECHO accepted 0/11 true keys (6/11 at share 0). Every
  non-refused true key ended INSUFFICIENT with reason `below_mass_floor`. BIRTH_CO_TIMING merges
  rose from 3 to 10. The adversary's identities are born alongside honest ones, the dependence
  graph merges honest clusters, and support mass falls below `MASS_FLOOR`. This is the same
  mechanism as G7.5(b). **The Sybil defence is a denial-of-service lever.**
- **MEDIAN / TRIMMED_MEAN.** ECHO's break point is at or above both on every arm (none in sweep
  on 6 arms; 0.143 on SYBIL_ADAPTIVE; 0.2 on COLLUSION_TIMING; MEDIAN 0.040). But at share 0,
  ECHO accepted **0.545 of true antibodies against MEDIAN's 1.000**, which fails the "not
  accept-nothing" row.
- **VALIDATION_FILTER.** Mean poison acceptance was 0.000 against 1.000 on LATENT_POISON and
  SLOW_POISON, where local validation is blind by construction. Aggregation does add something
  over local replay on these arms.
- **ROOT_QUORUM + LV.** ECHO is lower by more than 0.05 on SYBIL_ADAPTIVE (0.75 against 0.88),
  SLOW_POISON (0.00 against 0.25) and COLLUSION_TIMING (0.33 against 0.50). **But it loses
  detection: 0.571 against 0.786.** Under the §7 rule ("without losing detection") ECHO's extra
  terms are NOT-YET-JUSTIFIED against ROOT_QUORUM+LV.
- **CENTRAL_FEED.** Time-to-detect was 2.833 rounds for ECHO against 4.429 for the feed (arm
  NONE).
- **FedProx / personalised FL:** UNMEASURED (no parameters exist).

### A.3 Mechanisms: ablation verdicts (lesson 1: 0 firing = INERT)

| flag | verdict | firing | delta |
|---|---|---|---|
| epistemic_distance | **HARMFUL** | 6 | −0.273 true acceptance |
| gravity | NOT_YET_JUSTIFIED | 287 | 0.000 |
| dependence_clustering | JUSTIFIED | 95 | −10.093 amplification |
| cluster_cap | JUSTIFIED | 14 | −9.927 amplification |
| contextual_trust | **INERT** | 0 | 0.000 |
| falsification_weight | **INERT** | 0 | 0.000 (expected: adversaries report perfect survival) |
| contest_mass | **INERT** | 0 | 0.000 |
| probation | NOT_YET_JUSTIFIED | 1 | 0.000 |
| antibody_minimisation | NOT_YET_JUSTIFIED | 31 | 0.000 |
| reconstruction | JUSTIFIED | 18 | +0.900 recall |
| collective_novelty | JUSTIFIED | 64 | −1.000 |
| hypergraph | NOT_YET_JUSTIFIED | 18 | 0.000 |
| falsifier | JUSTIFIED | 22 | −1.000 false campaign rate |
| secure_aggregation | **HARMFUL** | 1 | +8.000 count inflation under Sybils |
| differential_privacy | JUSTIFIED | 58 | −0.610 |

**Threshold sensitivity.** Share of ECHO decisions that flip at ×0.5 and at ×2: MASS_FLOOR
0.167/0.333, TRUST_PRIOR 0.333/0.167, VALIDATION_FLOOR (triage) 0.113/0.128. **Inert on the
swept arms** (0/0): CLUSTER_CAP, CONTEST_RATIO, RELEVANCE_FLOOR, ECHO_PROBATION_ROUNDS. No
parameter flipped every decision.

**Churn (G7.10).** Over 720 rounds and 1727 peers every store stayed at or under its cap, and the
keyring refused 727. But the cross-host lineage DAG was still growing: its peak rose from 1003 in
the middle third to 1243 in the last third, against a cap of 16384. It is the only store the
gate names. The spec's plateau test (peak of the last third ≤ peak of the middle third) therefore
fails. Lineage is bounded by its cap but not settled at month scale.

### A.4 Residuals and deviations the integrator records

- **B7-1 (ADR-0067):** Stage 6 put all 2254 bridged capsules in
  UNCERTAIN. The value path to trusted state is closed. That is the lead's decision, not Stage 7's.
- **B7-2:** Stage 6 exposes no revocation input. Stage 7 computes the targeted Stage 6 capsule
  set (6/6 in G7.9) and cannot act on it.
- **Self-retraction suspects the whole key** (sovereignty package, pinned by a test). A per-key
  suspect mark lets one contributor move an ELIGIBLE key that other clusters support.
- **Spec claim refuted (campaign package):** D7.15 says suppression "can at most delay" a
  campaign. The gate measured 4 SUPPRESSION cases never detected, and a mean delay of 10.25
  rounds for the rest.
- **Integrator seam fixes:**
  - The fabric now refuses ECHO `local_validation=False` unless a lab declares `lab_ablation`.
  - The boundary predicates live in `pocketsec/stage7/gate_boundary.py`, shared by the gate
    and the test. Rule 6 compares SHA-256 digests, because Stage 6's repository-wide test
    forbids spelling its writer names under `pocketsec/`.
  - The harness may import `stage2.gate_criteria.imported_modules`, the one resolver.
  - The strict JSON readers moved to `capsule/wire_json.py`.

### A.5 The integration session's honesty ledger (preserved; its rows are carried into the consolidated ledger at the end)

#### (integration session) MEASURED
| claim | value | how it was produced (module:function) | experiment id | synthetic? |
|---|---|---|---|---|
| M0.1–M0.4 of the spec | see `docs/stage-7-spec.md` §0 | spec-time probes | — | yes |
| bridged capsules = admitted = gateway offered | 2254 = 2254 = 2254 | `gate_evidence:observe_run` | PS-S7-20260926-BASE-orpheus-gate-0001 (not registered) | yes |
| unanimous-fleet refusals | 1024/1024 revoke, 1024/1024 contest, 1024/1024 authority, 4/4 CHALLENGED | `gate_evidence:unanimous_evidence` | same | yes |
| ECHO amplification, SYBIL_ADAPTIVE | 4.590–12.467 | `labs.byzantine_suite:run_byzantine_suite` | same | yes |
| honest false-Sybil merge rate | 216/881 = 0.245 | `gate_evidence:non_iid_evidence` | same | yes |
| detection gain over NO_SHARING | 0.571 at share 0; 0.000 at BYZANTINE_POISON 0.2 | `labs.byzantine_suite:evaluate_run` | same | yes (counterfactual_at_boundary) |
| membership advantage, distilled vs raw | 0.000 vs 1.000 (200 trials) | `labs.privacy_attacks:membership_inference` | same | yes |
| incremental RSS, flood + 10k scale | 44 470 272 B (loadavg 7.27); 44 511 232 B (loadavg 14.13) | `governor.communication:measure_stage7_resources` | same | yes (dev host) |
| Stage 6 TRUSTED_CANDIDATE of bridged | 0/2254 | `hivelock.stage6_bridge:Stage6Bridge.receipts` | same | yes |

#### (integration session) UNMEASURED
| claim the architecture makes | why not measured | what would measure it | blocking? |
|---|---|---|---|
| real network latency, partitions, Sybil populations | no network, fleet simulated | a real fleet | yes for deployment |
| Stage 6-side revocation rollback | Stage 6 has no revocation input (B7-2) | a Stage 6 revocation API | no |
| promoted foreign knowledge with lineage | Stage 6 admits none (B7-1) | revising Stage 6's foreign prior | yes (G7.8) |
| edge-profile model bytes | Stage 7 ships no model | n/a | G7.10 reports it |
| DP guarantee beyond count releases; timing side channels | not built / not measured | a formal analysis | no |
| Ed25519, mTLS, zstd, FedProx | stdlib-only (ADR-0001) | third-party libraries | no |
| a real 2 GB device | dev host only | device run | no |

#### (integration session) REJECTED
| component | measured effect | verdict (REJECTED / NOT-YET-JUSTIFIED / RETRACTED / INERT / DEGENERATE / HARMFUL) | ADR |
|---|---|---|---|
| epistemic distance | −0.273 true acceptance against role equality | HARMFUL | 0069 |
| secure aggregation | +8.000 count inflation under Sybils | HARMFUL | 0066 |
| contextual trust, falsification weight, contest mass | firing 0 | INERT | 0069 |
| ECHO's extra terms against ROOT_QUORUM+LV | detection 0.571 against 0.786 | NOT-YET-JUSTIFIED | 0068 |
| gravity, probation, antibody minimisation, hypergraph | delta 0.000 | NOT-YET-JUSTIFIED | 0069 |

#### (integration session) RETRACTED
| retracted claim | where it was published | the defect | corrected value |
|---|---|---|---|
| "a suppression attack can at most delay a real campaign" | `docs/stage-7-spec.md` D7.15 | holds only for bounded suppression | 4 SUPPRESSION cases never detected |

#### (integration session) NOT A DETECTION RESULT
Every corpus is synthetic; the fleet is simulated in-process; every detection gain is a
counterfactual at the Stage 7→Stage 6 boundary, because Stage 6 admits no foreign capsule.

#### (integration session) PARAMETERS
Every constant in `docs/stage-7-spec.md` §4.23 is chosen, not measured. That includes the
thresholds swept above (MASS_FLOOR, CLUSTER_CAP, CONTEST_RATIO, RELEVANCE_FLOOR,
VALIDATION_FLOOR, TRUST_PRIOR, ECHO_PROBATION_ROUNDS) and the gate's own sizes (1000 flood peers,
64 unanimous peers, 4-round unanimous and flood runs). All of them are chosen, not measured.

---

## Appendix B — every command this session ran for a figure above, with its real output

Outputs are pasted verbatim. Where one is long, the excerpt is marked and the full payload is in
`results/<experiment id>.json`. Inline probe scripts are shown in abbreviated form; everything
they call is named. Two runs failed and are listed as failures:

- The first `resources.py` run at `--identities 5000` raised `ContractError: only an ACTIVE
  registered key can sign` (the own-key trap in §M.8).
- The first `fraction_sweep.py` smoke run raised a `TypeError` from
  `ThreatPredictionV1(evidence_relevance=None)`. Fixed to `()` in `_common.py` before any
  measurement.

### B.1 The gate
```
$ PYTHONHASHSEED=0 /usr/bin/time -v python -m pocketsec.stage7.cli --json gate > gate.json   (rendered)
start 15:35:05 load 7.10 12.95 12.87 4/1778 2724647
exit 1
end 15:53:17 load 19.69 17.45 14.63 17/1818 2817018
	User time (seconds): 910.08
	Elapsed (wall clock) time (h:mm:ss or m:ss): 18:12.66
	Maximum resident set size (kbytes): 290992
	Exit status: 1
[PASS] G7.1  No remote object can bypass Stage 6 quarantine
    (a) boundary offenders by rule {5: 0, 6: 0, 7: 0, 10: 0, 11: 0} ; constitution problems none. (b) 60 suite runs: bridges built 2254 ExperienceCapsuleV1, passed 2254 to admit, lab gateways were offered 2254; mismatched receivers none; Stage 6 buckets over the suite {'UNCERTAIN': 2254}. (c) 64 independent-root peers per receiver x 4 receivers: (i) revocations of the local-origin capsule refused local_sovereignty 1024/1024, accepted 0; (ii) SUPPORT for a locally-FP rule: 4/4 receivers ended CHALLENGED, never ELIGIBLE, never bridged; (iii) contests of the local antibody refused at ingress 1024/1024, local state intact at 4/4; (iv) authority-keyed payloads refused at SCHEMA 1024/1024; (v) bridged in the unanimous arm 0, Stage 6 buckets {} (reported; M0.2 predicts none TRUSTED_CANDIDATE)
[PASS] G7.2  No Stage 7 path can directly execute Stage 5 response
    boundary offenders by rule {3: 0, 8: 0, 9: 0}  (T2 no Stage 5 import, no execution/network primitive, T5 no authority-named dataclass field); wire-key fuzz: 12 words x every record of 5 knowledge types = 372 injections, 372 refused by from_dict, leaks none; unmodified controls round-tripped 5/5; AUTHORITY_INJECTION arm: 384 adversarial deliveries, 0 pooled
[PASS] G7.3  Local detection remains fully operational with network disabled
    4 receivers: local-output digest identical with the fabric absent, OFFLINE under a FLOOD, crashing every round, DISABLED and with a corrupt keyring at 4/4; corrupt keyring reached DISABLED at 4/4; faults fired (crash failures, offline drops) [('h005', 4, 490), ('h000', 4, 490), ('h002', 4, 487), ('h003', 4, 490)]; T7 offenders 0 . The partition is simulated: real network loss is UNMEASURED
[FAIL] G7.4  Sybil influence is bounded by provenance/dependence controls
    SYBIL_DECLARED_ROOT: ECHO amplification S=1:0.000 S=2:0.000 S=4:0.000 S=8:0.000 S=16:0.000 S=32:0.000 S=64:0.000 S=128:0.000; MAJORITY 0.000,1.143,2.142,3.804,6.217,6.909,6.909,6.909; MEDIAN 0.591,1.143,2.142,3.804,6.217,6.909,6.909,6.909; MEAN 0.000,1.143,2.142,3.804,6.217,6.909,6.909,6.909; break points {'ECHO': 'none in sweep', 'MAJORITY': '0.077', 'MEDIAN': '0.040', 'MEAN': '0.077'} | SYBIL_FORGED_ROOTS: ECHO amplification S=1:0.000 S=2:0.000 S=4:0.000 S=8:0.000 S=16:0.000 S=32:0.000 S=64:0.000 S=128:0.000; MAJORITY 0.000,1.143,2.142,3.804,6.217,6.909,6.909,6.909; MEDIAN 0.591,1.143,2.142,3.804,6.217,6.909,6.909,6.909; MEAN 0.000,1.143,2.142,3.804,6.217,6.909,6.909,6.909; break points {'ECHO': 'none in sweep', 'MAJORITY': '0.077', 'MEDIAN': '0.040', 'MEAN': '0.077'} | SYBIL_ADAPTIVE: ECHO amplification S=1:4.590 S=2:4.590 S=4:8.212 S=8:9.914 S=16:11.803 S=32:12.219 S=64:12.467 S=128:11.960; MAJORITY 2.142,4.503,7.068,10.011,12.550,14.429,15.615,16.136; MEDIAN 2.595,4.503,7.068,10.011,12.550,14.429,15.615,16.136; MEAN 2.142,4.503,7.068,10.011,12.550,14.429,15.615,16.136; break points {'ECHO': '0.143', 'MAJORITY': '0.077', 'MEDIAN': '0.040', 'MEAN': '0.077'}. DependenceGraph merges by kind {'BIRTH_CO_TIMING': 2609, 'COMMON_PARENT': 0, 'NEAR_IDENTICAL': 2450, 'SAME_ROOT': 2668} (Rule C: fired). Failures: ['SYBIL_ADAPTIVE S=1 amplification 4.590 (bound 2.0)', 'SYBIL_ADAPTIVE S=2 amplification 4.590 (bound 2.0)', 'SYBIL_ADAPTIVE S=4 amplification 8.212 (bound 2.0)', 'SYBIL_ADAPTIVE S=8 amplification 9.914 (bound 2.0)', 'SYBIL_ADAPTIVE S=16 amplification 11.803 (bound 2.0)', 'SYBIL_ADAPTIVE S=32 amplification 12.219 (bound 2.0)', 'SYBIL_ADAPTIVE S=64 amplification 12.467 (bound 2.0)', 'SYBIL_ADAPTIVE S=128 amplification 11.960 (bound 2.0)']. Spec §6.1 declared the adaptive arm unmeetable: declared roots are claims and binding them to real domains needs an identity authority stdlib cannot provide (ADR-0064)
[FAIL] G7.5  Non-IID legitimate hosts are not treated as malicious merely for difference
    (a) rare-role (ADMIN) honest antibodies ELIGIBLE at ADMIN receivers 1/1 = 1.000 vs majority-role at own-role receivers 5/8 = 0.625 (need rare >= majority - 0.05); (b) honest peers of different true roots merged into one dependence cluster 216/881 = 0.245 (bound 0.05); (c) rare-role (cluster, task) trust pairs below TRUST_PRIOR without a local refutation 0/12; rare-role key exclusion share by {'KRUM': 1.0, 'MULTI_KRUM': 0.0, 'BULYAN': 0.0} (reported). Real rare roles UNMEASURED
[PASS] G7.6  Distributed campaigns are validated against benign common-cause hypotheses
    80 cases over 10 arms: 69 SUPPORTED worlds, falsification problems none; false collective campaign rate 0.000 vs count_threshold_join 1.000 (bound 0.1); true-campaign recall {'TRUE_CAMPAIGN_2': 1.0, 'TRUE_CAMPAIGN_4': 1.0, 'TRUE_CAMPAIGN_10': 1.0}; benign-arm worlds explained by {'H0_COINCIDENCE': 8, 'H1_SHARED_UPDATE': 9, 'H2_ADMIN_AUTOMATION': 10, 'H3_TELEMETRY_ARTIFACT': 8, 'H4_COLLUDING_PEERS': 8} (INERT: none); suppression delay 10.250 rounds, SUPPRESSION cases never detected 4. Common causes are authored with the falsifier (confounded); real common-cause events UNMEASURED
[PASS] G7.7  Privacy leakage is measured, not assumed absent
    (a) canary scan over 2553 distinct exported blobs (every honest delivery of every suite run, the receivers' local capsules and the type samples) against 3177 raw strings and Stage 1 digests: 0 hits []; (b) 5 knowledge types: per-type wire paths == the table's paths for that payload (null observability excepted by expected_wire_paths) except none; union == EXPORT_FIELD_TABLE (38 rows) True; (c)(d) membership: distilled advantage 0.000, raw-steps control 1.000 over chance 0.000 (real, 200 trials); property: distilled advantage 0.163, raw-steps control 0.198 over chance 0.667 (real, 200 trials); (e) DP curve 4 epsilon points [(0.1, '0.000', '0.105'), (0.5, '0.000', '0.175'), (1.0, '0.141', '0.435'), (2.0, '0.641', '0.755'), (None, '1.000', '1.000')] (epsilon, novelty recall, count-membership advantage; seeded RNG, so NOT private); (f) SIEM oracle baseline: recall 0.750 at the cost of 1303 raw strings/digests exposed (a lower bound). Real attackers UNMEASURED
[FAIL] G7.8  All promoted foreign knowledge has cross-host and local lineage
    cross-host ancestry complete for 3648/3648 ELIGIBLE decisions; 2254/2254 bridged capsules have a local Stage 6 lineage node with a VERDICT child; Stage 6 put 0 bridged capsules in TRUSTED_CANDIDATE and the lab receiver promotes nothing, so foreign items promoted with lineage = 0. VACUOUS: the 'promoted' clause holds over zero objects — blocked on Stage 6 (B7-1, ADR-0067): every foreign capsule scores below MIN_PROVENANCE_SCORE
[PASS] G7.9  Revocation is targeted and reversible
    signed SELF_RETRACTION of kc-18f00c33a50d86d0ceb27d18 (15 descendants; submitted to the fabric's own RevocationPlane after the run (the ingress path is the FALSE_REVOCATION arm's)): accepted; exactly the target and its descendants SUSPECT True; non-descendants changed 0; ECHO keys newly SUSPECT ['mf-4c911542a7048a0b'] vs keys beneath ['mf-4c911542a7048a0b']; stage6_capsule_ids 6 = STAGE6_LINKs beneath 6 (True); reinstate restored the DAG digest byte-for-byte True. FALSE_REVOCATION arm: 80 judged, 0 accepted, 0 lineage nodes not LIVE. Stage 6-side rollback of the targeted capsules is UNMEASURED: Stage 6 exposes no revocation input (B7-2)
[FAIL] G7.10  Stage 7 remains inside the Stage 0 resource envelope
    FLOOD arm, 4 rounds, 56042 deliveries from 1000 simulated peers, then run_scale [(10, 0, 10, 65736, 272), (100, 0, 100, 453598, 2725), (1000, 0, 1000, 3373790, 22216), (10000, 8976, 1024, 10737538, 185162)] (peers, refused, table, bytes, work units): incremental RSS 44421120 B (sampled peak - start, floored 0; ceiling 125829120, normal target 57671680; within ceiling True); edge profile within_target None (exceeded [], UNMEASURED rows ['model_bytes']: Stage 7 ships no model and model_bytes=0 would claim a measurement of nothing — Stage 5 precedent); stores at cap ['keyring'] (keys offered 1024), pressure {'echo_keys': 0, 'graph': 0, 'keyring': 0, 'lineage': 0, 'novelty': 0, 'peers': 0, 'pool': 0, 'replay_keys': 0, 'replay_seen': 0, 'trust': 0}, governor refusals {'inbound:oversize': 4000, 'inbound:peer_bytes': 3516, 'inbound:round_bytes': 44590}; churn 720 rounds, 1727 peers seen, plateau_ok False; problems ["churn plateau failed: (store, middle-third peak, last-third peak) [('lineage', 1003, 1243)]"]. Wall 53.9s CPU 54.0s at loadavg (4.19, 11.15, 12.26) (observed, never asserted). In-process dev-host figure; a real 2 GB device is UNMEASURED
[FAIL] G7.11  ECHO/ORPHEUS survives ablation against simpler FL and threat-intel baselines
    preconditions P1=PASS, P2=PASS, P3=PASS, P4=PASS, P5=DEGENERATE_IN_FAVOUR; detection (counterfactual_at_boundary, DEGENERATE_IN_FAVOUR per P5): NONE@0.0: gain 0.571 (need >= 0.1), FP 0.000 vs NO_SHARING 0.000; BYZANTINE_POISON@0.2: gain 0.000 (need >= 0.1), FP 0.000 vs NO_SHARING 0.000 | break points (SYBIL_ADAPTIVE ECHO 0.14285714285714285; SYBIL_DECLARED_ROOT ECHO inf; SYBIL_FORGED_ROOTS ECHO inf; BYZANTINE_POISON ECHO inf; BYZANTINE_LATENT_POISON ECHO inf; BYZANTINE_SUPPRESS ECHO inf; SLOW_POISON ECHO inf; COLLUSION_TIMING ECHO 0.2), failures none | true acceptance at share 0 ECHO 0.545 vs MEDIAN 1.000; mean poison acceptance ECHO vs VALIDATION_FILTER {'BYZANTINE_LATENT_POISON': ('0.000', '1.000'), 'SLOW_POISON': ('0.000', '1.000')}; robustness failures ['share 0 true acceptance ECHO 0.545 < MEDIAN 1.000-0.05'] | ECHO vs ROOT_QUORUM+LV: arms where ECHO poison acceptance is lower by > 0.05 ['SYBIL_ADAPTIVE 0.75<0.88', 'SLOW_POISON 0.00<0.25', 'COLLUSION_TIMING 0.33<0.50']; detection ECHO 0.571 vs ROOT_QUORUM+LV 0.786 | ablation rows {'epistemic_distance': 'HARMFUL(firing 6, delta -0.273)', 'gravity': 'NOT_YET_JUSTIFIED(firing 287, delta 0.000)', 'dependence_clustering': 'JUSTIFIED(firing 95, delta -10.093)', 'cluster_cap': 'JUSTIFIED(firing 14, delta -9.927)', 'contextual_trust': 'INERT(firing 0, delta 0.000)', 'falsification_weight': 'INERT(firing 0, delta 0.000)', 'contest_mass': 'INERT(firing 0, delta 0.000)', 'probation': 'NOT_YET_JUSTIFIED(firing 1, delta 0.000)', 'antibody_minimisation': 'NOT_YET_JUSTIFIED(firing 31, delta 0.000)', 'reconstruction': 'JUSTIFIED(firing 18, delta 0.900)', 'collective_novelty': 'JUSTIFIED(firing 64, delta -1.000)', 'hypergraph': 'NOT_YET_JUSTIFIED(firing 18, delta 0.000)', 'falsifier': 'JUSTIFIED(firing 22, delta -1.000)', 'secure_aggregation': 'HARMFUL(firing 1, delta 8.000)', 'differential_privacy': 'JUSTIFIED(firing 58, delta -0.610)'}; missing none; delta None none; threshold sensitivity (flip share x0.5, x2) [('MASS_FLOOR', 0.167, 0.333), ('CLUSTER_CAP', 0.0, 0.0), ('CONTEST_RATIO', 0.0, 0.0), ('RELEVANCE_FLOOR', 0.0, 0.0), ('ECHO_PROBATION_ROUNDS', 0.0, 0.0), ('TRUST_PRIOR', 0.333, 0.167), ('VALIDATION_FLOOR (triage decisions)', 0.113, 0.128)]: silently decides every outcome none, inert ['CLUSTER_CAP', 'CONTEST_RATIO', 'RELEVANCE_FLOOR', 'ECHO_PROBATION_ROUNDS'] | catalogue problems none; experiments/registry.jsonl byte-identical True; findings headings missing none; HYPOTHESES == H0..H8 True | time-to-detect (rounds) ECHO 2.833 vs CENTRAL_FEED 4.429 | synthetic True: FAILS by construction on synthetic data (spec §6.1)
errors {}
timings (label, wall s, loadavg):
  resources               53.853 [4.19, 11.15, 12.26]
  churn                    9.851 [5.55, 11.21, 12.27]
  suite                   960.42 [19.09, 16.92, 14.27]
  unanimous               27.635 [18.85, 17.03, 14.38]
  authority                1.347 [19.19, 17.13, 14.43]
  samples                   0.01 [19.19, 17.13, 14.43]
  offline h005             2.132 [19.19, 17.13, 14.43]
  offline h000             2.328 [19.01, 17.12, 14.44]
  offline h002             1.935 [19.01, 17.12, 14.44]
  offline h003             1.845 [19.01, 17.12, 14.44]
  revocation run           2.816 [19.17, 17.19, 14.48]
  revocation               0.011 [19.17, 17.19, 14.48]
  false revocation         1.654 [19.17, 17.19, 14.48]
  campaign cases           0.018 [19.17, 17.19, 14.48]
  campaign                 0.264 [19.17, 17.19, 14.48]
  campaign outcomes        0.201 [19.17, 17.19, 14.48]
  privacy                  9.085 [18.68, 17.15, 14.49]
  canary scan              3.808 [19.19, 17.28, 14.55]
loadavg_end [19.69, 17.45, 14.63]
```

### B.2 Stage 7 tests
```
$ python -m pytest tests/test_stage7_*.py -p no:cacheprovider --junitxml=s7tests.xml
start 15:42:42 load 16.14 10.92 11.32 13/1798 2766414
exit 0 end 15:45:23 load 18.87 14.03 12.43 17/1831 2779109
373 passed in 154.17s (0:02:34)
junit: 373 tests 0 fail 0 err 0 skip 154.167 s
```

### B.3 Adversary-fraction sweep, 4 receivers (full summary)
```
$ PYTHONHASHSEED=0 python benchmarks/stage7/fraction_sweep.py --corpus-seed 7 --seed 0 && python benchmarks/stage7/summarise.py results/stage7-fraction-sweep-c7-s0-default.json

######## stage7-fraction-sweep-c7-s0-default.json: corpus seed 7 fleet seed 0 receivers 4 items 74 positives 14
preconditions: [('P1', 'PASS'), ('P2', 'PASS'), ('P3', 'PASS'), ('P4', 'PASS'), ('P5', 'DEGENERATE_IN_FAVOUR')]

[detection, run_benchmark] method: recall@FPR0.01 (tp/pos, fp/neg) per x
  NONE
    NO_SHARING             0.0:0.000(0/14,fp0/60)
    MAJORITY               0.0:0.000(14/14,fp11/60)
    MEAN                   0.0:0.000(14/14,fp11/60)
    MEDIAN                 0.0:0.000(14/14,fp11/60)
    TRIMMED_MEAN           0.0:0.000(14/14,fp11/60)
    MEDIAN+LV              0.0:0.786(11/14,fp0/60)
    TRIMMED_MEAN+LV        0.0:0.786(11/14,fp0/60)
    VALIDATION_FILTER      0.0:0.786(11/14,fp0/60)
    ROOT_QUORUM            0.0:0.786(11/14,fp0/60)
    ROOT_QUORUM_DECLARED   0.0:0.786(11/14,fp0/60)
    ECHO                   0.0:0.571(8/14,fp0/60)
  BYZANTINE_POISON
    NO_SHARING             0.0:0.000(0/14,fp0/60)  0.1:0.000(0/14,fp0/60)  0.2:0.000(0/14,fp0/60)  0.3:0.000(0/14,fp0/60)  0.4:0.000(0/14,fp0/60)  0.5:0.000(0/14,fp0/60)  0.6:0.000(0/14,fp0/60)
    MAJORITY               0.0:0.000(14/14,fp11/60)  0.1:0.000(14/14,fp45/60)  0.2:0.000(14/14,fp45/60)  0.3:0.000(14/14,fp45/60)  0.4:0.000(14/14,fp45/60)  0.5:0.000(14/14,fp45/60)  0.6:0.000(14/14,fp45/60)
    MEAN                   0.0:0.000(14/14,fp11/60)  0.1:0.000(14/14,fp45/60)  0.2:0.000(14/14,fp45/60)  0.3:0.000(14/14,fp45/60)  0.4:0.000(14/14,fp45/60)  0.5:0.000(14/14,fp45/60)  0.6:0.000(14/14,fp45/60)
    MEDIAN                 0.0:0.000(14/14,fp11/60)  0.1:0.000(14/14,fp45/60)  0.2:0.000(14/14,fp45/60)  0.3:0.000(14/14,fp45/60)  0.4:0.000(14/14,fp45/60)  0.5:0.000(14/14,fp45/60)  0.6:0.000(14/14,fp45/60)
    TRIMMED_MEAN           0.0:0.000(14/14,fp11/60)  0.1:0.000(14/14,fp45/60)  0.2:0.000(14/14,fp45/60)  0.3:0.000(14/14,fp45/60)  0.4:0.000(14/14,fp45/60)  0.5:0.000(14/14,fp45/60)  0.6:0.000(14/14,fp45/60)
    MEDIAN+LV              0.0:0.786(11/14,fp0/60)  0.1:0.786(11/14,fp0/60)  0.2:0.786(11/14,fp0/60)  0.3:0.786(11/14,fp0/60)  0.4:0.786(11/14,fp0/60)  0.5:0.786(11/14,fp0/60)  0.6:0.786(11/14,fp0/60)
    TRIMMED_MEAN+LV        0.0:0.786(11/14,fp0/60)  0.1:0.786(11/14,fp0/60)  0.2:0.786(11/14,fp0/60)  0.3:0.786(11/14,fp0/60)  0.4:0.786(11/14,fp0/60)  0.5:0.786(11/14,fp0/60)  0.6:0.786(11/14,fp0/60)
    VALIDATION_FILTER      0.0:0.786(11/14,fp0/60)  0.1:0.786(11/14,fp0/60)  0.2:0.786(11/14,fp0/60)  0.3:0.786(11/14,fp0/60)  0.4:0.786(11/14,fp0/60)  0.5:0.786(11/14,fp0/60)  0.6:0.786(11/14,fp0/60)
    ROOT_QUORUM            0.0:0.786(11/14,fp0/60)  0.1:0.000(0/14,fp0/60)  0.2:0.000(0/14,fp0/60)  0.3:0.000(0/14,fp0/60)  0.4:0.000(0/14,fp0/60)  0.5:0.000(0/14,fp0/60)  0.6:0.000(0/14,fp0/60)
    ROOT_QUORUM_DECLARED   0.0:0.786(11/14,fp0/60)  0.1:0.786(11/14,fp0/60)  0.2:0.786(11/14,fp0/60)  0.3:0.786(11/14,fp0/60)  0.4:0.786(11/14,fp0/60)  0.5:0.786(11/14,fp0/60)  0.6:0.786(11/14,fp0/60)
    ECHO                   0.0:0.571(8/14,fp0/60)  0.1:0.000(0/14,fp0/60)  0.2:0.000(0/14,fp0/60)  0.3:0.000(0/14,fp0/60)  0.4:0.000(0/14,fp0/60)  0.5:0.000(0/14,fp0/60)  0.6:0.000(0/14,fp0/60)
  BYZANTINE_LATENT_POISON
    NO_SHARING             0.0:0.000(0/14,fp0/60)  0.1:0.000(0/14,fp0/60)  0.2:0.000(0/14,fp0/60)  0.3:0.000(0/14,fp0/60)  0.4:0.000(0/14,fp0/60)  0.5:0.000(0/14,fp0/60)  0.6:0.000(0/14,fp0/60)
    MAJORITY               0.0:0.000(14/14,fp11/60)  0.1:0.000(14/14,fp11/60)  0.2:0.000(14/14,fp11/60)  0.3:0.000(14/14,fp11/60)  0.4:0.000(14/14,fp11/60)  0.5:0.000(14/14,fp11/60)  0.6:0.000(14/14,fp11/60)
    MEAN                   0.0:0.000(14/14,fp11/60)  0.1:0.000(14/14,fp11/60)  0.2:0.000(14/14,fp11/60)  0.3:0.000(14/14,fp11/60)  0.4:0.000(14/14,fp11/60)  0.5:0.000(14/14,fp11/60)  0.6:0.000(14/14,fp11/60)
    MEDIAN                 0.0:0.000(14/14,fp11/60)  0.1:0.000(14/14,fp11/60)  0.2:0.000(14/14,fp11/60)  0.3:0.000(14/14,fp11/60)  0.4:0.000(14/14,fp11/60)  0.5:0.000(14/14,fp11/60)  0.6:0.000(14/14,fp11/60)
    TRIMMED_MEAN           0.0:0.000(14/14,fp11/60)  0.1:0.000(14/14,fp11/60)  0.2:0.000(14/14,fp11/60)  0.3:0.000(14/14,fp11/60)  0.4:0.000(14/14,fp11/60)  0.5:0.000(14/14,fp11/60)  0.6:0.000(14/14,fp11/60)
    MEDIAN+LV              0.0:0.786(11/14,fp0/60)  0.1:0.000(12/14,fp4/60)  0.2:0.000(12/14,fp4/60)  0.3:0.000(12/14,fp4/60)  0.4:0.000(12/14,fp4/60)  0.5:0.000(12/14,fp4/60)  0.6:0.000(12/14,fp4/60)
    TRIMMED_MEAN+LV        0.0:0.786(11/14,fp0/60)  0.1:0.000(12/14,fp4/60)  0.2:0.000(12/14,fp4/60)  0.3:0.000(12/14,fp4/60)  0.4:0.000(12/14,fp4/60)  0.5:0.000(12/14,fp4/60)  0.6:0.000(12/14,fp4/60)
    VALIDATION_FILTER      0.0:0.786(11/14,fp0/60)  0.1:0.000(12/14,fp4/60)  0.2:0.000(12/14,fp4/60)  0.3:0.000(12/14,fp4/60)  0.4:0.000(12/14,fp4/60)  0.5:0.000(12/14,fp4/60)  0.6:0.000(12/14,fp4/60)
    ROOT_QUORUM            0.0:0.786(11/14,fp0/60)  0.1:0.786(11/14,fp0/60)  0.2:0.786(11/14,fp0/60)  0.3:0.786(11/14,fp0/60)  0.4:0.786(11/14,fp0/60)  0.5:0.786(11/14,fp0/60)  0.6:0.786(11/14,fp0/60)
    ROOT_QUORUM_DECLARED   0.0:0.786(11/14,fp0/60)  0.1:0.000(12/14,fp4/60)  0.2:0.000(12/14,fp4/60)  0.3:0.000(12/14,fp4/60)  0.4:0.000(12/14,fp4/60)  0.5:0.000(12/14,fp4/60)  0.6:0.000(12/14,fp4/60)
    ECHO                   0.0:0.571(8/14,fp0/60)  0.1:0.571(8/14,fp0/60)  0.2:0.571(8/14,fp0/60)  0.3:0.571(8/14,fp0/60)  0.4:0.571(8/14,fp0/60)  0.5:0.571(8/14,fp0/60)  0.6:0.571(8/14,fp0/60)
  SLOW_POISON
    NO_SHARING             0.0:0.000(0/14,fp0/60)  0.1:0.000(0/14,fp0/60)  0.2:0.000(0/14,fp0/60)  0.3:0.000(0/14,fp0/60)  0.4:0.000(0/14,fp0/60)  0.5:0.000(0/14,fp0/60)  0.6:0.000(0/14,fp0/60)
    MAJORITY               0.0:0.000(14/14,fp11/60)  0.1:0.000(14/14,fp11/60)  0.2:0.000(14/14,fp11/60)  0.3:0.000(14/14,fp11/60)  0.4:0.000(14/14,fp11/60)  0.5:0.000(14/14,fp11/60)  0.6:0.000(14/14,fp11/60)
    MEAN                   0.0:0.000(14/14,fp11/60)  0.1:0.000(14/14,fp11/60)  0.2:0.000(14/14,fp11/60)  0.3:0.000(14/14,fp11/60)  0.4:0.000(14/14,fp11/60)  0.5:0.000(14/14,fp11/60)  0.6:0.000(14/14,fp11/60)
    MEDIAN                 0.0:0.000(14/14,fp11/60)  0.1:0.000(14/14,fp11/60)  0.2:0.000(14/14,fp11/60)  0.3:0.000(14/14,fp11/60)  0.4:0.000(14/14,fp11/60)  0.5:0.000(14/14,fp11/60)  0.6:0.000(14/14,fp11/60)
    TRIMMED_MEAN           0.0:0.000(14/14,fp11/60)  0.1:0.000(14/14,fp11/60)  0.2:0.000(14/14,fp11/60)  0.3:0.000(14/14,fp11/60)  0.4:0.000(14/14,fp11/60)  0.5:0.000(14/14,fp11/60)  0.6:0.000(14/14,fp11/60)
    MEDIAN+LV              0.0:0.786(11/14,fp0/60)  0.1:0.000(12/14,fp4/60)  0.2:0.000(12/14,fp4/60)  0.3:0.000(12/14,fp4/60)  0.4:0.786(11/14,fp0/60)  0.5:0.786(11/14,fp0/60)  0.6:0.786(11/14,fp0/60)
    TRIMMED_MEAN+LV        0.0:0.786(11/14,fp0/60)  0.1:0.000(12/14,fp4/60)  0.2:0.000(12/14,fp4/60)  0.3:0.000(12/14,fp4/60)  0.4:0.786(11/14,fp0/60)  0.5:0.786(11/14,fp0/60)  0.6:0.786(11/14,fp0/60)
    VALIDATION_FILTER      0.0:0.786(11/14,fp0/60)  0.1:0.000(12/14,fp4/60)  0.2:0.000(12/14,fp4/60)  0.3:0.000(12/14,fp4/60)  0.4:0.786(11/14,fp0/60)  0.5:0.786(11/14,fp0/60)  0.6:0.786(11/14,fp0/60)
    ROOT_QUORUM            0.0:0.786(11/14,fp0/60)  0.1:0.786(11/14,fp0/60)  0.2:0.786(11/14,fp0/60)  0.3:0.786(11/14,fp0/60)  0.4:0.786(11/14,fp0/60)  0.5:0.786(11/14,fp0/60)  0.6:0.786(11/14,fp0/60)
    ROOT_QUORUM_DECLARED   0.0:0.786(11/14,fp0/60)  0.1:0.000(12/14,fp4/60)  0.2:0.000(12/14,fp4/60)  0.3:0.000(12/14,fp4/60)  0.4:0.786(11/14,fp0/60)  0.5:0.786(11/14,fp0/60)  0.6:0.786(11/14,fp0/60)
    ECHO                   0.0:0.571(8/14,fp0/60)  0.1:0.786(11/14,fp0/60)  0.2:0.786(11/14,fp0/60)  0.3:0.786(11/14,fp0/60)  0.4:0.786(11/14,fp0/60)  0.5:0.786(11/14,fp0/60)  0.6:0.786(11/14,fp0/60)
  COLLUSION_TIMING
    NO_SHARING             0.0:0.000(0/14,fp0/60)  0.1:0.000(0/14,fp0/60)  0.2:0.000(0/14,fp0/60)  0.3:0.000(0/14,fp0/60)  0.4:0.000(0/14,fp0/60)  0.5:0.000(0/14,fp0/60)  0.6:0.000(0/14,fp0/60)
    MAJORITY               0.0:0.000(14/14,fp11/60)  0.1:0.000(14/14,fp11/60)  0.2:0.000(14/14,fp11/60)  0.3:0.000(14/14,fp11/60)  0.4:0.000(14/14,fp11/60)  0.5:0.000(14/14,fp11/60)  0.6:0.000(14/14,fp11/60)
    MEAN                   0.0:0.000(14/14,fp11/60)  0.1:0.000(14/14,fp11/60)  0.2:0.000(14/14,fp11/60)  0.3:0.000(14/14,fp11/60)  0.4:0.000(14/14,fp11/60)  0.5:0.000(14/14,fp11/60)  0.6:0.000(14/14,fp11/60)
    MEDIAN                 0.0:0.000(14/14,fp11/60)  0.1:0.000(14/14,fp11/60)  0.2:0.000(14/14,fp11/60)  0.3:0.000(14/14,fp11/60)  0.4:0.000(14/14,fp11/60)  0.5:0.000(14/14,fp11/60)  0.6:0.000(14/14,fp11/60)
    TRIMMED_MEAN           0.0:0.000(14/14,fp11/60)  0.1:0.000(14/14,fp11/60)  0.2:0.000(14/14,fp11/60)  0.3:0.000(14/14,fp11/60)  0.4:0.000(14/14,fp11/60)  0.5:0.000(14/14,fp11/60)  0.6:0.000(14/14,fp11/60)
    MEDIAN+LV              0.0:0.786(11/14,fp0/60)  0.1:0.000(12/14,fp4/60)  0.2:0.000(12/14,fp4/60)  0.3:0.000(12/14,fp4/60)  0.4:0.000(12/14,fp4/60)  0.5:0.000(12/14,fp4/60)  0.6:0.000(12/14,fp4/60)
    TRIMMED_MEAN+LV        0.0:0.786(11/14,fp0/60)  0.1:0.000(12/14,fp4/60)  0.2:0.000(12/14,fp4/60)  0.3:0.000(12/14,fp4/60)  0.4:0.000(12/14,fp4/60)  0.5:0.000(12/14,fp4/60)  0.6:0.000(12/14,fp4/60)
    VALIDATION_FILTER      0.0:0.786(11/14,fp0/60)  0.1:0.000(12/14,fp4/60)  0.2:0.000(12/14,fp4/60)  0.3:0.000(12/14,fp4/60)  0.4:0.000(12/14,fp4/60)  0.5:0.000(12/14,fp4/60)  0.6:0.000(12/14,fp4/60)
    ROOT_QUORUM            0.0:0.786(11/14,fp0/60)  0.1:0.000(12/14,fp4/60)  0.2:0.000(12/14,fp4/60)  0.3:0.000(12/14,fp4/60)  0.4:0.786(11/14,fp0/60)  0.5:0.786(11/14,fp0/60)  0.6:0.786(11/14,fp0/60)
    ROOT_QUORUM_DECLARED   0.0:0.786(11/14,fp0/60)  0.1:0.000(12/14,fp4/60)  0.2:0.000(12/14,fp4/60)  0.3:0.000(12/14,fp4/60)  0.4:0.000(12/14,fp4/60)  0.5:0.000(12/14,fp4/60)  0.6:0.000(12/14,fp4/60)
    ECHO                   0.0:0.571(8/14,fp0/60)  0.1:0.571(8/14,fp0/60)  0.2:0.000(9/14,fp4/60)  0.3:0.000(9/14,fp4/60)  0.4:0.571(8/14,fp0/60)  0.5:0.571(8/14,fp0/60)  0.6:0.571(8/14,fp0/60)
  BYZANTINE_SUPPRESS
    NO_SHARING             0.0:0.000(0/14,fp0/60)  0.1:0.000(0/14,fp0/60)  0.2:0.000(0/14,fp0/60)  0.3:0.000(0/14,fp0/60)  0.4:0.000(0/14,fp0/60)  0.5:0.000(0/14,fp0/60)  0.6:0.000(0/14,fp0/60)
    MAJORITY               0.0:0.000(14/14,fp11/60)  0.1:0.000(14/14,fp11/60)  0.2:0.000(9/14,fp8/60)  0.3:0.000(9/14,fp8/60)  0.4:0.000(6/14,fp8/60)  0.5:0.000(6/14,fp8/60)  0.6:0.000(6/14,fp8/60)
    MEAN                   0.0:0.000(14/14,fp11/60)  0.1:0.000(14/14,fp11/60)  0.2:0.000(9/14,fp8/60)  0.3:0.000(9/14,fp8/60)  0.4:0.000(6/14,fp8/60)  0.5:0.000(6/14,fp8/60)  0.6:0.000(6/14,fp8/60)
    MEDIAN                 0.0:0.000(14/14,fp11/60)  0.1:0.000(14/14,fp11/60)  0.2:0.000(9/14,fp8/60)  0.3:0.000(9/14,fp8/60)  0.4:0.000(6/14,fp8/60)  0.5:0.000(6/14,fp8/60)  0.6:0.000(6/14,fp8/60)
    TRIMMED_MEAN           0.0:0.000(14/14,fp11/60)  0.1:0.000(14/14,fp11/60)  0.2:0.000(9/14,fp8/60)  0.3:0.000(9/14,fp8/60)  0.4:0.000(6/14,fp8/60)  0.5:0.000(6/14,fp8/60)  0.6:0.000(6/14,fp8/60)
    MEDIAN+LV              0.0:0.786(11/14,fp0/60)  0.1:0.786(11/14,fp0/60)  0.2:0.571(8/14,fp0/60)  0.3:0.571(8/14,fp0/60)  0.4:0.357(5/14,fp0/60)  0.5:0.357(5/14,fp0/60)  0.6:0.357(5/14,fp0/60)
    TRIMMED_MEAN+LV        0.0:0.786(11/14,fp0/60)  0.1:0.786(11/14,fp0/60)  0.2:0.571(8/14,fp0/60)  0.3:0.571(8/14,fp0/60)  0.4:0.357(5/14,fp0/60)  0.5:0.357(5/14,fp0/60)  0.6:0.357(5/14,fp0/60)
    VALIDATION_FILTER      0.0:0.786(11/14,fp0/60)  0.1:0.786(11/14,fp0/60)  0.2:0.786(11/14,fp0/60)  0.3:0.786(11/14,fp0/60)  0.4:0.786(11/14,fp0/60)  0.5:0.786(11/14,fp0/60)  0.6:0.786(11/14,fp0/60)
    ROOT_QUORUM            0.0:0.786(11/14,fp0/60)  0.1:0.786(11/14,fp0/60)  0.2:0.786(11/14,fp0/60)  0.3:0.786(11/14,fp0/60)  0.4:0.786(11/14,fp0/60)  0.5:0.786(11/14,fp0/60)  0.6:0.786(11/14,fp0/60)
    ROOT_QUORUM_DECLARED   0.0:0.786(11/14,fp0/60)  0.1:0.786(11/14,fp0/60)  0.2:0.571(8/14,fp0/60)  0.3:0.571(8/14,fp0/60)  0.4:0.357(5/14,fp0/60)  0.5:0.357(5/14,fp0/60)  0.6:0.357(5/14,fp0/60)
    ECHO                   0.0:0.571(8/14,fp0/60)  0.1:0.571(8/14,fp0/60)  0.2:0.571(8/14,fp0/60)  0.3:0.571(8/14,fp0/60)  0.4:0.571(8/14,fp0/60)  0.5:0.571(8/14,fp0/60)  0.6:0.571(8/14,fp0/60)
  SYBIL_DECLARED_ROOT
    NO_SHARING             S=1:0.000(0/14,fp0/60)  S=2:0.000(0/14,fp0/60)  S=4:0.000(0/14,fp0/60)  S=8:0.000(0/14,fp0/60)  S=16:0.000(0/14,fp0/60)  S=32:0.000(0/14,fp0/60)  S=64:0.000(0/14,fp0/60)  S=128:0.000(0/14,fp0/60)
    MAJORITY               S=1:0.000(14/14,fp11/60)  S=2:0.000(14/14,fp11/60)  S=4:0.000(14/14,fp11/60)  S=8:0.000(14/14,fp11/60)  S=16:0.000(14/14,fp11/60)  S=32:0.000(14/14,fp11/60)  S=64:0.000(14/14,fp11/60)  S=128:0.000(14/14,fp11/60)
    MEAN                   S=1:0.000(14/14,fp11/60)  S=2:0.000(14/14,fp11/60)  S=4:0.000(14/14,fp11/60)  S=8:0.000(14/14,fp11/60)  S=16:0.000(14/14,fp11/60)  S=32:0.000(14/14,fp11/60)  S=64:0.000(14/14,fp11/60)  S=128:0.000(14/14,fp11/60)
    MEDIAN                 S=1:0.000(14/14,fp11/60)  S=2:0.000(14/14,fp11/60)  S=4:0.000(14/14,fp11/60)  S=8:0.000(14/14,fp11/60)  S=16:0.000(14/14,fp11/60)  S=32:0.000(14/14,fp11/60)  S=64:0.000(14/14,fp11/60)  S=128:0.000(14/14,fp11/60)
    TRIMMED_MEAN           S=1:0.000(14/14,fp11/60)  S=2:0.000(14/14,fp11/60)  S=4:0.000(14/14,fp11/60)  S=8:0.000(14/14,fp11/60)  S=16:0.000(14/14,fp11/60)  S=32:0.000(14/14,fp11/60)  S=64:0.000(14/14,fp11/60)  S=128:0.000(14/14,fp11/60)
    MEDIAN+LV              S=1:0.000(12/14,fp4/60)  S=2:0.000(12/14,fp4/60)  S=4:0.000(12/14,fp4/60)  S=8:0.000(12/14,fp4/60)  S=16:0.000(12/14,fp4/60)  S=32:0.000(12/14,fp4/60)  S=64:0.000(12/14,fp4/60)  S=128:0.000(12/14,fp4/60)
    TRIMMED_MEAN+LV        S=1:0.000(12/14,fp4/60)  S=2:0.000(12/14,fp4/60)  S=4:0.000(12/14,fp4/60)  S=8:0.000(12/14,fp4/60)  S=16:0.000(12/14,fp4/60)  S=32:0.000(12/14,fp4/60)  S=64:0.000(12/14,fp4/60)  S=128:0.000(12/14,fp4/60)
    VALIDATION_FILTER      S=1:0.000(12/14,fp4/60)  S=2:0.000(12/14,fp4/60)  S=4:0.000(12/14,fp4/60)  S=8:0.000(12/14,fp4/60)  S=16:0.000(12/14,fp4/60)  S=32:0.000(12/14,fp4/60)  S=64:0.000(12/14,fp4/60)  S=128:0.000(12/14,fp4/60)
    ROOT_QUORUM            S=1:0.786(11/14,fp0/60)  S=2:0.786(11/14,fp0/60)  S=4:0.786(11/14,fp0/60)  S=8:0.786(11/14,fp0/60)  S=16:0.786(11/14,fp0/60)  S=32:0.786(11/14,fp0/60)  S=64:0.786(11/14,fp0/60)  S=128:0.786(11/14,fp0/60)
    ROOT_QUORUM_DECLARED   S=1:0.786(11/14,fp0/60)  S=2:0.786(11/14,fp0/60)  S=4:0.786(11/14,fp0/60)  S=8:0.786(11/14,fp0/60)  S=16:0.786(11/14,fp0/60)  S=32:0.786(11/14,fp0/60)  S=64:0.786(11/14,fp0/60)  S=128:0.786(11/14,fp0/60)
    ECHO                   S=1:0.571(8/14,fp0/60)  S=2:0.571(8/14,fp0/60)  S=4:0.571(8/14,fp0/60)  S=8:0.571(8/14,fp0/60)  S=16:0.571(8/14,fp0/60)  S=32:0.571(8/14,fp0/60)  S=64:0.571(8/14,fp0/60)  S=128:0.571(8/14,fp0/60)
  SYBIL_FORGED_ROOTS
    NO_SHARING             S=1:0.000(0/14,fp0/60)  S=2:0.000(0/14,fp0/60)  S=4:0.000(0/14,fp0/60)  S=8:0.000(0/14,fp0/60)  S=16:0.000(0/14,fp0/60)  S=32:0.000(0/14,fp0/60)  S=64:0.000(0/14,fp0/60)  S=128:0.000(0/14,fp0/60)
    MAJORITY               S=1:0.000(14/14,fp11/60)  S=2:0.000(14/14,fp11/60)  S=4:0.000(14/14,fp11/60)  S=8:0.000(14/14,fp11/60)  S=16:0.000(14/14,fp11/60)  S=32:0.000(14/14,fp11/60)  S=64:0.000(14/14,fp11/60)  S=128:0.000(14/14,fp11/60)
    MEAN                   S=1:0.000(14/14,fp11/60)  S=2:0.000(14/14,fp11/60)  S=4:0.000(14/14,fp11/60)  S=8:0.000(14/14,fp11/60)  S=16:0.000(14/14,fp11/60)  S=32:0.000(14/14,fp11/60)  S=64:0.000(14/14,fp11/60)  S=128:0.000(14/14,fp11/60)
    MEDIAN                 S=1:0.000(14/14,fp11/60)  S=2:0.000(14/14,fp11/60)  S=4:0.000(14/14,fp11/60)  S=8:0.000(14/14,fp11/60)  S=16:0.000(14/14,fp11/60)  S=32:0.000(14/14,fp11/60)  S=64:0.000(14/14,fp11/60)  S=128:0.000(14/14,fp11/60)
    TRIMMED_MEAN           S=1:0.000(14/14,fp11/60)  S=2:0.000(14/14,fp11/60)  S=4:0.000(14/14,fp11/60)  S=8:0.000(14/14,fp11/60)  S=16:0.000(14/14,fp11/60)  S=32:0.000(14/14,fp11/60)  S=64:0.000(14/14,fp11/60)  S=128:0.000(14/14,fp11/60)
    MEDIAN+LV              S=1:0.000(12/14,fp4/60)  S=2:0.000(12/14,fp4/60)  S=4:0.000(12/14,fp4/60)  S=8:0.000(12/14,fp4/60)  S=16:0.000(12/14,fp4/60)  S=32:0.000(12/14,fp4/60)  S=64:0.000(12/14,fp4/60)  S=128:0.000(12/14,fp4/60)
    TRIMMED_MEAN+LV        S=1:0.000(12/14,fp4/60)  S=2:0.000(12/14,fp4/60)  S=4:0.000(12/14,fp4/60)  S=8:0.000(12/14,fp4/60)  S=16:0.000(12/14,fp4/60)  S=32:0.000(12/14,fp4/60)  S=64:0.000(12/14,fp4/60)  S=128:0.000(12/14,fp4/60)
    VALIDATION_FILTER      S=1:0.000(12/14,fp4/60)  S=2:0.000(12/14,fp4/60)  S=4:0.000(12/14,fp4/60)  S=8:0.000(12/14,fp4/60)  S=16:0.000(12/14,fp4/60)  S=32:0.000(12/14,fp4/60)  S=64:0.000(12/14,fp4/60)  S=128:0.000(12/14,fp4/60)
    ROOT_QUORUM            S=1:0.786(11/14,fp0/60)  S=2:0.786(11/14,fp0/60)  S=4:0.786(11/14,fp0/60)  S=8:0.786(11/14,fp0/60)  S=16:0.786(11/14,fp0/60)  S=32:0.786(11/14,fp0/60)  S=64:0.786(11/14,fp0/60)  S=128:0.786(11/14,fp0/60)
    ROOT_QUORUM_DECLARED   S=1:0.786(11/14,fp0/60)  S=2:0.000(12/14,fp4/60)  S=4:0.000(12/14,fp4/60)  S=8:0.000(12/14,fp4/60)  S=16:0.000(12/14,fp4/60)  S=32:0.000(12/14,fp4/60)  S=64:0.000(12/14,fp4/60)  S=128:0.000(12/14,fp4/60)
    ECHO                   S=1:0.571(8/14,fp0/60)  S=2:0.571(8/14,fp0/60)  S=4:0.571(8/14,fp0/60)  S=8:0.571(8/14,fp0/60)  S=16:0.571(8/14,fp0/60)  S=32:0.571(8/14,fp0/60)  S=64:0.571(8/14,fp0/60)  S=128:0.571(8/14,fp0/60)
  SYBIL_ADAPTIVE
    NO_SHARING             S=1:0.000(0/14,fp0/60)  S=2:0.000(0/14,fp0/60)  S=4:0.000(0/14,fp0/60)  S=8:0.000(0/14,fp0/60)  S=16:0.000(0/14,fp0/60)  S=32:0.000(0/14,fp0/60)  S=64:0.000(0/14,fp0/60)  S=128:0.000(0/14,fp0/60)
    MAJORITY               S=1:0.000(14/14,fp11/60)  S=2:0.000(14/14,fp11/60)  S=4:0.000(14/14,fp11/60)  S=8:0.000(14/14,fp11/60)  S=16:0.000(14/14,fp11/60)  S=32:0.000(14/14,fp11/60)  S=64:0.000(14/14,fp11/60)  S=128:0.000(14/14,fp11/60)
    MEAN                   S=1:0.000(14/14,fp11/60)  S=2:0.000(14/14,fp11/60)  S=4:0.000(14/14,fp11/60)  S=8:0.000(14/14,fp11/60)  S=16:0.000(14/14,fp11/60)  S=32:0.000(14/14,fp11/60)  S=64:0.000(14/14,fp11/60)  S=128:0.000(14/14,fp11/60)
    MEDIAN                 S=1:0.000(14/14,fp11/60)  S=2:0.000(14/14,fp11/60)  S=4:0.000(14/14,fp11/60)  S=8:0.000(14/14,fp11/60)  S=16:0.000(14/14,fp11/60)  S=32:0.000(14/14,fp11/60)  S=64:0.000(14/14,fp11/60)  S=128:0.000(14/14,fp11/60)
    TRIMMED_MEAN           S=1:0.000(14/14,fp11/60)  S=2:0.000(14/14,fp11/60)  S=4:0.000(14/14,fp11/60)  S=8:0.000(14/14,fp11/60)  S=16:0.000(14/14,fp11/60)  S=32:0.000(14/14,fp11/60)  S=64:0.000(14/14,fp11/60)  S=128:0.000(14/14,fp11/60)
    MEDIAN+LV              S=1:0.000(12/14,fp4/60)  S=2:0.000(12/14,fp4/60)  S=4:0.000(12/14,fp4/60)  S=8:0.000(12/14,fp4/60)  S=16:0.000(12/14,fp4/60)  S=32:0.000(12/14,fp4/60)  S=64:0.000(12/14,fp4/60)  S=128:0.000(12/14,fp4/60)
    TRIMMED_MEAN+LV        S=1:0.000(12/14,fp4/60)  S=2:0.000(12/14,fp4/60)  S=4:0.000(12/14,fp4/60)  S=8:0.000(12/14,fp4/60)  S=16:0.000(12/14,fp4/60)  S=32:0.000(12/14,fp4/60)  S=64:0.000(12/14,fp4/60)  S=128:0.000(12/14,fp4/60)
    VALIDATION_FILTER      S=1:0.000(12/14,fp4/60)  S=2:0.000(12/14,fp4/60)  S=4:0.000(12/14,fp4/60)  S=8:0.000(12/14,fp4/60)  S=16:0.000(12/14,fp4/60)  S=32:0.000(12/14,fp4/60)  S=64:0.000(12/14,fp4/60)  S=128:0.000(12/14,fp4/60)
    ROOT_QUORUM            S=1:0.786(11/14,fp0/60)  S=2:0.000(12/14,fp4/60)  S=4:0.000(12/14,fp4/60)  S=8:0.000(12/14,fp4/60)  S=16:0.000(12/14,fp4/60)  S=32:0.000(12/14,fp4/60)  S=64:0.000(12/14,fp4/60)  S=128:0.000(12/14,fp4/60)
    ROOT_QUORUM_DECLARED   S=1:0.786(11/14,fp0/60)  S=2:0.000(12/14,fp4/60)  S=4:0.000(12/14,fp4/60)  S=8:0.000(12/14,fp4/60)  S=16:0.000(12/14,fp4/60)  S=32:0.000(12/14,fp4/60)  S=64:0.000(12/14,fp4/60)  S=128:0.000(12/14,fp4/60)
    ECHO                   S=1:0.786(11/14,fp0/60)  S=2:0.786(11/14,fp0/60)  S=4:0.000(12/14,fp4/60)  S=8:0.000(12/14,fp4/60)  S=16:0.000(12/14,fp4/60)  S=32:0.000(12/14,fp4/60)  S=64:0.000(12/14,fp4/60)  S=128:0.000(12/14,fp4/60)

[robustness, suite] poison accepted/offered per x; ECHO true accepted/offered
  BYZANTINE_POISON
    MAJORITY           0.0:0/0 0.1:4/4 0.2:4/4 0.3:4/4 0.4:4/4 0.5:4/4 0.6:4/4
    MEAN               0.0:0/0 0.1:4/4 0.2:4/4 0.3:4/4 0.4:4/4 0.5:4/4 0.6:4/4
    MEDIAN             0.0:0/0 0.1:4/4 0.2:4/4 0.3:4/4 0.4:4/4 0.5:4/4 0.6:4/4
    TRIMMED_MEAN       0.0:0/0 0.1:4/4 0.2:4/4 0.3:4/4 0.4:4/4 0.5:4/4 0.6:4/4
    MEDIAN+LV          0.0:0/0 0.1:0/4 0.2:0/4 0.3:0/4 0.4:0/4 0.5:0/4 0.6:0/4
    TRIMMED_MEAN+LV    0.0:0/0 0.1:0/4 0.2:0/4 0.3:0/4 0.4:0/4 0.5:0/4 0.6:0/4
    VALIDATION_FILTER  0.0:0/0 0.1:0/4 0.2:0/4 0.3:0/4 0.4:0/4 0.5:0/4 0.6:0/4
    ROOT_QUORUM+LV     0.0:0/0 0.1:0/4 0.2:0/4 0.3:0/4 0.4:0/4 0.5:0/4 0.6:0/4
    ECHO               0.0:0/0 0.1:0/4 0.2:0/4 0.3:0/4 0.4:0/4 0.5:0/4 0.6:0/4
    ECHO true          0.0:6/11 0.1:0/11 0.2:0/11 0.3:0/11 0.4:0/11 0.5:0/11 0.6:0/11
    MEDIAN+LV true     0.0:9/11 0.1:9/11 0.2:9/11 0.3:9/11 0.4:9/11 0.5:9/11 0.6:9/11
    ECHO amplification 0.0:None 0.1:None 0.2:None 0.3:None 0.4:None 0.5:None 0.6:None
    MEDIAN amplif.     0.0:None 0.1:0.6371681415929203 0.2:0.6611570247933884 0.3:0.6917293233082706 0.4:0.7248322147651007 0.5:0.757396449704142 0.6:0.7960199004975125
    stage6 poison: none bridged
  BYZANTINE_LATENT_POISON
    MAJORITY           0.0:0/0 0.1:4/4 0.2:4/4 0.3:4/4 0.4:4/4 0.5:4/4 0.6:4/4
    MEAN               0.0:0/0 0.1:4/4 0.2:4/4 0.3:4/4 0.4:4/4 0.5:4/4 0.6:4/4
    MEDIAN             0.0:0/0 0.1:4/4 0.2:4/4 0.3:4/4 0.4:4/4 0.5:4/4 0.6:4/4
    TRIMMED_MEAN       0.0:0/0 0.1:4/4 0.2:4/4 0.3:4/4 0.4:4/4 0.5:4/4 0.6:4/4
    MEDIAN+LV          0.0:0/0 0.1:4/4 0.2:4/4 0.3:4/4 0.4:4/4 0.5:4/4 0.6:4/4
    TRIMMED_MEAN+LV    0.0:0/0 0.1:4/4 0.2:4/4 0.3:4/4 0.4:4/4 0.5:4/4 0.6:4/4
    VALIDATION_FILTER  0.0:0/0 0.1:4/4 0.2:4/4 0.3:4/4 0.4:4/4 0.5:4/4 0.6:4/4
    ROOT_QUORUM+LV     0.0:0/0 0.1:0/4 0.2:0/4 0.3:0/4 0.4:0/4 0.5:0/4 0.6:0/4
    ECHO               0.0:0/0 0.1:0/4 0.2:0/4 0.3:0/4 0.4:0/4 0.5:0/4 0.6:0/4
    ECHO true          0.0:6/11 0.1:6/11 0.2:6/11 0.3:6/11 0.4:6/11 0.5:6/11 0.6:6/11
    MEDIAN+LV true     0.0:9/11 0.1:9/11 0.2:9/11 0.3:9/11 0.4:9/11 0.5:9/11 0.6:9/11
    ECHO amplification 0.0:None 0.1:0.0 0.2:0.0 0.3:0.0 0.4:0.0 0.5:0.0 0.6:0.0
    MEDIAN amplif.     0.0:None 0.1:0.6050420168067226 0.2:0.6299212598425197 0.3:0.6618705035971223 0.4:0.6967741935483871 0.5:0.7314285714285714 0.6:0.7729468599033816
    stage6 poison: none bridged
  SLOW_POISON
    MAJORITY           0.0:0/0 0.1:4/4 0.2:4/4 0.3:4/4 0.4:0/0 0.5:0/0 0.6:0/0
    MEAN               0.0:0/0 0.1:4/4 0.2:4/4 0.3:4/4 0.4:0/0 0.5:0/0 0.6:0/0
    MEDIAN             0.0:0/0 0.1:4/4 0.2:4/4 0.3:4/4 0.4:0/0 0.5:0/0 0.6:0/0
    TRIMMED_MEAN       0.0:0/0 0.1:4/4 0.2:4/4 0.3:4/4 0.4:0/0 0.5:0/0 0.6:0/0
    MEDIAN+LV          0.0:0/0 0.1:4/4 0.2:4/4 0.3:4/4 0.4:0/0 0.5:0/0 0.6:0/0
    TRIMMED_MEAN+LV    0.0:0/0 0.1:4/4 0.2:4/4 0.3:4/4 0.4:0/0 0.5:0/0 0.6:0/0
    VALIDATION_FILTER  0.0:0/0 0.1:4/4 0.2:4/4 0.3:4/4 0.4:0/0 0.5:0/0 0.6:0/0
    ROOT_QUORUM+LV     0.0:0/0 0.1:2/4 0.2:1/4 0.3:0/4 0.4:0/0 0.5:0/0 0.6:0/0
    ECHO               0.0:0/0 0.1:0/4 0.2:0/4 0.3:0/4 0.4:0/0 0.5:0/0 0.6:0/0
    ECHO true          0.0:6/11 0.1:9/11 0.2:9/11 0.3:9/11 0.4:9/11 0.5:9/11 0.6:9/11
    MEDIAN+LV true     0.0:9/11 0.1:9/11 0.2:9/11 0.3:9/11 0.4:9/11 0.5:9/11 0.6:9/11
    ECHO amplification 0.0:None 0.1:3.560023006339489 0.2:2.1944155614065664 0.3:0.955970028155937 0.4:0.7155330516270584 0.5:0.5831952876111287 0.6:0.48599607300927383
    MEDIAN amplif.     0.0:None 0.1:2.384105960264901 0.2:2.094240837696335 0.3:1.832669322709163 0.4:1.441703278134505 0.5:1.3231707317073171 0.6:1.223021582733813
    stage6 poison: none bridged
  COLLUSION_TIMING
    MAJORITY           0.0:0/0 0.1:4/4 0.2:4/4 0.3:4/4 0.4:4/4 0.5:4/4 0.6:4/4
    MEAN               0.0:0/0 0.1:4/4 0.2:4/4 0.3:4/4 0.4:4/4 0.5:4/4 0.6:4/4
    MEDIAN             0.0:0/0 0.1:4/4 0.2:4/4 0.3:4/4 0.4:4/4 0.5:4/4 0.6:4/4
    TRIMMED_MEAN       0.0:0/0 0.1:4/4 0.2:4/4 0.3:4/4 0.4:4/4 0.5:4/4 0.6:4/4
    MEDIAN+LV          0.0:0/0 0.1:4/4 0.2:4/4 0.3:4/4 0.4:4/4 0.5:4/4 0.6:4/4
    TRIMMED_MEAN+LV    0.0:0/0 0.1:4/4 0.2:4/4 0.3:4/4 0.4:4/4 0.5:4/4 0.6:4/4
    VALIDATION_FILTER  0.0:0/0 0.1:4/4 0.2:4/4 0.3:4/4 0.4:4/4 0.5:4/4 0.6:4/4
    ROOT_QUORUM+LV     0.0:0/0 0.1:4/4 0.2:4/4 0.3:4/4 0.4:0/4 0.5:0/4 0.6:0/4
    ECHO               0.0:0/0 0.1:0/4 0.2:4/4 0.3:4/4 0.4:0/4 0.5:0/4 0.6:0/4
    ECHO true          0.0:6/11 0.1:6/11 0.2:6/11 0.3:6/11 0.4:6/11 0.5:6/11 0.6:6/11
    MEDIAN+LV true     0.0:9/11 0.1:9/11 0.2:9/11 0.3:9/11 0.4:9/11 0.5:9/11 0.6:9/11
    ECHO amplification 0.0:None 0.1:0.0 0.2:2.1765951786403854 0.3:1.8828867230287594 0.4:0.0 0.5:0.0 0.6:0.0
    MEDIAN amplif.     0.0:None 0.1:0.6050420168067226 0.2:0.6299212598425197 0.3:0.6618705035971223 0.4:0.6967741935483871 0.5:0.7314285714285714 0.6:0.7729468599033816
    stage6 poison: ["0.2:{'UNCERTAIN': 16, 'poison_decisions_bridged': 4, 'receipts_evicted': 0}", "0.3:{'UNCERTAIN': 28, 'poison_decisions_bridged': 4, 'receipts_evicted': 0}"]
  BYZANTINE_SUPPRESS
    MAJORITY           0.0:0/0 0.1:0/0 0.2:0/0 0.3:0/0 0.4:0/0 0.5:0/0 0.6:0/0
    MEAN               0.0:0/0 0.1:0/0 0.2:0/0 0.3:0/0 0.4:0/0 0.5:0/0 0.6:0/0
    MEDIAN             0.0:0/0 0.1:0/0 0.2:0/0 0.3:0/0 0.4:0/0 0.5:0/0 0.6:0/0
    TRIMMED_MEAN       0.0:0/0 0.1:0/0 0.2:0/0 0.3:0/0 0.4:0/0 0.5:0/0 0.6:0/0
    MEDIAN+LV          0.0:0/0 0.1:0/0 0.2:0/0 0.3:0/0 0.4:0/0 0.5:0/0 0.6:0/0
    TRIMMED_MEAN+LV    0.0:0/0 0.1:0/0 0.2:0/0 0.3:0/0 0.4:0/0 0.5:0/0 0.6:0/0
    VALIDATION_FILTER  0.0:0/0 0.1:0/0 0.2:0/0 0.3:0/0 0.4:0/0 0.5:0/0 0.6:0/0
    ROOT_QUORUM+LV     0.0:0/0 0.1:0/0 0.2:0/0 0.3:0/0 0.4:0/0 0.5:0/0 0.6:0/0
    ECHO               0.0:0/0 0.1:0/0 0.2:0/0 0.3:0/0 0.4:0/0 0.5:0/0 0.6:0/0
    ECHO true          0.0:6/11 0.1:6/11 0.2:6/11 0.3:6/11 0.4:6/11 0.5:6/11 0.6:6/11
    MEDIAN+LV true     0.0:9/11 0.1:9/11 0.2:6/11 0.3:6/11 0.4:3/11 0.5:3/11 0.6:3/11
    ECHO amplification 0.0:None 0.1:0.0 0.2:0.0 0.3:0.0 0.4:0.0 0.5:0.0 0.6:0.0
    MEDIAN amplif.     0.0:None 0.1:0.0 0.2:0.0 0.3:0.0 0.4:0.0 0.5:0.0 0.6:0.0
    stage6 poison: none bridged
  SYBIL_DECLARED_ROOT
    MAJORITY           S=1:0/4 S=2:4/4 S=4:4/4 S=8:4/4 S=16:4/4 S=32:4/4 S=64:4/4 S=128:4/4
    MEAN               S=1:0/4 S=2:4/4 S=4:4/4 S=8:4/4 S=16:4/4 S=32:4/4 S=64:4/4 S=128:4/4
    MEDIAN             S=1:4/4 S=2:4/4 S=4:4/4 S=8:4/4 S=16:4/4 S=32:4/4 S=64:4/4 S=128:4/4
    TRIMMED_MEAN       S=1:4/4 S=2:4/4 S=4:4/4 S=8:4/4 S=16:4/4 S=32:4/4 S=64:4/4 S=128:4/4
    MEDIAN+LV          S=1:4/4 S=2:4/4 S=4:4/4 S=8:4/4 S=16:4/4 S=32:4/4 S=64:4/4 S=128:4/4
    TRIMMED_MEAN+LV    S=1:4/4 S=2:4/4 S=4:4/4 S=8:4/4 S=16:4/4 S=32:4/4 S=64:4/4 S=128:4/4
    VALIDATION_FILTER  S=1:4/4 S=2:4/4 S=4:4/4 S=8:4/4 S=16:4/4 S=32:4/4 S=64:4/4 S=128:4/4
    ROOT_QUORUM+LV     S=1:0/4 S=2:0/4 S=4:0/4 S=8:0/4 S=16:0/4 S=32:0/4 S=64:0/4 S=128:0/4
    ECHO               S=1:0/4 S=2:0/4 S=4:0/4 S=8:0/4 S=16:0/4 S=32:0/4 S=64:0/4 S=128:0/4
    ECHO true          S=1:6/11 S=2:6/11 S=4:6/11 S=8:6/11 S=16:6/11 S=32:6/11 S=64:6/11 S=128:6/11
    MEDIAN+LV true     S=1:9/11 S=2:9/11 S=4:9/11 S=8:9/11 S=16:9/11 S=32:9/11 S=64:9/11 S=128:9/11
    ECHO amplification S=1:0.0 S=2:0.0 S=4:0.0 S=8:0.0 S=16:0.0 S=32:0.0 S=64:0.0 S=128:0.0
    MEDIAN amplif.     S=1:0.591304347826087 S=2:1.1428571428571428 S=4:2.141732283464567 S=8:3.804195804195804 S=16:6.217142857142857 S=32:6.909090909090909 S=64:6.909090909090909 S=128:6.909090909090909
    stage6 poison: none bridged
  SYBIL_FORGED_ROOTS
    MAJORITY           S=1:0/4 S=2:4/4 S=4:4/4 S=8:4/4 S=16:4/4 S=32:4/4 S=64:4/4 S=128:4/4
    MEAN               S=1:0/4 S=2:4/4 S=4:4/4 S=8:4/4 S=16:4/4 S=32:4/4 S=64:4/4 S=128:4/4
    MEDIAN             S=1:4/4 S=2:4/4 S=4:4/4 S=8:4/4 S=16:4/4 S=32:4/4 S=64:4/4 S=128:4/4
    TRIMMED_MEAN       S=1:4/4 S=2:4/4 S=4:4/4 S=8:4/4 S=16:4/4 S=32:4/4 S=64:4/4 S=128:4/4
    MEDIAN+LV          S=1:4/4 S=2:4/4 S=4:4/4 S=8:4/4 S=16:4/4 S=32:4/4 S=64:4/4 S=128:4/4
    TRIMMED_MEAN+LV    S=1:4/4 S=2:4/4 S=4:4/4 S=8:4/4 S=16:4/4 S=32:4/4 S=64:4/4 S=128:4/4
    VALIDATION_FILTER  S=1:4/4 S=2:4/4 S=4:4/4 S=8:4/4 S=16:4/4 S=32:4/4 S=64:4/4 S=128:4/4
    ROOT_QUORUM+LV     S=1:0/4 S=2:0/4 S=4:0/4 S=8:0/4 S=16:0/4 S=32:0/4 S=64:0/4 S=128:0/4
    ECHO               S=1:0/4 S=2:0/4 S=4:0/4 S=8:0/4 S=16:0/4 S=32:0/4 S=64:0/4 S=128:0/4
    ECHO true          S=1:6/11 S=2:6/11 S=4:6/11 S=8:6/11 S=16:6/11 S=32:6/11 S=64:6/11 S=128:6/11
    MEDIAN+LV true     S=1:9/11 S=2:9/11 S=4:9/11 S=8:9/11 S=16:9/11 S=32:9/11 S=64:9/11 S=128:9/11
    ECHO amplification S=1:0.0 S=2:0.0 S=4:0.0 S=8:0.0 S=16:0.0 S=32:0.0 S=64:0.0 S=128:0.0
    MEDIAN amplif.     S=1:0.591304347826087 S=2:1.1428571428571428 S=4:2.141732283464567 S=8:3.804195804195804 S=16:6.217142857142857 S=32:6.909090909090909 S=64:6.909090909090909 S=128:6.909090909090909
    stage6 poison: none bridged
  SYBIL_ADAPTIVE
    MAJORITY           S=1:0/4 S=2:4/4 S=4:4/4 S=8:4/4 S=16:4/4 S=32:4/4 S=64:4/4 S=128:4/4
    MEAN               S=1:0/4 S=2:4/4 S=4:4/4 S=8:4/4 S=16:4/4 S=32:4/4 S=64:4/4 S=128:4/4
    MEDIAN             S=1:4/4 S=2:4/4 S=4:4/4 S=8:4/4 S=16:4/4 S=32:4/4 S=64:4/4 S=128:4/4
    TRIMMED_MEAN       S=1:4/4 S=2:4/4 S=4:4/4 S=8:4/4 S=16:4/4 S=32:4/4 S=64:4/4 S=128:4/4
    MEDIAN+LV          S=1:4/4 S=2:4/4 S=4:4/4 S=8:4/4 S=16:4/4 S=32:4/4 S=64:4/4 S=128:4/4
    TRIMMED_MEAN+LV    S=1:4/4 S=2:4/4 S=4:4/4 S=8:4/4 S=16:4/4 S=32:4/4 S=64:4/4 S=128:4/4
    VALIDATION_FILTER  S=1:4/4 S=2:4/4 S=4:4/4 S=8:4/4 S=16:4/4 S=32:4/4 S=64:4/4 S=128:4/4
    ROOT_QUORUM+LV     S=1:0/4 S=2:4/4 S=4:4/4 S=8:4/4 S=16:4/4 S=32:4/4 S=64:4/4 S=128:4/4
    ECHO               S=1:0/4 S=2:0/4 S=4:4/4 S=8:4/4 S=16:4/4 S=32:4/4 S=64:4/4 S=128:4/4
    ECHO true          S=1:9/11 S=2:9/11 S=4:9/11 S=8:9/11 S=16:9/11 S=32:9/11 S=64:9/11 S=128:9/11
    MEDIAN+LV true     S=1:9/11 S=2:9/11 S=4:9/11 S=8:9/11 S=16:9/11 S=32:9/11 S=64:9/11 S=128:9/11
    ECHO amplification S=1:4.589831324696037 S=2:4.589831324696037 S=4:8.211814928493796 S=8:9.913996621082696 S=16:11.802668878541594 S=32:12.21869836960528 S=64:12.466740880359497 S=128:11.960348051045122
    MEDIAN amplif.     S=1:2.5954198473282446 S=2:4.5033112582781465 S=4:7.068421052631579 S=8:10.011111111111111 S=16:12.549528301886792 S=32:14.4291553133515 S=64:15.614537444933921 S=128:16.13598901098901
    stage6 poison: ["S=4:{'UNCERTAIN': 12, 'poison_decisions_bridged': 4, 'receipts_evicted': 0}", "S=8:{'UNCERTAIN': 16, 'poison_decisions_bridged': 4, 'receipts_evicted': 0}", "S=16:{'UNCERTAIN': 24, 'poison_decisions_bridged': 4, 'receipts_evicted': 0}", "S=32:{'UNCERTAIN': 23, 'poison_decisions_bridged': 4, 'receipts_evicted': 0}", "S=64:{'UNCERTAIN': 27, 'poison_decisions_bridged': 4, 'receipts_evicted': 0}", "S=128:{'UNCERTAIN': 20, 'poison_decisions_bridged': 4, 'receipts_evicted': 0}"]

[break points] share (or identity share) where poison acceptance >= 0.5
    BYZANTINE_LATENT_POISON    ECHO               None
    BYZANTINE_LATENT_POISON    MAJORITY           0.1
    BYZANTINE_LATENT_POISON    MEAN               0.1
    BYZANTINE_LATENT_POISON    MEDIAN             0.1
    BYZANTINE_LATENT_POISON    MEDIAN+LV          0.1
    BYZANTINE_LATENT_POISON    ROOT_QUORUM+LV     None
    BYZANTINE_LATENT_POISON    TRIMMED_MEAN       0.1
    BYZANTINE_LATENT_POISON    TRIMMED_MEAN+LV    0.1
    BYZANTINE_LATENT_POISON    VALIDATION_FILTER  0.1
    BYZANTINE_POISON           ECHO               None
    BYZANTINE_POISON           MAJORITY           0.1
    BYZANTINE_POISON           MEAN               0.1
    BYZANTINE_POISON           MEDIAN             0.1
    BYZANTINE_POISON           MEDIAN+LV          None
    BYZANTINE_POISON           ROOT_QUORUM+LV     None
    BYZANTINE_POISON           TRIMMED_MEAN       0.1
    BYZANTINE_POISON           TRIMMED_MEAN+LV    None
    BYZANTINE_POISON           VALIDATION_FILTER  None
    BYZANTINE_SUPPRESS         ECHO               None
    BYZANTINE_SUPPRESS         MAJORITY           None
    BYZANTINE_SUPPRESS         MEAN               None
    BYZANTINE_SUPPRESS         MEDIAN             None
    BYZANTINE_SUPPRESS         MEDIAN+LV          None
    BYZANTINE_SUPPRESS         ROOT_QUORUM+LV     None
    BYZANTINE_SUPPRESS         TRIMMED_MEAN       None
    BYZANTINE_SUPPRESS         TRIMMED_MEAN+LV    None
    BYZANTINE_SUPPRESS         VALIDATION_FILTER  None
    COLLUSION_TIMING           ECHO               0.2
    COLLUSION_TIMING           MAJORITY           0.1
    COLLUSION_TIMING           MEAN               0.1
    COLLUSION_TIMING           MEDIAN             0.1
    COLLUSION_TIMING           MEDIAN+LV          0.1
    COLLUSION_TIMING           ROOT_QUORUM+LV     0.1
    COLLUSION_TIMING           TRIMMED_MEAN       0.1
    COLLUSION_TIMING           TRIMMED_MEAN+LV    0.1
    COLLUSION_TIMING           VALIDATION_FILTER  0.1
    SLOW_POISON                ECHO               None
    SLOW_POISON                MAJORITY           0.1
    SLOW_POISON                MEAN               0.1
    SLOW_POISON                MEDIAN             0.1
    SLOW_POISON                MEDIAN+LV          0.1
    SLOW_POISON                ROOT_QUORUM+LV     0.1
    SLOW_POISON                TRIMMED_MEAN       0.1
    SLOW_POISON                TRIMMED_MEAN+LV    0.1
    SLOW_POISON                VALIDATION_FILTER  0.1
    SYBIL_ADAPTIVE             ECHO               0.14285714285714285
    SYBIL_ADAPTIVE             MAJORITY           0.07692307692307693
    SYBIL_ADAPTIVE             MEAN               0.07692307692307693
    SYBIL_ADAPTIVE             MEDIAN             0.04
    SYBIL_ADAPTIVE             MEDIAN+LV          0.04
    SYBIL_ADAPTIVE             ROOT_QUORUM+LV     0.07692307692307693
    SYBIL_ADAPTIVE             TRIMMED_MEAN       0.04
    SYBIL_ADAPTIVE             TRIMMED_MEAN+LV    0.04
    SYBIL_ADAPTIVE             VALIDATION_FILTER  0.04
    SYBIL_DECLARED_ROOT        ECHO               None
    SYBIL_DECLARED_ROOT        MAJORITY           0.07692307692307693
    SYBIL_DECLARED_ROOT        MEAN               0.07692307692307693
    SYBIL_DECLARED_ROOT        MEDIAN             0.04
    SYBIL_DECLARED_ROOT        MEDIAN+LV          0.04
    SYBIL_DECLARED_ROOT        ROOT_QUORUM+LV     None
    SYBIL_DECLARED_ROOT        TRIMMED_MEAN       0.04
    SYBIL_DECLARED_ROOT        TRIMMED_MEAN+LV    0.04
    SYBIL_DECLARED_ROOT        VALIDATION_FILTER  0.04
    SYBIL_FORGED_ROOTS         ECHO               None
    SYBIL_FORGED_ROOTS         MAJORITY           0.07692307692307693
    SYBIL_FORGED_ROOTS         MEAN               0.07692307692307693
    SYBIL_FORGED_ROOTS         MEDIAN             0.04
    SYBIL_FORGED_ROOTS         MEDIAN+LV          0.04
    SYBIL_FORGED_ROOTS         ROOT_QUORUM+LV     None
    SYBIL_FORGED_ROOTS         TRIMMED_MEAN       0.04
    SYBIL_FORGED_ROOTS         TRIMMED_MEAN+LV    0.04
    SYBIL_FORGED_ROOTS         VALIDATION_FILTER  0.04
```

### B.4 Adversary-fraction sweep, 24 receivers (excerpt: NONE detection, then robustness and break points in full)
```
$ PYTHONHASHSEED=0 python benchmarks/stage7/fraction_sweep.py --corpus-seed 7 --seed 0 --all-receivers && python benchmarks/stage7/summarise.py …
######## sweep-c7-all.json: corpus seed 7 fleet seed 0 receivers 24 items 441 positives 81
preconditions: [('P1', 'PASS'), ('P2', 'PASS'), ('P3', 'PASS'), ('P4', 'PASS'), ('P5', 'DEGENERATE_IN_FAVOUR')]
[detection, run_benchmark] method: recall@FPR0.01 (tp/pos, fp/neg) per x
  NONE
    NO_SHARING             0.0:0.086(7/81,fp0/360)
    MAJORITY               0.0:0.000(81/81,fp44/360)
    MEAN                   0.0:0.000(81/81,fp44/360)
    MEDIAN                 0.0:0.000(81/81,fp44/360)
    TRIMMED_MEAN           0.0:0.000(81/81,fp44/360)
    MEDIAN+LV              0.0:0.901(73/81,fp0/360)
    TRIMMED_MEAN+LV        0.0:0.901(73/81,fp0/360)
    VALIDATION_FILTER      0.0:0.901(73/81,fp0/360)
    ROOT_QUORUM            0.0:0.901(73/81,fp0/360)
    ROOT_QUORUM_DECLARED   0.0:0.901(73/81,fp0/360)
    ECHO                   0.0:0.728(59/81,fp0/360)
[robustness, suite] poison accepted/offered per x; ECHO true accepted/offered
  BYZANTINE_POISON
    MAJORITY           0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:24/24 0.5:24/24 0.6:24/24
    MEAN               0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:24/24 0.5:24/24 0.6:24/24
    MEDIAN             0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:24/24 0.5:24/24 0.6:24/24
    TRIMMED_MEAN       0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:24/24 0.5:24/24 0.6:24/24
    MEDIAN+LV          0.0:0/0 0.1:0/24 0.2:0/24 0.3:0/24 0.4:0/24 0.5:0/24 0.6:0/24
    TRIMMED_MEAN+LV    0.0:0/0 0.1:0/24 0.2:0/24 0.3:0/24 0.4:0/24 0.5:0/24 0.6:0/24
    VALIDATION_FILTER  0.0:0/0 0.1:0/24 0.2:0/24 0.3:0/24 0.4:0/24 0.5:0/24 0.6:0/24
    ROOT_QUORUM+LV     0.0:0/0 0.1:0/24 0.2:0/24 0.3:0/24 0.4:0/24 0.5:0/24 0.6:0/24
    ECHO               0.0:0/0 0.1:0/24 0.2:0/24 0.3:0/24 0.4:0/24 0.5:0/24 0.6:0/24
    ECHO true          0.0:45/65 0.1:0/65 0.2:0/65 0.3:0/65 0.4:0/65 0.5:0/65 0.6:0/65
    MEDIAN+LV true     0.0:57/65 0.1:57/65 0.2:57/65 0.3:57/65 0.4:57/65 0.5:57/65 0.6:57/65
    ECHO amplification 0.0:None 0.1:None 0.2:None 0.3:None 0.4:None 0.5:None 0.6:None
    MEDIAN amplif.     0.0:None 0.1:0.6233766233766234 0.2:0.6477732793522267 0.3:0.6789667896678967 0.4:0.712871287128713 0.5:0.7463556851311953 0.6:0.7862407862407863
    stage6 poison: none bridged
  BYZANTINE_LATENT_POISON
    MAJORITY           0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:24/24 0.5:24/24 0.6:24/24
    MEAN               0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:24/24 0.5:24/24 0.6:24/24
    MEDIAN             0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:24/24 0.5:24/24 0.6:24/24
    TRIMMED_MEAN       0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:24/24 0.5:24/24 0.6:24/24
    MEDIAN+LV          0.0:0/0 0.1:22/24 0.2:22/24 0.3:22/24 0.4:22/24 0.5:22/24 0.6:22/24
    TRIMMED_MEAN+LV    0.0:0/0 0.1:22/24 0.2:22/24 0.3:22/24 0.4:22/24 0.5:22/24 0.6:22/24
    VALIDATION_FILTER  0.0:0/0 0.1:22/24 0.2:22/24 0.3:22/24 0.4:22/24 0.5:22/24 0.6:22/24
    ROOT_QUORUM+LV     0.0:0/0 0.1:0/24 0.2:0/24 0.3:0/24 0.4:0/24 0.5:0/24 0.6:0/24
    ECHO               0.0:0/0 0.1:0/24 0.2:0/24 0.3:0/24 0.4:0/24 0.5:0/24 0.6:0/24
    ECHO true          0.0:45/65 0.1:45/65 0.2:45/65 0.3:45/65 0.4:45/65 0.5:45/65 0.6:45/65
    MEDIAN+LV true     0.0:57/65 0.1:57/65 0.2:57/65 0.3:57/65 0.4:57/65 0.5:57/65 0.6:57/65
    ECHO amplification 0.0:None 0.1:0.0 0.2:0.0 0.3:0.0 0.4:0.0 0.5:0.0 0.6:0.0
    MEDIAN amplif.     0.0:None 0.1:0.5917808219178082 0.2:0.6169665809768637 0.3:0.6494117647058822 0.4:0.6849894291754757 0.5:0.7204502814258912 0.6:0.7631160572337043
    stage6 poison: none bridged
  SLOW_POISON
    MAJORITY           0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:0/0 0.5:0/0 0.6:0/0
    MEAN               0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:0/0 0.5:0/0 0.6:0/0
    MEDIAN             0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:0/0 0.5:0/0 0.6:0/0
    TRIMMED_MEAN       0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:0/0 0.5:0/0 0.6:0/0
    MEDIAN+LV          0.0:0/0 0.1:22/24 0.2:22/24 0.3:22/24 0.4:0/0 0.5:0/0 0.6:0/0
    TRIMMED_MEAN+LV    0.0:0/0 0.1:22/24 0.2:22/24 0.3:22/24 0.4:0/0 0.5:0/0 0.6:0/0
    VALIDATION_FILTER  0.0:0/0 0.1:22/24 0.2:22/24 0.3:22/24 0.4:0/0 0.5:0/0 0.6:0/0
    ROOT_QUORUM+LV     0.0:0/0 0.1:6/24 0.2:4/24 0.3:0/24 0.4:0/0 0.5:0/0 0.6:0/0
    ECHO               0.0:0/0 0.1:2/24 0.2:2/24 0.3:0/24 0.4:0/0 0.5:0/0 0.6:0/0
    ECHO true          0.0:45/65 0.1:57/65 0.2:57/65 0.3:57/65 0.4:57/65 0.5:57/65 0.6:57/65
    MEDIAN+LV true     0.0:57/65 0.1:57/65 0.2:57/65 0.3:57/65 0.4:57/65 0.5:57/65 0.6:57/65
    ECHO amplification 0.0:None 0.1:3.056024847163722 0.2:1.8294081571963507 0.3:0.9215617412010847 0.4:0.6903617308222034 0.5:0.5625905281039781 0.6:0.46876413821260726
    MEDIAN amplif.     0.0:None 0.1:2.3427331887201737 0.2:2.065404475043029 0.3:1.8134034165571615 0.4:1.4141476919599978 0.5:1.303370786516854 0.6:1.2040428707095374
    stage6 poison: ["0.1:{'UNCERTAIN': 4, 'poison_decisions_bridged': 2, 'receipts_evicted': 0}", "0.2:{'UNCERTAIN': 4, 'poison_decisions_bridged': 2, 'receipts_evicted': 0}"]
  COLLUSION_TIMING
    MAJORITY           0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:24/24 0.5:24/24 0.6:24/24
    MEAN               0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:24/24 0.5:24/24 0.6:24/24
    MEDIAN             0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:24/24 0.5:24/24 0.6:24/24
    TRIMMED_MEAN       0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:24/24 0.5:24/24 0.6:24/24
    MEDIAN+LV          0.0:0/0 0.1:22/24 0.2:22/24 0.3:22/24 0.4:22/24 0.5:22/24 0.6:22/24
    TRIMMED_MEAN+LV    0.0:0/0 0.1:22/24 0.2:22/24 0.3:22/24 0.4:22/24 0.5:22/24 0.6:22/24
    VALIDATION_FILTER  0.0:0/0 0.1:22/24 0.2:22/24 0.3:22/24 0.4:22/24 0.5:22/24 0.6:22/24
    ROOT_QUORUM+LV     0.0:0/0 0.1:22/24 0.2:22/24 0.3:22/24 0.4:0/24 0.5:0/24 0.6:0/24
    ECHO               0.0:0/0 0.1:8/24 0.2:22/24 0.3:22/24 0.4:0/24 0.5:0/24 0.6:0/24
    ECHO true          0.0:45/65 0.1:45/65 0.2:45/65 0.3:45/65 0.4:45/65 0.5:45/65 0.6:45/65
    MEDIAN+LV true     0.0:57/65 0.1:57/65 0.2:57/65 0.3:57/65 0.4:57/65 0.5:57/65 0.6:57/65
    ECHO amplification 0.0:None 0.1:1.0596813836960126 0.2:1.9881676217652735 0.3:1.7569852307350213 0.4:0.0 0.5:0.0 0.6:0.0
    MEDIAN amplif.     0.0:None 0.1:0.5917808219178082 0.2:0.6169665809768637 0.3:0.6494117647058822 0.4:0.6849894291754757 0.5:0.7204502814258912 0.6:0.7631160572337043
    stage6 poison: ["0.1:{'UNCERTAIN': 16, 'poison_decisions_bridged': 8, 'receipts_evicted': 0}", "0.2:{'UNCERTAIN': 88, 'poison_decisions_bridged': 22, 'receipts_evicted': 0}", "0.3:{'UNCERTAIN': 154, 'poison_decisions_bridged': 22, 'receipts_evicted': 0}"]
  BYZANTINE_SUPPRESS
    MAJORITY           0.0:0/0 0.1:0/0 0.2:0/0 0.3:0/0 0.4:0/0 0.5:0/0 0.6:0/0
    MEAN               0.0:0/0 0.1:0/0 0.2:0/0 0.3:0/0 0.4:0/0 0.5:0/0 0.6:0/0
    MEDIAN             0.0:0/0 0.1:0/0 0.2:0/0 0.3:0/0 0.4:0/0 0.5:0/0 0.6:0/0
    TRIMMED_MEAN       0.0:0/0 0.1:0/0 0.2:0/0 0.3:0/0 0.4:0/0 0.5:0/0 0.6:0/0
    MEDIAN+LV          0.0:0/0 0.1:0/0 0.2:0/0 0.3:0/0 0.4:0/0 0.5:0/0 0.6:0/0
    TRIMMED_MEAN+LV    0.0:0/0 0.1:0/0 0.2:0/0 0.3:0/0 0.4:0/0 0.5:0/0 0.6:0/0
    VALIDATION_FILTER  0.0:0/0 0.1:0/0 0.2:0/0 0.3:0/0 0.4:0/0 0.5:0/0 0.6:0/0
    ROOT_QUORUM+LV     0.0:0/0 0.1:0/0 0.2:0/0 0.3:0/0 0.4:0/0 0.5:0/0 0.6:0/0
    ECHO               0.0:0/0 0.1:0/0 0.2:0/0 0.3:0/0 0.4:0/0 0.5:0/0 0.6:0/0
    ECHO true          0.0:45/65 0.1:45/65 0.2:45/65 0.3:45/65 0.4:45/65 0.5:45/65 0.6:45/65
    MEDIAN+LV true     0.0:57/65 0.1:57/65 0.2:43/65 0.3:37/65 0.4:12/65 0.5:12/65 0.6:12/65
    ECHO amplification 0.0:None 0.1:0.0 0.2:0.0 0.3:0.0 0.4:0.0 0.5:0.0 0.6:0.0
    MEDIAN amplif.     0.0:None 0.1:0.0 0.2:0.0 0.3:0.0 0.4:0.0 0.5:0.0 0.6:0.0
    stage6 poison: none bridged
  SYBIL_DECLARED_ROOT
    MAJORITY           S=1:0/24 S=2:24/24 S=4:24/24 S=8:24/24 S=16:24/24 S=32:24/24 S=64:24/24 S=128:24/24
    MEAN               S=1:0/24 S=2:24/24 S=4:24/24 S=8:24/24 S=16:24/24 S=32:24/24 S=64:24/24 S=128:24/24
    MEDIAN             S=1:24/24 S=2:24/24 S=4:24/24 S=8:24/24 S=16:24/24 S=32:24/24 S=64:24/24 S=128:24/24
    TRIMMED_MEAN       S=1:24/24 S=2:24/24 S=4:24/24 S=8:24/24 S=16:24/24 S=32:24/24 S=64:24/24 S=128:24/24
    MEDIAN+LV          S=1:22/24 S=2:22/24 S=4:22/24 S=8:22/24 S=16:22/24 S=32:22/24 S=64:22/24 S=128:22/24
    TRIMMED_MEAN+LV    S=1:22/24 S=2:22/24 S=4:22/24 S=8:22/24 S=16:22/24 S=32:22/24 S=64:22/24 S=128:22/24
    VALIDATION_FILTER  S=1:22/24 S=2:22/24 S=4:22/24 S=8:22/24 S=16:22/24 S=32:22/24 S=64:22/24 S=128:22/24
    ROOT_QUORUM+LV     S=1:0/24 S=2:0/24 S=4:0/24 S=8:0/24 S=16:0/24 S=32:0/24 S=64:0/24 S=128:0/24
    ECHO               S=1:0/24 S=2:0/24 S=4:0/24 S=8:0/24 S=16:0/24 S=32:0/24 S=64:0/24 S=128:0/24
    ECHO true          S=1:45/65 S=2:45/65 S=4:45/65 S=8:45/65 S=16:45/65 S=32:45/65 S=64:45/65 S=128:45/65
    MEDIAN+LV true     S=1:57/65 S=2:57/65 S=4:57/65 S=8:57/65 S=16:57/65 S=32:57/65 S=64:57/65 S=128:57/65
    ECHO amplification S=1:0.0 S=2:0.0 S=4:0.0 S=8:0.0 S=16:0.0 S=32:0.0 S=64:0.0 S=128:0.0
    MEDIAN amplif.     S=1:0.5779036827195468 S=2:1.117808219178082 S=4:2.0976863753213366 S=8:3.734553775743707 S=16:6.123827392120075 S=32:6.721631205673758 S=64:6.721631205673758 S=128:6.721631205673758
    stage6 poison: none bridged
  SYBIL_FORGED_ROOTS
    MAJORITY           S=1:0/24 S=2:24/24 S=4:24/24 S=8:24/24 S=16:24/24 S=32:24/24 S=64:24/24 S=128:24/24
    MEAN               S=1:0/24 S=2:24/24 S=4:24/24 S=8:24/24 S=16:24/24 S=32:24/24 S=64:24/24 S=128:24/24
    MEDIAN             S=1:24/24 S=2:24/24 S=4:24/24 S=8:24/24 S=16:24/24 S=32:24/24 S=64:24/24 S=128:24/24
    TRIMMED_MEAN       S=1:24/24 S=2:24/24 S=4:24/24 S=8:24/24 S=16:24/24 S=32:24/24 S=64:24/24 S=128:24/24
    MEDIAN+LV          S=1:22/24 S=2:22/24 S=4:22/24 S=8:22/24 S=16:22/24 S=32:22/24 S=64:22/24 S=128:22/24
    TRIMMED_MEAN+LV    S=1:22/24 S=2:22/24 S=4:22/24 S=8:22/24 S=16:22/24 S=32:22/24 S=64:22/24 S=128:22/24
    VALIDATION_FILTER  S=1:22/24 S=2:22/24 S=4:22/24 S=8:22/24 S=16:22/24 S=32:22/24 S=64:22/24 S=128:22/24
    ROOT_QUORUM+LV     S=1:0/24 S=2:0/24 S=4:0/24 S=8:0/24 S=16:0/24 S=32:0/24 S=64:0/24 S=128:0/24
    ECHO               S=1:0/24 S=2:0/24 S=4:0/24 S=8:0/24 S=16:0/24 S=32:0/24 S=64:0/24 S=128:0/24
    ECHO true          S=1:45/65 S=2:45/65 S=4:45/65 S=8:45/65 S=16:45/65 S=32:45/65 S=64:45/65 S=128:45/65
    MEDIAN+LV true     S=1:57/65 S=2:57/65 S=4:57/65 S=8:57/65 S=16:57/65 S=32:57/65 S=64:57/65 S=128:57/65
    ECHO amplification S=1:0.0 S=2:0.0 S=4:0.0 S=8:0.0 S=16:0.0 S=32:0.0 S=64:0.0 S=128:0.0
    MEDIAN amplif.     S=1:0.5779036827195468 S=2:1.117808219178082 S=4:2.0976863753213366 S=8:3.734553775743707 S=16:6.123827392120075 S=32:6.721631205673758 S=64:6.721631205673758 S=128:6.721631205673758
    stage6 poison: none bridged
  SYBIL_ADAPTIVE
    MAJORITY           S=1:0/24 S=2:24/24 S=4:24/24 S=8:24/24 S=16:24/24 S=32:24/24 S=64:24/24 S=128:24/24
    MEAN               S=1:0/24 S=2:24/24 S=4:24/24 S=8:24/24 S=16:24/24 S=32:24/24 S=64:24/24 S=128:24/24
    MEDIAN             S=1:24/24 S=2:24/24 S=4:24/24 S=8:24/24 S=16:24/24 S=32:24/24 S=64:24/24 S=128:24/24
    TRIMMED_MEAN       S=1:24/24 S=2:24/24 S=4:24/24 S=8:24/24 S=16:24/24 S=32:24/24 S=64:24/24 S=128:24/24
    MEDIAN+LV          S=1:22/24 S=2:22/24 S=4:22/24 S=8:22/24 S=16:22/24 S=32:22/24 S=64:22/24 S=128:22/24
    TRIMMED_MEAN+LV    S=1:22/24 S=2:22/24 S=4:22/24 S=8:22/24 S=16:22/24 S=32:22/24 S=64:22/24 S=128:22/24
    VALIDATION_FILTER  S=1:22/24 S=2:22/24 S=4:22/24 S=8:22/24 S=16:22/24 S=32:22/24 S=64:22/24 S=128:22/24
    ROOT_QUORUM+LV     S=1:0/24 S=2:22/24 S=4:22/24 S=8:22/24 S=16:22/24 S=32:22/24 S=64:22/24 S=128:22/24
    ECHO               S=1:0/24 S=2:1/24 S=4:22/24 S=8:22/24 S=16:22/24 S=32:22/24 S=64:22/24 S=128:22/24
    ECHO true          S=1:57/65 S=2:57/65 S=4:57/65 S=8:57/65 S=16:57/65 S=32:57/65 S=64:57/65 S=128:57/65
    MEDIAN+LV true     S=1:57/65 S=2:57/65 S=4:57/65 S=8:57/65 S=16:57/65 S=32:57/65 S=64:57/65 S=128:57/65
    ECHO amplification S=1:4.449359333367047 S=2:4.579595224152472 S=4:7.922162034806605 S=8:9.452358838766454 S=16:11.375197481570034 S=32:12.234244176098121 S=64:12.235272602411722 S=128:12.119037320047607
    MEDIAN amplif.     S=1:2.543640897755611 S=2:4.425162689804772 S=4:6.9879101899827285 S=8:9.921855921855922 S=16:12.481683554169914 S=32:14.373357498867241 S=64:15.584371184371184 S=128:16.121000758150114
    stage6 poison: ["S=2:{'UNCERTAIN': 2, 'poison_decisions_bridged': 1, 'receipts_evicted': 0}", "S=4:{'UNCERTAIN': 66, 'poison_decisions_bridged': 22, 'receipts_evicted': 0}", "S=8:{'UNCERTAIN': 88, 'poison_decisions_bridged': 22, 'receipts_evicted': 0}", "S=16:{'UNCERTAIN': 132, 'poison_decisions_bridged': 22, 'receipts_evicted': 0}", "S=32:{'UNCERTAIN': 130, 'poison_decisions_bridged': 22, 'receipts_evicted': 0}", "S=64:{'UNCERTAIN': 134, 'poison_decisions_bridged': 22, 'receipts_evicted': 0}", "S=128:{'UNCERTAIN': 118, 'poison_decisions_bridged': 22, 'receipts_evicted': 0}"]

[break points] share (or identity share) where poison acceptance >= 0.5
    BYZANTINE_LATENT_POISON    ECHO               None
    BYZANTINE_LATENT_POISON    MAJORITY           0.1
    BYZANTINE_LATENT_POISON    MEAN               0.1
    BYZANTINE_LATENT_POISON    MEDIAN             0.1
    BYZANTINE_LATENT_POISON    MEDIAN+LV          0.1
    BYZANTINE_LATENT_POISON    ROOT_QUORUM+LV     None
    BYZANTINE_LATENT_POISON    TRIMMED_MEAN       0.1
    BYZANTINE_LATENT_POISON    TRIMMED_MEAN+LV    0.1
    BYZANTINE_LATENT_POISON    VALIDATION_FILTER  0.1
    BYZANTINE_POISON           ECHO               None
    BYZANTINE_POISON           MAJORITY           0.1
    BYZANTINE_POISON           MEAN               0.1
    BYZANTINE_POISON           MEDIAN             0.1
    BYZANTINE_POISON           MEDIAN+LV          None
    BYZANTINE_POISON           ROOT_QUORUM+LV     None
    BYZANTINE_POISON           TRIMMED_MEAN       0.1
    BYZANTINE_POISON           TRIMMED_MEAN+LV    None
    BYZANTINE_POISON           VALIDATION_FILTER  None
    BYZANTINE_SUPPRESS         ECHO               None
    BYZANTINE_SUPPRESS         MAJORITY           None
    BYZANTINE_SUPPRESS         MEAN               None
    BYZANTINE_SUPPRESS         MEDIAN             None
    BYZANTINE_SUPPRESS         MEDIAN+LV          None
    BYZANTINE_SUPPRESS         ROOT_QUORUM+LV     None
    BYZANTINE_SUPPRESS         TRIMMED_MEAN       None
    BYZANTINE_SUPPRESS         TRIMMED_MEAN+LV    None
    BYZANTINE_SUPPRESS         VALIDATION_FILTER  None
    COLLUSION_TIMING           ECHO               0.2
    COLLUSION_TIMING           MAJORITY           0.1
    COLLUSION_TIMING           MEAN               0.1
    COLLUSION_TIMING           MEDIAN             0.1
    COLLUSION_TIMING           MEDIAN+LV          0.1
    COLLUSION_TIMING           ROOT_QUORUM+LV     0.1
    COLLUSION_TIMING           TRIMMED_MEAN       0.1
    COLLUSION_TIMING           TRIMMED_MEAN+LV    0.1
    COLLUSION_TIMING           VALIDATION_FILTER  0.1
    SLOW_POISON                ECHO               None
    SLOW_POISON                MAJORITY           0.1
    SLOW_POISON                MEAN               0.1
    SLOW_POISON                MEDIAN             0.1
    SLOW_POISON                MEDIAN+LV          0.1
    SLOW_POISON                ROOT_QUORUM+LV     None
    SLOW_POISON                TRIMMED_MEAN       0.1
    SLOW_POISON                TRIMMED_MEAN+LV    0.1
    SLOW_POISON                VALIDATION_FILTER  0.1
    SYBIL_ADAPTIVE             ECHO               0.14285714285714285
    SYBIL_ADAPTIVE             MAJORITY           0.07692307692307693
    SYBIL_ADAPTIVE             MEAN               0.07692307692307693
    SYBIL_ADAPTIVE             MEDIAN             0.04
    SYBIL_ADAPTIVE             MEDIAN+LV          0.04
    SYBIL_ADAPTIVE             ROOT_QUORUM+LV     0.07692307692307693
    SYBIL_ADAPTIVE             TRIMMED_MEAN       0.04
    SYBIL_ADAPTIVE             TRIMMED_MEAN+LV    0.04
    SYBIL_ADAPTIVE             VALIDATION_FILTER  0.04
    SYBIL_DECLARED_ROOT        ECHO               None
    SYBIL_DECLARED_ROOT        MAJORITY           0.07692307692307693
    SYBIL_DECLARED_ROOT        MEAN               0.07692307692307693
    SYBIL_DECLARED_ROOT        MEDIAN             0.04
    SYBIL_DECLARED_ROOT        MEDIAN+LV          0.04
    SYBIL_DECLARED_ROOT        ROOT_QUORUM+LV     None
    SYBIL_DECLARED_ROOT        TRIMMED_MEAN       0.04
    SYBIL_DECLARED_ROOT        TRIMMED_MEAN+LV    0.04
    SYBIL_DECLARED_ROOT        VALIDATION_FILTER  0.04
    SYBIL_FORGED_ROOTS         ECHO               None
    SYBIL_FORGED_ROOTS         MAJORITY           0.07692307692307693
    SYBIL_FORGED_ROOTS         MEAN               0.07692307692307693
    SYBIL_FORGED_ROOTS         MEDIAN             0.04
    SYBIL_FORGED_ROOTS         MEDIAN+LV          0.04
    SYBIL_FORGED_ROOTS         ROOT_QUORUM+LV     None
    SYBIL_FORGED_ROOTS         TRIMMED_MEAN       0.04
    SYBIL_FORGED_ROOTS         TRIMMED_MEAN+LV    0.04
    SYBIL_FORGED_ROOTS         VALIDATION_FILTER  0.04
```
```
$ PYTHONHASHSEED=0 python benchmarks/stage7/fraction_sweep.py --corpus-seed 11 --seed 1 --all-receivers && python benchmarks/stage7/summarise.py …
######## sweep-c11-all.json: corpus seed 11 fleet seed 1 receivers 24 items 434 positives 74
preconditions: [('P1', 'PASS'), ('P2', 'PASS'), ('P3', 'PASS'), ('P4', 'PASS'), ('P5', 'DEGENERATE_IN_FAVOUR')]
[detection, run_benchmark] method: recall@FPR0.01 (tp/pos, fp/neg) per x
  NONE
    NO_SHARING             0.0:0.162(12/74,fp0/360)
    MAJORITY               0.0:0.000(74/74,fp45/360)
    MEAN                   0.0:0.000(74/74,fp45/360)
    MEDIAN                 0.0:0.000(74/74,fp45/360)
    TRIMMED_MEAN           0.0:0.000(74/74,fp45/360)
    MEDIAN+LV              0.0:0.905(67/74,fp0/360)
    TRIMMED_MEAN+LV        0.0:0.905(67/74,fp0/360)
    VALIDATION_FILTER      0.0:0.905(67/74,fp0/360)
    ROOT_QUORUM            0.0:0.905(67/74,fp0/360)
    ROOT_QUORUM_DECLARED   0.0:0.905(67/74,fp0/360)
    ECHO                   0.0:0.432(32/74,fp0/360)
[robustness, suite] poison accepted/offered per x; ECHO true accepted/offered
  BYZANTINE_POISON
    MAJORITY           0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:24/24 0.5:24/24 0.6:24/24
    MEAN               0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:24/24 0.5:24/24 0.6:24/24
    MEDIAN             0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:24/24 0.5:24/24 0.6:24/24
    TRIMMED_MEAN       0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:24/24 0.5:24/24 0.6:24/24
    MEDIAN+LV          0.0:0/0 0.1:0/24 0.2:0/24 0.3:0/24 0.4:0/24 0.5:0/24 0.6:0/24
    TRIMMED_MEAN+LV    0.0:0/0 0.1:0/24 0.2:0/24 0.3:0/24 0.4:0/24 0.5:0/24 0.6:0/24
    VALIDATION_FILTER  0.0:0/0 0.1:0/24 0.2:0/24 0.3:0/24 0.4:0/24 0.5:0/24 0.6:0/24
    ROOT_QUORUM+LV     0.0:0/0 0.1:0/24 0.2:0/24 0.3:0/24 0.4:0/24 0.5:0/24 0.6:0/24
    ECHO               0.0:0/0 0.1:0/24 0.2:0/24 0.3:0/24 0.4:0/24 0.5:0/24 0.6:0/24
    ECHO true          0.0:20/60 0.1:0/60 0.2:0/60 0.3:0/60 0.4:0/60 0.5:0/60 0.6:0/60
    MEDIAN+LV true     0.0:52/60 0.1:52/60 0.2:52/60 0.3:52/60 0.4:52/60 0.5:52/60 0.6:52/60
    ECHO amplification 0.0:None 0.1:None 0.2:None 0.3:None 0.4:None 0.5:None 0.6:None
    MEDIAN amplif.     0.0:None 0.1:0.6771159874608151 0.2:0.6997084548104956 0.3:0.7282321899736147 0.4:0.7587822014051523 0.5:0.7885010266940452 0.6:0.823327615780446
    stage6 poison: none bridged
  BYZANTINE_LATENT_POISON
    MAJORITY           0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:24/24 0.5:24/24 0.6:24/24
    MEAN               0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:24/24 0.5:24/24 0.6:24/24
    MEDIAN             0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:24/24 0.5:24/24 0.6:24/24
    TRIMMED_MEAN       0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:24/24 0.5:24/24 0.6:24/24
    MEDIAN+LV          0.0:0/0 0.1:22/24 0.2:22/24 0.3:22/24 0.4:22/24 0.5:22/24 0.6:22/24
    TRIMMED_MEAN+LV    0.0:0/0 0.1:22/24 0.2:22/24 0.3:22/24 0.4:22/24 0.5:22/24 0.6:22/24
    VALIDATION_FILTER  0.0:0/0 0.1:22/24 0.2:22/24 0.3:22/24 0.4:22/24 0.5:22/24 0.6:22/24
    ROOT_QUORUM+LV     0.0:0/0 0.1:0/24 0.2:0/24 0.3:0/24 0.4:0/24 0.5:0/24 0.6:0/24
    ECHO               0.0:0/0 0.1:0/24 0.2:0/24 0.3:0/24 0.4:0/24 0.5:0/24 0.6:0/24
    ECHO true          0.0:20/60 0.1:20/60 0.2:20/60 0.3:20/60 0.4:20/60 0.5:20/60 0.6:20/60
    MEDIAN+LV true     0.0:52/60 0.1:52/60 0.2:52/60 0.3:52/60 0.4:52/60 0.5:52/60 0.6:52/60
    ECHO amplification 0.0:None 0.1:0.0 0.2:0.0 0.3:0.0 0.4:0.0 0.5:0.0 0.6:0.0
    MEDIAN amplif.     0.0:None 0.1:0.6297376093294461 0.2:0.653950953678474 0.3:0.6848635235732009 0.4:0.7184035476718403 0.5:0.7514677103718199 0.6:0.7907742998352554
    stage6 poison: none bridged
  SLOW_POISON
    MAJORITY           0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:0/0 0.5:0/0 0.6:0/0
    MEAN               0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:0/0 0.5:0/0 0.6:0/0
    MEDIAN             0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:0/0 0.5:0/0 0.6:0/0
    TRIMMED_MEAN       0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:0/0 0.5:0/0 0.6:0/0
    MEDIAN+LV          0.0:0/0 0.1:22/24 0.2:22/24 0.3:22/24 0.4:0/0 0.5:0/0 0.6:0/0
    TRIMMED_MEAN+LV    0.0:0/0 0.1:22/24 0.2:22/24 0.3:22/24 0.4:0/0 0.5:0/0 0.6:0/0
    VALIDATION_FILTER  0.0:0/0 0.1:22/24 0.2:22/24 0.3:22/24 0.4:0/0 0.5:0/0 0.6:0/0
    ROOT_QUORUM+LV     0.0:0/0 0.1:16/24 0.2:12/24 0.3:12/24 0.4:0/0 0.5:0/0 0.6:0/0
    ECHO               0.0:0/0 0.1:0/24 0.2:1/24 0.3:5/24 0.4:0/0 0.5:0/0 0.6:0/0
    ECHO true          0.0:20/60 0.1:52/60 0.2:52/60 0.3:52/60 0.4:52/60 0.5:52/60 0.6:52/60
    MEDIAN+LV true     0.0:52/60 0.1:52/60 0.2:52/60 0.3:52/60 0.4:52/60 0.5:52/60 0.6:52/60
    ECHO amplification 0.0:None 0.1:3.921712412052309 0.2:2.6166263416442486 0.3:2.0450636788254464 0.4:1.2384141697810342 0.5:0.6784497663388172 0.6:0.565304737399978
    MEDIAN amplif.     0.0:None 0.1:2.4601366742596813 0.2:2.146690518783542 0.3:1.8673883626522327 0.4:1.5008304728158566 0.5:1.3738959764474976 0.6:1.2406517094017095
    stage6 poison: ["0.2:{'UNCERTAIN': 2, 'poison_decisions_bridged': 1, 'receipts_evicted': 0}", "0.3:{'UNCERTAIN': 10, 'poison_decisions_bridged': 5, 'receipts_evicted': 0}"]
  COLLUSION_TIMING
    MAJORITY           0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:24/24 0.5:24/24 0.6:24/24
    MEAN               0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:24/24 0.5:24/24 0.6:24/24
    MEDIAN             0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:24/24 0.5:24/24 0.6:24/24
    TRIMMED_MEAN       0.0:0/0 0.1:24/24 0.2:24/24 0.3:24/24 0.4:24/24 0.5:24/24 0.6:24/24
    MEDIAN+LV          0.0:0/0 0.1:22/24 0.2:22/24 0.3:22/24 0.4:22/24 0.5:22/24 0.6:22/24
    TRIMMED_MEAN+LV    0.0:0/0 0.1:22/24 0.2:22/24 0.3:22/24 0.4:22/24 0.5:22/24 0.6:22/24
    VALIDATION_FILTER  0.0:0/0 0.1:22/24 0.2:22/24 0.3:22/24 0.4:22/24 0.5:22/24 0.6:22/24
    ROOT_QUORUM+LV     0.0:0/0 0.1:22/24 0.2:22/24 0.3:22/24 0.4:0/24 0.5:0/24 0.6:0/24
    ECHO               0.0:0/0 0.1:0/24 0.2:22/24 0.3:22/24 0.4:0/24 0.5:0/24 0.6:0/24
    ECHO true          0.0:20/60 0.1:20/60 0.2:20/60 0.3:20/60 0.4:20/60 0.5:20/60 0.6:20/60
    MEDIAN+LV true     0.0:52/60 0.1:52/60 0.2:52/60 0.3:52/60 0.4:52/60 0.5:52/60 0.6:52/60
    ECHO amplification 0.0:None 0.1:0.0 0.2:3.0098589055991476 0.3:2.3892965546397718 0.4:0.0 0.5:0.0 0.6:0.0
    MEDIAN amplif.     0.0:None 0.1:0.6297376093294461 0.2:0.653950953678474 0.3:0.6848635235732009 0.4:0.7184035476718403 0.5:0.7514677103718199 0.6:0.7907742998352554
    stage6 poison: ["0.2:{'UNCERTAIN': 88, 'poison_decisions_bridged': 22, 'receipts_evicted': 0}", "0.3:{'UNCERTAIN': 154, 'poison_decisions_bridged': 22, 'receipts_evicted': 0}"]
  BYZANTINE_SUPPRESS
    MAJORITY           0.0:0/0 0.1:0/0 0.2:0/0 0.3:0/0 0.4:0/0 0.5:0/0 0.6:0/0
    MEAN               0.0:0/0 0.1:0/0 0.2:0/0 0.3:0/0 0.4:0/0 0.5:0/0 0.6:0/0
    MEDIAN             0.0:0/0 0.1:0/0 0.2:0/0 0.3:0/0 0.4:0/0 0.5:0/0 0.6:0/0
    TRIMMED_MEAN       0.0:0/0 0.1:0/0 0.2:0/0 0.3:0/0 0.4:0/0 0.5:0/0 0.6:0/0
    MEDIAN+LV          0.0:0/0 0.1:0/0 0.2:0/0 0.3:0/0 0.4:0/0 0.5:0/0 0.6:0/0
    TRIMMED_MEAN+LV    0.0:0/0 0.1:0/0 0.2:0/0 0.3:0/0 0.4:0/0 0.5:0/0 0.6:0/0
    VALIDATION_FILTER  0.0:0/0 0.1:0/0 0.2:0/0 0.3:0/0 0.4:0/0 0.5:0/0 0.6:0/0
    ROOT_QUORUM+LV     0.0:0/0 0.1:0/0 0.2:0/0 0.3:0/0 0.4:0/0 0.5:0/0 0.6:0/0
    ECHO               0.0:0/0 0.1:0/0 0.2:0/0 0.3:0/0 0.4:0/0 0.5:0/0 0.6:0/0
    ECHO true          0.0:20/60 0.1:20/60 0.2:20/60 0.3:20/60 0.4:20/60 0.5:20/60 0.6:20/60
    MEDIAN+LV true     0.0:52/60 0.1:52/60 0.2:52/60 0.3:32/60 0.4:24/60 0.5:24/60 0.6:24/60
    ECHO amplification 0.0:None 0.1:0.0 0.2:0.0 0.3:0.0 0.4:0.0 0.5:0.0 0.6:0.0
    MEDIAN amplif.     0.0:None 0.1:0.0 0.2:0.0 0.3:0.0 0.4:0.0 0.5:0.0 0.6:0.0
    stage6 poison: none bridged
  SYBIL_DECLARED_ROOT
    MAJORITY           S=1:0/24 S=2:24/24 S=4:24/24 S=8:24/24 S=16:24/24 S=32:24/24 S=64:24/24 S=128:24/24
    MEAN               S=1:0/24 S=2:24/24 S=4:24/24 S=8:24/24 S=16:24/24 S=32:24/24 S=64:24/24 S=128:24/24
    MEDIAN             S=1:24/24 S=2:24/24 S=4:24/24 S=8:24/24 S=16:24/24 S=32:24/24 S=64:24/24 S=128:24/24
    TRIMMED_MEAN       S=1:24/24 S=2:24/24 S=4:24/24 S=8:24/24 S=16:24/24 S=32:24/24 S=64:24/24 S=128:24/24
    MEDIAN+LV          S=1:22/24 S=2:22/24 S=4:22/24 S=8:22/24 S=16:22/24 S=32:22/24 S=64:22/24 S=128:22/24
    TRIMMED_MEAN+LV    S=1:22/24 S=2:22/24 S=4:22/24 S=8:22/24 S=16:22/24 S=32:22/24 S=64:22/24 S=128:22/24
    VALIDATION_FILTER  S=1:22/24 S=2:22/24 S=4:22/24 S=8:22/24 S=16:22/24 S=32:22/24 S=64:22/24 S=128:22/24
    ROOT_QUORUM+LV     S=1:0/24 S=2:0/24 S=4:0/24 S=8:0/24 S=16:0/24 S=32:0/24 S=64:0/24 S=128:0/24
    ECHO               S=1:0/24 S=2:0/24 S=4:0/24 S=8:0/24 S=16:0/24 S=32:0/24 S=64:0/24 S=128:0/24
    ECHO true          S=1:20/60 S=2:20/60 S=4:20/60 S=8:20/60 S=16:20/60 S=32:20/60 S=64:20/60 S=128:20/60
    MEDIAN+LV true     S=1:52/60 S=2:52/60 S=4:52/60 S=8:52/60 S=16:52/60 S=32:52/60 S=64:52/60 S=128:52/60
    ECHO amplification S=1:0.0 S=2:0.0 S=4:0.0 S=8:0.0 S=16:0.0 S=32:0.0 S=64:0.0 S=128:0.0
    MEDIAN amplif.     S=1:0.6163141993957705 S=2:1.1895043731778425 S=4:2.223433242506812 S=8:3.932530120481928 S=16:6.387475538160469 S=32:6.9944649446494465 S=64:6.9944649446494465 S=128:6.9944649446494465
    stage6 poison: none bridged
  SYBIL_FORGED_ROOTS
    MAJORITY           S=1:0/24 S=2:24/24 S=4:24/24 S=8:24/24 S=16:24/24 S=32:24/24 S=64:24/24 S=128:24/24
    MEAN               S=1:0/24 S=2:24/24 S=4:24/24 S=8:24/24 S=16:24/24 S=32:24/24 S=64:24/24 S=128:24/24
    MEDIAN             S=1:24/24 S=2:24/24 S=4:24/24 S=8:24/24 S=16:24/24 S=32:24/24 S=64:24/24 S=128:24/24
    TRIMMED_MEAN       S=1:24/24 S=2:24/24 S=4:24/24 S=8:24/24 S=16:24/24 S=32:24/24 S=64:24/24 S=128:24/24
    MEDIAN+LV          S=1:22/24 S=2:22/24 S=4:22/24 S=8:22/24 S=16:22/24 S=32:22/24 S=64:22/24 S=128:22/24
    TRIMMED_MEAN+LV    S=1:22/24 S=2:22/24 S=4:22/24 S=8:22/24 S=16:22/24 S=32:22/24 S=64:22/24 S=128:22/24
    VALIDATION_FILTER  S=1:22/24 S=2:22/24 S=4:22/24 S=8:22/24 S=16:22/24 S=32:22/24 S=64:22/24 S=128:22/24
    ROOT_QUORUM+LV     S=1:0/24 S=2:0/24 S=4:0/24 S=8:0/24 S=16:0/24 S=32:0/24 S=64:0/24 S=128:0/24
    ECHO               S=1:0/24 S=2:0/24 S=4:0/24 S=8:0/24 S=16:0/24 S=32:0/24 S=64:0/24 S=128:0/24
    ECHO true          S=1:20/60 S=2:20/60 S=4:20/60 S=8:20/60 S=16:20/60 S=32:20/60 S=64:20/60 S=128:20/60
    MEDIAN+LV true     S=1:52/60 S=2:52/60 S=4:52/60 S=8:52/60 S=16:52/60 S=32:52/60 S=64:52/60 S=128:52/60
    ECHO amplification S=1:0.0 S=2:0.0 S=4:0.0 S=8:0.0 S=16:0.0 S=32:0.0 S=64:0.0 S=128:0.0
    MEDIAN amplif.     S=1:0.6163141993957705 S=2:1.1895043731778425 S=4:2.223433242506812 S=8:3.932530120481928 S=16:6.387475538160469 S=32:6.9944649446494465 S=64:6.9944649446494465 S=128:6.9944649446494465
    stage6 poison: none bridged
  SYBIL_ADAPTIVE
    MAJORITY           S=1:0/24 S=2:24/24 S=4:24/24 S=8:24/24 S=16:24/24 S=32:24/24 S=64:24/24 S=128:24/24
    MEAN               S=1:0/24 S=2:24/24 S=4:24/24 S=8:24/24 S=16:24/24 S=32:24/24 S=64:24/24 S=128:24/24
    MEDIAN             S=1:24/24 S=2:24/24 S=4:24/24 S=8:24/24 S=16:24/24 S=32:24/24 S=64:24/24 S=128:24/24
    TRIMMED_MEAN       S=1:24/24 S=2:24/24 S=4:24/24 S=8:24/24 S=16:24/24 S=32:24/24 S=64:24/24 S=128:24/24
    MEDIAN+LV          S=1:22/24 S=2:22/24 S=4:22/24 S=8:22/24 S=16:22/24 S=32:22/24 S=64:22/24 S=128:22/24
    TRIMMED_MEAN+LV    S=1:22/24 S=2:22/24 S=4:22/24 S=8:22/24 S=16:22/24 S=32:22/24 S=64:22/24 S=128:22/24
    VALIDATION_FILTER  S=1:22/24 S=2:22/24 S=4:22/24 S=8:22/24 S=16:22/24 S=32:22/24 S=64:22/24 S=128:22/24
    ROOT_QUORUM+LV     S=1:0/24 S=2:22/24 S=4:22/24 S=8:22/24 S=16:22/24 S=32:22/24 S=64:22/24 S=128:22/24
    ECHO               S=1:0/24 S=2:6/24 S=4:22/24 S=8:22/24 S=16:22/24 S=32:22/24 S=64:22/24 S=128:22/24
    ECHO true          S=1:52/60 S=2:52/60 S=4:52/60 S=8:52/60 S=16:52/60 S=32:52/60 S=64:52/60 S=128:52/60
    MEDIAN+LV true     S=1:52/60 S=2:52/60 S=4:52/60 S=8:52/60 S=16:52/60 S=32:52/60 S=64:52/60 S=128:52/60
    ECHO amplification S=1:5.494890003330509 S=2:6.356406150057234 S=4:9.042698087232843 S=8:10.702995390858575 S=16:11.973495006576105 S=32:12.546505775146125 S=64:12.502061743210339 S=128:12.526947447919435
    MEDIAN amplif.     S=1:2.691292875989446 S=2:4.646924829157175 S=4:7.298747763864043 S=8:10.212765957446809 S=16:12.719810576164166 S=32:14.524195415605464 S=64:15.63852813852814 S=128:16.177904205427847
    stage6 poison: ["S=2:{'UNCERTAIN': 12, 'poison_decisions_bridged': 6, 'receipts_evicted': 0}", "S=4:{'UNCERTAIN': 66, 'poison_decisions_bridged': 22, 'receipts_evicted': 0}", "S=8:{'UNCERTAIN': 88, 'poison_decisions_bridged': 22, 'receipts_evicted': 0}", "S=16:{'UNCERTAIN': 112, 'poison_decisions_bridged': 22, 'receipts_evicted': 0}", "S=32:{'UNCERTAIN': 106, 'poison_decisions_bridged': 22, 'receipts_evicted': 0}", "S=64:{'UNCERTAIN': 124, 'poison_decisions_bridged': 22, 'receipts_evicted': 0}", "S=128:{'UNCERTAIN': 99, 'poison_decisions_bridged': 22, 'receipts_evicted': 0}"]

[break points] share (or identity share) where poison acceptance >= 0.5
    BYZANTINE_LATENT_POISON    ECHO               None
    BYZANTINE_LATENT_POISON    MAJORITY           0.1
    BYZANTINE_LATENT_POISON    MEAN               0.1
    BYZANTINE_LATENT_POISON    MEDIAN             0.1
    BYZANTINE_LATENT_POISON    MEDIAN+LV          0.1
    BYZANTINE_LATENT_POISON    ROOT_QUORUM+LV     None
    BYZANTINE_LATENT_POISON    TRIMMED_MEAN       0.1
    BYZANTINE_LATENT_POISON    TRIMMED_MEAN+LV    0.1
    BYZANTINE_LATENT_POISON    VALIDATION_FILTER  0.1
    BYZANTINE_POISON           ECHO               None
    BYZANTINE_POISON           MAJORITY           0.1
    BYZANTINE_POISON           MEAN               0.1
    BYZANTINE_POISON           MEDIAN             0.1
    BYZANTINE_POISON           MEDIAN+LV          None
    BYZANTINE_POISON           ROOT_QUORUM+LV     None
    BYZANTINE_POISON           TRIMMED_MEAN       0.1
    BYZANTINE_POISON           TRIMMED_MEAN+LV    None
    BYZANTINE_POISON           VALIDATION_FILTER  None
    BYZANTINE_SUPPRESS         ECHO               None
    BYZANTINE_SUPPRESS         MAJORITY           None
    BYZANTINE_SUPPRESS         MEAN               None
    BYZANTINE_SUPPRESS         MEDIAN             None
    BYZANTINE_SUPPRESS         MEDIAN+LV          None
    BYZANTINE_SUPPRESS         ROOT_QUORUM+LV     None
    BYZANTINE_SUPPRESS         TRIMMED_MEAN       None
    BYZANTINE_SUPPRESS         TRIMMED_MEAN+LV    None
    BYZANTINE_SUPPRESS         VALIDATION_FILTER  None
    COLLUSION_TIMING           ECHO               0.2
    COLLUSION_TIMING           MAJORITY           0.1
    COLLUSION_TIMING           MEAN               0.1
    COLLUSION_TIMING           MEDIAN             0.1
    COLLUSION_TIMING           MEDIAN+LV          0.1
    COLLUSION_TIMING           ROOT_QUORUM+LV     0.1
    COLLUSION_TIMING           TRIMMED_MEAN       0.1
    COLLUSION_TIMING           TRIMMED_MEAN+LV    0.1
    COLLUSION_TIMING           VALIDATION_FILTER  0.1
    SLOW_POISON                ECHO               None
    SLOW_POISON                MAJORITY           0.1
    SLOW_POISON                MEAN               0.1
    SLOW_POISON                MEDIAN             0.1
    SLOW_POISON                MEDIAN+LV          0.1
    SLOW_POISON                ROOT_QUORUM+LV     0.1
    SLOW_POISON                TRIMMED_MEAN       0.1
    SLOW_POISON                TRIMMED_MEAN+LV    0.1
    SLOW_POISON                VALIDATION_FILTER  0.1
    SYBIL_ADAPTIVE             ECHO               0.14285714285714285
    SYBIL_ADAPTIVE             MAJORITY           0.07692307692307693
    SYBIL_ADAPTIVE             MEAN               0.07692307692307693
    SYBIL_ADAPTIVE             MEDIAN             0.04
    SYBIL_ADAPTIVE             MEDIAN+LV          0.04
    SYBIL_ADAPTIVE             ROOT_QUORUM+LV     0.07692307692307693
    SYBIL_ADAPTIVE             TRIMMED_MEAN       0.04
    SYBIL_ADAPTIVE             TRIMMED_MEAN+LV    0.04
    SYBIL_ADAPTIVE             VALIDATION_FILTER  0.04
    SYBIL_DECLARED_ROOT        ECHO               None
    SYBIL_DECLARED_ROOT        MAJORITY           0.07692307692307693
    SYBIL_DECLARED_ROOT        MEAN               0.07692307692307693
    SYBIL_DECLARED_ROOT        MEDIAN             0.04
    SYBIL_DECLARED_ROOT        MEDIAN+LV          0.04
    SYBIL_DECLARED_ROOT        ROOT_QUORUM+LV     None
    SYBIL_DECLARED_ROOT        TRIMMED_MEAN       0.04
    SYBIL_DECLARED_ROOT        TRIMMED_MEAN+LV    0.04
    SYBIL_DECLARED_ROOT        VALIDATION_FILTER  0.04
    SYBIL_FORGED_ROOTS         ECHO               None
    SYBIL_FORGED_ROOTS         MAJORITY           0.07692307692307693
    SYBIL_FORGED_ROOTS         MEAN               0.07692307692307693
    SYBIL_FORGED_ROOTS         MEDIAN             0.04
    SYBIL_FORGED_ROOTS         MEDIAN+LV          0.04
    SYBIL_FORGED_ROOTS         ROOT_QUORUM+LV     None
    SYBIL_FORGED_ROOTS         TRIMMED_MEAN       0.04
    SYBIL_FORGED_ROOTS         TRIMMED_MEAN+LV    0.04
    SYBIL_FORGED_ROOTS         VALIDATION_FILTER  0.04
```

### B.5 Paired detection
```
$ for c in 7 11; do for r in '' --all-receivers; do PYTHONHASHSEED=0 python benchmarks/stage7/paired_detection.py --corpus-seed $c --seed {0|1} $r; done; done
corpus seed 7, 4 receivers, 14 positives (locally-unseen families), loadavg [16.58, 16.89, 14.64]
  ECHO               caught 8/14 FP 0
  ROOT_QUORUM        caught 11/14 FP 0
  VALIDATION_FILTER  caught 11/14 FP 0
  ECHO vs ROOT_QUORUM: only ECHO 0, only ROOT_QUORUM 3, exact sign-test p 2.50e-01
  ECHO vs VALIDATION_FILTER: only ECHO 0, only VALIDATION_FILTER 3, exact sign-test p 2.50e-01
  ROOT_QUORUM vs VALIDATION_FILTER: only ROOT_QUORUM 0, only VALIDATION_FILTER 0, exact sign-test p 1.00e+00
corpus seed 7, 24 receivers, 81 positives (locally-unseen families), loadavg [16.91, 16.96, 14.71]
  ECHO               caught 59/81 FP 0
  ROOT_QUORUM        caught 73/81 FP 0
  VALIDATION_FILTER  caught 73/81 FP 0
  ECHO vs ROOT_QUORUM: only ECHO 0, only ROOT_QUORUM 14, exact sign-test p 1.22e-04
  ECHO vs VALIDATION_FILTER: only ECHO 0, only VALIDATION_FILTER 14, exact sign-test p 1.22e-04
  ROOT_QUORUM vs VALIDATION_FILTER: only ROOT_QUORUM 0, only VALIDATION_FILTER 0, exact sign-test p 1.00e+00
corpus seed 11, 4 receivers, 12 positives (locally-unseen families), loadavg [16.68, 16.91, 14.7]
  ECHO               caught 3/12 FP 0
  ROOT_QUORUM        caught 10/12 FP 0
  VALIDATION_FILTER  caught 10/12 FP 0
  ECHO vs ROOT_QUORUM: only ECHO 0, only ROOT_QUORUM 7, exact sign-test p 1.56e-02
  ECHO vs VALIDATION_FILTER: only ECHO 0, only VALIDATION_FILTER 7, exact sign-test p 1.56e-02
  ROOT_QUORUM vs VALIDATION_FILTER: only ROOT_QUORUM 0, only VALIDATION_FILTER 0, exact sign-test p 1.00e+00
corpus seed 11, 24 receivers, 74 positives (locally-unseen families), loadavg [14.77, 16.46, 14.6]
  ECHO               caught 32/74 FP 0
  ROOT_QUORUM        caught 67/74 FP 0
  VALIDATION_FILTER  caught 67/74 FP 0
  ECHO vs ROOT_QUORUM: only ECHO 0, only ROOT_QUORUM 35, exact sign-test p 5.82e-11
  ECHO vs VALIDATION_FILTER: only ECHO 0, only VALIDATION_FILTER 35, exact sign-test p 5.82e-11
  ROOT_QUORUM vs VALIDATION_FILTER: only ROOT_QUORUM 0, only VALIDATION_FILTER 0, exact sign-test p 1.00e+00
```

### B.6 ECHO configuration grid (corpus 7 in full; corpus 11 in full)
```
$ PYTHONHASHSEED=0 python benchmarks/stage7/config_grid.py
NONE x=0.0
    full: rec 0.571 fp 0.000 true 0.545 poison - amp -
    no_distance: rec 0.786 fp 0.000 true 0.818 poison - amp -
    req+probation: rec 0.786 fp 0.000 true 0.818 poison - amp -
    required: rec 0.786 fp 0.000 true 0.818 poison - amp -
BYZANTINE_POISON x=0.1
    full: rec 0.000 fp 0.000 true 0.000 poison 0.000 amp -
    no_distance: rec 0.071 fp 0.000 true 0.091 poison 0.000 amp 0.000
    req+probation: rec 0.214 fp 0.000 true 0.273 poison 0.000 amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
BYZANTINE_POISON x=0.2
    full: rec 0.000 fp 0.000 true 0.000 poison 0.000 amp -
    no_distance: rec 0.071 fp 0.000 true 0.091 poison 0.000 amp 0.000
    req+probation: rec 0.214 fp 0.000 true 0.273 poison 0.000 amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
BYZANTINE_POISON x=0.3
    full: rec 0.000 fp 0.000 true 0.000 poison 0.000 amp -
    no_distance: rec 0.071 fp 0.000 true 0.091 poison 0.000 amp 0.000
    req+probation: rec 0.214 fp 0.000 true 0.273 poison 0.000 amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
BYZANTINE_POISON x=0.4
    full: rec 0.000 fp 0.000 true 0.000 poison 0.000 amp -
    no_distance: rec 0.071 fp 0.000 true 0.091 poison 0.000 amp 0.000
    req+probation: rec 0.214 fp 0.000 true 0.273 poison 0.000 amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
BYZANTINE_POISON x=0.5
    full: rec 0.000 fp 0.000 true 0.000 poison 0.000 amp -
    no_distance: rec 0.071 fp 0.000 true 0.091 poison 0.000 amp 0.000
    req+probation: rec 0.214 fp 0.000 true 0.273 poison 0.000 amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
BYZANTINE_POISON x=0.6
    full: rec 0.000 fp 0.000 true 0.000 poison 0.000 amp -
    no_distance: rec 0.071 fp 0.000 true 0.091 poison 0.000 amp 0.000
    req+probation: rec 0.214 fp 0.000 true 0.273 poison 0.000 amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
BYZANTINE_LATENT_POISON x=0.1
    full: rec 0.571 fp 0.000 true 0.545 poison 0.000 amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    required: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 2.483
BYZANTINE_LATENT_POISON x=0.2
    full: rec 0.571 fp 0.000 true 0.545 poison 0.000 amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    required: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 2.162
BYZANTINE_LATENT_POISON x=0.3
    full: rec 0.571 fp 0.000 true 0.545 poison 0.000 amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    required: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 1.878
BYZANTINE_LATENT_POISON x=0.4
    full: rec 0.571 fp 0.000 true 0.545 poison 0.000 amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    required: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 1.662
BYZANTINE_LATENT_POISON x=0.5
    full: rec 0.571 fp 0.000 true 0.545 poison 0.000 amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    required: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 1.506
BYZANTINE_LATENT_POISON x=0.6
    full: rec 0.571 fp 0.000 true 0.545 poison 0.000 amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    required: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 1.255
SLOW_POISON x=0.1
    full: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 3.560
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 2.545
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.500 amp 2.948
    required: rec 0.786 fp 0.000 true 0.818 poison 0.500 amp 3.750
SLOW_POISON x=0.2
    full: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 2.194
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 1.598
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.250 amp 1.695
    required: rec 0.786 fp 0.000 true 0.818 poison 0.250 amp 2.500
SLOW_POISON x=0.3
    full: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.956
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.649
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.616
    required: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 1.561
SLOW_POISON x=0.4
    full: rec 0.786 fp 0.000 true 0.818 poison - amp 0.716
    no_distance: rec 0.786 fp 0.000 true 0.818 poison - amp 0.486
    req+probation: rec 0.786 fp 0.000 true 0.818 poison - amp 0.460
    required: rec 0.786 fp 0.000 true 0.818 poison - amp 1.256
SLOW_POISON x=0.5
    full: rec 0.786 fp 0.000 true 0.818 poison - amp 0.583
    no_distance: rec 0.786 fp 0.000 true 0.818 poison - amp 0.396
    req+probation: rec 0.786 fp 0.000 true 0.818 poison - amp 0.375
    required: rec 0.786 fp 0.000 true 0.818 poison - amp 1.087
SLOW_POISON x=0.6
    full: rec 0.786 fp 0.000 true 0.818 poison - amp 0.486
    no_distance: rec 0.786 fp 0.000 true 0.818 poison - amp 0.330
    req+probation: rec 0.786 fp 0.000 true 0.818 poison - amp 0.312
    required: rec 0.786 fp 0.000 true 0.818 poison - amp 0.980
COLLUSION_TIMING x=0.1
    full: rec 0.571 fp 0.000 true 0.545 poison 0.000 amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    req+probation: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 1.532
    required: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 2.483
COLLUSION_TIMING x=0.2
    full: rec 0.000 fp 0.067 true 0.545 poison 1.000 amp 2.177
    no_distance: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 1.351
    req+probation: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 1.455
    required: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 2.162
COLLUSION_TIMING x=0.3
    full: rec 0.000 fp 0.067 true 0.545 poison 1.000 amp 1.883
    no_distance: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 1.288
    req+probation: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 1.373
    required: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 1.878
COLLUSION_TIMING x=0.4
    full: rec 0.571 fp 0.000 true 0.545 poison 0.000 amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
COLLUSION_TIMING x=0.5
    full: rec 0.571 fp 0.000 true 0.545 poison 0.000 amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
COLLUSION_TIMING x=0.6
    full: rec 0.571 fp 0.000 true 0.545 poison 0.000 amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
BYZANTINE_SUPPRESS x=0.1
    full: rec 0.571 fp 0.000 true 0.545 poison - amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison - amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison - amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison - amp 0.000
BYZANTINE_SUPPRESS x=0.2
    full: rec 0.571 fp 0.000 true 0.545 poison - amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison - amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison - amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison - amp 0.000
BYZANTINE_SUPPRESS x=0.3
    full: rec 0.571 fp 0.000 true 0.545 poison - amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison - amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison - amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison - amp 0.000
BYZANTINE_SUPPRESS x=0.4
    full: rec 0.571 fp 0.000 true 0.545 poison - amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison - amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison - amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison - amp 0.000
BYZANTINE_SUPPRESS x=0.5
    full: rec 0.571 fp 0.000 true 0.545 poison - amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison - amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison - amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison - amp 0.000
BYZANTINE_SUPPRESS x=0.6
    full: rec 0.571 fp 0.000 true 0.545 poison - amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison - amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison - amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison - amp 0.000
SYBIL_DECLARED_ROOT x=1
    full: rec 0.571 fp 0.000 true 0.545 poison 0.000 amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
SYBIL_DECLARED_ROOT x=2
    full: rec 0.571 fp 0.000 true 0.545 poison 0.000 amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
SYBIL_DECLARED_ROOT x=4
    full: rec 0.571 fp 0.000 true 0.545 poison 0.000 amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
SYBIL_DECLARED_ROOT x=8
    full: rec 0.571 fp 0.000 true 0.545 poison 0.000 amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
SYBIL_DECLARED_ROOT x=16
    full: rec 0.571 fp 0.000 true 0.545 poison 0.000 amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
SYBIL_DECLARED_ROOT x=32
    full: rec 0.571 fp 0.000 true 0.545 poison 0.000 amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
SYBIL_DECLARED_ROOT x=64
    full: rec 0.571 fp 0.000 true 0.545 poison 0.000 amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
SYBIL_DECLARED_ROOT x=128
    full: rec 0.571 fp 0.000 true 0.545 poison 0.000 amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
SYBIL_FORGED_ROOTS x=1
    full: rec 0.571 fp 0.000 true 0.545 poison 0.000 amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
SYBIL_FORGED_ROOTS x=2
    full: rec 0.571 fp 0.000 true 0.545 poison 0.000 amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
SYBIL_FORGED_ROOTS x=4
    full: rec 0.571 fp 0.000 true 0.545 poison 0.000 amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
SYBIL_FORGED_ROOTS x=8
    full: rec 0.571 fp 0.000 true 0.545 poison 0.000 amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
SYBIL_FORGED_ROOTS x=16
    full: rec 0.571 fp 0.000 true 0.545 poison 0.000 amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
SYBIL_FORGED_ROOTS x=32
    full: rec 0.571 fp 0.000 true 0.545 poison 0.000 amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
SYBIL_FORGED_ROOTS x=64
    full: rec 0.571 fp 0.000 true 0.545 poison 0.000 amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
SYBIL_FORGED_ROOTS x=128
    full: rec 0.571 fp 0.000 true 0.545 poison 0.000 amp 0.000
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
    required: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 0.000
SYBIL_ADAPTIVE x=1
    full: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 4.590
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 3.091
    req+probation: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 3.188
    required: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 2.720
SYBIL_ADAPTIVE x=2
    full: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 4.590
    no_distance: rec 0.786 fp 0.000 true 0.818 poison 0.000 amp 3.091
    req+probation: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 5.161
    required: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 6.182
SYBIL_ADAPTIVE x=4
    full: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 8.212
    no_distance: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 6.174
    req+probation: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 5.161
    required: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 6.182
SYBIL_ADAPTIVE x=8
    full: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 9.914
    no_distance: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 8.048
    req+probation: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 7.083
    required: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 6.182
SYBIL_ADAPTIVE x=16
    full: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 11.803
    no_distance: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 9.684
    req+probation: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 9.444
    required: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 8.293
SYBIL_ADAPTIVE x=32
    full: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 12.219
    no_distance: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 10.203
    req+probation: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 10.066
    required: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 8.886
SYBIL_ADAPTIVE x=64
    full: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 12.467
    no_distance: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 10.625
    req+probation: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 10.503
    required: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 9.239
SYBIL_ADAPTIVE x=128
    full: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 11.960
    no_distance: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 10.018
    req+probation: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 9.993
    required: rec 0.000 fp 0.067 true 0.818 poison 1.000 amp 9.239
wrote /home/anil/Documents/Research/pocketsec/results/stage7-config-grid-c7-default.json; loadavg [16.09, 15.38, 14.57] -> [14.77, 14.43, 13.78]
```
```
$ PYTHONHASHSEED=0 python benchmarks/stage7/config_grid.py --corpus-seed 11 --seed 1
NONE x=0.0
    full: rec 0.250 fp 0.000 true 0.200 poison - amp -
    no_distance: rec 0.667 fp 0.000 true 0.600 poison - amp -
    req+probation: rec 0.833 fp 0.000 true 0.800 poison - amp -
    required: rec 0.833 fp 0.000 true 0.800 poison - amp -
BYZANTINE_POISON x=0.1
    full: rec 0.000 fp 0.000 true 0.000 poison 0.000 amp -
    no_distance: rec 0.083 fp 0.000 true 0.100 poison 0.000 amp 0.000
    req+probation: rec 0.083 fp 0.000 true 0.100 poison 0.000 amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
BYZANTINE_POISON x=0.2
    full: rec 0.000 fp 0.000 true 0.000 poison 0.000 amp -
    no_distance: rec 0.083 fp 0.000 true 0.100 poison 0.000 amp 0.000
    req+probation: rec 0.083 fp 0.000 true 0.100 poison 0.000 amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
BYZANTINE_POISON x=0.3
    full: rec 0.000 fp 0.000 true 0.000 poison 0.000 amp -
    no_distance: rec 0.083 fp 0.000 true 0.100 poison 0.000 amp 0.000
    req+probation: rec 0.083 fp 0.000 true 0.100 poison 0.000 amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
BYZANTINE_POISON x=0.4
    full: rec 0.000 fp 0.000 true 0.000 poison 0.000 amp -
    no_distance: rec 0.083 fp 0.000 true 0.100 poison 0.000 amp 0.000
    req+probation: rec 0.083 fp 0.000 true 0.100 poison 0.000 amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
BYZANTINE_POISON x=0.5
    full: rec 0.000 fp 0.000 true 0.000 poison 0.000 amp -
    no_distance: rec 0.083 fp 0.000 true 0.100 poison 0.000 amp 0.000
    req+probation: rec 0.083 fp 0.000 true 0.100 poison 0.000 amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
BYZANTINE_POISON x=0.6
    full: rec 0.000 fp 0.000 true 0.000 poison 0.000 amp -
    no_distance: rec 0.083 fp 0.000 true 0.100 poison 0.000 amp 0.000
    req+probation: rec 0.083 fp 0.000 true 0.100 poison 0.000 amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
BYZANTINE_LATENT_POISON x=0.1
    full: rec 0.250 fp 0.000 true 0.200 poison 0.000 amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison 0.000 amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
    required: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 2.667
BYZANTINE_LATENT_POISON x=0.2
    full: rec 0.250 fp 0.000 true 0.200 poison 0.000 amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison 0.000 amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
    required: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 2.286
BYZANTINE_LATENT_POISON x=0.3
    full: rec 0.250 fp 0.000 true 0.200 poison 0.000 amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison 0.000 amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
    required: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 1.957
BYZANTINE_LATENT_POISON x=0.4
    full: rec 0.250 fp 0.000 true 0.200 poison 0.000 amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison 0.000 amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
    required: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 1.714
BYZANTINE_LATENT_POISON x=0.5
    full: rec 0.250 fp 0.000 true 0.200 poison 0.000 amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison 0.000 amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
    required: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 1.542
BYZANTINE_LATENT_POISON x=0.6
    full: rec 0.250 fp 0.000 true 0.200 poison 0.000 amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison 0.000 amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
    required: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 1.285
SLOW_POISON x=0.1
    full: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 4.531
    no_distance: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 3.698
    req+probation: rec 0.000 fp 0.067 true 0.800 poison 0.750 amp 4.605
    required: rec 0.000 fp 0.067 true 0.800 poison 0.750 amp 4.615
SLOW_POISON x=0.2
    full: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 2.535
    no_distance: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 2.072
    req+probation: rec 0.000 fp 0.067 true 0.800 poison 0.250 amp 2.162
    required: rec 0.000 fp 0.067 true 0.800 poison 0.250 amp 2.500
SLOW_POISON x=0.3
    full: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 1.467
    no_distance: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 1.173
    req+probation: rec 0.000 fp 0.067 true 0.800 poison 0.250 amp 1.256
    required: rec 0.000 fp 0.067 true 0.800 poison 0.250 amp 1.763
SLOW_POISON x=0.4
    full: rec 0.833 fp 0.000 true 0.800 poison - amp 0.935
    no_distance: rec 0.833 fp 0.000 true 0.800 poison - amp 0.730
    req+probation: rec 0.833 fp 0.000 true 0.800 poison - amp 0.677
    required: rec 0.833 fp 0.000 true 0.800 poison - amp 1.227
SLOW_POISON x=0.5
    full: rec 0.833 fp 0.000 true 0.800 poison - amp 0.764
    no_distance: rec 0.833 fp 0.000 true 0.800 poison - amp 0.596
    req+probation: rec 0.833 fp 0.000 true 0.800 poison - amp 0.552
    required: rec 0.833 fp 0.000 true 0.800 poison - amp 0.882
SLOW_POISON x=0.6
    full: rec 0.833 fp 0.000 true 0.800 poison - amp 0.632
    no_distance: rec 0.833 fp 0.000 true 0.800 poison - amp 0.497
    req+probation: rec 0.833 fp 0.000 true 0.800 poison - amp 0.460
    required: rec 0.833 fp 0.000 true 0.800 poison - amp 0.787
COLLUSION_TIMING x=0.1
    full: rec 0.250 fp 0.000 true 0.200 poison 0.000 amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison 0.000 amp 0.000
    req+probation: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 2.483
    required: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 2.667
COLLUSION_TIMING x=0.2
    full: rec 0.000 fp 0.067 true 0.200 poison 1.000 amp 3.701
    no_distance: rec 0.000 fp 0.067 true 0.600 poison 1.000 amp 2.212
    req+probation: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 2.162
    required: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 2.286
COLLUSION_TIMING x=0.3
    full: rec 0.000 fp 0.067 true 0.200 poison 1.000 amp 2.740
    no_distance: rec 0.000 fp 0.067 true 0.600 poison 1.000 amp 1.916
    req+probation: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 1.878
    required: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 1.957
COLLUSION_TIMING x=0.4
    full: rec 0.250 fp 0.000 true 0.200 poison 0.000 amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison 0.000 amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
COLLUSION_TIMING x=0.5
    full: rec 0.250 fp 0.000 true 0.200 poison 0.000 amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison 0.000 amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
COLLUSION_TIMING x=0.6
    full: rec 0.250 fp 0.000 true 0.200 poison 0.000 amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison 0.000 amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
BYZANTINE_SUPPRESS x=0.1
    full: rec 0.250 fp 0.000 true 0.200 poison - amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison - amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison - amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison - amp 0.000
BYZANTINE_SUPPRESS x=0.2
    full: rec 0.250 fp 0.000 true 0.200 poison - amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison - amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison - amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison - amp 0.000
BYZANTINE_SUPPRESS x=0.3
    full: rec 0.250 fp 0.000 true 0.200 poison - amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison - amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison - amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison - amp 0.000
BYZANTINE_SUPPRESS x=0.4
    full: rec 0.250 fp 0.000 true 0.200 poison - amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison - amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison - amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison - amp 0.000
BYZANTINE_SUPPRESS x=0.5
    full: rec 0.250 fp 0.000 true 0.200 poison - amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison - amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison - amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison - amp 0.000
BYZANTINE_SUPPRESS x=0.6
    full: rec 0.250 fp 0.000 true 0.200 poison - amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison - amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison - amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison - amp 0.000
SYBIL_DECLARED_ROOT x=1
    full: rec 0.250 fp 0.000 true 0.200 poison 0.000 amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison 0.000 amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
SYBIL_DECLARED_ROOT x=2
    full: rec 0.250 fp 0.000 true 0.200 poison 0.000 amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison 0.000 amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
SYBIL_DECLARED_ROOT x=4
    full: rec 0.250 fp 0.000 true 0.200 poison 0.000 amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison 0.000 amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
SYBIL_DECLARED_ROOT x=8
    full: rec 0.250 fp 0.000 true 0.200 poison 0.000 amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison 0.000 amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
SYBIL_DECLARED_ROOT x=16
    full: rec 0.250 fp 0.000 true 0.200 poison 0.000 amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison 0.000 amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
SYBIL_DECLARED_ROOT x=32
    full: rec 0.250 fp 0.000 true 0.200 poison 0.000 amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison 0.000 amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
SYBIL_DECLARED_ROOT x=64
    full: rec 0.250 fp 0.000 true 0.200 poison 0.000 amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison 0.000 amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
SYBIL_DECLARED_ROOT x=128
    full: rec 0.250 fp 0.000 true 0.200 poison 0.000 amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison 0.000 amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
SYBIL_FORGED_ROOTS x=1
    full: rec 0.250 fp 0.000 true 0.200 poison 0.000 amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison 0.000 amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
SYBIL_FORGED_ROOTS x=2
    full: rec 0.250 fp 0.000 true 0.200 poison 0.000 amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison 0.000 amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
SYBIL_FORGED_ROOTS x=4
    full: rec 0.250 fp 0.000 true 0.200 poison 0.000 amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison 0.000 amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
SYBIL_FORGED_ROOTS x=8
    full: rec 0.250 fp 0.000 true 0.200 poison 0.000 amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison 0.000 amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
SYBIL_FORGED_ROOTS x=16
    full: rec 0.250 fp 0.000 true 0.200 poison 0.000 amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison 0.000 amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
SYBIL_FORGED_ROOTS x=32
    full: rec 0.250 fp 0.000 true 0.200 poison 0.000 amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison 0.000 amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
SYBIL_FORGED_ROOTS x=64
    full: rec 0.250 fp 0.000 true 0.200 poison 0.000 amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison 0.000 amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
SYBIL_FORGED_ROOTS x=128
    full: rec 0.250 fp 0.000 true 0.200 poison 0.000 amp 0.000
    no_distance: rec 0.667 fp 0.000 true 0.600 poison 0.000 amp 0.000
    req+probation: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
    required: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 0.000
SYBIL_ADAPTIVE x=1
    full: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 6.129
    no_distance: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 4.770
    req+probation: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 4.690
    required: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 3.542
SYBIL_ADAPTIVE x=2
    full: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 6.129
    no_distance: rec 0.833 fp 0.000 true 0.800 poison 0.000 amp 4.770
    req+probation: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 7.351
    required: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 6.906
SYBIL_ADAPTIVE x=4
    full: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 10.156
    no_distance: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 8.246
    req+probation: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 7.351
    required: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 6.906
SYBIL_ADAPTIVE x=8
    full: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 11.822
    no_distance: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 9.912
    req+probation: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 9.404
    required: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 6.906
SYBIL_ADAPTIVE x=16
    full: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 12.913
    no_distance: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 11.580
    req+probation: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 11.242
    required: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 8.500
SYBIL_ADAPTIVE x=32
    full: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 13.352
    no_distance: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 12.289
    req+probation: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 12.295
    required: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 9.488
SYBIL_ADAPTIVE x=64
    full: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 12.855
    no_distance: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 11.651
    req+probation: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 11.156
    required: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 8.500
SYBIL_ADAPTIVE x=128
    full: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 13.354
    no_distance: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 11.916
    req+probation: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 11.569
    required: rec 0.000 fp 0.067 true 0.800 poison 1.000 amp 8.718
wrote /home/anil/Documents/Research/pocketsec/results/stage7-config-grid-c11-default.json; loadavg [11.01, 11.63, 12.88] -> [1.58, 4.18, 8.07]
exit 0
```
```
$ python - (dominance check over results/stage7-config-grid-c{7,11}-default.json: no_distance vs full on recall, poison acceptance and FP rate)
grid c7: cases 55; no_distance worse than full: []; strictly better recall: 39
grid c11: cases 55; no_distance worse than full: []; strictly better recall: 39
```

### B.7 Why ECHO refuses (v2, registered -0011)
```
$ PYTHONHASHSEED=0 python benchmarks/stage7/echo_refusals.py

== NONE x=0.0: MEDIAN+LV true 9/11; ECHO refusals of those keys: {'status=REFUSED': 5, 'reason=local_origin': 5, 'reason=local_confirmed': 8, 'status=INSUFFICIENT': 3, 'reason=below_mass_floor': 3}
   full          true_acceptance 0.545  poison_acceptance -  amplification -
   required      true_acceptance 0.818  poison_acceptance -  amplification -
   no_distance   true_acceptance 0.818  poison_acceptance -  amplification -
   no_trust      true_acceptance 0.545  poison_acceptance -  amplification -
   no_probation  true_acceptance 0.636  poison_acceptance -  amplification -
   no_contest    true_acceptance 0.545  poison_acceptance -  amplification -
   floor_half    true_acceptance 0.818  poison_acceptance -  amplification -

== BYZANTINE_POISON x=0.1: MEDIAN+LV true 9/11; ECHO refusals of those keys: {'status=REFUSED': 5, 'reason=local_origin': 5, 'reason=local_confirmed': 8, 'status=INSUFFICIENT': 9, 'reason=below_mass_floor': 9}
   full          true_acceptance 0.000  poison_acceptance 0.000  amplification -
   required      true_acceptance 0.818  poison_acceptance 0.000  amplification 0.000
   no_distance   true_acceptance 0.091  poison_acceptance 0.000  amplification 0.000
   no_trust      true_acceptance 0.000  poison_acceptance 0.000  amplification -
   no_probation  true_acceptance 0.455  poison_acceptance 0.000  amplification 0.000
   no_contest    true_acceptance 0.000  poison_acceptance 0.000  amplification -
   floor_half    true_acceptance 0.636  poison_acceptance 0.000  amplification 0.000

== BYZANTINE_POISON x=0.2: MEDIAN+LV true 9/11; ECHO refusals of those keys: {'status=REFUSED': 5, 'reason=local_origin': 5, 'reason=local_confirmed': 8, 'status=INSUFFICIENT': 9, 'reason=below_mass_floor': 9}
   full          true_acceptance 0.000  poison_acceptance 0.000  amplification -
   required      true_acceptance 0.818  poison_acceptance 0.000  amplification 0.000
   no_distance   true_acceptance 0.091  poison_acceptance 0.000  amplification 0.000
   no_trust      true_acceptance 0.000  poison_acceptance 0.000  amplification -
   no_probation  true_acceptance 0.455  poison_acceptance 0.000  amplification 0.000
   no_contest    true_acceptance 0.000  poison_acceptance 0.000  amplification -
   floor_half    true_acceptance 0.636  poison_acceptance 0.000  amplification 0.000

== BYZANTINE_LATENT_POISON x=0.2: MEDIAN+LV true 9/11; ECHO refusals of those keys: {'status=REFUSED': 5, 'reason=local_origin': 5, 'reason=local_confirmed': 8, 'status=INSUFFICIENT': 3, 'reason=below_mass_floor': 3}
   full          true_acceptance 0.545  poison_acceptance 0.000  amplification 0.000
   required      true_acceptance 0.818  poison_acceptance 1.000  amplification 2.162
   no_distance   true_acceptance 0.818  poison_acceptance 0.000  amplification 0.000
   no_trust      true_acceptance 0.545  poison_acceptance 0.000  amplification 0.000
   no_probation  true_acceptance 0.636  poison_acceptance 1.000  amplification 2.168
   no_contest    true_acceptance 0.545  poison_acceptance 0.000  amplification 0.000
   floor_half    true_acceptance 0.818  poison_acceptance 0.000  amplification 0.000

== SLOW_POISON x=0.2: MEDIAN+LV true 9/11; ECHO refusals of those keys: {'status=REFUSED': 5, 'reason=local_origin': 5, 'reason=local_confirmed': 5}
   full          true_acceptance 0.818  poison_acceptance 0.000  amplification 2.194
   required      true_acceptance 0.818  poison_acceptance 0.250  amplification 2.500
   no_distance   true_acceptance 0.818  poison_acceptance 0.000  amplification 1.598
   no_trust      true_acceptance 0.818  poison_acceptance 0.000  amplification 2.143
   no_probation  true_acceptance 0.818  poison_acceptance 0.250  amplification 3.013
   no_contest    true_acceptance 0.818  poison_acceptance 0.000  amplification 2.194
   floor_half    true_acceptance 0.818  poison_acceptance 0.250  amplification 2.313

== COLLUSION_TIMING x=0.2: MEDIAN+LV true 9/11; ECHO refusals of those keys: {'status=REFUSED': 5, 'reason=local_origin': 5, 'reason=local_confirmed': 8, 'status=INSUFFICIENT': 3, 'reason=below_mass_floor': 3}
   full          true_acceptance 0.545  poison_acceptance 1.000  amplification 2.177
   required      true_acceptance 0.818  poison_acceptance 1.000  amplification 2.162
   no_distance   true_acceptance 0.818  poison_acceptance 1.000  amplification 1.351
   no_trust      true_acceptance 0.545  poison_acceptance 1.000  amplification 2.239
   no_probation  true_acceptance 0.636  poison_acceptance 1.000  amplification 2.168
   no_contest    true_acceptance 0.545  poison_acceptance 1.000  amplification 2.177
   floor_half    true_acceptance 0.818  poison_acceptance 1.000  amplification 1.920

== SYBIL_ADAPTIVE x=16: MEDIAN+LV true 9/11; ECHO refusals of those keys: {'status=REFUSED': 5, 'reason=local_origin': 5, 'reason=local_confirmed': 5}
   full          true_acceptance 0.818  poison_acceptance 1.000  amplification 11.803
   required      true_acceptance 0.818  poison_acceptance 1.000  amplification 8.293
   no_distance   true_acceptance 0.818  poison_acceptance 1.000  amplification 9.684
   no_trust      true_acceptance 0.818  poison_acceptance 1.000  amplification 11.857
   no_probation  true_acceptance 0.818  poison_acceptance 1.000  amplification 10.617
   no_contest    true_acceptance 0.818  poison_acceptance 1.000  amplification 11.803
   floor_half    true_acceptance 0.818  poison_acceptance 1.000  amplification 11.025
wrote /home/anil/Documents/Research/pocketsec/results/stage7-echo-refusals-c7-default.json; loadavg end [1.88, 1.95, 5.02]
```

### B.8 Probation horizon check
```
$ PYTHONHASHSEED=0 python - <<'EOF'   # horizon check (probation), corpus 7, 4 receivers
from dataclasses import replace
from pocketsec.stage7.echo.inference import EchoConfig
from pocketsec.stage7.labs.byzantine_suite import echo_metric, accepted_keys
from pocketsec.stage7.aggregation.robust import Aggregator
from pocketsec.stage7.labs.fleet_corpus import build_fleet_corpus
from pocketsec.stage7.labs.partition import simulate, replay_with
from pocketsec.stage7.labs.simulated_fleet import AdversaryArm, FleetSpec, default_receivers
c = build_fleet_corpus(seed=7); rx = default_receivers(c); D = EchoConfig()
for arm in (AdversaryArm.BYZANTINE_LATENT_POISON, AdversaryArm.SLOW_POISON, AdversaryArm.NONE):
    for rounds in (12, 24, 36):
        run = simulate(c, FleetSpec(arm=arm, adversary_share=0.0 if arm is AdversaryArm.NONE else 0.2, rounds=rounds, receivers=rx))
        ... full / no_probation / required via replay_with; echo_metric true/poison; first acceptance round of poison keys
EOF
BYZANTINE_LATENT_POISON rounds 12 full: true 0.5454545454545454 poison 0.0 poison-first-rounds [] | no_probation: true 0.6363636363636364 poison 1.0 poison-first-rounds [0, 0, 0, 0] | required: true 0.8181818181818182 poison 1.0 poison-first-rounds [0, 0, 0, 0]
BYZANTINE_LATENT_POISON rounds 24 full: true 0.5454545454545454 poison 0.0 poison-first-rounds [] | no_probation: true 0.6363636363636364 poison 1.0 poison-first-rounds [0, 0, 0, 0] | required: true 0.8181818181818182 poison 1.0 poison-first-rounds [0, 0, 0, 0]
BYZANTINE_LATENT_POISON rounds 36 full: true 0.5454545454545454 poison 0.0 poison-first-rounds [] | no_probation: true 0.6363636363636364 poison 1.0 poison-first-rounds [0, 0, 0, 0] | required: true 0.8181818181818182 poison 1.0 poison-first-rounds [0, 0, 0, 0]
SLOW_POISON rounds 12 full: true 0.8181818181818182 poison 0.0 poison-first-rounds [] | no_probation: true 0.8181818181818182 poison 0.25 poison-first-rounds [6] | required: true 0.8181818181818182 poison 0.25 poison-first-rounds [6]
SLOW_POISON rounds 24 full: true 0.8181818181818182 poison 0.0 poison-first-rounds [] | no_probation: true 0.8181818181818182 poison 0.25 poison-first-rounds [6] | required: true 0.8181818181818182 poison 0.25 poison-first-rounds [6]
SLOW_POISON rounds 36 full: true 0.8181818181818182 poison 0.0 poison-first-rounds [] | no_probation: true 0.8181818181818182 poison 0.25 poison-first-rounds [6] | required: true 0.8181818181818182 poison 0.25 poison-first-rounds [6]
NONE rounds 12 full: true 0.5454545454545454 poison None poison-first-rounds [] | no_probation: true 0.6363636363636364 poison None poison-first-rounds [] | required: true 0.8181818181818182 poison None poison-first-rounds []
NONE rounds 24 full: true 0.5454545454545454 poison None poison-first-rounds [] | no_probation: true 0.6363636363636364 poison None poison-first-rounds [] | required: true 0.8181818181818182 poison None poison-first-rounds []
NONE rounds 36 full: true 0.5454545454545454 poison None poison-first-rounds [] | no_probation: true 0.6363636363636364 poison None poison-first-rounds [] | required: true 0.8181818181818182 poison None poison-first-rounds []
loadavg (19.68896484375, 17.45166015625, 14.634765625)
```

### B.9 F6 and gravity on two corpus seeds
```
$ PYTHONHASHSEED=0 python - <<'EOF'   # F6 and gravity rows on two corpus seeds
from pocketsec.stage7.labs.byzantine_suite import _RunCache, _distance_auc_row, _gravity_row
for seed, fs in ((7,0),(11,1)):
    c = build_fleet_corpus(seed=seed); cache = _RunCache(c, rounds=12, seed=fs, receivers=default_receivers(c))
    print("corpus", seed, _distance_auc_row(cache)); print("corpus", seed, _gravity_row(cache))
EOF
corpus 7 AblationRow(core_id='ORPH-F05', flag='epistemic_distance_auc', control='role equality', metric='AUC(-D_E predicts local usefulness) on NONE', full_value=0.42994505494505497, control_value=0.41774402068519717, delta=0.012201034259857801, firing_count=214, verdict='NOT_YET_JUSTIFIED')
corpus 7 AblationRow(core_id='ORPH-F06', flag='gravity', control='validate every capsule (counterfactual bound)', metric='true keys lost to triage (lower is better)', full_value=0.0, control_value=0.0, delta=0.0, firing_count=287, verdict='NOT_YET_JUSTIFIED')
corpus 11 AblationRow(core_id='ORPH-F05', flag='epistemic_distance_auc', control='role equality', metric='AUC(-D_E predicts local usefulness) on NONE', full_value=0.8226584022038568, control_value=0.5795454545454546, delta=0.2431129476584022, firing_count=152, verdict='JUSTIFIED')
corpus 11 AblationRow(core_id='ORPH-F06', flag='gravity', control='validate every capsule (counterfactual bound)', metric='true keys lost to triage (lower is better)', full_value=0.0, control_value=0.0, delta=0.0, firing_count=296, verdict='NOT_YET_JUSTIFIED')
loadavg (14.24267578125, 12.60693359375, 13.1015625)
```

### B.10 Resources: flood + scale to 100k, CPU ratio
```
$ PYTHONHASHSEED=0 /usr/bin/time -v python benchmarks/stage7/resources.py --identities 1000 --scale 10000 30000 100000
start 15:41:45 load 12.62 9.40 10.89 16/1791 2760627
flood identities 1000: deliveries 56042, keys offered 1024
  over_cap []
  at_cap ['keyring']
  pressure {'echo_keys': 0, 'graph': 0, 'keyring': 0, 'lineage': 0, 'novelty': 0, 'peers': 0, 'pool': 0, 'replay_keys': 0, 'replay_seen': 0, 'trust': 0}
  governor_refused {'inbound:oversize': 4000, 'inbound:peer_bytes': 3516, 'inbound:round_bytes': 44590} outbound_over []
  scale peers 10000: refused 8976 table 1024 store bytes 10737538 work units 185162
  scale peers 30000: refused 28976 table 1024 store bytes 23122979 work units 546254
  scale peers 100000: refused 96928 table 1024 store bytes 66246025 work units 1819927
  peak sampled RSS 405090304 B, incremental 355151872 B, within ceiling False, edge profile within target False; cpu 811.07 s wall 1110.71 s at loadavg (14.85, 15.23, 14.55)
  store bytes at end {'bridge': 0, 'echo': 17281, 'fabric': 29812, 'governor': 536, 'graph': 249929, 'hypergraph': 936, 'ingress': 132122, 'keyring': 563472, 'lineage': 28314, 'novelty': 384, 'peers': 74370, 'reconstructor': 64, 'replay': 162530, 'revocations': 824, 'trust': 2060}
cpu ratio {"deliveries": 503, "pooled": 216, "fabric_cpu_s": 1.5789523239999426, "fabric_wall_s": 1.5794371480005793, "fabric_cpu_per_delivery_s": 0.0031390702266400447, "median_lv_cpu_s_same_pools": 0.005232542000044305, "ratio_fabric_over_median_lv": 301.7562637789765, "loadavg_before": [14.85, 15.23, 14.55], "loadavg_after": [14.85, 15.23, 14.55], "note": "fabric cpu includes simulating the senders' traffic (signing) \u2014 an upper bound on receiver cost; the median figure excludes local validation replay that the fabric also pays"}
wrote /home/anil/Documents/Research/pocketsec/results/stage7-resources-i1000.json
	Command being timed: "python benchmarks/stage7/resources.py --identities 1000 --scale 10000 30000 100000"
	User time (seconds): 807.21
	Elapsed (wall clock) time (h:mm:ss or m:ss): 18:35.74
	Maximum resident set size (kbytes): 395160
	Exit status: 0
exit 0
```

### B.11 Scale memory attribution
```
$ PYTHONHASHSEED=0 python - <<'EOF'   # scale-run memory attribution: receiver stores vs simulated senders
... replicates labs.partition.run_scale for n in (10000, 30000), once with the lab keyring
(capacity n+64) and once with the production keyring (MAX_KEYS); prints fabric.memory_bytes()
and /proc/self/statm RSS deltas
EOF
n=10000 [lab keyring n+64] keys provisioned 10000 peers table 1024 refused 8976 store bytes total 10338832 top [('keyring', 5365692), ('replay', 2795136), ('graph', 1273990), ('peers', 453864), ('ingress', 207166)]; RSS: simulated senders +18800640 B, receiver+senders now +33083392 B over start; loadavg (16.08, 14.01, 13.92)
n=10000 [production keyring MAX_KEYS] keys provisioned 1018 peers table 1018 refused 0 store bytes total 3175663 top [('graph', 1267582), ('keyring', 563472), ('peers', 451458), ('replay', 444314), ('ingress', 205853)]; RSS: simulated senders +18800640 B, receiver+senders now +33153024 B over start; loadavg (16.11, 14.31, 14.03)
n=30000 [lab keyring n+64] keys provisioned 30000 peers table 1024 refused 28976 store bytes total 22582541 top [('keyring', 17106684), ('replay', 3133744), ('graph', 1273990), ('peers', 453864), ('lineage', 292287)]; RSS: simulated senders +36671488 B, receiver+senders now +74829824 B over start; loadavg (9.4, 12.82, 13.55)
n=30000 [production keyring MAX_KEYS] keys provisioned 1018 peers table 1018 refused 0 store bytes total 3339772 top [('graph', 1267582), ('keyring', 563472), ('peers', 451458), ('replay', 444314), ('lineage', 292287)]; RSS: simulated senders +36671488 B, receiver+senders now +71733248 B over start; loadavg (14.56, 13.25, 13.59)
```

### B.12 Lab flood own-key probe
```
$ PYTHONHASHSEED=0 python - <<'EOF'   # lab flood: where is the receiver's own key in the directory?
for n in (1000, 1004, 1010, 1100, 2000):
    f = SimulatedFleet(c, FleetSpec(arm=AdversaryArm.FLOOD, sybils_per_root=n, rounds=4, seed=0, receivers=(r,)))
    ... position of fleet.peer_of_host(r)'s key in f.key_directory(r); try simulated_receiver(c, f, r)
EOF
MAX_KEYS 1024
1000 directory 1024 own-key position [915] built
1004 directory 1028 own-key position [919] built
1010 directory 1034 own-key position [925] built
1100 directory 1124 own-key position [1003] built
2000 directory 2024 own-key position [1808] ContractError: only an ACTIVE registered key can sign: 'key-fe2869be5fead229'
```

### B.13 Churn
```
$ PYTHONHASHSEED=0 python - <<'EOF'   # churn endurance at 720 / 2160 / 4320 rounds, then 18000
from pocketsec.stage7.labs.partition import run_churn_endurance
c = build_fleet_corpus(seed=7)
for rounds in (720, 2160, 4320): r = run_churn_endurance(c, rounds=rounds, seed=0); print(...)
EOF
CHURN_ROUNDS 720
720 peers_seen 1727 plateau_ok False unplateaued (('lineage', 1003, 1243),) peaks (('echo_keys', 4, 1024), ('graph', 529, 1024), ('keyring', 1024, 1024), ('lineage', 1243, 16384), ('novelty', 0, 1024), ('peers', 529, 1024), ('pool', 0, 2048), ('replay_keys', 529, 4096), ('replay_seen', 989, 8192), ('trust', 49, 4096)) evictions (('echo_keys_refused', 0), ('graph_evicted', 0), ('keyring_refused', 727), ('lineage_evicted', 0), ('peers_evicted', 0), ('peers_refused', 0), ('replay_evicted', 0), ('trust_evicted', 0)) wall 23.7s load (16.4169921875, 13.69677734375, 13.43603515625)
2160 peers_seen 5140 plateau_ok False unplateaued (('lineage', 1963, 2683),) peaks (('echo_keys', 4, 1024), ('graph', 529, 1024), ('keyring', 1024, 1024), ('lineage', 2683, 16384), ('novelty', 0, 1024), ('peers', 529, 1024), ('pool', 0, 2048), ('replay_keys', 529, 4096), ('replay_seen', 989, 8192), ('trust', 49, 4096)) evictions (('echo_keys_refused', 0), ('graph_evicted', 0), ('keyring_refused', 4140), ('lineage_evicted', 0), ('peers_evicted', 0), ('peers_refused', 0), ('replay_evicted', 0), ('trust_evicted', 0)) wall 73.4s load (16.13330078125, 14.23388671875, 13.64697265625)
4320 peers_seen 10262 plateau_ok False unplateaued (('lineage', 3403, 4843),) peaks (('echo_keys', 4, 1024), ('graph', 529, 1024), ('keyring', 1024, 1024), ('lineage', 4843, 16384), ('novelty', 0, 1024), ('peers', 529, 1024), ('pool', 0, 2048), ('replay_keys', 529, 4096), ('replay_seen', 989, 8192), ('trust', 49, 4096)) evictions (('echo_keys_refused', 0), ('graph_evicted', 0), ('keyring_refused', 9262), ('lineage_evicted', 0), ('peers_evicted', 0), ('peers_refused', 0), ('replay_evicted', 0), ('trust_evicted', 0)) wall 133.7s load (14.25634765625, 14.359375, 13.7890625)
exit 0
```
```
$ (same, rounds=18000)
18000 peers_seen 42814 plateau_ok False unplateaued (('lineage', 12523, 16384),) peaks (('echo_keys', 4, 1024), ('graph', 529, 1024), ('keyring', 1024, 1024), ('lineage', 16384, 16384), ('novelty', 0, 1024), ('peers', 529, 1024), ('pool', 0, 2048), ('replay_keys', 529, 4096), ('replay_seen', 989, 8192), ('trust', 49, 4096)) evictions (('echo_keys_refused', 0), ('graph_evicted', 0), ('keyring_refused', 41814), ('lineage_evicted', 2139), ('peers_evicted', 0), ('peers_refused', 0), ('replay_evicted', 0), ('trust_evicted', 0)) wall 312.4s load (5.380859375, 7.02734375, 10.16943359375)
exit 0
```

### B.14 Coarse-context linkability
```
$ PYTHONHASHSEED=0 python benchmarks/stage7/linkability.py --corpus-seed 7; … --corpus-seed 11
role                                             distinct   4  hosts with anonymity set 1: 0/22  histogram {2: 2, 4: 8, 12: 12}
software_epoch                                   distinct   4  hosts with anonymity set 1: 0/22  histogram {2: 2, 4: 8, 12: 12}
role+software_epoch                              distinct   4  hosts with anonymity set 1: 0/22  histogram {2: 2, 4: 8, 12: 12}
role+family_profile                              distinct  15  hosts with anonymity set 1: 10/22  histogram {1: 10, 2: 6, 3: 6}
role+software_epoch+family_profile+visibility    distinct  15  hosts with anonymity set 1: 10/22  histogram {1: 10, 2: 6, 3: 6}
distinct (kernel_id, package_digest) in the corpus: 4 over 24 hosts; exporting hosts 22; capsules 31
wrote /home/anil/Documents/Research/pocketsec/results/stage7-linkability-c7.json
role                                             distinct   4  hosts with anonymity set 1: 0/22  histogram {2: 2, 4: 8, 12: 12}
software_epoch                                   distinct   4  hosts with anonymity set 1: 0/22  histogram {2: 2, 4: 8, 12: 12}
role+software_epoch                              distinct   4  hosts with anonymity set 1: 0/22  histogram {2: 2, 4: 8, 12: 12}
role+family_profile                              distinct  13  hosts with anonymity set 1: 8/22  histogram {1: 8, 2: 6, 4: 8}
role+software_epoch+family_profile+visibility    distinct  13  hosts with anonymity set 1: 8/22  histogram {1: 8, 2: 6, 4: 8}
distinct (kernel_id, package_digest) in the corpus: 4 over 24 hosts; exporting hosts 22; capsules 36
wrote /home/anil/Documents/Research/pocketsec/results/stage7-linkability-c11.json
```

### B.15 Ledger writes
```
$ python benchmarks/stage7/register.py <id> <result json> <title> <command>   (x9)
recorded PS-S7-20260926-H8-fraction-sweep-default-0002 -> results/PS-S7-20260926-H8-fraction-sweep-default-0002.json
recorded PS-S7-20260926-H8-fraction-sweep-all-c7-0003 -> results/PS-S7-20260926-H8-fraction-sweep-all-c7-0003.json
recorded PS-S7-20260926-H8-fraction-sweep-all-c11-0004 -> results/PS-S7-20260926-H8-fraction-sweep-all-c11-0004.json
recorded PS-S7-20260926-H8-echo-config-grid-c7-0005 -> results/PS-S7-20260926-H8-echo-config-grid-c7-0005.json
recorded PS-S7-20260926-H8-echo-config-grid-c11-0006 -> results/PS-S7-20260926-H8-echo-config-grid-c11-0006.json
recorded PS-S7-20260926-H8-resources-scale-0007 -> results/PS-S7-20260926-H8-resources-scale-0007.json
recorded PS-S7-20260926-H8-linkability-c7-0008 -> results/PS-S7-20260926-H8-linkability-c7-0008.json
recorded PS-S7-20260926-H8-linkability-c11-0009 -> results/PS-S7-20260926-H8-linkability-c11-0009.json
recorded PS-S7-20260926-H8-echo-refusals-0010 -> results/PS-S7-20260926-H8-echo-refusals-0010.json
integrity []
74 experiments/registry.jsonl
```
```
$ /usr/bin/time -v python -m pocketsec.stage7.cli experiments --register
start 16:53:20 load 0.60 3.13 7.32 2/1756 3115294
exit 1
end 17:00:38 load 2.00 1.98 5.13 2/1729 3135504
registered 18 entries: ['PS-S7-20260926-BASE-orpheus-gate-0001', 'PS-S7-20260926-H8-ablation-0001', 'PS-S7-20260926-H8-ablation-0002', 'PS-S7-20260926-H8-ablation-0003', 'PS-S7-20260926-H8-ablation-0004', 'PS-S7-20260926-H8-ablation-0005', 'PS-S7-20260926-H8-ablation-0006', 'PS-S7-20260926-H8-ablation-0007', 'PS-S7-20260926-H8-ablation-0008', 'PS-S7-20260926-H8-ablation-0009', 'PS-S7-20260926-H8-ablation-0010', 'PS-S7-20260926-H8-ablation-0011', 'PS-S7-20260926-H8-ablation-0012', 'PS-S7-20260926-H8-ablation-0013', 'PS-S7-20260926-H8-ablation-0014', 'PS-S7-20260926-H8-ablation-0015', 'PS-S7-20260926-H8-ablation-0016', 'PS-S7-20260926-H8-ablation-0017']
gate result: FAILED (5)
	User time (seconds): 437.33
	Elapsed (wall clock) time (h:mm:ss or m:ss): 7:17.64
	Maximum resident set size (kbytes): 291000
	Exit status: 1
```
```
$ python benchmarks/stage7/register.py PS-S7-20260926-H8-echo-refusals-v2-0011 …
recorded PS-S7-20260926-H8-echo-refusals-v2-0011 -> results/PS-S7-20260926-H8-echo-refusals-v2-0011.json
93 experiments/registry.jsonl
integrity problems []
```


---

## Honesty ledger

### MEASURED

Rows M0.1–M0.5 are the spec-time probes (`docs/stage-7-spec.md` §0); they were not re-run in
this session. Every other row was produced by code run in this session unless the row says
"integration session". The fleet is simulated and the corpora are synthetic, so **every** row
is synthetic: yes.

| claim | value | how it was produced (module:function) | experiment id | synthetic? |
|---|---|---|---|---|
| M0.1–M0.5 (spec) | see `docs/stage-7-spec.md` §0 | spec-time probes | — | yes |
| gate criteria met | 6/11 (fails G7.4, G7.5, G7.8, G7.10, G7.11); loadavg 7.10 → 19.69 | `pocketsec.stage7.gate:run_gate` via `cli --json gate`, seed 0, corpus 7 | PS-S7-20260926-BASE-orpheus-gate-0001 (see Appendix B for its registration) | yes |
| bridged = admitted = offered; Stage 6 buckets | 2254 = 2254 = 2254; UNCERTAIN 2254, TRUSTED_CANDIDATE 0 | `gate_evidence:observe_run` | same | yes |
| unanimous-fleet refusals | 1024/1024 revoke, 1024/1024 contest, 1024/1024 authority, 4/4 CHALLENGED | `gate_evidence:unanimous_evidence` | same | yes |
| wire-key authority fuzz | 372/372 refused | `gate_construction:check_g7_2` | same | yes |
| offline equivalence | identical digests at 4/4 receivers over 5 conditions | `labs.partition:run_offline_equivalence` | same | yes |
| honest false-Sybil merge rate | 216/881 = 0.245 | `gate_evidence:non_iid_evidence` | same | yes |
| revocation targeted/reversible | 15 descendants, 0 non-descendants changed, byte-identical reinstate; 0/80 false revocations accepted | `gate_evidence:revocation_evidence`, `false_revocation_evidence` | same | yes |
| incremental RSS, gate flood + 10k scale | 44 421 120 B (loadavg 4.19) | `governor.communication:measure_stage7_resources` | same | yes (dev host) |
| gate process maximum RSS | 290 992 kB | `/usr/bin/time -v` around the gate | — | yes |
| detection at share 0 (recall@FPR 0.01): ECHO / VALIDATION_FILTER / MEDIAN / NO_SHARING | corpus 7×4: 0.571 / 0.786 / 0.000 (FP 11/60) / 0.000; corpus 7×24: 0.728 / 0.901 / 0.000 / 0.086; corpus 11×24: 0.432 / 0.905 / 0.000 / 0.162 | `stage0.benchmark.harness:run_benchmark` over `benchmarks/stage7/_common.py:AntibodySetSlot` | PS-S7-20260926-H8-fraction-sweep-default-0002, -all-c7-0003, -all-c11-0004 | yes (counterfactual_at_boundary) |
| ECHO catches a strict subset of VALIDATION_FILTER's catches | only-ECHO 0 on 4/4 receiver sets; only-baseline 3, 14, 7, 35 | `benchmarks/stage7/paired_detection.py:main` | (not registered; printed output in Appendix B) | yes |
| detection gain over NO_SHARING at BYZANTINE_POISON 0.2 | 0.000 (4 receivers, both 24-receiver sets) | `run_benchmark` via `fraction_sweep.py` | -0002, -0003, -0004 | yes |
| break points (MEDIAN / MEDIAN+LV / ROOT_QUORUM+LV / ECHO) | SYBIL_ADAPTIVE 0.04 / 0.04 / 0.077 / 0.143; DECLARED and FORGED 0.04 / 0.04 / none / none; LATENT 0.1 / 0.1 / none / none; COLLUSION 0.1 / 0.1 / 0.1 / 0.2 | `labs.byzantine_suite:break_points` | -0002, -0003, -0004 | yes |
| poison bridged into Stage 6 | COLLUSION 0.2/0.3: 4 → 16/28 capsules (4 receivers), 22 → 88/154 (24 receivers); SYBIL_ADAPTIVE S ≥ 4: 22 → 66–134; all UNCERTAIN, 0 TRUSTED_CANDIDATE | `hivelock.stage6_bridge:Stage6Bridge.receipts` | -0002, -0003, -0004 | yes |
| epistemic distance off vs shipped ECHO | no worse in 55/55 cases on both corpora; strictly better recall in 39 on each | `labs.partition:replay_with` via `config_grid.py` | PS-S7-20260926-H8-echo-config-grid-c7-0005, -c11-0006 | yes |
| F6: AUC(−D_E predicts usefulness) | corpus 7: 0.430 (role 0.418); corpus 11: 0.823 (role 0.580) | `labs.byzantine_suite:_distance_auc_row` | (not registered; Appendix B) | yes |
| probation on LATENT_POISON | poison 1.000 without, 0.000 with, at 12/24/36 rounds | `replay_with` horizon script | (not registered; Appendix B) | yes |
| contextual trust / contest mass switched off | acceptance unchanged in 7/7 cases each | `benchmarks/stage7/echo_refusals.py` | PS-S7-20260926-H8-echo-refusals-0010 | yes |
| coarse-context anonymity sets | 10/22 (corpus 7) and 8/22 (corpus 11) exporting hosts singled out by (role, family_profile) | `benchmarks/stage7/linkability.py` | -linkability-c7-0008, -c11-0009 | yes |
| incremental RSS, flood + scale to 100k offered peers | 355 151 872 B; edge profile exceeded (386.3 MB); loadavg 14.85. **Harness-dominated** (§M.8) | `measure_stage7_resources` via `resources.py` | PS-S7-20260926-H8-resources-scale-0007 | yes |
| receiver store bytes, production keyring, 10k / 30k offered | 3 175 663 / 3 339 772 B | `OrpheusFabric.memory_bytes` (getsizeof estimate) | (Appendix B) | yes |
| fabric / MEDIAN+LV CPU on the same pools | ≈ 302× (fabric 3.14 ms per delivery including sender simulation); loadavg 14.85 | `time.process_time` in `resources.py:cpu_ratio` | -resources-scale-0007 | yes |
| churn lineage peaks | 1243 / 2683 / 4843 / 16 384 at 720 / 2160 / 4320 / 18 000 rounds; 2139 evictions at the cap | `labs.partition:run_churn_endurance` | (Appendix B) | yes |
| lab flood own-key ordering | the receiver fails to build at 2000 identities (own key at position 1808 of 2024) | `labs.partition:simulated_receiver` probe | (Appendix B) | yes |
| Stage 7 tests | 373 run, 0 failed, 0 errors, 0 skipped | pytest `--junitxml` | — | n/a |
| gate reproduction without a hash seed, and the contention it shows | 6/11 again, same five failures; 7:17.64 wall and 437.33 s CPU at load 0.60–2.00, against 18:12.66 and 910.08 s at load 7.10–19.69 | `cli experiments --register` under `/usr/bin/time -v` | PS-S7-20260926-BASE-orpheus-gate-0001, H8-ablation-0001..0017 | yes |
| local validation's effect on identity aggregators | MEDIAN → MEDIAN+LV: share-0 FP 11/60 → 0 (recall@0.01 0.000 → 0.786); BYZANTINE_POISON break 0.1 → none | `run_benchmark` via `fraction_sweep.py` | -0002 | yes |
| (integration session, reproduced) ECHO amplification on SYBIL_ADAPTIVE | 4.590–12.467 | `labs.byzantine_suite:run_byzantine_suite` | gate | yes |
| (integration session, reproduced) membership advantage, distilled vs raw | 0.000 vs 1.000 (200 trials) | `labs.privacy_attacks:membership_inference` | gate | yes |

### UNMEASURED

| claim the architecture makes | why not measured | what would measure it | blocking? |
|---|---|---|---|
| Real network latency, partitions, real Sybil populations | No network exists; the fleet is simulated in-process | A real fleet | yes, for deployment |
| Realised on-host collective detection | Stage 6 admits no foreign capsule (B7-1): 0/2254 TRUSTED_CANDIDATE | A revised Stage 6 foreign prior | yes (G7.8) |
| Stage 6-side revocation rollback | Stage 6 has no revocation input (B7-2) | A Stage 6 revocation API | no |
| Stage 7 endpoint RSS at 100k offered peers | Process RSS includes 100k simulated senders and the lab's n+64 keyring; RSS cannot separate them | A receiver-only process fed from outside | no |
| A real 2 GB device | Dev host only | A device run | no |
| Edge-profile `model_bytes` | Stage 7 ships no model | n/a | G7.10 reports it |
| FedProx / personalised FL baselines | No model parameters exist (ADR-0062) | n/a | no |
| A DP guarantee | Seeded RNG; count releases only; basic composition | A formal analysis and a CSPRNG | no |
| Timing side channels, and `sequence` volume leakage over time | Not built or measured | A longitudinal export analysis | no |
| `software_epoch` identifiability in a real fleet | The generator has 4 images | Real image diversity | no |
| Ed25519, mTLS, zstd, QUIC | stdlib only (ADR-0001) | Third-party libraries | no |
| An adversary that adapts to probation's hold length | Adversaries share an author with the defences | An independent red team | yes, for any robustness claim |
| Lab flood above about 1100 identities | Receiver own-key ordering trap (§M.8) | A lab fix | no |
| The full repository test suite | Not run by this session | `pytest` over `tests/` | no |

### REJECTED

| component | measured effect | verdict (REJECTED / NOT-YET-JUSTIFIED / RETRACTED / INERT / DEGENERATE / HARMFUL) | ADR |
|---|---|---|---|
| ECHO as shipped (against NO_SHARING, MEDIAN, VALIDATION_FILTER and ROOT_QUORUM+LV) | detection 0.000 under BYZANTINE_POISON 0.1–0.6; at share 0 it catches a strict subset of VALIDATION_FILTER's catches (0.571 vs 0.786; 0.728 vs 0.901; 0.432 vs 0.905); robustness better than MEDIAN on every Sybil and latent arm | NOT-YET-JUSTIFIED | 0068 |
| epistemic distance as an ECHO weight | no worse in 55/55 cases on both corpora when off; recall +0.215 (corpus 7) and +0.417 (corpus 11) at NONE | HARMFUL | 0069 |
| epistemic distance as a predictor (F6) | AUC 0.430 (corpus 7) vs 0.823 (corpus 11) | NOT-YET-JUSTIFIED (unstable) | 0069 |
| contextual trust, falsification weight, contest mass | 0 firing in the gate; acceptance unchanged in 7/7 replays | INERT | 0069 |
| gravity, antibody minimisation, hypergraph | delta 0.000 | NOT-YET-JUSTIFIED | 0069 |
| secure aggregation | +8.000 count inflation under Sybils | HARMFUL | 0069 (off per 0066) |
| plain identity aggregators without local validation (MAJORITY, MEAN/FedAvg rule, MEDIAN, TRIMMED_MEAN) | recall@FPR 0.01 = 0.000 with no adversary (FP 11/60) | REJECTED as a sharing baseline worth shipping | 0068 |
| dependence clustering's false-merge behaviour (not the mechanism) | 24.5 % honest false merges; turns ROOT_QUORUM's BYZANTINE_POISON recall 11/14 → 0/14 | HARMFUL side effect (the mechanism itself is JUSTIFIED for Sybils) | 0069 |
| "Stage 7 as a detection accelerator" (the value claim) | see ECHO row; realised value 0 by B7-1 | NOT-YET-JUSTIFIED; ship the boundary only | 0067, 0068 |

### RETRACTED

| retracted claim | where it was published | the defect | corrected value |
|---|---|---|---|
| "a suppression attack can at most delay a real campaign" | `docs/stage-7-spec.md` D7.15 | It holds only for bounded suppression | 4 SUPPRESSION cases never detected (reproduced this session) |
| Probation is NOT_YET_JUSTIFIED (firing 1, delta 0) | the gate's ablation row; Appendix A §A.3 | It was measured on one arm (COLLUSION_TIMING), where every configuration accepts poison | On LATENT_POISON it moves poison acceptance 1.000 → 0.000: a trade-off, not "no effect" |
| "Nothing host-identifying leaves the host" (spec §1 thesis sentence), as applied to the coarse-context fields | `docs/stage-7-spec.md` §1 | Coarse-context fields were treated as non-identifying without an anonymity measurement | (role, family_profile) singles out 10/22 and 8/22 exporting hosts |
| collective_novelty and differential_privacy JUSTIFIED | §M.5.1, §A.3, ADR-0069 | corpus-free toy probes; the fabric never exercises either (review F4) | INERT on the fabric path: firing 0 (§R.5) |
| gravity NOT_YET_JUSTIFIED, firing 287 | §M.5.1, §M.5.2, §A.3, ADR-0069 | all 287 triages came from dividing by cluster size, which the cluster cap already counts (R7-5) | INERT, firing 0 (§R.3) |
| ECHO_PROBATION_ROUNDS inert under ×0.5 / ×2 | §M.5.2, §A.3, ADR-0069 | the flip metric could not see a change of first-ELIGIBLE round (S7-R7) | flip share 0.444 / 0.333 (§R.5) |
| property inference: distilled 0.163 vs raw 0.198, chance 0.667, 200 trials | §M.7, G7.7 | resampling over 22/24 hosts; one chance for two rows (F8) | exhaustive: 0.182 (chance 0.727) vs 0.208 (chance 0.667) (§R.5) |
| G7.3 offline digest shows the fabric cannot touch local state | §M.6 | the digest read only the benign ring (F2) | now digests validator state, verdicts, sovereignty keys and local lineage; still identical 4/4 (§R.5) |
| churn stores "bounded by refusal"; keyring refusals 727 / 4140 / 9262 / 41 814 | §M.8, §A.3 | the keyring never reclaimed dead keys, so the receiver stopped admitting (R7-4) | 0 refusals; graph and peer table grow to their caps (§R.4) |

### NOT A DETECTION RESULT

Every corpus in this document is synthetic: Stage 7's `labs/fleet_corpus.py` at corpus seeds 7
and 11, built from Stage 1's scenario vocabulary. The fleet is simulated in-process, with no
network, and the adversaries are written by the same author as the defences.

Every detection figure is a counterfactual at the Stage 7 → Stage 6 boundary, because Stage 6
admits no foreign capsule. Realised on-host collective detection is 0 by construction.

The fleet corpus is DEGENERATE_IN_FAVOUR of sharing (P5), so a gain over NO_SHARING says only
that transfer is possible on this generator. Nothing here says how any mechanism would perform
on real hosts.

### PARAMETERS

Every constant in `docs/stage-7-spec.md` §4.23 is **chosen, not measured**. That includes:
- the thresholds swept above: MASS_FLOOR, CLUSTER_CAP, CONTEST_RATIO, RELEVANCE_FLOOR,
  VALIDATION_FLOOR, TRUST_PRIOR, ECHO_PROBATION_ROUNDS;
- BREAK_LEVEL 0.5, FPR_BUDGET 0.01, DETECTION_GAIN_MIN 0.10;
- HONEST_ROOTS 16, SUITE_ROUNDS 12;
- the gate's sizes: 1000 flood identities, 64 unanimous peers, 4-round unanimous and flood runs.

The review-fix session added three more chosen parameters: `MAX_KEYS_PER_OPENER` = 128,
`KEY_TOMBSTONE_BITS` = 2^19, and the plateau rule's tolerance (a store's own largest
one-round change in the middle third, §R.4).

This session's own choices are also chosen, not measured:
- the corpus seeds (7, 11) and fleet seeds (0, 1);
- the scale sizes (10k, 30k, 100k);
- the churn lengths (720, 2160, 4320, 18 000 rounds);
- the four ECHO configurations of the grid.
