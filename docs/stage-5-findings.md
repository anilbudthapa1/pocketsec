# Stage 5 — SAFE + AEGIS + SENTINEL — findings (D5.20)

- **Date:** 2026-09-26
- **Written by:** the Stage 5 integrator (Part II, retained verbatim), the Stage 5
  measurement wave (Part I, the ledger rows marked `[M]`, Appendix A) and the Stage 5 fix
  wave (Part III, the ledger rows marked `[F]`)
- **Status of the phase:** **BLOCKED** on falsifier F5's size clause (integrator, Part II §3),
  unchanged by the measurement wave and by the fix wave (Part III).
- **Fix wave (Part III, 2026-09-26):** the assurance table now reads 6 / 7 / 2 (P1 and P2
  downgraded to TESTED); G5.13's earlier in-process "mutation" run is retracted as
  evidence and replaced by behavioural probes; five findings are accepted known defects
  with reasons (F.2).
- **The stage's central claim is NOT SUPPORTED by the measurements.** The claim under test
  (architecture §1 and §50, spec §1.1, the lead's mandate) is that the SAFE/AEGIS machinery —
  the SAFE Action Field, the Counterfactual Response Twin, the Intervention Cone, the Action
  Shadow and the Pareto/regret selector — chooses a smaller sufficient intervention than a
  simple playbook and beats it on measured collateral and effectiveness. On four synthetic
  corpora it contains nothing, and on Stage 4's real output nothing in Stage 5 can act at all.
  The safety boundary, by contrast, holds on every construction criterion measured.

# Part I — measurement wave

## M.0 The results in eight lines

1. **The full planner contains 0 of 80 hostile incidents** across four corpora, cold and
   primed — exactly what act-never (B1) contains. What it adds over B1 is observations and
   escalations to a person: it is a recommender (falsifier F7's "recommendation-only mode").
   (PS-S5-20260926-BASE-arms-counter-corpora-0002)
2. **Why:** the cone-informed Action Shadow of each containment candidate is a per-operator
   *constant* (0.4146 `SUSPEND_PROCESS`, 0.3627 `RESTRICT_LOCAL_SOCKET`, on 20 of 20, 60 of 60
   and 20 of 20 cases in three builders) sitting just above the chosen 0.35 ceiling. The
   planner records `SHADOW` as the rejection on 20 of 20 containment candidates — cold as
   well as primed. (PS-S5-20260926-BASE-shadow-gate-0004)
3. **Ablation with headroom** (memory primed): removing the twin, the cone or the shadow gate
   (SAFE-F04/F05/F06) each takes the planner from 0 to 10 contained on C1 and from 0 to 5 on
   C2, at zero added collateral on every corpus — **measured HARMFUL on these corpora**. The
   other eight flags: no effect, cold or primed. (PS-S5-20260926-BASE-ablation-primed-0005)
4. **The fixed playbook's win is a label leak.** On the gate corpus, host Phi — B2's only
   input — is 4.0 on all 10 benign and 10.0 on all 10 hostile cases; B2 equals the answer on
   20 of 20. On a counter-corpus that re-hosts a quarter of each class, B2 falls to 5
   contained with 5 collateral, while a literal single-world control (SW) holds 10 with 0.
   (PS-S5-20260926-BASE-corpus-audit-0003, -arms-counter-corpora-0002)
5. **G5.9 cannot be passed by any policy on its own corpus**: on 30 of 30 ambiguous pairs no
   operator is sufficient on the compromised half and harmless on the benign half, so every
   policy acts on both halves or on neither; and the benign world leads on 30 of 30, so a
   single-world planner is exactly as cautious as the multi-world one.
   (PS-S5-20260926-BASE-corpus-audit-0003)
6. **End to end, the seam is inert.** Stage 4's real `CBFResolutionV1` exports for its 60
   gate incidents carry 0 of 3764 lineage rows with any Stage 5 target key; Stage 5 generates
   0 candidates and the planner returns `NO_ACTION` on 60 of 60. Every Stage 5 containment
   figure, this wave's and the integrator's, is about resolutions Stage 4 does not produce.
   (PS-S5-20260926-BASE-stage4-seam-0006)
7. **Bounded, but not live.** One long-lived executor stack stays inside every bound over 600
   actions, and refuses every new action after 82 (journal entries are never compacted);
   nothing outside the gate and the labs schedules the lease sweeper, so an unswept
   containment outlives its lease. (PS-S5-20260926-BASE-longlived-bounds-0007)
8. **Resource envelope met where measured**: SENTINEL + executor 4182016 B incremental RSS
   (target < 10 MB) with no planner module loaded; simulation workspace 9633792 B (target
   10–30 MB); peak sampled RSS 31846400–33726464 B per arm against the 104857600 B edge
   target; the full planner costs 3.0–3.9x the playbook's CPU per case cold, 35.9–44.9x
   primed. (PS-S5-20260926-BASE-component-rss-0008, -arms-counter-corpora-0002)

## M.1 How this wave measured

- **Instruments.** Stage 0's `ResourceSampler` around every arm, `check_profile("edge")`,
  `ExperimentRegistry.register` for the ledger and `results/<id>.json` for payloads
  (integration plan §5.3 steps 4–5). **`run_benchmark` was not used**: it requires a
  `ModelSlot` from `SecurityEventSequenceV1` to `ThreatPredictionV1`, and Stage 5 consumes a
  `CBFResolutionV1` plus a host and emits receipts. Wrapping a responder as a detector would
  invent an encoding and report a PR-AUC that measures the encoding. Stages 3 and 4 recorded
  their non-detector measurements the same way.
- **Scripts.** Ten scripts in `benchmarks/stage5/` (README there), each re-runnable as
  `PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage5/<script>.py`. They live outside the
  package because each needs something the stage forbids inside it: naming the executor (T4),
  importing a Stage 4 module other than `stage5_interface` (T1), a process launcher (P2), or
  loosening the shadow ceiling (a safety lever that must not ship).
- **Ledger.** Ten rows appended: `PS-S5-20260925-BASE-safe-gate-0001` (the id `gate.py` has
  always cited, registered here for the time it was run, after the gate completed so G5.15's
  byte-identity check is unaffected) and `PS-S5-20260926-BASE-*-0002` … `-0010`.
  `verify_integrity()` after appending: 41 entries, `[]` problems. Every row
  `synthetic_data: true`.
- **Corpora.** C1 `build_response_corpus(count=20, seed=11)` (the gate's); C2
  `build_decoupled_phi_corpus(count=20, seed=11)`; C3 `build_ambiguous_pairs(count=30,
  seed=11)`; C4 `build_hostile_leading_pairs(count=30, seed=11)`. C2 and C4 are new, in
  `pocketsec/stage5/labs/counter_corpora.py`, deterministic from the seed, tested by
  `tests/test_stage5_counter_corpora.py`. Stage 1's corpora were not used directly: Stage 5
  consumes Stage 4 resolutions and a host, not SSIR transitions. They reach Stage 5 through
  Stage 4 in M.7, and that path is itself the finding.
- **Contention.** Load average is recorded before and after every run (1.8–3.6 throughout).
  No absolute timing here is a device figure; only within-run ratios are quoted.
- **Rule 1** (session-unique identities): 80 of 80 distinct `(pid, start_time_ticks)` across C1
  and both pair orientations (PS-S5-20260926-BASE-corpus-audit-0003).

## M.2 Every arm on four corpora

`[contained, collateral, actions, escalations]`; hostile cases in brackets after each corpus;
CPU per case as a within-run ratio to B2 on the same corpus. `+p` = effectiveness memory
primed by the gate's own in-simulator LAB_SANDBOX drills. SW is the lead's baseline (2) as
literally specified (leading world plus the case's *policy* harm table; never `truth`; no
twin, cone, shadow, identifiability, memory or hysteresis), defined in
`benchmarks/stage5/arms.py`. PS-S5-20260926-BASE-arms-counter-corpora-0002, loadavg
3.59 → 3.11.

| arm | C1 (10) | C2 (10) | C3 (30) | C4 (30) | CPU/case vs B2, C1 / C2 / C3 / C4 |
|---|---|---|---|---|---|
| **AEGIS** | 0, 0, 10, 10 | 0, 0, 10, 10 | 0, 0, 60, 0 | 0, 0, 60, 0 | 3.9 / 3.3 / 3.4 / 3.0 |
| **AEGIS +p** | 0, 0, 10, 10 | 0, 0, 10, 10 | 0, 0, 60, 0 | 0, 0, 60, 0 | 44.9 / 39.6 / 36.1 / 35.9 |
| B1 act-never | 0, 0, 0, 0 | 0, 0, 0, 0 | 0, 0, 0, 0 | 0, 0, 0, 0 | 1.3 / 0.8 / 0.6 / 0.7 |
| **B2 fixed playbook** | 10, 0, 10, 0 | **5, 5**, 10, 0 | 30, 30, 60, 0 | 30, 30, 60, 0 | 1.0 |
| B4 act-always | 10, 10, 20, 0 | 10, 10, 20, 0 | 30, 30, 60, 0 | 30, 30, 60, 0 | 1.6 / 1.2 / 1.1 / 1.0 |
| B7 +p | 10, 0, 20, 0 | 5, 0, 15, 5 | 0, 0, 60, 0 | 0, 0, 60, 0 | 41.6 / 39.2 / 31.1 / 32.8 |
| B7 without hysteresis +p | 10, 0, 20, 0 | 10, 0, 20, 0 | 0, 0, 60, 0 | 0, 0, 60, 0 | 42.2 / 40.9 / 31.4 / 33.7 |
| **SW single-world** | 10, 0, 10, 0 | **10, 0**, 10, 0 | 0, 0, 0, 0 | 30, 30, 60, 0 | 1.1 / 1.6 / 0.7 / 1.2 |
| B9 human only | 10, 0, 20, 20 | 10, 0, 20, 20 | 30, 0, 60, 60 | 30, 0, 60, 60 | 1.2 / 1.2 / 1.1 / 1.0 |

B3, B5, B6, B8 and the cold B7 arms are in Appendix A.2. Planner faults: 0 in every row.
Totals over the 80 hostile cases: AEGIS 0 contained with 0 collateral; B1 0 with 0; SW 50 with
30 (all 30 on C4, where it is the act-always endpoint); B2 75 with 65.

**Reading.** No corpus has an arm that beats SW on both axes. AEGIS equals B1 on containment
everywhere. On C4 AEGIS sits at the act-never end of the frontier and SW at the act-always
end; that is the only corpus on which AEGIS is not dominated, and it is not dominated there
only because nothing can be (M.6). The primed arms' CPU cost is mostly the priming drills (16
per containment operator per case), not planning; the cold ratio (3.0–3.9x) is the planning
cost.

## M.3 Why the planner never acts: a shadow gate on a constant

PS-S5-20260926-BASE-shadow-gate-0004. Distinct Action Shadow values per operator over every
case of a builder:

| builder | cases | `SUSPEND_PROCESS` generation / cone-informed | `RESTRICT_LOCAL_SOCKET` generation / cone-informed |
|---|---|---|---|
| C1 | 20 | {0.25} / {0.4146} | {0.1667} / {0.3627} |
| C3 | 60 | {0.25} / {0.4146} | {0.1667} / {0.3627} |
| two-epoch (20, 11) | 20 | {0.25} / {0.4146} | {0.1667} / {0.3627} |
| evidence (6, 11) | 6 | {0.2917} / {0.4348} | {0.1667} / {0.3627} |
| flood (10, 11) | 10 | {0.25} / {0.4628} | {0.1667} / {0.4348} |

The shadow the planner gates on varies with the *shape* of a host (a 24-process flood host
scores higher) and not with anything about the incident. Across the gate's corpus it is one
number per operator, so `shadow_gate` acts as a fixed per-operator ban expressed through a
continuous score. The cone adds 0.1646 to `SUSPEND_PROCESS` and 0.1960 to
`RESTRICT_LOCAL_SOCKET`; generation-time shadow alone would pass the 0.35 ceiling. Rejection
reasons on C1's 10 hostile cases, full planner: cold `SUSPEND_PROCESS:SHADOW` 10 and
`RESTRICT_LOCAL_SOCKET:SHADOW` 10, decisions `ESCALATE` 10; primed identical.

## M.4 Ablation with headroom, and sensitivity

The gate's G5.14 ablation runs cold, where the planner never contains anything, so its eleven
deltas of 0.0 are a property of a planner that never acts (MEMORY.md trap 9). Leave-one-out
repeated cold and primed (PS-S5-20260926-BASE-ablation-primed-0005; `[contained, collateral]`
on C1 / C2 / C3 / C4; the full planner is `[0, 0]` on all four in both regimes):

| flag off | core id | cold | primed | verdict |
|---|---|---|---|---|
| `enable_twin` | SAFE-F04 | no change | **[10,0] / [5,0]** / [0,0] / [0,0] | **HARMFUL on these corpora** |
| `enable_cone` | SAFE-F05 | no change | **[10,0] / [5,0]** / [0,0] / [0,0] | **HARMFUL on these corpora** |
| `enable_shadow_gate` | SAFE-F06 | no change | **[10,0] / [5,0]** / [0,0] / [0,0] | **HARMFUL on these corpora** |
| `enable_multi_world` | (B7's switch) | no change | no change | NOT-YET-JUSTIFIED; the flag does not disable Response Identifiability (M.5) |
| `enable_regret` | SAFE-F07 | no change | no change | NOT-YET-JUSTIFIED |
| `enable_pareto` | SAFE-F08 | no change | no change | NOT-YET-JUSTIFIED |
| `enable_hysteresis` | SAFE-F18 | no change | no change | NOT-YET-JUSTIFIED (unreachable: the shadow gate refuses earlier) |
| `enable_effectiveness_memory` | SAFE-F20 | no change | no change | NOT-YET-JUSTIFIED |
| `enable_response_cells` | SAFE-F21, F22 | no change | no change | NOT-YET-JUSTIFIED (never consulted, ADR-0045) |
| `enable_residual` | SAFE-F16 | no change | no change | NOT-YET-JUSTIFIED |
| `enable_d3fend` | SAFE-F23 | no change | no change | NOT-YET-JUSTIFIED (0 of 14 mapped, ADR-0047) |

F04, F05 and F06 are one causal chain (the twin feeds the cone, the cone raises the shadow,
the gate compares it with the ceiling); removing any link has the same effect. "HARMFUL" here
means: costs containment and buys no collateral reduction on any of four corpora. It does not
mean the shadow gate is useless as a safety veto on a real host; nothing here measures that.
Spec §6 / G5.14 says a HARMFUL mechanism "is defaulted off with an ADR". **Not applied by this
wave**: the gate's own ablation reads 0.0, the three flags form a safety veto in the decision
path, and no ADR number in 0040–0049 is free. The decision is the lead's.

**Sensitivity, not tuning** (PS-S5-20260926-BASE-shadow-gate-0004). With
`SHADOW_AUTONOMY_CEILING` patched to 0.37, 0.42, 0.50 or 0.70 (and restored; the script
asserts it), primed AEGIS and primed B6 read `[10,0]` on C1, `[5,0]` on C2, `[0,0]` on C3 and
C4 at every value; cold AEGIS stays `[0,0]` everywhere (no reliability samples). At no
ceiling does AEGIS beat SW on any corpus. No value is proposed: choosing the ceiling on the
corpus it is scored on would fit the gate to the answer. B6 (scalar utility) equals AEGIS
(Pareto) in every cell at every ceiling — falsifier F4.

## M.5 The single-world control was not single-world

PS-S5-20260926-BASE-b7-identifiability-0010, primed, hostile cases, plan decisions and
containment-candidate rejection reasons:

| corpus | AEGIS | B7 | B7 without hysteresis |
|---|---|---|---|
| C1 | ESCALATE 10; SHADOW 20 | ACT 10 | ACT 10 |
| C2 | ESCALATE 10; SHADOW 20 | ACT 5, DEFER 5; HYSTERESIS 5 | ACT 10 |
| C4 | OBSERVE 30; NOT_IDENTIFIABLE 60 | OBSERVE 30; NOT_IDENTIFIABLE 60 | OBSERVE 30; NOT_IDENTIFIABLE 60 |

`NOT_IDENTIFIABLE` names the benign *rival* world ("causes unacceptable harm in
['admin_maintenance_window'], whose support exceeds RULED_OUT_SUPPORT"). B7 turns
`enable_multi_world` off, but Response Identifiability still evaluates every world, so B7 is
a multi-world planner without the twin and cone, and "full planner vs B7" in G5.9 and
ADR-0048 compared multi-world with multi-world. SW is the control the lead specified. The
other B7 difference is hysteresis: the controller's enter threshold reads host Phi at 6.0 —
the playbook's own signal and threshold — and HOLDs the 5 C2 hostile cases whose host Phi is
4.0.

## M.6 What the corpora let a trivial rule know, and what they cannot test

PS-S5-20260926-BASE-corpus-audit-0003:

| check | C1 | C2 | C3 (G5.9's shape) | C4 |
|---|---|---|---|---|
| host Phi by class | benign 4.0 ×10; hostile 10.0 ×10 | each class 5 at 4.0, 5 at 10.0 | — | — |
| B2's decision equals `truth` | **20 of 20** | 10 of 20 | — | — |
| Stage 4 leading world equals `truth` | 20 of 20 | 20 of 20 | — | — |
| pairs with identical resolutions | — | — | 30 of 30 | 30 of 30 |
| operators sufficient on the compromised half and not harmful on the benign half | — | — | **none, on 30 of 30** | **none, on 30 of 30** |
| benign world leads | — | — | 30 of 30 | 0 of 30 |

Also none on 30 of 30, and benign-leading on 30 of 30, on the gate's own G5.9 seed
(`build_ambiguous_pairs(count=30, seed=17)`, Appendix A.12). Two consequences:

- **C1 is saturated for B2**: one field solves it, which is why it could not show any mechanism
  helping, and why ADR-0048's F1 reading is stronger than the evidence. Stage 4's leading
  world is also the answer on 20 of 20, by the corpus author's choice, so any arm that reads it
  and acts is correct on C1 — which is what SW does.
- **G5.9 as operationalised is unsatisfiable by construction.** On an indistinguishable pair
  whose truth tables admit no operator that is sufficient in one world and harmless in the
  other, every policy produces (1 contained, 1 collateral) or (0, 0) per pair. "Reduces
  collateral at no loss of containment" cannot happen on this corpus for any planner. That is
  a property of the fixture, not of the planner; a pair that tests multi-world value needs an
  operator that is harmless in both worlds and sufficient in one, and the truth tables hold
  none.

## M.7 End to end: Stage 4's real output through Stage 5

PS-S5-20260926-BASE-stage4-seam-0006 (Stage 4's gate corpus, count 60, seed 11, through
`stage4.gate_criteria.drive_engine` and `close_incident`; Stage 4 engine 6.253 CPU s at
loadavg 2.61; exports digest `309dd1fc80db17a386dcc71d6a53814403c3dd77a04be720005bde59ce46bd3c`):

| quantity | value |
|---|---|
| identifiability / verdict | `UNKNOWN` 60 of 60 / `UNKNOWN` 60 of 60 |
| hypotheses per export | 2: 11, 3: 32, 4: 17 |
| lineage keys | `store`, `locator`, `digest` — 3764 each |
| lineage rows with any of `target_pid`, `target_unit`, `target_session`, `target_socket` | **0 of 3764** |
| Stage 5 candidates, all 60 exports | **0** |
| field truncation reasons (top four) | "identifiability UNKNOWN … only O0/O1" ×300; restoration refused ×240; cells key ×60; "no observable process target" ×60 |
| full-planner decision | `NO_ACTION` 60 of 60 |

Two independent reasons nothing acts: Stage 4 identifies nothing on its own corpus, and even
an identified incident would name no target Stage 5 can read, because Stage 4's exporter
writes `EvidenceRef` triples and Stage 5 reads four `target_*` keys that only Stage 5's own
fixture (`labs/response_corpus.py:_lineage_row`) writes. Two key spaces that can never match
— the lead's lesson (3). G5.1 passes on "53 of 53 seam symbols resolve", a check that a type
exists — the lead's lesson (4). ADR-0045's addendum records it; the fix changes Stage 4's
exporter and needs a new schema `$id`, so it is not this wave's to make.

## M.8 Resource cost against the edge envelope

The two §43 rows the gate reports UNMEASURED, measured in separate fresh processes as median
`ru_maxrss` minus an upstream-only baseline (24100 KB), 3 repeats each
(PS-S5-20260926-BASE-component-rss-0008, loadavg 2.40 → 2.69):

| row | work in the child | incremental RSS | tracemalloc peak | spec target |
|---|---|---|---|---|
| `sentinel_and_executor` | 100 raced transactions (100 refused at revalidation) + 100 un-raced (`COMMITTED_VERIFIED` 100) | **4182016 B** | 3562769 B | prefer < 10 MB |
| `simulation_workspace` | field + twin + cone for every candidate of the 40-case flood (640 cones) | **9633792 B** | 6232318 B | 10–30 MB on demand |

- The privileged child loaded **no** `aegis`, `safe`, `twin`, `cells` or `memory` module: the
  privileged half runs with the planner absent from the process.
- The gate still reports both rows UNMEASURED and G5.12 still fails: `resources.py` has no
  in-package producer for them, and P2 forbids the process launcher that produced these.
- Per arm (`check_profile("edge")` on each arm's sampler): peak sampled RSS 31846400–33726464 B
  over all 68 arm × corpus runs, against the 104857600 B edge target; `within_target` is
  `None` in every row because `model_bytes` is UNMEASURED (Stage 5 has no model) — reported as
  `None`, not as a pass.
- Whole gate process: `/usr/bin/time` max RSS 39652 KB, 11.56 s wall, loadavg 2.17 (A.1).
- CPU per case (M.2): the full planner 3.0–3.9x the playbook cold; SW 0.7–1.6x.

## M.9 Bounds and liveness under sustained load

PS-S5-20260926-BASE-longlived-bounds-0007: one kernel, journal, token store, lease registry,
governor and memory serving 600 hostile `SUSPEND_PROCESS` actions (each on its own simulated
host; corpus seeds 13–16), `ManualClock` moved only by the script.

| regime | outcomes over 600 | journal | spent nonces | traced heap over start |
|---|---|---|---|---|
| A: sweep after every action | `COMMITTED_VERIFIED` 82, then `REFUSED_JOURNAL_FULL` 518 (from action index 82) | 258224 B / 492 entries, full by action 100 | capped at 256, 426 evictions | 422692 B at 300, 425320 B at 600 |
| B: never sweep | `COMMITTED_VERIFIED` 9, `REFUSED_SENTINEL` 241 (`PRECONDITION` + `FORBIDDEN_COMBINATION`), `REFUSED_JOURNAL_FULL` 350 (from index 250) | 235301 B / 509 entries | capped at 256, 344 evictions | 352633 B at 300, 385117 B at 600 |
| C: 60 actions, never swept, clock moved past every hard deadline | 2 committed; **2 of 2 still suspended on their hosts**; leases expired by data 2, active 0 | — | — | — |

Every bound held: nothing grew past its constant. What does not hold is liveness. The journal
refuses instead of evicting (correct: evicting live rollback state would make a reversible
action permanent) but never compacts finalised, released actions, so a long-lived stack stops
acting after about 82 contain-and-rollback cycles. The gate's G5.12 figures (max journal
3296 B, max 1 lease) come from a fresh stack per case and cannot see this. And
`LeaseSweeper.sweep` has no caller outside `gate_runtime.py` and `labs/baselines.py`: lease
expiry is a pure function of the lease's data (P7), but the host change it should end
persists until something calls the sweeper, and the stage ships nothing that does. ADR-0044's
addendum records both.

## M.10 The hysteresis controller, in isolation

PS-S5-20260926-BASE-hysteresis-isolated-0009 — the real `HysteresisController` with
`DEFAULT_HYSTERESIS`, 240 samples 30 s apart, against a single 6.0 threshold:

| trace | hysteresis acts / releases | single threshold acts / releases | time to act |
|---|---|---|---|
| S1 alternating 5.5 / 6.5 | 1 / 0 | 120 / 119 | 30 s / 30 s |
| S2 uniform [3.5, 8.5], `random.Random(11)` | 1 / 0 | 64 / 63 | 30 s / 30 s |
| S3 step 4.0 → 10.0 at 600 s | 1 / 0 | 1 / 0 | 600 s / 600 s |

The mechanism does what §19 says, at no latency cost on a real step; under noise it never
releases, so containment length is set by the lease. End to end it is never reached by the
full planner (M.3) and costs primed B7 five containments on C2 (M.2, M.5). Verdict unchanged:
NOT-YET-JUSTIFIED as a system component (ADR-0049 addendum).

## M.11 The executor properties, as this wave counts them

Unchanged from the integrator's table (Part II §4): 8 PROVEN_BY_CONSTRUCTION, 5 TESTED, 2
UNMEASURED of 15; this wave's gate run reads the same counts and 8 of 8 mutations failing
their named test (A.1). This wave adds no property and upgrades none. Two measured facts bear
on rows the table already has: the privileged half ran 200 transactions with no planner module
in the process (M.8), and lease expiry — P7, a pure function of the lease — does not by itself
undo anything on the host (M.9).

## M.12 What would change this conclusion

- **A seam that carries targets.** If Stage 4's exporter named the process lineage it already
  attributes, in Stage 5's four `target_*` keys, and identified some incidents, M.7 could be
  re-run with something to act on. Until then no Stage 5 effectiveness figure describes the
  real pipeline.
- **A corpus with ground truth independent of both inputs.** Real or replayed incidents in
  which neither host Phi nor Stage 4's leading world is the label by construction, with an
  operator that is harmless in one world and sufficient in the other. There G5.9 becomes
  satisfiable, and the twin/cone/shadow chain could show that it refuses the *right* actions
  rather than all of them.
- **A calibrated shadow** (F3): at least 30 committed actions with measured residuals on a
  host whose consequences the twin did not author. If a calibrated ceiling separates harmful
  from harmless containments, SAFE-F04/05/06 move from HARMFUL to evaluable.
- **A real host** (ADR-0046): every rollback, recovery and collateral figure here is a property
  of `SimulatedHost`, a model this stage's authors wrote.
- **What would strengthen the rejection**: the same outcome on an independent corpus, or SW
  continuing to dominate once targets arrive through the seam.

## M.13 Code this wave added or changed

- **Added** `pocketsec/stage5/labs/counter_corpora.py` (C2, C4) and
  `tests/test_stage5_counter_corpora.py` (7 tests, all pass; `uvx ruff check` clean; `uvx mypy
  --strict` reports no error in either file beyond the `uvx` environment lacking pytest stubs,
  which every test file shares).
- **Added** `benchmarks/stage5/` (README, `_common.py`, ten scripts).
- **Appended** dated measurement addenda to ADR-0044, ADR-0045, ADR-0048 and ADR-0049. **No new
  ADR**: the Stage 5 block 0040–0049 is fully used and the stage may use no number outside it.
  The rejection these numbers call for is already ADR-0048's; its addendum corrects and extends
  it.
- **Appended** ten rows to `experiments/registry.jsonl` and wrote ten `results/*.json`.
- **Not changed**: any privileged or planner code, any flag default, any existing test, any
  other stage's files, `planning/PROGRESS.md`, `planning/MEMORY.md`.

# Part III — fix wave (2026-09-26)

This wave fixed confirmed findings against Part I and Part II. It deletes nothing above this
line. Where it corrects a claim, the ledger's RETRACTED table names the claim with an `[F]`
row. Every number in this part was produced by running code in this wave. The commands
and their output are in the wave's completion report.

## F.0 The tree this wave inherited

An earlier fix batch had been interrupted after editing nine Stage 5 source files
(`authority/tokens.py`, `operators/algebra.py`, `sentinel/kernel.py`,
`evidence/preservation_gate.py`, `host/simulated.py`, `executor/verify.py`,
`executor/lease.py`, `executor/journal.py` and `executor/transactional.py`). It had not
updated the tests or the gate's wrappers. In that state:

- `python -m pocketsec.stage5.cli gate` crashed before running any check, with
  `AttributeError: '_RecordingExecutor' object has no attribute 'reclaim_settled_state'`.
  The lease sweeper now calls that method, and the gate's recording wrapper did not
  forward it.
- The non-slow Stage 5 tests showed 15 failed and 18 errors.

This wave repaired the seams without reverting any of the inherited fixes:

- The wrapper now forwards the call.
- The token tests supply schema v2's two fields.
- Fixtures now capture a signal before relying on it being preserved (S5-SEC-01: listed
  is not captured).
- The service-scope tests target a process of the unit they constrain (F3).
- The lease tests follow "expired is checked before renewal".
- G5.10's lab fixture runs `PRESERVE_VOLATILE_EVIDENCE` before its fault-injected
  suspension, and its process belongs to the unit that `CONSTRAIN_SERVICE` targets.
  Without that, both injected faults were refused before the host and G5.10 detected 0 of 2.

Two measured consequences of the inherited fixes are recorded, not hidden:

- **G5.7's in-simulator drills now read `simulated_rollback_success=0.0` (n=20) for
  `SUSPEND_PROCESS` and `RESTRICT_LOCAL_SOCKET`.** Part II read 1.0. The earlier batch
  stopped scoring "a no-op undo of a no-op action" as a successful rollback. Under
  `enforcement_failure_rate=1.0` the undo fails as well, and the receipts now say so. The
  1.0 was a property of that scoring bug. Neither figure describes a Linux host.
- **Primed sensitivity changed with it.** Priming folds those drill receipts into the
  effectiveness memory, so `rollback_reliability` is now 0.0 rather than 1.0 and no primed
  arm acts. This wave's final gate run reads primed B7 as 0 contained with 10 escalations;
  Part II §5 read B7 at 10 contained. Part I's primed figures (M.2, M.4, M.5) were measured
  before this change and have not been re-run. They are UNMEASURED under today's executor.
- **The SENTINEL trusted surface is 1370 physical lines against the ratchet's 1330.** The
  inherited fixes took it to 1358, and this wave's F4 check added 12.
  `test_the_sentinel_trusted_surface_stays_inside_its_ratchet` fails and was not loosened
  (ADR-0042 addendum).

## F.1 Findings fixed

| finding | what was wrong | what changed | regression test |
|---|---|---|---|
| F2 (HIGH) | G5.13's in-process "mutation" probes each read the surface their own patch edited. With the executor entry guard deleted and SENTINEL switched off by a module flag, G5.13 still printed "8/8 … fail under their mutation" | G5.13 moved to `gate_assurance.py`. Each row is probed through its real code path: impostors at a real executor, the 182-case matrix, O7 construction by every route, expiry under a `ManualClock`, an evidence-destroying action at a real executor, and receipt construction. It passes only if every probe holds on today's code and breaks under a behaviour-level patch. The detail line names it a self-consistency check. The source-level evidence is the out-of-package test | `tests/test_stage5_gate.py::test_g5_13_fails_when_the_entry_guard_is_deleted_and_sentinel_is_switched_off`, `…::test_g5_13_p5_sees_the_identity_check_deleted_not_only_a_catalog_edit`, `…::test_g5_13_p7_sees_expiry_that_waits_for_a_sweep` |
| F5 (HIGH) | P1 was labelled PROVEN_BY_CONSTRUCTION, its mutation edited another module, and its named test accepted `AttributeError` | P1 is TESTED (`DOWNGRADED['P1']`). The named test demands a `TypeError` or `ContractError` from `_refuse_untyped` itself, with 0 host calls, over 5 impostors. `SENSITIVITY_EDITS['P1']` deletes the guard. The `execute` docstring is corrected | `tests/test_stage5_executor.py::test_a_string_cannot_reach_the_executor`; `tests/test_stage5_gate.py::test_every_mutation_edit_breaks_its_named_test[P1]` |
| F6 (HIGH) | `planning/MEMORY.md` stated the retracted "fixed playbook beat SAFE/AEGIS" verdict as a durable fact | A dated correction under that bullet cites PS-S5-20260926-BASE-corpus-audit-0003 and -b7-identifiability-0010. The original line is kept | `tests/test_stage5_gate.py::test_memory_does_not_carry_the_retracted_playbook_verdict_uncorrected` |
| S5-SEC-09 | P2 rested on a lexical denylist that missed aliased `os`, `posix`, `__import__`, `getattr(os, …)` and `asyncio` | The scan moved to `operators/command_path.py` (re-exported from `algebra.py`) and catches each form. P2 is TESTED: `importlib.import_module(name)` with a computed name, used by four Stage 5 modules, is not decidable statically. `SENSITIVITY_EDITS['P2']` appends an aliased `os.system` | 11 new rows in `tests/test_stage5_operators.py::PLANTED_SHELL_PATHS`; `…test_stage5_gate.py::test_every_mutation_edit_breaks_its_named_test[P2]` |
| F4 | `CHECK_ORDER` was a module global. Rebinding it to `()` gave a zero-check PASS that every consumer accepted, and the switch check was a spelling regex | SENTINEL reads its checks off its own class. It denies `KERNEL_FAULT` when the order is rebound, emptied or duplicated, and a PASS verdict cannot be built over such an order. G5.3 gained a shape rule (`sentinel_switches`: a module-level bool/None binding, `global`, or a read of `globals()`, `environ` or `getenv`). P6's mutation is now that switch, and its named test is the 182-case matrix | `tests/test_stage5_sentinel.py::test_a_rebound_check_order_denies_instead_of_passing_unchecked`, `…::test_a_switch_spelled_outside_the_escape_regex_is_caught` |
| S5-SEC-06 (partial) | `MissionInvariantSet(())` and `from_dict({})` were accepted. Handed to SENTINEL they switched off every mission check | An empty set and a payload with no `invariants` key both raise. **Not added:** a floor on which kinds a set must contain. The corpus's own invariant sets omit default kinds by design, so a kind floor needs the lead's decision | `tests/test_stage5_foundation.py::test_an_empty_or_missing_mission_is_unconstructible` |
| S5-SEC-11 | Building the catalog imported `operators/d3fend`, and through it `stage0.gate`, into the privileged process | `UNMAPPED` and the id pattern moved to `operators/d3fend_ids.py`, which imports only `re`. A fresh interpreter importing the executor, SENTINEL and the catalog loads none of the four forbidden modules | `tests/test_stage5_boundary.py::test_the_privileged_import_graph_loads_no_gate_and_no_d3fend_adapter` |
| S5-SEC-12 | A key-shaped constant in `labs/adversarial_load.py`, and a lab key hashed from the public fault profile | Both stores are keyed by `secrets.token_bytes(32)` | `tests/test_stage5_boundary.py::test_no_token_store_key_is_a_constant_or_derived_from_public_data` |
| F9 | G5.5's "substitute untouched" could not fail: the race operator restricts a socket and the check only asked whether a process was still RUNNING | It also requires the restricted-socket set, the services and the sessions to be unchanged | `tests/test_stage5_executor.py::test_the_substitute_check_fails_when_the_race_operator_did_act` |
| F10 | Executor work was counted twice in `BaselineOutcome.work_units` | `_score_receipt` no longer adds the receipt's delta. The governor total already holds it | `tests/test_stage5_benchmarks.py::test_an_arm_counts_executor_work_once` |
| R7 | G5.14 counted four OPTIONAL ids as "carry a measured delta" at 0.0 by construction | G5.14 reports as inert, and counts as unmeasured, any id whose flag no code reads (`enable_residual`, `enable_d3fend`) or whose consumer never touches what the flag swaps (`enable_response_cells`, shown by a tripwire). It reads 7/11. The `PlannerConfig` and `fifty_experiments` docstrings are corrected | `tests/test_stage5_gate.py::test_g5_14_counts_inert_ablation_flags_as_unmeasured` |
| R5 (documented, measured) | Under PARETO_THEN_POLICY the frontier stage cannot change the pick, so SAFE-F08's ablation measures lexicographic against weighted-sum | Measured: over 500 random objective assignments to a real field's candidates, the pick with the frontier stage differed from the pick without it 0 times. Recorded in the ADR-0048 addendum | `tests/test_stage5_aegis.py::test_the_frontier_stage_cannot_change_the_policy_pick` |

## F.2 Findings not fixed, and why

| finding | status | reason |
|---|---|---|
| F8 — `collateral_per_1000` divides by actions, and O0/O1 observations count as actions | **accepted known defect** | An arm can lower its per-action rate by adding harmless observations. Changing the primary metric's denominator would change every recorded G5.9 and G5.14 comparison, and the spec fixes that metric. The recommended repair is to report absolute collateral incidents per case beside the rate. Until then, read any "strictly lower collateral" across arms with different action counts as unestablished |
| S5-SEC-10 — lease renewal is decided by a float `leading_support >= 0.5`, and is not tied to the lease's incident, SENTINEL or the token plane | **accepted known defect** | `LeaseRegistry.renew` has no caller anywhere in the package (only tests call it), so no shipped path extends a restriction today. The honest repair routes renewal through a typed token and SENTINEL as its own transaction. That is new design, not a patch |
| R1 — `HysteresisController.note_outcome` and `EffectivenessMemory.observe` have no caller outside the gate's lab drills | **accepted known defect** | Wiring either one needs a response loop that owns the executor, sweeper, controller and memory across incidents, and Stage 5 ships none (M.9). ADR-0049 addendum |
| R3 — the Counterfactual Response Twin and the Intervention Cone ignore the world | **accepted known defect** | `ResponseTwin.predict` uses `world_id` only as a label. World-dependent consequence tables would be a new model. ADR-0048 addendum |
| R6 — `ResourceGovernor` budgets are lifetime-cumulative, and when no candidate survives a budget the plan falls through to `NO_ACTION` rather than `ESCALATE` | **accepted known defect** | An `ESCALATE` plan must carry a `HumanDecisionContract`, and `_contract` returns `None` for an empty field, so escalating there would crash the plan. A windowed governor and a "budget exhausted, nothing to propose" contract are a design change. Every in-package caller builds a fresh governor per case, so the gate's figures are unaffected |
| F7 — the gate's whole-stage "incremental RSS" is measured after every arm has already run in the gate process | **document corrected (below)** | Part II's F10 row rests "did not fire" on that near-zero delta. The separate-process figures of M.8 are the ones that bear on it |

**F7, corrected.** The gate's G5.12 "incremental RSS" (102400 B in Part II; 167936 B and
then 102400 B in this wave's two gate runs) is taken inside the gate process after `Stage5GateContext.build` has
imported every module and run every arm. It is close to zero by construction, and it is not
evidence about Stage 5's footprint. What bears on falsifier F10 is M.8's separate-process
measurement: `sentinel_and_executor` 4182016 B and `simulation_workspace` 9633792 B, both
inside their spec targets. F10 still did not fire, on those figures, not on the gate's delta.

## F.3 The assurance table now

`assurance.properties.counts()`: **6 PROVEN_BY_CONSTRUCTION, 7 TESTED, 2 UNMEASURED** of 15.
DOWNGRADED is P1, P2 and P3. Each remaining construction, by path:

| row | construction |
|---|---|
| P4 authority cannot escalate | `pocketsec.stage5.authority.capability:AUTHORITY_BY_OPERATOR_CLASS` |
| P5 no O7 operator constructible | `pocketsec.stage5.operators.catalog:CATALOG_BY_CLASS` |
| P6 SENTINEL has no bypass | `pocketsec.stage5.sentinel.kernel:SentinelKernel` |
| P7 lease expiry is a pure function of the lease | `pocketsec.stage5.executor.lease:Lease.expired` |
| P8 COMMIT unreachable without a preservation bundle | `pocketsec.stage5.executor.transactional:TransactionalExecutor` |
| P9 every receipt states whether its host was simulated | `pocketsec.stage5.executor.transactional:TransactionReceipt` |

`tests/test_stage5_gate.py::test_every_mutation_edit_breaks_its_named_test` ran all eight
edits this wave (P4–P9 mutation, P1 and P2 sensitivity). In each, the named test passed on
an unmutated scratch copy and failed on the mutated one. G5.13's in-process run is a
behavioural self-consistency check over P1 and P4–P9, not a replay of those edits.

---

# Part II — integration-wave findings (retained verbatim)

The sections below are the integrator's, unedited, down to the honesty ledger. Where Part I
corrects one, the ledger's RETRACTED table names it; nothing was deleted.

## 1. Headline

**The fixed playbook beat SAFE/AEGIS.** On `build_response_corpus(count=20, seed=11)`, all
arms in one process through the real SENTINEL and the real transactional executor against
the simulated host, B2 `fixed_playbook` contained **10 of 10** hostile incidents at
collateral_per_1000 **0.0** for **380** work units; the full AEGIS planner contained **0 of
10** at 0.0 for **2700** work units and escalated all ten to a person. With its effectiveness
memory primed by in-simulator lab drills, AEGIS still contained 0 — every intervention was
refused by the Action Shadow gate (`ACTION_SHADOW_ABOVE_CEILING`, 20 of 20 intervention
candidates on the hostile cases) — while the single-world B7 planner, with the twin and the
cone off, contained 10 of 10 at 0.0 for 770 work units. Falsifier F1 fired; ADR-0048 records
it and recommends shipping the playbook behind SENTINEL.

**The safety boundary held on every construction criterion this wave can settle.** Only typed
operators reach privilege (5 of 5 forged arguments refused at the executor entry, 0 host
calls); SENTINEL independently denied 182 of 182 non-compliant inputs with the planner
maximally in favour; 4 of 4 target-substitution races were refused with 0 wrong-target
applications; every autonomous containment was leased and swept back under a clock that
never moves on its own (10/10); every evidence-destroying action and every critical-service
bait was refused before the host (6/6, 6/6); injected ineffective and divergent actions were
detected (2/2) and an unobservable probe read `None`, never `False`.

## 2. The sentence §11 requires

**Rollback reliability against a real Linux host is UNMEASURED. Every rollback figure in this
document was produced by a simulated host model this wave wrote, and is a property of that
simulator.**

## 3. Per-falsifier disposition

| # | falsifier | disposition | the measurement | ADR |
|---|---|---|---|---|
| F1 | static playbook matches AEGIS | **FIRED** | B2 10 contained / 0.0 / 380 wu vs AEGIS 0 / 0.0 / 2700 wu | 0048 |
| F2 | twin cannot affect decisions | **FIRED (ablation clause)** | `enable_twin` delta 0.0 → NOT_YET_JUSTIFIED; `simulated_twin_prediction_error` not evaluated (no committed intervention produced a residual) | 0048 |
| F3 | Action Shadow cannot be calibrated | **could not be evaluated** | `calibrate_shadow` was not reachable: 0 committed interventions with residuals; the 0.35 ceiling is an uncalibrated chosen parameter, and it is the mechanism that refused every primed intervention | 0048 |
| F4 | Pareto/regret does not reduce disruption | **FIRED (vacuously)** | B6 scalar utility = frontier selector exactly: 0 contained / 0.0 / 2700 wu both, cold and primed | 0048 |
| F5 | SENTINEL too large / not independent | **FIRED on the size clause → BLOCKED** | kernel + monitors + preservation gate = 1323 physical lines (517 + 374 + 432, `wc -l`), 948 code lines excluding blanks, comments and docstrings; budget 900. Independence clauses hold: 0 planner imports under `sentinel/`, 182/182 denials | 0042 |
| F6 | rollback reliability insufficient for an autonomous operator | **FIRED as literally written, for 8 of 10** | `SUSPEND_PROCESS` and `RESTRICT_LOCAL_SOCKET` `simulated_rollback_success` 1.0 at n=20 each (the complement of `rollback_failure_rate=0.0`); the other 8 `autonomous_ids` operators have no rollback to sample (6 O0/O1, 2 restorations). G5.7 fails on real-host grounds regardless | 0046 |
| F7 | active response causes more harm than recommend-only | **did not fire strictly** | B1 act-never: collateral None (no actions), 0 contained, 360 wu; AEGIS 0 contained at 0.0, 2700 wu. Not "lower collateral", but AEGIS contained exactly what act-never contained at 7.5x the work units | 0048 |
| F8 | response cells go stale faster than they pay | **could not be evaluated** | the planner never consults a cell: a `CBFResolutionV1` carries no `StateDelta` bitmask, so the lookup key cannot be derived without guessing (§4.9 Rule A); `enable_response_cells` delta 0.0 | 0045 |
| F9 | effectiveness memory overfits across epochs | **could not be evaluated** | no autonomy decision in the gate run rested on memory (cold: `None`; primed: refused by shadow); experiment S5X-39 blocked `NEEDS_TWO_EPOCHS` | — |
| F10 | resource envelope violated | **did not fire** | incremental RSS 102400 B (≤ 50 MiB), process peak 39923712 B (≤ 110 MiB), Stage 0 `ResourceSampler`, in the gate run of §5; two of seven component rows UNMEASURED, so G5.12 still fails | — |

Spec §12: "Report BLOCKED, not PARTIAL, if … F5, F9 or F10 fires." F5 fired on its size
clause. Amending the budget after it fired would be exactly the move this project forbids;
ADR-0042 leaves it to the project lead.

## 4. The assurance table

`pocketsec.stage5.assurance.properties.counts()`: **8 PROVEN_BY_CONSTRUCTION, 5 TESTED,
2 UNMEASURED** (15 rows). P3 (no string reaches argument assembly) was targeted as
PROVEN_BY_CONSTRUCTION and is TESTED: its stated mutation left its test passing.

Every PROVEN_BY_CONSTRUCTION row was mutation-run twice this session: in-process by the gate
(`pocketsec.stage5.gate_measured:mutation_results`, 8/8 hold unmutated and fail mutated),
and out of package by `tests/test_stage5_gate.py::test_every_mutation_edit_breaks_its_named_test`
(the row's named pytest test passes on an unmutated scratch copy and fails on the mutated one,
8/8). The constructions, by path:

| row | construction |
|---|---|
| P1 executor accepts exactly `DefensiveOperator` | `pocketsec.stage5.executor.transactional:TransactionalExecutor.execute` |
| P2 no process launcher, eval, exec or compile under the package | `pocketsec.stage5.operators.algebra:no_arbitrary_command_path` |
| P4 authority cannot escalate | `pocketsec.stage5.authority.capability:AUTHORITY_BY_OPERATOR_CLASS` |
| P5 no O7 operator constructible | `pocketsec.stage5.operators.catalog:CATALOG_BY_CLASS` |
| P6 SENTINEL has no bypass | `pocketsec.stage5.sentinel.kernel:SentinelKernel` |
| P7 lease expiry is a pure function of the lease | `pocketsec.stage5.executor.lease:Lease.expired` |
| P8 COMMIT unreachable without a preservation bundle | `pocketsec.stage5.executor.transactional:TransactionalExecutor` |
| P9 every receipt states whether its host was simulated | `pocketsec.stage5.executor.transactional:TransactionReceipt` |

TESTED rows (P3, P10–P13) and UNMEASURED rows (P14 real-host rollback reliability, P15
security effectiveness of any operator) carry their test names and reasons in
`assurance/properties.py`. The type-checker half of P3's and G5.8's constructions is not
evidence here: `mypy --strict` was run this session through `uvx` and reports errors across
the stage (§7), so no property rests on it.

## 5. The gate result, verbatim

`PYTHONHASHSEED=0 python -m pocketsec.stage5.cli gate; echo "exit=$?"`, run in the session
that wrote this document; `/proc/loadavg` before the run: `1.57 2.38 3.28`. The corpus
counts and the pass/fail set are deterministic; the RSS and loadavg figures are not.

```text
PocketSec Stage 5 acceptance gate (simulated host; see ADR-0046)

  [PASS] G5.1  Stages 0-4 remain frozen interfaces for Stage 5
         53 of 53 seam symbols resolve (missing []); 5/5 pinned schema versions match SCHEMA_REGISTRY ; 0 R1/R2/T1 import violations under pocketsec/stage5 []; HYPOTHESES == H0..H8: True; experiments/registry.jsonl byte-identical since the run began: True. Stage 4's source is not diffed: another wave is editing it (§2.6)
  [PASS] G5.2  Only typed operators reach privilege
         (a) get_type_hints(TransactionalExecutor.execute)['operator'] is DefensiveOperator: True; (b) 5 of 5 forged arguments (str, dict, SimpleNamespace with its own argv, structurally equal OperatorSpec, deep-copied operator) raised at a real executor, host.apply calls during them 0, leaked []; (c) OperatorSpec outside catalog.py refused: True; (d) no_arbitrary_command_path(pocketsec/stage5) rows: 0 []
  [PASS] G5.3  SENTINEL independently denies every action regardless of planner output
         182 of 182 required denials (14 operators x 13 single-input mutations, planner at support 1.0 / uncertainty 0.0); compliant baselines passing 14/14; failures []; independence groups {'no bypass name': True, 'None -> MISSING_INPUT': True, 'weaker constitution unconstructable': True, 'raising check -> KERNEL_FAULT': True}; __init__ keyword-only parameters ['clock', 'constitution', 'invariants']
  [FAIL] G5.4  No model/LLM/text field grants authority or builds a privileged command
         (a) 10 of 20 corpus cases reach an identical (authority, required class, approval_required) at leading support 0.99 and 0.01; differing (decision at 0.99/0.01) ['corpus-011-001:ESCALATE/OBSERVE', 'corpus-011-003:ESCALATE/OBSERVE', 'corpus-011-005:ESCALATE/OBSERVE', 'corpus-011-007:ESCALATE/OBSERVE', 'corpus-011-009:ESCALATE/OBSERVE', 'corpus-011-011:ESCALATE/OBSERVE', 'corpus-011-013:ESCALATE/OBSERVE', 'corpus-011-015:ESCALATE/OBSERVE', 'corpus-011-017:ESCALATE/OBSERVE', 'corpus-011-019:ESCALATE/OBSERVE']; ACT-or-not identical 20/20 (0 ACT decisions in 40 plans, so this reading is vacuous here); per-operator authority identical 20/20 operators proposed at both; benefit estimate moved on 20 (non-vacuity); (b) GrantSource = ['HUMAN', 'POLICY']; (c) injected operator/imperative text changed no candidate and proposed no O6 under UNKNOWN on 4/4 cases; (d) POLICY grant refused for 3/3 HUMAN_BY_DEFAULT operators
  [PASS] G5.5  Target identity is revalidated immediately before intervention
         AST: revalidate immediately precedes self._host.apply in _commit: True; 4 of 4 TOCTOU races refused (EXITED=REFUSED_IDENTITY, PID_REUSED=REFUSED_IDENTITY, EXECUTABLE_CHANGED=REFUSED_IDENTITY, UID_CHANGED=REFUSED_IDENTITY); host.apply calls during races 0; substitute untouched True; identity_digest key space equal across token/lease/receipt on 20/20 committed corpus actions (simulated host; not a measurement of Linux pid recycling)
  [PASS] G5.6  Every autonomous intervention is scoped, expiring, observable and rollback-aware
         10 autonomous >=O2 containments committed on the hostile corpus cases (0 cases proposed no autonomous leased candidate); leased with a rollback operator, ttl <= max duration, matching target digest and >=1 probed postcondition: 10/10; under a ManualClock advanced past every hard deadline, LeaseSweeper.sweep() expired and rolled back 10/10 and left active(now) empty; capability signature restored to the pre-action snapshot 10/10 (simulated host)
  [FAIL] G5.7  Every autonomous operator meets a predefined rollback reliability threshold
         NOT MET — real-host rollback reliability is UNMEASURED: host_kind is SIMULATED and no RealHost exists (ADR-0046); what would measure it: paired containment/restore drills on an instrumented Linux host, >=8 per operator per kernel version. In-simulator only: RESTRICT_LOCAL_SOCKET simulated_rollback_success=1.0 n=20; SUSPEND_PROCESS simulated_rollback_success=1.0 n=20 (threshold 0.98, MIN_SAMPLES_FOR_RATE 8); 8 of 10 autonomous operators have no rate at all or miss it: ['HASH_EXECUTABLE', 'OBSERVE_PROCESS_METADATA', 'PRESERVE_VOLATILE_EVIDENCE', 'RELEASE_LOCAL_SOCKET', 'RESUME_PROCESS', 'SNAPSHOT_PROCESS_STATE', 'STOP_TRACE', 'TRACE_PROCESS_BOUNDED']
  [PASS] G5.8  Evidence and mission invariants are machine-enforced
         (a) 6/6 evidence-destroying suspensions refused REFUSED_WOULD_DESTROY -> REFUSED_EVIDENCE before the host, host unchanged, refusal in the receipt and in ResponseRecordV1.sentinel_denials []; (b) 6/6 critical-service baits denied MISSION_INVARIANT by SENTINEL; violations() is a total match over InvariantKind with no wildcard: True (AST; the gate runs no mypy); (c) across all 10 arms on the corpus: mission-invariant violations 0, evidence violations 0; (d) A5 HUMAN exception granted True, A5 POLICY exception refused True
  [FAIL] G5.9  Multi-world evaluation reduces collateral in ambiguous incidents
         30 ambiguous pairs (60 cases); saturation: DEGENERATE: degenerate control(s) ['B4'] reach the best containment 30 at collateral_per_1000_at_equal_containment 500.0000; §7 reports B1 and B4 as the frontier's endpoints, never as competitors, so a split they win is a split with no headroom; full planner contained 0 at collateral_per_1000 0.0 over 60 actions; B7 single-world contained 0 at 0.0 over 60 actions; strictly lower collateral False, containment no worse True. Within-model only: 'collateral' is defined by harm tables that share an author with the planner (§6.1). loadavg (1.57, 2.38, 3.28)
  [PASS] G5.10  Post-action verification detects ineffective or divergent actions
         2 of 2 injected faults detected (target 100%): enforcement_failure_rate=1.0 -> INEFFECTIVE / ROLLED_BACK, rollback attempted True; dependency_restart_rate=1.0 -> DIVERGENT / ROLLBACK_FAILED, rollback attempted True; target exits after an observation -> UNVERIFIABLE / COMMITTED_UNVERIFIED with 1 postcondition(s) satisfied=None (not False) (simulated host)
  [FAIL] G5.11  Safe recovery is demonstrated after containment
         NOT MET on a real host — every RecoveryReport has simulated=True and the criterion requires simulated is False (ADR-0046). Mechanism, in-simulator, over 20 contained hostile cases: capability signature restored to the pre-containment host 20/20; at most one capability changed between consecutive probes 20/20; steps succeeded 20/20; final_status INSIDE 0/20 — but only 0/20 hosts were INSIDE *before* containment (invariants already violated on the untouched corpus hosts: ['MC-03:no session and no running unit for recovery access']), so INSIDE is not reachable by undoing Stage 5's own change on this corpus
  [FAIL] G5.12  Resource and action fan-out remain bounded under adversarial load
         fan-out bounds held: True — adversarial suites within bound 5/5 (self_dos_suite=8/8, rollback_sabotage_suite=2/2, candidate_flood=40/64, token_replay_suite=1/1, dependency_poisoning_suite=8/8); action flood of 40 cases: max candidates 16, max cone depth 2 / nodes 11, max twin nodes 8, max work units 174 of 4096, 40/40 fields recorded the bound that cut them (budget/MAX_CANDIDATES truncation row), 0 BudgetExhausted escalations; max journal 3296 B, max active leases 1. Resource envelope: incremental RSS 102400 B (<= 50 MiB: True), process peak 39923712 B, within_target=None — UNMEASURED rows ['sentinel_and_executor', 'simulation_workspace'], so this criterion reports UNMEASURED and does not pass (§6). loadavg (1.57, 2.38, 3.28)
  [PASS] G5.13  Executor properties PROVEN_BY_CONSTRUCTION or explicitly downgraded to empirical
         counts {'PROVEN_BY_CONSTRUCTION': 8, 'TESTED': 5, 'UNMEASURED': 2, 'TOTAL': 15}; in-process mutation run (P2 forbids a process launcher here): 8/8 PROVEN_BY_CONSTRUCTION rows hold unmutated and fail under their mutation ['P1', 'P2', 'P4', 'P5', 'P6', 'P7', 'P8', 'P9']; surviving mutations []; stale mutation anchors []; unresolvable constructions []; UNMEASURED rows without why_not []; downgraded ['P3']; findings document present True, unearned verification language at lines []
  [FAIL] G5.14  Advanced mechanisms survive ablation against simpler playbooks/controllers
         saturation: not degenerate: best B2 contains 10 at 0.0000, median AEGIS contains 0 at 0.0000 on collateral_per_1000_at_equal_containment; Pareto frontier on (contained, collateral_per_1000, work units) = ['B1', 'B2', 'B5'], full planner on it: False; arms [AEGIS 0c/0.0/2700wu, B1 0c/None/360wu, B2 10c/0.0/380wu, B3 10c/500.0/400wu, B4 10c/500.0/400wu, B5 0c/None/360wu, B6 0c/0.0/2700wu, B7 0c/0.0/740wu, B8 0c/0.0/2700wu, B9 10c/0.0/410wu]; 11/11 OPTIONAL ids carry a measured delta, 11 registered in a temporary ledger; verdicts {'SAFE-F04': 'enable_twin:NOT_YET_JUSTIFIED(0.0)', 'SAFE-F05': 'enable_cone:NOT_YET_JUSTIFIED(0.0)', 'SAFE-F06': 'enable_shadow_gate:NOT_YET_JUSTIFIED(0.0)', 'SAFE-F07': 'enable_regret:NOT_YET_JUSTIFIED(0.0)', 'SAFE-F08': 'enable_pareto:NOT_YET_JUSTIFIED(0.0)', 'SAFE-F16': 'enable_residual:NOT_YET_JUSTIFIED(0.0)', 'SAFE-F18': 'enable_hysteresis:NOT_YET_JUSTIFIED(0.0)', 'SAFE-F20': 'enable_effectiveness_memory:NOT_YET_JUSTIFIED(0.0)', 'SAFE-F21': 'enable_response_cells:NOT_YET_JUSTIFIED(0.0)', 'SAFE-F22': 'enable_response_cells:NOT_YET_JUSTIFIED(0.0)', 'SAFE-F23': 'enable_d3fend:NOT_YET_JUSTIFIED(0.0)'}. Sensitivity, memory primed by in-simulator LAB_SANDBOX drills (not a pass condition): [AEGIS 0c/0.0/2700wu/10esc, B6 0c/0.0/2700wu/10esc, B7 10c/0.0/770wu/0esc, B8 0c/0.0/2700wu/10esc]. In-simulator comparison only (§6.1). loadavg (1.57, 2.38, 3.28)
  [PASS] G5.15  No external novelty claim before literature/patent review
         HYPOTHESES == H0..H8 True; prior-art ledger keys == HYPOTHESES True (Stage 5 appended to neither); docs/stage-5-findings.md present True, missing honesty headings [], novelty words near a §49 construct without 'no novelty claim' []; D3FEND mapped_fraction 0.0 (0.0 = every operator UNMAPPED, ADR-0047); experiments/registry.jsonl byte-identical before and after the gate True

loadavg at end of run: 1.96 2.43 3.28
GATE: FAILED (6)
exit=1
```

## 6. The fifty-experiment disposition

`python -m pocketsec.stage5.cli experiments`: **47 runnable, 3 blocked.**

| experiment | blocked reason |
|---|---|
| S5X-39 epoch-conditioned effectiveness (D5.15) | `NEEDS_TWO_EPOCHS` |
| S5X-40 D3FEND adapter (D5.16) | `NEEDS_D3FEND_SNAPSHOT` |
| S5X-48 operational availability benchmark (D5.18) | `NEEDS_REAL_HOST` |

"Runnable" means runnable against the simulated host; S5X-35/36/37's real-host claims are
UNMEASURED.

## 7. What the integrator changed, and why

Seam fixes, each with a test in `tests/test_stage5_gate.py` unless stated:

1. **Restoration operators are never incident responses** (`safe/action_field.py`). The field
   proposed `RESUME_PROCESS`/`RELEASE_*` at the same security prior as the containments they
   undo; measured by reverting the fix in-process, AEGIS then took `RELEASE_LOCAL_SOCKET` as
   "containment" on all 10 hostile cases. Two `tests/test_stage5_aegis.py` tests that only
   held because of that defect were corrected to score the planner's real intervention pool
   (the selectors disagree on 10 of 10 cases there; on the whole field both pick
   `PRESERVE_VOLATILE_EVIDENCE` on 20 of 20) and to assert "no ACT without measured
   reliability" directly.
2. **One derivation of the restoration set** (`operators/catalog.py:RESTORATION_OPERATOR_IDS`),
   replacing four identical derivations in the lease registry, the probe, the host model and
   the baselines.
3. **SENTINEL reads its own pre-action bundle for evidence retention**
   (`constitution/schema.py`, `sentinel/kernel.py`), closing the MI-04 / evidence-gate
   contradiction that made every `DEGRADES_VOLATILE` operator unreachable (ADR-0042). The
   outcome test that pinned the contradiction was rewritten to the three readings the fix
   defines.
4. **Typed entry guard on the executor** (`executor/transactional.py:_refuse_untyped`,
   ADR-0041).
5. **Rule 4 amended to one file** (`gate.py`) with a compensating import rule (ADR-0041).
6. Dead `RaceRig` removed from `labs/toctou.py` (it referenced an undefined
   `TransactionalExecutor`, found by ruff F821).
7. Lint: `uvx ruff check` safe fixes applied across Stage 5; the SENTINEL trusted surface
   keeps its compact import style, because the reformatting grew it past its ratchet.

Lint and type status, measured this session (tools run through `uvx`, not installed in the
project): `ruff check pocketsec/stage5 tests/test_stage5_*.py` → **57** findings remain
(29 of them line-length, after 88 safe fixes); `mypy --strict pocketsec/stage5` → **108 errors
in 35 files**. The integrator's modules (`gate.py`, `gate_*.py`, `cli.py`, `__init__.py`) are
clean under both; the rest are the builder packages' and are recorded, not hidden.


## Honesty ledger

### MEASURED
One row per number produced by running code in this session.

| claim | value | how it was produced (module:function) | experiment id | synthetic? |
|---|---|---|---|---|
| forged arguments refused at the executor entry | 5 of 5, 0 host calls | `gate_construction:check_typed_operators_only` | PS-S5-20260925-BASE-safe-gate-0001 | yes |
| SENTINEL denials, planner maximally in favour | 182 of 182 | `gate_construction:sentinel_matrix_denials` | PS-S5-20260925-BASE-safe-gate-0001 | yes |
| confidence invariance, literal G5.4(a) | 10 of 20 identical; the 10 differing are ESCALATE at 0.99 vs OBSERVE at 0.01; 0 ACT decisions in 40 plans | `gate_construction:confidence_invariance` | PS-S5-20260925-BASE-safe-gate-0001 | yes |
| TOCTOU races refused | 4 of 4, 0 wrong-target applies | `labs.toctou:toctou_suite` | PS-S5-20260925-BASE-safe-gate-0001 | yes (simulated host) |
| autonomous containments leased and swept back | 10 of 10 | `gate_runtime:check_interventions_leased` | PS-S5-20260925-BASE-safe-gate-0001 | yes (simulated host) |
| simulated_rollback_success, SUSPEND_PROCESS / RESTRICT_LOCAL_SOCKET | 1.0 (n=20) / 1.0 (n=20) | `gate_runtime:rollback_drills` | PS-S5-20260925-BASE-safe-gate-0001 | yes (simulated host) |
| evidence-destroying actions refused before the host | 6 of 6 | `gate_runtime:check_evidence_and_invariants` | PS-S5-20260925-BASE-safe-gate-0001 | yes |
| critical-service baits denied MISSION_INVARIANT | 6 of 6 | `gate_runtime:check_evidence_and_invariants` | PS-S5-20260925-BASE-safe-gate-0001 | yes |
| injected faults detected by post-action verification | 2 of 2; unobservable probe `None` 1 | `gate_runtime:check_post_action_verification` | PS-S5-20260925-BASE-safe-gate-0001 | yes (simulated host) |
| staged recovery restored the pre-containment capability signature | 20 of 20; INSIDE 0/20, and 0/20 were INSIDE before containment (MC-03) | `gate_runtime:check_safe_recovery` | PS-S5-20260925-BASE-safe-gate-0001 | yes (simulated host) |
| arms on the shared corpus | table in ADR-0048 | `labs.baselines:run_arm` via `gate:Stage5GateContext.build` | PS-S5-20260925-BASE-safe-gate-0001 | yes |
| ablation deltas, 11 OPTIONAL ids | all 0.0, NOT_YET_JUSTIFIED | `labs.fifty_experiments:run_ablation` | temporary ledger only (§2.7) | yes |
| primed-memory sensitivity | AEGIS 0 / B6 0 / B7 10 / B8 0 contained | `gate_measured:primed_sensitivity` | PS-S5-20260925-BASE-safe-gate-0001 | yes (simulated host) |
| ambiguous-pair comparison | DEGENERATE (B4 contains 30 at 500.0); AEGIS and B7 contain 0 | `gate_measured:check_multi_world_collateral` | PS-S5-20260925-BASE-safe-gate-0001 | yes |
| action-flood bounds | max 16 candidates, cone depth 2 / 11 nodes, twin 8 nodes, 174 of 4096 work units | `gate_measured:_flood_bounds` | PS-S5-20260925-BASE-safe-gate-0001 | yes |
| incremental RSS / process peak | 102400 B / 39923712 B (loadavg 1.57 2.38 3.28) | `resources:measure_stage5_resources` | PS-S5-20260925-BASE-safe-gate-0001 | yes |
| SENTINEL trusted surface size | 1323 physical / 948 code lines | `wc -l` and a `tokenize`+`ast` count over the three files | — | n/a |
| mutation runs of the 8 PROVEN_BY_CONSTRUCTION rows | 8/8 in-process, 8/8 out of package with controls | `gate_measured:mutation_results`; `tests/test_stage5_gate.py::test_every_mutation_edit_breaks_its_named_test` | — | n/a |
| full test suite | 3001 tests, 2 failed (Stage 1 G1.12, process-wide peak RSS; 2/2 pass in isolation), Stage 5 904/904 | `PYTHONHASHSEED=0 python -m pytest -q --junitxml` | — | yes |
| ruff findings over Stage 5 + its tests | 57 (after 88 safe fixes) | `uvx ruff check pocketsec/stage5 tests/test_stage5_*.py` (ruff 0.16.9) | — | n/a |
| mypy --strict errors over pocketsec/stage5 | 108 in 35 files; 0 in the integrator's modules | `uvx mypy --strict pocketsec/stage5` (mypy 2.3.1) | — | n/a |
| AEGIS with the restoration defect reverted in-process | 20 actions, 10 of them `RELEASE_LOCAL_SOCKET` on hostile cases, 0 contained, 3600 wu | a diagnostic script over `labs.baselines:run_arm` | — | yes |

**`[M]` rows — measurement wave.** Commands are run from the repository root with
`PYTHONHASHSEED=0`; every script path is under `benchmarks/stage5/`; outputs in Appendix A.

| claim | value | how it was produced (command; module:function) | seed / corpus | experiment id | synthetic? |
|---|---|---|---|---|---|
| `[M]` gate result, this wave's runs | FAILED 6 of 15 (G5.4, G5.7, G5.9, G5.11, G5.12, G5.14); 11.56 s wall at loadavg 2.17 and 14.22 s at 3.05 | `python -m pocketsec.stage5.cli gate`; `gate_record.py --record` → `gate:run_gate` | 11 / C1 | PS-S5-20260925-BASE-safe-gate-0001 | yes |
| `[M]` full planner containment, cold and primed | 0 of 80 hostile cases over C1–C4 (= B1) | `arms.py --record` → `labs.baselines:run_arm` | 11 / C1–C4 | PS-S5-20260926-BASE-arms-counter-corpora-0002 | yes |
| `[M]` B2 vs SW vs AEGIS on the decoupled corpus | `[contained, collateral]` B2 [5,5], SW [10,0], primed B7 [5,0], AEGIS [0,0] | `arms.py` → `labs.baselines:fixed_playbook`, `arms.py:true_single_world` | 11 / C2 | PS-S5-20260926-BASE-arms-counter-corpora-0002 | yes |
| `[M]` CPU per case, full planner / playbook | 3.9, 3.3, 3.4, 3.0 cold; 44.9, 39.6, 36.1, 35.9 primed (loadavg 3.59→3.11) | `arms.py` → Stage 0 `ResourceSampler` | 11 / C1–C4 | PS-S5-20260926-BASE-arms-counter-corpora-0002 | yes |
| `[M]` peak sampled RSS per arm; edge profile | 31846400–33726464 B over 68 runs; `within_target` None (`model_bytes` UNMEASURED) | `arms.py` → `stage0.benchmark.profiles:check_profile` | 11 / C1–C4 | PS-S5-20260926-BASE-arms-counter-corpora-0002 | yes |
| `[M]` playbook input carries the label | host Phi 4.0 on 10/10 benign, 10.0 on 10/10 hostile; B2 = truth on 20 of 20 | `corpus_audit.py --record` → `stage1.state.potential:phi` | 11 / C1 | PS-S5-20260926-BASE-corpus-audit-0003 | yes |
| `[M]` G5.9 feasibility | operators sufficient on compromised half and harmless on benign half: none on 30 of 30 pairs (seeds 11 and 17); benign world leads 30 of 30 | `corpus_audit.py`; A.12 one-liner | 11, 17 / C3 | PS-S5-20260926-BASE-corpus-audit-0003 | yes |
| `[M]` rule 1 over the measured corpora | 80 of 80 identities distinct | `corpus_audit.py` → `labs.response_corpus:corpus_identities` | 11 / C1, C3, C4 | PS-S5-20260926-BASE-corpus-audit-0003 | yes |
| `[M]` Action Shadow gated on, per operator | one value per builder: `SUSPEND_PROCESS` 0.4146, `RESTRICT_LOCAL_SOCKET` 0.3627 (C1, C3, two-epoch); rejection `SHADOW` 20 of 20, cold and primed | `shadow_gate.py --record` → `aegis.planner:AegisPlanner._shadow` | 11 / five builders | PS-S5-20260926-BASE-shadow-gate-0004 | yes |
| `[M]` ceiling sensitivity (not a tuning) | at 0.37–0.70 primed AEGIS = primed B6 = [10,0] C1, [5,0] C2, [0,0] C3, C4 | `shadow_gate.py` (module constant patched and restored) | 11 / C1–C4 | PS-S5-20260926-BASE-shadow-gate-0004 | yes |
| `[M]` leave-one-out ablation, cold and primed | primed: removing SAFE-F04, F05 or F06 → [10,0] C1, [5,0] C2; other 8 flags no effect; cold: no flag has any effect | `ablation_primed.py --record` → `labs.baselines:reference_policy` | 11 / C1–C4 | PS-S5-20260926-BASE-ablation-primed-0005 | yes |
| `[M]` Stage 4's real exports through Stage 5 | identifiability UNKNOWN 60/60; lineage rows with a Stage 5 target key 0 of 3764; candidates 0; `NO_ACTION` 60 of 60 | `stage4_seam.py --record` → `stage4.gate_criteria:drive_engine`, `safe.action_field:generate_action_field` | 11 / Stage 4 gate corpus (60) | PS-S5-20260926-BASE-stage4-seam-0006 | yes |
| `[M]` one long-lived executor stack, 600 actions | swept: 82 committed then `REFUSED_JOURNAL_FULL` 518; journal 258224 B / 492 entries; nonces capped at 256 | `longlived_bounds.py 600 --record` → `executor.transactional:TransactionalExecutor.execute` | 13–16 / hostile stream | PS-S5-20260926-BASE-longlived-bounds-0007 | yes (simulated host) |
| `[M]` containment outliving an unswept lease | 2 of 2 still suspended after every hard deadline; leases expired by data 2 | `longlived_bounds.py` → `executor.lease:LeaseRegistry.expired` | 13 / hostile stream | PS-S5-20260926-BASE-longlived-bounds-0007 | yes (simulated host) |
| `[M]` `sentinel_and_executor` incremental RSS | 4182016 B (tracemalloc peak 3562769 B); 0 planner modules loaded; 100 raced refused, 100 un-raced committed | `component_rss.py --repeats 3 --record` (separate processes, `ru_maxrss`) | 23 / TOCTOU setups | PS-S5-20260926-BASE-component-rss-0008 | yes |
| `[M]` `simulation_workspace` incremental RSS | 9633792 B (tracemalloc peak 6232318 B), 640 cones | `component_rss.py` | 23 / flood (40) | PS-S5-20260926-BASE-component-rss-0008 | yes |
| `[M]` hysteresis controller in isolation | acts 1 vs 120 (S1), 1 vs 64 (S2), 1 vs 1 (S3, both at 600 s) | `hysteresis_isolated.py --record` → `executor.lease:HysteresisController.decide` | 11 / three synthetic Phi traces | PS-S5-20260926-BASE-hysteresis-isolated-0009 | yes |
| `[M]` B7 is not single-world | primed, C4 hostile halves: `NOT_IDENTIFIABLE` 60 of 60 (rival world); C2: `HYSTERESIS` 5 | `b7_identifiability.py --record` → `aegis.planner:AegisPlanner.plan` | 11 / C1, C2, C4 | PS-S5-20260926-BASE-b7-identifiability-0010 | yes |
| `[M]` new tests | `tests/test_stage5_counter_corpora.py` 7 of 7; with `tests/test_stage5_boundary.py` 45 of 45 | `python3 -m pytest … --junitxml` | — | — | yes |
| `[M]` full test suite | 3008 tests, 2 failed (Stage 1 G1.12, process-wide peak RSS), 0 skipped; `test_stage5_*` 911 of 911 | `python3 -m pytest --junitxml` (loadavg 1.20 at start, 732.07 s) | — | — | yes |
| `[M]` ledger integrity after appending | 41 entries, `verify_integrity()` `[]` | `stage0.experiments.registry:ExperimentRegistry.verify_integrity` | — | — | n/a |

**`[F]` rows — fix wave (Part III).** Run from the repository root with `PYTHONHASHSEED=0`.

| claim | value | how it was produced | experiment id | synthetic? |
|---|---|---|---|---|
| `[F]` inherited tree before any fix | gate crashed with `AttributeError` before any check; non-slow Stage 5 tests 15 failed, 18 errors | `python -m pocketsec.stage5.cli gate`; `python -m pytest tests/test_stage5_*.py -m "not slow"` | — | n/a |
| `[F]` out-of-package mutation and sensitivity edits | 8 of 8 break their named test; each control passes | `pytest tests/test_stage5_gate.py -k test_every_mutation_edit_breaks_its_named_test` | — | n/a |
| `[F]` behavioural G5.13 probes | P1, P4–P9 hold on today's code and break under their patch; the F2 verifier scenario fails G5.13 naming P1 and P6 | `gate_assurance:mutation_results`; `tests/test_stage5_gate.py` | — | yes (simulated host) |
| `[F]` frontier stage against the policy pick | differs on 0 of 500 random objective assignments | `tests/test_stage5_aegis.py::test_the_frontier_stage_cannot_change_the_policy_pick` | — | yes |
| `[F]` inert ablation flags | unread: `enable_d3fend`, `enable_residual`; cells tripwire untouched on all 20 gate cases | `gate_measured:unread_ablation_flags`, `gate_measured:cells_consulted` | — | yes |
| `[F]` SENTINEL trusted surface | 1370 physical lines (kernel 554, monitors 374, preservation gate 442) against the ratchet's 1330 | `tests/test_stage5_sentinel.py::test_the_sentinel_trusted_surface_stays_inside_its_ratchet` | — | n/a |

### UNMEASURED
Absence of a row is a claim that everything was measured.

| claim the architecture makes | why not measured | what would measure it | blocking? |
|---|---|---|---|
| every autonomous operator meets a rollback reliability threshold (G5.7) | no real host; `SimulatedHost` rates are the complement of a chosen parameter | paired containment/restore drills on an instrumented Linux host, ≥8 per operator per kernel version | yes — G5.7 fails |
| safe recovery after containment (G5.11) | no real host; and every corpus host violates MC-03 before anything happens | the same drills, on a corpus with an admin-recovery session | yes — G5.11 fails |
| multi-world evaluation reduces collateral (G5.9) | the ambiguous-pair split is DEGENERATE; harm tables share an author with the planner | ambiguous incidents from real telemetry with independent ground truth | yes — G5.9 fails |
| Action Shadow calibration (F3) | no committed intervention produced a residual | ≥30 committed actions with measured residuals in one run | no |
| hysteresis reduces actions (ADR-0049) | single-shot corpus; no belief sequence oscillates around the threshold | a replayed belief-sequence corpus with B8 on the same sequences | no |
| response-cell staleness (F8) | cells are never consulted (no StateDelta bitmask at the seam) | a seam carrying the bitmask, then `build_two_epoch_corpus` | no |
| effectiveness-memory overfitting across epochs (F9) | no memory-backed autonomy decision was taken | two-epoch replay with autonomy enabled | no |
| two of seven §43 resource rows (`sentinel_and_executor`, `simulation_workspace`) | no self-reported footprint | a per-component allocator probe or a separate-process measurement | yes — G5.12 fails |
| the §40 RL planner and learned model-free controller baselines | ADR-0040 forbids numpy in Stage 5 | an offline research harness outside the privileged stage | no |
| commercial EDR playbooks | not present in the repository | licensed playbooks, run through the same harness | no |
| D3FEND mappings | no dated snapshot committed, no network | a committed dated D3FEND release | no |
| `mypy --strict` clean across Stage 5 | errors remain in builder packages (count in the completion report) | fixing them | no |

**`[M]` rows — measurement wave.**

| claim the architecture makes | why not measured | what would measure it | blocking? |
|---|---|---|---|
| `[M]` any Stage 5 response effectiveness on the real Stage 1→4 pipeline | Stage 4's exports carry no Stage 5 target key and identify nothing on Stage 4's corpus: 0 candidates, `NO_ACTION` 60 of 60 (M.7) | a Stage 4 exporter that names process lineage in `target_*` keys, then `benchmarks/stage5/stage4_seam.py` again | yes — the stage's value on its own pipeline |
| `[M]` whether the Action Shadow gate prevents harm on any host | its input is constant per operator on every corpus here, and no residual exists to calibrate against | ≥ 30 committed actions with measured residuals on a host the twin did not author | yes — F3, and the HARMFUL reading of SAFE-F04/05/06 |
| `[M]` multi-world value on ambiguous incidents | G5.9's pairs admit no operator harmless in one world and sufficient in the other (M.6) | a pair corpus whose truth tables contain such an operator | yes — G5.9 |
| `[M]` the two §43 rows *inside the gate* | measured here out of package (M.8), but the gate has no in-package producer and P2 forbids the launcher | a per-component allocator probe that lives in the package | yes — G5.12 still reads UNMEASURED |
| `[M]` executor liveness in a real long-running process | Stage 5 ships no runtime loop; the long-lived stack here is driven by a script | a daemon that owns the sweeper and journal compaction, run for days on a host | yes — M.9 |

### REJECTED

| component | measured effect | verdict (REJECTED / NOT-YET-JUSTIFIED / RETRACTED) | ADR |
|---|---|---|---|
| SAFE/AEGIS planning machinery (twin, cone, Pareto/regret, multi-world) as the autonomous path | contains 0 of 10 vs the playbook's 10, cold and primed | NOT-YET-JUSTIFIED on this corpus; removal from the autonomous path recommended | 0048 |
| each OPTIONAL SAFE-F04…F23 mechanism | ablation delta 0.0 | NOT-YET-JUSTIFIED | 0048 |
| hysteresis (SAFE-F18) | delta 0.0; not measurable here | NOT-YET-JUSTIFIED | 0049 |

**`[M]` rows — measurement wave.**

| component | measured effect | verdict (REJECTED / NOT-YET-JUSTIFIED / RETRACTED) | ADR |
|---|---|---|---|
| `[M]` Counterfactual Response Twin, Intervention Cone, Action Shadow gate (SAFE-F04/F05/F06) on the autonomous path | primed removal of any one: C1 0→10 contained, C2 0→5, collateral unchanged at 0 on all four corpora; cold: no effect | NOT-YET-JUSTIFIED — **measured HARMFUL on these corpora**; default-off recommended to the lead, **not applied** (safety veto; no free ADR number) | 0048 addendum |
| `[M]` the full SAFE/AEGIS planner as an autonomous chooser | 0 of 80 hostile contained over C1–C4, cold and primed, and at every swept ceiling never better than SW | REJECTED as the autonomous path on this evidence; retained as a recommendation generator | 0048 and addendum |
| `[M]` the fixed playbook B2 as the autonomous path (ADR-0048's recommendation) | its C1 win is a label leak (B2 = truth 20 of 20); on C2 [5 contained, 5 collateral] vs SW [10, 0] | REJECTED as a recommendation | 0048 addendum |
| `[M]` Pareto selector over scalar utility (SAFE-F08) | B6 = AEGIS in every cell, every corpus, every ceiling | NOT-YET-JUSTIFIED (F4) | 0048 |
| `[M]` lease/hysteresis controller (SAFE-F18) | in isolation 1 vs 120 and 1 vs 64 acts, no latency cost; end to end unreachable by AEGIS, and costs primed B7 5 containments on C2 | NOT-YET-JUSTIFIED as a system component | 0049 addendum |

### RETRACTED

| retracted claim | where it was published | the defect | corrected value |
|---|---|---|---|
| "a SUSPEND_PROCESS of a process holding process_memory_map is denied MISSION_INVARIANT, and that ordering is correct" | `tests/test_stage5_outcome.py` (pinned), builder reports | MI-04 ignored the bundle SENTINEL already held, making every DEGRADES_VOLATILE operator unreachable | the suspension proceeds once the evidence gate has preserved the signal; still denied without an accepted bundle |
| "the Pareto selector and scalar utility disagree on this corpus" | `tests/test_stage5_aegis.py` (whole-field scoring) | the disagreement came only from restoration operators wrongly in the field | they agree 20/20 on the whole field and disagree 10/10 on the intervention pool the planner actually uses |

**`[M]` rows — measurement wave.** None of the superseded text was deleted.

| retracted claim | where it was published | the defect | corrected value |
|---|---|---|---|
| `[M]` "Cold, … `None` blocks every autonomous leased intervention — so the planner escalates" | ADR-0048 Context | an inferred cause, not the recorded one | the planner records `SHADOW` on 20 of 20 containment candidates cold, identical to primed (PS-S5-20260926-BASE-shadow-gate-0004) |
| `[M]` "B7 single-world (no twin, no cone, no regret)" and "B7 single-world contained 0" as the single-world control | ADR-0048; Part II §5 (G5.9 detail); `labs/baselines.py` B7 docstring | `enable_multi_world=False` leaves Response Identifiability evaluating rival worlds | B7 rejects 60 of 60 C4 containments `NOT_IDENTIFIABLE`; the literal single-world control SW reads [10,0] C1, [10,0] C2, [0,0] C3, [30,30] C4 (-0010, -0002) |
| `[M]` "ship the fixed playbook behind SENTINEL … as the autonomous path" | ADR-0048 Decision 4; Part II §1 | B2's C1 result is one field that equals the label | no autonomous chooser is supported by these measurements (-0002, -0003) |
| `[M]` "max journal 3296 B, max active leases 1" read as evidence that executor state stays bounded under load | Part II §5 (G5.12 detail) | each figure is from a fresh stack per case | the numbers stand; under one long-lived stack every bound holds and liveness fails at 82 actions (-0007) |

**`[F]` rows — fix wave (Part III).** None of the superseded text was deleted.

| retracted claim | where it was published | the defect | corrected value |
|---|---|---|---|
| `[F]` "8 PROVEN_BY_CONSTRUCTION, 5 TESTED, 2 UNMEASURED" | Part II §4; M.11; ADR-0042 title and Decision 4 | P1's evidence could not see its guard deleted; P2 was a lexical denylist | 6 / 7 / 2; DOWNGRADED P1, P2, P3 (F.3) |
| `[F]` "Every PROVEN_BY_CONSTRUCTION row was mutation-run twice … in-process by the gate … 8/8 hold unmutated and fail mutated" | Part II §4 and the MEASURED row "mutation runs of the 8 PROVEN_BY_CONSTRUCTION rows"; M.11 ("8 of 8 mutations failing"); ADR-0042 Verification | each in-process probe read the surface its own patch edited, and passed with the entry guard deleted and SENTINEL switched off (F2) | the in-process run is not mutation evidence; the out-of-package test is (8 of 8 edits, with controls, this wave) |
| `[F]` "11/11 OPTIONAL ids carry a measured delta" | Part II §5 (G5.14 detail) | four deltas were 0.0 by construction (R7) | 7/11; SAFE-F16, F21, F22 and F23 are inert |
| `[F]` "`enable_residual` and `enable_d3fend` are read by other subsystems" | `aegis/planner.py` and `labs/fifty_experiments.py` docstrings | nothing reads them | corrected in both docstrings |
| `[F]` "incremental RSS 102400 B" as the reason F10 did not fire | Part II §3, F10 row | measured after every arm had run in the same process | F10 rests on M.8's separate-process rows (F.2, F7) |
| `[F]` `simulated_rollback_success` 1.0 (n=20) for both containment operators | Part II ledger; F6 row of Part II §3 | a no-op undo of a no-op action was scored as a success (fixed by the earlier batch) | 0.0 (n=20) in this wave's gate run; still in-simulator only |
| `[F]` G5.5 "substitute untouched True" as a discriminating signal | Part II §1 and §5 | the check could not fail for the race operator (F9) | it now also compares the socket, service and session state |
| `[F]` arm work units (AEGIS 2700, B2 380, B7 740 and the rest) | Part II §1, §3 and §5; MEMORY.md | executor spend was counted twice (F10) | AEGIS 2690, B2 370, B7 730 in this wave's gate run; the ordering of the arms is unchanged |

### NOT A DETECTION RESULT
Every corpus in this stage is synthetic, every host is `SimulatedHost`, and "collateral",
"sufficient operator" and "benign admin" are hand-written tables authored by the same wave as
the planner. Nothing here is a detection, response-effectiveness or collateral result about a
Linux host. The construction criteria (G5.2, G5.3, G5.5, G5.6, G5.8, G5.10) are properties of
the code and do not carry the authorship confound; the comparison criteria (G5.9, G5.14) do.

`[M]` The measurement wave adds two synthetic counter-corpora (C2, C4), three synthetic Phi
traces and a synthetic 600-action stream; every host is `SimulatedHost`. The one input that is
not a Stage 5 fixture — Stage 4's gate corpus in M.7 — is itself synthetic (Stage 1's
ambiguous corpus). Nothing here is a detection, response-effectiveness, collateral or
rollback result about a Linux host. M.7's negative is the exception in kind: it is a
structural property of the seam (which keys are written, which are read), and it holds for
any input.

### PARAMETERS
Every threshold, weight and bound below was CHOSEN, not measured. Values read from the code
this session.

| constant | value | module | why this value | measured? |
|---|---|---|---|---|
| `MAX_AUTONOMOUS_AUTHORITY` | A2 | `constitution/invariants.py` | O0–O3 only, §31 | no |
| `MAX_MISSION_INVARIANTS` / `MAX_INVARIANT_SET_BYTES` | 64 / 16384 | `constitution/schema.py` | bounded policy state | no |
| `MAX_CANDIDATES` | 16 | `safe/action_field.py` | §34 cap | no |
| `RULED_OUT_SUPPORT` | 0.05 | `safe/action_field.py` | a world below it cannot be cited | no |
| `MAX_TWIN_NODES` / `MAX_TWIN_DEPTH` / `MAX_TWIN_BYTES` / `MAX_TWIN_PROJECTIONS` | 64 / 2 / 20480 / 16 | `twin/response_twin.py` | bounded twin | no |
| `MAX_CONE_DEPTH` / `MAX_CONE_BRANCHES_PER_NODE` / `MAX_CONE_NODES` | 3 / 4 / 32 | `aegis/cone.py` | bounded cone | no |
| `MAX_CONCURRENT_LEASES` / `MAX_RENEWALS` / `MAX_LEASE_LIFETIME_SECONDS` / `DEFAULT_LEASE_TTL_SECONDS` | 4 / 3 / 3600 / 300 | `executor/lease.py` | bounded autonomy | no |
| `DEFAULT_HYSTERESIS` | enter 6.0, exit 3.0, dwell 120 s, cooldown 300 s, 3 cycles, escalate after 2 rollbacks | `executor/lease.py` | §19 | no |
| `MAX_JOURNAL_BYTES` / `MAX_JOURNAL_ENTRIES` | 262144 / 512 | `executor/journal.py` | bounded journal | no |
| `MAX_SPENT_NONCES` / `MAX_TOKEN_LIFETIME_SECONDS` | 256 / 900 | `authority/tokens.py` | replay window, stated as a bound | no |
| `MAX_BUNDLE_BYTES` / `MAX_VOLATILE_SIGNALS` | 65536 / 16 | `evidence/preservation_gate.py` | bounded bundle | no |
| `MAX_CATALOG_ENTRIES` | 32 | `operators/catalog.py` | headroom over 14 | no |
| `MAX_OPERATOR_DURATION_SECONDS` / `MAX_ARGV_ATOMS` | 900 / 8 | `operators/algebra.py` | bounded operator | no |
| `MAX_SIMULATED_PROCESSES` | 64 | `host/simulated.py` | bounded host model | no |
| `MAX_RECOVERY_STEPS` | 8 | `recovery/safe_state.py` | bounded recovery | no |
| `MAX_EFFECTIVENESS_RECORDS` / `MIN_SAMPLES_FOR_RATE` | 256 / 8 | `memory/effectiveness.py` | `None` below 8 | no |
| `AUTONOMOUS_ROLLBACK_THRESHOLD` | 0.98 | `memory/effectiveness.py` | §21 | no |
| `MAX_RESPONSE_CELLS` / `MIN_VERIFIED_EFFECTS_TO_CRYSTALLIZE` / `MIN_DISTINCT_EPOCHS_TO_CRYSTALLIZE` | 64 / 5 / 2 | `cells/response_cells.py` | §29 | no |
| `MAX_MONITOR_HISTORY` | 64 | `sentinel/monitors.py` | bounded monitors | no |
| `MAX_CONTRACT_BYTES` | 8192 | `aegis/human_contract.py` | bounded contract | no |
| `SHADOW_AUTONOMY_CEILING` / `SHADOW_HUMAN_CEILING` / `MIN_CALIBRATION_SAMPLES` | 0.35 / 0.70 / 30 | `aegis/shadow.py` | uncalibrated (F3); the ceiling decided ADR-0048's primed result | no |
| `DEFAULT_WEIGHTS` | 1.0 on each of nine objectives | `aegis/pareto.py` | B6's arbitrary scalarisation | no |
| `MATERIAL_RESIDUAL` | 0.25 | `executor/residual.py` | §21 | no |
| `SATURATION_EPSILON` | 0.01 | `labs/fifty_experiments.py` | ADR-0120's band | no |
| `STAGE5_NORMAL_INCREMENTAL_RSS_BYTES` / `STAGE5_PEAK_CEILING_BYTES` | 52428800 / 115343360 | `resources.py` | §43 | no |
| `ResourceBudget` (`STAGE5_BUDGET`) | 16 candidates, 8 worlds/action, 64 dependency nodes, 4096 work units, 8 autonomous actions per 3600 s | `governor.py` | §34 | no |

**`[M]` rows — measurement wave.**

| constant | value | module | why this value | measured? |
|---|---|---|---|---|
| `DECOUPLING_MODULUS` / residues | 4 / benign 0, hostile 1 | `labs/counter_corpora.py` | a quarter of each class re-hosted | no |
| `HOSTILE_LEADING_SUPPORT_GAP` | 0.10 | `labs/counter_corpora.py` | mirrors `AMBIGUOUS_SUPPORT_GAP`, inside `IDENTIFIABILITY_MARGIN` 0.15 | no |
| shadow ceilings swept | 0.35, 0.37, 0.42, 0.50, 0.70 | `benchmarks/stage5/shadow_gate.py` | around the two constant shadow values; sensitivity only | no |
| hysteresis traces | 240 samples × 30 s; S1 5.5/6.5; S2 uniform [3.5, 8.5] seed 11; S3 step at 600 s | `benchmarks/stage5/hysteresis_isolated.py` | bracket the 6.0 enter and 3.0 exit thresholds | no |
| long-lived stream | 600 actions; clock +3601 s (swept) or +30 s (unswept) per action | `benchmarks/stage5/longlived_bounds.py` | past every hard deadline, or well inside it | no |
| component RSS repeats | 3, median | `benchmarks/stage5/component_rss.py` | spread observed 28052–28220 KB privileged | no |


# Appendix A — commands and real output (measurement wave)

Every command below was run in this session from the repository root; output is pasted as printed. `results/*.json` is git-ignored, so the figures are quoted here.

### A.1 The gate, interactive run

```text
$ cat /proc/loadavg; /usr/bin/time -f 'wall %e s, user %U s, maxrss %M KB' env PYTHONHASHSEED=0 .venv/bin/python -m pocketsec.stage5.cli gate
2.17 2.46 2.86 3/1509 492598
PocketSec Stage 5 acceptance gate (simulated host; see ADR-0046)

  [PASS] G5.1  Stages 0-4 remain frozen interfaces for Stage 5
         53 of 53 seam symbols resolve (missing []); 5/5 pinned schema versions match SCHEMA_REGISTRY ; 0 R1/R2/T1 import violations under pocketsec/stage5 []; HYPOTHESES == H0..H8: True; experiments/registry.jsonl byte-identical since the run began: True. Stage 4's source is not diffed: another wave is editing it (§2.6)
  [PASS] G5.2  Only typed operators reach privilege
         (a) get_type_hints(TransactionalExecutor.execute)['operator'] is DefensiveOperator: True; (b) 5 of 5 forged arguments (str, dict, SimpleNamespace with its own argv, structurally equal OperatorSpec, deep-copied operator) raised at a real executor, host.apply calls during them 0, leaked []; (c) OperatorSpec outside catalog.py refused: True; (d) no_arbitrary_command_path(pocketsec/stage5) rows: 0 []
  [PASS] G5.3  SENTINEL independently denies every action regardless of planner output
         182 of 182 required denials (14 operators x 13 single-input mutations, planner at support 1.0 / uncertainty 0.0); compliant baselines passing 14/14; failures []; independence groups {'no bypass name': True, 'None -> MISSING_INPUT': True, 'weaker constitution unconstructable': True, 'raising check -> KERNEL_FAULT': True}; __init__ keyword-only parameters ['clock', 'constitution', 'invariants']
  [FAIL] G5.4  No model/LLM/text field grants authority or builds a privileged command
         (a) 10 of 20 corpus cases reach an identical (authority, required class, approval_required) at leading support 0.99 and 0.01; differing (decision at 0.99/0.01) ['corpus-011-001:ESCALATE/OBSERVE', 'corpus-011-003:ESCALATE/OBSERVE', 'corpus-011-005:ESCALATE/OBSERVE', 'corpus-011-007:ESCALATE/OBSERVE', 'corpus-011-009:ESCALATE/OBSERVE', 'corpus-011-011:ESCALATE/OBSERVE', 'corpus-011-013:ESCALATE/OBSERVE', 'corpus-011-015:ESCALATE/OBSERVE', 'corpus-011-017:ESCALATE/OBSERVE', 'corpus-011-019:ESCALATE/OBSERVE']; ACT-or-not identical 20/20 (0 ACT decisions in 40 plans, so this reading is vacuous here); per-operator authority identical 20/20 operators proposed at both; benefit estimate moved on 20 (non-vacuity); (b) GrantSource = ['HUMAN', 'POLICY']; (c) injected operator/imperative text changed no candidate and proposed no O6 under UNKNOWN on 4/4 cases; (d) POLICY grant refused for 3/3 HUMAN_BY_DEFAULT operators
  [PASS] G5.5  Target identity is revalidated immediately before intervention
         AST: revalidate immediately precedes self._host.apply in _commit: True; 4 of 4 TOCTOU races refused (EXITED=REFUSED_IDENTITY, PID_REUSED=REFUSED_IDENTITY, EXECUTABLE_CHANGED=REFUSED_IDENTITY, UID_CHANGED=REFUSED_IDENTITY); host.apply calls during races 0; substitute untouched True; identity_digest key space equal across token/lease/receipt on 20/20 committed corpus actions (simulated host; not a measurement of Linux pid recycling)
  [PASS] G5.6  Every autonomous intervention is scoped, expiring, observable and rollback-aware
         10 autonomous >=O2 containments committed on the hostile corpus cases (0 cases proposed no autonomous leased candidate); leased with a rollback operator, ttl <= max duration, matching target digest and >=1 probed postcondition: 10/10; under a ManualClock advanced past every hard deadline, LeaseSweeper.sweep() expired and rolled back 10/10 and left active(now) empty; capability signature restored to the pre-action snapshot 10/10 (simulated host)
  [FAIL] G5.7  Every autonomous operator meets a predefined rollback reliability threshold
         NOT MET — real-host rollback reliability is UNMEASURED: host_kind is SIMULATED and no RealHost exists (ADR-0046); what would measure it: paired containment/restore drills on an instrumented Linux host, >=8 per operator per kernel version. In-simulator only: RESTRICT_LOCAL_SOCKET simulated_rollback_success=1.0 n=20; SUSPEND_PROCESS simulated_rollback_success=1.0 n=20 (threshold 0.98, MIN_SAMPLES_FOR_RATE 8); 8 of 10 autonomous operators have no rate at all or miss it: ['HASH_EXECUTABLE', 'OBSERVE_PROCESS_METADATA', 'PRESERVE_VOLATILE_EVIDENCE', 'RELEASE_LOCAL_SOCKET', 'RESUME_PROCESS', 'SNAPSHOT_PROCESS_STATE', 'STOP_TRACE', 'TRACE_PROCESS_BOUNDED']
  [PASS] G5.8  Evidence and mission invariants are machine-enforced
         (a) 6/6 evidence-destroying suspensions refused REFUSED_WOULD_DESTROY -> REFUSED_EVIDENCE before the host, host unchanged, refusal in the receipt and in ResponseRecordV1.sentinel_denials []; (b) 6/6 critical-service baits denied MISSION_INVARIANT by SENTINEL; violations() is a total match over InvariantKind with no wildcard: True (AST; the gate runs no mypy); (c) across all 10 arms on the corpus: mission-invariant violations 0, evidence violations 0; (d) A5 HUMAN exception granted True, A5 POLICY exception refused True
  [FAIL] G5.9  Multi-world evaluation reduces collateral in ambiguous incidents
         30 ambiguous pairs (60 cases); saturation: DEGENERATE: degenerate control(s) ['B4'] reach the best containment 30 at collateral_per_1000_at_equal_containment 500.0000; §7 reports B1 and B4 as the frontier's endpoints, never as competitors, so a split they win is a split with no headroom; full planner contained 0 at collateral_per_1000 0.0 over 60 actions; B7 single-world contained 0 at 0.0 over 60 actions; strictly lower collateral False, containment no worse True. Within-model only: 'collateral' is defined by harm tables that share an author with the planner (§6.1). loadavg (2.32, 2.48, 2.86)
  [PASS] G5.10  Post-action verification detects ineffective or divergent actions
         2 of 2 injected faults detected (target 100%): enforcement_failure_rate=1.0 -> INEFFECTIVE / ROLLED_BACK, rollback attempted True; dependency_restart_rate=1.0 -> DIVERGENT / ROLLBACK_FAILED, rollback attempted True; target exits after an observation -> UNVERIFIABLE / COMMITTED_UNVERIFIED with 1 postcondition(s) satisfied=None (not False) (simulated host)
  [FAIL] G5.11  Safe recovery is demonstrated after containment
         NOT MET on a real host — every RecoveryReport has simulated=True and the criterion requires simulated is False (ADR-0046). Mechanism, in-simulator, over 20 contained hostile cases: capability signature restored to the pre-containment host 20/20; at most one capability changed between consecutive probes 20/20; steps succeeded 20/20; final_status INSIDE 0/20 — but only 0/20 hosts were INSIDE *before* containment (invariants already violated on the untouched corpus hosts: ['MC-03:no session and no running unit for recovery access']), so INSIDE is not reachable by undoing Stage 5's own change on this corpus
  [FAIL] G5.12  Resource and action fan-out remain bounded under adversarial load
         fan-out bounds held: True — adversarial suites within bound 5/5 (self_dos_suite=8/8, rollback_sabotage_suite=2/2, candidate_flood=40/64, token_replay_suite=1/1, dependency_poisoning_suite=8/8); action flood of 40 cases: max candidates 16, max cone depth 2 / nodes 11, max twin nodes 8, max work units 174 of 4096, 40/40 fields recorded the bound that cut them (budget/MAX_CANDIDATES truncation row), 0 BudgetExhausted escalations; max journal 3296 B, max active leases 1. Resource envelope: incremental RSS 233472 B (<= 50 MiB: True), process peak 39464960 B, within_target=None — UNMEASURED rows ['sentinel_and_executor', 'simulation_workspace'], so this criterion reports UNMEASURED and does not pass (§6). loadavg (2.32, 2.48, 2.86)
  [PASS] G5.13  Executor properties PROVEN_BY_CONSTRUCTION or explicitly downgraded to empirical
         counts {'PROVEN_BY_CONSTRUCTION': 8, 'TESTED': 5, 'UNMEASURED': 2, 'TOTAL': 15}; in-process mutation run (P2 forbids a process launcher here): 8/8 PROVEN_BY_CONSTRUCTION rows hold unmutated and fail under their mutation ['P1', 'P2', 'P4', 'P5', 'P6', 'P7', 'P8', 'P9']; surviving mutations []; stale mutation anchors []; unresolvable constructions []; UNMEASURED rows without why_not []; downgraded ['P3']; findings document present True, unearned verification language at lines []
  [FAIL] G5.14  Advanced mechanisms survive ablation against simpler playbooks/controllers
         saturation: not degenerate: best B2 contains 10 at 0.0000, median AEGIS contains 0 at 0.0000 on collateral_per_1000_at_equal_containment; Pareto frontier on (contained, collateral_per_1000, work units) = ['B1', 'B2', 'B5'], full planner on it: False; arms [AEGIS 0c/0.0/2700wu, B1 0c/None/360wu, B2 10c/0.0/380wu, B3 10c/500.0/400wu, B4 10c/500.0/400wu, B5 0c/None/360wu, B6 0c/0.0/2700wu, B7 0c/0.0/740wu, B8 0c/0.0/2700wu, B9 10c/0.0/410wu]; 11/11 OPTIONAL ids carry a measured delta, 11 registered in a temporary ledger; verdicts {'SAFE-F04': 'enable_twin:NOT_YET_JUSTIFIED(0.0)', 'SAFE-F05': 'enable_cone:NOT_YET_JUSTIFIED(0.0)', 'SAFE-F06': 'enable_shadow_gate:NOT_YET_JUSTIFIED(0.0)', 'SAFE-F07': 'enable_regret:NOT_YET_JUSTIFIED(0.0)', 'SAFE-F08': 'enable_pareto:NOT_YET_JUSTIFIED(0.0)', 'SAFE-F16': 'enable_residual:NOT_YET_JUSTIFIED(0.0)', 'SAFE-F18': 'enable_hysteresis:NOT_YET_JUSTIFIED(0.0)', 'SAFE-F20': 'enable_effectiveness_memory:NOT_YET_JUSTIFIED(0.0)', 'SAFE-F21': 'enable_response_cells:NOT_YET_JUSTIFIED(0.0)', 'SAFE-F22': 'enable_response_cells:NOT_YET_JUSTIFIED(0.0)', 'SAFE-F23': 'enable_d3fend:NOT_YET_JUSTIFIED(0.0)'}. Sensitivity, memory primed by in-simulator LAB_SANDBOX drills (not a pass condition): [AEGIS 0c/0.0/2700wu/10esc, B6 0c/0.0/2700wu/10esc, B7 10c/0.0/770wu/0esc, B8 0c/0.0/2700wu/10esc]. In-simulator comparison only (§6.1). loadavg (2.17, 2.46, 2.86)
  [PASS] G5.15  No external novelty claim before literature/patent review
         HYPOTHESES == H0..H8 True; prior-art ledger keys == HYPOTHESES True (Stage 5 appended to neither); docs/stage-5-findings.md present True, missing honesty headings [], novelty words near a §49 construct without 'no novelty claim' []; D3FEND mapped_fraction 0.0 (0.0 = every operator UNMAPPED, ADR-0047); experiments/registry.jsonl byte-identical before and after the gate True

loadavg at end of run: 2.29 2.47 2.86
GATE: FAILED (6)
Command exited with non-zero status 1
wall 11.56 s, user 11.52 s, maxrss 39652 KB
```

### A.2 Every arm on four corpora

```text
$ PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage5/arms.py --record PS-S5-20260926-BASE-arms-counter-corpora-0002

C1_corpus_20_11  (20 cases, 10 hostile) sha256 07fe384c7ece3b28
  arm           contained  missed  actions collateral collat/1000  esc faults  cpu_s/case   x B2
  AEGIS                 0      10       10          0         0.0   10      0     0.00814    3.9
  AEGIS+primed          0      10       10          0         0.0   10      0     0.09473   44.9
  B1                    0      10        0          0        None    0      0     0.00278    1.3
  B2                   10       0       10          0         0.0    0      0     0.00211    1.0
  B3                   10       0       20         10       500.0    0      0     0.00331    1.6
  B4                   10       0       20         10       500.0    0      0     0.00327    1.6
  B5                    0      10        0          0        None    0      0     0.00219    1.0
  B6                    0      10       10          0         0.0   10      0     0.00834    4.0
  B6+primed             0      10       10          0         0.0   10      0     0.10383   49.2
  B7                    0      10       10          0         0.0   10      0     0.00435    2.1
  B7+primed            10       0       20          0         0.0    0      0     0.08792   41.6
  B7-nohyst             0      10       10          0         0.0   10      0     0.00429    2.0
  B7-nohyst+primed        10       0       20          0         0.0    0      0     0.08918   42.2
  B8                    0      10       10          0         0.0   10      0     0.00740    3.5
  B8+primed             0      10       10          0         0.0   10      0     0.09226   43.7
  B9                   10       0       20          0         0.0   20      0     0.00254    1.2
  SW                   10       0       10          0         0.0    0      0     0.00234    1.1

C2_decoupled_20_11  (20 cases, 10 hostile) sha256 018f9d98d50362f2
  arm           contained  missed  actions collateral collat/1000  esc faults  cpu_s/case   x B2
  AEGIS                 0      10       10          0         0.0   10      0     0.00710    3.3
  AEGIS+primed          0      10       10          0         0.0   10      0     0.08559   39.6
  B1                    0      10        0          0        None    0      0     0.00169    0.8
  B2                    5       5       10          5       500.0    0      0     0.00216    1.0
  B3                   10       0       20         10       500.0    0      0     0.00243    1.1
  B4                   10       0       20         10       500.0    0      0     0.00261    1.2
  B5                    0      10        0          0        None    0      0     0.00158    0.7
  B6                    0      10       10          0         0.0   10      0     0.00948    4.4
  B6+primed             0      10       10          0         0.0   10      0     0.09548   44.2
  B7                    0      10       10          0         0.0   10      0     0.00403    1.9
  B7+primed             5       5       15          0         0.0    5      0     0.08471   39.2
  B7-nohyst             0      10       10          0         0.0   10      0     0.00452    2.1
  B7-nohyst+primed        10       0       20          0         0.0    0      0     0.08826   40.9
  B8                    0      10       10          0         0.0   10      0     0.00757    3.5
  B8+primed             0      10       10          0         0.0   10      0     0.08574   39.7
  B9                   10       0       20          0         0.0   20      0     0.00258    1.2
  SW                   10       0       10          0         0.0    0      0     0.00340    1.6

C3_benign_leading_pairs_30_11  (60 cases, 30 hostile) sha256 59ea2780eb241ca0
  arm           contained  missed  actions collateral collat/1000  esc faults  cpu_s/case   x B2
  AEGIS                 0      30       60          0         0.0    0      0     0.00819    3.4
  AEGIS+primed          0      30       60          0         0.0    0      0     0.08621   36.1
  B1                    0      30        0          0        None    0      0     0.00152    0.6
  B2                   30       0       60         30       500.0    0      0     0.00239    1.0
  B3                   30       0       60         30       500.0    0      0     0.00238    1.0
  B4                   30       0       60         30       500.0    0      0     0.00271    1.1
  B5                    0      30        0          0        None    0      0     0.00172    0.7
  B6                    0      30       60          0         0.0    0      0     0.00834    3.5
  B6+primed             0      30       60          0         0.0    0      0     0.09036   37.8
  B7                    0      30       60          0         0.0    0      0     0.00476    2.0
  B7+primed             0      30       60          0         0.0    0      0     0.07445   31.1
  B7-nohyst             0      30       60          0         0.0    0      0     0.00462    1.9
  B7-nohyst+primed         0      30       60          0         0.0    0      0     0.07508   31.4
  B8                    0      30       60          0         0.0    0      0     0.00797    3.3
  B8+primed             0      30       60          0         0.0    0      0     0.07434   31.1
  B9                   30       0       60          0         0.0   60      0     0.00270    1.1
  SW                    0      30        0          0        None    0      0     0.00164    0.7

C4_hostile_leading_pairs_30_11  (60 cases, 30 hostile) sha256 7fce3ea39aa093bd
  arm           contained  missed  actions collateral collat/1000  esc faults  cpu_s/case   x B2
  AEGIS                 0      30       60          0         0.0    0      0     0.00626    3.0
  AEGIS+primed          0      30       60          0         0.0    0      0     0.07493   35.9
  B1                    0      30        0          0        None    0      0     0.00138    0.7
  B2                   30       0       60         30       500.0    0      0     0.00209    1.0
  B3                   30       0       60         30       500.0    0      0     0.00238    1.1
  B4                   30       0       60         30       500.0    0      0     0.00210    1.0
  B5                    0      30        0          0        None    0      0     0.00138    0.7
  B6                    0      30       60          0         0.0    0      0     0.00764    3.7
  B6+primed             0      30       60          0         0.0    0      0     0.07027   33.6
  B7                    0      30       60          0         0.0    0      0     0.00397    1.9
  B7+primed             0      30       60          0         0.0    0      0     0.06857   32.8
  B7-nohyst             0      30       60          0         0.0    0      0     0.00402    1.9
  B7-nohyst+primed         0      30       60          0         0.0    0      0     0.07033   33.7
  B8                    0      30       60          0         0.0    0      0     0.00741    3.5
  B8+primed             0      30       60          0         0.0    0      0     0.07433   35.6
  B9                   30       0       60          0         0.0   60      0     0.00213    1.0
  SW                   30       0       60         30       500.0    0      0     0.00250    1.2

loadavg before [3.59, 2.64, 2.84] after [3.11, 2.75, 2.87]
recorded PS-S5-20260926-BASE-arms-counter-corpora-0002 -> results/PS-S5-20260926-BASE-arms-counter-corpora-0002.json
```

### A.3 Corpus audit

```text
$ PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage5/corpus_audit.py --record PS-S5-20260926-BASE-corpus-audit-0003
C1_label_leak: {"phi_by_class": {"benign=True,phi=4.0": 10, "benign=False,phi=10.0": 10}, "b2_decision_equals_truth": 20, "stage4_leading_equals_truth": 20, "cases": 20}
C2_label_leak: {"phi_by_class": {"benign=True,phi=10.0": 5, "benign=False,phi=4.0": 5, "benign=True,phi=4.0": 5, "benign=False,phi=10.0": 5}, "b2_decision_equals_truth": 10, "stage4_leading_equals_truth": 20, "cases": 20}
C3_feasibility: {"pairs": 30, "feasible_set_size_histogram": {"0": 30}, "resolutions_identical": 30, "benign_world_leads": 30}
C4_feasibility: {"pairs": 30, "feasible_set_size_histogram": {"0": 30}, "resolutions_identical": 30, "benign_world_leads": 0}
rule1_identities: {"rows": 80, "unique": 80, "rows_incl_shared_pair_halves": 140}
loadavg before [3.11, 2.75, 2.87] after [3.11, 2.75, 2.87]
recorded PS-S5-20260926-BASE-corpus-audit-0003 -> results/PS-S5-20260926-BASE-corpus-audit-0003.json
```

### A.4 Action Shadow constancy and ceiling sensitivity

```text
$ PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage5/shadow_gate.py --record PS-S5-20260926-BASE-shadow-gate-0004
A. distinct shadow values per operator (containment operators shown)
  C1_corpus_20_11                  n=20  {"RESTRICT_LOCAL_SOCKET": {"generation": [0.1667], "cone_informed": [0.3627]}, "SUSPEND_PROCESS": {"generation": [0.25], "cone_informed": [0.4146]}}
  C3_benign_leading_pairs_30_11    n=60  {"RESTRICT_LOCAL_SOCKET": {"generation": [0.1667], "cone_informed": [0.3627]}, "SUSPEND_PROCESS": {"generation": [0.25], "cone_informed": [0.4146]}}
  two_epoch_20_11                  n=20  {"RESTRICT_LOCAL_SOCKET": {"generation": [0.1667], "cone_informed": [0.3627]}, "SUSPEND_PROCESS": {"generation": [0.25], "cone_informed": [0.4146]}}
  evidence_6_11                    n=6   {"RESTRICT_LOCAL_SOCKET": {"generation": [0.1667], "cone_informed": [0.3627]}, "SUSPEND_PROCESS": {"generation": [0.2917], "cone_informed": [0.4348]}}
  flood_10_11                      n=10  {"RESTRICT_LOCAL_SOCKET": {"generation": [0.1667], "cone_informed": [0.4348]}, "SUSPEND_PROCESS": {"generation": [0.25], "cone_informed": [0.4628]}}
  ceiling SHADOW_AUTONOMY_CEILING = 0.35
  C1 hostile cases, full planner: {"cold": {"decisions": {"ESCALATE": 10}, "containment_rejections": {"RESTRICT_LOCAL_SOCKET:SHADOW": 10, "SUSPEND_PROCESS:SHADOW": 10}}, "primed": {"decisions": {"ESCALATE": 10}, "containment_rejections": {"RESTRICT_LOCAL_SOCKET:SHADOW": 10, "SUSPEND_PROCESS:SHADOW": 10}}}

B. sensitivity to SHADOW_AUTONOMY_CEILING: [contained, collateral, actions, escalations]
  ceiling 0.35  {"C1": {"AEGIS": [0, 0, 10, 10], "AEGIS+primed": [0, 0, 10, 10], "B6+primed": [0, 0, 10, 10]}, "C2": {"AEGIS": [0, 0, 10, 10], "AEGIS+primed": [0, 0, 10, 10], "B6+primed": [0, 0, 10, 10]}, "C3": {"AEGIS": [0, 0, 60, 0], "AEGIS+primed": [0, 0, 60, 0], "B6+primed": [0, 0, 60, 0]}, "C4": {"AEGIS": [0, 0, 60, 0], "AEGIS+primed": [0, 0, 60, 0], "B6+primed": [0, 0, 60, 0]}}
  ceiling 0.37  {"C1": {"AEGIS": [0, 0, 10, 10], "AEGIS+primed": [10, 0, 20, 0], "B6+primed": [10, 0, 20, 0]}, "C2": {"AEGIS": [0, 0, 10, 10], "AEGIS+primed": [5, 0, 15, 5], "B6+primed": [5, 0, 15, 5]}, "C3": {"AEGIS": [0, 0, 60, 0], "AEGIS+primed": [0, 0, 60, 0], "B6+primed": [0, 0, 60, 0]}, "C4": {"AEGIS": [0, 0, 60, 0], "AEGIS+primed": [0, 0, 60, 0], "B6+primed": [0, 0, 60, 0]}}
  ceiling 0.42  {"C1": {"AEGIS": [0, 0, 10, 10], "AEGIS+primed": [10, 0, 20, 0], "B6+primed": [10, 0, 20, 0]}, "C2": {"AEGIS": [0, 0, 10, 10], "AEGIS+primed": [5, 0, 15, 5], "B6+primed": [5, 0, 15, 5]}, "C3": {"AEGIS": [0, 0, 60, 0], "AEGIS+primed": [0, 0, 60, 0], "B6+primed": [0, 0, 60, 0]}, "C4": {"AEGIS": [0, 0, 60, 0], "AEGIS+primed": [0, 0, 60, 0], "B6+primed": [0, 0, 60, 0]}}
  ceiling 0.5   {"C1": {"AEGIS": [0, 0, 10, 10], "AEGIS+primed": [10, 0, 20, 0], "B6+primed": [10, 0, 20, 0]}, "C2": {"AEGIS": [0, 0, 10, 10], "AEGIS+primed": [5, 0, 15, 5], "B6+primed": [5, 0, 15, 5]}, "C3": {"AEGIS": [0, 0, 60, 0], "AEGIS+primed": [0, 0, 60, 0], "B6+primed": [0, 0, 60, 0]}, "C4": {"AEGIS": [0, 0, 60, 0], "AEGIS+primed": [0, 0, 60, 0], "B6+primed": [0, 0, 60, 0]}}
  ceiling 0.7   {"C1": {"AEGIS": [0, 0, 10, 10], "AEGIS+primed": [10, 0, 20, 0], "B6+primed": [10, 0, 20, 0]}, "C2": {"AEGIS": [0, 0, 10, 10], "AEGIS+primed": [5, 0, 15, 5], "B6+primed": [5, 0, 15, 5]}, "C3": {"AEGIS": [0, 0, 60, 0], "AEGIS+primed": [0, 0, 60, 0], "B6+primed": [0, 0, 60, 0]}, "C4": {"AEGIS": [0, 0, 60, 0], "AEGIS+primed": [0, 0, 60, 0], "B6+primed": [0, 0, 60, 0]}}
loadavg before [3.11, 2.75, 2.87] after [2.56, 2.65, 2.81]
recorded PS-S5-20260926-BASE-shadow-gate-0004 -> results/PS-S5-20260926-BASE-shadow-gate-0004.json
```

### A.5 Leave-one-out ablation, cold and primed

```text
$ PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage5/ablation_primed.py --record PS-S5-20260926-BASE-ablation-primed-0005

== cold: [contained, collateral, actions, escalations] per corpus
  FULL                                               {"C1": [0, 0, 10, 10], "C2": [0, 0, 10, 10], "C3": [0, 0, 60, 0], "C4": [0, 0, 60, 0]}  -
  enable_multi_world                                 {"C1": [0, 0, 10, 10], "C2": [0, 0, 10, 10], "C3": [0, 0, 60, 0], "C4": [0, 0, 60, 0]}  NOT-YET-JUSTIFIED (no effect on any corpus)
  enable_twin                   SAFE-F04             {"C1": [0, 0, 10, 10], "C2": [0, 0, 10, 10], "C3": [0, 0, 60, 0], "C4": [0, 0, 60, 0]}  NOT-YET-JUSTIFIED (no effect on any corpus)
  enable_cone                   SAFE-F05             {"C1": [0, 0, 10, 10], "C2": [0, 0, 10, 10], "C3": [0, 0, 60, 0], "C4": [0, 0, 60, 0]}  NOT-YET-JUSTIFIED (no effect on any corpus)
  enable_shadow_gate            SAFE-F06             {"C1": [0, 0, 10, 10], "C2": [0, 0, 10, 10], "C3": [0, 0, 60, 0], "C4": [0, 0, 60, 0]}  NOT-YET-JUSTIFIED (no effect on any corpus)
  enable_regret                 SAFE-F07             {"C1": [0, 0, 10, 10], "C2": [0, 0, 10, 10], "C3": [0, 0, 60, 0], "C4": [0, 0, 60, 0]}  NOT-YET-JUSTIFIED (no effect on any corpus)
  enable_pareto                 SAFE-F08             {"C1": [0, 0, 10, 10], "C2": [0, 0, 10, 10], "C3": [0, 0, 60, 0], "C4": [0, 0, 60, 0]}  NOT-YET-JUSTIFIED (no effect on any corpus)
  enable_hysteresis             SAFE-F18             {"C1": [0, 0, 10, 10], "C2": [0, 0, 10, 10], "C3": [0, 0, 60, 0], "C4": [0, 0, 60, 0]}  NOT-YET-JUSTIFIED (no effect on any corpus)
  enable_effectiveness_memory   SAFE-F20             {"C1": [0, 0, 10, 10], "C2": [0, 0, 10, 10], "C3": [0, 0, 60, 0], "C4": [0, 0, 60, 0]}  NOT-YET-JUSTIFIED (no effect on any corpus)
  enable_response_cells         SAFE-F21,SAFE-F22    {"C1": [0, 0, 10, 10], "C2": [0, 0, 10, 10], "C3": [0, 0, 60, 0], "C4": [0, 0, 60, 0]}  NOT-YET-JUSTIFIED (no effect on any corpus)
  enable_residual               SAFE-F16             {"C1": [0, 0, 10, 10], "C2": [0, 0, 10, 10], "C3": [0, 0, 60, 0], "C4": [0, 0, 60, 0]}  NOT-YET-JUSTIFIED (no effect on any corpus)
  enable_d3fend                 SAFE-F23             {"C1": [0, 0, 10, 10], "C2": [0, 0, 10, 10], "C3": [0, 0, 60, 0], "C4": [0, 0, 60, 0]}  NOT-YET-JUSTIFIED (no effect on any corpus)

== primed: [contained, collateral, actions, escalations] per corpus
  FULL                                               {"C1": [0, 0, 10, 10], "C2": [0, 0, 10, 10], "C3": [0, 0, 60, 0], "C4": [0, 0, 60, 0]}  -
  enable_multi_world                                 {"C1": [0, 0, 10, 10], "C2": [0, 0, 10, 10], "C3": [0, 0, 60, 0], "C4": [0, 0, 60, 0]}  NOT-YET-JUSTIFIED (no effect on any corpus)
  enable_twin                   SAFE-F04             {"C1": [10, 0, 20, 0], "C2": [5, 0, 15, 5], "C3": [0, 0, 60, 0], "C4": [0, 0, 60, 0]}  HARMFUL (removal strictly better on some corpus, worse on none)
  enable_cone                   SAFE-F05             {"C1": [10, 0, 20, 0], "C2": [5, 0, 15, 5], "C3": [0, 0, 60, 0], "C4": [0, 0, 60, 0]}  HARMFUL (removal strictly better on some corpus, worse on none)
  enable_shadow_gate            SAFE-F06             {"C1": [10, 0, 20, 0], "C2": [5, 0, 15, 5], "C3": [0, 0, 60, 0], "C4": [0, 0, 60, 0]}  HARMFUL (removal strictly better on some corpus, worse on none)
  enable_regret                 SAFE-F07             {"C1": [0, 0, 10, 10], "C2": [0, 0, 10, 10], "C3": [0, 0, 60, 0], "C4": [0, 0, 60, 0]}  NOT-YET-JUSTIFIED (no effect on any corpus)
  enable_pareto                 SAFE-F08             {"C1": [0, 0, 10, 10], "C2": [0, 0, 10, 10], "C3": [0, 0, 60, 0], "C4": [0, 0, 60, 0]}  NOT-YET-JUSTIFIED (no effect on any corpus)
  enable_hysteresis             SAFE-F18             {"C1": [0, 0, 10, 10], "C2": [0, 0, 10, 10], "C3": [0, 0, 60, 0], "C4": [0, 0, 60, 0]}  NOT-YET-JUSTIFIED (no effect on any corpus)
  enable_effectiveness_memory   SAFE-F20             {"C1": [0, 0, 10, 10], "C2": [0, 0, 10, 10], "C3": [0, 0, 60, 0], "C4": [0, 0, 60, 0]}  NOT-YET-JUSTIFIED (no effect on any corpus)
  enable_response_cells         SAFE-F21,SAFE-F22    {"C1": [0, 0, 10, 10], "C2": [0, 0, 10, 10], "C3": [0, 0, 60, 0], "C4": [0, 0, 60, 0]}  NOT-YET-JUSTIFIED (no effect on any corpus)
  enable_residual               SAFE-F16             {"C1": [0, 0, 10, 10], "C2": [0, 0, 10, 10], "C3": [0, 0, 60, 0], "C4": [0, 0, 60, 0]}  NOT-YET-JUSTIFIED (no effect on any corpus)
  enable_d3fend                 SAFE-F23             {"C1": [0, 0, 10, 10], "C2": [0, 0, 10, 10], "C3": [0, 0, 60, 0], "C4": [0, 0, 60, 0]}  NOT-YET-JUSTIFIED (no effect on any corpus)

loadavg before [2.24, 2.58, 2.79] after [2.61, 2.62, 2.77]
recorded PS-S5-20260926-BASE-ablation-primed-0005 -> results/PS-S5-20260926-BASE-ablation-primed-0005.json
```

### A.6 Stage 4's real exports through Stage 5

```text
$ PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage5/stage4_seam.py --record PS-S5-20260926-BASE-stage4-seam-0006
stage4_incidents: 60
stage4_engine_cpu_seconds: 6.253
identifiability: {"UNKNOWN": 60}
verdict: {"UNKNOWN": 60}
hypotheses_per_export: {"3": 32, "2": 11, "4": 17}
lineage_keys: {"store": 3764, "locator": 3764, "digest": 3764}
lineage_rows: 3764
lineage_rows_with_a_target_key: 0
stage5_candidates_by_operator: {}
stage5_field_truncations_top: [["identifiability UNKNOWN is not in ACTIONABLE_IDENTIFIABILITY, so only O0/O1 may be propose", 300], ["a restoration operator is reachable only as a rollback or a recovery step, never as an inc", 240], ["cells (ResponseCellField) are keyed by incident_invariant_key(mechanism_id, state_delta_ma", 60], ["no intervention survived and the resolution names no observable process target, so the fie", 60]]
aegis_decisions: {"NO_ACTION": 60}
stage5_target_keys: ["target_pid", "target_session", "target_socket", "target_unit"]
exports_sha256: "309dd1fc80db17a386dcc71d6a53814403c3dd77a04be720005bde59ce46bd3c"
loadavg before [2.61, 2.62, 2.77] after [2.56, 2.61, 2.76]
recorded PS-S5-20260926-BASE-stage4-seam-0006 -> results/PS-S5-20260926-BASE-stage4-seam-0006.json
```

### A.7 One long-lived executor stack

```text
$ PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage5/longlived_bounds.py 600 --record PS-S5-20260926-BASE-longlived-bounds-0007
A_sweep_each: {"outcomes": {"COMMITTED_VERIFIED": 82, "REFUSED_JOURNAL_FULL": 518}, "first_index": {"COMMITTED_VERIFIED": 0, "REFUSED_JOURNAL_FULL": 82}, "deny_reasons": {}, "checkpoints": [{"actions": 100, "journal_bytes": 258224, "journal_entries": 492, "journal_full": true, "active_leases": 0, "spent_nonces": 182, "nonce_evictions": 0, "memory_rows": 1, "memory_evictions": 0, "traced_bytes_over_start": 384924}, {"actions": 200, "journal_bytes": 258224, "journal_entries": 492, "journal_full": true, "active_leases": 0, "spent_nonces": 256, "nonce_evictions": 26, "memory_rows": 1, "memory_evictions": 0, "traced_bytes_over_start": 394516}, {"actions": 300, "journal_bytes": 258224, "journal_entries": 492, "journal_full": true, "active_leases": 0, "spent_nonces": 256, "nonce_evictions": 126, "memory_rows": 1, "memory_evictions": 0, "traced_bytes_over_start": 422692}, {"actions": 400, "journal_bytes": 258224, "journal_entries": 492, "journal_full": true, "active_leases": 0, "spent_nonces": 256, "nonce_evictions": 226, "memory_rows": 1, "memory_evictions": 0, "traced_bytes_over_start": 424432}, {"actions": 500, "journal_bytes": 258224, "journal_entries": 492, "journal_full": true, "active_leases": 0, "spent_nonces": 256, "nonce_evictions": 326, "memory_rows": 1, "memory_evictions": 0, "traced_bytes_over_start": 424860}, {"actions": 600, "journal_bytes": 258224, "journal_entries": 492, "journal_full": true, "active_leases": 0, "spent_nonces": 256, "nonce_evictions": 426, "memory_ro …[line truncated here; full text in results/]
B_never_sweep: {"outcomes": {"COMMITTED_VERIFIED": 9, "REFUSED_SENTINEL": 241, "REFUSED_JOURNAL_FULL": 350}, "first_index": {"COMMITTED_VERIFIED": 0, "REFUSED_SENTINEL": 1, "REFUSED_JOURNAL_FULL": 250}, "deny_reasons": {"PRECONDITION": 241, "FORBIDDEN_COMBINATION": 241}, "checkpoints": [{"actions": 100, "journal_bytes": 94331, "journal_entries": 204, "journal_full": false, "active_leases": 1, "spent_nonces": 100, "nonce_evictions": 0, "memory_rows": 1, "memory_evictions": 0, "traced_bytes_over_start": 173295}, {"actions": 200, "journal_bytes": 188023, "journal_entries": 407, "journal_full": false, "active_leases": 1, "spent_nonces": 200, "nonce_evictions": 0, "memory_rows": 1, "memory_evictions": 0, "traced_bytes_over_start": 291561}, {"actions": 300, "journal_bytes": 235301, "journal_entries": 509, "journal_full": true, "active_leases": 0, "spent_nonces": 256, "nonce_evictions": 44, "memory_rows": 1, "memory_evictions": 0, "traced_bytes_over_start": 352633}, {"actions": 400, "journal_bytes": 235301, "journal_entries": 509, "journal_full": true, "active_leases": 0, "spent_nonces": 256, "nonce_evictions": 144, "memory_rows": 1, "memory_evictions": 0, "traced_bytes_over_start": 380805}, {"actions": 500, "journal_bytes": 235301, "journal_entries": 509, "journal_full": true, "active_leases": 0, "spent_nonces": 256, "nonce_evictions": 244, "memory_rows": 1, "memory_evictions": 0, "traced_bytes_over_start": 384401}, {"actions": 600, "journal_bytes": 235301, "journal_entries": 509,  …[line truncated here; full text in results/]
C_unswept_persistence: {"actions": 60, "committed": 2, "still_contained_after_every_hard_deadline_without_sweep": 2, "leases_expired_by_data": 2, "leases_active": 0}
bounds: {"MAX_JOURNAL_BYTES": 262144, "MAX_JOURNAL_ENTRIES": 512, "MAX_CONCURRENT_LEASES": 4, "MAX_SPENT_NONCES": 256, "MAX_EFFECTIVENESS_RECORDS": 256}
loadavg before [2.56, 2.61, 2.76] after [2.4, 2.57, 2.75]
recorded PS-S5-20260926-BASE-longlived-bounds-0007 -> results/PS-S5-20260926-BASE-longlived-bounds-0007.json
```

### A.8 Component RSS in separate processes

```text
$ PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage5/component_rss.py --repeats 3 --record PS-S5-20260926-BASE-component-rss-0008
baseline: {"median_ru_maxrss_kb": 24100, "incremental_over_baseline_bytes": 0, "median_tracemalloc_peak_bytes": 0, "planner_modules_loaded": [], "work": {}, "all_ru_maxrss_kb": [24100, 24100, 24100]}
privileged: {"median_ru_maxrss_kb": 28184, "incremental_over_baseline_bytes": 4182016, "median_tracemalloc_peak_bytes": 3562769, "planner_modules_loaded": [], "work": {"race_transactions": 100, "races_refused": 100, "unraced_transactions": 100, "unraced_outcomes": {"COMMITTED_VERIFIED": 100}}, "all_ru_maxrss_kb": [28184, 28220, 28052]}
simulation: {"median_ru_maxrss_kb": 33508, "incremental_over_baseline_bytes": 9633792, "median_tracemalloc_peak_bytes": 6232318, "planner_modules_loaded": ["pocketsec.stage5.aegis", "pocketsec.stage5.aegis.cone", "pocketsec.stage5.aegis.human_contract", "pocketsec.stage5.aegis.pareto", "pocketsec.stage5.aegis.planner", "pocketsec.stage5.aegis.shadow", "pocketsec.stage5.cells", "pocketsec.stage5.cells.response_cells", "pocketsec.stage5.memory", "pocketsec.stage5.memory.effectiveness", "pocketsec.stage5.safe", "pocketsec.stage5.safe.action_field", "pocketsec.stage5.twin", "pocketsec.stage5.twin.response_twin"], "work": {"cones": 640, "twin_predictions": 640, "cases": 40}, "all_ru_maxrss_kb": [33508, 33500, 33532]}
loadavg before [2.4, 2.57, 2.75] after [2.69, 2.63, 2.77]
recorded PS-S5-20260926-BASE-component-rss-0008 -> results/PS-S5-20260926-BASE-component-rss-0008.json
```

### A.9 Hysteresis controller in isolation

```text
$ PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage5/hysteresis_isolated.py --record PS-S5-20260926-BASE-hysteresis-isolated-0009
S1_oscillation: {"hysteresis": {"acts": 1, "releases": 0, "escalate_samples": 0, "first_act_seconds": 30, "active_at_end": true}, "single_threshold": {"acts": 120, "releases": 119, "escalate_samples": 0, "first_act_seconds": 30, "active_at_end": true}}
S2_noise: {"hysteresis": {"acts": 1, "releases": 0, "escalate_samples": 0, "first_act_seconds": 30, "active_at_end": true}, "single_threshold": {"acts": 64, "releases": 63, "escalate_samples": 0, "first_act_seconds": 30, "active_at_end": true}}
S3_step: {"hysteresis": {"acts": 1, "releases": 0, "escalate_samples": 0, "first_act_seconds": 600, "active_at_end": true}, "single_threshold": {"acts": 1, "releases": 0, "escalate_samples": 0, "first_act_seconds": 600, "active_at_end": true}}
loadavg before [2.69, 2.63, 2.77] after [2.69, 2.63, 2.77]
recorded PS-S5-20260926-BASE-hysteresis-isolated-0009 -> results/PS-S5-20260926-BASE-hysteresis-isolated-0009.json
```

### A.10 B7 identifiability diagnostic

```text
$ PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage5/b7_identifiability.py --record PS-S5-20260926-BASE-b7-identifiability-0010
C1 (hostile cases, primed): {"AEGIS": {"decisions": {"ESCALATE": 10}, "containment_rejection_reasons": {"SHADOW": 20}}, "B7": {"decisions": {"ACT": 10}, "containment_rejection_reasons": {}}, "B7-nohyst": {"decisions": {"ACT": 10}, "containment_rejection_reasons": {}}}
C2 (hostile cases, primed): {"AEGIS": {"decisions": {"ESCALATE": 10}, "containment_rejection_reasons": {"SHADOW": 20}}, "B7": {"decisions": {"DEFER": 5, "ACT": 5}, "containment_rejection_reasons": {"HYSTERESIS": 5}}, "B7-nohyst": {"decisions": {"ACT": 10}, "containment_rejection_reasons": {}}}
C4 (hostile cases, primed): {"AEGIS": {"decisions": {"OBSERVE": 30}, "containment_rejection_reasons": {"NOT_IDENTIFIABLE": 60}}, "B7": {"decisions": {"OBSERVE": 30}, "containment_rejection_reasons": {"NOT_IDENTIFIABLE": 60}}, "B7-nohyst": {"decisions": {"OBSERVE": 30}, "containment_rejection_reasons": {"NOT_IDENTIFIABLE": 60}}}
loadavg before [2.05, 2.49, 2.71] after [2.04, 2.47, 2.71]
recorded PS-S5-20260926-BASE-b7-identifiability-0010 -> results/PS-S5-20260926-BASE-b7-identifiability-0010.json
```

### A.11 The gate, recorded run

```text
$ PYTHONHASHSEED=0 .venv/bin/python benchmarks/stage5/gate_record.py --record
GATE: FAILED (6) ['G5.4', 'G5.7', 'G5.9', 'G5.11', 'G5.12', 'G5.14']; wall 14.22 s; loadavg [3.05, 2.51, 2.8] -> [3.59, 2.64, 2.84]
recorded PS-S5-20260925-BASE-safe-gate-0001 -> results/PS-S5-20260925-BASE-safe-gate-0001.json
{"failed": ["G5.4", "G5.7", "G5.9", "G5.11", "G5.12", "G5.14"]}
```

### A.12 G5.9 feasibility on the gate's own seed (17)

```text
$ .venv/bin/python -c "from pocketsec.stage5.labs.response_corpus import build_ambiguous_pairs, BENIGN_MECHANISMS; p=build_ambiguous_pairs(count=30, seed=17); print('seed17 pairs', len(p), 'feasible-nonempty', sum(1 for b,h in p if h.truth.sufficient_operator_ids - b.truth.harmful_operator_ids), 'benign-leads', sum(1 for b,_ in p if max(b.resolution.hypotheses,key=lambda x:x['support'])['mechanism_id'] in BENIGN_MECHANISMS))"
seed17 pairs 30 feasible-nonempty 0 benign-leads 30
```

### A.13 Reproducing the integrator's baseline table and resource rows

```text
$ cat /proc/loadavg; /usr/bin/time -v env PYTHONHASHSEED=0 .venv/bin/python -m pocketsec.stage5.cli baselines
1.38 1.55 2.24 2/1520 418195
Baselines on build_response_corpus(count=20, seed=11), corpus 07fe384c7ece3b28754aec1cc798277c063922bd2046f7b870fc6a38a76cf795
(simulated host; collateral is defined by harm tables authored with the planner)

  arm     contained  missed  actions  collat/1000  work units  escalations  denials
  AEGIS           0      10       10          0.0        2700           10        0
  B1              0      10        0         None         360            0        0
  B2             10       0       10          0.0         380            0        0
  B3             10       0       20        500.0         400            0        0
  B4             10       0       20        500.0         400            0        0
  B5              0      10        0         None         360            0        0
  B6              0      10       10          0.0        2700           10        0
  B7              0      10       10          0.0         740           10        0
  B8              0      10       10          0.0        2700           10        0
  B9             10       0       20          0.0         410           20        0

  Pareto frontier: ['B1', 'B2', 'B5']
  saturation: not degenerate: best B2 contains 10 at 0.0000, median AEGIS contains 0 at 0.0000 on collateral_per_1000_at_equal_containment
  loadavg 1.38 1.55 2.24
	User time (seconds): 0.80
	Elapsed (wall clock) time (h:mm:ss or m:ss): 0:00.81
	Maximum resident set size (kbytes): 33400

$ PYTHONHASHSEED=0 .venv/bin/python -m pocketsec.stage5.cli resources
Stage 5 resources (Stage 0 ResourceSampler; process-wide peak is an upper bound)

  aegis_planning_state             9476 B
  normal_incremental_rss           167936 B
  peak_without_optional_lm         34586624 B
  rollback_evidence_hot_state      1503 B
  sentinel_and_executor            UNMEASURED
  simulation_workspace             UNMEASURED
  twin_dependency_state            1398 B

  incremental RSS 167936 B, peak 34586624 B, within_target None
  resources.measure_stage5_resources, full loop through the executor, over 20 cases, 34 candidates; unmeasured rows ['sentinel_and_executor', 'simulation_workspace']; stage0 sampler unavailable []
  loadavg (2.51, 2.7, 2.98)
```

### A.14 Preview and diagnostic runs

These scratch scripts preceded the recorded scripts above and were superseded by them; each
recorded script re-measured the same quantity, and the recorded values are the ones quoted
in Part I. Output lines are pasted as printed (long lines cut where marked).

```text
$ PYTHONHASHSEED=0 .venv/bin/python scratchpad/me/why_no_act.py        # -> shadow_gate.py
loadavg 1.15 1.49 2.19 2/1454 420438
== primed=False: plan decisions on 10 hostile cases {'ESCALATE': 10}
containment-candidate rejection reasons: {('RESTRICT_LOCAL_SOCKET', 'SHADOW'): 10, ('SUSPEND_PROCESS', 'SHADOW'): 10}
  RESTRICT_LOCAL_SOCKET: n=10 generation-time shadow [0.1667]  cone-informed shadow [0.3627]  rollback_reliability ['None']  ceiling 0.35
  SUSPEND_PROCESS: n=10 generation-time shadow [0.25]  cone-informed shadow [0.4146]  rollback_reliability ['None']  ceiling 0.35
== primed=True: plan decisions on 10 hostile cases {'ESCALATE': 10}
containment-candidate rejection reasons: {('RESTRICT_LOCAL_SOCKET', 'SHADOW'): 10, ('SUSPEND_PROCESS', 'SHADOW'): 10}
  RESTRICT_LOCAL_SOCKET: n=10 generation-time shadow [0.1667]  cone-informed shadow [0.3627]  rollback_reliability ['1.0']  ceiling 0.35
  SUSPEND_PROCESS: n=10 generation-time shadow [0.25]  cone-informed shadow [0.4146]  rollback_reliability ['1.0']  ceiling 0.35

$ PYTHONHASHSEED=0 .venv/bin/python scratchpad/me/shadow_and_feasibility.py   # -> shadow_gate.py, corpus_audit.py
loadavg 1.00 1.38 2.11 1/1429 422048
  pairs by |feasible operator set|: {0: 30} of 30 pairs
  pairs whose LEADING world is a benign mechanism: 30 of 30
  (benign_admin, phi) -> count: {(True, 4.0): 10, (False, 10.0): 10}
  B2 act/decline decision == not benign_admin on 20 of 20 cases
  Stage-4 leading world == truth.true_mechanism_id on 20 of 20 cases

$ PYTHONHASHSEED=0 .venv/bin/python scratchpad/me/stage4_seam.py        # -> benchmarks/stage5/stage4_seam.py
stage4 incidents 60, cpu_s 5.60
identifiability: {'UNKNOWN': 60}
lineage rows total: 3764 rows carrying any LINEAGE_TARGET_KEYS key: 0
candidates by operator over all exports: {}
AEGIS plan decisions on real exports: {'NO_ACTION': 60}

$ PYTHONHASHSEED=0 .venv/bin/python scratchpad/me/longlived.py 600       # -> longlived_bounds.py
== A_sweep_each: outcomes {'COMMITTED_VERIFIED': 82, 'REFUSED_JOURNAL_FULL': 518}
== B_never_sweep: outcomes {'COMMITTED_VERIFIED': 9, 'REFUSED_SENTINEL': 241, 'REFUSED_JOURNAL_FULL': 350}

$ PYTHONHASHSEED=0 .venv/bin/python scratchpad/me/unswept.py            # -> longlived_bounds.py part C
loadavg 9.32 3.53 2.68 10/1765 439337
regime B deny reasons over 60 actions: {'PRECONDITION': 58, 'FORBIDDEN_COMBINATION': 58}
committed containments 2; still in force on their host after clock passed every hard deadline with no sweep: 2
leases whose data says expired: 2 active: 0

$ PYTHONHASHSEED=0 .venv/bin/python scratchpad/me/c4_b7.py              # -> b7_identifiability.py
== C4 B7 primed, hostile halves: decisions {'OBSERVE': 30}
   reject 15 ('SUSPEND_PROCESS', 'NOT_IDENTIFIABLE', "SUSPEND_PROCESS causes unacceptable harm in ['admin_maintenance_window'], whose support exceeds RULED_OUT_SUPP")
== C2 B7 primed, hostile cases: decisions {'DEFER': 5, 'ACT': 5}
   reject 5 ('RESTRICT_LOCAL_SOCKET', 'HYSTERESIS', 'controller HOLD: dwell or cooldown not satisfied')
```

The scripts `arms.py`, `shadow_gate.py`, `ablation_primed.py`, `stage4_seam.py`,
`longlived_bounds.py`, `component_rss.py` and `hysteresis_isolated.py` were each also run once
without `--record` before recording; those runs printed the same counts as the recorded ones
(the CPU ratios differed within the load noise, e.g. cold AEGIS 3.4x vs 3.9x B2 on C1).

### A.15 Tests, lint, type check, ledger

```text
$ PYTHONHASHSEED=0 python3 -m pytest tests/test_stage5_counter_corpora.py tests/test_stage5_boundary.py -p no:cacheprovider --junitxml=…/cc.xml
45 passed in 1.75s
errors="0" failures="0" skipped="0" tests="45"

$ uvx ruff check pocketsec/stage5/labs/counter_corpora.py tests/test_stage5_counter_corpora.py
All checks passed!

$ uvx mypy --strict pocketsec/stage5/labs/counter_corpora.py 2>&1 | grep counter_corpora
(no output: no error in the new module; the run reports 96 errors in 32 other files, pre-existing)

$ uvx mypy --strict tests/test_stage5_counter_corpora.py 2>&1 | grep test_stage5_counter_corpora
tests/test_stage5_counter_corpora.py:9: error: Cannot find implementation or library stub for module named "pytest"  [import-not-found]

$ cat /proc/loadavg; PYTHONHASHSEED=0 python3 -m pytest -p no:cacheprovider --junitxml=…/suite.xml
1.20 2.18 2.60 3/1610 540183
…
GATE: FAILED (1)
=========================== short test summary info ============================
FAILED tests/test_stage1_pipeline.py::test_stage1_acceptance_gate_passes - As...
FAILED tests/test_stage1_pipeline.py::test_gate_cli_exits_zero - AssertionErr...
2 failed, 3006 passed in 732.07s (0:12:12)
(junit: total 3008, failed 2, skipped 0; test_stage5_* 911, failed 0, skipped 0.
 The two failures are Stage 1's gate criterion G1.12 — "peak RSS 118513664 B vs Edge
 target 104857600 B" — measured process-wide inside the full-suite process; not a Stage 5
 file, and the integrator recorded the same two.)

$ .venv/bin/python -c "…ExperimentRegistry(Path('experiments/registry.jsonl')).verify_integrity()…"   # before appending
entries 31 problems []
$ (same, after appending the ten Stage 5 rows)
entries 41 problems []
['PS-S5-20260925-BASE-safe-gate-0001', 'PS-S5-20260926-BASE-arms-counter-corpora-0002', 'PS-S5-20260926-BASE-corpus-audit-0003', 'PS-S5-20260926-BASE-shadow-gate-0004', 'PS-S5-20260926-BASE-ablation-primed-0005', 'PS-S5-20260926-BASE-stage4-seam-0006', 'PS-S5-20260926-BASE-longlived-bounds-0007', 'PS-S5-20260926-BASE-component-rss-0008', 'PS-S5-20260926-BASE-hysteresis-isolated-0009', 'PS-S5-20260926-BASE-b7-identifiability-0010']
```
