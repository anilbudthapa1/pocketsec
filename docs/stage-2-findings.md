# Stage 2 — DTL completion findings (D2.6–D2.15)

**Status:** measurement wave complete. **Stage 2 acceptance gate: FAILED (7 of 13).**
**Every number in this document was produced by running code in this session.**

- **Host:** Linux 7.1.5+kali-amd64, Python 3.14.7, 8 cores, numpy 2.4.6.
- **Repository state:** working tree at `/home/anil/Documents/Research/pocketsec`.
- **Corpora:** all synthetic. `synthetic_data=True` travels with every dataset provenance
  block quoted below. **Nothing here is a detection result.**
- **Load warning.** Another project was building on this host for most of this session
  (measured load average 13–21 on 8 cores). PR-AUC, log-loss, Brier and byte counts are
  deterministic and unaffected. **Every wall-clock µs/event figure below carries the load
  average it was taken under, and only ratios within a single run transfer.** This is the
  rule `planning/MEMORY.md` already records after a 7× inflation between two passes of the
  same gate.

---

## 0. The one-paragraph answer

Stage 2's central claim — *detection emerges from prediction, repeated understanding
condenses into discrete reusable structure, and computation becomes proportional to
novelty* — **is not supported by these numbers**, and this wave produced the first
evidence in the repository that is capable of refuting it rather than merely failing to
support it. On the only non-degenerate split that exists (`ambiguous` count=240), a full
eleven-component ablation returns **zero JUSTIFIED learned mechanisms**: five REJECTED,
four NOT-YET-JUSTIFIED, one UNMEASURABLE, and the three JUSTIFIED rows are two safety
gates measured against a null control plus one mechanism that an already-accepted ADR
rejects. Criterion 1 does change on that split — the Stage 2 core is no longer dominated
by the zero-parameter Φ-oracle — but it changes in a way that helps the **TCN**, not the
DTL, and the latent frontier is flat at PR-AUC 1.0000 from its smallest configuration
upward, so the win comes with no headroom in which any component could earn its place.

---

## 1. What was measured, and the commands

### 1.1 Test suite and gate reproduction

```
cd /home/anil/Documents/Research/pocketsec && python3 -m pytest -q ; echo "EXIT=$?"
```
```
EXIT=0
```
**755 tests collected across 22 files, all passing**, at the start of this session.

**A concurrent session began writing Stage 3 into this working tree while this wave ran.**
`pocketsec/stage3/` was created at 05:29–06:09 and the collected total grew from 755 to
**1177**. A final suite run at the end of the session reports two failures, **both in
`tests/test_stage3_boundary.py`**:

```
FAILED tests/test_stage3_boundary.py::test_no_stage3_dataclass_field_names_response_authority
FAILED tests/test_stage3_boundary.py::test_every_stage3_module_parses_and_declares_future_annotations
```

**No Stage 0, Stage 1 or Stage 2 test fails.** This wave created no file under
`pocketsec/stage3/` or `tests/test_stage3*`, and touched no other session's work; per the
`planning/MEMORY.md` parallel-session protocol these are reported, not fixed. They are also
the likeliest source of the host load recorded throughout this document.

```
cd /home/anil/Documents/Research/pocketsec
echo "LOAD BEFORE: $(cat /proc/loadavg)"
/usr/bin/time -v python3 -m pocketsec.stage2.cli gate
```
```
LOAD BEFORE: 1.67 2.89 4.54 1/2544 1895300
EXIT=1
LOAD AFTER: 1.37 2.60 4.35 1/2594 1898295
...
GATE: FAILED (7)
```

**Superseded by the defect-repair wave: `GATE: FAILED (9)`.** G2.6 and G2.10 moved
from PASS to FAIL when the things they were passing on were checked — see §2.0,
ADR-0124 and ADR-0125. Neither is a regression in the stage; both are criteria
that had never been evaluated against a measurement.
```
	User time (seconds): 57.39
	System time (seconds): 0.08
	Percent of CPU this job got: 99%
	Elapsed (wall clock) time (h:mm:ss or m:ss): 0:57.49
	Maximum resident set size (kbytes): 80304
```

**Gate result reproduced exactly as `planning/PROGRESS.md` records it: FAILED (7 of 13),
exit 1**, on `ambiguous` count=60, train seed=3, eval seed=11.

| criterion | result | deciding figure (this session) |
|---|---|---|
| G2.1 baselines / not dominated | **FAIL** | 9 baselines above base rate 0.3333; phi-oracle 1.0000 @ 0.1 µs/event dominates mlp-pooled and tcn, both also 1.0000 |
| G2.2 latent frontier | **FAIL** | degenerate, `ORDER_FREE_BASELINE_TIES_BEST`; no knee recorded |
| G2.3 selective routing | **FAIL** | policy proposes a cheap path for 0.6301 of events; the ledger proves `CORE_INFERENCE` skipped for 0.9966 and P3/P4 work performed for 0.0034. The derived-cheap-path figure of **0.0000** is a structural floor of the harness, not a measurement — see §2.0 |
| G2.4 behaviour atoms | PASS (REJECTED branch) | learned log-loss 3.472387 @ 249856 B vs hash 1.683493 @ 3136 B |
| G2.5 calibration | **FAIL** | held-out Brier exactly 0.0 — perfect separability, the saturation G2.2 refuses the corpus for. Conformal coverage is 0.9167 vs nominal 0.9 ±0.05 and now **passes**; the previous 0.9793 was the eviction policy, not the predictor (ADR-0128) |
| G2.6 cone / hazard | **FAIL** | cone Brier 1.566994 **beats** marginal 1.850148, so this run does not reproduce the rejection; hazard 0.117936 vs constant 0.078202 does. Flags off + an ADR filename is no longer sufficient (ADR-0125) |
| G2.7 causal credit | **FAIL** | spine inspects 5.0 nodes at chain recall 0.3611 vs naive 19.75 at 1.0. The previous "attributed nothing" was a dict join that could never match, not a measurement (S2-FC-01) |
| G2.8 drift | PASS | recover 3, invalidated 2, normalised 0, 21 promotions; control normalises 377 |
| G2.9 poisoning | PASS | 18 promotions, 0 escalating, 0 from a poison lineage; control 244 escalating |
| G2.10 sleeping brain | **FAIL** | 4082/4096 cache-resolved (0.9966) and the compute really was avoided — but only **0.0127** of those hits served the answer the deep path computed for the same event (4030 of 4082 disagreed). See §2.0 and ADR-0124 |
| G2.11 resources | PASS | peak sampled RSS 70275072 B; incremental 4411392 B under the 83886080 B ceiling |
| G2.12 ablation support | **FAIL** | see §4 — the registry clause is now closed, the degeneracy clause is not |
| G2.13 Stage 3 export | **FAIL** | exporter refuses the candidate: `distinct_epochs 1 < 2` |

Note G2.10's µs/event: **135.90 / 181.67** in the defect-repair wave against
**103.66 / 403.48** and **122.48 / 647.23** recorded previously. These are NOT
comparable with each other. Two things changed besides host load: the cone is no
longer expanded when `FUTURE_CONE_DEFAULT_ENABLED` is false (ADR-0125), which
removes work from the deep path, and the control pass now also checks each
would-be hit's answer against the deep path's. Only a ratio taken within one run
is transferable, and this run's is 1.34×.

### 2.0 Two criteria moved from PASS to FAIL, and neither is a regression

The defect-repair wave took the gate from 7 failures to 9. Both new failures are
criteria that were passing on a number nobody had checked:

- **G2.10** (ADR-0124). The 0.9966 skipped fraction measured *key repetition*.
  The P0 key carries no lineage and the stored payload is the first inserting
  lineage's own state snapshot, so a hit serves another lineage's numbers —
  measured this session, **0.0127** answer agreement over 4,082 would-be hits.
  The compute was avoided; the answer changed. Counting that as sleep is
  ADR-0010's notional accounting one layer down.
- **G2.6** (ADR-0125). Its removal branch was `removed and bool(adr)` — two
  hardcoded flags and a `docs/adr/*.md` **filename** containing "future-cone" and
  "rejected", with an empty file of that name sufficient. The two measurements it
  paid for were computed and discarded. It now requires the rejection to be
  reproduced, and on this split the cone **beats** its control (1.566994 vs
  1.850148), so it is not.

Two more headline figures were false rather than merely unflattering:

- **G2.3's "the ledger derives a cheap path for 0.0000 of events"** is identically
  0.0 for every possible input. `runtime_pass` performs a mandatory
  `WINDOW_UPDATE` on every event before the cache is consulted, that derives
  `P2_LOCAL` (8.0 units), and a path is the max over performed work — so no event
  can derive P0/P1 however well the cache performs. Verified by a second pass over
  an already-warm cache: 464/464 events resolved from the cache, cone and
  inference genuinely skipped, derived cheap fraction still 0.0000. The criterion
  could not distinguish a working router from a broken one. It now reports the
  ledger-proven skipped-inference fraction (0.9966) and the performed P3/P4
  fraction (0.0034) instead, and states the floor. G2.3's FAIL verdict was and
  remains independently correct: `ROUTER_DEFAULT_ENABLED` is False on a separately
  measured −0.115 PR-AUC at 3.4× the time.
- **G2.7's "the credit spine attributed NOTHING"** and its stated cause ("no
  probe's divergence reached `MATERIAL_DIVERGENCE`") were artefacts of a
  dictionary join that can never match: `nodes` was keyed by
  `CausalNode.signature` (16 hex) and looked up by `probe.target_signature`, a
  positional locator `lineage:index:rN:mM` whose own docstring calls it
  "provenance for the probe itself, never an identity the ledger trusts".
  `assign_causal_credit` was never called once. 20 of 136 probes on the drift
  corpus were material and none was ever offered to the ledger. Re-measured with
  the join on the real causal signature: **5.0 nodes inspected at chain recall
  0.3611** against naive ancestry's 19.75 at 1.0. Still FAIL — concision bought
  with recall does not meet the criterion — but now measured. Registry entry
  `PS-S2-20260924-H8-causal-credit-0016` is retracted by
  `PS-S2-20260925-H8-causal-credit-retraction-0022`; the re-measured report row is
  REJECTED at −0.6482, not −1.0.

### 1.2 The saturation sweep — the load-bearing new measurement

`planning/MEMORY.md` and ADR-0120 both assert that every available corpus is degenerate.
**That assertion is false in exactly one cell, and this is the first run of
`saturation_check` across the full corpus × size grid.**

```
PYTHONPATH=/home/anil/Documents/Research/pocketsec PYTHONHASHSEED=0 python3 sweep.py sweep.json
```
(script: `saturation_check(build_dataset(...seed=3), build_dataset(...seed=11))` for each cell;
`pocketsec.stage2.research.saturation:saturation_check`)

| corpus | count | base | best | median | spread | order-free | Φ-oracle | degenerate | reason |
|---|---|---|---|---|---|---|---|---|---|
| ambiguous | 60 | 0.3333 | 1.0000 | 0.6586 | 0.3414 | 1.0000 | 1.0000 | True | ORDER_FREE_BASELINE_TIES_BEST |
| ambiguous | 120 | 0.3333 | 1.0000 | 0.8475 | 0.1525 | 1.0000 | 0.8495 | True | ORDER_FREE_BASELINE_TIES_BEST |
| **ambiguous** | **240** | **0.3333** | **1.0000** | **0.9125** | **0.0875** | **0.9125** | **0.5975** | **False** | **INFORMATIVE** |
| hard | 60 | 0.4000 | 0.9902 | 0.9839 | 0.0064 | 0.9902 | 0.7600 | True | DEGENERATE_SPREAD |
| hard | 120 | 0.3667 | 0.9970 | 0.9950 | 0.0020 | 0.9970 | 0.8017 | True | DEGENERATE_SPREAD |
| hard | 240 | 0.3500 | 0.9992 | 0.9986 | 0.0006 | 0.9992 | 0.8436 | True | DEGENERATE_SPREAD |
| long | 60 | 0.3333 | 1.0000 | 0.3454 | 0.6546 | 0.5629 | 0.3226 | True | BASELINE_BELOW_BASE_RATE |
| long | 120 | 0.3333 | 1.0000 | 0.3333 | 0.6667 | 0.3333 | 0.3121 | True | BASELINE_BELOW_BASE_RATE |
| long | 240 | 0.3333 | 1.0000 | 0.3361 | 0.6639 | 0.3361 | 0.3172 | True | BASELINE_BELOW_BASE_RATE |

**Eight of nine splits are degenerate. `ambiguous` count=240 is not.** The selection rule
is not mine and is not outcome-driven: `saturation_check`'s four conditions and their
thresholds (0.01, 0.02) were fixed in code by ADR-0120 before this measurement, and are
pinned by `tests/test_stage2_report.py::test_every_degeneracy_condition_is_enforced_at_its_stated_threshold`.
Using the only cell that guard admits is not cherry-picking. **Reporting it without §3.2's
caveat would be.**

### 1.3 The cost frontier on the non-degenerate split

```
PYTHONPATH=... PYTHONHASHSEED=0 python3 frontier240.py 240 frontier240.json
```
(`pocketsec.stage2.research.cli:measure_frontier`, wall 142.4 s, load average 1.73)

```json
"pareto": {
  "best_quality": 1.0,
  "cheapest_at_best_quality": "tcn",
  "cheapest_microseconds_per_event": 5.19,
  "dominated": [],
  "tied_at_best_quality": ["tcn"],
  "verdict": "tcn detects as well as anything measured (1.0000) at 5.2 us/event, ..."
}
```

**`dominated: []`.** At count=240 the Φ-oracle falls to 0.5975 and stops tying, so it stops
dominating. **This is the only measurement in this wave that changes criterion 1's answer**
— and §3.1 sets out precisely how much it is worth.

The same frontier re-measured inside the full D2.14 report, which additionally admits
`dtl-conv` (it needs 64 padded steps; at count=240 the longest sequence is 93):

| model | PR-AUC | µs/event | parameters |
|---|---|---|---|
| **tcn** | **1.0000** | **15.91** | 6,961 |
| dtl-conv | 1.0000 | (dominated by tcn) | 19,851 |
| mlp-pooled | 0.9125 | 8.85 | 4,657 |
| phi-oracle | 0.5975 | 0.16 | **0** |

`"dominated": [{"name": "dtl-conv", "dominated_by": ["tcn"]}]` — **ADR-0010's central
finding survives at count=240. DTL-C is still dominated by a plain TCN.** (load average
13–21; ratios only.)

---

## 2. The component ablation — the first one taken with headroom

```
PYTHONPATH=... PYTHONHASHSEED=0 python3 -m pocketsec.stage2.research.cli --json report --count 240
```
`ambiguous`, count=240, train seed=3, test seed=11, encoder `dtl-encoder.1.0.0`,
17,595 train / 17,898 test transitions, base rate 0.3333, `synthetic_data: true`.
Wall clock ≈ 68 min at load average 11–21. Saturation verdict inside the report:
`degenerate: false, reason: INFORMATIVE`, so **no row was refused** — this is the first
Stage 2 report in the repository whose component rows are measured rather than
`UNMEASURABLE`.

| verdict | component | metric | with | without | delta | control |
|---|---|---|---|---|---|---|
| **REJECTED** | behaviour_atom_quantizer | transition_log_loss | 3.5881 | 1.8460 | **−1.7420** | HashBucketQuantizer |
| **REJECTED** | transition_lattice | next_family_top1 | 0.4367 | 0.4926 | **−0.0558** | relation_family_bigram |
| **UNMEASURABLE** | merge_fission | log_loss_per_kib | — | — | — | max_macro=0 (0 merges: both arms built the same lattice) |
| JUSTIFIED | future_cone | branch_brier | 1.5548 | 1.8660 | +0.3112 | marginal_cone |
| **REJECTED** | hazard_heads | hazard_brier | 0.1631 | 0.0768 | **−0.0862** | constant_hazard |
| **REJECTED** | uncertainty | expected_calibration_error | 0.5904 | 0.5739 | **−0.0165** | one_minus_max |
| **REJECTED** | multiscale_window | next_family_top1 | 0.5912 | 0.7099 | **−0.1187** | window=1 (re-measured per lineage, ADR-0126) |
| NOT_YET_JUSTIFIED | transition_cache | hit_rate | 0.013465 | 0.013465 | 0.0000 | lru_control (re-measured: 312 evictions per policy) |
| NOT_YET_JUSTIFIED | utility_forgetting | hit_rate | 0.013465 | 0.013465 | 0.0000 | lru_control/random_control (random 0.0) |
| JUSTIFIED | epoch_guard | malicious_patterns_normalised | 0.0000 | 377.0000 | +377 | accept_everything |
| JUSTIFIED | quarantine_promotion | poisoned_promotions | 0.0000 | 64.0000 | +64 | accept_everything |
| **REJECTED** | causal_credit | chain_recall | 0.3518 | 1.0000 | **−0.6482** | naive_ancestry (re-measured, S2-FC-01) |
| UNMEASURABLE | compile_candidate_export | microseconds_per_event | None | None | None | phi_oracle |

**Three rows in the table above were corrected by the defect-repair wave, and the
corrections are retractions in the append-only ledger rather than edits.**
`merge_fission` and `transition_cache` were arithmetic identities, not measurements:
`keep` was computed as a quarter of the held-out *lookup* count (4,474) while the cache
held 416 entries, so `_require_keep` returned surplus 0 and all three eviction policies
took their early exit and evicted nothing — the two arms were bit-identical floats. With
`keep` taken from the cache's own occupancy (416 entries, keep=104) each policy evicts 312
keys and the row is a real null. `merge_fission` compared `max_macro=64` against
`max_macro=0` after **0 merges**, so both arms built the same lattice; it is now
UNMEASURABLE. Retractions: `PS-S2-20260925-H8-merge-fission-retraction-0020`,
`PS-S2-20260925-H8-transition-cache-retraction-0021`,
`PS-S2-20260925-H8-multiscale-window-retraction-0023`,
`PS-S2-20260925-H8-causal-credit-retraction-0022`.

**Read this table carefully, because its shape matters more than any single row.**

- **Not one learned predictive mechanism is JUSTIFIED.** The two unambiguous JUSTIFIED rows
  — `epoch_guard` and `quarantine_promotion` — are safety machinery measured against
  `accept_everything`, a null control. They establish that a gate which refuses things
  refuses things. They are not evidence that Stage 2 learns.
- **Three rows are newly REJECTED by this wave, not by a prior ADR.**
  - `transition_lattice` **loses to an order-1 bigram** over `relation_family`
    (0.4367 vs 0.4926). The Dynamic Transition Lattice — the structure the stage is named
    after — predicts the next relation family *worse than counting pairs*.
  - `uncertainty` is **worse-calibrated than `1 − max p`** (ECE 0.5904 vs 0.5739). D2.9's
    calibrated-uncertainty module does not beat the one-line control.
  - `multiscale_window` is **−0.1187 against a window of one** (0.5912 vs 0.7099). The
    +0.0002 previously recorded here did not measure `WindowStore` at all: relation
    families were grouped by **session** while the store keys on the causal-signature
    root, and replacing the store with a stub that held nothing returned bit-identical
    accuracies. Re-measured per lineage (3,576 lineages of mean length 5.0 against 240
    sessions of mean length 73.3), the store's extra taps are a measured **loss**. See
    ADR-0126, which also records what acting on this costs: truncating every window to
    its last step drops the exported Φ-oracle candidate from average precision 0.5975
    to 0.3243.
- Three rows reproduce existing ADRs on the informative split: `behaviour_atom_quantizer`
  (ADR-0115), `hazard_heads` (ADR-0116), `causal_credit` (ADR-0122).

### 2.1 The one JUSTIFIED learned row does not survive inspection

`future_cone` scores +0.3112 branch Brier against `marginal_cone`. The comparison **is**
like-for-like: `research/stage2_report.py:measure_future_cone` scores both at `max_depth=1`
against the same `branch_label` truth with the same `multiclass_brier`.

But `multiclass_brier` has a maximum of 2.0, and **both predictors sit near that maximum**
(1.5548 and 1.8660). Measured this session on the same split:

```
contexts scored              4000
mean cone unresolved mass    0.646407
cone argmax is UNKNOWN       0/4000 = 0.0000
```
(`predict_future_cone(..., max_depth=1)` + `gate_measures:cone_distribution` over
`ambiguous` count=240 seed=11, lattice trained on seed=3)

The cone holds **64.6% of its probability mass on `UNKNOWN`**, a label that is never the
observed outcome, while still always naming a concrete branch as its argmax. Its Brier
advantage is the advantage of being *less confidently wrong* than a control that is more
confidently wrong. **That is not calibration value, and it does not overturn ADR-0116.**
`FUTURE_CONE_DEFAULT_ENABLED = False` remains correct, and the mechanism is default-off, so
this measured delta cannot reach any verdict, score or compile candidate.

### 2.2 The latent frontier is flat, which is the real verdict on G2.2

`latent_frontier`, dimensions 12 → 96:

| latent | 12 | 16 | 24 | 32 | 48 | 64 | 96 |
|---|---|---|---|---|---|---|---|
| PR-AUC | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| parameters | 5,055 | 6,699 | 9,987 | 13,275 | 19,851 | 26,427 | 39,579 |

`"knee": {"latent": 12, "pr_auc": 1.0}` — the knee is the **smallest dimension tried**.

**This is the finding that qualifies everything in §1.3.** `saturation_check` asks whether a
split can rank *architecture families*, and at count=240 it can (Φ-oracle 0.5975, markov
0.4023, vq-prototype 0.3526, mlp-pooled 0.9125, gru/tcn 1.0000). It does **not** ask whether
the split leaves headroom above the winner, and here it does not: the Stage 2 core is
already perfect at its smallest configuration. So a corpus can be INFORMATIVE by the
guard's four conditions and still be useless for justifying any refinement of the winning
model — which is exactly what the `multiscale_window` +0.0002 row shows happening.

**Recommendation:** `saturation_check` should gain a fifth condition — *best == ceiling with
no descent across the frontier* — so that a flat frontier is refused as loudly as a tie
with an order-free baseline. This wave measured the need for it; implementing it belongs to
the `report` package, not to a measurement pass.

---

## 3. What this does and does not do to acceptance criterion 1

### 3.1 It changes the answer on one split

The project lead's instruction was explicit: *the gate must FAIL on criterion 1 unless this
wave measures something that genuinely changes it.* Something did. At `ambiguous` count=240
the cost frontier reports `dominated: []` and the Stage 2 core (tcn, 1.0000 @ 5.19 µs/event
standalone, 15.91 µs/event inside the report) is not beaten on cost by the zero-parameter
Φ-oracle, which falls to 0.5975.

### 3.2 It should not be used to pass the gate, and here is why

1. **The gate measures at count=60 and count=60 is degenerate.** `GATE_COUNT` is a frozen
   constant and `gate.py` **refuses frontier evidence whose `(corpus, count, seed)` differs
   from the split the gate itself ran** — by design, and correctly. Changing `GATE_COUNT` to
   240 is an integrator decision with an ADR attached, not a measurement result, and it
   would make an ~68-minute report a gate precondition.
2. **Criterion 1 asks whether the *DTL* beats the best baseline. It does not.** The model
   that is undominated at count=240 is the **TCN**, and `dtl-conv` is explicitly
   `dominated_by: ["tcn"]` in the same run. ADR-0010 is untouched.
3. **The frontier is flat at 1.0000 (§2.2).** "Not dominated" here means "saturates the
   metric at 5,055 parameters", not "extracts more signal".
4. **The shipped pareto times three of nine models.** `TIMED_MODELS = ("phi-oracle",
   "mlp-pooled", "tcn")`. `gru` also reaches 1.0000 at count=240 and **was never timed**, so
   whether `gru` dominates `tcn` on cost is **UNMEASURED**. `dominated: []` is a claim about
   three models, not nine. I attempted the all-nine timing and abandoned it at 12 minutes
   per seed under load 15–18; see UNMEASURED.
5. **Seed robustness** — see §3.3.

**Conclusion: criterion 1 remains UNMET, and the gate is right to fail it.** What changed is
the *reason*: it is no longer "a zero-parameter scorer dominates the learned core" but
"the learned core that is undominated is the one ADR-0010 already accepted, on a split where
nothing has headroom".

### 3.3 Seed robustness of the INFORMATIVE verdict

```
PYTHONPATH=... PYTHONHASHSEED=0 python3 seeds240.py seeds240.json
```
(`saturation_check` at `ambiguous` count=240, train seed=3, eval seeds 11/17/23/29)

| eval seed | degenerate | reason | best | median | spread | order-free | Φ-oracle | markov-bigram | wall s | load |
|---|---|---|---|---|---|---|---|---|---|---|
| 11 | **False** | INFORMATIVE | 1.0000 | 0.9125 | 0.0875 | 0.9125 | 0.5975 | 0.4023 | 144.7 | 1.8 |
| 17 | **False** | INFORMATIVE | 1.0000 | 0.9394 | 0.0606 | 0.9394 | 0.5904 | 0.4039 | 471.4 | 16.8 |
| 23 | **True** | BASELINE_BELOW_BASE_RATE | 1.0000 | 0.9229 | 0.0771 | 0.9229 | 0.5945 | **0.3307** | 854.6 | 37.8 |
| 29 | **False** | INFORMATIVE | 1.0000 | 0.9424 | 0.0576 | 0.9107 | 0.5886 | 0.4080 | 1354.7 | 14.9 |

**Three of four eval seeds are INFORMATIVE.** Seed 23 is refused on condition 4 — a baseline
below the base rate — and it fails by **0.0026** (`markov-bigram` 0.3307 against a base rate
of 0.3333). That is the guard doing its job strictly, not a different corpus.

The facts §3.1 rests on are stable across **all four** seeds:

- `gru` and `tcn` both score **exactly 1.0000 in every seed**. The ceiling tie is not a
  seed artefact, which reinforces §2.2: there is never headroom above the winner.
- The Φ-oracle sits in **0.5886 – 0.5975**, a range of 0.0089. Its collapse from 1.0000 at
  count=60 to ≈0.59 at count=240 is robust, and so is "it no longer ties, so it no longer
  dominates".
- The order-free control stays clearly below best in every seed (0.9107 – 0.9394), well
  outside the 0.02 tolerance.
- Spread is 0.0576 – 0.0875, always above the 0.01 threshold.

**Verdict: the INFORMATIVE classification is seed-sensitive (3/4); the measurements that
matter for §3.1 are not (4/4).**

This table also quantifies the load warning in the header. The same deterministic work took
**144.7 s and 1354.7 s** — a **9.4× spread** — across load averages 1.8 to 37.8, while
returning scores that differ only in the corpus draw. No wall-clock figure in this document
should be compared against one taken in another session.

---

## 4. Ablation support, and what registering it did

Before this session, `experiments/registry.jsonl` held **6** Stage 2 entries, highest
sequence `0006`, **none** from the completion wave — verified directly:

```
python3 -c "import json; [print(json.loads(l)['experiment_id']) for l in open('experiments/registry.jsonl')]"
```

The eleven component verdicts measured in §2 were appended to the append-only,
digest-chained ledger, replicating `research/cli.py:_register` exactly (same fields, same
skip rules — a verdict with no delta is skipped, not recorded as though measured):

```
REGISTERED 11
  PS-S2-20260924-H8-behaviour-atom-quantizer-0007
  PS-S2-20260924-H8-transition-lattice-0008
  PS-S2-20260924-H8-merge-fission-0009
  PS-S2-20260924-H8-future-cone-0010
  PS-S2-20260924-H8-hazard-heads-0011
  PS-S2-20260924-H8-uncertainty-0012
  PS-S2-20260924-H8-multiscale-window-0013
  PS-S2-20260924-H8-transition-cache-0014
  PS-S2-20260924-H8-causal-credit-0016
  PS-S2-20260924-H8-epoch-guard-0017
  PS-S2-20260924-H8-quarantine-promotion-0018
```
```
verify_integrity -> []      # digest chain intact, 20 entries
```

Re-running the gate afterwards:

```
GATE: FAILED (7)      # at the time; GATE: FAILED (9) after the defect-repair wave
```

G2.12 still fails.

**But the criterion those eleven rows were registered against was a bare row count, and the
defect-repair wave replaced it.** `passed` was `len(this_wave) >= len(optional)` — two
integers, with nothing joining a registered experiment to a component and nothing reading
what any of them measured. Appending twelve rows about *anything* — twelve reruns of one
ablation, or twelve about components already REJECTED — flipped it to PASS with every
OPTIONAL core id exactly as unjustified as before, and the append-only digest chain does not
prevent that because appending is a supported operation. Demonstrated by execution
(S2-AUTH-09): one well-formed row about an already-rejected component flipped the criterion,
with `verify_integrity()` returning no problems. The sentence *"the registry clause is
closed"* above was therefore true of a check that checked nothing.

G2.12 now joins `slot_name` to a core id through `core_ids.ABLATION_SLOTS` and reads each
row's recorded verdict. Measured this session: **1 of 12 OPTIONAL core ids carries a
registered JUSTIFIED ablation** (DTL-F05, from `future_cone-0010`). The eleven without one
are named in the gate output: DTL-F04, DTL-F08, DTL-F09, DTL-F10, DTL-F11, DTL-F12,
DTL-F13, DTL-F14, DTL-F15, DTL-F16, DTL-F17. Two of those — **DTL-F09**
(`score_prediction_residual`) and **DTL-F12** (`request_observation_escalation`) — have no
ablation slot in the report at all: nothing measures them, in either direction.

The degeneracy clause the detail string already called independent is now also evaluated,
which it previously was not (S2-FC-02). **Registering real measurements did not and must not
make the gate pass, and appending unreal ones no longer can.**

### 4.1 A defect found while registering: two components share one experiment id

Eleven verdicts were registered, not twelve. `utility_forgetting` (DTL-F15) and
`transition_cache` (DTL-F16) are separate `ComponentVerdict` rows with separate controls
and separate details, but both carry `"experiment_id": "PS-S2-20260924-H8-transition-cache-0014"`:

```json
{"component": "transition_cache",    "core_ids": ["DTL-F16"], "control": "lru_control",
 "experiment_id": "PS-S2-20260924-H8-transition-cache-0014", "delta": 0.0}
{"component": "utility_forgetting",  "core_ids": ["DTL-F15"], "control": "lru_control/random_control",
 "experiment_id": "PS-S2-20260924-H8-transition-cache-0014", "delta": 0.0}
```

`_register`'s duplicate guard therefore drops the second silently. `provenance.experiment_ids`
does mint a distinct `...-utility-forgetting-0015`, so the id exists and the verdict does not
use it. **DTL-F15 has no ledger entry, and G2.12 reads the ledger.** This is a defect in
`research/stage2_report.py:measure_cache_and_forgetting`, not in the registry; it is reported
here rather than patched, because changing a `report`-owned module is not a measurement.

Separately, `compile_candidate_export` is `UNMEASURABLE` for an interesting reason that is
the mirror image of the count=60 result:

> `"no learned candidate matched the Φ-oracle's PR-AUC (0.5975) within 0.01, so there is no
> equal-quality cost comparison to make"`

At count=60 every learned candidate *tied* the Φ-oracle and lost on cost. At count=240 they
*beat* it by 0.4025, so the equal-quality comparison the metric is defined on does not exist.
Neither split answers "does any neural candidate beat the Φ-oracle on µs/event at equal
PR-AUC". That question remains **UNMEASURED**.

---

## 5. Resource cost, and a discrepancy worth naming

Two measurements of the same runtime path, and they disagree about the Edge envelope.

| | stdlib gate path (`stage2/cli.py resources`) | inside the numpy research process (`report`) |
|---|---|---|
| events | 4,096 | 4,096 |
| peak sampled RSS | **70,275,072 B (67.0 MB)** | **1,436,262,400 B (1369.7 MB)** |
| incremental RSS | 4,411,392 B | 274,432 B |
| incremental ceiling | 83,886,080 B | 83,886,080 B |
| within incremental ceiling | **True** | **True** |
| Edge profile `within_target` | **True** | **False** — `"agent_rss 1369.7 MB > 100 MB target"` |
| CPU s/event | 0.000688 | 0.00182 |
| model bytes | 1,102,420 | 1,102,420 |

Both are honest and they measure different things. `ResourceSampler` samples the **whole
process**, so in the research process it is measuring numpy plus two 240-session compiled
corpora, not Stage 2's runtime footprint. The Edge claim belongs to the stdlib column; the
1369.7 MB figure is the cost of *measuring*, which ADR-0008 explicitly permits to be heavy.

**But the report publishes `within_target: false` with no such distinction, and a reader
quoting the D2.14 report alone would conclude Stage 2 breaches the Edge envelope by 13×.**
The honest number for the deployed path is **67.0 MB peak / 4.4 MB incremental**, and the
comparable figure is a *target comparison on this development host, not a measurement on a
2 GB device*.

### 5.1 `PATH_COST_UNITS` is not merely uncalibrated — it is inverted

`path_cost` block, 4,096 events, this session:

| WorkKind | measured µs | measured relative | declared `PATH_COST_UNITS` |
|---|---|---|---|
| CACHE_LOOKUP | 31.187 | 1.00 | P0 1.0 |
| CORE_INFERENCE | 32.849 | **1.05** | P3 40.0 |
| CONE_EXPANSION | 48.707 | 1.56 | — |
| WINDOW_UPDATE | 75.240 | 2.41 | — |
| LATTICE_LOOKUP | **790.895** | **25.36** | P1 2.0 |

`"declared_status": "UNMEASURED"`. The "expensive" deep inference costs **1.05×** a cache
lookup; the lattice lookup the ladder prices at 2.0 costs **25.36×** and is 79% of the
per-event budget. ADR-0120 measured this ratio at 11.94×; this session measures **25.36×**
at count=240. Every `compute_units_per_event` remains a policy simulation, and the honest
cost number is wall-clock µs/event (1691.45 here, at load 13–21 — ratio-only).

---

## 6. Bounds under flood and adversarial load

### 6.1 Repeat flood — 50,000 events

```
PYTHONPATH=... PYTHONHASHSEED=0 python3 flood.py 50000 flood.json
```
Drives the real runtime path (`gate_measures:runtime_pass`) over `ambiguous` count=240
(17,898 distinct source transitions) replayed to 50,000 events.

| events | atoms | quantizer B | lattice B | cache entries | cache B | window lineages | window B | ledger retained | process peak RSS |
|---|---|---|---|---|---|---|---|---|---|
| 5,000 | 256 | 249,856 | 197,328 | 288 | 91,920 | 22 | 1,159,884 | 4,096 | 89,251,840 |
| 15,000 | 256 | 249,856 | 286,440 | 371 | 115,650 | 43 | 3,143,030 | 4,096 | 89,251,840 |
| 30,000 | 256 | 249,856 | 306,192 | 414 | 127,932 | 57 | 3,666,994 | 4,096 | 89,251,840 |
| 50,000 | **256** | **249,856** | **307,688** | **417** | **128,814** | **57** | 4,073,112 | **4,096** | **89,251,840** |

- **Atoms pin at MAX_ATOMS = 256** from event 5,000 and never move. Quantizer bytes flat at
  249,856 B across a 10× increase in events. **Bounded.**
- **Lattice bytes plateau** at 307,688 B (identical at 40k, 45k, 50k). **Bounded.**
- **Ledger retains 4,096 = MAX_LEDGER_EVENTS with `truncated: true`.** Bounded, and the
  truncation is reported rather than hidden.
- **Process peak RSS is constant at 89,251,840 B (85.1 MB) from 5,000 to 50,000 events.**
- Window bytes still creep at 50,000 (4,073,112 B) but stay under the structure's own
  declared `memory_bound_bytes` of 6,719,488 B, and the growth rate is decaying
  (+2.4% per 5,000-event chunk at the end).

### 6.2 Adversarial variant — and the bound that could not be exercised

```
PYTHONPATH=... PYTHONHASHSEED=0 python3 flood2.py flood2.json
```
Eight independent compiles (seeds 11–43) concatenated, 35,332 events, to maximise distinct
lineage identities.

**It did not work, and the failure is the finding.** Across 8 seeds × 60 sessions the
`WindowStore` held **16 lineages**, against `MAX_LINEAGES = 64`:

| events | window lineages | evicted lineages | root evictions | truncated steps | cache entries | cache evictions |
|---|---|---|---|---|---|---|
| 5,000 | 8 | 0 | 0 | 4,590 | 275 | 0 |
| 20,000 | 16 | 0 | 0 | 19,423 | 445 | 0 |
| 35,332 | **16** | **0** | **0** | **34,702** | **594** | **0** |

**No corpus in this repository can drive `WindowStore` past 16 of its 64 lineage slots, or
the transition cache past 594 of its 1,024 entries.** Different seeds do not produce
different lineage identities, because the generators reuse role process identities across
scenarios — the exact corpus trap `planning/MEMORY.md` records.

Consequences, stated plainly:

- **What actually bounds memory under load is per-lineage window truncation** (34,702 steps
  truncated out of 35,332 events) **and atom saturation at MAX_ATOMS**, not the capacity
  caps.
- **The `MAX_LINEAGES` and `MAX_CACHE_ENTRIES` eviction paths are covered by unit tests
  (`test_root_map_is_bounded_and_its_evictions_are_counted`,
  `test_the_cache_default_capacity_is_the_declared_bound`) but are NOT exercised by any
  corpus-driven load in this repository.** Their behaviour under real pressure is
  **UNMEASURED**.

### 6.3 The D2.4 honesty mechanism — verified, and its limit found

ADR-0114 claims a path is reported skipped only when the ledger proves the work did not run.
Tested directly this session against `pocketsec.stage2.router.accounting`:

```
1 fabricated skip REFUSED: phantom savings: work recorded as skipped was also performed (account[0]:CORE_IN...
2 caller ran deep work; derived path = P3_PREDICTIVE (caller had no vote)
3 unrecorded deep work ACCEPTED; derived path = P0_COMPILED -> the ledger bounds dishonesty to omission, it cannot detect it
4 abandoned account REFUSED: event 'e4' is still open; an abandoned account loses its records and w...
```

**The mechanism is real**: a fabricated skip raises, and `close()` takes no path argument so
a caller cannot vote itself onto a cheap path. This is a genuine repair of the ADR-0010
defect.

**Its limit, measured:** work that is simply **never recorded** is indistinguishable from
work that never ran, and derives the *cheapest* path (`P0_COMPILED`). The ledger converts
path dishonesty from *mislabelling* into *omission*. That is a real improvement and it is
not a proof. Any future wake-rate claim depends on every expensive call site recording
itself, which no test currently enforces.

---

## 7. The verdict on the central claim

**NOT SUPPORTED.** Component by component, on the only split capable of showing otherwise:

| Stage 2 thesis clause | measured outcome |
|---|---|
| "detection emerges from prediction" | Already FIRED (F1): joint training 0.3333 vs detached 1.0000. This wave adds that the predictive structures themselves lose to trivial controls — lattice −0.0558 vs a bigram, hazard −0.0862 vs a constant, uncertainty −0.0165 vs `1−max p`. |
| "repeated understanding condenses into discrete reusable structure" | Learned atoms −1.7420 transition log-loss against a hash bucket at 80× the memory (ADR-0115, reproduced). `merge_fission` −0.0000. The discrete layer is **rejected**. |
| "computation becomes proportional to novelty" | **The evidence for this clause was largely artefactual and is restated here from measurements the defect-repair wave actually took.** The router proposes a cheap path for 0.6301 of events; the "ledger derives 0.0000" figure is a structural floor of the harness and says nothing about the router (§2.0). What the ledger does prove: `CORE_INFERENCE` genuinely skipped for **0.9966** of events at 0.0034 performing P3/P4 work — real avoided compute — but only **0.0127** of those cache hits served the answer the deep path would have computed (ADR-0124), so computation became cheaper by becoming *different*, not by becoming proportional to novelty. The transition cache still matches a plain LRU (0.013465 both, now with 312 real evictions per policy rather than none), and utility forgetting still buys nothing. **NOT SUPPORTED**, on better evidence than before. |

The architecture gate's own escape hatches — *"Behaviour Atoms are demonstrably stable
enough to reuse, OR the discrete layer is rejected"* and *"Future Cone adds measurable value,
OR is removed"* — both resolve to the **rejection** branch. G2.4 PASSES by taking it and
reproduces its rejecting measurement this run (learned log-loss 3.472387 vs hash 1.683493).
G2.6 does **not**: taking a rejection branch requires reproducing the rejection, and on this
split the cone beats its control (ADR-0125). The escape hatch is available; it has not been
earned on this corpus.

What survives Stage 2 is what ADR-0009 and ADR-0010 already identified: **a TCN**, plus two
safety gates (`epoch_guard`, `quarantine_promotion`) that work, plus the D2.4 work ledger,
plus a compile-candidate format that can carry a zero-parameter scorer. That is a real and
useful residue. It is not the Dynamic Transition Lattice.

---

## 8. What would change this conclusion

In descending order of how much it would move the answer.

1. **Real telemetry.** Every corpus here is synthetic and nine of nine splits are either
   degenerate or saturated at the top. This is the blocker, and a fifth synthetic corpus is
   not the fix — `planning/MEMORY.md` records four already producing only trivial or
   impossible tasks. **Nothing in §2 should be treated as a property of a component until it
   is re-measured on real host telemetry.**
2. **A corpus where the best model does not reach 1.0000.** §2.2 shows the Stage 2 core
   saturating at 5,055 parameters. Until a split exists where the winner scores below
   ceiling, no ablation of the winner can be positive, and every NOT_YET_JUSTIFIED row in §2
   stays honestly undecidable rather than disproven.
3. **Timing all nine baselines.** If `gru` (1.0000 at count=240) is cheaper than `tcn`, the
   §1.3 frontier changes again and criterion 1's new reason changes with it. UNMEASURED.
4. **Exercising the capacity caps.** A corpus that produces more than 64 distinct lineages
   would turn §6.2's UNMEASURED into a measurement. Until then the eviction paths are
   unit-tested only.
5. **A fifth saturation condition** (§2.2) — a flat frontier refused as loudly as an
   order-free tie. This would have made G2.2's failure legible in one number instead of
   requiring §2.2.
6. **`distinct_epochs ≥ 2` for the Φ-oracle candidate.** G2.13's only remaining problem is
   that the exporter refuses a candidate observed in one epoch. A corpus spanning two
   corroborated epochs would close it; weakening the exporter must not.

---

## Honesty ledger

### MEASURED

One row per number produced by running code in this session.

| claim | value | how it was produced (module:function) | experiment id | synthetic? |
|---|---|---|---|---|
| Full test suite passes | 755 collected, exit 0 (session start) | `pytest` over `tests/` | — | yes |
| Suite at session end | 1177 collected, 2 failures, both `tests/test_stage3_boundary.py`; 0 in Stage 0/1/2 | `pytest` over `tests/` | — | yes |
| Stage 2 gate result | FAILED (7 of 13), exit 1 | `pocketsec.stage2.cli:main` → `gate:run_gate` | — | yes |
| Gate cost | 57.49 s wall, 57.39 s user, 80,304 KB peak RSS | `/usr/bin/time -v` | — | yes |
| Splits degenerate | 8 of 9 | `research.saturation:saturation_check` | — | yes |
| `ambiguous` 240 verdict | `INFORMATIVE`, spread 0.0875, order-free 0.9125, Φ 0.5975 | `research.saturation:saturation_check` | — | yes |
| Seed robustness of that verdict | INFORMATIVE on 3 of 4 eval seeds (11/17/29); seed 23 refused on `markov-bigram` 0.3307 vs base rate 0.3333 | `research.saturation:saturation_check` | — | yes |
| `gru`/`tcn` ceiling tie | both exactly 1.0000 on all four eval seeds | `research.saturation:saturation_check` | — | yes |
| Φ-oracle stability at count=240 | 0.5886 – 0.5975 across four eval seeds | `research.saturation:saturation_check` | — | yes |
| Cost frontier, count=240 | `dominated: []`; tcn 1.0000 @ 5.19 µs/event | `research.cli:measure_frontier` | — | yes |
| dtl-conv at count=240 | 1.0000, `dominated_by: ["tcn"]` | `research.stage2_report:_sleeping_brain` | — | yes |
| phi-oracle at count=240 | 0.5975 @ 0.16 µs/event, 0 parameters | `research.stage2_report:_sleeping_brain` | — | yes |
| behaviour_atom_quantizer | 3.5881 vs 1.8460 log-loss (−1.7420) | `research.stage2_report:measure_behaviour_atoms` | PS-S2-20260924-H8-behaviour-atom-quantizer-0007 | yes |
| transition_lattice | 0.4367 vs 0.4926 top-1 (−0.0558) | `research.stage2_report` | PS-S2-20260924-H8-transition-lattice-0008 | yes |
| merge_fission | 0.0042 vs 0.0042 (−0.0000) | `research.stage2_report` | PS-S2-20260924-H8-merge-fission-0009 | yes |
| future_cone | 1.5548 vs 1.8660 Brier (+0.3112) | `research.stage2_report:measure_future_cone` | PS-S2-20260924-H8-future-cone-0010 | yes |
| cone unresolved mass | 0.646407 mean; argmax UNKNOWN 0/4000 | `predictors.future_cone:predict_future_cone` + `gate_measures:cone_distribution` | — | yes |
| hazard_heads | 0.1631 vs 0.0768 Brier (−0.0862) | `research.stage2_report` | PS-S2-20260924-H8-hazard-heads-0011 | yes |
| uncertainty | ECE 0.5904 vs 0.5739 (−0.0165) | `research.stage2_report` | PS-S2-20260924-H8-uncertainty-0012 | yes |
| multiscale_window | 0.4928 vs 0.4926 (+0.0002) | `research.stage2_report` | PS-S2-20260924-H8-multiscale-window-0013 | yes |
| transition_cache | hit rate 0.0136 vs 0.0136 (0.0000) | `research.stage2_report` | PS-S2-20260924-H8-transition-cache-0014 | yes |
| utility_forgetting | 0.0136 vs 0.0136 (0.0000) | `research.stage2_report:measure_cache_and_forgetting` | **none** — see §4.1 | yes |
| causal_credit | chain recall 0.0000 vs 1.0000 (−1.0000) | `research.stage2_report:attribution_report` | PS-S2-20260924-H8-causal-credit-0016 | yes |
| epoch_guard | 0 vs 377 malicious normalised | `research.stage2_report:_gate_verdicts` | PS-S2-20260924-H8-epoch-guard-0017 | yes |
| quarantine_promotion | 0 vs 64 poisoned promotions | `research.stage2_report:_gate_verdicts` | PS-S2-20260924-H8-quarantine-promotion-0018 | yes |
| Latent frontier | PR-AUC 1.0000 at all of 12/16/24/32/48/64/96; knee = 12 | `research.stage2_report:latent_frontier` | — | yes |
| Runtime RSS (stdlib) | peak sampled 70,275,072 B; incremental 4,411,392 B | `gate_measures:resource_pass` | — | yes |
| Runtime CPU (stdlib) | 0.000688 CPU s/event over 4,096 events | `gate_measures:resource_pass` | — | yes |
| Research-process RSS | 1,436,262,400 B, `within_target: false` | `research.stage2_report:resource_report` | — | yes |
| Measured work-kind ladder | LATTICE_LOOKUP 25.36× CACHE_LOOKUP | `research.stage2_report:path_cost_report` | — | yes |
| Flood 50,000 events | atoms 256, quantizer 249,856 B, ledger 4,096 truncated, peak RSS 89,251,840 B constant | `gate_measures:runtime_pass` | — | yes |
| Adversarial lineage flood | 16 of 64 lineages, 0 evictions, 34,702/35,332 steps truncated | `gate_measures:runtime_pass` | — | yes |
| Phantom-savings refusal | fabricated skip raises `ContractError`; unrecorded work derives `P0_COMPILED` | `router.accounting:WorkLedger.assert_no_phantom_savings` | — | yes |
| Registry after append | 20 entries, `verify_integrity() -> []`, 11 from this wave | `stage0.experiments.registry:ExperimentRegistry` | — | yes |
| Gate after registration | still FAILED (7) | `pocketsec.stage2.cli:main` | — | yes |

### UNMEASURED

| claim the architecture makes | why not measured | what would measure it | blocking? |
|---|---|---|---|
| The cost frontier ranks all nine baselines | `TIMED_MODELS` times three. The all-nine run was abandoned after 12 min/seed at load 15–18 | `sleeping_brain_report(build_baselines(...))` on a quiet host | **Yes for §3.1** — `gru` ties `tcn` at 1.0000 and is untimed |
| `MAX_LINEAGES = 64` bounds the window under load | No corpus produces more than 16 distinct lineages (§6.2) | A corpus with >64 distinct process lineages | Yes for the bounds claim |
| `MAX_CACHE_ENTRIES = 1024` bounds the cache under load | Reached 594 with 0 evictions | Same | Yes for the bounds claim |
| `PATH_COST_UNITS` is calibrated from measured CPU | No calibration code exists; measured ladder is inverted (§5.1) | A calibration pass writing the constants from measurement | No — reported UNMEASURED |
| `P4_DEEP` execution path | No runtime implementation exists for P4; histogram is always 0 | An implementation | No |
| Lint and type status | `ruff` and `mypy` are not installed — verified this session: `python3 -m ruff --version` → `No module named ruff`; same for mypy | Installing the `dev` extra | No, but it is a standing gap across 61+ modules |
| Seed robustness of the count=240 **cost frontier** | Only the saturation verdict was repeated across seeds (§3.3), not the timed pareto | `measure_frontier` per seed on a quiet host | Qualifies §3.1 |
| Resource cost on a 2 GB device | Measured on an 8-core development host only | A 2 GB target device | Yes for the Edge claim as a *device* claim |
| Atom stability under real drift | Measured across reruns of one generator only | Real telemetry across a real epoch change | Yes |

### REJECTED

| component | measured effect | verdict | ADR |
|---|---|---|---|
| Learned Behaviour Atom quantizer | −1.7420 transition log-loss vs `HashBucketQuantizer` at 249,856 B vs 3,136 B | REJECTED | ADR-0115 (reproduced at count=240) |
| Transition lattice next-family prediction | −0.0558 top-1 vs an order-1 `relation_family` bigram | **REJECTED (new this wave)** | ADR-0123 (this wave) |
| Calibrated uncertainty (D2.9) | ECE 0.5904 vs 0.5739 for `1 − max p` | **REJECTED (new this wave)** | ADR-0123 (this wave) |
| Runtime multiscale window (DTL-F03) | **−0.1187** next-family top-1 vs `window=1`, re-measured per lineage | **REJECTED** (was NOT-YET-JUSTIFIED at a mis-grouped +0.0002) | ADR-0126 |
| Hazard heads | −0.0862 Brier vs `constant_hazard` | REJECTED | ADR-0116 (reproduced) |
| Future Cone | +0.3112 Brier vs `marginal_cone`, but both near the 2.0 Brier ceiling and 64.6% of cone mass on `UNKNOWN` | REJECTED (default-off upheld) | ADR-0116 |
| Counterfactual credit ledger | chain recall **0.3518** vs naive ancestry 1.0000 | REJECTED | ADR-0122 (conclusion stands; the 0.0000 was a join that never matched — S2-FC-01) |
| Merge / fission | **UNMEASURABLE** — 0 merges, so `max_macro=64` and `max_macro=0` built the same lattice | was NOT-YET-JUSTIFIED at a forced −0.0000 | ADR-0123, corrected by S2-FC-04 |
| Transition cache vs plain LRU | hit rate 0.013465 vs 0.013465, now with 312 evictions per policy | NOT-YET-JUSTIFIED | — (F10 already recorded; the earlier row evicted nothing, S2-FC-04) |
| Predictive-utility forgetting | hit rate 0.013465 vs LRU 0.013465 / random 0.0 | NOT-YET-JUSTIFIED | — (F11) |
| Need-to-Compute router | proposes cheap path 0.6301; the "ledger derives 0.0000" figure is a harness floor, not evidence about the router (§2.0) | REJECTED, default-off — on the separately measured −0.115 PR-AUC at 3.4× the time, which is what the verdict rests on | ADR-0114 |

### RETRACTED

| retracted claim | where it was published | the defect | corrected value |
|---|---|---|---|
| "On the corpora this repository has, the guard refuses." | `docs/adr/0120-corpus-degeneracy-guard.md`, Consequences | The full corpus × size grid had not been run; ADR-0120 measured the Φ-oracle alone at count=240 and `saturation_check` only at count=30 and `hard`/6 | **`ambiguous` count=240 seed=11 is `INFORMATIVE` (degenerate=False)** — §1.2. The guard's own thresholds admit one split. ADR-0120's decision, thresholds and every other measurement stand; only this summary sentence is superseded. |
| G2.10 wake-rate cost "122.48 vs 647.23 µs/event" | `planning/MEMORY.md`, Stage 2 completion wave table | Not a defect — a host-load artefact the entry itself flags | **103.66 vs 403.48 µs/event** this session at load 1.4–1.7. Both are valid on their own host state; only the ratio (5.3× then, 3.9× now) is comparable. Neither supersedes the other. |
| "the credit spine attributed NOTHING … no probe's divergence reached `MATERIAL_DIVERGENCE`" | G2.7 gate detail, the `causal_credit` ablation row, registry `PS-S2-20260924-H8-causal-credit-0016`, and this document | `nodes` was keyed by `CausalNode.signature` (16 hex) and looked up by `probe.target_signature`, a positional locator `lineage:index:rN:mM`. The two key spaces are disjoint, so `assign_causal_credit` was never called once; 20 of 136 probes WERE material. Both `gate_criteria.py` and `stage2_report.py` carried the identical line, so their agreement was never a cross-check. | **5.0 nodes inspected at chain recall 0.3611** vs naive 19.75 at 1.0 (gate, 4 sessions); report row REJECTED at **−0.6482**, not −1.0. Retracted by `PS-S2-20260925-H8-causal-credit-retraction-0022`. |
| "the ledger derived a cheap path for 0.0000 of events" as evidence about the router | G2.3 gate detail, §7 thesis-clause table, `planning/MEMORY.md` | Identically 0.0 for every possible input: `runtime_pass` performs a mandatory `WINDOW_UPDATE` on every event, that derives `P2_LOCAL` (8.0 units), and a path is the max over performed work — so P0/P1 is unreachable however well the cache performs. A warm-cache pass resolving 464/464 events still reported 0.0000. | The figure is retained and **labelled a structural floor**. The measurements that discriminate: `CORE_INFERENCE` proven skipped for **0.9966**, P3/P4 performed for **0.0034**. G2.3's FAIL verdict was always independently correct via `ROUTER_DEFAULT_ENABLED=False`. |
| "The transition cache matches a plain LRU exactly (hit rate 0.0136 both)" and `merge_fission` −0.0000 | §7 thesis-clause table, §4 ablation table, ADR-0123's Option B rationale, registry 0009 and 0014 | Neither was a comparison. `keep` was a quarter of the held-out **lookup** count (4,474) against a cache holding 416 entries, so all three eviction policies evicted nothing and the arms were bit-identical. `merge_fission` compared two arms built after 0 merges, i.e. the same lattice twice. | Cache: **0.013465 vs 0.013465 with 312 evictions per policy** (random 0.0) — a real null. Merge/fission: **UNMEASURABLE**. Retracted by `PS-S2-20260925-H8-merge-fission-retraction-0020` and `PS-S2-20260925-H8-transition-cache-retraction-0021`. |
| "`multiscale_window` +0.0002 … DTL-F03 earns nothing measurable" | §4 ablation table, ADR-0123 decision 3 | The row did not measure `WindowStore`. Relation families were grouped by **session** while the store keys on the causal-signature root; replacing the store with a stub that held nothing returned bit-identical accuracies, and the measuring function's own docstring said the figures "would be the same for any component that supplied the same taps". | **0.5912 vs 0.7099, delta −0.1187** re-measured per lineage: a REJECTED loss, not a null. Acting on ADR-0123 decision 3 separately costs the exported Φ-oracle candidate **0.5975 → 0.3243** average precision. ADR-0126. Retracted by `PS-S2-20260925-H8-multiscale-window-retraction-0023`. |
| "conformal coverage 0.9793 is outside 0.9 ±0.05" as a calibration result | G2.5 gate detail | A property of `SplitConformal`'s eviction policy, not of the ΔΦ predictor. Median-closest eviction kept both tails and hollowed out the middle, so the rank-0.9 order statistic of the retained set was ~the 99th percentile of the stream. 3,299 of 4,323 residuals were discarded and the gate printed none of that. | With the cap lifted: radius **0.750000**, coverage **0.9167** — the clause PASSES. Reservoir sampling now keeps the retained set a uniform sample; ADR-0128. G2.5 still fails, on its held-out Brier of exactly 0.0. |
| G2.6 and G2.10 recorded as PASS | this document's §1.1 gate table | G2.6's removal branch was two hardcoded flags plus a `docs/adr/*.md` **filename**, with the two measurements it paid for discarded; G2.10's skipped fraction had never been checked against the answers the deep path would have produced. | Both **FAIL**. ADR-0125 and ADR-0124. The gate total moves from 7 failures to 9. |

Nothing has been deleted. ADR-0120's text, ADR-0010's superseded headline and the retracted
per-lineage-pooling result in `docs/stage-2-dtl-findings.md` all remain in place.

### NOT A DETECTION RESULT

**Every corpus used in this document is synthetic.** `ambiguous`, `hard`, `long`, the drift
corpus and the poison suite are all generated from seeded builders in
`pocketsec/stage1/labs/` and `pocketsec/stage2/labs/`, and `synthetic_data: true` travels
with every dataset provenance block quoted above.

Therefore: **no PR-AUC, recall, log-loss, Brier, ECE, hit-rate or wake-rate figure in this
document is evidence that PocketSec detects anything on a real Linux host.** Eight of nine
splits cannot rank mechanisms at all; the ninth ranks architecture families but saturates at
the top, so even its component deltas describe this generator rather than a property of the
mechanism. The resource figures are measurements of *this* development host (8 cores, Linux
7.1.5+kali-amd64, Python 3.14.7) under contention from unrelated work, and the Stage 0 Edge
profile is a **target comparison, not a device measurement**. The poisoning and drift results
are mechanism tests against patterns this project wrote for itself, not adversarial proofs.

The single most defensible conclusion available from this wave is the negative one, and it
does not depend on any corpus being realistic: **the Stage 2 mechanisms lose to trivial
controls that run on the same synthetic data.** A bigram, a hash bucket, `1 − max p`, a
constant hazard, a plain LRU and a window of one are not sophisticated baselines, and they
are ahead.
