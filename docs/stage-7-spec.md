# Stage 7 — ORPHEUS + HIVELOCK — implementation contract

- **Status:** Accepted as the build contract for the Stage 7 wave. Binding on eight work packages
  and the integrator.
- **Date:** 2026-09-26
- **Source of truth:** `docs/architecture/sources/stage-07-orpheus-hivelock.md` (architecture),
  `planning/PHASE_07_CLAUDE_CODE.md` (checklist, gate, STOP conditions),
  `docs/architecture/stage-3-12-integration-plan.md` (layout, seams, import rules). The project
  lead's Stage 7 guidance overrides the architecture where they conflict. This document records
  each conflict where it applies.
- **ADR block:** 0060–0069 (lead's assignment; the integration plan's 0053–0062 block collided
  with Stage 6's 0050–0059 and is superseded). All ten numbers are assigned in §10. None exists on
  disk at spec time (`ls docs/adr | grep '^006'` → empty).

---

## 0. What was measured before this contract was written

Every number below was produced by running code in this session. The scripts are in the
scratchpad, not the repository. Load average was recorded next to each run. No timing figure is
quoted: none of these probes is a timing measurement.

| # | claim | value | command / module | loadavg |
|---|---|---|---|---|
| M0.1 | Every upstream symbol this contract names exists | **96 OK, 0 missing** | `verify_seam.py`: `inspect.getsourcefile`/`getsourcelines` over the §3.1 table | 5.75 4.81 6.05 |
| M0.2 | What Stage 6's gateway does with foreign knowledge today | 40 FOREIGN_PACKAGE capsules (Stage 1 `build_corpus(count=40, seed=7, split="eval")` → `EncodedStep.from_transition` → `KnowledgePackageV1` → `verify_package` → `package_to_capsules(enabled=True)` → `QuarantineGateway.admit`): **TRUSTED_CANDIDATE 0**, UNCERTAIN 16, HOSTILE_SUSPECT 24. `score_provenance(...).score` = **0.08 on all 40** (min = max = 0.08000000000000002). Reasons: `low_provenance` 40, `hostile_suspect` 24, `normalization` 12 | `probe_foreign.py` | 4.16 4.96 6.43 |
| M0.3 | Can a ≤2-step Stage 6 motif learned on one set of hosts detect the same technique on disjoint scenarios (the transfer an antibody needs, lesson 2)? — Stage 1 corpus, source seed 3 and receiver seed 11, 120 episodes each | container-escape recall **6/6**, memory-credential-theft **6/6**, privileged-persistence **12/12**, sudo-credential-exfil **12/12**; receiver FP **0/84** for every technique; best motif length 2 in all four | `probe_express.py` (`match_motif`) | 9.74 6.25 6.48 |
| M0.4 | Same probe, ambiguous corpus (90 episodes each) | partial-chain **10/10**, single-lineage-exfil **20/20**, FP **0/60** | `probe_express_amb.py` | 10.75 6.82 6.67 |
| M0.5 | M0.1 and M0.2 re-run after the Stage 6 wave wrote its ledger mid-session | still **96 OK / 0 missing**. Still **0 TRUSTED_CANDIDATE of 40**, score 0.08 on all 40. `SOURCE_CLASS_PRIOR[FOREIGN_HOST]=0.2`, `FLAG_RISK[FOREIGN_ORIGIN]=0.6`, `MIN_PROVENANCE_SCORE=0.5` unchanged (`trust.py:77`, `:101`, `:64`) | same scripts | 9.55 6.80 6.16 |

**Reported by the Stage 6 wave, not re-measured here** (`planning/PROGRESS.md`,
`planning/MEMORY.md`, updated during this session). `pocketsec-stage6 gate` FAILED, 6/13. The
boundary checks passed. The Stage 6 learner "learns nothing on the synthetic timeline: 0 learned
items". Stage 7 relies on none of this: M0.2/M0.5 already close the foreign path
independently. It does mean that no local trusted detector exists for
`invariants_from_learning_record` to export on the synthetic corpora. **Stage 7's labs therefore
forge antibodies from lab-labelled local incidents (§4.19), not from Stage 6 trusted state.** The
learning-record path is built and tested on hand-built records.

**What M0.2 means. It is the first finding of this stage, and it is a blocker (B7-1, ADR-0067).**
Stage 6's provenance score is `prior × visibility × (1 − max flag risk)`. For a foreign capsule
that is `0.2 × ≤1 × (1 − 0.6) ≤ 0.08`, below `MIN_PROVENANCE_SCORE = 0.5`
(`stage6/provenance/trust.py:64`). Every foreign capsule therefore stops at `low_provenance`
before the foreign path runs. Stage 6's own docstring calls the corroboration branch INERT.
**The only legitimate path from collective knowledge to local trusted state is closed by
construction.** It stays closed however good or bad Stage 7 is. Three consequences:

1. "How much adversarial knowledge reaches **promotion**" is identically 0 at every adversary
   share. A criterion measured there cannot fail, so it is not a criterion (Stage 2 lesson 10).
   Stage 7 measures its defences at **its own output boundary**: the set of antibodies ECHO marks
   `ELIGIBLE` and the bridge hands to `QuarantineGateway.admit`. The Stage 6 buckets are reported
   next to that figure and never substituted for it.
2. "Collective detection gain" cannot be realised on the host. It is measured as a
   **counterfactual at the Stage 7→Stage 6 boundary**: what the receiver's detection would be if
   the antibodies Stage 7 delivered were installed. It is labelled `counterfactual_at_boundary`
   every time it appears.
3. Architecture falsifier §49.7 ("foreign knowledge rarely survives Stage 6 local validation")
   **already fires today**, measured at 0/40 survivals. Stage 7 cannot change Stage 6 constants
   and does not edit Stage 6. It reports this. The lead decides whether Stage 6's foreign prior
   is revised.

**What M0.3/M0.4 mean. The corpora are saturated in favour of sharing.** One motif transfers at
recall 1.0 and FP 0 on both synthetic corpora in the repository. On such a corpus, *any* sharing
mechanism shows a large detection gain for families the receiver has not seen locally. The gain
therefore cannot tell good aggregation from bad. Stage 7 builds its own fleet corpus (§4.19) that
adds deliberate non-IID collisions: benign ADMIN persistence and benign DESKTOP egress. Even so,
detection-gain figures are reported with the flag `DEGENERATE_IN_FAVOUR` when the oracle transfer
precondition reads 1.0/0 (§4.19 P5). Robustness figures do separate mechanisms. They are
confounded by construction, because this wave authors both the adversary and the defence (lesson
6, §9).

---

## 1. What Stage 7 must deliver

**Thesis, bound to code.** Stage 7's deliverable is **the boundary that keeps foreign knowledge
untrusted**. The sharing protocol is secondary. Stated so a gate can check it:

> *Foreign bytes enter only through `HivelockIngress.receive`. Foreign knowledge leaves Stage 7
> only through `Stage6Bridge.hand_over`, as `ExperienceCapsuleV1` values passed to
> `QuarantineGateway.admit` and to no other function. No Stage 7 module can name a Stage 6 writer
> or anything in Stage 5. No collective outcome, however unanimous, can change a local decision
> without local evidence. Every store is bounded. Nothing host-identifying leaves the host.*

### 1.1 Checklist → deliverable → module → package

Every item of `planning/PHASE_07_CLAUDE_CODE.md` appears here. Checklist item NN is deliverable
D7.NN.

| # | deliverable | module(s) under `pocketsec/stage7/` | core id(s) | package |
|---|---|---|---|---|
| 01 | D7.1 Collective Constitution | `constitution/collective.py` | ORPH-F01 | foundation |
| 02 | D7.2 Knowledge Capsule schema/compiler | `capsule/knowledge_capsule.py` (schema), `capsule/compiler.py` (compiler) | ORPH-F03 | foundation, privacy |
| 03 | D7.3 Privacy Distiller + Privacy Ledger | `privacy/distiller.py`, `privacy/ledger.py` | ORPH-F04, ORPH-F19 | privacy |
| 04 | D7.4 Peer Identity/Integrity plane | `identity/peer.py`, `identity/integrity.py` | ORPH-F02 | ingress |
| 05 | D7.5 Epistemic Distance engine | `relevance/epistemic_distance.py` | ORPH-F05 | graph |
| 06 | D7.6 Knowledge Gravity engine | `relevance/gravity.py` | ORPH-F06 | graph |
| 07 | D7.7 HIVELOCK ingress/quarantine | `hivelock/ingress.py`; the Stage 6 handoff is `hivelock/stage6_bridge.py` | ORPH-F07, ORPH-F17 | ingress, sovereignty |
| 08 | D7.8 Dependence/Sybil graph | `graph/dependence.py`, `graph/sybil.py`, `trust/contextual.py` (§22) | ORPH-F08 | graph |
| 09 | D7.9 Byzantine evidence benchmark suite | `aggregation/robust.py` (aggregator families), `labs/byzantine_suite.py` (runner) | ORPH-F09, ORPH-F22 | echo, adversary |
| 10 | D7.10 ECHO collective inference engine | `echo/inference.py` | ORPH-F09 | echo |
| 11 | D7.11 Knowledge Antibody Forge | `antibody/forge.py` | ORPH-F10 | echo |
| 12 | D7.12 Partial-World Reconstructor | `reconstruct/partial_world.py` | ORPH-F11 | campaign |
| 13 | D7.13 Campaign Hypergraph | `campaign/hypergraph.py` | ORPH-F13 | campaign |
| 14 | D7.14 Collective Novelty engine | `novelty/collective.py` | ORPH-F12 | campaign |
| 15 | D7.15 Consensus Falsifier | `falsifier/consensus.py` | ORPH-F14 | campaign |
| 16 | D7.16 Cross-host lineage/revocation | `lineage/cross_host.py` | ORPH-F15, ORPH-F16 | sovereignty |
| 17 | D7.17 Optional secure aggregation module | `aggregation/secure.py` | ORPH-F18 | sovereignty |
| 18 | D7.18 Communication/resource governor | `governor/communication.py`; offline/partition mode in `orpheus/fabric.py` | ORPH-F20, ORPH-F21 | ingress, sovereignty |
| 19 | D7.19 72-experiment adversarial benchmark | `labs/seventy_two_experiments.py` (catalogue), `labs/simulated_fleet.py`, `labs/byzantine_suite.py`, `labs/privacy_attacks.py`, `labs/campaign_sim.py` | ORPH-F22 | adversary, campaign |
| 20 | D7.20 Stage 1–7 endurance/falsification report | `labs/partition.py` (`run_churn_endurance`, `run_offline_equivalence`, `run_scale`); the report is `docs/stage-7-findings.md` (integrator) | ORPH-F21, ORPH-F22 | adversary, integrator |

### 1.2 The required test focus of the phase file, bound

| phase-file focus | where it is tested |
|---|---|
| capsule signature/schema/replay | `tests/test_stage7_foundation.py` (schema), `tests/test_stage7_ingress.py` (HMAC, key revoke/rotate, replay, expiry) |
| privacy leakage | `tests/test_stage7_privacy.py` (field table, residual screen, canaries), `tests/test_stage7_adversary.py` (membership/property inference), G7.7 |
| Sybil/dependence and Byzantine aggregation | `tests/test_stage7_graph.py`, `tests/test_stage7_echo.py`, `tests/test_stage7_adversary.py`, G7.4, G7.11 |
| partition/offline behaviour | `tests/test_stage7_sovereignty.py`, `tests/test_stage7_adversary.py` (`labs/partition.py`), G7.3 |
| revocation | `tests/test_stage7_sovereignty.py`, G7.9 |
| local-sovereignty no-bypass | `tests/test_stage7_boundary.py` (AST), `tests/test_stage7_sovereignty.py` (unanimous fleet), G7.1 |
| bandwidth/RAM caps | `tests/test_stage7_ingress.py` (governor), `tests/test_stage7_adversary.py` (flood, 10k peers), G7.10 |

---

## 2. Repository rules this wave operates under

### 2.1 Layout: integration plan §1.2, amended (ADR-0060)

```
pocketsec/stage7/
    __init__.py                     # integrator. EMPTY or a lazy surface (stage6/__init__.py shape)
    core_ids.py                     # ORPH-F01 … ORPH-F22 (one per architecture layer 7.0–7.21)
    gate.py, gate_*.py              # integrator. 11 checks
    cli.py                          # integrator. pocketsec-stage7 {gate,suite,privacy,campaign,partition,resources,catalogue,experiments}
    constitution/collective.py      # D7.1
    capsule/knowledge_capsule.py    # D7.2 schema: KnowledgeCapsuleV1 and its sub-records
    capsule/compiler.py             # D7.2 compiler: distil → commit → seal (unsigned) → ledger charge
    privacy/distiller.py            # D7.3 export field table, generalisation, residual screen, canary scan
    privacy/ledger.py               # D7.3 PrivacyLedger, budget, geometric DP mechanism (counts only)
    identity/peer.py                # D7.4 PeerIdentity, PeerTable, pseudonym
    identity/integrity.py           # D7.4 Keyring (register/rotate/revoke), HMAC sign/verify, ReplayGuard
    hivelock/ingress.py             # D7.7 the §21 pipeline → IngressVerdict
    hivelock/stage6_bridge.py       # layer 7.16: THE ONE module that hands anything to Stage 6
    governor/communication.py       # D7.18 exchange modes, byte budgets, bounded inbox, resource measurement
    graph/dependence.py             # D7.8 DependenceGraph (union-find clusters over typed edges)
    graph/sybil.py                  # D7.8 SybilReport, amplification factor
    trust/contextual.py             # §22 ContextualTrust (task- and epoch-scoped, decaying)
    relevance/epistemic_distance.py # D7.5 LocalContext, EpistemicDistance
    relevance/gravity.py            # D7.6 KnowledgeGravity
    aggregation/robust.py           # D7.9 aggregator families (the baselines ECHO must beat)
    aggregation/secure.py           # D7.17 pairwise-mask secure sum, default OFF
    antibody/forge.py               # D7.11 forge, LocalValidator, BenignRing, prototype_steps
    echo/inference.py               # D7.10 ECHO
    campaign/hypergraph.py          # D7.13
    reconstruct/partial_world.py    # D7.12
    novelty/collective.py           # D7.14
    falsifier/consensus.py          # D7.15 (+ §19 negative-evidence weight)
    lineage/cross_host.py           # D7.16 CrossHostLineageDAG + RevocationPlane
    orpheus/fabric.py               # §32 composition root; §43 failure isolation; layer 7.20 offline mode
    labs/fleet_corpus.py            # simulated fleet corpus (roles, hosts, episodes, canaries)
    labs/simulated_fleet.py         # simulated honest peers + every adversary arm; lab Stage 6 receiver
    labs/campaign_sim.py            # distributed campaign + common-cause arms
    labs/byzantine_suite.py         # D7.9 runner: aggregators × arms × shares, break points, ablation
    labs/privacy_attacks.py         # membership / property inference, DP curve
    labs/partition.py               # offline equivalence, partition/stale recovery, churn endurance, scale
    labs/seventy_two_experiments.py # D7.19 S7X-01…72 catalogue with honest status per row
```

Amendments to integration plan §1.2, all recorded in ADR-0060:

- `hivelock/quarantine.py` → **`hivelock/stage6_bridge.py`**. Stage 7 must not build a second
  quarantine (lead's rule: "do not build a second promotion gate"). The module is the handoff to
  Stage 6's quarantine, and its name says so.
- `identity/revocation.py` is folded into `identity/integrity.py` (key revoke/rotate). Capsule
  revocation (D7.16) is `lineage/cross_host.py`. Two modules named `revocation.py` in two packages
  would be the confusion the plan warns against.
- **Added:** `lineage/cross_host.py` (D7.16 has no module in the plan), `trust/contextual.py`
  (§22), `orpheus/fabric.py` (§32/§43/layer 7.20), `labs/fleet_corpus.py`,
  `labs/simulated_fleet.py` (the plan's `labs/sybil_sim.py`, renamed because it simulates honest
  peers as well, and the lead requires `simulated_*` names), `labs/campaign_sim.py`,
  `labs/privacy_attacks.py`, `labs/seventy_two_experiments.py`.
- **Empty directories on disk.** `pocketsec/stage7/{collective,hivelock,orpheus,privacy,trust}/`
  exist, hold no files and are not packages (`ls -la`, this session). `hivelock/`, `orpheus/`,
  `privacy/` and `trust/` are filled by this layout. **`collective/` is deleted by package
  `foundation`** (ADR-0121 precedent), and `tests/test_stage7_boundary.py` forbids its return.
- **No `research/` package, no numpy** (integration plan §2.4 lists Stage 7 as "no").

Every subsystem `__init__.py` stays **empty**. Consumers import the leaf module. An empty
subsystem package is a defect (ADR-0121).

### 2.2 Hard mechanical constraints (same as Stage 6 §2.3, restated because they bite)

- Python ≥ 3.11 and `from __future__ import annotations`. Strict typing on every public API.
  `@dataclass(frozen=True, slots=True)` for every value type. Explicit `__all__`. A module
  docstring that says what the module is **for**. Before writing, read
  `stage6/fleet/package.py` and `stage6/export/learning_record.py`: they are the house style and
  the two Stage 6 modules Stage 7 sits next to.
- Files under ~800 lines, functions under ~50. `print()` only in `cli.py`.
- **Every store is bounded, every truncation explicit, every eviction counted and recorded.** A
  store without `memory_bytes()` and a named cap constant is a defect.
- **Time is rounds, not wall clock.** Every age, window, expiry and horizon is counted in
  simulated exchange rounds (`round_index: int`). Wall clock is recorded beside
  `/proc/loadavg` as an observation and never asserted.
- **Cost is work units.** Ingress, graph, ECHO, forge, reconstruction and novelty charge a
  `WorkMeter` (`pocketsec.stage6.resources.WorkMeter`, reused, §3.1). Work units are the primary
  cost measure. Only within-run ratios of wall time are ever compared.
- **The T5 trap. Read this before naming a field.** No annotated `@dataclass` field under
  `pocketsec/stage7/` may contain, lowercased, any member of `FORBIDDEN_AUTHORITY_FIELDS`
  (`action, remediation, execute, command, shell, kill, quarantine, block, authorize,
  authorization, privilege, sudo`). There is no exemption list. The words that bite in *this*
  stage: **`redaction`, `extraction`, `fraction`, `transaction`, `interaction`** (all contain
  `action`); `quarantined`, `quarantine_bucket`; `blocked`, `block_size`; **`skill`**; `executed`;
  `privileged`. The privacy distiller reports **`fields_generalised`**, never "redactions". Every
  share is a **`share`** or a **`rate`**. Stage 6's bucket is carried as **`stage6_bucket`**.
  Enum members are not fields and are not screened. The **wire** is screened more strictly than
  T5: every key at every depth of a `KnowledgeCapsuleV1` payload is screened (§4.2).
- **No real network.** No module under `pocketsec/stage7/` imports `socket`, `ssl`, `http`,
  `urllib`, `ftplib`, `smtplib`, `socketserver`, `select`, `selectors`, `asyncio`, `subprocess`,
  `multiprocessing`, `ctypes`, `pty`, `xmlrpc` or `telnetlib`, or calls `os.system`, `os.popen`,
  `os.exec*` or `os.spawn*`. The fleet is simulated in-process (`labs/simulated_fleet.py`). Every
  fleet-level property (real latency, real partition behaviour, real Sybil populations, transport
  security) is **UNMEASURED for real deployments**.

### 2.3 Upstream imports: an allow-list (ADR-0061)

| upstream | Stage 7 may import | from which Stage 7 files | never |
|---|---|---|---|
| Stage 0 | anything under `pocketsec.stage0` | any | — |
| Stage 1 | anything under `pocketsec.stage1` | any | — |
| Stage 2 | `pocketsec.stage2.encoder.ssir_encoder` | any | everything else, `research.*` |
| Stage 3, 4, **5** | **nothing** (T2 forbids Stage 5 outright) | — | everything |
| Stage 6 `capsule.experience_capsule` | `EncodedStep`, `ExperienceCapsuleV1`, `PrivacyClass`, `SECRET_PATTERN`, `source_group_of` | any | other names |
| Stage 6 `memory.semantic` | `MotifStep`, `match_motif`, `motif_pattern_key`, `MAX_MOTIF_LENGTH`, `context_id_for` | any | all other names |
| Stage 6 `memory.semantic` | `genesis_state` | `labs/` only (the lab receiver) | — |
| Stage 6 `export.learning_record` | `LearningRecordV1` | `capsule/compiler.py` only | — |
| Stage 6 `fleet.package` | `KnowledgePackageV1`, `KNOWLEDGE_PACKAGE_V1_VERSION`, `sign_package`, `verify_package`, `package_to_capsules` | `hivelock/stage6_bridge.py` only | — |
| Stage 6 `fleet.package` | `MIN_KEY_BYTES` | `identity/integrity.py`, `hivelock/stage6_bridge.py` | — |
| Stage 6 `capsule.quarantine` | `QuarantineGateway`, `QuarantineVerdict`, `QuarantineBucket` | `hivelock/stage6_bridge.py`, `labs/` | — |
| Stage 6 `fossils.lineage` | `KnowledgeLineageDAG` | `hivelock/stage6_bridge.py` (calls only `.has`), `labs/` | — |
| Stage 6 `provenance.ledger` | `ProvenanceLedger` | `labs/` only (constructs the lab receiver's gateway) | — |
| Stage 6 `resources` | `WorkMeter`, `WorkBudgetExceeded`, `loadavg` | any | the rest |
| Stage 6, everything else | **nothing**: `promotion.*`, `chamber.*`, `conservation.*`, `shadow.*`, `consolidator.*`, `plasticity.*`, `rehearsal.*`, `homeostasis.*`, `fossils.store`, `memory.{episodic,procedural,competition,half_life}`, `gate*`, `labs.*` | — | — |

The integrator's harness (`gate.py`, `gate_*.py`, `cli.py`) has the `labs/` allowances and
nothing more.

**Stage 6 is being built by another wave right now.** Stage 7 codes against Stage 6's types *as
they stand* (M0.1 verified every name above). If a name moves, the package reports a blocker. It
does not edit Stage 6. `resources.WorkMeter`/`loadavg` are outside the Stage 6 spec's named
interface. They are admitted because they are stateless utilities. A second work meter would be
the duplication the repository forbids. They hold no trusted state (ADR-0061 records this
deviation).

### 2.4 Another wave may be building in this tree

- **Never** edit, revert or delete anything under `pocketsec/stage<other>/`,
  `tests/test_stage<other>_*.py` or `docs/stage-<other>-*.md`. Never run `git checkout`,
  `git stash`, `git restore`, `git clean` or `git commit`.
- **Never** edit `tests/test_repository_structure.py`. Stage 7's rules live in
  `tests/test_stage7_boundary.py` (§5.1). That file **imports** the shared resolver
  `pocketsec.stage2.gate_criteria.imported_modules` (`gate_criteria.py:547`) and never copies it.
- Judge Stage 7 by `tests/test_stage7_*.py` plus `pocketsec-stage7 gate`. Report failures in
  another stage's test files and move on.
- `pyproject.toml` is shared. The integrator appends exactly
  `pocketsec-stage7 = "pocketsec.stage7.cli:main"` and one CI step. Nothing else.

### 2.5 The gate never mutates the real experiment ledger

`Stage7GateContext.build()` records ablation rows in a **temporary** registry. G7.11 asserts that
`experiments/registry.jsonl` is byte-identical before and after the gate run. Rows are written
only by `pocketsec-stage7 experiments --register`.

### 2.6 Hypothesis binding: no H13 is minted (ADR-0060)

ADR-0012 was never written, and `HYPOTHESES` holds H0–H8. Stage 7 binds its gate to `BASE`
(Stage 5 precedent) and its ablation rows to `H8` ("combine only components independently
justified by ablation").

```python
STAGE7_HYPOTHESIS = "BASE"
EXPERIMENT_ID = "PS-S7-20260926-BASE-orpheus-gate-0001"
ABLATION_HYPOTHESIS = "H8"
```

### 2.7 Timing on a contended host

Every timing figure carries `/proc/loadavg` (`stage6.resources.loadavg`). Every comparison of two
paths is a **within-run ratio**. No absolute microsecond figure is ever presented as a device
measurement. A Stage 2 gate measured a 7× inflation at load 23–67 against load 8–12.

---

## 3. The data seam

### 3.1 Consumed from Stages 0–6. Every symbol exists (M0.1), cited `path:line`

| symbol | path:line | how Stage 7 uses it |
|---|---|---|
| `ContractError`, `register_schema`, `digest_of_bytes`, `require_identifier`, `require_finite_unit_interval`, `EvidenceRef` | `stage0/contracts/common.py:32`, `:49`, `:116`, `:72`, `:84`, `:124` | validation, schema registration of `pocketsec.knowledge_capsule.v1`, content addressing |
| `Verdict`, `NON_COMMITTAL_VERDICTS`, `FORBIDDEN_AUTHORITY_FIELDS` | `stage0/contracts/threat_prediction_v1.py:66`, constants | T5 and the wire-key screen; `Verdict.MALICIOUS` on bridged items |
| `GateCheck(id, title, passed, detail)`, `GateReport(checks)`, `REPO_ROOT` | `stage0/gate.py:44`, `:55` | the gate |
| `ResourceSampler(*, interval_seconds=0.01)`, `ResourceMetrics`, `read_rss_bytes` | `stage0/benchmark/resource_metrics.py:103`, `:57`, `:38` | G7.10; the only RSS source |
| `check_profile(metrics, profile_name, *, model_bytes=None)`, `ProfileReport`, `PROFILES`, `HOST_RAM_TARGET_BYTES` (2147483648) | `stage0/benchmark/profiles.py:85`, `:61` | G7.10; `within_target is None` is UNMEASURED |
| `evaluate_scores(labels, scores, *, threshold, fpr_budget, latencies_ns, abstentions, host_count, duration_seconds)`, `recall_at_max_fpr(labels, scores, max_fpr) -> (recall, threshold)`, `average_precision`, `confusion_at_threshold` | `stage0/benchmark/security_metrics.py:211`, `:122`, `:92`, `:73` | every recall/FP figure. No second metric implementation |
| `ExperimentRegistry(path).register(*, experiment_id, hypothesis, title, slot_name, dataset_name, dataset_version, dataset_sha256, git_commit, seeds, synthetic_data, notes, result_path)`, `format_experiment_id(*, stage, hypothesis, slug, sequence, date)` | `stage0/experiments/registry.py:106`, `ids.py:56` | CLI registration only |
| `HYPOTHESES`, `SeedSet(master)` | `stage0/hypotheses.py`, `stage0/repro/seeds.py:23` | G7.11 discipline; seeds |
| `Stage1Pipeline().run_scenario(scenario, *, sensor, offset)`, `ScenarioResult(scenario, transitions, …)` | `stage1/pipeline.py:77`, `:46` | the fleet corpus compiles every scenario once, session-unique offsets |
| `Behaviour(operation, fields)`, `Scenario(name, behaviours, label, technique, unseen_technique)`, `BENIGN_PATTERNS`, `BENIGN_PRIVILEGED`, `ATTACK_EXFIL`, `ATTACK_PERSISTENCE`, `ATTACK_UNSEEN_MEMORY`, `ATTACK_UNSEEN_ESCAPE` | `stage1/labs/corpus.py:33`, `:44`, constants | the only scenario types. No fifth one |
| `SSIRTransitionV1`, `SemanticProperty`, `Relation`, `RelationFamily`, `family_of` | `stage1/ssir/transition.py:81`, `entities.py:64`, `relations.py:19`, `:56`, `:95` | prototype steps and chain-stage derivation |
| `Epoch`, `EpochModel(identity=…)`, `SystemIdentity(kernel_id, package_digest, service_digest, container_id, policy_digest, user_role_digest)` | `stage1/epoch/model.py:104`, `:136`, `:54` | the bridge's local epoch; `software_epoch_class` |
| `EncodedTransition`, `encode_ssir_transition`, `FEATURE_LAYOUT`, `FEATURE_WIDTH` (96), `GROUP_OFFSETS`, `feature_names()` | `stage2/encoder/ssir_encoder.py:142`, `:195`, constants, `:122` | bit orders (`object.<P>`, `raised.<dim>`); prototype features |
| `imported_modules(node, path)` | `stage2/gate_criteria.py:547` | tests only: the one import resolver |
| `EncodedStep` (features, relation, relation_family, state_delta_mask, time_bucket, delta_phi, object_property_mask, epoch_id, actor_slot, uncertainty, source_group, causal_signature, parent_signature, evidence) | `stage6/capsule/experience_capsule.py:303` | fleet corpus episodes; prototype steps for the bridge |
| `ExperienceCapsuleV1`, `PrivacyClass` (`PUBLIC_DERIVED`, `HOST_SENSITIVE`, `SECRET_BEARING`), `SECRET_PATTERN`, `source_group_of` | `experience_capsule.py:541`, `:174`, constant, `:295` | the only form foreign knowledge takes into Stage 6; privacy class on the wire |
| `MotifStep(relation, require_properties, forbid_properties, require_raised)`, `match_motif(motif, steps)`, `motif_pattern_key`, `MAX_MOTIF_LENGTH` (2), `context_id_for`, `genesis_state(*, identity, threshold)` | `stage6/memory/semantic.py:222`, `:783`, `:250`, constant, `:195`, `:758` | **the antibody grammar is Stage 6's DETECTOR grammar, exactly** (lesson 3); `genesis_state` only in labs |
| `LearningRecordV1` (items with `kind`, `pattern_key`, `motif`, `weight`, `evidence_count`, `simulated`) | `stage6/export/learning_record.py:118` | the Stage 6→7 handoff: trusted DETECTOR motifs become exportable antibodies |
| `KnowledgePackageV1`, `KNOWLEDGE_PACKAGE_V1_VERSION`, `sign_package(package, *, key)`, `verify_package(package, *, keyring)`, `package_to_capsules(package, *, verification, epoch, sequence, enabled)`, `MIN_KEY_BYTES` (16) | `stage6/fleet/package.py:140`, constant, `:245`, `:289`, `:369`, constant | the bridge reuses Stage 6's own foreign-import rewrite (source group, epoch, WEAK label) instead of a second one |
| `QuarantineGateway.admit(capsule) -> QuarantineVerdict`, `QuarantineBucket` (`TRUSTED_CANDIDATE`, `UNCERTAIN`, `HOSTILE_SUSPECT`, `DISCARD`) | `stage6/capsule/quarantine.py:377`, `:438`, `:144` | the single admission function (integration plan §3.2) |
| `KnowledgeLineageDAG.has(node_id)` | `stage6/fossils/lineage.py:207`, `:349` | G7.8: local lineage of every bridged capsule |
| `ProvenanceLedger()` | `stage6/provenance/ledger.py:139` | labs: the lab receiver's gateway |
| `WorkMeter`, `WorkBudgetExceeded`, `loadavg()` | `stage6/resources.py:137`, `:133`, `:181` | work units; loadavg beside timings |

### 3.2 The upstream contracts, quoted where they decide Stage 7's design

**Stage 6 foreign import** (`fleet/package.py` docstring). "HMAC-SHA256 … proves **key
membership, not host identity** … the vote is bound to the key, not the host —
`independence_group = "fleet:" + key_id` — and N Sybil hosts sharing one key are ONE vote." Three
foreign claims are rewritten, not trusted. Every step's `source_group` becomes the hash of the
fleet group. Every step's `epoch_id` becomes the local epoch. The label origin is `WEAK`. Items
must be `PUBLIC_DERIVED`, carry 1–64 `EncodedStep` dicts and ≥ 1 evidence ref, and pass
`SECRET_PATTERN`. `package_to_capsules` raises `FleetDisabledError` unless `enabled=True`.
**Stage 7 uses this rather than building a second import path.** The bridge signs one package per
supporting dependence cluster with a key derived for that cluster. Stage 6's independence group
is therefore Stage 7's cluster (§4.7).

**Stage 6 gateway** (`quarantine.py:438`). One argument. `ContractError` unless a trusted view is
bound. Step 9: "`FOREIGN_PACKAGE`: at most `UNCERTAIN` unless a local independent group
corroborates the same pattern or motif." Under the current parameters it is never reached
(M0.2).

**Stage 6 learning record** (`learning_record.py` docstring). Per item it carries kind, pattern
key, motif bitmasks, weight, context ids, status, candidate id, evidence **count** and a simulated
flag. It carries no capsule ids, evidence digests, signatures, source groups or baseline anchors.
Stage 7 distils **DETECTOR** rows only. Baseline (normality) knowledge is never exported
(ADR-0063).

**Stage 6 motif** (`semantic.py:222`, `:783`). A motif is 1–2 `MotifStep`s. Each is a bitmask
test `(relation, require_properties, forbid_properties, require_raised)`. A 2-step motif requires
step *i* then *j* (*i* < *j*) **within one actor**. Known inexpressible, stated in advance: counts,
timing, chains longer than 2 steps. **Stage 7's antibody inherits exactly this expressivity.** A
graded match score is not built (§4.11), because its only consumer is boolean.

### 3.3 Exposed to Stage 8 (and Stage 12) — the names this contract assigns

Integration plan §3.2 names them. Each exists at the module below after this wave. Stage 8 reaches
them only through Stage 6 admission, and they carry no authority.

| type | module | for |
|---|---|---|
| `KnowledgeCapsuleV1` (schema `pocketsec.knowledge_capsule.v1` @ `1.0.0`) | `capsule/knowledge_capsule.py` | the wire unit; Stage 8's `adapters/stage7.py`, Stage 12 |
| `PeerIdentity`, `PeerTable` | `identity/peer.py` | Stage 12 trust graph input |
| `PrivacyLedger`, `LeakageMeasurement` | `privacy/ledger.py`, `labs/privacy_attacks.py` | disclosure accounting |
| `EpistemicDistance`, `LocalContext` | `relevance/epistemic_distance.py` | transfer relevance |
| `KnowledgeGravity` | `relevance/gravity.py` | validation triage |
| `IngressVerdict`, `IngressOutcome`, `PooledCapsule` | `hivelock/ingress.py` | never promotes; terminal success is `POOLED` |
| `DependenceGraph`, `SybilReport` | `graph/dependence.py`, `graph/sybil.py` | Stage 12 `quorum/independence.py` input |
| `EchoInference`, `EchoDecision`, `EchoStatus` | `echo/inference.py` | the collective decision record |
| `KnowledgeAntibody`, `LocalValidation` | `antibody/forge.py` | portable invariant |
| `PartialWorld`, `CampaignHypergraph`, `CollectiveNovelty`, `ConsensusFalsification` | `reconstruct/`, `campaign/`, `novelty/`, `falsifier/` | advisory only; never bridged |
| `Revocation`, `CrossHostLineageDAG` | `lineage/cross_host.py` | ancestry and targeted invalidation |
| `CommunicationBudget`, `ExchangeMode` | `governor/communication.py` | bounded exchange |
| `BridgeReceipt` | `hivelock/stage6_bridge.py` | the record of what was handed to Stage 6 and what Stage 6 said |

**Binding inherited by Stage 8.** A Stage 7 object is never authority. It reaches trusted state
only as an `ExperienceCapsuleV1` through `QuarantineGateway.admit`, and today that path admits
nothing foreign (M0.2).

---

## 4. Deliverables: modules, types, signatures, bounds

`[package]` names the owner (§5). Every constant cited is in the §4.23 table and is a **chosen
parameter, not a measurement**.

### 4.0 The model everything else hangs on. Read first

- **Knowledge unit.** An *antibody* is a Stage 6 motif (`tuple[MotifRow, ...]`, 1–2 rows of
  four ints) meaning "this behaviour pattern is malicious". Its identity is `antibody_key` =
  `compact_feature_signature` = `"mf-" + sha256(canonical rows)[:16]`.
- **Direction rule (ADR-0063).** A foreign peer may suggest **what to fear**, never **what to
  trust**. There is no foreign normality, baseline or "benign" knowledge type. A peer's `CONTEST`
  stance can only *reduce* ECHO's support mass for a key. It never creates trusted knowledge. A
  foreign `REVOCATION` is accepted only as the contributor's own self-retraction (§4.16).
- **Round.** The fabric processes deliveries in rounds. All state is keyed on
  `round_index: int`.
- **Receiver.** Every decision is per receiving host, relative to its `LocalContext`. There is
  no global collective state.
- **Measurement boundary.** Stage 7's defences are measured at `EchoStatus.ELIGIBLE` and at
  `Stage6Bridge.hand_over` (§0). Stage 6's buckets are reported beside that, never instead of it.
- **Score for detection experiments** (labs only, never on the endpoint). For each held-out
  episode, `score = 1.0` if any antibody in the evaluated set satisfies `match_motif`, else
  `0.0`. Recall comes from `recall_at_max_fpr` at `FPR_BUDGET`.

### D7.1 — Collective Constitution `[foundation]`

```python
# pocketsec/stage7/constitution/collective.py
class CollectiveLaw(StrEnum):                           # architecture §3, plus the lead's two
    NO_DIRECT_TRUSTED_WRITE = "NO_DIRECT_TRUSTED_WRITE"
    NO_STAGE5_INVOCATION = "NO_STAGE5_INVOCATION"
    FOREIGN_IS_UNTRUSTED_EVEN_SIGNED = "FOREIGN_IS_UNTRUSTED_EVEN_SIGNED"
    MAJORITY_IS_NOT_TRUTH = "MAJORITY_IS_NOT_TRUTH"
    NO_UNBOUNDED_IDENTITY_INFLUENCE = "NO_UNBOUNDED_IDENTITY_INFLUENCE"
    NO_RAW_HOST_DATA_EXPORT = "NO_RAW_HOST_DATA_EXPORT"
    EVERY_IMPORT_REJECTABLE_EXPIRABLE_REVOCABLE = "EVERY_IMPORT_REJECTABLE_EXPIRABLE_REVOCABLE"
    LOCAL_PROTECTION_SURVIVES_NETWORK_LOSS = "LOCAL_PROTECTION_SURVIVES_NETWORK_LOSS"
    LOCAL_SOVEREIGNTY = "LOCAL_SOVEREIGNTY"             # no collective outcome changes a local decision without local evidence
    NO_FOREIGN_NORMALITY = "NO_FOREIGN_NORMALITY"       # ADR-0063

@dataclass(frozen=True, slots=True)
class LawBinding:
    law: CollectiveLaw
    enforced_by: str        # "pocketsec.stage7.<module>:<qualname>" — importlib-resolvable
    tested_by: str          # "tests/test_stage7_<key>.py::test_<name>" — the file must define that test
    statement: str

COLLECTIVE_CONSTITUTION: tuple[LawBinding, ...]    # exactly one binding per CollectiveLaw
COLLECTIVE_EXCHANGE_ENABLED: bool = False          # §28: Stage 7 is an accelerator, not a dependency; off by default
def verify_collective_constitution() -> tuple[str, ...]
    # resolves every enforced_by with importlib (lazily; packages build in parallel), checks each
    # tested_by file exists and defines the named function (ast), returns problems; () = all resolve
```

Required bindings (the `enforced_by` → `tested_by` pairs are fixed here so packages agree):

| law | enforced_by | tested_by |
|---|---|---|
| NO_DIRECT_TRUSTED_WRITE | `hivelock.stage6_bridge:Stage6Bridge.hand_over` | `tests/test_stage7_boundary.py::test_no_stage7_module_names_a_stage6_writer` |
| NO_STAGE5_INVOCATION | `capsule.knowledge_capsule:authority_key_violations` | `tests/test_stage7_boundary.py::test_no_stage7_module_imports_stage5` |
| FOREIGN_IS_UNTRUSTED_EVEN_SIGNED | `hivelock.ingress:HivelockIngress.receive` | `tests/test_stage7_ingress.py::test_a_validly_signed_capsule_is_only_ever_pooled` |
| MAJORITY_IS_NOT_TRUTH | `echo.inference:EchoEngine.infer` | `tests/test_stage7_echo.py::test_identity_count_does_not_raise_mass_within_a_cluster` |
| NO_UNBOUNDED_IDENTITY_INFLUENCE | `graph.dependence:DependenceGraph.observe` | `tests/test_stage7_graph.py::test_sybils_sharing_a_root_are_one_cluster` |
| NO_RAW_HOST_DATA_EXPORT | `privacy.distiller:residual_identifier_hits` | `tests/test_stage7_privacy.py::test_no_raw_fleet_string_survives_export` |
| EVERY_IMPORT_REJECTABLE_EXPIRABLE_REVOCABLE | `lineage.cross_host:RevocationPlane.submit` | `tests/test_stage7_sovereignty.py::test_revocation_marks_exactly_the_descendants` |
| LOCAL_PROTECTION_SURVIVES_NETWORK_LOSS | `orpheus.fabric:OrpheusFabric.run_round` | `tests/test_stage7_sovereignty.py::test_local_detection_is_identical_with_the_fabric_absent_offline_or_crashing` |
| LOCAL_SOVEREIGNTY | `echo.inference:EchoEngine.infer` | `tests/test_stage7_sovereignty.py::test_a_unanimous_fleet_cannot_change_a_local_decision` |
| NO_FOREIGN_NORMALITY | `capsule.knowledge_capsule:KnowledgeType` | `tests/test_stage7_foundation.py::test_no_knowledge_type_can_assert_normality` |

Bounds: pure data. Failure mode: a non-empty `verify_collective_constitution()` fails G7.1. A law
bound to a symbol that does not exist is a docstring.

### D7.2 (schema) — `KnowledgeCapsuleV1` `[foundation]`

```python
# pocketsec/stage7/capsule/knowledge_capsule.py
KNOWLEDGE_CAPSULE_V1_ID = "pocketsec.knowledge_capsule.v1"
KNOWLEDGE_CAPSULE_V1_VERSION = register_schema(KNOWLEDGE_CAPSULE_V1_ID, "1.0.0")

class KnowledgeType(StrEnum):      # architecture §5 minus the two with no consumer (ADR-0062)
    ANTIBODY = "ANTIBODY"                       # consumer: ECHO → bridge → Stage 6
    NOVELTY = "NOVELTY"                         # consumer: collective novelty engine (advisory)
    CAMPAIGN_FRAGMENT = "CAMPAIGN_FRAGMENT"     # consumer: hypergraph / reconstructor (advisory)
    NEGATIVE_EVIDENCE = "NEGATIVE_EVIDENCE"     # consumer: consensus falsifier (§19)
    REVOCATION = "REVOCATION"                   # consumer: RevocationPlane
    # DRIFT_NOTICE: context only, and epoch context already rides on every capsule → no consumer.
    # MODEL_DELTA: Stage 6's learner is parameter-free (ADR-0050) → nothing to apply a delta to.
    # Both are REFUSED as unknown types; S7X-48/49 (model replacement, backdoor adapter) are
    # refused by construction and the catalogue records them so.

class Stance(StrEnum): SUPPORT = "SUPPORT"; CONTEST = "CONTEST"
class RoleClass(StrEnum): WEB = "WEB"; DEV = "DEV"; ADMIN = "ADMIN"; DESKTOP = "DESKTOP"; UNKNOWN = "UNKNOWN"
class VisibilityClass(StrEnum): FULL = "FULL"; PARTIAL = "PARTIAL"; LOW = "LOW"
class ChainStage(StrEnum): ACCESS = "ACCESS"; CREDENTIAL = "CREDENTIAL"; ELEVATION = "ELEVATION"; PERSISTENCE = "PERSISTENCE"; EGRESS = "EGRESS"; OTHER = "OTHER"
class RevocationGround(StrEnum): SELF_RETRACTION = "SELF_RETRACTION"; LOCAL_EVIDENCE = "LOCAL_EVIDENCE"

@dataclass(frozen=True, slots=True)
class MotifRow:                      # == stage6 MotifStep.to_payload(); four non-negative ints
    relation: int; require_properties: int; forbid_properties: int; require_raised: int
    def to_motif_step(self) -> MotifStep
    @classmethod
    def from_motif_step(cls, step: MotifStep) -> MotifRow

@dataclass(frozen=True, slots=True)
class EpochContext:            # architecture "epoch_context"
    software_epoch: str        # "se-" + 16 hex (privacy.distiller.software_epoch_class)
    visibility: VisibilityClass

@dataclass(frozen=True, slots=True)
class SourceContextSketch:     # architecture "source_context_sketch"
    role: RoleClass
    family_profile: tuple[int, ...]   # len == len(RelationFamily); each 0..FAMILY_PROFILE_LEVELS-1

@dataclass(frozen=True, slots=True)
class ValidationSummary:       # SELF-REPORTED by the contributor; the receiver never trusts it as evidence
    episodes_replayed: int; true_matches: int; false_matches: int

@dataclass(frozen=True, slots=True)
class FalsificationSummary:    # SELF-REPORTED
    mutations_tried: int; mutations_survived: int     # survived <= tried
    counter_hypotheses: tuple[str, ...]               # CounterHypothesis values; <= 6

@dataclass(frozen=True, slots=True)
class ProvenanceCommitment:    # architecture "provenance_commitment" — knowledge without it is refused
    contributor: str                          # "peer-" + 16 hex pseudonym
    provenance_root: str                      # "root-" + 16 hex; a DECLARED administrative domain
    evidence_commitments: tuple[str, ...]     # "hc-" + 32 hex keyed commitments; 1..MAX_EVIDENCE_COMMITMENTS, distinct
    aggregation_decision: str | None          # "agg-" + 32 hex EchoDecision id for a derived capsule; None for originals

@dataclass(frozen=True, slots=True)
class ObservabilityClaim:      # NEGATIVE_EVIDENCE only (§19); each value in [0,1]
    expected_observability: float; sensor_health: float; temporal_coverage: float

@dataclass(frozen=True, slots=True)
class KnowledgeCapsuleV1:
    capsule_id: str                              # "kc-" + 24 hex over the unsigned payload minus capsule_id; derived, checked
    knowledge_type: KnowledgeType
    stance: Stance                               # CONTEST only on ANTIBODY; every other type SUPPORT
    semantic_invariant: tuple[MotifRow, ...]     # 1..MAX_MOTIF_LENGTH rows; () iff REVOCATION
    compact_feature_signature: str               # "mf-" + 16 hex of the invariant; "" iff REVOCATION; derived, checked
    causal_motif: tuple[ChainStage, ...]         # derive_chain_stages(invariant); derived, checked
    attack_mappings: tuple[str, ...]             # ALWAYS () in v1 — "if evidenced", and nothing is (ADR-0065)
    epoch_context: EpochContext
    source_context_sketch: SourceContextSketch
    validation_summary: ValidationSummary
    falsification_summary: FalsificationSummary
    provenance_commitment: ProvenanceCommitment
    independence_group: str                      # must equal provenance_commitment.provenance_root (declared claim)
    privacy_class: PrivacyClass                  # must be PUBLIC_DERIVED
    created_round: int
    expiry_round: int                            # created_round < expiry_round <= created_round + MAX_EXPIRY_HORIZON_ROUNDS
    sequence: int                                # per key_id, strictly increasing (replay)
    parent_capsules: tuple[str, ...]             # "kc-" ids, distinct, <= MAX_PARENT_CAPSULES
    time_window: tuple[int, int] | None          # CAMPAIGN_FRAGMENT / NEGATIVE_EVIDENCE only; lo <= hi, hi-lo <= MAX_WINDOW_ROUNDS
    observability: ObservabilityClaim | None     # NEGATIVE_EVIDENCE only
    revocation_target: str | None                # REVOCATION only: "kc-" id
    revocation_ground: RevocationGround | None   # REVOCATION only
    key_id: str                                  # "key-" + 16 hex
    signature: str                               # hex HMAC-SHA256 of unsigned_bytes(); "" = unsigned
    schema_version: str = KNOWLEDGE_CAPSULE_V1_VERSION

    def unsigned_bytes(self) -> bytes    # canonical JSON of to_dict() without "signature"
    def canonical_bytes(self) -> bytes   # sorted keys, compact separators, allow_nan=False, trailing "\n"
    def digest(self) -> str              # "sha256:" of canonical_bytes()
    def to_dict(self) -> dict[str, Any]  # adds "schema_id"
    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> KnowledgeCapsuleV1   # strict: exact keys at every depth, no coercion
    @classmethod
    def from_bytes(cls, data: bytes) -> KnowledgeCapsuleV1                  # refuses len > MAX_KNOWLEDGE_CAPSULE_BYTES BEFORE json.loads

def seal_capsule(**fields: Any) -> KnowledgeCapsuleV1       # derives capsule_id, signature, compact_feature_signature, causal_motif
def motif_fingerprint(rows: Sequence[MotifRow]) -> str      # "mf-" + 16 hex
def derive_chain_stages(rows: Sequence[MotifRow]) -> tuple[ChainStage, ...]
    # per row, bit positions from stage2 feature_names(): CREDENTIAL if the object props include CREDENTIAL or
    # CREDENTIAL_READER; ELEVATION if raised includes the privilege dimension; PERSISTENCE if PERSISTENCE or
    # PERSISTENCE_WRITER; EGRESS if EXTERNAL_ENDPOINT; ACCESS if the relation's family is the access/read family;
    # else OTHER. One stage per row, the first that applies in that order.
def authority_key_violations(payload: object, *, prefix: str = "capsule") -> tuple[str, ...]
    # every key path at every depth whose lowercased key contains a FORBIDDEN_AUTHORITY_FIELDS member
WIRE_STRING_SHAPES: tuple[re.Pattern[str], ...]
    # the closed vocabulary of string values the wire may carry: the id shapes above, a 64-hex signature,
    # enum values of this module's enums and PrivacyClass, CounterHypothesis values, a semver.
```

**Construction refuses** (each case has a test named for it): an unknown `knowledge_type` or
`schema_id`/`schema_version` ("Unknown schema/version → reject", §43); any authority-named key at
any depth; a missing provenance element (no contributor, no root, zero commitments) ("knowledge
without provenance is refused"); `independence_group != provenance_root`; `privacy_class` other
than `PUBLIC_DERIVED`; a non-empty `attack_mappings`; a derived field that does not match its
derivation; `CONTEST` on a non-ANTIBODY type; type-specific fields on the wrong type; an
over-long window or expiry horizon; any string value outside `WIRE_STRING_SHAPES`.

Bounds: `MAX_KNOWLEDGE_CAPSULE_BYTES = 4096` ("KB-scale", §28). **The 10 KB, 100 KB and 1 MB
classes of §45 are refused before parsing by construction.** S7X-62 measures the cost of that
refusal, not a transfer.

### D7.2 (compiler) — `capsule/compiler.py` `[privacy]`

```python
@dataclass(frozen=True, slots=True)
class ExportContext:
    host_secret: bytes            # >= MIN_KEY_BYTES; derives the pseudonym and the commitment key; never exported
    identity: SystemIdentity      # consumed only through software_epoch_class()
    role: RoleClass
    provenance_root: str          # "root-..." this host declares
    key_id: str                   # the host's signing key id
    visibility_share: float       # [0,1]: 1 - share of recent local steps with observation_incomplete
    family_counts: Mapping[int, int]   # RelationFamily index -> local transition count (quantised on export)
    fleet_scope: str              # pseudonym scope; a new scope gives an unlinkable contributor id

def compile_capsule(
    *, knowledge_type: KnowledgeType, invariant: Sequence[MotifRow], evidence_digests: Sequence[str],
    validation: ValidationSummary, falsification: FalsificationSummary, context: ExportContext,
    ledger: PrivacyLedger, created_round: int, sequence: int, stance: Stance = Stance.SUPPORT,
    parents: Sequence[str] = (), aggregation_decision: str | None = None,
    time_window: tuple[int, int] | None = None, observability: ObservabilityClaim | None = None,
    revocation_target: str | None = None, revocation_ground: RevocationGround | None = None,
) -> KnowledgeCapsuleV1
    # UNSIGNED (signature=""); signing is Keyring.sign. Charges ledger.charge(knowledge_type.value, ...)
    # BEFORE sealing (budget exhaustion raises PrivacyBudgetExhausted; nothing is produced).
    # Evidence digests (sha256:...) become commitments via distiller.evidence_commitment; raw digests
    # never appear in the result. Runs residual_identifier_hits on the result and raises on any hit.
def invariants_from_learning_record(record: LearningRecordV1) -> tuple[tuple[MotifRow, ...], ...]
    # the Stage 6 -> 7 handoff: DETECTOR rows with status ACTIVE and simulated False only
    # (simulated rows are refused: a simulated detection is not shared as knowledge, ADR-0046 precedent)
```

### D7.3 — Privacy Distiller + Privacy Ledger `[privacy]`

**What leaves the host, by field (ADR-0065).** `EXPORT_FIELD_TABLE` is the exact set of
flattened wire key paths of `KnowledgeCapsuleV1.to_dict()`. A test asserts that
`set(flatten_keys(capsule.to_dict())) == set(EXPORT_FIELD_TABLE)` for every knowledge type. An
undeclared field cannot leave.

| wire field | disclosure class | what it reveals, and why it is allowed |
|---|---|---|
| `schema_id`, `schema_version`, `knowledge_type`, `stance`, `capsule_id`, `signature`, `key_id`, `sequence`, `created_round`, `expiry_round` | PROTOCOL | protocol state; `sequence` reveals the host's export volume (declared) |
| `semantic_invariant` (4 ints per row), `compact_feature_signature`, `causal_motif` | SEMANTIC_CLASS | relation id and SemanticProperty / dimension **bitmasks** only: no path, name, address, uid, pid, time or count |
| `epoch_context.software_epoch` | COARSE_CONTEXT | unkeyed hash of `(kernel_id, package_digest)`. **Linkable across hosts that share an image, by design**: it is the §9 "same software image" signal. Declared, not hidden |
| `epoch_context.visibility` | COARSE_CONTEXT | 3-level visibility class |
| `source_context_sketch.role` | COARSE_CONTEXT | the host's role class. **Disclosed by design** (epistemic distance needs it) |
| `source_context_sketch.family_profile` | COARSE_CONTEXT | per relation family, a 4-level quantised share of local transitions. A property-inference channel; G7.7(d) measures it |
| `validation_summary.*`, `falsification_summary.*` | SELF_REPORTED_COUNT | small counts; unverifiable by the receiver |
| `provenance_commitment.contributor` | PSEUDONYM | `"peer-" + HMAC(host_secret, "contributor:" + fleet_scope)[:16]`. **All capsules from one host in one scope are linkable, by design** (replay and independence need it) |
| `provenance_commitment.provenance_root`, `independence_group` | PSEUDONYM | declared domain id |
| `provenance_commitment.evidence_commitments` | COMMITMENT | `"hc-" + HMAC(host_secret, "evidence:" + digest)[:32]`. A peer cannot test membership of an evidence digest it guesses. The contributor can later open it |
| `provenance_commitment.aggregation_decision`, `parent_capsules`, `revocation_target` | PROTOCOL | ids of Stage 7 objects |
| `time_window` | COARSE_CONTEXT | round interval (rounds, not timestamps: "minimum useful resolution", §6) |
| `observability.*` | COARSE_CONTEXT | three [0,1] floats |
| `revocation_ground` | PROTOCOL | enum |
| `attack_mappings`, `privacy_class` | PROTOCOL | constants (`()`, `PUBLIC_DERIVED`) |

**Never leaves** (enforced by the residual screen, and tested with canaries): raw event fields
(paths, addresses, ports, uids, pids, command lines), `EncodedStep.features` (novelty, timing and
uncertainty groups are host-baseline dependent), `time_bucket`, `delta_phi`, `source_group`,
`causal_signature`/`parent_signature`, raw `sha256:` evidence digests, capsule ids of Stage 6
(`cap-…`), Stage 6 source groups (`grp-…`), `SystemIdentity` fields in clear, labels, and any
baseline/normality anchor.

```python
# pocketsec/stage7/privacy/distiller.py
class Disclosure(StrEnum): PROTOCOL, SEMANTIC_CLASS, COARSE_CONTEXT, SELF_REPORTED_COUNT, PSEUDONYM, COMMITMENT
@dataclass(frozen=True, slots=True)
class FieldDisclosure: path: str; disclosure: Disclosure; rationale: str
EXPORT_FIELD_TABLE: Mapping[str, FieldDisclosure]
def flatten_keys(payload: Mapping[str, Any], *, prefix: str = "") -> tuple[str, ...]   # "a.b" paths; list items share their parent path
def software_epoch_class(identity: SystemIdentity) -> str          # "se-" + sha256(kernel_id + "|" + package_digest)[:16]
def contributor_pseudonym(host_secret: bytes, fleet_scope: str) -> str
def evidence_commitment(host_secret: bytes, digest: str) -> str    # refuses a non-"sha256:<64hex>" digest
def distil_context(*, identity: SystemIdentity, role: RoleClass, visibility_share: float,
                   family_counts: Mapping[int, int]) -> tuple[EpochContext, SourceContextSketch]
    # visibility: FULL >= 0.9, PARTIAL >= 0.5, else LOW; family_profile: share of total -> 4 levels
    # (0: 0, 1: (0, 0.1], 2: (0.1, 0.4], 3: > 0.4)
@dataclass(frozen=True, slots=True)
class DistillationReport: fields_generalised: tuple[str, ...]; residual_hits: tuple[str, ...]; canary_hits: tuple[str, ...]
def residual_identifier_hits(payload: object, *, prefix: str = "capsule") -> tuple[str, ...]
    # every string value outside WIRE_STRING_SHAPES, plus SECRET_PATTERN matches — the constructive privacy screen
def canary_hits(blob: bytes, canaries: Iterable[str]) -> tuple[str, ...]  # substring search, bounded to MAX_CANARY_REPORT names
```

```python
# pocketsec/stage7/privacy/ledger.py
class PrivacyBudgetExhausted(RuntimeError): ...
@dataclass(frozen=True, slots=True)
class PrivacyLedgerEntry:                     # architecture §29, every row bound
    representation_type: str                  # a KnowledgeType value, or "novelty_counts"
    sensitivity_class: PrivacyClass
    recipient_scope: str                      # the fleet scope
    release_count: int
    dp_epsilon: float | None                  # None when no DP was applied to this representation
    dp_delta: float | None                    # always None: the geometric mechanism is pure-ε
    inference_test_results: tuple[tuple[str, float], ...]   # (test name, advantage) recorded by labs, <= 8
    expiry_round: int                         # window end
class PrivacyLedger:
    def __init__(self, *, capacity: int = MAX_LEDGER_ENTRIES, epsilon_budget: float = EPSILON_BUDGET,
                 window_rounds: int = PRIVACY_WINDOW_ROUNDS, max_releases: int = MAX_RELEASES_PER_WINDOW) -> None
    def charge(self, representation_type: str, *, recipient_scope: str, round_index: int,
               epsilon: float | None = None) -> PrivacyLedgerEntry          # raises PrivacyBudgetExhausted
    def record_inference_test(self, representation_type: str, *, recipient_scope: str, name: str, advantage: float) -> None
    def entries(self) -> tuple[PrivacyLedgerEntry, ...]
    def evictions(self) -> int
    def memory_bytes(self) -> int
def geometric_noise(epsilon: float, *, sensitivity: int = 1, rng: random.Random | None = None) -> int
    # two-sided geometric (discrete Laplace), integer output: no float-snapping channel. rng defaults to
    # secrets.SystemRandom(); a seeded Random (labs, for reproducibility) is NOT private and the report says so.
def release_counts(counts: Mapping[str, int], *, epsilon: float | None, ledger: PrivacyLedger,
                   recipient_scope: str, round_index: int, rng: random.Random | None = None) -> dict[str, int]
    # each host contributes 0/1 per pattern per round (sensitivity 1, enforced by the caller's clamp);
    # epsilon None = exact counts (the control); charges the ledger once per release (basic composition)
```

**What DP is claimed for, exactly (ADR-0065).** Only the per-round population count release that
feeds collective novelty (D7.14). The claim is pure ε-DP per release, under a per-host per-pattern
contribution clamp of 1, with basic composition across releases. It rests on the ledger's budget
enforcement. It is not formally verified. Timing side channels are UNMEASURED, and a seeded RNG
voids the guarantee. **No DP is claimed for knowledge capsules.** Their privacy is generalisation
plus commitments, and G7.7 measures it by attack, not by a label.

### D7.4 — Peer Identity / Integrity plane `[ingress]`

```python
# pocketsec/stage7/identity/peer.py
@dataclass(frozen=True, slots=True)
class PeerIdentity:
    peer_id: str            # "peer-" + 16 hex (== the capsule's contributor)
    key_id: str
    provenance_root: str    # DECLARED; the lab knows the true root, the endpoint never does
    role_claim: RoleClass
    first_seen_round: int
    last_seen_round: int
class PeerTable:
    def __init__(self, *, capacity: int = MAX_PEERS, idle_rounds: int = PEER_IDLE_ROUNDS) -> None
    def observe(self, peer_id: str, *, key_id: str, provenance_root: str, role_claim: RoleClass,
                round_index: int) -> PeerIdentity | None
        # full table: evict the least-recently-seen entry ONLY if it has been idle > idle_rounds
        # (recorded in a bounded eviction log); otherwise REFUSE the newcomer (None, counted).
        # A flood of fresh identities can therefore never evict established peers.
    def get(self, peer_id: str) -> PeerIdentity | None
    def refused(self) -> int; def evictions(self) -> int; def eviction_log(self) -> tuple[tuple[str, int], ...]
    def memory_bytes(self) -> int
```

```python
# pocketsec/stage7/identity/integrity.py
class KeyState(StrEnum): ACTIVE = "ACTIVE"; ROTATED = "ROTATED"; REVOKED = "REVOKED"
@dataclass(frozen=True, slots=True)
class KeyRecord: key_id: str; owner: str; state: KeyState; not_after_round: int | None
@dataclass(frozen=True, slots=True)
class IntegrityVerdict: valid: bool; reason: str   # "ok"|"unsigned"|"unknown_key"|"revoked_key"|"expired_key"|"bad_signature"|"contributor_key_mismatch"
class Keyring:
    def __init__(self, *, capacity: int = MAX_KEYS) -> None
    def register(self, key_id: str, key: bytes, *, owner: str, round_index: int) -> None   # len(key) >= MIN_KEY_BYTES; full -> ContractError
    def rotate(self, old_key_id: str, new_key_id: str, new_key: bytes, *, round_index: int,
               grace_rounds: int = KEY_GRACE_ROUNDS) -> None
    def revoke(self, key_id: str, *, round_index: int) -> None
    def sign(self, capsule: KnowledgeCapsuleV1, *, key_id: str) -> KnowledgeCapsuleV1       # HMAC-SHA256 hex over unsigned_bytes()
    def verify(self, capsule: KnowledgeCapsuleV1, *, round_index: int) -> IntegrityVerdict  # hmac.compare_digest; owner == contributor
    def owner_of(self, key_id: str) -> str | None
    def state_digest(self) -> str             # sha256 over sorted records (keys hashed, never exported)
    def verify_state(self, expected_digest: str) -> bool   # the fabric's "trust store corrupt" check (§43)
    def memory_bytes(self) -> int
class ReplayGuard:
    def __init__(self, *, max_keys: int = MAX_REPLAY_KEYS, max_seen: int = MAX_SEEN_CAPSULES) -> None
    def check(self, capsule: KnowledgeCapsuleV1, *, round_index: int) -> str | None
        # "duplicate_capsule" | "replayed_sequence" (sequence <= high-water for key_id) | "expired" | "not_yet_valid"
    def admit(self, capsule: KnowledgeCapsuleV1) -> None   # records high-water and seen id; both LRU-bounded, evictions counted
    def evictions(self) -> tuple[int, int]; def memory_bytes(self) -> int
```

**What HMAC proves (ADR-0064), stated once and in every docstring that signs.** A valid signature
proves that *someone holding the key registered as `key_id`* produced these bytes unaltered. With
simulated pre-provisioned pairwise keys (`labs/simulated_fleet.py:simulated_key_provisioning`),
that is **key possession, not host identity**. A stolen key is a full impersonation. Asymmetric
signatures (Ed25519) need a third-party library (ADR-0001), and **real identity binding is
UNMEASURED**. **Known residual (tested):** replay of a capsule whose key's high-water entry and
seen-id entry were both evicted is caught only by `expiry_round`. The replay window is therefore
bounded by `MAX_EXPIRY_HORIZON_ROUNDS`, and a test demonstrates the bound.

### D7.5 — Epistemic Distance `[graph]`

```python
# pocketsec/stage7/relevance/epistemic_distance.py
@dataclass(frozen=True, slots=True)
class LocalContext:             # the receiving host, never exported
    role: RoleClass; software_epoch: str; visibility: VisibilityClass; family_profile: tuple[int, ...]
    local_keys: frozenset[str]            # antibody keys of LOCAL-origin knowledge (sovereignty)
    observable_relations: frozenset[int]  # relations this host's sensors can observe (visibility adjustment)
@dataclass(frozen=True, slots=True)
class EpistemicDistance:
    total: float; role: float; software_epoch: float; visibility: float; behaviour: float
    policy: None; architecture: None      # UNMEASURED — no exported representation exists (lesson 3; ADR-0065)
DISTANCE_WEIGHTS: Mapping[str, float]    # role 1.0, software_epoch 0.25, visibility 0.25, behaviour 0.5
def epistemic_distance(sketch: SourceContextSketch, epoch: EpochContext, local: LocalContext, *,
                       enabled: bool = True) -> EpistemicDistance
    # role: 0 same, 0.5 if either UNKNOWN, else 1.0; software_epoch: 0/1 equality; visibility: level difference / 2;
    # behaviour: L1 distance of family_profile / (3 * len); total = sum(w_i * term_i).
    # enabled=False is the CONTROL: total = role term only (role equality).
def relevance(distance: EpistemicDistance) -> float     # 1 / (1 + total)
```

Architecture §7's six terms are bound as follows. `role_distance`, `software_epoch_distance`,
`telemetry_visibility_distance` and `behavior_distribution_distance` are built as above.
`policy_distance` and `architecture_distance` are **not built**: no exported field carries them,
and exporting a policy digest would be new disclosure with no consumer. Both appear in the
UNMEASURED ledger.

### D7.6 — Knowledge Gravity `[graph]`

```python
# pocketsec/stage7/relevance/gravity.py
@dataclass(frozen=True, slots=True)
class KnowledgeGravity:
    value: float; validation: float; independence: float; compatibility: float; recency: float
    distance: float; suspicion: float
def knowledge_gravity(capsule: KnowledgeCapsuleV1, *, distance: EpistemicDistance, independence: float,
                      suspicion: float, local: LocalContext, round_index: int) -> KnowledgeGravity
    # validation   = (true_matches + 1) / (true_matches + false_matches + 2)   — SELF-REPORTED, forgeable (declared)
    # independence = 1 / size of the contributor's dependence cluster (DependenceGraph.independence)
    # compatibility= 1.0 if every invariant relation is in local.observable_relations else 0.0 (visibility adjustment)
    # recency      = max(0, 1 - (round_index - created_round) / MAX_EXPIRY_HORIZON_ROUNDS)
    # value = validation*independence*compatibility*recency / (1 + distance.total + suspicion)
```

`PrivacyCost(K)` in §8's denominator is **not bound**. The receiver cannot observe the sender's
disclosure cost. The sender-side `PrivacyLedger` enforces disclosure instead (ADR-0065).
Gravity's only effect is triage. A capsule with `value < VALIDATION_FLOOR` is `METADATA_ONLY`
(§4.7) and is never local-validated or pooled. **Control: validate everything** (gravity off).
The firing count is the number of capsules triaged to metadata. The measured value is local
validation work saved against detection lost (G7.11).

### D7.7 — HIVELOCK ingress `[ingress]`

```python
# pocketsec/stage7/hivelock/ingress.py
class IngressStage(StrEnum):
    SIZE_RATE, SCHEMA, INTEGRITY, REPLAY_EXPIRY, PROVENANCE, PRIVACY, DEPENDENCE, SUSPICION, RELEVANCE, POOLED
class IngressOutcome(StrEnum): REFUSED = "REFUSED"; METADATA_ONLY = "METADATA_ONLY"; POOLED = "POOLED"; ROUTED_REVOCATION = "ROUTED_REVOCATION"
@dataclass(frozen=True, slots=True)
class IngressVerdict:
    verdict_id: str                 # "iv-" + 32 hex over (raw_digest, outcome, reasons, received_round)
    raw_digest: str                 # sha256 of the received bytes — the LOCAL evidence digest of this foreign object
    capsule_id: str | None          # None if refused before SCHEMA
    outcome: IngressOutcome
    stage_reached: IngressStage
    reasons: tuple[str, ...]
    peer_id: str | None
    cluster_id: str | None
    gravity: float | None
    received_round: int
@dataclass(frozen=True, slots=True)
class PooledCapsule:
    capsule: KnowledgeCapsuleV1; raw_digest: str; peer_id: str; cluster_id: str; relevance: float
    gravity: float; received_round: int
class HivelockIngress:
    def __init__(self, *, keyring: Keyring, replay: ReplayGuard, peers: PeerTable, governor: CommunicationGovernor,
                 cluster_of: Callable[[KnowledgeCapsuleV1, PeerIdentity, int], str],
                 relevance_of: Callable[[KnowledgeCapsuleV1], float],
                 gravity_of: Callable[[KnowledgeCapsuleV1, str, int], float],
                 lineage_resolves: Callable[[str], bool] = lambda _id: False,
                 local_keys: Callable[[], frozenset[str]] = frozenset,
                 gravity_floor: float = VALIDATION_FLOOR, gravity_enabled: bool = True,
                 meter: WorkMeter | None = None) -> None
        # the graph, relevance and lineage are INJECTED callables: ingress imports no graph/echo/lineage module,
        # so package order stays acyclic; orpheus/fabric.py wires the real ones.
    def receive(self, data: bytes, *, sender: str, round_index: int) -> IngressVerdict
    def drain_pool(self) -> tuple[PooledCapsule, ...]
    def drain_revocations(self) -> tuple[tuple[KnowledgeCapsuleV1, str], ...]   # (capsule, peer_id)
    def metadata(self) -> tuple[tuple[str, str, float], ...]                      # (capsule_id, peer_id, gravity), bounded ring
    def stats(self) -> Mapping[str, int]      # offered, refused:<stage>:<reason>, pooled, metadata_only, routed_revocation
    def memory_bytes(self) -> int
```

`receive`'s pipeline follows §21 in exactly this order. Each stage is recorded in `reasons`, and
the first refusal ends the call:

1. **SIZE_RATE**: `governor.admit_inbound(sender, len(data), round_index=…)`. This covers
   oversize (> `MAX_KNOWLEDGE_CAPSULE_BYTES`, **before parsing**), per-sender byte and count caps,
   inbox caps and partition mode.
2. **SCHEMA**: `KnowledgeCapsuleV1.from_bytes`. `ContractError`, `ValueError` or `UnicodeError`
   is a REFUSED with the error class and at most 60 characters of message.
3. **INTEGRITY**: `keyring.verify`. `contributor` must be the key's owner.
4. **REPLAY_EXPIRY**: `replay.check`. On pass, `replay.admit`.
5. **PROVENANCE**: the provenance commitment is complete (schema guaranteed). A capsule with
   `aggregation_decision` or `parent_capsules` must have every parent resolve through
   `lineage_resolves`. Otherwise `unresolvable_lineage` (S7X-46, lineage tamper).
6. **PRIVACY**: `residual_identifier_hits(capsule.to_dict()) == ()`. Defence in depth, since the
   schema already constrains strings.
7. **DEPENDENCE**: `peers.observe(...)`. A refused newcomer is REFUSED `peer_table_full`. Then
   `cluster_id = cluster_of(capsule, peer, round_index)`.
8. **SUSPICION** (the sovereignty and direction rules): an ANTIBODY `CONTEST` or a REVOCATION
   whose key or target is in `local_keys()` is REFUSED `local_sovereignty`. A REVOCATION goes to
   the bounded revocation inbox (`ROUTED_REVOCATION`) and never to the pool.
9. **RELEVANCE**: `gravity = gravity_of(capsule, cluster_id, round_index)`. If `gravity_enabled`
   and `gravity < gravity_floor`, the result is `METADATA_ONLY`, kept in a bounded metadata ring.
10. **POOLED**: appended to the bounded pool (`MAX_POOL_CAPSULES`). If the pool is full, the
    newcomer is refused and counted. Nothing is evicted.

**`IngressVerdict` never promotes and never marks anything trusted.** Its best outcome is
`POOLED`: candidate evidence for ECHO.

### D7.8 — Dependence / Sybil graph, and contextual trust `[graph]`

```python
# pocketsec/stage7/graph/dependence.py
class EdgeKind(StrEnum):
    SAME_ROOT = "SAME_ROOT"                 # declared provenance root equal — always merges
    NEAR_IDENTICAL = "NEAR_IDENTICAL"       # same compact_feature_signature AND identical validation, falsification
                                            # summaries AND source_context_sketch — a copy/relay; merges
    COMMON_PARENT = "COMMON_PARENT"         # both contributed capsules derived from the same parent capsule; merges
    BIRTH_CO_TIMING = "BIRTH_CO_TIMING"     # first seen within BIRTH_WINDOW_ROUNDS in a burst >= BURST_MIN AND Jaccard of
                                            # their (antibody_key, round) contribution sets >= CO_TIMING_JACCARD over
                                            # >= CO_TIMING_MIN_EVENTS events; merges
    # "same software image" is NOT an edge: merging every host of one image would erase honest independence.
@dataclass(frozen=True, slots=True)
class DependenceEdge: a: str; b: str; kind: EdgeKind; first_round: int
class DependenceGraph:
    def __init__(self, *, max_peers: int = MAX_GRAPH_PEERS, max_edges_per_peer: int = MAX_EDGES_PER_PEER,
                 max_history: int = MAX_CONTRIBUTION_HISTORY_PER_PEER, clustering: bool = True) -> None
        # clustering=False is the CONTROL: SAME_ROOT only (declared roots are trusted as independence)
    def observe(self, capsule: KnowledgeCapsuleV1, peer: PeerIdentity, *, round_index: int) -> str
        # records contribution history, derives edges, union-find merge; returns "cl-" + 16 hex of the
        # cluster's canonical representative (lexicographically smallest peer id)
    def cluster_of(self, peer_id: str) -> str
    def clusters(self) -> tuple[tuple[str, tuple[str, ...]], ...]
    def independence(self, peer_id: str) -> float          # 1 / cluster size
    def edges(self) -> tuple[DependenceEdge, ...]
    def merges_by_kind(self) -> Mapping[EdgeKind, int]      # firing counts
    def evictions(self) -> int                               # peers beyond max_peers: refuse newcomers (they are
                                                             # their own singleton cluster, counted) — never evict
    def memory_bytes(self) -> int
```

```python
# pocketsec/stage7/graph/sybil.py
@dataclass(frozen=True, slots=True)
class SybilReport:
    peers: int; clusters: int; largest_cluster_share: float
    suspected_clusters: tuple[str, ...]      # size >= SYBIL_MIN_CLUSTER merged across >= 2 declared roots by behaviour edges
    amplification: float | None              # None when the adversary's true root share is 0 (lab only)
    refused_peers: int
def sybil_report(graph: DependenceGraph, *, support_mass_by_peer: Mapping[str, float] | None = None,
                 adversary_peers: frozenset[str] | None = None, adversary_true_roots: int | None = None,
                 total_true_roots: int | None = None) -> SybilReport
def amplification_factor(adversary_mass_share: float, adversary_root_share: float) -> float | None
    # architecture §46 "Sybil influence amplification factor": (adversary share of accepted support mass) /
    # (adversary share of TRUE independent roots). 1.0 = identity count bought nothing; the naive majority's is ~S.
```

```python
# pocketsec/stage7/trust/contextual.py    — §22: Trust(peer, task, epoch) != global reputation
@dataclass(frozen=True, slots=True)
class TrustState: reliability: float; confirmations: int; refutations: int; last_round: int
class ContextualTrust:
    def __init__(self, *, capacity: int = MAX_TRUST_ENTRIES, prior: float = TRUST_PRIOR,
                 half_life_rounds: int = TRUST_HALF_LIFE_ROUNDS, enabled: bool = True) -> None
        # enabled=False is the CONTROL: reliability == prior for everyone
    def reliability(self, cluster_id: str, task: str, *, round_index: int) -> float
        # task = "-".join(causal_motif values); decays toward prior with the half-life; clamped [TRUST_FLOOR, TRUST_CEILING]
    def record(self, cluster_id: str, task: str, *, confirmed: bool, round_index: int) -> None
        # confirmation: +CONFIRM_STEP; refutation: multiply by REFUTE_FACTOR (asymmetric on purpose)
    def evictions(self) -> int; def memory_bytes(self) -> int
```

Trust **never removes local validation**. ECHO evaluates local validation independently of
reliability, and a test pins this. Trust is the slow-poisoning target (arm SLOW_POISON). If
reputation measurably raises poison acceptance, it is HARMFUL and ADR-0069 says so.

### D7.9 — Byzantine evidence benchmark suite: aggregator families `[echo]`, runner `[adversary]`

```python
# pocketsec/stage7/aggregation/robust.py
class Aggregator(StrEnum):
    NO_SHARING, MAJORITY, MEAN, MEDIAN, TRIMMED_MEAN, KRUM, MULTI_KRUM, BULYAN,
    VALIDATION_FILTER, ROOT_QUORUM, CENTRAL_FEED, ECHO
    # MEAN is FedAvg's aggregation rule applied to stance vectors: there are no parameters to average (ADR-0062).
@dataclass(frozen=True, slots=True)
class StanceMatrix:
    identities: tuple[str, ...]                 # rows: peer ids (identities, NOT clusters — that is the point)
    keys: tuple[str, ...]                       # columns: antibody keys
    values: tuple[tuple[int, ...], ...]         # +1 SUPPORT, -1 CONTEST, 0 silent
    roots: tuple[str, ...]                      # declared root per row (ROOT_QUORUM, CENTRAL_FEED)
def stance_matrix(pool: Sequence[PooledCapsule]) -> StanceMatrix           # bounded by the pool
def aggregate(matrix: StanceMatrix, method: Aggregator, *, clusters: Mapping[str, str] | None = None,
              local_ok: Callable[[str], bool] | None = None, feed_root: str | None = None,
              byzantine_share: float = BYZANTINE_ASSUMED_SHARE, trim: float = TRIM_SHARE,
              quorum: int = MIN_QUORUM) -> AggregateResult
@dataclass(frozen=True, slots=True)
class AggregateResult: method: Aggregator; accepted: tuple[str, ...]; refused_reason: str | None; excluded_identities: tuple[str, ...]
```

Semantics. These are fixed so the comparison is exact. "Voters" of a key are the identities with
a non-zero stance on it.

- MAJORITY: accept iff sum of voter stances > 0 and voters ≥ `quorum`.
- MEAN: mean over voters > `ACCEPT_LEVEL` (0.0) and voters ≥ `quorum`.
- MEDIAN: the median over voters is > 0.
- TRIMMED_MEAN: drop ⌊`trim`·n⌋ of the voters from each end, then take the mean.
- KRUM, MULTI_KRUM, BULYAN operate on full identity vectors (silent = 0) with
  `f = max(1, ⌊byzantine_share · n⌋)`. KRUM selects one vector. MULTI_KRUM averages the
  m = n − f best. BULYAN applies Multi-Krum selection, then a coordinate-wise trimmed mean.
  Accept a key iff the aggregated coordinate > 0. When the method's `n` precondition fails
  (Krum n ≤ 2f+2, Bulyan n < 4f+3), `refused_reason` is set and nothing is accepted.
- VALIDATION_FILTER: accept any key with ≥ 1 SUPPORT whose `local_ok(key)` is True. No
  aggregation at all.
- ROOT_QUORUM: `local_ok` holds and at least 2 distinct `clusters` support, with supporting
  clusters strictly outnumbering contesting clusters. This is the dumbest Sybil-robust control.
- CENTRAL_FEED: accept keys supported by `feed_root` with `local_ok`.
- NO_SHARING: accept nothing.
- ECHO is not computed here. It is `echo/inference.py`. The suite reads its ELIGIBLE set.

Every non-ECHO method is also reported **"+LV"**: its accepted set intersected with `local_ok`.
This isolates what aggregation adds over local validation (lesson 4). The central raw-log SIEM
baseline is lab-only (`labs/byzantine_suite.py:siem_oracle`). The receiver forges antibodies from
*every* host's raw labelled episodes. That is the detection upper bound at the maximum privacy
cost: every canary leaves.

### D7.10 — ECHO collective inference `[echo]`

```python
# pocketsec/stage7/echo/inference.py
class EchoStatus(StrEnum):
    ELIGIBLE = "ELIGIBLE"            # may be handed to Stage 6 — as a candidate, never as trusted
    INSUFFICIENT = "INSUFFICIENT"    # not enough independent evidence — a valid, common answer
    CHALLENGED = "CHALLENGED"        # local evidence contradicts it (local FP) — local dominates, kept as challenged
    SUSPECT = "SUSPECT"              # an ancestor is revoked (D7.16)
    REFUSED = "REFUSED"              # a local-origin key contested/revoked from outside (sovereignty), or malformed
@dataclass(frozen=True, slots=True)
class ClusterEvidence:
    cluster_id: str; stance: Stance; identities: int; capsule_ids: tuple[str, ...]   # <= 8
    reliability: float; relevance: float; falsification: float; mass: float         # mass is capped
@dataclass(frozen=True, slots=True)
class EchoDecision:
    decision_id: str                 # "agg-" + 32 hex over (antibody_key, status, evidence rows, round_index)
    antibody_key: str
    invariant: tuple[MotifRow, ...]
    status: EchoStatus
    local_validation: LocalValidation
    support_mass: float; contest_mass: float
    support_clusters: int; contest_clusters: int
    eligible_rounds: int             # consecutive rounds ELIGIBLE (probation)
    evidence: tuple[ClusterEvidence, ...]   # <= MAX_CLUSTERS_PER_DECISION, highest mass first
    truncated: bool
    reasons: tuple[str, ...]
    round_index: int
@dataclass(frozen=True, slots=True)
class EchoConfig:                    # every flag is an ablation switch (core_ids)
    cluster_cap: bool = True; dependence_clustering: bool = True; contextual_trust: bool = True
    epistemic_distance: bool = True; falsification_weight: bool = True; contest_mass: bool = True
    local_validation: bool = True; probation: bool = True
    cap: float = CLUSTER_CAP; mass_floor: float = MASS_FLOOR; contest_ratio: float = CONTEST_RATIO
    relevance_floor: float = RELEVANCE_FLOOR; probation_rounds: int = ECHO_PROBATION_ROUNDS
@dataclass(frozen=True, slots=True)
class EchoInference:
    round_index: int; decisions: tuple[EchoDecision, ...]; keys_tracked: int; keys_refused: int
    firing: tuple[tuple[str, int], ...]      # per mechanism: decisions that differ from the mechanism-off answer
class EchoEngine:
    def __init__(self, *, local: LocalContext, validator: LocalValidator, trust: ContextualTrust,
                 cluster_of: Callable[[str], str], config: EchoConfig = EchoConfig(),
                 meter: WorkMeter | None = None) -> None
    def offer(self, pooled: Sequence[PooledCapsule]) -> int        # per-key table; newcomers past caps refused, counted
    def mark_suspect(self, antibody_keys: Iterable[str]) -> None   # from the RevocationPlane
    def clear_suspect(self, antibody_keys: Iterable[str]) -> None  # reinstatement
    def infer(self, *, round_index: int) -> EchoInference
    def record_outcome(self, antibody_key: str, *, confirmed: bool, round_index: int) -> None
        # local observation after eligibility -> ContextualTrust.record for every supporting cluster
    def memory_bytes(self) -> int
```

**The decision per antibody key K**, in this order (§35–§37, bound):

1. If K ∈ `local.local_keys`, the result is REFUSED `local_origin` (local knowledge is never
   re-decided by foreign evidence). If K is suspect, the result is SUSPECT.
2. `lv = validator.validate(K.invariant)`. `LOCAL_FP` → **CHALLENGED**, whatever the support
   mass. This is the sovereignty rule and it has no override. `NOT_OBSERVABLE` → INSUFFICIENT
   `not_observable`.
3. Group contributions by `cluster_of(peer)`. With `dependence_clustering` off, group by
   declared root. For each cluster c and stance:
   `mass_c = min(cap, reliability_c × relevance_c × falsification_c)`. Here
   `relevance_c = max over its capsules of relevance`, and a cluster below `relevance_floor`
   contributes 0 ("split by epistemic context before averaging", §25).
   `falsification_c = (mutations_survived + 1) / (mutations_tried + 2)` (self-reported, clipped),
   and CONTEST clusters use 1.0. **Identity count inside a cluster never raises its mass**
   (§36).
4. `support_mass = Σ SUPPORT mass_c` and `contest_mass = Σ CONTEST mass_c`. **ELIGIBLE** iff
   `support_mass ≥ mass_floor` and `support_mass ≥ contest_ratio × contest_mass`, and K has been
   so for `probation_rounds` consecutive rounds (the timing-collusion defence: contests get time
   to arrive). Otherwise INSUFFICIENT, with the failing clause as reason.
5. `LOCAL_CONFIRMED` (K matches a locally confirmed incident) does not change the status. It is
   recorded as a trust confirmation. Local evidence is the only thing that ever confirms.

Architecture §37's `local_validation_c` multiplies every cluster by the same receiver-side
factor. It is therefore applied once, as a gate (step 2), and not as a per-cluster weight. That
is algebraically the same for 0/1 outcomes and avoids a graded score with no graded consumer.

### D7.11 — Knowledge Antibody Forge `[echo]`

```python
# pocketsec/stage7/antibody/forge.py
class LocalValidation(StrEnum): PASS = "PASS"; LOCAL_FP = "LOCAL_FP"; LOCAL_CONFIRMED = "LOCAL_CONFIRMED"; NOT_OBSERVABLE = "NOT_OBSERVABLE"
@dataclass(frozen=True, slots=True)
class LocalIncident:              # a LOCAL resolution labelled MALICIOUS (lab: ground truth — declared optimistic)
    incident_id: str; steps: tuple[EncodedStep, ...]; evidence_digests: tuple[str, ...]
class BenignRing:                 # locally-resolved benign episodes; bounded FIFO, evictions counted
    def __init__(self, *, capacity: int = MAX_BENIGN_EPISODES) -> None
    def add(self, steps: Sequence[EncodedStep]) -> None
    def episodes(self) -> tuple[tuple[EncodedStep, ...], ...]
    def evictions(self) -> int; def memory_bytes(self) -> int
class LocalValidator:
    def __init__(self, *, benign: BenignRing, incidents: Sequence[LocalIncident],
                 observable_relations: frozenset[int], fp_ceiling: int = LOCAL_FP_CEILING,
                 meter: WorkMeter | None = None) -> None
    def validate(self, invariant: Sequence[MotifRow]) -> LocalValidation
        # NOT_OBSERVABLE if some row's relation is not observable; LOCAL_FP if it matches > fp_ceiling benign
        # episodes; LOCAL_CONFIRMED if it matches a local incident; else PASS
@dataclass(frozen=True, slots=True)
class KnowledgeAntibody:
    antibody_key: str; invariant: tuple[MotifRow, ...]; chain: tuple[ChainStage, ...]
    validation: ValidationSummary; falsification: FalsificationSummary; minimised: bool
def forge_antibody(incident: LocalIncident, *, benign: BenignRing, minimise: bool = True, seed: int = 0,
                   meter: WorkMeter | None = None) -> KnowledgeAntibody | None
    # §13: candidates = single-step motifs over the incident's escalating steps (object props / raised non-zero)
    # plus same-actor ordered pairs (<= MAX_FORGE_CANDIDATES); keep those matching the incident and ALL
    # attack-preserving mutations and NO benign-ring episode and NO doppelganger mutation; if minimise, greedily
    # drop require_properties bits (<= MAX_BIT_DROPS) while those tests still hold; choose shortest, then fewest
    # bits, then lexicographic. None = no stable discriminative core (INSUFFICIENT is a valid output).
def copied_rule(incident: LocalIncident) -> KnowledgeAntibody | None
    # the CONTROL (§13 "a rule copied from the original host"): the first and last escalating steps of the
    # incident's most-escalating actor, full masks, no minimisation, no mutation tests
def mutate_incident(incident: LocalIncident, *, seed: int) -> tuple[tuple[tuple[EncodedStep, ...], ...],
                                                                  tuple[tuple[EncodedStep, ...], ...]]
    # (attack_preserving, doppelgangers), MUTATIONS_PER_INCIDENT each: preserving = drop non-escalating steps,
    # re-slot other actors, interleave benign-ring steps; doppelganger = split the escalating steps across two
    # actor slots (the attribution-only difference the ambiguous corpus is built on)
def matches(invariant: Sequence[MotifRow], steps: Sequence[EncodedStep]) -> bool   # stage6 match_motif, never a copy
def prototype_steps(invariant: Sequence[MotifRow], *, source_group: str) -> tuple[EncodedStep, ...]
    # one EncodedStep per row, actor_slot 0: relation one-hot at `relation`, relation-family one-hot at
    # family_of(Relation(relation)), object-semantics bits from require_properties, raised bits from require_raised,
    # every other feature 0.0 (no novelty, no timing, no uncertainty); object_property_mask=require_properties,
    # state_delta_mask=require_raised; time_bucket 0, delta_phi 0.0, uncertainty 0.0, epoch_id 0,
    # causal/parent signature "", evidence (). INVARIANT (tested): matches(invariant, prototype_steps(invariant)).
```

**The §14 match formula, bound and reduced (ADR-0062).**
`structural_similarity × causal_consistency` is `match_motif`: boolean, same-actor ordered.
`context_compatibility` is ECHO's relevance floor. `local_evidence_support` is `LocalValidation`.
`visibility_adjustment` is `NOT_OBSERVABLE`. A graded product is not built, because the only
consumer (a Stage 6 DETECTOR motif) is boolean. Lesson 3.

### D7.12 — Partial-World Reconstructor `[campaign]`

```python
# pocketsec/stage7/reconstruct/partial_world.py
class WorldStatus(StrEnum): CANDIDATE, SUPPORTED, UNRESOLVED, REJECTED_COMMON_CAUSE, REJECTED_COLLUSION
@dataclass(frozen=True, slots=True)
class PartialWorld:
    world_id: str; edge_id: str; fragment_ids: tuple[str, ...]; clusters: int
    stages: tuple[ChainStage, ...]; window: tuple[int, int]; support: float
    status: WorldStatus; falsification: ConsensusFalsification | None; first_supported_round: int | None
class PartialWorldReconstructor:
    def __init__(self, *, hypergraph: CampaignHypergraph, falsifier: ConsensusFalsifier,
                 min_clusters: int = MIN_WORLD_CLUSTERS, min_stages: int = MIN_WORLD_STAGES,
                 falsify: bool = True) -> None
        # falsify=False is the "no falsifier" ablation: every candidate hyperedge becomes SUPPORTED
    def reconstruct(self, *, round_index: int, negative: Sequence[NegativeClaim] = ()) -> tuple[PartialWorld, ...]
    def memory_bytes(self) -> int
def count_threshold_join(fragments: Sequence[Fragment], *, window: int, k: int) -> tuple[tuple[str, ...], ...]
    # the CONTROL: any >= k fragments from >= k clusters inside one window, no stage order, no falsifier
```

SUPPORTED iff the falsifier's surviving explanation is H5 and negative evidence does not reach the
veto. **A world is never deleted by negative evidence or falsification.** It becomes UNRESOLVED or
REJECTED_* and is kept (§43). Partial worlds are **advisory**. They are never bridged to Stage 6,
carry no authority and emit no `ThreatPredictionV1` (novelty ≠ maliciousness; a campaign
hypothesis ≠ a verdict).

### D7.13 — Campaign Hypergraph `[campaign]`

```python
# pocketsec/stage7/campaign/hypergraph.py
@dataclass(frozen=True, slots=True)
class Fragment:
    capsule_id: str; cluster_id: str; role: RoleClass; stage: ChainStage; window: tuple[int, int]
    software_epoch: str; visibility: VisibilityClass; rarity: float        # rarity from D7.14, 0 if unknown
@dataclass(frozen=True, slots=True)
class Hyperedge:
    edge_id: str; fragment_ids: tuple[str, ...]; stages: tuple[ChainStage, ...]; clusters: int
    window: tuple[int, int]; weight: float     # independence × temporal coherence × mean rarity
class CampaignHypergraph:
    def __init__(self, *, max_fragments: int = MAX_FRAGMENTS, max_edges: int = MAX_HYPEREDGES,
                 expiry_rounds: int = CAMPAIGN_EXPIRY_ROUNDS, enabled: bool = True) -> None
        # enabled=False is the CONTROL: a pairwise co-occurrence graph (edges of exactly two fragments)
    def add_fragment(self, fragment: Fragment) -> bool          # False = refused (full), counted
    def build_edges(self, *, round_index: int, join_window: int = JOIN_WINDOW_ROUNDS) -> tuple[Hyperedge, ...]
        # temporally overlapping fragments (interval overlap within join_window — never timestamp equality, §20),
        # distinct stages orderable ACCESS < CREDENTIAL < ELEVATION < PERSISTENCE < EGRESS, >= 2 clusters
    def expire(self, *, round_index: int, preserved: frozenset[str] = frozenset()) -> int   # incident-preserved edges kept
    def evictions(self) -> int; def memory_bytes(self) -> int
```

### D7.14 — Collective Novelty `[campaign]`

```python
# pocketsec/stage7/novelty/collective.py
class NoveltyStatus(StrEnum): COLLECTIVELY_NOVEL, EXPLAINED_BY_EPOCH, LOCAL_ONLY, INSUFFICIENT
@dataclass(frozen=True, slots=True)
class CollectiveNovelty:
    pattern_key: str; rarity: float; coherence: float; causal_surprise: float; persistence: float
    independent_support: int; benign_epoch_explanation: float; score: float; status: NoveltyStatus
class CollectiveNoveltyEngine:
    def __init__(self, *, local: LocalContext, window_rounds: int = NOVELTY_WINDOW_ROUNDS,
                 max_patterns: int = MAX_NOVELTY_PATTERNS, enabled: bool = True) -> None
        # enabled=False is the CONTROL: local novelty only (first local sighting of the pattern)
    def observe(self, pooled: PooledCapsule) -> None           # NOVELTY capsules only
    def observe_population(self, counts: Mapping[str, int], *, role: RoleClass, round_index: int) -> None
        # released (exact, DP-noised or secure-summed) per-role population counts — the §17 conditioning
    def evaluate(self, *, round_index: int) -> tuple[CollectiveNovelty, ...]
    def memory_bytes(self) -> int
```

§17 binding. `rarity = 1 − min(1, count_in_relevant_roles / RARITY_SCALE)`.
`coherence = min(1, distinct clusters in window / 2)`.
`causal_surprise = (escalating stages in causal_motif) / 3`, clipped at 1.
`persistence = rounds reported / window`. `independent_support` = distinct clusters.
`benign_epoch_explanation` = share of reporters whose `software_epoch` first appeared inside the
window (a fresh image, H1). The score is
`rarity × coherence × causal_surprise × persistence / (1 + EPOCH_EXPLANATION_K × explanation)`.
The status is COLLECTIVELY_NOVEL iff `score ≥ NOVELTY_FLOOR` and support ≥ 2. **Novelty is not
maliciousness.** Collective novelty feeds fragment rarity (D7.13) and reporting only.

### D7.15 — Consensus Falsifier `[campaign]`

```python
# pocketsec/stage7/falsifier/consensus.py
class CounterHypothesis(StrEnum):
    H0_COINCIDENCE, H1_SHARED_UPDATE, H2_ADMIN_AUTOMATION, H3_TELEMETRY_ARTIFACT, H4_COLLUDING_PEERS, H5_REAL_CAMPAIGN
class HypothesisStatus(StrEnum): REJECTED = "REJECTED"; SURVIVES = "SURVIVES"; UNEVALUATED = "UNEVALUATED"
@dataclass(frozen=True, slots=True)
class HypothesisTest: hypothesis: CounterHypothesis; status: HypothesisStatus; statistic: float | None; reason: str
@dataclass(frozen=True, slots=True)
class NegativeClaim:         # from NEGATIVE_EVIDENCE capsules (§19)
    capsule_id: str; cluster_id: str; stage: ChainStage; window: tuple[int, int]; weight: float
@dataclass(frozen=True, slots=True)
class ConsensusFalsification:
    world_id: str; tests: tuple[HypothesisTest, ...]     # exactly six, one per CounterHypothesis, in enum order
    explanation: CounterHypothesis | None                # H5 iff H0–H4 all REJECTED; the first survivor otherwise;
                                                         # None when several benign survivors tie (UNIDENTIFIABLE is valid)
    negative_weight: float
def negative_evidence_weight(claim: ObservabilityClaim, *, host_relevance: float) -> float
    # §19: expected_observability × sensor_health × temporal_coverage × host_relevance; a peer that could not
    # observe (expected_observability == 0) contributes 0
class ConsensusFalsifier:
    def __init__(self, *, stage_base_rates: Mapping[ChainStage, float], relevant_hosts: int,
                 enabled: bool = True) -> None
    def falsify(self, world: PartialWorld, fragments: Sequence[Fragment], *,
                negative: Sequence[NegativeClaim] = (), birth_burst: Callable[[Sequence[str]], bool]) -> ConsensusFalsification
```

The tests, fixed:

- **H0**: the Poisson upper tail of observing ≥ n co-windowed fragments of these stages, given the
  per-stage background rate × `relevant_hosts`. REJECTED iff p < `COINCIDENCE_P`.
- **H1**: SURVIVES iff every fragment shares one `software_epoch` and that epoch first appeared
  inside the window.
- **H2**: SURVIVES iff all fragments come from one role and one declared root, with window starts
  identical within `ADMIN_SYNC_TOLERANCE_ROUNDS`.
- **H3**: SURVIVES iff a majority of fragments are `VisibilityClass.LOW`.
- **H4**: SURVIVES iff contributing clusters < `MIN_WORLD_CLUSTERS` after dependence clustering,
  or `birth_burst(contributor peers)`.
- **H5**: SURVIVES iff H0–H4 are all REJECTED.

**Negative evidence.** The weight is capped per cluster at `NEG_CLUSTER_CAP`. A Σ ≥
`NEG_EVIDENCE_FLOOR` moves a world to UNRESOLVED, never to deleted. A suppression attack can
therefore at most delay a real campaign, and its success is measured (S7X-40).

**Not built, declared.** Architecture §18's "request/seek the cheapest privacy-safe observations
that distinguish the worlds" needs a query protocol between peers. The simulated fleet has none,
so a vocabulary of requests would have no consumer (lesson 3). It is UNMEASURED.

### D7.16 — Cross-host lineage / revocation `[sovereignty]`

```python
# pocketsec/stage7/lineage/cross_host.py
class NodeRole(StrEnum): FOREIGN_CAPSULE, LOCAL_CAPSULE, ECHO_DECISION, STAGE6_LINK
class LinkState(StrEnum): LIVE = "LIVE"; SUSPECT = "SUSPECT"; REVOKED = "REVOKED"
@dataclass(frozen=True, slots=True)
class LineageRecord:
    node_id: str; role: NodeRole; parents: tuple[str, ...]; state: LinkState; round_index: int
    detail: str        # STAGE6_LINK: "<stage6 capsule_id>|<verdict_id>|<bucket>"; ECHO_DECISION: antibody_key; else ""
class CrossHostLineageDAG:
    def __init__(self, *, max_nodes: int = MAX_LINEAGE_NODES) -> None
    def add(self, record: LineageRecord) -> None      # unknown parents counted as unresolved, never invented
    def has(self, node_id: str) -> bool
    def get(self, node_id: str) -> LineageRecord | None
    def descendants(self, node_id: str, *, limit: int = MAX_DESCENDANT_WALK) -> tuple[tuple[str, ...], bool]  # (ids, truncated)
    def ancestry_complete(self, node_id: str) -> bool  # every ancestor present and none evicted
    def set_state(self, node_ids: Iterable[str], state: LinkState) -> None
    def state_digest(self) -> str
    def evictions(self) -> int     # evicts oldest LEAF nodes that are not referenced by a live STAGE6_LINK; tombstones counted
    def memory_bytes(self) -> int
@dataclass(frozen=True, slots=True)
class Revocation:
    revocation_id: str; target: str; ground: RevocationGround; issuer: str      # peer id, or "local"
    accepted: bool; reason: str
    affected: tuple[str, ...]; affected_truncated: bool           # target + descendants marked SUSPECT
    stage6_capsule_ids: tuple[str, ...]                           # the targeted Stage 6 set (from STAGE6_LINK details)
    prior_digest: str                                             # DAG state digest before; reinstate restores it
class RevocationPlane:
    def __init__(self, *, dag: CrossHostLineageDAG, owner_of_key: Callable[[str], str | None],
                 contributor_of: Callable[[str], str | None], local_keys: Callable[[], frozenset[str]],
                 echo_suspect: Callable[[Iterable[str], bool], None], capacity: int = MAX_REVOCATIONS) -> None
    def submit(self, capsule: KnowledgeCapsuleV1, *, sender_peer: str, round_index: int) -> Revocation
    def revoke_locally(self, target: str, *, round_index: int) -> Revocation     # ground LOCAL_EVIDENCE
    def reinstate(self, revocation_id: str) -> bool     # True iff the DAG digest returns to prior_digest exactly
    def history(self) -> tuple[Revocation, ...]; def memory_bytes(self) -> int
```

**Authority rules (§24: "revocation is itself untrusted input until verified").**

- A foreign `SELF_RETRACTION` is accepted iff the target's contributor equals the owner of the
  revocation's key.
- A foreign capsule claiming `LOCAL_EVIDENCE` is refused `foreign_claims_local_ground`.
- A foreign revocation of a `LOCAL_CAPSULE` node or a local key is refused `local_sovereignty`.
- An unknown target is refused `unknown_target`, and nothing changes.
- A third party's revocation of someone else's capsule is refused `not_contributor`. It may still
  arrive as a CONTEST capsule, which only reduces mass.
- Ambiguity (descendants truncated or evicted) marks what is known SUSPECT and never deletes
  (§43).

**Accepted revocations** mark the target and its descendants SUSPECT, call `echo_suspect` for the
affected antibody keys, and compute `stage6_capsule_ids` from the STAGE6_LINK records beneath
them. **Stage 7 cannot act on Stage 6.** Stage 6 exposes no revocation or re-evaluation input
(blocker B7-2, ADR-0067). The targeted set is computed and reported. Stage 6-side rollback is
UNMEASURED, and today it is vacuous because Stage 6 promotes no foreign capsule (M0.2).

### D7.17 — Optional secure aggregation `[sovereignty]`

```python
# pocketsec/stage7/aggregation/secure.py
SECURE_AGGREGATION_ENABLED: bool = False
MODULUS: int = 2 ** 32
@dataclass(frozen=True, slots=True)
class MaskedVector: participant: str; round_index: int; values: tuple[int, ...]
@dataclass(frozen=True, slots=True)
class SecureRoundResult:
    round_index: int; participants: tuple[str, ...]; total: tuple[int, ...] | None   # None = aborted
    aborted: bool; reason: str; bytes_exchanged: int
def pairwise_mask(pair_key: bytes, *, round_index: int, length: int) -> tuple[int, ...]   # HMAC-SHA256 counter-mode PRG
def mask_vector(values: Sequence[int], *, participant: str, pair_keys: Mapping[str, bytes],
                round_index: int) -> MaskedVector       # + mask to higher ids, - mask to lower ids, mod MODULUS
def aggregate_masked(vectors: Sequence[MaskedVector], *, expected: frozenset[str],
                     round_index: int) -> SecureRoundResult
    # any expected participant missing -> ABORT, no partial result (§43 "abort round; no partial unsafe update")
```

**What it is and is not (ADR-0066).** It is a pairwise-masking secure sum (Bonawitz's masking
layer only) over **simulated pre-provisioned pair keys**. Stdlib has no key agreement.
Hand-rolling Diffie–Hellman is out of scope, and so is Shamir-based dropout recovery. It hides
each host's count vector from an **honest-but-curious** aggregator. It does not authenticate. It
does not tolerate dropout (a dropout aborts). **It prevents exactly the per-client inspection
that Byzantine filtering needs.** The suite measures that trade-off: novelty-count inflation
under a Sybil arm with secure summing against plaintext summing with per-cluster clamping. It is
off by default and used only for D7.14's population counts. No privacy guarantee is claimed
beyond "the aggregator sees only the sum, under the simulated key assumption".

### D7.18 — Communication / resource governor `[ingress]`; offline/partition mode `[sovereignty]`

```python
# pocketsec/stage7/governor/communication.py
class ExchangeMode(StrEnum): OFFLINE, IDLE, ROUTINE, INCIDENT, RESEARCH
MODE_ROUND_BYTES: Mapping[ExchangeMode, int]   # OFFLINE 0, IDLE 0, ROUTINE 16384, INCIDENT 262144, RESEARCH 1048576 (outbound)
@dataclass(frozen=True, slots=True)
class CommunicationBudget:
    mode: ExchangeMode; round_index: int; outbound_cap: int; outbound_used: int
    inbound_cap: int; inbound_used: int; inbox_capsules: int; inbox_bytes: int
    refused: tuple[tuple[str, int], ...]         # reason -> count, cumulative
class CommunicationGovernor:
    def __init__(self, *, mode: ExchangeMode = ExchangeMode.IDLE, research_enabled: bool = RESEARCH_ENABLED) -> None
    def set_mode(self, mode: ExchangeMode, *, round_index: int) -> None
        # RESEARCH refused unless research_enabled; INCIDENT auto-reverts to ROUTINE after INCIDENT_MAX_ROUNDS
    def begin_round(self, round_index: int) -> None     # resets per-round counters
    def admit_inbound(self, sender: str, size: int, *, round_index: int) -> str | None
        # refusal reasons: "partitioned", "oversize", "peer_bytes", "peer_count", "round_bytes", "inbox_full"
        # inbound cap = max(MODE_ROUND_BYTES[ROUTINE], MODE_ROUND_BYTES[mode]) unless OFFLINE (0)
    def admit_outbound(self, size: int, *, round_index: int) -> str | None
    def release(self, count: int, size: int) -> None     # inbox drained by the fabric
    def partition(self) -> None; def heal(self, *, round_index: int) -> None
    def budget(self) -> CommunicationBudget; def memory_bytes(self) -> int
@dataclass(frozen=True, slots=True)
class Stage7ResourceReport:
    peak_sampled_rss_bytes: int | None; incremental_rss_bytes: int | None   # max(0, sampled_peak - start); None = UNMEASURED
    within_ceiling: bool | None; profile: ProfileReport | None
    store_bytes: tuple[tuple[str, int], ...]; loadavg: tuple[float, float, float]
    wall_seconds: float; cpu_seconds: float
def measure_stage7_resources(run: Callable[[], Mapping[str, int]]) -> Stage7ResourceReport
    # ResourceSampler around run(); run returns store_name -> memory_bytes(); within_ceiling is None whenever RSS
    # was unreadable (UNMEASURED is never True) and the dataclass refuses a verdict its figures do not support
```

```python
# pocketsec/stage7/orpheus/fabric.py
class FabricState(StrEnum): DISABLED = "DISABLED"; OFFLINE = "OFFLINE"; ACTIVE = "ACTIVE"; DEGRADED = "DEGRADED"
@dataclass(frozen=True, slots=True)
class FabricComponents:
    local: LocalContext; keyring: Keyring; replay: ReplayGuard; peers: PeerTable; governor: CommunicationGovernor
    graph: DependenceGraph; trust: ContextualTrust; validator: LocalValidator; echo_config: EchoConfig
    lineage: CrossHostLineageDAG; hypergraph: CampaignHypergraph; novelty: CollectiveNoveltyEngine
    falsifier: ConsensusFalsifier; bridge: Stage6Bridge | None      # None: no Stage 6 handoff (measurement arms)
@dataclass(frozen=True, slots=True)
class RoundReport:
    round_index: int; state: FabricState; received: int; pooled: int
    refused_by_stage: tuple[tuple[str, int], ...]; decisions: tuple[tuple[str, int], ...]
    bridged: int; stage6_buckets: tuple[tuple[str, int], ...]; revocations: tuple[tuple[str, int], ...]
    worlds: tuple[tuple[str, int], ...]; novel: int; failures: int; budget: CommunicationBudget
class OrpheusFabric:
    def __init__(self, components: FabricComponents, *, exchange_enabled: bool = COLLECTIVE_EXCHANGE_ENABLED,
                 meter: WorkMeter | None = None) -> None      # exchange_enabled False -> DISABLED; nothing is received
    def deliver(self, data: bytes, *, sender: str) -> IngressVerdict | None   # None when DISABLED/OFFLINE (counted)
    def run_round(self) -> RoundReport
        # ingress drain -> revocations -> ECHO offer/infer -> bridge ELIGIBLE (once per decision) -> fragments ->
        # hypergraph -> reconstruct/falsify -> novelty. NEVER raises: any component exception sets DEGRADED,
        # disables exchange for the rest of the round, is counted; a keyring whose state digest fails
        # verify_state sets DISABLED (§43 "peer trust store corrupt -> disable exchange, preserve local cognition")
    def publish(self, capsules: Sequence[KnowledgeCapsuleV1]) -> tuple[bytes, ...]   # signed, within outbound budget
    def partition(self) -> None; def heal(self) -> None
    def memory_bytes(self) -> Mapping[str, int]
```

**The fabric holds no reference to anything local-detection uses.** Local detection (Stage 1–6)
never imports Stage 7 (T7, tested). The fabric being absent, OFFLINE, DISABLED or crashing is
therefore invisible to local detection by construction. G7.3 measures it anyway.

### 7.16 — the Stage-6 local gate (`hivelock/stage6_bridge.py`) `[sovereignty]`

```python
# pocketsec/stage7/hivelock/stage6_bridge.py
@dataclass(frozen=True, slots=True)
class BridgeReceipt:
    decision_id: str; antibody_key: str
    stage6_capsule_ids: tuple[str, ...]; verdict_ids: tuple[str, ...]
    stage6_buckets: tuple[str, ...]          # QuarantineBucket values, as Stage 6 returned them — never reinterpreted
    trusted_candidates: int                  # how many Stage 6 put in TRUSTED_CANDIDATE (reported, never acted on)
class Stage6Bridge:
    def __init__(self, *, gateway: QuarantineGateway, local_dag: KnowledgeLineageDAG, epoch: Epoch,
                 bridge_secret: bytes, lineage: CrossHostLineageDAG, exchange_enabled: bool,
                 capacity: int = MAX_BRIDGE_LINKS) -> None
        # the gateway is INJECTED already bound to the host's trusted view (the controller binds it; Stage 7 never
        # constructs a controller); local_dag is only ever asked .has()
    def hand_over(self, decision: EchoDecision, *, raw_digests: Mapping[str, str], sequence: int) -> BridgeReceipt
    def created(self) -> int      # ExperienceCapsuleV1 values this bridge built
    def admitted(self) -> int     # values it passed to gateway.admit — G7.1 asserts created == admitted
    def memory_bytes(self) -> int
```

`hand_over`:

1. Refuse unless `decision.status is ELIGIBLE`.
2. For each supporting cluster c, up to `MAX_BRIDGE_CAPSULES_PER_DECISION`, build one item
   `{"privacy_class": "PUBLIC_DERIVED", "steps": [s.to_dict() for s in prototype_steps(invariant,
   source_group=source_group_of("stage7:" + c))], "evidence_refs": [raw_digest of each of c's
   capsules, ≤ 32], "verdict": "MALICIOUS"}`. The evidence refs are real **local** digests of the
   bytes this host received.
3. Wrap the item in `KnowledgePackageV1(package_id="s7-" + decision_id[4:28] + "-" + c[3:11],
   source_host="stage7-" + c, key_id="s7c-" + c[3:], …)`. Sign it with
   `sign_package(key=HMAC(bridge_secret, c))`. Verify with `verify_package` against the bridge's
   own derived keyring. This is local integrity only, and it names the cluster as Stage 6's
   independence group `fleet:s7c-<cluster>`.
4. Call `package_to_capsules(..., enabled=self.exchange_enabled)`. With the default `False` this
   raises `FleetDisabledError`. The bridge does not catch it: exchange off means no handoff.
5. Call `gateway.admit(capsule)` for each, record `STAGE6_LINK` nodes in the cross-host DAG, and
   return the receipt.

**This is the only module in `pocketsec/` that calls `.admit` on anything or imports
`fleet.package` from Stage 7.** It never inspects, overrides or retries a Stage 6 verdict.

### D7.19 — the 72-experiment adversarial benchmark `[adversary]` (+ `labs/campaign_sim.py` `[campaign]`)

```python
# pocketsec/stage7/labs/seventy_two_experiments.py
class ExperimentStatus(StrEnum): RUN = "RUN"; REFUSED_BY_CONSTRUCTION = "REFUSED_BY_CONSTRUCTION"; UNMEASURED = "UNMEASURED"
@dataclass(frozen=True, slots=True)
class S7Experiment: sid: str; title: str; deliverable: str; runner: str | None; status: ExperimentStatus; note: str
S7_EXPERIMENTS: tuple[S7Experiment, ...]      # exactly 72, S7X-01 … S7X-72, titles verbatim from architecture §48
def catalogue_problems() -> tuple[str, ...]   # every RUN row's runner resolves ("module:qualname") and is exercised by the
                                              # gate or CLI; every non-RUN row has a non-empty note; () = consistent
```

Fixed statuses for the rows this wave cannot run:

| S7X | status | note |
|---|---|---|
| 15, 16 | RUN | Krum / Bulyan families in `aggregation/robust.py` |
| 19 | RUN | the secure-sum prototype |
| 20 | RUN | dropout aborts; recovery NOT built |
| 47 | RUN | a malicious aggregator in the secure sum alters the total → detected only if a participant cross-checks; measured as undetected (declared) |
| 48, 49 | REFUSED_BY_CONSTRUCTION | model replacement / backdoor adapter: no MODEL_DELTA type |
| 50–51 | RUN | `labs/privacy_attacks.py` |
| 53 | RUN | DP curve on population counts |
| 59, 60 | RUN | simulated peers at the ingress; not a network |
| 61 | RUN | 1 KB class |
| 62 | REFUSED_BY_CONSTRUCTION | > `MAX_KNOWLEDGE_CAPSULE_BYTES`; refusal cost measured |
| 63 | RUN | HMAC-SHA256 only; Ed25519 UNMEASURED |
| 64 | RUN | `zlib` as a stdlib stand-in; zstd UNMEASURED |
| 69 | UNMEASURED | a full Stage 1–7 endurance on real telemetry does not exist; the synthetic churn run is S7X-70 |
| 72 | RUN | against FedAvg (= MEAN) and the central feed; FedProx/personalised FL are UNMEASURED (no parameters) |

Every other row is RUN, and its runner is named in the catalogue.

```python
# pocketsec/stage7/labs/campaign_sim.py           [campaign]
CAMPAIGN_SIM_VERSION = "stage7-campaign-sim-v0.1.0"
class CampaignArm(StrEnum):
    TRUE_CAMPAIGN_2, TRUE_CAMPAIGN_4, TRUE_CAMPAIGN_10, BENIGN_COINCIDENCE, SHARED_SOFTWARE_UPDATE,
    ADMIN_AUTOMATION, TELEMETRY_ARTIFACT, COLLUDING_FABRICATION, SUPPRESSION, TEMPORAL_UNCERTAINTY
@dataclass(frozen=True, slots=True)
class CampaignCase: arm: CampaignArm; fragments: tuple[Fragment, ...]; negative: tuple[NegativeClaim, ...]; is_campaign: bool; start_round: int
def build_campaign_cases(*, seed: int, per_arm: int = 8) -> tuple[CampaignCase, ...]
def run_campaign_sim(cases: Sequence[CampaignCase], *, falsify: bool = True, hypergraph: bool = True) -> CampaignSimReport
@dataclass(frozen=True, slots=True)
class CampaignSimReport:
    true_recall: float | None; false_campaign_rate: float | None; control_false_campaign_rate: float | None
    time_to_detect_rounds: tuple[tuple[str, int | None], ...]; rejections_by_hypothesis: tuple[tuple[str, int], ...]
    suppression_delay_rounds: float | None; synthetic: bool = True
```

### D7.20 — Stage 1–7 endurance / falsification `[adversary]` + findings `[integrator]`

```python
# pocketsec/stage7/labs/partition.py
@dataclass(frozen=True, slots=True)
class OfflineEquivalence: digest_absent: str; digest_offline: str; digest_crashing: str; digest_disabled: str; identical: bool
def run_offline_equivalence(corpus: FleetCorpus, *, receiver: str) -> OfflineEquivalence
    # local outputs = sha256 over (Stage 1 transition digests of the receiver's held-out episodes, local antibody
    # scores); computed with the fabric never constructed / OFFLINE under a flood / crashing every round / DISABLED
@dataclass(frozen=True, slots=True)
class PartitionReport: stale_refused: int; replay_refused: int; recovered_rounds: int | None; expired_refused: int
def run_partition_recovery(corpus: FleetCorpus, *, partition_rounds: int = 8, seed: int = 0) -> PartitionReport
@dataclass(frozen=True, slots=True)
class ChurnReport:
    rounds: int; peers_seen: int; store_peaks: tuple[tuple[str, int, int], ...]   # (store, peak count, cap)
    evictions: tuple[tuple[str, int], ...]; plateau_ok: bool                      # peak(last third) <= peak(middle third)
def run_churn_endurance(corpus: FleetCorpus, *, rounds: int = CHURN_ROUNDS, churn_share: float = 0.1, seed: int = 0) -> ChurnReport
@dataclass(frozen=True, slots=True)
class ScaleRow: peers: int; refused_peers: int; table_size: int; memory_bytes: int; work_units: int
def run_scale(*, peer_counts: Sequence[int] = (10, 100, 1000, 10000), seed: int = 0) -> tuple[ScaleRow, ...]
```

`docs/stage-7-findings.md` (integrator) is the D7.20 report. It ends with the §11 honesty ledger.

### 4.19 — the simulated fleet corpus `[privacy]` (`labs/fleet_corpus.py`)

```python
FLEET_CORPUS_VERSION = "stage7-fleet-corpus-v0.1.0"
class AttackFamily(StrEnum): EXFIL, PERSIST, MEMORY_THEFT, ESCAPE     # Stage 1's ATTACK_* chains
@dataclass(frozen=True, slots=True)
class HostSpec:
    host_id: str; role: RoleClass; identity: SystemIdentity; families_local: frozenset[AttackFamily]
    canaries: tuple[str, ...]; late_benign: bool       # late_benign: the role's rare benign behaviour appears only held-out
@dataclass(frozen=True, slots=True)
class FleetEpisode:
    host_id: str; index: int; steps: tuple[EncodedStep, ...]; label: int; family: AttackFamily | None
    evidence_digests: tuple[str, ...]; history: bool     # True = first half (local history), False = held-out
@dataclass(frozen=True, slots=True)
class FleetCorpus:
    version: str; seed: int; hosts: tuple[HostSpec, ...]; episodes: tuple[FleetEpisode, ...]
    raw_strings: frozenset[str]      # every Behaviour field value used + every canary (the privacy scan set)
    raw_digests: frozenset[str]      # every Stage 1 evidence sha256 digest produced
    def for_host(self, host_id: str, *, history: bool) -> tuple[FleetEpisode, ...]
def build_fleet_corpus(*, hosts: int = 24, episodes_per_host: int = 40, seed: int = 7) -> FleetCorpus
@dataclass(frozen=True, slots=True)
class Precondition: name: str; status: str; detail: str      # "PASS" | "BLOCKED" | "DEGENERATE" | "DEGENERATE_IN_FAVOUR"
def fleet_preconditions(corpus: FleetCorpus) -> tuple[Precondition, ...]
```

Roles and behaviour are built only from Stage 1 `Behaviour`/`Scenario`: `BENIGN_PATTERNS`,
`BENIGN_PRIVILEGED`, the four `ATTACK_*` chains, and these role additions:

| role | benign mix (Stage 1 pattern index or new `Behaviour` tuple) |
|---|---|
| WEB | web request `[1]`, local chatter `[4]`, package query `[3]` |
| DEV | build `[0]`, package query `[3]`, local chatter `[4]` |
| DESKTOP | backup `[2]`, package query `[3]`, **`DESKTOP_WEB_CLIENT`** = (connect external :443, send) — benign egress |
| ADMIN | `BENIGN_PRIVILEGED`, backup `[2]`, **`ADMIN_CREDENTIAL_ROTATION`** = (setuid 0, read `/etc/shadow`, write `/etc/shadow`), **`ADMIN_SERVICE_INSTALL`** = (setuid 0, write `/etc/systemd/system/<canary>.service`, execve systemctl) — **benign persistence, the same meaning as `ATTACK_PERSISTENCE`** |

Hosts are assigned roles in the cycle WEB, WEB, DEV, DESKTOP, WEB, ADMIN, so ADMIN is the rare
role (1 in 6). Each host sees 1–2 attack families locally. Receivers are the hosts lacking ≥ 2
families. Half of the ADMIN hosts are `late_benign`: `ADMIN_SERVICE_INSTALL` appears only in
their held-out half, which is the target of the latent-poison arm. Every path, user name and
address field embeds a host canary (`/srv/cnry-<host>-…`, `cnry-<host>-user`,
`10.<h>.<x>.<y>`). Every Stage 1 run uses a session-unique offset
(`host_index * 100000 + episode * 1000`), which is the MEMORY corpus trap.

Preconditions (G7.11 and the suite refuse to run past a BLOCKED one):

- **P1**: median per-class ΔΦ is non-zero for both classes (integration plan §5.4).
- **P2**: session-unique actor identities across the corpus.
- **P3 (lesson 2)**: for each family, an oracle motif forged on one host transfers at recall ≥ 0.9
  and 0 FP to a same-role receiver. Otherwise BLOCKED: the representation cannot express the task.
- **P4**: non-IID is real. The WEB-forged `copied_rule` for PERSIST matches ≥ 1 ADMIN benign
  episode. Otherwise the non-IID arms are DEGENERATE.
- **P5**: when P3's transfer is 1.0 recall / 0 FP for every family, the result is
  DEGENERATE_IN_FAVOUR. It is reported and does not block, and every detection-gain figure
  carries the flag (M0.3 predicts it).

### 4.20 — the simulated fleet and adversaries `[adversary]` (`labs/simulated_fleet.py`)

```python
SIMULATED_FLEET_VERSION = "stage7-simulated-fleet-v0.1.0"
class AdversaryArm(StrEnum):
    NONE,
    SYBIL_DECLARED_ROOT,     # (a) one adversary root, S identities declaring that root
    SYBIL_FORGED_ROOTS,      # (a) S identities each declaring a fresh root, born in one burst, identical summaries
    SYBIL_ADAPTIVE,          # (a) forged roots + staggered births + jittered summaries + random relays of honest keys
    BYZANTINE_POISON,        # (b) a share of independent roots send a consistent poison antibody that matches receiver-role benign
    BYZANTINE_LATENT_POISON, # (b) poison matching a benign behaviour absent from the receiver's ring (late_benign) — local validation cannot see it
    BYZANTINE_SUPPRESS,      # (b) contests against true antibodies + third-party revocations
    SLOW_POISON,             # (c) relay true antibodies for SLOW_POISON_WARMUP_ROUNDS (earn trust), then latent poison
    COLLUSION_TIMING,        # (d) a colluding minority releases poison support in one round (race the contests) and
                             #     fabricates co-windowed campaign fragments
    FLOOD, REPLAY, FALSE_REVOCATION, LINEAGE_TAMPER, AUTHORITY_INJECTION, UNANIMOUS_FLEET
@dataclass(frozen=True, slots=True)
class FleetSpec:
    arm: AdversaryArm; honest_roots: int = HONEST_ROOTS; adversary_share: float = 0.0   # share of independent roots
    sybils_per_root: int = 1; rounds: int = SUITE_ROUNDS; seed: int = 0; receivers: tuple[str, ...] = ()
@dataclass(frozen=True, slots=True)
class Delivery: sender: str; receiver: str; data: bytes; adversarial: bool; poison_key: str | None; round_index: int
@dataclass(frozen=True, slots=True)
class FleetGroundTruth:
    poison_keys: frozenset[str]; true_keys_by_family: Mapping[AttackFamily, frozenset[str]]
    adversary_peers: frozenset[str]; true_root_of: Mapping[str, str]; honest_roots: int; adversary_roots: int
def simulated_key_provisioning(peers: Sequence[str], receivers: Sequence[str], *, seed: int) -> Mapping[tuple[str, str], bytes]
def simulated_stage6_receiver(identity: SystemIdentity) -> tuple[QuarantineGateway, KnowledgeLineageDAG]
    # ProvenanceLedger() + KnowledgeLineageDAG() + QuarantineGateway(...) bound to genesis_state(identity=...) — LAB ONLY
class SimulatedFleet:
    def __init__(self, corpus: FleetCorpus, spec: FleetSpec) -> None
    def round_traffic(self, round_index: int, *, visible_keys: Mapping[str, frozenset[str]]) -> tuple[Delivery, ...]
        # honest peers: forge from local history incidents, compile, sign, send SUPPORT; send CONTEST for any key visible
        # last round that matches their own benign ring (bounded per round); adversaries per arm
    def ground_truth(self) -> FleetGroundTruth
```

### 4.21 — the Byzantine suite runner `[adversary]` (`labs/byzantine_suite.py`)

```python
@dataclass(frozen=True, slots=True)
class SuiteRow:
    arm: str; aggregator: str; lv: bool; adversary_share: float; sybils_per_root: int
    poison_offered: int; poison_accepted: int; true_offered: int; true_accepted: int
    recall_no_sharing: float | None; recall_collective: float | None     # counterfactual_at_boundary
    fp_rate_collective: float | None; amplification: float | None; stage6_trusted_candidates: int
@dataclass(frozen=True, slots=True)
class BreakPoint: arm: str; aggregator: str; lv: bool; share: float | None    # smallest share with poison acceptance >= BREAK_LEVEL; None = none in sweep
@dataclass(frozen=True, slots=True)
class AblationRow:
    core_id: str; flag: str; control: str; metric: str; full_value: float | None; control_value: float | None
    delta: float | None; firing_count: int; verdict: str      # JUSTIFIED | NOT_YET_JUSTIFIED | HARMFUL | INERT
@dataclass(frozen=True, slots=True)
class ByzantineReport:
    rows: tuple[SuiteRow, ...]; break_points: tuple[BreakPoint, ...]; ablations: tuple[AblationRow, ...]
    threshold_sensitivity: tuple[tuple[str, float, float], ...]   # (parameter, flip share at x0.5, at x2)
    firing: tuple[tuple[str, int], ...]; preconditions: tuple[Precondition, ...]
    loadavg: tuple[float, float, float]; synthetic: bool = True
def run_byzantine_suite(corpus: FleetCorpus, *, arms: Sequence[AdversaryArm], shares: Sequence[float] = SHARES,
                        sybil_counts: Sequence[int] = SYBIL_COUNTS, rounds: int = SUITE_ROUNDS, seed: int = 0,
                        with_stage6: bool = True) -> ByzantineReport
def run_ablation(corpus: FleetCorpus, *, seed: int = 0) -> tuple[AblationRow, ...]
def siem_oracle(corpus: FleetCorpus, *, receiver: str) -> tuple[float | None, int]   # (recall, canary strings exposed)
```

**Identical inputs (lesson 4).** For each (arm, share or sybil count) the fleet traffic is
generated once and ingested once per receiver through the real fabric. Every aggregator is then
evaluated on **the same pool** (`stance_matrix(pool)`). ECHO's figure is the fabric's own
ELIGIBLE set. Break points and the "+LV" variants come from that one run. `with_stage6=True`
routes ECHO's ELIGIBLE set through a real `Stage6Bridge` into `simulated_stage6_receiver` and
records Stage 6's buckets.

### 4.22 — privacy attacks `[adversary]` (`labs/privacy_attacks.py`)

```python
@dataclass(frozen=True, slots=True)
class LeakageMeasurement:
    attack: str; representation: str          # "distilled" | "raw_steps_control"
    trials: int; advantage: float | None       # TPR - FPR (membership) or accuracy - chance (property); None = UNMEASURED
    chance: float | None; synthetic: bool = True
def canary_scan(corpus: FleetCorpus, exported: Sequence[bytes]) -> tuple[int, tuple[str, ...]]   # (hits, first names)
def membership_inference(corpus: FleetCorpus, *, representation: str, trials: int = 200, seed: int = 0) -> LeakageMeasurement
    # attacker holds a candidate local incident and the source host's exported capsules; guesses "was this incident a
    # source?" by invariant match (distilled) or by nearest EncodedStep feature match (raw control = Stage 6's fleet item)
def property_inference(corpus: FleetCorpus, *, representation: str, trials: int = 200, seed: int = 0) -> LeakageMeasurement
    # infers an UNdisclosed host property (whether the host runs the local database service, pattern [4]) from
    # family_profile (distilled) vs raw feature vectors (control); nearest-centroid, stdlib
def dp_curve(corpus: FleetCorpus, *, epsilons: Sequence[float | None] = (0.1, 0.5, 1.0, 2.0, None), seed: int = 0
             ) -> tuple[tuple[float | None, float | None, float | None], ...]
    # (epsilon, collective-novelty recall on true distributed novelty, count-membership advantage)
```

### 4.23 — parameters (every value chosen, not measured)

| constant | value | module |
|---|---|---|
| `COLLECTIVE_EXCHANGE_ENABLED` | False | `constitution/collective.py` |
| `MAX_KNOWLEDGE_CAPSULE_BYTES` / `MAX_EVIDENCE_COMMITMENTS` / `MAX_PARENT_CAPSULES` | 4096 / 8 / 8 | `capsule/knowledge_capsule.py` |
| `MAX_EXPIRY_HORIZON_ROUNDS` / `MAX_WINDOW_ROUNDS` / `FAMILY_PROFILE_LEVELS` | 64 / 16 / 4 | `capsule/knowledge_capsule.py` |
| `MAX_PEERS` / `PEER_IDLE_ROUNDS` / `MAX_PEER_EVICTION_LOG` | 1024 / 64 / 256 | `identity/peer.py` |
| `MAX_KEYS` / `KEY_GRACE_ROUNDS` / `MAX_REPLAY_KEYS` / `MAX_SEEN_CAPSULES` | 1024 / 8 / 4096 / 8192 | `identity/integrity.py` |
| `MODE_ROUND_BYTES` | 0 / 0 / 16384 / 262144 / 1048576 | `governor/communication.py` |
| `MAX_BYTES_PER_PEER_PER_ROUND` / `MAX_CAPSULES_PER_PEER_PER_ROUND` | 8192 / 8 | `governor/communication.py` |
| `MAX_INBOX_CAPSULES` / `MAX_INBOX_BYTES` / `INCIDENT_MAX_ROUNDS` / `RESEARCH_ENABLED` | 1024 / 4194304 / 8 / False | `governor/communication.py` |
| `STAGE7_INCREMENTAL_NORMAL_BYTES` / `STAGE7_INCREMENTAL_CEILING_BYTES` | 55 MiB / 120 MiB (§44) | `governor/communication.py` |
| `MAX_POOL_CAPSULES` / `MAX_METADATA_RECORDS` / `MAX_REVOCATION_INBOX` / `VALIDATION_FLOOR` | 2048 / 1024 / 256 / 0.05 | `hivelock/ingress.py` |
| `MAX_GRAPH_PEERS` / `MAX_EDGES_PER_PEER` / `MAX_CONTRIBUTION_HISTORY_PER_PEER` | 1024 / 32 / 64 | `graph/dependence.py` |
| `BIRTH_WINDOW_ROUNDS` / `BURST_MIN` / `CO_TIMING_JACCARD` / `CO_TIMING_MIN_EVENTS` / `SYBIL_MIN_CLUSTER` | 2 / 8 / 0.8 / 3 / 4 | `graph/` |
| `MAX_TRUST_ENTRIES` / `TRUST_PRIOR` / `TRUST_FLOOR` / `TRUST_CEILING` | 4096 / 0.5 / 0.05 / 1.0 | `trust/contextual.py` |
| `CONFIRM_STEP` / `REFUTE_FACTOR` / `TRUST_HALF_LIFE_ROUNDS` | 0.1 / 0.25 / 64 | `trust/contextual.py` |
| `DISTANCE_WEIGHTS` | role 1.0, software_epoch 0.25, visibility 0.25, behaviour 0.5 | `relevance/epistemic_distance.py` |
| `CLUSTER_CAP` / `MASS_FLOOR` / `CONTEST_RATIO` / `RELEVANCE_FLOOR` / `ECHO_PROBATION_ROUNDS` | 1.0 / 1.0 / 1.0 / 0.2 / 2 | `echo/inference.py` |
| `MAX_KEYS_TRACKED` / `MAX_CONTRIBUTIONS_PER_KEY` / `MAX_CLUSTERS_PER_DECISION` | 1024 / 64 / 16 | `echo/inference.py` |
| `MAX_KEYS_PER_OPENER` (review fix S7-AUTH-02/R7-3: keys one dependence cluster may hold open; a full key evicts a surplus identity of its largest (cluster, stance) group instead of refusing every newcomer, S7-R2) | 128 | `echo/inference.py` |
| `KEY_TOMBSTONE_BITS` (review fix R7-4: Bloom filter of reclaimed key ids; dead keyring records are reclaimed, live ones never) | 2^19 | `identity/integrity.py` |
| `LOCAL_FP_CEILING` / `MAX_BENIGN_EPISODES` / `MAX_FORGE_CANDIDATES` / `MUTATIONS_PER_INCIDENT` / `MAX_BIT_DROPS` | 0 / 512 / 64 / 8 / 16 | `antibody/forge.py` |
| `TRIM_SHARE` / `MIN_QUORUM` / `ACCEPT_LEVEL` / `BYZANTINE_ASSUMED_SHARE` | 0.2 / 2 / 0.0 / 0.2 | `aggregation/robust.py` |
| `MAX_FRAGMENTS` / `MAX_HYPEREDGES` / `JOIN_WINDOW_ROUNDS` / `CAMPAIGN_EXPIRY_ROUNDS` | 2048 / 512 / 4 / 32 | `campaign/hypergraph.py` |
| `MIN_WORLD_CLUSTERS` / `MIN_WORLD_STAGES` | 2 / 3 | `reconstruct/partial_world.py` |
| `COINCIDENCE_P` / `ADMIN_SYNC_TOLERANCE_ROUNDS` / `NEG_CLUSTER_CAP` / `NEG_EVIDENCE_FLOOR` | 0.01 / 0 / 1.0 / 1.5 | `falsifier/consensus.py` |
| `MAX_NOVELTY_PATTERNS` / `NOVELTY_WINDOW_ROUNDS` / `RARITY_SCALE` / `NOVELTY_FLOOR` / `EPOCH_EXPLANATION_K` | 1024 / 16 / 8 / 0.3 / 4 | `novelty/collective.py` |
| `EPSILON_BUDGET` / `PRIVACY_WINDOW_ROUNDS` / `MAX_RELEASES_PER_WINDOW` / `MAX_LEDGER_ENTRIES` | 4.0 / 64 / 256 / 256 | `privacy/ledger.py` |
| `MAX_LINEAGE_NODES` / `MAX_DESCENDANT_WALK` / `MAX_REVOCATIONS` | 16384 / 1024 / 256 | `lineage/cross_host.py` |
| `MAX_PARTICIPANTS` / `MAX_VECTOR_LEN` / `SECURE_AGGREGATION_ENABLED` | 256 / 1024 / False | `aggregation/secure.py` |
| `MAX_BRIDGE_CAPSULES_PER_DECISION` / `MAX_BRIDGE_LINKS` | 8 / 4096 | `hivelock/stage6_bridge.py` |
| `FPR_BUDGET` / `SHARES` / `SYBIL_COUNTS` / `SUITE_ROUNDS` / `HONEST_ROOTS` | 0.01 / (0, .1, .2, .3, .4, .5, .6) / (1, 2, 4, 8, 16, 32, 64, 128) / 12 / 16 | `labs/` |
| `BREAK_LEVEL` / `DETECTION_GAIN_MIN` / `FEED_LAG_ROUNDS` / `SLOW_POISON_WARMUP_ROUNDS` / `CHURN_ROUNDS` | 0.5 / 0.10 / 4 / 6 / 720 | `labs/` |

**Lesson 5 is enforced, not hoped for.** G7.11 runs a threshold sensitivity sweep over
`MASS_FLOOR`, `CLUSTER_CAP`, `CONTEST_RATIO`, `RELEVANCE_FLOOR`, `VALIDATION_FLOOR`,
`TRUST_PRIOR` and `ECHO_PROBATION_ROUNDS` (each ×0.5 and ×2, or ±1 for integers). It reports
the share of ECHO decisions that flip. **A parameter whose change flips every decision, or no
decision on any arm, is named in the findings as "silently decides every outcome" or "inert".**
The Stage 5 `0.35` ceiling is the precedent.

### 4.24 — core ids `[foundation]` (`core_ids.py`)

One id per architecture layer 7.0–7.21 (`ORPH-F01` … `ORPH-F22`), with the Stage 6 shape
(`Stage7Function(core_id, architecture_layer, name, symbol, function_class, ablation_flags,
simple_control)`, `resolve_symbols()`, `optional_functions()`), plus `PINNED_SCHEMAS`:
`pocketsec.experience_capsule.v1`, `pocketsec.knowledge_package.v1` and
`pocketsec.learning_record.v1`, all at `1.0.0`. The gate joins them to `SCHEMA_REGISTRY` so a
Stage 6 bump is named rather than silently consumed.

| id | layer | symbol | class | ablation flag(s) → simple control |
|---|---|---|---|---|
| ORPH-F01 | 7.0 | `constitution.collective:verify_collective_constitution` | REQUIRED | — |
| ORPH-F02 | 7.1 | `identity.integrity:Keyring.verify` | REQUIRED | — |
| ORPH-F03 | 7.2 | `capsule.compiler:compile_capsule` | REQUIRED | — |
| ORPH-F04 | 7.3 | `privacy.distiller:residual_identifier_hits` | REQUIRED | — |
| ORPH-F05 | 7.4 | `relevance.epistemic_distance:epistemic_distance` | OPTIONAL | `epistemic_distance` → role equality |
| ORPH-F06 | 7.5 | `relevance.gravity:knowledge_gravity` | OPTIONAL | `gravity` → validate every capsule |
| ORPH-F07 | 7.6 | `hivelock.ingress:HivelockIngress.receive` | REQUIRED | — |
| ORPH-F08 | 7.7 | `graph.dependence:DependenceGraph.observe` | REQUIRED, ablated | `dependence_clustering` → declared roots only |
| ORPH-F09 | 7.8 | `echo.inference:EchoEngine.infer` | REQUIRED, ablated | `cluster_cap` → uncapped identity sum; `contextual_trust` → constant prior; `falsification_weight` → 1.0; `contest_mass` → ignore contests; `probation` → 0 rounds |
| ORPH-F10 | 7.9 | `antibody.forge:forge_antibody` | OPTIONAL | `antibody_minimisation` → `copied_rule` |
| ORPH-F11 | 7.10 | `reconstruct.partial_world:PartialWorldReconstructor.reconstruct` | OPTIONAL | `reconstruction` → no reconstruction |
| ORPH-F12 | 7.11 | `novelty.collective:CollectiveNoveltyEngine.evaluate` | OPTIONAL | `collective_novelty` → local novelty only |
| ORPH-F13 | 7.12 | `campaign.hypergraph:CampaignHypergraph.build_edges` | OPTIONAL | `hypergraph` → pairwise co-occurrence |
| ORPH-F14 | 7.13 | `falsifier.consensus:ConsensusFalsifier.falsify` | REQUIRED, ablated | `falsifier` → `count_threshold_join` |
| ORPH-F15 | 7.14 | `lineage.cross_host:CrossHostLineageDAG.ancestry_complete` | REQUIRED | — |
| ORPH-F16 | 7.15 | `lineage.cross_host:RevocationPlane.submit` | REQUIRED | — |
| ORPH-F17 | 7.16 | `hivelock.stage6_bridge:Stage6Bridge.hand_over` | REQUIRED | — |
| ORPH-F18 | 7.17 | `aggregation.secure:aggregate_masked` | OPTIONAL | `secure_aggregation` → plaintext sum |
| ORPH-F19 | 7.18 | `privacy.ledger:PrivacyLedger.charge` | REQUIRED (DP OPTIONAL) | `differential_privacy` → exact counts |
| ORPH-F20 | 7.19 | `governor.communication:CommunicationGovernor.admit_inbound` | REQUIRED | — |
| ORPH-F21 | 7.20 | `orpheus.fabric:OrpheusFabric.run_round` | REQUIRED | — |
| ORPH-F22 | 7.21 | `labs.byzantine_suite:run_byzantine_suite` (lab) | REQUIRED | — |

**Rule C (firing).** Every OPTIONAL or ablated mechanism reports a firing count on the fleet
corpus: the number of decisions, triages, merges, rejections or noise draws that changed an
outcome relative to its control. **A count of 0 is INERT, not measured**, and the ablation row
says so.

---

## 5. Work packages

Eight packages. **No two share a file.** Integrator-owned and in no package:
`pocketsec/stage7/{__init__.py, gate.py, gate_*.py, cli.py}`, `tests/test_stage7_gate.py`,
`docs/stage-7-findings.md`, ADRs 0060–0069, the one `pyproject.toml` line and the one CI step.
Each package owns the empty `__init__.py` of every subsystem directory it is first to populate.

| # | key | delivers | owns (under `pocketsec/stage7/` unless shown) | depends on | ≈ lines incl. tests |
|---|---|---|---|---|---|
| 1 | `foundation` | D7.1, D7.2 schema, core ids | `core_ids.py`, `constitution/{__init__,collective}.py`, `capsule/{__init__,knowledge_capsule}.py`, `tests/test_stage7_foundation.py`; deletes empty `collective/` | — | 1150 |
| 2 | `privacy` | D7.2 compiler, D7.3, fleet corpus | `capsule/compiler.py`, `privacy/{__init__,distiller,ledger}.py`, `labs/{__init__,fleet_corpus}.py`, `tests/test_stage7_privacy.py` | foundation | 1250 |
| 3 | `ingress` | D7.4, D7.7 (ingress), D7.18 (governor) | `identity/{__init__,peer,integrity}.py`, `hivelock/{__init__,ingress}.py`, `governor/{__init__,communication}.py`, `tests/test_stage7_ingress.py` | foundation, privacy | 1250 |
| 4 | `graph` | D7.5, D7.6, D7.8, §22 | `graph/{__init__,dependence,sybil}.py`, `trust/{__init__,contextual}.py`, `relevance/{__init__,epistemic_distance,gravity}.py`, `tests/test_stage7_graph.py` | foundation, ingress | 1200 |
| 5 | `echo` | D7.9 families, D7.10, D7.11 | `aggregation/{__init__,robust}.py`, `antibody/{__init__,forge}.py`, `echo/{__init__,inference}.py`, `tests/test_stage7_echo.py` | foundation, privacy, ingress, graph | 1250 |
| 6 | `campaign` | D7.12–D7.15, campaign arms | `campaign/{__init__,hypergraph}.py`, `reconstruct/{__init__,partial_world}.py`, `novelty/{__init__,collective}.py`, `falsifier/{__init__,consensus}.py`, `labs/campaign_sim.py`, `tests/test_stage7_campaign.py` | foundation, privacy, ingress, graph | 1250 |
| 7 | `sovereignty` | D7.16, D7.17, layer 7.16 bridge, layer 7.20 fabric, the boundary | `lineage/{__init__,cross_host}.py`, `aggregation/secure.py`, `hivelock/stage6_bridge.py`, `orpheus/{__init__,fabric}.py`, `tests/test_stage7_sovereignty.py`, `tests/test_stage7_boundary.py` | 1–6 | 1400 |
| 8 | `adversary` | D7.9 runner, D7.19, D7.20 harness | `labs/{simulated_fleet,byzantine_suite,partition,privacy_attacks,seventy_two_experiments}.py`, `tests/test_stage7_adversary.py` | 1–7 | 1350 |

**Build order is package order.** Packages 1–5 and 7 carry the security boundary. Package 8 does
not start its suite until `tests/test_stage7_{foundation,privacy,ingress,graph,echo,sovereignty,
boundary}.py` pass. Packages build in parallel against the signatures in §4. A package that finds
a signature it depends on unworkable reports it to the integrator. It does not change another
package's file. The line figures are budgets. A package that overruns splits functions, not
features. Tests use small fleets (≤ 8 hosts, ≤ 4 rounds). The full sweep runs only in the gate
and the CLI.

### 5.1 `tests/test_stage7_boundary.py`, owned by `sovereignty`

AST rules for Stage 7 only. The one resolver is `pocketsec.stage2.gate_criteria.imported_modules`.
`tests/test_repository_structure.py` and `tests/test_stage6_boundary.py` are read for the
technique and never edited. Every check walks the AST, never the text. A committed negative
fixture (in the test, via `tmp_path`) proves the checker catches `from ..stage5 import x`,
`from . import research`, `from ...stage6.promotion import controller`, and a
`getattr(x, "_install_trusted")` string.

1. **R1 / ADR-0001.** Only stdlib roots or `pocketsec`, including deferred imports.
2. **R2.** No `pocketsec.stage*.research*` import, and `pocketsec/stage7/research/` does not
   exist.
3. **T2.** No import of `pocketsec.stage5` (relative, deferred and `from pocketsec import stage5`
   all count).
4. **Stage 3/4 none. Stage 2 only `encoder.ssir_encoder`.**
5. **The Stage 6 allow-list of §2.3**, at the granularity of module **and imported name** and
   **importing file**. `from pocketsec.stage6.memory.semantic import genesis_state` is refused
   outside `labs/`. `import pocketsec.stage6.memory.semantic` (a whole-module import) is refused
   everywhere, because names cannot be checked through it.
6. **Stage 6 writer names.** Across `pocketsec/stage7/`, none of `LearningPromotionController`,
   `TrustedMind`, `EvolutionChamber`, `ShadowMind`, `CanaryEvaluator`, `_install_trusted`,
   `_trusted_state`, `with_changes`, `promote_trusted`, `rollback_learning`, `_issue_verdict`,
   `_issued_verdicts` may appear as a Name, Attribute, def, arg or string constant.
7. **The one door.** An `ast.Attribute` named `admit` that is called appears only in
   `hivelock/stage6_bridge.py`. `fleet.package` and `capsule.quarantine` are imported only where
   §2.3 allows.
8. **No execution or network primitive** (§2.2 list), including
   `os.system`/`os.popen`/`os.exec*`/`os.spawn*` attribute calls.
9. **T5.** No annotated `@dataclass` field whose lowercased name contains a
   `FORBIDDEN_AUTHORITY_FIELDS` member. No exemption list.
10. **Runtime never imports labs.** No module outside `labs/` and the integrator's harness
    (`gate.py`, `gate_*.py`, `cli.py`) imports `pocketsec.stage7.labs`, and nothing outside the
    harness imports the harness.
11. **T7 / no earlier stage depends on Stage 7.** No module under `pocketsec/stage0/`…`stage6/`
    imports `pocketsec.stage7`. Stage 6's `capsule/quarantine.py` is T3's only permitted
    importer and today imports nothing from Stage 7. The test asserts the "nothing" and names
    the permission.
12. **No second harness, ledger, contracts or corpus type.** No directory named `contracts`,
    `benchmark`, `experiments` or `research`. No `def run_benchmark`,
    `class ExperimentRegistry`, `class Scenario`, `class Behaviour`, `class QuarantineGateway` or
    `class PromotionController`.
13. **No empty package (ADR-0121)**, and `collective/` does not exist.

---

## 6. Acceptance gate, as executable checks

Eleven checks, one per bullet of architecture §50 in its order (integration plan §5.1 fixes the
count at 11). `Stage7GateContext.build()` builds the fleet corpus once and runs the suite,
privacy attacks, campaign simulation, partition and scale runs and the resource run once each.
Every check runs the real subsystem. A check over zero objects is **VACUOUS and FAILS** with the
reason (Stage 6 precedent), never passes.

| id | §50 criterion | executable check | met on synthetic data? |
|---|---|---|---|
| **G7.1** | No remote object can bypass Stage 6 quarantine | **(a) Construction:** boundary rules 5, 6, 7, 10 and 11 evaluated in-gate, 0 offenders; `verify_collective_constitution() == ()`. **(b) Behaviour:** over every suite arm, `bridge.created() == bridge.admitted()`, and the lab gateway's `offered` count rose by exactly that number; no `ExperienceCapsuleV1` exists in the run that the bridge did not build. **(c) Unanimous fleet (lead's test):** 64 independent-root peers all agree against the receiver. (i) Revoke a local-origin antibody: 64/64 refused `local_sovereignty`, antibody live. (ii) SUPPORT an antibody that FPs locally: CHALLENGED, 0 bridged. (iii) CONTEST a locally confirmed antibody: 64/64 refused at ingress, local key unaffected. (iv) Authority-keyed payloads: 64/64 refused at SCHEMA. (v) Whatever is bridged in the unanimous arms lands in a Stage 6 bucket other than TRUSTED_CANDIDATE, reported with counts (M0.2 predicts all). **PASS iff (a), (b), (c)(i)–(iv) hold, (v) is reported, and the whole thing ran over ≥ 1 bridged capsule** | yes |
| **G7.2** | No Stage 7 path can directly execute Stage 5 response | Boundary rules 3, 8 and 9. The wire-key fuzz: each of the 12 `FORBIDDEN_AUTHORITY_FIELDS` words injected as a key at top level and at every nested record is refused by `KnowledgeCapsuleV1.from_dict` (12 × depth, all refused). The AUTHORITY_INJECTION arm: 0 capsules pooled. **PASS iff 0 offenders and every injection refused** | yes (construction) |
| **G7.3** | Local detection remains fully operational with network disabled | `run_offline_equivalence` for every receiver: the digest of local outputs is identical with the fabric absent, OFFLINE under a FLOOD, DISABLED, crashing every round (injected exception), and with the keyring state corrupted (fabric → DISABLED). Plus rule 11 (T7). **PASS iff identical for every receiver and the corrupt-keyring run reached DISABLED** | yes. The partition is simulated; real network loss is UNMEASURED |
| **G7.4** | Sybil influence is bounded by provenance/dependence controls | `run_byzantine_suite` over SYBIL_DECLARED_ROOT, SYBIL_FORGED_ROOTS and SYBIL_ADAPTIVE at every `SYBIL_COUNTS` value with 1 adversary root against `HONEST_ROOTS`. Reports ECHO's amplification factor and MAJORITY/MEDIAN/MEAN's beside it, and the break point per aggregator. **PASS iff ECHO's amplification ≤ 1.0 + 0.05 on DECLARED_ROOT (construction), ≤ 2.0 on FORGED_ROOTS and ≤ 2.0 on ADAPTIVE at every S.** Firing: DependenceGraph merges by kind > 0 | **NO**: see §6.1 |
| **G7.5** | Non-IID legitimate hosts are not treated as malicious merely for statistical difference | Arm NONE with the rare ADMIN role. (a) Rare-role honest antibodies (forged on ADMIN, validated locally) reach ELIGIBLE at ADMIN receivers at a rate ≥ majority-role antibodies at their own-role receivers − 0.05. (b) The DependenceGraph merges honest peers of different true roots in ≤ 5% of honest peer pairs (false-Sybil rate). (c) No honest rare-role cluster's reliability falls below `TRUST_PRIOR` without a local refutation (contests alone never refute). Reports the share of rare-role peers that KRUM/MULTI_KRUM/BULYAN excluded as outliers. **PASS iff (a), (b), (c)** | yes (synthetic roles) |
| **G7.6** | Distributed campaigns are validated against benign common-cause hypotheses | `run_campaign_sim` over every `CampaignArm`. Every SUPPORTED world has a `ConsensusFalsification` with 6 tests and none UNEVALUATED. False collective campaign rate ≤ `count_threshold_join`'s and ≤ 0.10. True-campaign recall > 0 on TRUE_CAMPAIGN_{2,4,10}. Each of H0–H4 rejected ≥ 1 benign-arm world (else that test is INERT and the check FAILS). **PASS iff all** | yes as mechanism. Common causes are authored with the falsifier (confounded, §9) |
| **G7.7** | Privacy leakage is measured, not assumed absent because raw data stays local | (a) `canary_scan` over every byte exported in the gate: every `corpus.raw_strings` and every `corpus.raw_digests` searched, **0 hits**. (b) For every knowledge type, `flatten_keys(to_dict()) == EXPORT_FIELD_TABLE` keys. (c) `membership_inference` and (d) `property_inference`, distilled vs `raw_steps_control`, with non-None advantages; the raw control's advantage must exceed chance by ≥ 0.1, else `DEGENERATE` (the attack is not real) and the check FAILS. (e) `dp_curve` present with ≥ 4 ε points. (f) `siem_oracle`'s canary exposure is reported as the privacy cost of the central-SIEM baseline. **PASS iff (a) = 0, (b) exact, (c)(d) measured and not DEGENERATE, (e) present** | yes |
| **G7.8** | All promoted foreign knowledge has cross-host and local lineage | Every ELIGIBLE decision: `lineage.ancestry_complete(decision_id)` (contributors, commitments, decision record). Every bridged capsule: `local_dag.has(stage6_capsule_id)` with a VERDICT child. Then **promoted**: the count of bridged capsules Stage 6 put in TRUSTED_CANDIDATE and later promoted. **If that count is 0, the "promoted" clause is VACUOUS and the check FAILS**, naming B7-1. **PASS iff the lineage clauses hold over ≥ 1 bridged capsule and ≥ 1 foreign item was promoted with lineage** | **NO**: B7-1 (M0.2) |
| **G7.9** | Revocation is targeted and reversible | On a lineage built by the suite: a SELF_RETRACTION of a capsule with ≥ 2 generations of descendants marks **exactly** `descendants(target)` SUSPECT (non-descendants changed: 0) and moves exactly the affected ECHO keys to SUSPECT. `stage6_capsule_ids` equals exactly the STAGE6_LINKs beneath. `reinstate` returns the DAG digest to `prior_digest` byte-for-byte. The FALSE_REVOCATION arm (third party, forged `LOCAL_EVIDENCE`, unknown target, local-origin target): 0 state changes. **PASS iff all.** The detail states that Stage 6-side rollback is UNMEASURED (B7-2) | yes (Stage 7's half) |
| **G7.10** | Stage 7 remains inside the Stage 0 resource envelope | `measure_stage7_resources` around the FLOOD arm at 1000 simulated peers plus `run_scale` to 10 000 peers. Incremental RSS (sampled peak − start, floored 0) ≤ `STAGE7_INCREMENTAL_CEILING_BYTES`, reported against the 55 MiB normal target. `check_profile(..., "edge")`. Every store's `memory_bytes()` and count ≤ its cap at every round, with eviction or refusal counters > 0 for every store the flood reaches (the flood must hit a bound). Outbound bytes per round ≤ `MODE_ROUND_BYTES[mode]`. `run_churn_endurance` has `plateau_ok`. RSS unreadable → `within_ceiling is None` → UNMEASURED → **FAIL**. Wall clock and loadavg recorded, never asserted | yes, in-process on the dev host. Device figures are UNMEASURED |
| **G7.11** | ECHO/ORPHEUS survives ablation against simpler FL and threat-intel baselines | Preconditions P1–P4 (BLOCKED → FAIL). Then §7's comparisons from one `run_byzantine_suite` and `run_ablation`: detection gain over NO_SHARING ≥ `DETECTION_GAIN_MIN`; ECHO's break point strictly above MEDIAN's (and TRIMMED_MEAN's) on the Sybil arms and ≥ on the Byzantine arms; ECHO vs ROOT_QUORUM+LV and VALIDATION_FILTER; every OPTIONAL/ablated flag has an `AblationRow` with a non-None delta, a firing count and a verdict; the threshold sensitivity sweep is present; `catalogue_problems() == ()`; `experiments/registry.jsonl` is byte-identical before and after; `docs/stage-7-findings.md` exists with all six honesty-ledger headings; `set(HYPOTHESES) == {H0…H8}`. **FAILS by construction on synthetic data**: PASS additionally requires `ByzantineReport.synthetic is False` | **NO** |

### 6.1 The criteria that cannot be met here, declared

- **G7.8: NOT MET, blocked on Stage 6 (B7-1, ADR-0067).** Stage 6 scores every foreign capsule at
  0.08 < 0.5 (M0.2), so no foreign knowledge is ever promoted, and "all promoted foreign knowledge
  has lineage" is vacuous. The check fails instead of passing on nothing. Stage 7 cannot fix this
  without editing Stage 6, which it may not do. The lineage clauses Stage 7 *can* settle (cross-host
  ancestry of every ELIGIBLE decision, a Stage 6 lineage node for every bridged capsule) are checked
  and reported in the detail.
- **G7.4: NOT MET for the adaptive arm; the absent dependency is an identity authority.** Declared
  provenance roots are claims. In the simulator an adversary mints a fresh root for free. A
  forged-root, staggered-birth, jittered Sybil defeats every behavioural edge by construction. It
  can be stopped only by contests from same-role honest peers and by local validation, neither of
  which is a provenance control. Binding roots to real administrative domains needs asymmetric
  signatures or attestation (ADR-0001: none in stdlib; ADR-0064). The declared-root bound holds by
  construction (per-cluster cap). The check is written to include the adaptive arm and is expected
  to FAIL there. The measured break point is the finding.
- **G7.11: NOT MET, synthetic data.** The fleet corpus, the adversaries and the defences share an
  author (lesson 6). M0.3/M0.4 show transfer is saturated in favour of sharing. A mechanism shown
  JUSTIFIED here has shown its *mechanism* works, not that it survives a real fleet. A mechanism
  that is NOT_YET_JUSTIFIED, HARMFUL or INERT here has no evidence for it, and the findings
  recommend removing it.
- **Met as mechanism, UNMEASURED as value:**
  - G7.3: real network partitions and real stale-peer behaviour.
  - G7.5: real rare roles.
  - G7.6: real common-cause events.
  - G7.7: real attackers, and the DP claim beyond the count release.
  - G7.10: a real 2 GB device (tests-and-tooling Trap 16).

---

## 7. The baselines Stage 7 must beat

All figures come from one `run_byzantine_suite` on identical pools (§4.21). Detection is
`counterfactual_at_boundary` recall at `FPR_BUDGET` via `recall_at_max_fpr`. Robustness is the
poison-acceptance rate and the break point at `BREAK_LEVEL`.

| baseline (the dumbest thing that could work) | question (§47) | Stage 7 must beat it on | if it does not |
|---|---|---|---|
| **NO_SHARING**: every host learns alone | does collective intelligence add value? | mean receiver recall on locally-unseen families by ≥ `DETECTION_GAIN_MIN` at share 0 **and** at share 0.2, without raising receiver FP rate above NO_SHARING's + 0.01 | collective adds nothing → Stage 7 is **NOT-YET-JUSTIFIED**; ADR-0068 recommends shipping nothing but the boundary |
| **MAJORITY** (identity vote) and **MEAN** (= FedAvg's rule on stance vectors) | why independence-aware evidence matters; does capsule intelligence beat ordinary averaging? | Sybil break point (identity share) and amplification factor | ECHO's independence machinery is decorative |
| **MEDIAN** and **TRIMMED_MEAN** (β = 0.2), the dumbest Byzantine-robust aggregators | does ECHO improve robust aggregation? | break point: **strictly** higher on every Sybil arm, **≥** on every Byzantine arm; and at every share, ECHO poison acceptance ≤ MEDIAN+LV's + 0.05; at share 0, ECHO true-antibody acceptance ≥ MEDIAN's − 0.05 (not accept-nothing) | ECHO is **NOT-YET-JUSTIFIED**; recommend MEDIAN + local validation |
| **KRUM / MULTI_KRUM / BULYAN** | Byzantine baseline families | break point and rare-role exclusion rate (G7.5) | reported. Krum's known rare-client exclusion is the non-IID contrast |
| **VALIDATION_FILTER**: any single peer's antibody that passes local validation | isolates local validation from aggregation (lesson 4) | poison acceptance on BYZANTINE_LATENT_POISON and SLOW_POISON, where local validation is blind by construction | aggregation adds nothing over local replay |
| **ROOT_QUORUM + LV**: ≥ 2 distinct clusters, more supporters than contesters, local validation | the control for ECHO's extra terms (gravity, distance, trust, falsification weight, probation) | at least one robustness metric by > 0.05 without losing detection | ECHO's extra terms are **NOT-YET-JUSTIFIED**; reduce ECHO to ROOT_QUORUM + LV (ADR-0068) |
| **CENTRAL_FEED** (one curated root, `FEED_LAG_ROUNDS` behind) | does bidirectional discovery add value over a threat-intel feed? | time-to-detect for a newly seen family (rounds) at equal FP | a feed suffices |
| **SIEM oracle** (receiver sees all raw labelled episodes) | what privacy/resource capability is traded? | not beaten on detection by design (upper bound); compared on canary exposure (G7.7(f)) and bytes moved | reported as the trade-off |
| **Secure-aggregation-only** (MEAN under masking) | privacy without robustness | novelty-count inflation under SYBIL_FORGED_ROOTS: secure sum vs plaintext sum + per-cluster clamp | secure aggregation's cost to robustness is the finding, not a failure |
| FedProx / personalised FL | does heterogeneity handling suffice? | **UNMEASURED: no model parameters exist** (ADR-0062) | — |

Per mechanism, the control that isolates it (ablation = full ECHO/fabric with that one flag
replaced):

| core id / flag | mechanism | simple control | metric | firing count |
|---|---|---|---|---|
| ORPH-F05 `epistemic_distance` | D_E relevance | role equality | receiver FP rate from cross-role antibodies; ELIGIBLE rate of useful antibodies. **Plus AUC of −D_E predicting local usefulness (TP > 0, FP = 0 on the receiver's held-out)**: falsifier F6 | decisions differing from role-equality |
| ORPH-F06 `gravity` | triage | validate everything | work units saved vs recall lost | capsules triaged to metadata |
| ORPH-F08 `dependence_clustering` | behavioural merge | declared roots only | amplification on FORGED/ADAPTIVE | merges by kind |
| ORPH-F09 `cluster_cap` | per-cluster cap | uncapped identity sum | amplification on DECLARED_ROOT | decisions changed |
| ORPH-F09 `contextual_trust` | §22 reputation | constant prior | poison acceptance on SLOW_POISON (**HARMFUL if it raises it**) | decisions changed |
| ORPH-F09 `falsification_weight` | self-reported survival | 1.0 | poison acceptance (expected INERT: adversaries report perfect survival) | decisions changed |
| ORPH-F09 `contest_mass` | honest counter-evidence | ignore contests | LATENT_POISON acceptance vs SUPPRESS success | decisions changed |
| ORPH-F09 `probation` | 2-round hold | 0 rounds | COLLUSION_TIMING bridged poison | bridges delayed/avoided |
| ORPH-F10 `antibody_minimisation` | §13 minimal core | `copied_rule` | receiver recall and FP on transfer; bytes | antibodies differing from copied rule |
| ORPH-F11/F13/F14 | reconstruction, hypergraph, falsifier | none / pairwise / `count_threshold_join` | false campaign rate, true recall, time-to-detect | worlds changed |
| ORPH-F12 `collective_novelty` | population rarity | local novelty only | S7X-38 rare-benign false-novel rate vs S7X-39 unknown-campaign recall | statuses changed |
| ORPH-F18 `secure_aggregation` | masked sum | plaintext | exactness; inflation under Sybil | rounds summed |
| ORPH-F19 `differential_privacy` | geometric noise | exact counts | the ε/utility/advantage curve | noise draws that changed a status |

Required mechanisms (clustering, cap, falsifier) are ablated anyway. A required defence that never
fires is still a finding.

---

## 8. What would falsify this stage's central claim

**Central claim.** Stage 7 lets a host gain detection from other hosts' knowledge. No foreign
object reaches trusted state except through Stage 6's gateway. No collective outcome overrides a
local decision. Sybil influence scales with independent provenance roots, not identities.
Poisoned-knowledge acceptance stays below that of the median aggregator. Nothing host-identifying
leaves the host.

| # | falsifier | where measured | consequence |
|---|---|---|---|
| F1 | any AST or behavioural path by which a foreign object reaches Stage 6 other than `Stage6Bridge.hand_over` → `admit`, or reaches Stage 5 at all | G7.1, G7.2 | the boundary is void; **BLOCK** the stage |
| F2 | the unanimous fleet changes any local decision | G7.1(c) | sovereignty void; BLOCK |
| F3 | detection gain over NO_SHARING < 0.10 on locally-unseen families (architecture §49.1) | G7.11, §7 | collective intelligence adds nothing here → NOT-YET-JUSTIFIED |
| F4 | ECHO's break point ≤ MEDIAN's on the Sybil arms (§49.4 "dependence-aware evidence does not materially improve Sybil/collusion resistance") | G7.4, G7.11 | recommend MEDIAN + local validation |
| F5 | ECHO within 0.05 of ROOT_QUORUM+LV on every metric | §7 | gravity/distance/trust/falsification weight are decorative; reduce ECHO |
| F6 | AUC of −D_E predicting transfer usefulness ≤ 0.6 (§49.3) | §7 | epistemic distance NOT-YET-JUSTIFIED; use role equality |
| F7 | any canary or raw digest in exported bytes, or an undeclared field exported | G7.7 | privacy void; BLOCK export |
| F8 | distilled antibodies lose signal: receiver recall < raw-steps control − 0.05 (§49.2) | G7.7, §7 | distillation too lossy |
| F9 | the falsifier's false campaign rate ≥ `count_threshold_join`'s (§49.5), or collective novelty's false-novel rate on S7X-38 ≥ its unknown-campaign recall on S7X-39 (§49.6) | G7.6, §7 | reconstruction / novelty adds population noise |
| F10 | contextual trust raises poison acceptance on SLOW_POISON | §7 | reputation is HARMFUL; remove it |
| F11 | any store exceeds its cap, RSS exceeds the ceiling, or the churn plateau fails (§49.8) | G7.10 | bounded-state claim void |
| F12 | revocation affects a non-descendant, or reinstatement does not restore the digest (§49.9) | G7.9 | revocation is not targeted/reversible |
| F13 | foreign knowledge survives Stage 6 at rate 0 (§49.7). **Fires today (M0.2: 0/40)** | G7.8 | the value path is closed; the lead decides Stage 6's foreign prior |
| F14 | Stage 7 accepts more poison (ECHO ELIGIBLE poison share) than it adds true antibodies at any share ≤ 0.3 (§49.10: "increases poisoning risk more than collective detection benefit") | §7 | net harmful at that share; state the share |

---

## 9. Honest limits: what this wave cannot prove

### 9.1 The two that matter most

1. **Stage 6 admits no foreign knowledge (M0.2).** Every "gain" in this stage is a counterfactual
   at Stage 7's own boundary. Realised on-host collective detection is **0 by construction** under
   Stage 6's current parameters. It becomes measurable only if the lead revises
   `SOURCE_CLASS_PRIOR[FOREIGN_HOST]` or `FLAG_RISK[FOREIGN_ORIGIN]` in Stage 6, and that is not
   Stage 7's decision.
2. **The fleet, the attacks and the defences are all simulated and share an author.** There is no
   real network and no real fleet. Every corpus is synthetic and saturated in favour of sharing
   (M0.3, M0.4). The robustness comparison is confounded (lesson 6). The claims this wave can
   settle are **construction and bound properties**: the one door, no Stage 5 path, the per-cluster
   cap, bounded stores, targeted and reversible revocation, the field table and the canary scan.

### 9.2 The rest

- HMAC-SHA256 over simulated pre-provisioned keys proves key possession, not host identity.
  Ed25519, mutual TLS, QUIC, Protobuf/FlatBuffers and zstd are UNMEASURED (ADR-0001, ADR-0064).
- Declared provenance roots are claims. There is no administrative attestation, and the
  adaptive-Sybil arm shows what that costs.
- `ValidationSummary` and `FalsificationSummary` are self-reported and forgeable. Only the
  receiver's local validation is evidence.
- Secure aggregation is a masking prototype: no key agreement, no dropout recovery, no
  malicious-aggregator detection, off by default.
- DP covers only population count releases. It is pure-ε under a contribution clamp with basic
  composition, not formally verified, and side channels are unmeasured.
- The receiver's benign ring and local incidents come from lab ground truth: optimistic. A
  poisoned local benign ring is UNMEASURED.
- The antibody grammar is Stage 6's motif. It cannot express counts, timing or chains longer
  than 2 steps.
- `policy_distance` and `architecture_distance` (§7), active distinguishing-observation requests
  (§18), anti-collusion challenge sets sent to peers (§38; local validation on the receiver's
  private holdout is the only challenge built), ADWIN/DDM drift baselines (§40), FedProx and
  personalised FL, model deltas and backdoor adapters: not built or UNMEASURED, each with a reason
  in the ledger.
- Stage 6 exposes no revocation input (B7-2). Stage 7 computes the targeted Stage 6 capsule set
  and cannot act on it.
- Wall clock is contended. RSS is an in-process dev-host figure. Timing figures are within-run
  ratios only.
- Every threshold in §4.23 is a chosen parameter. None is calibrated.

---

## 10. ADRs: block 0060–0069, all ten assigned

The integrator writes all ten from `docs/adr/0000-adr-template.md`. Each keeps an **Options
considered** table with a measured-consequence column.

| ADR | title | status at spec time |
|---|---|---|
| 0060 | Stage 7 layout amendments (bridge not quarantine, lineage/trust/fabric added, `collective/` deleted), no research package, no H13: BASE for the gate, H8 for ablation | decided (§2.1, §2.6) |
| 0061 | Stage 7 consumes Stage 6 through a module-and-name allow-list; the bridge is the one caller of `admit`; foreign knowledge enters Stage 6 only through `fleet.package` rewrites | decided (§2.3) |
| 0062 | Knowledge types are those with a consumer; DRIFT_NOTICE and MODEL_DELTA are refused; FedAvg reduces to MEAN on stances; FedProx/personalised FL not applicable; §14's graded match reduced to boolean | decided (§4.2, D7.11) |
| 0063 | Foreign peers may suggest what to fear, never what to trust: no foreign normality; contests only reduce mass; foreign revocation only as self-retraction | decided (§4.0, D7.16) |
| 0064 | HMAC with simulated pre-provisioned keys proves key possession, not identity; provenance roots are declared claims | decided (D7.4) |
| 0065 | What leaves the host, by field; evidence as keyed commitments; `attack_mappings` always empty; DP only on population counts; PrivacyCost, policy and architecture distance not bound | decided (D7.3) |
| 0066 | Secure aggregation is an off-by-default masking prototype that aborts on dropout and claims no guarantee | decided (D7.17) |
| 0067 | **Blockers B7-1 and B7-2:** Stage 6 admits no foreign capsule (0.08 < 0.5, measured 0/40) and has no revocation input; Stage 7 measures at its own boundary | **decided from M0.2**; findings add the gate's figures |
| 0068 | ECHO verdict against MEDIAN, ROOT_QUORUM+LV and VALIDATION_FILTER | **written from measurement** by the integrator |
| 0069 | Sybil break point; verdicts for contextual trust, epistemic distance, gravity, minimisation, collective novelty and DP | **written from measurement** |

---

## 11. The honesty ledger `docs/stage-7-findings.md` must end with

The structure is verbatim from integration plan §7, plus PARAMETERS (Stage 6 precedent):

```markdown
## Honesty ledger

### MEASURED
| claim | value | how it was produced (module:function) | experiment id | synthetic? |
|---|---|---|---|---|

### UNMEASURED
| claim the architecture makes | why not measured | what would measure it | blocking? |
|---|---|---|---|

### REJECTED
| component | measured effect | verdict (REJECTED / NOT-YET-JUSTIFIED / RETRACTED / INERT / DEGENERATE / HARMFUL) | ADR |
|---|---|---|---|

### RETRACTED
| retracted claim | where it was published | the defect | corrected value |
|---|---|---|---|

### NOT A DETECTION RESULT
Every corpus is synthetic; the fleet is simulated in-process; every detection gain is a
counterfactual at the Stage 7→Stage 6 boundary, because Stage 6 admits no foreign capsule.

### PARAMETERS
Every §4.23 constant, with the sentence "chosen, not measured".
```

Every MEASURED row quotes its number inline (`results/*.json` is git-ignored) and records
`/proc/loadavg` beside any timing. M0.1–M0.4 of §0 are the first four MEASURED rows.

---

## 12. Completion output

The integrator ends the wave with the phase file's nine-item block:

1. `PHASE 7 STATUS: COMPLETE | PARTIAL | BLOCKED`.
2. Implemented checklist IDs 01–20.
3. Files changed.
4. Tests run, with exact counts. Count with `--junitxml`, because `-q` on top of `addopts = "-q"`
   suppresses the summary line (MEMORY Stage 5 trap 5).
5. Measured benchmark and resource results, with load averages.
6. Unresolved defects.
7. ADRs 0060–0069.
8. The exact MEMORY.md and PROGRESS.md edits.
9. The recommended next phase, **without starting it**.

**Expected status: PARTIAL.** G7.8 is blocked on Stage 6 (B7-1). G7.4's adaptive arm needs an
absent identity authority. G7.11 fails by construction on synthetic data (§6.1).
