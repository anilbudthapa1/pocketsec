<!-- Extracted verbatim from the architecture source `PocketSec_Stage_4_Causal_Belief_Field_Final_v2.docx`.
     Text-only conversion for tooling; the .docx remains the authoritative artefact. -->

POCKETSEC
Stage 4 — Causal Belief Field
CBF + LUCID: Self-Questioning, Counterfactual, Evidence-Conserving Security Cognition
Stage 4 does not correlate alerts. It maintains a sparse field of possible security worlds, continuously predicts what evidence each world should produce, searches for contradictions, actively chooses the cheapest observation that can collapse uncertainty, and emits a conclusion only when the surviving world-model is sufficiently identified.
Advanced Final Research & Implementation Specification v2.0 • 22 September 2026

# 1. Why v1 Was Too Conventional

The earlier Stage 4 still resembled an advanced SIEM correlator: evidence → hypotheses → incident. That is useful, but not enough for PocketSec. The revised Stage 4 treats incident understanding as online system identification under partial observability. It reasons not only about events that occurred, but about latent security state, expected-but-missing evidence, sensor visibility, alternative causal worlds, and the value of future observations.

# 2. New Research Theory — Causal Belief Field (CBF)

A Causal Belief Field is a bounded set of competing latent security-world models. Each world explains how the host could have produced the current evidence and predicts what should be observed next. Worlds gain or lose support as evidence arrives. They may split, merge, crystallize, collapse or remain unresolved.

# 3. Experimental Engine — LUCID

LUCID means Latent Uncertainty and Causal Identification Dynamics. LUCID updates the CBF, challenges its own explanations, computes discriminating observations and decides when the evidence is sufficient to resolve an incident.
W_i(t) = ( latent_security_state, causal_mechanism, expected_observations, forbidden_observations, visibility_model, temporal_hazard, consequence, contradictions, evidence_lineage, uncertainty)CBF_t = { (W_i, support_i) } for i = 1..K, with K hard-bounded

# 4. The Core Change: Infer Worlds, Not Labels

Instead of asking “is this event malicious?”, Stage 4 asks which latent world could have generated the evidence.
Observed:  ssh login -> shell -> sudo -> read sensitive file -> TLS egressPossible worlds: W1 approved administration W2 compromised administrator session W3 stolen SSH credential W4 legitimate automation with unusual destination W5 unresolved novel mechanismEach W predicts DIFFERENT missing/next evidence.
The useful intelligence lies in the differences between those predictions.

# 5. Partial Observability Model

Linux telemetry is incomplete by construction. LUCID therefore separates world state from observed evidence.
latent world state: X_tobservation:         O_tsensor policy:       A_tvisibility:          V_tX_(t+1) ~ Transition(X_t, event)O_t      ~ Observation(X_t, A_t, V_t)
This prevents the dangerous inference “I did not observe it, therefore it did not happen.”

# 6. Sensor Shadow

Every inference carries a Sensor Shadow: what PocketSec could not observe under the active collection policy.
Shadow_t = PotentialSecurityEvidence - ObservableEvidence(A_t, kernel, privileges, dropped_events)
The Sensor Shadow directly modifies confidence and can trigger Stage 1 observation escalation.

# 7. Evidence Tension

Rather than only accumulating supporting evidence, LUCID measures tension between a world and reality.
Tension(W) =  unexpected_observation_cost+ missing_expected_evidence_cost+ causal_inconsistency+ temporal_inconsistency+ security_state_inconsistency+ visibility_adjusted_contradiction
A world can die from accumulated tension even if no single event disproves it.

# 8. Negative Evidence Without the Classic Trap

Missing evidence counts against a world only when the visibility model says PocketSec should have observed it.
If P(observe e | e occurred, A_t, V_t) is highAND W strongly predicts eAND e is absent,then absence is informative.Otherwise:absence remains UNKNOWN.
This turns Stage 2 negative-space learning into an incident-level mechanism.

# 9. Causal Intervention Operator

LUCID does not merely correlate ancestry. It performs bounded virtual interventions over its internal world models.
do(remove E17)do(replace actor semantic class)do(block privilege transition)do(remove destination novelty)Measure:  change in predicted security outcome  change in world support  change in future evidence distribution
This is an approximation to causal responsibility, not a claim that observational endpoint telemetry magically identifies true causality.

# 10. Responsibility Flux

Responsibility is dynamic. As evidence arrives, causal responsibility can move between events.
RF(E_j,t) = change in security-world distribution when E_j is counterfactually perturbed
The Causal Spine is therefore updated as a flux, rather than frozen at first detection.

# 11. Belief Geometry

The CBF is not required to be one probability vector. Stage 4 benchmarks multiple representations:
Representation
Strength
Risk
Calibrated probabilities
simple decisions
misleading if model misspecified
Log-odds / energy
stable incremental updates
not automatically probabilistic
Evidence intervals
represents imprecision
more complex composition
Conformal sets
coverage-oriented abstention
exchangeability/drift limitations
e-values/e-process style evidence
sequential evidence accumulation
requires careful null construction
The representation is selected empirically; Stage 4 does not call arbitrary neural scores probabilities.

# 12. World Birth

A new world is created only when existing worlds cannot explain a security-relevant residual.
Residual = ObservedEvidence - BestExplainedEvidenceif residual is:  security-relevant  persistent  not visibility artifact  not explainable by existing worldsthen:  spawn bounded UNKNOWN world
This allows zero-day/novel behaviour without generating a hypothesis for every anomaly.

# 13. World Death

Kill W when:  hard contradictionOR sustained evidence tensionOR dominated by simpler world with equivalent explanatory coverageOR epoch invalidationOR assurance falls below threshold
Killed worlds remain in a compact tombstone record to prevent oscillation and support later reopening.

# 14. World Fission and Fusion

FISSION:one world predicts incompatible evidence regimesW -> W_a + W_bFUSION:two worlds become observationally/security equivalentW_a + W_b -> W*
This borrows the adaptive-complexity philosophy of Stage 2/3: representational complexity appears only where reality demands it.

# 15. Counterfactual Future Cones at Incident Scale

Stage 2 predicts local Future Cones. Stage 4 composes them into incident-level counterfactual futures.
W2 compromised session:  branch A -> persistence  branch B -> credential access  branch C -> data staging  branch D -> session endsW1 benign admin:  branch A -> package/service action  branch B -> logoutObserved next evidence collapses branches/worlds.
Only bounded security-relevant futures are maintained.

# 16. Information Geometry — Find the Most Discriminating Observation

The next sensor action should distinguish worlds, not merely collect more data.
Discrimination(o) = expected distance between posterior world fields after possible outcomes of oUtility(o) = Discrimination(o) * SecurityConsequence / (CPU + memory + telemetry volume + privilege/risk cost)
This is more targeted than generic anomaly-driven telemetry escalation.

# 17. Counterfactual Sensor Planning

Before enabling expensive telemetry, LUCID simulates whether that telemetry could actually distinguish the leading worlds.
candidate sensor actions:  trace file access for PID subtree  increase exec lineage depth  temporarily capture DNS metadata  watch one persistence path  collect one process hash  inspect one systemd unit changeIf predicted outcomes are nearly identical across worlds:  do NOT spend the telemetry budget.
This is a key route to extremely low overhead.

# 18. Security Free-Energy Analogy — Strictly Operational

Stage 4 may experimentally use an active-inference-like objective, but without claiming biological or physical equivalence.
F_security =  unresolved_world_uncertainty+ evidence_prediction_error+ consequence_weighted_unknownness+ sensing_costChoose bounded action that reduces expected F_security.
If this objective does not outperform simpler information-gain planning, it is removed.

# 19. Incident Identifiability

A crucial new concept: some incidents are fundamentally not identifiable from available endpoint telemetry.
Identifiable(H) iff available/affordable observations can distinguish H from material alternatives within required error bounds.
PocketSec should explicitly report NON-IDENTIFIABLE instead of fabricating certainty.

# 20. Resolution Horizon

Each high-consequence ambiguity receives a bounded Resolution Horizon.
Resolution Horizon =  max time / evidence / compute budget  allowed before:    resolve    escalate to analyst    preserve as unresolved    request higher observation tier
This prevents endless reasoning loops.

# 21. Semantic Conservation

Stage 3 crystallized semantics must survive Stage 4 abstraction.
If evidence says:  process P read object classified CREDENTIAL_MATERIALStage 4 may infer:  possible credential accessIt may NOT infer:  password stolenunless evidence supports that stronger statement.
Abstraction is allowed; factual amplification is not.

# 22. Epistemic Type System

Every field in the authoritative Incident Object has a type:
Type
Meaning
OBS
direct observation
DER
deterministic derivation
INF
model inference
CF
counterfactual result
EXT
external knowledge mapping
UNK
unknown/unobserved
The type system is enforced by serialization and renderer APIs, not merely documentation.

# 23. Claim Compiler

Human-readable claims are compiled from typed evidence, not generated freely.
claim template:[INF] Possible credential-access sequencebecause:  [OBS] E17 ...  [DER] parent-child relation ...  [OBS] E24 ...against:  [OBS] approved session metadata ...unknown:  [UNK] direct exfiltration evidence
A language model can paraphrase only after the typed claim exists.

# 24. Self-Questioning Engine

For every high-consequence world, LUCID automatically generates challenges:
What evidence would falsify this world?What alternative explains the same evidence?Which claim depends on missing visibility?Which single event carries too much responsibility?What expected evidence is absent?Would actor renaming change the conclusion?Would removing novelty change the conclusion?Is the ATT&CK mapping stronger than the evidence?
These questions are executed as structured tests, not sent as open-ended prompts.

# 25. Adversarial Belief Stress

Before resolving an incident, high-consequence conclusions are attacked by synthetic perturbations.
- Insert plausible benign context and test whether conclusion collapses.
- Remove one critical event at a time.
- Rename binaries/users/paths while preserving semantics.
- Delay steps to simulate low-and-slow behaviour.
- Inject benign decoys into ancestry.
- Drop telemetry according to realistic sensor loss.
- Replace exact IOCs with unseen equivalents.
- Perturb epoch/configuration context.

# 26. Belief Crystallization

Stage 4 connects back to Stage 3: recurring resolved incident-world structures may become Stage 3 Knowledge Cells.
repeated CBF resolution    ↓stable incident invariant    ↓Stage 3 CRYSTAL candidate    ↓future incidents become cheaper
Thus the system learns not only event dynamics but how to resolve incidents.

# 27. Reverse Flow: Knowledge Cells Can Be Challenged

Stage 4 contradictions can send pressure backward into Stage 3.
Knowledge Cell says known benign transitionStage 4 world field accumulates contradictory security evidence        ↓cell stress signal        ↓Stage 3 audit / partial melt
No stage is allowed to become permanently unquestionable.

# 28. Sparse World Graph

Full provenance graphs can become enormous. Stage 4 stores a sparse causal world graph containing only evidence with explanatory, contradictory or discriminating utility.
node retained if:  causal_credit > θ  OR contradiction_value > θ  OR discrimination_value > θ  OR mandatory evidence retention
USENIX 2025 provenance research emphasizes that attribution quality and concise attack reconstruction matter operationally; Stage 4 makes this a first-class resource constraint.

# 29. Incident Entropy Budget

Each incident receives a bounded reasoning budget.
Budget_I = { max_worlds, max_edges, max_counterfactuals, max_sensor_escalations, max_reasoning_ms, max_memory_bytes}
When the budget is exhausted, LUCID must prune safely or abstain/escalate. It cannot silently simplify into benign.

# 30. World Dominance Pruning

W_a dominates W_b if:  W_a explains >= critical evidence  W_a has <= contradictions  W_a requires <= unsupported assumptions  W_a costs <= representation budget  and no security-critical future unique to W_b is lost
Dominance pruning reduces world count while preserving material alternatives.

# 31. Sequential Evidence Accumulation

Stage 4 benchmarks sequential tests/e-process-inspired evidence accumulation for worlds that unfold slowly. The objective is anytime-valid evidence where assumptions permit, without pretending all model scores satisfy statistical guarantees.
Evidence_t(W) updated per relevant observationStop when:  sufficient support,  sufficient contradiction,  resolution horizon reached,  or non-identifiability established.
This is especially relevant to sparse persistence and slow credential misuse.

# 32. Calibration Under Drift

Confidence calibration is epoch-conditioned. Stage 4 monitors calibration error itself as a security signal.
if calibration_error(epoch) rises:  widen uncertainty  increase abstention  raise audit rate  reduce crystallization trust
Confidence is never treated as stationary across host changes.

# 33. External Knowledge as Constraints, Not Answers

MITRE ATT&CK Detection Strategies, Sigma-derived semantics and local knowledge can constrain or name behaviour, but they do not decide the world.
Internal world -> observed semantic behaviourExternal adapter -> candidate technique / detection strategyMapping retained only with evidence rationale + version
ATT&CK v18's shift to Detection Strategies/Analytics supports maintaining a versioned adapter rather than coupling PocketSec's internal model to a fixed external schema.

# 34. Optional Tiny Language Model — Reduced Role

The tiny language model now has an even narrower function: linguistic compression of a typed Claim Graph.
CBF/LUCID  -> Typed Claim Graph  -> deterministic validator  -> optional tiny LM verbalizer  -> claim/evidence checker  -> output
If the verbalizer adds an unsupported proposition, the output is rejected and deterministic rendering is used.

# 35. Stage 4 Runtime

Stage 1 SSIR / visibility                         |           Stage 2 DTL / Future Cones                         |           Stage 3 Knowledge Cells                         v                 Evidence Integrator                         |                         v                CAUSAL BELIEF FIELD          /        |        |        \       world A   world B   world C   UNKNOWN          \        |        |        /                  LUCID        +-----------+-----------+        |           |           | counterfactual  tension    sensor planning        |           |           |        +-----------+-----------+                    |           identifiability gate             /             \         resolved       unresolved            |               |       claim compiler   analyst/AOP            |       optional verbalizer

# 36. Core Functional IDs

ID
Function
LUC-F01
update_causal_belief_field
LUC-F02
spawn_world
LUC-F03
kill_world
LUC-F04
fission_world
LUC-F05
fuse_worlds
LUC-F06
estimate_sensor_shadow
LUC-F07
calculate_evidence_tension
LUC-F08
update_sequential_evidence
LUC-F09
counterfactual_intervene
LUC-F10
calculate_responsibility_flux
LUC-F11
predict_world_future_cone
LUC-F12
test_identifiability
LUC-F13
plan_discriminating_observation
LUC-F14
simulate_sensor_value
LUC-F15
self_question_world
LUC-F16
stress_world_adversarially
LUC-F17
prune_dominated_worlds
LUC-F18
compile_typed_claim_graph
LUC-F19
stress_stage3_cell
LUC-F20
export_incident_world_record

# 37. Data Structures

CausalBeliefField { incident_id epoch worlds[K_MAX] sensor_shadow resolution_horizon entropy_budget typed_claim_graph evidence_refs}World { latent_state mechanism_id support_state expected_evidence forbidden_evidence contradictions future_cone causal_spine uncertainty consequence visibility_requirements}

# 38. Training / Learning Strategy

Most Stage 4 machinery should not require end-to-end training. Learned components are deliberately narrow:
Component
Training
world transition priors
from Stage 2 / offline traces
motif proposal
offline + Stage 3 crystallized structures
visibility model
measured sensor experiments
world support calibration
held-out incidents/benign traces
information-value predictor
optional distilled estimator after exact simulator data
claim verbalizer
optional tiny model; never authoritative
This reduces model memory and makes failures localizable.

# 39. Dataset Design

Stage 4 needs counterfactual incident datasets, not only attack labels.
- Same evidence prefix with different benign/malicious continuations.
- Same attack semantics with renamed actors/paths/binaries.
- Telemetry-drop variants with known visibility masks.
- Benign administration deliberately resembling attack chains.
- Low-and-slow timing variants.
- Decoy/noise injection variants.
- Epoch/configuration-change variants.
- World pairs designed to be non-identifiable under low telemetry and identifiable after one targeted observation.

# 40. The Key Benchmark: Resolution Efficiency

Resolution Efficiency = CorrectlyResolvedSecurityInformation ------------------------------------------------- CPU + RAM + telemetry bytes + analyst evidence load
This complements detection metrics and directly measures Stage 4's purpose.

# 41. Advanced Evaluation

- World-set recall: does the true explanation remain in the surviving field?
- Premature-collapse rate: how often does LUCID resolve before evidence justifies it?
- Non-identifiability accuracy: can it recognize when evidence cannot decide?
- Counterfactual stability: do irrelevant renamings preserve conclusions?
- Sensor-value regret: cost difference between chosen observation and best hindsight observation.
- Evidence tension discrimination between correct and incorrect worlds.
- Responsibility-flux attribution quality.
- World count and graph size per incident.
- Time/bytes required to collapse ambiguity.
- Unsupported authoritative claim count: target zero.
- False incidents/host/day, PR-AUC, detection latency and FP burden.
- Peak RSS/PSS, CPU/event, CPU/incident and telemetry amplification.

# 42. Baselines That Must Beat Us If We Are Wrong

Baseline
Why
fixed-window correlation
cheap operational baseline
Bayesian/HMM model
probabilistic latent-state baseline
dynamic Bayesian network
structured temporal baseline
provenance graph + scoring
causal graph baseline
Orthrus-like attribution principles
high-quality attribution comparison
tiny GNN
learned graph baseline
active-information-gain planner
simpler sensing baseline
pure DTL
tests whether Stage 4 adds anything
LLM incident summarizer
tests hallucination/cost tradeoff
USENIX Security 2025 found that simpler PIDS models can outperform unnecessary complexity on several benchmark settings, so CBF/LUCID is rejected if its advanced machinery does not earn its cost.

# 43. 40-Experiment Research Program

S4X-01  partial-observability simulatorS4X-02  sensor visibility calibrationS4X-03  CBF representation comparisonS4X-04  world birthS4X-05  world deathS4X-06  fission/fusionS4X-07  evidence tensionS4X-08  negative evidenceS4X-09  sensor-shadow reasoningS4X-10  bounded counterfactual interventionS4X-11  responsibility fluxS4X-12  future-cone compositionS4X-13  world dominance pruningS4X-14  incident entropy budgetS4X-15  sequential evidence accumulationS4X-16  conformal/set-valued abstention baselineS4X-17  calibration under epoch driftS4X-18  identifiability testS4X-19  non-identifiable incident benchmarkS4X-20  information-gain sensingS4X-21  counterfactual sensor planningS4X-22  security-free-energy objectiveS4X-23  active sensing cost comparisonS4X-24  slow-attack world persistenceS4X-25  benign-admin ambiguityS4X-26  missing telemetryS4X-27  event floodS4X-28  semantic rename invarianceS4X-29  decoy ancestryS4X-30  self-questioningS4X-31  adversarial belief stressS4X-32  typed epistemic graphS4X-33  claim compilerS4X-34  tiny-LM verbalizer guardS4X-35  Stage3 contradiction feedbackS4X-36  belief crystallizationS4X-37  sparse world graphS4X-38  resource benchmarkS4X-39  full ablationS4X-40  falsification / simpler-model challenge

# 44. Resource Architecture

Component
Research target
CBF active worlds
K capped 4–16 normally; exceptional cap explicit
World state
KB-scale/world, not model-context-scale
Sparse causal graph
hard bounded per incident
Counterfactual workspace
allocated on demand then freed
Sensor planner
no persistent heavy model required
LUCID normal incremental RSS
target < 25–45 MB
Peak without optional LM
initial ceiling < 90 MB
Optional LM
separate on-demand budget; never required for detection/resolution
The strongest target is not merely staying below 2 GB; it is keeping Stage 4 small enough that Stage 1–3 remain comfortable on the same machine.

# 45. Failure-Safe Rules

- OOM pressure prunes low-consequence dominated worlds first; never converts uncertainty to benign.
- Counterfactual engine failure disables counterfactual claims but preserves evidence/detection.
- Sensor planner failure falls back to Stage 1 default observation policy.
- Calibration failure widens uncertainty and increases abstention.
- External ATT&CK knowledge failure never blocks internal incident reasoning.
- Optional language model failure falls back to typed deterministic claims.
- Corrupt incident state is quarantined and reconstructable from retained evidence references where possible.

# 46. Hard Falsification Criteria

- A simpler Bayesian/HMM or fixed-window correlator reaches equivalent incident quality and attribution at materially lower cost.
- CBF true-world retention is poor despite high resource use.
- World birth causes hypothesis explosion under benign novelty.
- Negative-evidence reasoning produces unsafe conclusions under sensor loss.
- Counterfactual interventions do not improve attribution or sensor planning.
- Identifiability testing cannot distinguish unresolved cases reliably.
- Active sensing does not reduce total telemetry cost at comparable security quality.
- Self-questioning does not catch meaningful errors beyond ordinary validation.
- Stage 3 feedback destabilizes trusted Knowledge Cells.
- CBF/LUCID exceeds Edge resource targets or materially increases false incidents.

# 47. Acceptance Gate

- Partial-observability and visibility models are empirically measured for supported telemetry sources.
- CBF preserves the ground-truth world or an equivalent explanation in controlled ambiguous incidents.
- System explicitly recognizes constructed non-identifiable cases.
- Evidence Tension and Sensor Shadow behave correctly under dropped telemetry.
- At least one active sensing method reduces bytes/CPU versus always-on rich telemetry at comparable resolution quality.
- Counterfactual stress identifies predefined spurious causal explanations.
- Typed Claim Graph enforces OBS/DER/INF/CF/EXT/UNK separation.
- Authoritative output contains zero unsupported factual claims in the benchmark suite.
- World count, graph size and reasoning time remain hard bounded.
- CBF/LUCID beats or complements simpler baselines on the measured Pareto frontier.
- Stage 4 remains optional to core Stage 1–3 detection if it crashes.
- All novelty claims remain provisional until formal prior-art/patent review.

# 48. Stage 4 Deliverables

- D4X.1 — Causal Belief Field formal specification.
- D4X.2 — LUCID update engine.
- D4X.3 — Sensor Visibility + Sensor Shadow model.
- D4X.4 — Evidence Tension engine.
- D4X.5 — World birth/death/fission/fusion.
- D4X.6 — Counterfactual Intervention + Responsibility Flux.
- D4X.7 — Incident Future Cone composer.
- D4X.8 — Identifiability engine.
- D4X.9 — Discriminating Observation / Sensor Planner.
- D4X.10 — Sequential evidence and calibration module.
- D4X.11 — Self-Questioning + Adversarial Belief Stress.
- D4X.12 — Sparse World Graph and entropy-budget controller.
- D4X.13 — Typed Epistemic Claim Graph + Claim Compiler.
- D4X.14 — Stage 3 contradiction/crystallization feedback.
- D4X.15 — Optional guarded tiny-LM verbalizer.
- D4X.16 — 40-experiment benchmark, ablation and falsification report.

# 49. Stage 5 Handoff

Stage 5 should receive a Causal Belief Field resolution object containing the surviving world set, consequence distribution, evidence lineage, uncertainty, identifiability state and recommended information gaps. Stage 5 can then study safe action selection: reversible investigation and containment under explicit authority, predicted side effects and rollback guarantees. It should not need to reinterpret raw logs.

# 50. Research Grounding

The advanced architecture is deliberately not a copy of existing PIDS or incident-response systems. Current research nevertheless imposes important constraints. USENIX Security 2025 work on ORTHRUS argues that Quality of Attribution and concise attack reconstruction are essential, while a companion evaluation found that unnecessary model complexity can lose to simple neural baselines. These results justify both the sparse causal-world design and the aggressive falsification requirement.
NIST SP 800-61r3, finalized in April 2025, integrates incident response into broader cybersecurity risk management rather than treating it as a standalone late-stage process. Stage 4's continuous feedback and improvement loops are compatible with that direction.
MITRE ATT&CK v18 replaced technique-level Detections with Detection Strategies and Analytics and deprecated Data Sources, reinforcing PocketSec's decision to keep internal semantics independent of external framework versions.

# 51. Novelty Boundary

CBF, LUCID, Sensor Shadow, Evidence Tension, Responsibility Flux, Incident Identifiability, the specific self-questioning/active-sensing loop and their composition are PocketSec research constructs. Some mathematical ingredients have strong neighboring precedents in causal inference, partially observable state estimation, sequential testing, active learning/inference, provenance analysis and conformal uncertainty. A new name or combination is not proof of novelty. Patent and systematic literature review are required before external novelty claims.

# 52. Stage 4 Thesis

Do not ask the AI to decide which story sounds most malicious. Maintain several possible worlds. Predict what each world would make observable. Search for the cheapest evidence that separates them. Attack your own explanation. Collapse the field only when reality—not model confidence—has made the alternatives distinguishable.
