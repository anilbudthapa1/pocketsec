<!-- Extracted verbatim from the architecture source `PocketSec_Stage_6_HELIOS_MNEMOSYNE_Final_Architecture.docx`.
     Text-only conversion for tooling; the .docx remains the authoritative artefact. -->

POCKETSEC
STAGE 6 — HELIOS + MNEMOSYNE
Trustworthy Long-Horizon Self-Evolution for Ultra-Lightweight Security Intelligence
PocketSec must become more knowledgeable with age without allowing attackers, drift, repetition, model updates, or memory pressure to rewrite what the system has already learned to protect. Stage 6 turns learning itself into a security-sensitive, evidence-governed process.
Final Architecture & Research Specification v1.0 • September 2026

# 0. Stage 6 Architecture at a Glance

Layer
Subsystem
Purpose
6.0
Learning Constitution
immutable laws governing what may learn/change
6.1
Experience Gateway
receive evidence/outcomes from Stages 1–5
6.2
Experience Quarantine
prevent direct online learning from raw telemetry
6.3
Provenance & Trust Ledger
track origin, independence, epoch and contamination risk
6.4
Episodic Security Memory
bounded high-value incident/benign episodes
6.5
Semantic Memory
stable concepts, cells, priors and invariants
6.6
Procedural Memory
verified response/detection procedures
6.7
Epistemic Half-Life
age knowledge according to evidence stability
6.8
Adaptive Plasticity Field
decide exactly what may change and by how much
6.9
Memory Competition
new knowledge must compete with validated old knowledge
6.10
Counterfactual Rehearsal
reconstruct compressed historical cases
6.11
Knowledge Fossils
immutable checkpoints of validated cognition
6.12
Knowledge Lineage DAG
ancestry for every promoted learned object
6.13
HELIOS Evolution Chamber
isolated candidate learning/mutation
6.14
MNEMOSYNE Consolidator
merge, compress, age and retire knowledge
6.15
Shadow Mind
candidate model runs without authority
6.16
Knowledge Conservation Gate
regression and anti-forgetting barrier
6.17
Poisoning Immune Layer
detect slow/targeted learning manipulation
6.18
Semantic Homeostasis
prevent malicious normalization
6.19
Drift/Epoch Engine
distinguish legitimate change from adversarial drift
6.20
Canary Promotion
small, reversible candidate deployment
6.21
Learning Rollback
restore cognition after bad update
6.22
Model/Cell Lifecycle
version, retire, melt, resurrect knowledge
6.23
Resource Governor
bounded RAM, CPU, disk and update frequency
6.24
Optional Fleet Exchange
privacy/trust-gated knowledge exchange; not required
6.25
Assurance & Falsification
prove/measure that learning helps rather than harms

# 1. Stage 6 Mission

Stages 1–5 let PocketSec observe, model, understand and safely act. Stage 6 asks a different question: how can that intelligence improve for months or years without catastrophic forgetting, attacker-controlled poisoning, uncontrolled model growth, privacy leakage or permanent corruption? The deployed endpoint is therefore not a continuously retrained neural network. It is a bounded cognitive system whose learning is quarantined, tested, versioned and reversible.

# 2. Core Law — Learning Is a Privileged Operation

RAW TELEMETRY != TRAINING DATAREPETITION     != TRUTHMODEL SCORE    != KNOWLEDGENOVELTY        != PERMISSION TO ADAPTSUCCESS ON NEW DATA != PERMISSION TO FORGET OLD SECURITY CAPABILITY
Learning is treated similarly to Stage 5 privileged action: a candidate update must cross independent trust, conservation and promotion gates.

# 3. Knowledge Conservation Law

For candidate update ΔK:Promote(ΔK) only if:  NewUtility(ΔK) > minimum_gain  AND HistoricalSecurityLoss(ΔK) <= ε_security  AND SafetyInvariantLoss = 0  AND PoisonRisk <= threshold  AND ResourceGrowth <= budget  AND RollbackState exists
This is an engineering law, not a claim of mathematical conservation in the physical sense.

# 4. Multi-Timescale Cognition

Timescale
State
Update style
milliseconds–seconds
working event/world state
volatile; Stages 1–5
minutes–hours
host baseline adaptation
cheap statistics; reversible
hours–days
episodic memory
selective episode admission
days–weeks
semantic consolidation
cells/priors/model candidates
weeks–months
structural evolution
shadow-tested model/architecture changes
months–years
knowledge archaeology
aging, fossils, recurrence, resurrection
Different timescales must not share the same learning rule.

# 5. Experience Gateway

Inputs: Stage1 telemetry quality + sensor context Stage2 dynamics / Future Cones Stage3 Knowledge Cell outcomes Stage4 resolved/unresolved worlds Stage5 action + verified outcome explicit analyst labels (if available)Output: ExperienceCapsule
ExperienceCapsule { evidence_refs epoch source_provenance security_worlds resolution_state action_outcome visibility confidence_components contradiction_history privacy_class contamination_flags}

# 6. Experience Quarantine

No ExperienceCapsule can directly modify a trusted model, baseline or Knowledge Cell. New experience enters quarantine and accumulates independent evidence.
incoming experience   ↓deduplicate   ↓provenance score   ↓correlation/dependence check   ↓poisoning suspicion   ↓novelty decomposition   ↓quarantine bucket:  trusted-candidate / uncertain / hostile-suspect / discard

# 7. Provenance & Trust Ledger

Field
Reason
source class
kernel sensor, derived inference, analyst, external dataset
epoch
software/configuration context
independence group
avoid counting duplicated evidence as independent
sensor visibility
missing evidence interpretation
label origin
ground truth, weak label, teacher label, inference
transformation lineage
ETL/augmentation history
hash/version
reproducibility
contamination risk
possible attacker influence
Repeated attacker-generated events from one compromised process should not become thousands of independent votes for normality.

# 8. Memory Architecture

Memory
Contents
Implementation direction
Working
active incident state
bounded in-memory structs
Episodic
selected high-value episodes
SQLite/LMDB + compact binary blobs
Semantic
stable concepts/priors/cells
versioned compact tables + model artifacts
Procedural
verified response/detection recipes
typed records
Fossil
immutable validated snapshots
content-addressed compressed artifacts
The architecture avoids a heavyweight vector database unless measurements demonstrate value.

# 9. Episodic Admission

EpisodeValue =  security_information* novelty* future_replay_value* label_quality* provenance_trust/ (storage_cost + redundancy + poison_risk)
Only high-value episodes are retained. Raw event streams remain governed by earlier bounded retention.

# 10. Epistemic Half-Life

Knowledge does not decay merely because it is old. Its effective half-life depends on stability, recurrence, contradiction and environmental change.
H_i =H0 * (1 + validation_strength + recurrence)     -------------------------------------     (1 + contradiction + epoch_distance + drift_sensitivity)Trust_i(t) = Trust_i(0) * 2^(-age/H_i)
The formula is a research starting point and must be calibrated empirically.

# 11. Adaptive Plasticity Field (APF)

P_i(t) =(N_i * V_i * S_i * U_i)-----------------------(1 + R_i + C_i + Q_i + B_i)N = noveltyV = independent validationS = temporal stabilityU = expected security utilityR = forgetting riskC = contradiction with trusted knowledgeQ = poisoning suspicionB = resource/budget pressure
Plasticity is assigned locally to a baseline statistic, Knowledge Cell, classifier head, adapter, threshold or other component. The entire model does not become equally plastic.

# 12. Plasticity Masks

Candidate update mask:  frozen_core = TRUE  adaptable_layers = selected  max_parameter_delta = bounded  max_threshold_delta = bounded  max_cell_mutations = bounded  expiry/review = required
For neural candidates, parameter-efficient adapters or narrow heads are preferred before full-model retraining.

# 13. Memory Competition

New explanations compete against validated old explanations under the same replay set.
K_new challenges K_oldCompare:  explanatory coverage  security recall  false-positive burden  calibration  epoch applicability  resource cost  adversarial robustnessReplace only if new knowledge dominatesor coexist by epoch/context if both remain valid.
This avoids catastrophic replacement when a concept has merely become context-dependent.

# 14. Counterfactual Rehearsal

Full raw replay buffers are too expensive. PocketSec stores compact sufficient episode representations and reconstructs perturbations.
episode skeleton + semantic invariants + causal/world structure + outcome + visibility mask       ↓replay variants: rename actors alter timing drop telemetry change benign context substitute equivalent process class inject decoy events
The purpose is to test whether new learning preserves semantic security capability rather than memorizing identities.

# 15. Knowledge Fossils

A Fossil is an immutable content-addressed snapshot of a validated cognitive state or critical knowledge subset.
Fossil { artifact_hash parent_hashes model/cell/rule versions benchmark fingerprint epoch range security capabilities preserved creation reason}
Fossils allow rollback, historical comparison and resurrection after recurring concepts.

# 16. Knowledge Lineage DAG

Experience Capsules      ↓Candidate Cell / Model Adapter      ↓Shadow Evaluation      ↓Promoted Knowledge v17      ↓later merged into v23Every edge stores:  reason  evidence  tests  parent versions  transformation  approver/gate result
A learned fact without lineage is not trusted knowledge.

# 17. HELIOS Evolution Chamber

All nontrivial learning occurs in an isolated candidate environment.
Candidate type
Examples
statistical
EWMA/baseline parameter update
symbolic
new rule/motif/Knowledge Cell
classifier
new tiny model/head
adapter
LoRA-like or narrow parameter-efficient module where justified
calibration
threshold/isotonic/temperature-like mapping
structural
feature removal/addition, model replacement proposal
Structural candidates face the strongest gate.

# 18. MNEMOSYNE Consolidator

MNEMOSYNE performs memory maintenance rather than raw model training.
- deduplicate semantically equivalent episodes
- merge stable Knowledge Cells
- split cells whose contexts diverge
- age weak knowledge
- fossilize high-value validated knowledge
- retire obsolete context-specific knowledge
- select rehearsal exemplars
- compress historical statistics
- schedule candidate learning when resource budget allows

# 19. Shadow Mind

A candidate model or knowledge state runs on the same inputs as production but has zero authority.
Trusted Mind -> actual Stage 1–5 decisionsCandidate Shadow -> predictions onlyCompare:  misses caught  regressions introduced  FP changes  calibration  latency  RAM  disagreement cases  poisoning sensitivity
Shadow execution may be sampled rather than continuous on 2 GB systems.

# 20. Knowledge Conservation Gate (KCG)

Gate
Requirement
G1 Integrity
artifact/provenance valid
G2 Historical replay
critical past capability retained
G3 Current holdout
new utility demonstrated
G4 Counterfactual replay
semantic invariance survives perturbation
G5 Adversarial
poison/evasion regression acceptable
G6 Calibration
confidence not degraded materially
G7 Resource
RAM/CPU/disk budget satisfied
G8 Shadow
live disagreement within policy
G9 Rollback
known-good fossil available
A candidate can fail one gate and return to quarantine without affecting production.

# 21. Semantic Homeostasis

Attackers may repeat malicious behaviour until an adaptive system normalizes it. Semantic Homeostasis protects stable security invariants.
Protected semantic anchors:  privilege boundary semantics  credential-material semantics  executable trust boundaries  persistence semantics  evidence integrity  response authority invariantsBaseline frequency may adapt.Protected meaning does NOT adapt merely from frequency.
This is one of Stage 6's central defenses against slow poisoning.

# 22. Drift vs Poisoning Discriminator

Signal
Legitimate drift tendency
Poisoning suspicion
provenance
trusted software/config change
attacker-controlled event source
breadth
coherent multi-sensor change
narrow targeted feature manipulation
timing
aligned with epoch/change
strategic gradual repetition
validation
independent corroboration
single correlated source
security semantics
meaning stable
attempts to normalize protected semantics
rollback test
new state consistently valid
candidate fails historical/adversarial replay
No single signal decides drift vs poisoning; the discriminator produces a structured suspicion state.

# 23. Epoch Engine

Epoch boundary candidates: kernel/package upgrade service deployment config change new user/workload role hardware/network changeAt boundary:  preserve old baseline  create provisional new context  avoid immediate overwrite  compare for recurrence / rollback
Old knowledge can become dormant rather than deleted.

# 24. Recurrence and Knowledge Resurrection

Concept drift can recur. When a historical context returns, MNEMOSYNE searches fossils and dormant cells before relearning.
current context signature  ↓match dormant epoch?  yes -> resurrect candidate       -> shadow verify       -> promote  no  -> normal adaptation

# 25. Catastrophic Forgetting Defense Stack

Technique family
PocketSec use
replay
small curated episodic/counterfactual rehearsal
regularization
optional parameter-drift constraints for neural candidates
parameter isolation
adapters/heads/plasticity masks
dynamic architecture
only if resource growth remains bounded
knowledge distillation
compress validated teacher/candidate into tiny student
symbolic retention
Knowledge Cells/fossils independent of neural weights
Stage 6 benchmarks combinations; no single continual-learning algorithm is assumed best.

# 26. Teacher-Assisted Evolution

A powerful offline teacher may label or critique difficult quarantined episodes, but teacher output is weak evidence until validated.
Quarantined episode   ↓offline teacher proposals   ↓cross-check: deterministic facts multiple teacher consistency (optional) known rules/cells analyst/lab ground truth where available   ↓candidate training label with provenance
The endpoint never treats a teacher-generated explanation as ground truth by default.

# 27. Model Evolution Strategy

Priority
Method
Why
1
threshold/statistical adaptation
cheapest, interpretable
2
Knowledge Cell/rule evolution
compact and inspectable
3
tiny classifier head update
bounded learned adaptation
4
parameter-efficient adapter
when base representation remains useful
5
distilled replacement model
when structural gain is proven
6
full retrain/rearchitecture
offline only, strongest gate
This preserves the original PocketSec principle: intelligence per MB and per CPU cycle.

# 28. Production Runtime Tools

Need
Preferred tool/concept
Rationale
core daemon
Rust
memory safety, low overhead, strong systems integration
eBPF integration
libbpf-rs/Aya depending prototype results
Rust-friendly kernel telemetry
local durable state
SQLite WAL or LMDB benchmark winner
bounded, embedded, no server
compact serialization
Protobuf/FlatBuffers benchmark
schema/versioning vs allocation tradeoff
tiny ML inference
ONNX Runtime C/C++ API or tract/ORT Rust binding
portable CPU inference
model format
ONNX for classifiers; GGUF only if tiny LM remains optional
separate detector from language layer
hash/content addressing
BLAKE3/SHA-256 according assurance requirement
artifact identity/lineage
compression
zstd
fast compact episodic/fossil storage
IPC
Unix domain sockets / bounded shared ring
local and lightweight
Tool selection remains benchmark-driven. Python stays primarily in research/training.

# 29. Training/Research Tools

Function
Tool candidates
classical ML
scikit-learn, LightGBM/XGBoost where justified
deep/tiny models
PyTorch
continual-learning experiments
Avalanche + custom PocketSec harness
hyperparameter search
Optuna, bounded offline
export
ONNX
quantization
ONNX Runtime quantization; QAT in training framework when needed
dataset/versioning
DVC or content-addressed manifest approach
experiment tracking
MLflow optional on development workstation; not endpoint
property tests
Hypothesis + Rust proptest
benchmarks
Criterion.rs, perf, hyperfine, /usr/bin/time -v, smem
ONNX Runtime's official documentation supports INT8 quantization and selected INT4/UInt4 weight-only operators; quantization choice must be validated against accuracy and CPU behavior, not file size alone.

# 30. Endpoint vs Development Machine

Operation
2 GB endpoint
development machine
inference
YES
YES
cheap baseline update
YES
simulate/test
episode selection
YES
YES
quarantine/trust scoring
YES
YES
shadow candidate inference
sampled/bounded
full
tiny calibration update
possible
preferred for validation
classifier retraining
normally NO
YES
distillation
NO
YES
large teacher inference
NO
YES
architecture search
NO
YES
full historical replay
NO
YES
fossil rollback
YES
YES
The endpoint is adaptive, not a miniature training cluster.

# 31. ONNX/Quantization Policy

- Export narrow detection models to ONNX after training.
- Benchmark FP32, INT8 and where supported/useful INT4 weight-only variants.
- Measure RSS/PSS and inference workspace in addition to artifact size.
- Prefer static quantization for suitable CNN-style models and evaluate dynamic quantization for RNN/transformer-style candidates in line with runtime guidance.
- Reject quantization if security recall/calibration degradation exceeds the acceptance threshold.

# 32. Optional Tiny Language Model Evolution

The language model remains non-authoritative. If Stage 6 adapts it, adaptation is limited to explanation quality, vocabulary or compact domain knowledge—not detection authority.
Typed Claim Graph -> optional tiny LMStage6 may update:  explanation adapter  retrieval corpus  terminology mappingStage6 may NOT let:  LM-generated text become training truth  LM rewrite evidence  LM grant Stage5 authority

# 33. Poisoning Threat Model

- slow baseline poisoning through repeated malicious behavior
- label poisoning through compromised analyst/tool output
- teacher-generated systematic mislabels
- model replacement/supply-chain tampering
- backdoor triggers in candidate models
- quarantine flooding to bias exemplar selection
- epoch manipulation to force knowledge retirement
- fossil deletion/corruption
- lineage tampering
- fleet update Sybil/collusion attacks if fleet exchange is enabled
NIST AI 100-2e2025 explicitly treats poisoning, evasion and privacy attacks across predictive and generative AI lifecycles; Stage 6 maps its learning threat model to that taxonomy.

# 34. Poisoning Suspicion Score

Q(x) = f( source_control_by_adversary, dependence/repetition, protected-semantic conflict, unusual label shift, trigger-like concentration, cross-epoch inconsistency, historical regression, counterfactual instability)
Q is not necessarily one learned scalar. A structured vector may preserve more diagnostic value.

# 35. Backdoor/Trigger Evaluation

Candidate neural models undergo trigger-oriented tests before promotion:
- feature concentration and shortcut checks
- rare-token/path/user perturbations
- semantic-preserving renaming
- subpopulation performance
- activation/utilization comparison where practical
- clean vs suspected-trigger differential tests
- teacher/model artifact integrity verification
NIST published 2025 work specifically on explaining poisoned AI models, reinforcing the need to inspect how suspicious training influence is encoded rather than relying only on aggregate accuracy.

# 36. Privacy Boundary

Learning memory can be more sensitive than transient detection because it persists. ExperienceCapsules therefore carry privacy classes.
- avoid retaining raw credentials/secrets
- tokenize/hash identifiers where semantic identity is sufficient
- store compact derived episode skeletons instead of full command history where possible
- encrypt sensitive fossil/episode stores at rest if threat model requires
- no fleet export by default
- explicit configuration required before cross-host knowledge leaves the endpoint

# 37. Optional Fleet Knowledge Exchange

Fleet learning is Stage 6 optional, not foundational. Exchange should prefer compact validated knowledge objects over raw telemetry or unconstrained gradient sharing.
Host A validated cellHost B validated cell      ↓signed knowledge package      ↓local quarantine on Host C      ↓local replay + context validation      ↓candidate only
A remote majority never overrides local security invariants automatically.

# 38. Anti-Sybil / Trust for Fleet Mode

- signed host identities where administratively available
- source diversity caps
- no vote amplification from duplicate/correlated hosts
- local validation before promotion
- reputation is evidence, not authority
- rate limits and package size limits
- reject unsigned/unversioned model artifacts

# 39. Resource Architecture

Subsystem
Normal target
Peak target
quarantine metadata
5–15 MB
25 MB
episodic hot index
5–15 MB
25 MB
semantic/procedural memory
5–20 MB
30 MB
lineage/fossil metadata cache
3–10 MB
15 MB
MNEMOSYNE consolidation workspace
0–15 MB
35 MB on demand
Shadow Mind
normally off/sampled
model-dependent bounded window
Stage 6 incremental RSS excluding shadow model
prefer 25–55 MB
<100 MB initial ceiling
Disk is bounded separately; a starting research target is 100–500 MB for compressed episodic/fossil history depending on device role, with strict quotas and retention policies.

# 40. Resource-Aware Consolidation

Run consolidation only if:  memory_pressure < threshold  CPU load < threshold  incident urgency low  disk budget available  power/thermal policy allowsOtherwise:  queue bounded metadata  postpone expensive work  never block detection

# 41. Failure-Safe Learning

- Learning subsystem crash leaves trusted cognition unchanged.
- Corrupt candidate artifacts are discarded, not loaded.
- Quarantine overflow uses value-aware eviction; it never auto-promotes.
- Fossil corruption triggers integrity failure and fallback to another known-good version.
- Shadow Mind OOM terminates shadow evaluation before production detection.
- Bad canary automatically reverts to previous trusted version.
- Unknown lineage blocks promotion.

# 42. Promotion State Machine

QUARANTINED   ↓CANDIDATE   ↓OFFLINE-VALIDATED   ↓SHADOW   ↓CANARY   ↓TRUSTED   ↓DORMANT / FOSSILIZED / RETIREDAny stage may -> REJECTEDAny promoted stage may -> ROLLBACK

# 43. Canary Deployment

Canary does not mean partial unsafe response authority. It means limited cognitive influence.
- small percentage of eligible detections use candidate score as secondary evidence
- no new Stage 5 autonomous authority solely because of candidate
- compare candidate vs trusted disagreements
- strict time/incident count window
- automatic rollback on regression threshold

# 44. Learning Rollback

Rollback restores:  model artifact  thresholds/calibration  Knowledge Cell versions  baseline snapshot  response-cell versions if affected  lineage pointerIt does NOT delete:  evidence of why rollback occurred  candidate failure record

# 45. Stage 6 Functional IDs

ID
Function
S6-F01
build_experience_capsule
S6-F02
quarantine_experience
S6-F03
score_provenance
S6-F04
detect_evidence_dependence
S6-F05
estimate_poison_suspicion
S6-F06
admit_episode
S6-F07
update_epistemic_half_life
S6-F08
compute_plasticity_field
S6-F09
generate_plasticity_mask
S6-F10
compete_knowledge
S6-F11
generate_counterfactual_replay
S6-F12
create_fossil
S6-F13
update_lineage_dag
S6-F14
spawn_evolution_candidate
S6-F15
consolidate_memory
S6-F16
run_shadow_mind
S6-F17
run_conservation_gate
S6-F18
detect_semantic_normalization_attack
S6-F19
classify_drift_vs_poisoning
S6-F20
open_new_epoch
S6-F21
resurrect_dormant_knowledge
S6-F22
promote_canary
S6-F23
promote_trusted
S6-F24
rollback_learning
S6-F25
melt_or_retire_knowledge
S6-F26
export_learning_record

# 46. Repository Architecture

stage6/├── constitution/├── experience/├── quarantine/├── provenance/├── episodic_memory/├── semantic_memory/├── procedural_memory/├── half_life/├── plasticity/├── competition/├── rehearsal/├── fossils/├── lineage/├── helios/├── mnemosyne/├── shadow/├── conservation/├── poisoning/├── homeostasis/├── epochs/├── recurrence/├── canary/├── rollback/├── fleet_optional/├── resource_governor/├── assurance/├── benchmarks/└── tests/

# 47. Candidate Continual-Learning Baselines

Family
Why benchmark
naive fine-tuning
catastrophic-forgetting lower baseline
experience replay
strong simple baseline
reservoir sampling replay
bounded-memory baseline
EWC/SI-style regularization
parameter-stability baseline
LwF/distillation
knowledge-retention baseline
adapter/head isolation
parameter-isolation baseline
dynamic expansion
capacity-growth baseline
prototype/class centroid
very lightweight non-neural baseline
online calibration only
tests whether retraining is unnecessary
PocketSec APF + hybrid memory
proposed architecture
The final algorithm is selected by the security/resource Pareto frontier, not novelty alone.

# 48. Evaluation Metrics

- forward transfer to genuinely new benign/attack behavior
- backward transfer / historical security retention
- catastrophic forgetting on critical techniques
- false positives per host/day before and after adaptation
- PR-AUC and calibrated precision/recall under class imbalance
- poisoning attack success rate
- backdoor trigger success rate
- time-to-detect poisoning
- time-to-adapt to legitimate drift
- incorrect-normalization rate for malicious repetition
- knowledge resurrection accuracy on recurring epochs
- replay bytes per preserved capability
- candidate rejection rate and reasons
- rollback frequency and recovery time
- lineage completeness
- RAM/PSS/CPU/disk growth over simulated months

# 49. Security-Weighted Continual Learning Objective

Maximize:  NewThreatUtility+ LegitimateDriftAdaptation+ HistoricalCapabilityRetention+ CalibrationQualityMinimize:  PoisoningSusceptibility+ CatastrophicForgetting+ FalsePositiveBurden+ MemoryGrowth+ CPUCost+ UnverifiableKnowledgesubject to:  protected semantic invariants  resource budgets  rollback availability

# 50. 60-Experiment Research Program

S6X-01  experience capsule schemaS6X-02  quarantine isolationS6X-03  provenance scoringS6X-04  duplicate/dependence detectionS6X-05  episodic admissionS6X-06  bounded reservoir baselineS6X-07  semantic episode compressionS6X-08  epistemic half-lifeS6X-09  APF plasticityS6X-10  plasticity masksS6X-11  naive fine-tune forgetting baselineS6X-12  replay baselineS6X-13  regularization baselineS6X-14  distillation baselineS6X-15  adapter isolation baselineS6X-16  prototype baselineS6X-17  knowledge competitionS6X-18  counterfactual rehearsalS6X-19  semantic rename replayS6X-20  telemetry-drop replayS6X-21  timing perturbation replayS6X-22  knowledge fossilS6X-23  fossil integrityS6X-24  lineage DAGS6X-25  candidate evolution chamberS6X-26  shadow mindS6X-27  sampled shadow schedulingS6X-28  conservation gateS6X-29  canary promotionS6X-30  automatic learning rollbackS6X-31  legitimate package-upgrade driftS6X-32  new-service epochS6X-33  recurring old epochS6X-34  knowledge resurrectionS6X-35  slow baseline poisoningS6X-36  malicious repetition normalizationS6X-37  label poisoningS6X-38  teacher label corruptionS6X-39  trigger/backdoor candidateS6X-40  quarantine floodingS6X-41  epoch manipulationS6X-42  lineage tamperingS6X-43  fossil corruptionS6X-44  model artifact tamperingS6X-45  semantic homeostasisS6X-46  drift-vs-poison discriminatorS6X-47  false poison alarm under real driftS6X-48  resource-pressure consolidationS6X-49  OOM shadow failureS6X-50  month-scale memory growth simulationS6X-51  year-scale knowledge aging simulationS6X-52  INT8 candidate benchmarkS6X-53  INT4 candidate benchmark where applicableS6X-54  offline teacher-assisted labelingS6X-55  optional fleet signed packageS6X-56  fleet duplicate/Sybil simulationS6X-57  privacy leakage auditS6X-58  full ablationS6X-59  simpler-baseline falsificationS6X-60  complete Stage1–6 endurance run

# 51. Month/Year Simulation Harness

Because Stage 6 claims long-horizon behavior, ordinary short benchmarks are insufficient.
Synthetic timeline: Month 1 stable host Month 2 software update Month 3 benign workload expansion Month 4 slow poisoning attempt Month 5 new attack family Month 6 rollback to old application stack Month 7 sensor change Month 8 recurring old attack Month 9 benign rare admin activity Month 10 targeted label poison Month 11 resource pressure Month 12 mixed recurrenceMeasure knowledge state at every epoch.
The same framework should scale to multi-year accelerated replay.

# 52. Acceptance Gate

- Raw telemetry cannot directly modify trusted cognition.
- Every promoted knowledge object has complete provenance and lineage.
- Critical historical security capabilities remain within predefined regression bounds.
- Slow malicious repetition cannot simply become normal through frequency.
- Legitimate epoch changes can adapt without destroying old recurring knowledge.
- Candidate models/cells are evaluated in isolation before influence.
- Shadow/canary failure cannot grant Stage 5 authority.
- Learning rollback restores a known-good cognitive state.
- Poisoning tests include data, label, model and slow-drift attacks.
- Endpoint adaptation stays within the Stage 0 resource envelope.
- Full retraining/distillation remains off-endpoint unless measurement proves otherwise.
- Knowledge growth is bounded over month/year simulation.
- Every advanced Stage 6 mechanism survives ablation against simpler continual-learning baselines.

# 53. Final Deliverables

- D6.1 — Learning Constitution.
- D6.2 — ExperienceCapsule + Quarantine Gateway.
- D6.3 — Provenance/Trust Ledger.
- D6.4 — Bounded Episodic/Semantic/Procedural Memory.
- D6.5 — Epistemic Half-Life engine.
- D6.6 — Adaptive Plasticity Field + masks.
- D6.7 — Memory Competition engine.
- D6.8 — Counterfactual Rehearsal engine.
- D6.9 — Knowledge Fossil store.
- D6.10 — Knowledge Lineage DAG.
- D6.11 — HELIOS Evolution Chamber.
- D6.12 — MNEMOSYNE Consolidator.
- D6.13 — Shadow Mind runtime.
- D6.14 — Knowledge Conservation Gate.
- D6.15 — Semantic Homeostasis + poisoning defenses.
- D6.16 — Drift/Epoch/Recurrence engine.
- D6.17 — Canary + Learning Rollback controller.
- D6.18 — Quantized candidate export pipeline.
- D6.19 — Optional fleet knowledge package protocol.
- D6.20 — 60-experiment + month/year endurance benchmark.

# 54. Research Grounding and Boundaries

NIST AI 100-2e2025 provides a current taxonomy for adversarial machine learning covering poisoning, evasion, privacy and other attacks across AI lifecycles. Stage 6 uses this as a threat-model foundation rather than claiming that quarantine alone solves poisoning.
ONNX Runtime documentation confirms production support for INT8 quantization and selected INT4/UInt4 weight-only operators, with different recommendations by model type. PocketSec therefore benchmarks quantized candidates rather than assuming lower-bit models are automatically superior.
Continual learning, rehearsal, regularization, parameter isolation, distillation, drift detection, federated learning and backdoor defenses are established research areas. HELIOS, MNEMOSYNE, Epistemic Half-Life, Adaptive Plasticity Field, Semantic Homeostasis and the exact PocketSec composition are proposed research constructs. Their novelty is not established until systematic literature and patent review.

# 55. Stage 6 Thesis

A security intelligence should not learn simply because it has observed something often. It should learn only when the new knowledge has provenance, survives adversarial challenge, improves future security, preserves critical historical capability, fits the resource budget, and can be rolled back. PocketSec Stage 6 therefore makes plasticity itself conditional, local, evidence-governed and reversible.

# 56. Stage 7 Handoff

Only after trustworthy single-host self-evolution is demonstrated should Stage 7 investigate collective intelligence: privacy-preserving multi-host knowledge exchange, decentralized trust, population-level novelty, federated/distilled knowledge transfer and defense against colluding or poisoned peers. Stage 7 must inherit Stage 6's quarantine rule: external knowledge is always a candidate, never authority.
