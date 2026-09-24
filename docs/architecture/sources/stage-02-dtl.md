<!-- Extracted verbatim from the architecture source `PocketSec_Stage_2_DTL_Core_Final.docx`.
     Text-only conversion for tooling; the .docx remains the authoritative artefact. -->

POCKETSEC
Stage 2 — DTL Intelligence Core
Dynamic Transition Lattice: Predictive, Counterfactual, Self-Compiling Security Intelligence
Research objective: discover the smallest adaptive internal machine that can predict security-relevant futures, represent uncertainty, reason over alternative futures, and progressively convert stable learned dynamics into cheap executable transitions.
Final Research & Implementation Specification v1.0 • 22 September 2026

# 1. Stage 2 Mission

Stage 2 builds PocketSec's first real learning core. It consumes Stage 1 SSIR transitions, Host Security State, Behaviour Epoch, causal state and uncertainty. It does not attempt to imitate a general-purpose LLM. It learns the dynamics of a Linux host: what states exist, how they change, which futures are plausible, what remains uncertain, and which learned transitions can eventually execute without expensive inference.
The proposed experimental core is named DTL — Dynamic Transition Lattice. DTL is a research architecture, not a claim of novelty or superiority. Every component must be compared against strong simple baselines and removed if it does not improve the measured Pareto frontier.

# 2. Why a Dynamic Transition Lattice

A flat classifier maps observations directly to labels. A conventional sequence model maintains a continuous hidden state. DTL instead investigates a hybrid structure: a compact continuous predictive state is dynamically quantized into reusable behavioural prototypes, connected by probabilistic transitions, organized across multiple timescales, and selectively activated by semantic routing.
SSIR τ_t + Security State S_t              |              v      Semantic Event Encoder              |              v       Relevance / Need Router       /       |       |       \ execution  identity  network  persistence ...       \       |       |       /              v   Multi-timescale latent state z_t              |      +-------+--------+      |                |      v                v Continuous core   Discrete prototypes      |                |      +-------+--------+              v      Dynamic Transition Lattice              |   +----------+-----------+------------+   v          v           v            vfuture     state Δ     uncertainty   counterfactualprediction prediction     / OOD       futures

# 3. The Stage 2 Scientific Question

Find Z* = the minimum adaptive state that preserves security-relevant predictive information while minimizing memory, update compute, wake frequency and attribution cost.
A conceptual multi-objective objective is:
J = L_future + αL_state + βL_security + γL_calibration + δL_counterfactual + λC_compute + μC_memory + νC_wake + ρC_complexity
No single scalar score will decide success. Stage 2 maintains a Pareto frontier across detection/prediction quality, resource use, calibration, robustness and analyst attribution quality.

# 4. DTL Core State

The core state is factorized rather than monolithic:
z_t = [ z_fast, z_session, z_host, z_epoch, z_causal, z_uncertainty ]
State block
Timescale
Purpose
z_fast
ms–seconds
process/file/network micro-dynamics
z_session
seconds–hours
login/session/privilege trajectory
z_host
hours–days
stable host behavioural dynamics
z_epoch
configuration regime
concept-drift context
z_causal
event-dependent
security-carrying causal spine
z_uncertainty
continuous
what the model does not yet know
Each block has an independent update gate and decay policy. An event should not force every state block to wake.

# 5. Selective State Update

Modern selective state-space research demonstrates that input-dependent selection can decide what information propagates or is forgotten while retaining linear sequence scaling; this is a useful baseline principle, not a design to copy blindly.
g_t = Router(τ_t, S_t, U_t)z_(t+1)^k =    F_k(z_t^k, τ_t)    if g_t[k] > threshold    Decay_k(z_t^k)     otherwise
DTL extends the idea into security-specific modular state: semantic routing chooses which capability domains and timescales require updates. The router itself must be tiny and measurable.

# 6. Need-to-Compute Gate

Stage 0's novelty principle becomes a broader information-need gate:
Need_t = f(Novelty, SecurityPotential, Uncertainty, CausalResponsibility, PredictionError)
Need determines one of several execution paths:
Path
Mechanism
Expected cost
P0
compiled/cached exact transition
minimal
P1
prototype/lattice lookup
very low
P2
small local state update
low
P3
multi-block predictive inference
moderate
P4
counterfactual/deep analysis + AOP request
rare/high
The key metric is not only inference latency; it is the distribution of events across P0–P4.

# 7. Future Cone, Not Single Next-Event Prediction

A security system should not only predict one next event. DTL investigates a bounded Future Cone: a compact distribution over several plausible security-state trajectories.
Current state z_t   |   +--> future A: normal continuation       p=.91   +--> future B: administrative escalation p=.07   +--> future C: credential→egress chain   p=.002   +--> unresolved/unknown                  p=.018
The Future Cone is deliberately shallow and bounded. It is not a generative simulator of arbitrary Linux activity. Its purpose is to estimate security-relevant continuation risk and identify branches whose observation would most reduce uncertainty.

# 8. Predictive Heads

Head
Predicts
Reason
H1 Relation
next operation family
sequence surprise
H2 Object semantics
likely target class
semantic surprise
H3 State delta
next security capability change
security trajectory
H4 Temporal
time-to-next relevant transition bucket
slow/fragmented attacks
H5 Causal
likely responsible predecessor/state
attribution
H6 Epoch consistency
whether behaviour fits current regime
concept drift
H7 Security potential
expected ΔΦ distribution
consequence
H8 Uncertainty/OOD
confidence and unknownness
safe escalation
These produce a surprise vector rather than a single anomaly score.

# 9. Surprise Geometry

I_t = [I_relation, I_object, I_state, I_time, I_causal, I_epoch]
DTL treats surprise as structured geometry. Two events with equal aggregate surprise may differ radically: one may be temporally unusual but harmless; another may be a highly improbable privilege-to-credential transition. Downstream risk uses the direction of surprise, not only its magnitude.

# 10. Security-Relevant Predictive Bottleneck

Stage 2 explicitly searches for the smallest latent state that preserves information about security-relevant futures. The latent-size sweep is mandatory, not cosmetic.
candidate dimensions:8 → 16 → 24 → 32 → 48 → 64 → 96 → 128 → 256For each:future predictionattack recallFP/host/daycalibrationRAM/stateCPU/eventwake rate
The chosen size is the knee of the measured frontier, not the largest model that fits.

# 11. Discrete Behaviour Atoms

Continuous state is powerful but difficult to cache, merge and compile. DTL therefore investigates quantizing recurrent security states into discrete Behaviour Atoms.
z_t (continuous) → Q(z_t) → atom a_i
Vector-quantized representation learning establishes that useful discrete latent codes can be learned; DTL tests whether security dynamics admit similarly compact discrete prototypes.
Atom property
Purpose
prototype vector
represent a behavioural regime
visit count
stability/evidence
epoch distribution
context validity
outgoing transitions
future dynamics
security-state summary
capability meaning
uncertainty envelope
known limits
compile status
neural / candidate / executable

# 12. Dynamic Transition Lattice

Atoms are not treated as a simple flat Markov chain. The lattice can contain multiple abstraction levels: fine-grained atoms for ambiguous regions and merged macro-states for stable equivalent regions.
Macro State M7              /      |       \           a17      a23      a91            |\       |        |            | \      |        +--> a105            |  +--> a44            +------> a23
Transitions carry conditional probabilities, uncertainty, epoch validity, evidence counts and optional compiled actions. The structure may grow, merge and prune under strict validation.

# 13. Predictive Equivalence and State Merging

Two atoms may be candidates for merging when their security-relevant futures are sufficiently equivalent:
a_i ≈ a_j if D(P(Y_security_future|a_i), P(Y_security_future|a_j)) < ε and their uncertainty/epoch constraints are compatible.
Candidate distance measures and tests must be benchmarked. Merging is reversible. A merged macro-state that later becomes heterogeneous must split.

# 14. State Fission: Learn More Only Where Needed

The inverse operation is equally important. If a prototype accumulates incompatible futures, elevated uncertainty or conflicting security outcomes, it undergoes fission.
stable atom -> keep compactheterogeneous atom -> split into finer atomsrare unresolved region -> temporary high-resolution stateresolved region -> merge/compile
This creates adaptive representational density: complexity accumulates only where the security dynamics require it.

# 15. Reversible Intelligence Phase Change

Stage 2 introduces the preconditions for Stage 3 compilation. Intelligence can exist in several phases:
NEURAL/CONTINUOUS      ↓ stableDISCRETE ATOM      ↓ repeated + calibratedCANDIDATE TRANSITION      ↓ independently validatedEXECUTABLE/CACHED TRANSITIONIf drift or error rises:EXECUTABLE → CANDIDATE → DISCRETE → NEURAL
Stage 2 may create candidates and caches, but permanent compiler machinery remains Stage 3. The important Stage 2 work is measuring when a transition is stable enough to be considered compilable.

# 16. Counterfactual Twin

DTL maintains a lightweight counterfactual capability: compare the observed trajectory with nearby alternatives obtained by masking or substituting high-responsibility transitions.
Observed:session → sudo → interpreter → credential read → egressCounterfactual:session → [sudo removed] → interpreter → ?Responsibility(sudo) ≈ divergence between predicted security futures
This is used for attribution and evidence selection, not unrestricted generative reasoning.

# 17. Causal Credit Ledger

Instead of storing every historical edge at equal importance, DTL maintains a bounded ledger of transitions that materially changed predicted security state or Future Cone.
Credit(e_i) = Δ predicted security outcome when e_i is masked/perturbed, approximated under a strict compute budget.
This should improve analyst attribution quality while keeping causal memory bounded. Recent provenance IDS research emphasizes that practical systems must optimize attribution quality and scalability, not only headline detection accuracy.

# 18. Epistemic Budget and Abstention

DTL must be able to say 'unknown'. Confidence is not derived from softmax alone. Stage 2 compares cheap uncertainty estimators such as entropy, prototype distance, calibrated ensembles where affordable, conformal-style calibration, and predictive disagreement.
LOW uncertainty + LOW Φ -> cheap pathHIGH uncertainty + LOW Φ -> observe lazilyLOW uncertainty + HIGH Φ -> known high-risk pathHIGH uncertainty + HIGH Φ -> AOP escalation + deeper inference + preserve evidence

# 19. Active Perception Loop

DTL uncertainty / Future Cone ambiguity             |             v    Information Need Estimator             |             v Stage 1 Adaptive Observation Policy             |       richer local telemetry             |             v          new SSIR             |             +------> DTL update
The research target is value-of-information: request extra telemetry only when its expected reduction in decision uncertainty justifies collection cost.

# 20. Memory as Predictive Utility, Not Age

Conventional caches forget because entries are old. DTL investigates forgetting based on future utility.
Retain(m) ∝ FutureSecurityUtility(m) × CausalResponsibility(m) × UncertaintyReduction(m)
An old but predictive credential-escalation pattern may remain. A recent repetitive benign pattern may collapse quickly into a compiled/cached transition.

# 21. Behavioural Thermodynamics — Experimental Metaphor, Measured Mechanism

To avoid pseudo-science, DTL does not claim physical thermodynamics. It uses an engineering analogy that must reduce to measurable quantities.
Term
Operational definition
Behavioural entropy
uncertainty of future transition/state distribution
Free capacity
remaining compute/memory budget
Energy
measured CPU cycles / inference cost
Phase change
representation moves neural↔discrete↔compiled
Cooling
uncertainty falls through repeated stable evidence
Heating
drift/conflict increases uncertainty and forces richer inference
Any metaphor that cannot be mapped to measurable variables is excluded from the implementation.

# 22. Multi-Horizon Hazard Prediction

Some security outcomes are better expressed as hazards than exact next events. DTL tests compact hazard heads for questions such as 'probability of a privilege transition within the next N relevant events' or 'credential exposure before session termination'.
h_k(t | z_t) = conditional hazard for security outcome k over bounded horizon
This may detect slow chains without storing or generating long token contexts.

# 23. Negative-Space Learning

Security information also exists in expected events that fail to occur. DTL therefore investigates prediction residuals over both observed and expected-but-absent transitions.
Expected after state a_17:  service child heartbeat / normal file accessObserved:  silence + new external channelResidual includes:  unexpected event + missing expected continuation
This is experimental and retained only if it improves real detection or calibration.

# 24. Epoch-Conditioned Dynamics

All learned transitions carry epoch context. A transition can be stable in one system regime and invalid in another.
P(a_(t+1) | a_t, τ_t, epoch_t)
Stage 2 must test controlled package upgrades, service changes and workload changes. It must not 'learn away' malicious behaviour merely because it repeats.

# 25. Anti-Poisoning Learning Gate

Online adaptation is security-sensitive. New observations do not automatically update trusted prototypes or compiled candidates.
new experience   ↓quarantine buffer   ↓consistency / epoch / risk checks   ↓candidate update   ↓delayed promotionhigh-risk or suspicious samples:retain as evidence; do not silently normalize
Continual-learning backdoor research demonstrates that persistent poisoning is a real threat; Stage 2 therefore separates observation from trusted model adaptation.

# 26. Training Objectives

Candidate joint loss:
L = w1 * L_relation+w2 * L_object+w3 * L_state_delta+w4 * L_time+w5 * L_security_potential+w6 * L_causal+w7 * L_epoch+w8 * L_calibration+w9 * L_quantization+w10* L_counterfactual+ regularization(resource proxies)
Loss terms are ablated individually. No head remains because it sounds sophisticated.

# 27. Training Curriculum

Phase
Data
Goal
C0
synthetic unit transitions
verify mechanics
C1
benign host traces
learn ordinary dynamics
C2
controlled attack lab
security-state trajectories
C3
public provenance/endpoint datasets
generalization
C4
renamed/obfuscated counterfactual traces
semantic robustness
C5
epoch/drift scenarios
adaptation
C6
poisoning/adversarial scenarios
learning integrity
Training occurs on a development machine. The 2 GB endpoint performs inference, bounded baseline statistics and only carefully gated adaptation.

# 28. Baselines DTL Must Beat or Complement

Baseline
Why required
n-gram / Markov
extremely cheap sequence baseline
logistic/MLP state features
simple discriminative baseline
GRU
compact recurrent baseline
LSTM
gated recurrent baseline
TCN/1D CNN
parallel local temporal baseline
tiny Transformer
attention baseline
selective SSM / Mamba-like
linear-time state-space baseline
prototype/VQ recurrent model
discrete-state baseline
simple provenance NN
complexity sanity check
Recent unified provenance-IDS evaluation found that simple neural networks can match or exceed much more complex systems on several datasets while being lighter and real-time. DTL therefore has no right to exist unless it demonstrates a measurable advantage.

# 29. DTL Core IDs / Stable Functional Interfaces

Stage 2 should expose versioned functionality IDs so the hub remains model-replaceable:
Core ID
Function
DTL-F01
encode_ssir_transition
DTL-F02
route_information_need
DTL-F03
update_multiscale_state
DTL-F04
quantize_behaviour_atom
DTL-F05
predict_future_cone
DTL-F06
predict_security_state_delta
DTL-F07
estimate_uncertainty
DTL-F08
estimate_security_hazard
DTL-F09
score_prediction_residual
DTL-F10
assign_causal_credit
DTL-F11
counterfactual_probe
DTL-F12
request_observation_escalation
DTL-F13
merge_equivalent_atoms
DTL-F14
split_heterogeneous_atom
DTL-F15
forget_low_utility_memory
DTL-F16
lookup_transition_cache
DTL-F17
propose_compile_candidate
DTL-F18
detect_epoch_mismatch
DTL-F19
quarantine_adaptation_sample
DTL-F20
export_evidence_bound_prediction

# 30. Prototype Module Layout

stage2/├── encoder/├── router/├── state/│   ├── fast/│   ├── session/│   ├── host/│   ├── epoch/│   └── causal/├── lattice/│   ├── atoms/│   ├── transitions/│   ├── merge/│   └── split/├── predictors/├── uncertainty/├── counterfactual/├── credit/├── adaptation/├── cache/├── compile_candidates/├── training/├── baselines/├── benchmarks/└── tests/

# 31. Resource Architecture

Stage 2 keeps the Stage 0 Edge profile as the primary target. Initial research budgets are ceilings to challenge, not promises:
Component
Expected research target
SSIR encoder + router
< 5–10 MB RSS incremental
Predictive core weights
prefer < 5–25 MB after compression
Dynamic latent state
KB-scale per active host/session
Atom/codebook lattice
bounded, target < 5–20 MB
Transition/cache tables
bounded, target < 5–20 MB
Uncertainty/counters
< 5 MB
Peak Stage 2 incremental RAM
initial ceiling 80 MB; drive downward experimentally
An optional larger research model may be used only as a teacher or reference on development hardware. It is not the deployment architecture.

# 32. Quantization and Arithmetic Research

Stage 2 should test FP32 only as a reference. Deployment experiments include FP16/BF16 where supported, INT8, INT4 where kernels permit, vector quantization, low-bit recurrent state, and mixed precision by state importance.
high-responsibility state -> higher precisionstable/low-uncertainty state -> lower precisioncompiled transition -> integer/table lookup
File-size reduction is not enough; RSS, workspace, latency and CPU cycles must be measured.

# 33. Sleeping-Brain Benchmark

A defining experiment measures how often expensive inference can remain asleep:
Measure:P0 compiled/cache %P1 lattice lookup %P2 local update %P3 full predictive %P4 deep/counterfactual %Plot:security quality vs full-core wake rate vs CPU/event
The target is the safest Pareto point, not an arbitrary 99% sleep target.

# 34. Evaluation Beyond Accuracy

- Future prediction: cross-entropy/perplexity where meaningful, top-k transition accuracy, state-delta accuracy.
- Security: precision, recall, F1, PR-AUC, recall at fixed FP budget, FP/host/day, detection latency.
- Calibration: expected calibration error, Brier score and coverage/error for chosen uncertainty method.
- Unknowns: OOD/unseen-binary and unseen-technique performance.
- Attribution: number of evidence nodes/transitions an analyst must inspect; causal-spine precision/recall.
- Efficiency: RSS/PSS, model bytes, state bytes, CPU/event, events/sec, p95/p99 latency, wake-rate distribution.
- Lattice: atom count, transition count, merge/split rates, cache hit rate, compile-candidate stability.
- Drift: recovery time after legitimate epoch change without catastrophic normalization of attacks.
- Reliability: bounded queue behaviour, overload loss, restart recovery and corrupted-state handling.

# 35. Stage 2 Experimental Program

S2-E01  Markov/n-gram baselineS2-E02  MLP feature-state baselineS2-E03  GRU baselineS2-E04  LSTM baselineS2-E05  TCN baselineS2-E06  tiny Transformer baselineS2-E07  selective SSM baselineS2-E08  latent-dimension sweepS2-E09  multi-timescale stateS2-E10  semantic sparse routerS2-E11  multi-head future predictionS2-E12  Future ConeS2-E13  structured surprise vectorS2-E14  vector-quantized Behaviour AtomsS2-E15  atom equivalence + mergingS2-E16  atom fissionS2-E17  lattice transition probabilitiesS2-E18  transition cacheS2-E19  sleeping-brain benchmarkS2-E20  security hazard headsS2-E21  uncertainty calibrationS2-E22  active-perception feedbackS2-E23  counterfactual twinS2-E24  causal credit ledgerS2-E25  predictive-utility forgettingS2-E26  negative-space learningS2-E27  epoch-conditioned dynamicsS2-E28  anti-poisoning adaptationS2-E29  low-bit latent/state arithmeticS2-E30  full DTL ablation and Pareto analysis

# 36. Hard Falsification Criteria

DTL must be simplified or rejected if any of the following persist after fair tuning:
- A simple baseline achieves statistically comparable security performance with materially lower cost.
- Discrete atoms add complexity without improving wake rate, attribution, robustness or memory.
- Future Cone predictions are poorly calibrated or do not improve detection/observation decisions.
- Counterfactual analysis adds latency but not attribution quality.
- Online adaptation cannot be protected adequately against poisoning within the endpoint budget.
- Atom merging/splitting is unstable under repeated runs or creates unacceptable alert variance.
- Low-bit state causes security degradation beyond the predefined tolerance.
- The architecture cannot operate within the Stage 0 Edge resource envelope.

# 37. Reliability and Fail-Safe Behaviour

- Prediction failure never suppresses deterministic Stage 1 evidence.
- Unknown/NaN/corrupt model state causes abstention and safe state reset, not benign classification.
- Lattice/cache entries are versioned by model and epoch.
- All dynamic structures have hard caps and deterministic eviction.
- Compile candidates never become trusted solely from frequency.
- Adaptation buffers are bounded and separated from trusted weights/state.
- Full-core crash falls back to Stage 1 deterministic/rule paths and cached validated transitions where safe.
- Every alert references immutable evidence IDs; generated explanations cannot create evidence.

# 38. Stage 2 Acceptance Gate

- At least five strong baselines have been implemented under identical Stage 1 inputs and evaluation splits.
- A minimum-sufficient latent-state frontier has been measured.
- Selective routing reduces measured compute without unacceptable security loss.
- Behaviour Atoms are demonstrably stable enough to reuse, or the discrete layer is rejected.
- Prediction uncertainty is calibrated well enough to support abstention/AOP decisions.
- Future Cone or hazard prediction adds measurable value beyond next-event prediction, or is removed.
- Causal credit produces more concise attribution than naive ancestry under controlled attacks.
- Concept-drift/epoch tests demonstrate adaptation without simply normalizing repeated malicious behaviour.
- Poisoning tests validate the quarantine/promotion path.
- Sleeping-brain results quantify how much traffic avoids expensive inference.
- DTL remains within the Stage 0 Edge memory/CPU envelope on the 2 GB target.
- Every surviving DTL component has an ablation-supported reason to exist.
- Stable transition candidates can be exported to Stage 3 without embedding DTL-specific assumptions into the PocketSec hub.

# 39. Stage 2 Deliverables

- D2.1 — DTL Core specification and versioned functional IDs.
- D2.2 — Baseline suite and unified benchmark harness.
- D2.3 — Multi-timescale predictive core.
- D2.4 — Need-to-Compute sparse router.
- D2.5 — Multi-head predictive/surprise engine.
- D2.6 — Behaviour Atom quantizer and bounded lattice.
- D2.7 — Merge/fission and predictive-equivalence evaluator.
- D2.8 — Future Cone / hazard prototype.
- D2.9 — Calibrated uncertainty and abstention module.
- D2.10 — Counterfactual Twin and Causal Credit Ledger.
- D2.11 — AOP feedback/value-of-information prototype.
- D2.12 — Epoch-conditioned and anti-poisoning adaptation pipeline.
- D2.13 — Transition cache and compile-candidate exporter.
- D2.14 — Full resource, robustness, drift, attribution and ablation report.
- D2.15 — Stage 3 neural-to-executable compiler interface.

# 40. Stage 3 Handoff

Stage 3 receives validated Behaviour Atoms, transition statistics, uncertainty envelopes, causal evidence requirements and compile candidates. Its job is to build the reversible Intelligence Compiler: transform stable learned transitions into independently testable executable rules/tables/state-machine fragments, continuously verify them against the predictive core, and decompile them when drift invalidates their assumptions.

# 41. Research Honesty / Novelty Boundary

Several ingredients have established precedents: selective state-space updates, discrete latent representations, provenance-based intrusion detection, concept-drift handling, continual learning and uncertainty estimation. The research contribution, if any, must emerge from the measured combination, security-specific formulation, resource regime, reversible neural↔discrete↔compiled lifecycle, and empirical results. No claim that 'nobody has done this' is permitted without systematic literature and patent/prior-art review.

# 42. Stage 2 Thesis

Do not make a tiny model imitate a giant model. Build the smallest adaptive machine that knows what security future to expect, knows when it does not know, and turns repeated understanding into structure that can eventually execute without the model.

# 43. Research Anchors

- Gu & Dao, Mamba: Linear-Time Sequence Modeling with Selective State Spaces (2023) — input-selective state-space baseline.
- van den Oord, Vinyals & Kavukcuoglu, Neural Discrete Representation Learning / VQ-VAE (2017) — learned discrete latent representations.
- Bilot et al., Sometimes Simpler is Better, USENIX Security 2025 — unified PIDS evaluation, complexity/scalability warning and simple-baseline requirement.
- Jiang et al., ORTHRUS, USENIX Security 2025 — Quality of Attribution and concise causal attack reconstruction.
- Yang et al., CADE, USENIX Security 2021 — concept-drift detection/explanation in security.
- Guo et al., Persistent Backdoor Attacks in Continual Learning, USENIX Security 2025 — threat model for trusted adaptation.
