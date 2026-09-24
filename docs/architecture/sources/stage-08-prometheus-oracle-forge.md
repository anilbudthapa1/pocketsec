<!-- Extracted verbatim from the architecture source `PocketSec_Stage_8_AION_PROMETHEUS_ORACLE_FORGE_Ultra_Advanced_Final.docx`.
     Text-only conversion for tooling; the .docx remains the authoritative artefact. -->

POCKETSEC — STAGE 8
PROMETHEUS + ORACLE + FORGE
Autonomous Defensive Scientific Discovery, Falsification and Intelligence Compression
Comprehensive Final Research Architecture v1.0 • September 2026

# 0. Stage 8 Thesis

Stage 8 turns PocketSec from a system that detects, reasons, learns and collaborates into a bounded defensive research system. Its purpose is not to autonomously invent attacks against real systems. Its purpose is to discover compact defensive knowledge from unexplained observations by generating competing hypotheses, designing safe experiments, attempting to falsify its own theories, and compressing surviving mechanisms into tiny deployable detectors.
OBSERVATION → RESIDUAL → HYPOTHESES → SAFE EXPERIMENTS → FALSIFICATION → SURVIVING MECHANISM → COMPRESSION → STAGE 6 QUARANTINE

# 1. Research Grounding

Recent scientific-AI systems demonstrate that hypothesis generation, experiment proposal, analysis and revision can be integrated into multi-agent scientific workflows. Nature reported both Robin, which integrates hypothesis generation and data analysis, and Co-Scientist, which uses generation, critique and refinement for scientific hypothesis discovery. These systems establish a useful scientific-discovery baseline, but PocketSec requires a stricter cybersecurity boundary: hypotheses and experiments are untrusted until falsified and active adversarial experimentation remains isolated.
MITRE CALDERA provides an established defensive adversary-emulation platform based on ATT&CK and automated planning, showing the value of controlled emulation for evaluating defenses. Stage 8 uses such emulation concepts as a laboratory baseline, while its primary research target is discovery of previously unencoded defensive mechanisms rather than replay of known techniques.
NIST AI 100-2e2025 explicitly covers poisoning, evasion, privacy and misuse risks across predictive and generative AI lifecycles. Stage 8 therefore treats the research engine itself as an adversarial target.

# 2. Stage 8 Layer Map

Layer
Subsystem
Purpose
8.0
Discovery Constitution
hard scientific/safety laws
8.1
Residual Observatory
find what current theory cannot explain
8.2
Discovery Priority Field
decide which residual deserves research
8.3
Hypothesis Genome
typed, testable theory representation
8.4
PROMETHEUS
generate diverse competing mechanisms
8.5
Hypothesis Ecology
branch, mutate, merge, compete and retire theories
8.6
Mechanism Grammar
bounded vocabulary for causal/security mechanisms
8.7
ORACLE
design and execute safe falsification experiments
8.8
Experiment Value Engine
maximize information gain per cost/risk
8.9
Counterfactual Laboratory
mutate evidence/worlds without real attack
8.10
Metamorphic Laboratory
test semantic invariance
8.11
Benign Doppelgänger Engine
construct strongest benign alternatives
8.12
Adversarial Challenger
construct evasion/poisoning counterexamples
8.13
Causal Identifiability Gate
detect when mechanism cannot be resolved
8.14
Theory Ledger
record support, contradiction and falsification history
8.15
Discovery Reproducibility Gate
require repeatability across splits/epochs
8.16
FORGE
compile discoveries into cheap representations
8.17
Representation Tournament
rule/FSM/cell/model competition
8.18
Discovery Compression Ratio
measure research-to-runtime efficiency
8.19
Stage 6 Admission Bridge
all discoveries become candidates
8.20
Safety Sandbox
strictly isolated emulation boundary
8.21
Research Resource Governor
bound compute/search explosion
8.22
Research Integrity Plane
protect experiments/models/data
8.23
Novelty/Originality Audit
distinguish new mechanism from rediscovery
8.24
Assurance/Falsification
kill unsupported Stage 8 ideas

# 3. Discovery Constitution

- Stage 8 is defensive research, not an autonomous offensive agent.
- No hypothesis grants permission to execute an action on external systems.
- No generated procedure may bypass Stage 5 authority or Stage 6 learning gates.
- An LLM may propose theories but cannot define ground truth.
- Every accepted theory must state observations that could falsify it.
- UNKNOWN/UNIDENTIFIABLE is a valid scientific result.
- Complexity is penalized; simpler mechanisms are preferred when explanatory power is equivalent.
- Discoveries are not trusted until they survive Stage 6 quarantine, shadow and conservation testing.
- Real-system active experiments require explicit isolated lab authorization; production defaults to observation/replay only.

# 4. Discovery Residual Field

R_D(x,t) =ObservedStructure(x,t)-BestExplainableStructure(  Stage2 dynamics,  Stage3 cells,  Stage4 worlds,  Stage6 learned knowledge,  Stage7 collective knowledge)
A large residual is not automatically malicious. It is a statement that PocketSec's current explanatory model is inadequate. Residuals are clustered by structure, context, epoch, visibility and recurrence.

# 5. Residual Decomposition

Residual type
Meaning
R-observation
sensor data violates expected pattern
R-causal
events fit statistically but causal ordering is unexplained
R-temporal
timing/sequence cannot be explained
R-world
no Stage-4 world explains all evidence
R-response
Stage-5 intervention produced unexpected result
R-learning
Stage-6 candidate behaves differently from prediction
R-collective
Stage-7 population pattern has no local/global explanation
R-visibility
apparent anomaly may be caused by missing telemetry

# 6. Discovery Priority Field

Priority(R) = SecurityImpactPotential * Recurrence * CrossContextPersistence * InformationGap * IndependentSupport / (KnownExplanationProbability + ExperimentCost + SafetyRisk + ResourceCost)
This prevents the research engine from wasting compute on every novelty.

# 7. Hypothesis Genome

HypothesisGenome { hypothesis_id observation_scope proposed_mechanism causal_dependencies necessary_conditions sufficient_conditions_candidate predicted_observations forbidden_observations competing_explanations visibility_assumptions falsification_tests information_requests complexity_cost provenance parent_hypotheses status}

# 8. Mechanism Grammar

PROMETHEUS is not allowed to emit arbitrary prose as its internal scientific state. It composes hypotheses from a bounded grammar.
Mechanism :=  Trigger  → StateTransition*  → SecurityRelevantEffectTrigger classes: execution | auth | privilege | file | network | persistence | identity | configurationRelations: precedes | enables | causes_candidate | suppresses | requires | correlates | contradictsModifiers: rare | repeated | epoch-specific | user-specific | visibility-dependent | collective
Natural language is only a rendering of this typed representation.

# 9. PROMETHEUS — Hypothesis Generation

PROMETHEUS combines several generators rather than relying on one LLM.
Generator
Role
causal template generator
compose mechanism structures
analogy engine
adapt validated mechanisms to new contexts
residual clustering
derive hypotheses from repeated unexplained motifs
symbolic enumerator
systematically search small mechanism grammar
tiny/large offline LM
propose semantic interpretations and missing alternatives
Stage-7 collective input
seed hypotheses from distributed evidence
null generator
benign/no-attack explanations
The LLM is one generator among several and has no privileged status.

# 10. Hypothesis Diversity

DiversitySet = maximize: mechanism_distance + causal_structure_distance + benign/adversarial balance + assumption diversitysubject to bounded hypothesis count
Stage 8 deliberately retains incompatible hypotheses early to avoid premature convergence.

# 11. Hypothesis Ecology

birth → challenge → mutate → merge/split → experiment → survive/falsify → fossilize/discard
Mutation is bounded: change one condition, causal edge, timing assumption, visibility assumption or mechanism class at a time. Unconstrained genetic programming is excluded.

# 12. Theory Complexity and MDL Principle

TheoryCost(H) = description_length(mechanism) + number_of_assumptions + special_cases + runtime_cost_of_resulting_detector
Minimum-description-length ideas are used as a model-selection pressure: a complicated theory must explain materially more evidence than a simpler one.

# 13. Theory Score

Score(H) = PredictiveFit + CausalCoherence + FalsificationSurvival + CrossEpochGeneralization + IndependentEvidence - Complexity - Contradictions - VisibilityDependence - AdversarialFragility
This is a research objective; individual terms must be calibrated and ablated.

# 14. ORACLE — Experimental Design

ORACLE chooses the cheapest safe experiment that most separates surviving hypotheses.
X* = argmax_X ExpectedInformationGain(X) -------------------------- CPU + RAM + Time + PrivacyCost + SafetyRisk + LabCost

# 15. Expected Information Gain

EIG(X) = H(Hypotheses | current evidence) - E_result[H(Hypotheses | evidence + result(X))]
Approximate estimators are used when exact Bayesian computation is too expensive.

# 16. Experiment Classes

Class
Example
Production safe?
historical replay
re-run theory on stored episodes
yes
counterfactual mutation
rename/timing/context perturbation
yes
telemetry dropout
remove sensor evidence
yes
metamorphic transform
semantic-preserving transformations
yes
benign alternative generation
construct admin/software explanations
yes
synthetic event world
generate typed event sequences
yes
isolated emulation
authorized sandbox/VM/container lab
lab only
real production intervention
not Stage-8 default; Stage 5 governs
no direct path

# 17. Counterfactual Laboratory

- process/user renaming
- path substitution within semantic class
- timing dilation/compression
- event deletion according to sensor visibility
- benign parent substitution
- destination class substitution
- epoch/configuration changes
- noise/decoy insertion
- causal-edge removal
- reordering where causally possible
A theory that depends on irrelevant names rather than semantics should fail these tests.

# 18. Metamorphic Testing

If transform T preserves security semantics,Detector/Theory(x) should approximately equal Detector/Theory(T(x))If transform T destroys the claimed causal mechanism,support should fall.
Metamorphic relations are especially valuable where perfect labels are unavailable.

# 19. Benign Doppelgänger Engine

For every malicious-looking hypothesis, Stage 8 constructs the strongest plausible benign explanation: automation, software update, admin script, backup, package manager, monitoring agent, developer tooling, orchestration, or workload-specific behavior.
A hypothesis is not strong until it can distinguish its malicious mechanism from its best benign doppelgänger.

# 20. Adversarial Challenger

The challenger attacks theories and candidate detectors with safe transformations rather than generating operational intrusion instructions.
- feature obfuscation
- timing changes
- living-off-the-land substitutions
- event flooding
- rare benign mimicry
- partial telemetry loss
- poisoned labels/capsules
- shortcut-trigger tests
The output is a robustness test corpus, not a deployment-ready attack plan.

# 21. Causal Identifiability Gate

IDENTIFIED: evidence/experiments distinguish mechanism sufficientlyEQUIVALENCE_CLASS: multiple mechanisms predict the same observable dataUNIDENTIFIABLE: available safe observations cannot resolve the difference
Stage 8 must never invent certainty when its sensors cannot identify the cause.

# 22. Theory Ledger

TheoryRecord { genome evidence_for evidence_against experiments predictions failed_predictions counterexamples revisions resource_cost reproducibility status}
Every scientific conclusion is auditable.

# 23. Prediction Before Observation

Where possible, Stage 8 records a hypothesis prediction before evaluating the relevant held-out episode. This reduces post-hoc storytelling.
hypothesis → signed prediction record → hidden/held-out replay → score

# 24. Discovery Reproducibility Gate

- survive host/campaign/time-separated holdouts
- survive at least one independent replay corpus where available
- survive counterfactual/metamorphic tests
- retain calibration under class imbalance
- document telemetry requirements
- document contexts where theory fails

# 25. Novelty Audit

Stage 8 must distinguish true new knowledge from rediscovery of known ATT&CK/Sigma/YARA/literature concepts.
candidate mechanism → semantic search / rule comparison / ATT&CK mapping / literature index → classify:    known    known-combination    context extension    potentially novel
Potential novelty is never claimed as proven novelty without dedicated literature and patent review.

# 26. FORGE — Discovery Compiler

FORGE converts a surviving theory into multiple cheap executable representations.
Representation
Best for
typed rule
clear deterministic invariant
finite-state machine
short temporal chains
Knowledge Cell
reusable causal/security motif
statistical score
frequency/rate/rarity mechanism
prototype/centroid
compact behavioral class
logistic/linear classifier
small interpretable feature combination
tiny tree ensemble
nonlinear tabular relation
tiny MLP/1D CNN/GRU
only when sequence/nonlinearity proves necessary
tiny transformer
only if cheaper forms fail materially

# 27. Representation Tournament

For each representation r: measure:  precision/recall/PR-AUC  FP/host/day  latency  RSS/PSS  bytes  calibration  adversarial robustness  interpretabilitySelect Pareto-minimal representation meeting security threshold.
The most sophisticated representation does not win automatically.

# 28. Discovery Compression Ratio

DCR = DiscoveryComputeCost -------------------- DeployedInferenceCostAlso track: KnowledgeBytesSaved = size(expensive research state) - size(compiled detector)
High DCR is desirable only if the compiled detector preserves the discovery's security value.

# 29. Intelligence Crystallization

large/offline reasoning + many hypotheses + expensive replay + optional large teacher         ↓surviving mechanism         ↓FORGE         ↓kilobyte-scale rule/cell/model         ↓cheap edge intelligence
This is the central connection to PocketSec's ≤2 GB objective.

# 30. Distillation from Research Models

If a large offline model discovers a useful classification boundary, Stage 8 can distill its behavior into a tiny student, but only after evidence-grounded validation.
- teacher labels carry provenance and uncertainty
- hard ground-truth/lab labels override teacher opinion
- student evaluated on unseen families/hosts/epochs
- distillation rejected if it learns teacher shortcuts

# 31. Program Synthesis Boundary

Stage 8 may synthesize defensive predicates, state machines and feature programs from a restricted DSL. It must not synthesize unrestricted shellcode, exploitation programs or arbitrary privileged scripts.
Allowed DSL: event predicates bounded arithmetic temporal windows set membership graph relations FSM transitions risk contributionsNo arbitrary syscalls/network actions.
Execution remains detection-only until Stage 5 separately authorizes any response.

# 32. Scientific Memory

Memory
Content
question memory
unresolved residuals
hypothesis memory
genomes and lineage
experiment memory
design/results
counterexample memory
theories' failure cases
discovery fossils
validated mechanisms
negative-result memory
failed ideas to avoid repeated compute
Negative results are valuable because they prevent the research engine from repeatedly rediscovering dead ends.

# 33. Hypothesis Lineage DAG

residual → H1 → H1a/H1b → experiment → H1b2 → discovery D17 → FORGE candidates → Stage6 candidate
Every deployed discovery can be traced back to observations and falsification history.

# 34. Research Integrity Plane

- content-address datasets, hypotheses, experiments and model artifacts
- version all transformations
- separate training and hidden evaluation data
- detect leakage between replay splits
- sign promotion records
- treat LLM/tool output as untrusted input
- protect benchmark corpora from candidate access where practical
- record random seeds and environment manifests

# 35. Experiment Sandbox

Active emulation is physically/logically separated from production.
- VM/container namespace isolation appropriate to the experiment
- no route to unrelated networks
- synthetic credentials/data
- bounded CPU/RAM/disk/network
- snapshot/revert
- explicit allow-listed emulation primitives
- audit log of every lab action
- kill switch/time limit
MITRE CALDERA may be used as one lab baseline for known ATT&CK behaviors; Stage 8's discovery logic remains separate.

# 36. Automated Scientific-Agent Security

Because Stage 8 itself is agentic, prompt/tool/data attacks become research-system attacks.
- malicious log text attempting to redirect hypothesis generation
- poisoned literature/knowledge retrieval
- tool-output injection
- benchmark contamination
- hypothesis explosion DoS
- self-confirming teacher loops
- fake novelty claims
- experiment-result tampering
Typed internal objects and independent verification reduce reliance on free-form language.

# 37. LLM Role

Task
LLM role
semantic hypothesis proposal
useful optional generator
causal truth
not authority
experiment selection
candidate proposals; ORACLE scores typed designs
evidence extraction
must cite structured evidence
novelty claim
cannot establish
detector execution
not required
human explanation
optional
Stage 8 can use a powerful development-machine LLM while deploying none of it to the endpoint.

# 38. Tool Architecture

Function
Preferred tools/concepts
offline research
Python + PyTorch/scikit-learn
causal experiments
DoWhy/EconML/causal-learn candidates where assumptions fit
Bayesian/active design
Pyro/NumPy/SciPy/custom lightweight estimators
symbolic search
custom typed DSL + enumerative/beam search
property/metamorphic tests
Hypothesis + custom generators
emulation lab
MITRE CALDERA + isolated custom replay harness
event replay
custom deterministic PocketSec simulator
graph analysis
NetworkX offline; compact custom runtime
model export
ONNX
edge runtime
Rust + existing Stage 1–7 components
experiment tracking
content-addressed manifests; MLflow optional offline
Tools are candidates, not architectural dependencies. The best measured tool wins.

# 39. Causal Discovery Boundary

Pure observational causal discovery cannot generally identify every causal direction without assumptions. Stage 8 records those assumptions and uses interventions only in authorized simulations/labs. PC/FCI/GES/NOTEARS-style families can be benchmarks for structure discovery, but no algorithm is treated as an oracle.

# 40. Active Learning vs Active Experimentation

Active learning selects examples whose labels would improve a detector. Active experimentation selects observations/interventions that distinguish mechanisms. Stage 8 uses both, but keeps them separate so classification uncertainty is not confused with causal uncertainty.

# 41. Bayesian Model Competition

Posterior(H_i) ∝ Likelihood(E | H_i) × Prior(H_i)But: priors are explicit/versioned likelihood approximations documented adversarially generated evidence down-weighted posterior never overrides hard safety gates
Bayesian competition is one option; score-based and MDL approaches remain baselines.

# 42. Unknown-Unknown Search

Stage 8 prioritizes structured residuals that persist across independent contexts but fail known mechanism matching.
UnknownUnknownCandidate = residual recurrence × structural coherence × cross-epoch persistence × independent support × failure of known-library retrieval

# 43. Scientific Stopping Rules

- stop when one hypothesis is sufficiently identified for the intended detector
- stop when all remaining hypotheses are observationally equivalent
- stop when expected information gain falls below cost threshold
- stop on safety/resource budget
- stop when residual is explained by telemetry failure
- stop when the candidate is known prior art and no extension remains

# 44. Research Resource Governor

Resource
Bound
active residuals
top-N priority queue
hypotheses/residual
hard cap
branch depth
hard cap
experiments/hypothesis
hard cap
LLM calls
offline budget
counterfactual worlds
bounded sample
sandbox runtime
time/CPU/RAM quota
stored failed hypotheses
compressed summary
Research can be expensive offline, but it must remain controllable and reproducible.

# 45. Endpoint Resource Model

Stage 8 is mostly an offline/development capability. The endpoint only needs residual summaries, discovery fossils and FORGE outputs.
Endpoint component
Target
residual tracker
5–15 MB
discovery-fossil index
3–10 MB
compiled detector additions
prefer KB–few MB
Stage 8 normal endpoint incremental RSS
prefer <20–35 MB
full PROMETHEUS/ORACLE research
off-endpoint by default

# 46. Safe Development-Machine Architecture

PocketSec replay corpus      ↓Residual Observatory      ↓PROMETHEUS      ↓Hypothesis genomes      ↓ORACLE ┌────┼─────┐ replay counterfactual sandbox └────┼─────┘      ↓Theory Ledger      ↓Reproducibility + Novelty Gates      ↓FORGE      ↓Representation Tournament      ↓signed Discovery Package      ↓Stage6 Quarantine on endpoint

# 47. Discovery Package

DiscoveryPackage { mechanism required_features detector_candidates selected_representation evidence_lineage falsification_results failure_conditions resource_profile robustness_profile known-technique mappings novelty_classification artifact_hashes}

# 48. Stage 6 Admission

A Stage 8 discovery is still only a candidate.
DiscoveryPackage → Stage6 Quarantine → Shadow Mind → Conservation Gate → Canary → Trusted
Stage 8 has no bypass.

# 49. Stage 7 Interaction

Stage 7 can contribute distributed residuals and independent counterexamples. Stage 8 can return compact discoveries as Knowledge Antibodies, but those antibodies retain Stage 7/6 zero-trust handling on other hosts.

# 50. Metrics

- percentage of residuals explained by validated mechanisms
- novel mechanism precision after human/prior-art review
- hypothesis falsification rate
- experiments required per validated discovery
- information gain per CPU-hour
- benign-doppelgänger rejection performance
- cross-host/time/campaign generalization
- false discovery rate
- reproducibility rate
- causal identifiability/abstention correctness
- FORGE compression ratio
- edge bytes/RSS/latency per compiled discovery
- regression introduced by new detector
- adversarial robustness after compilation

# 51. Baselines

Baseline
Question
human/manual research
does Stage 8 accelerate discovery?
LLM-only hypothesis generation
does typed falsification matter?
anomaly clustering only
does mechanism discovery add value?
active learning only
is causal experimentation useful?
Bayesian optimization
experiment-selection baseline
random experiment selection
information-gain baseline
PC/FCI/GES/NOTEARS families
causal-discovery baselines where applicable
known ATT&CK/CALDERA replay
known-technique baseline
direct large-model detector
does FORGE compression preserve value?

# 52. 80-Experiment Program

S8X-01  residual field construction
S8X-02  residual decomposition
S8X-03  priority calibration
S8X-04  telemetry-failure residual
S8X-05  hypothesis genome validation
S8X-06  mechanism grammar coverage
S8X-07  symbolic generator
S8X-08  LLM generator
S8X-09  analogy generator
S8X-10  null/benign generator
S8X-11  hypothesis diversity
S8X-12  bounded mutation
S8X-13  hypothesis merge/split
S8X-14  MDL complexity
S8X-15  Bayesian competition
S8X-16  score competition
S8X-17  prediction-before-observation
S8X-18  hidden holdout integrity
S8X-19  historical replay
S8X-20  time-split replay
S8X-21  host-split replay
S8X-22  family/campaign split
S8X-23  counterfactual rename
S8X-24  timing mutation
S8X-25  telemetry dropout
S8X-26  decoy insertion
S8X-27  causal-edge deletion
S8X-28  metamorphic invariant
S8X-29  benign doppelgänger admin
S8X-30  software-update doppelgänger
S8X-31  backup/orchestration doppelgänger
S8X-32  adversarial challenger
S8X-33  living-off-land substitution
S8X-34  slow behavior
S8X-35  event flood robustness
S8X-36  shortcut trigger
S8X-37  EIG experiment selection
S8X-38  random experiment baseline
S8X-39  cost-aware EIG
S8X-40  stopping rule
S8X-41  causal identifiability
S8X-42  equivalence class
S8X-43  unidentifiable abstention
S8X-44  PC baseline
S8X-45  FCI baseline
S8X-46  GES/score baseline
S8X-47  NOTEARS-style baseline
S8X-48  sandbox isolation
S8X-49  CALDERA known-technique lab
S8X-50  sandbox kill switch
S8X-51  experiment tamper detection
S8X-52  hypothesis DoS
S8X-53  prompt/log injection
S8X-54  poisoned retrieval
S8X-55  teacher self-confirmation
S8X-56  negative-result memory
S8X-57  novelty ATT&CK mapping
S8X-58  Sigma/YARA overlap audit
S8X-59  known-combination classification
S8X-60  potential-novelty review
S8X-61  FORGE rule
S8X-62  FORGE FSM
S8X-63  FORGE Knowledge Cell
S8X-64  FORGE logistic model
S8X-65  FORGE tree model
S8X-66  FORGE tiny neural model
S8X-67  representation tournament
S8X-68  INT8 export
S8X-69  compression ratio
S8X-70  edge latency
S8X-71  edge RSS
S8X-72  cross-epoch generalization
S8X-73  Stage6 quarantine
S8X-74  Shadow Mind discovery
S8X-75  Conservation Gate rejection
S8X-76  canary rollback
S8X-77  Stage7 antibody export
S8X-78  distributed residual discovery
S8X-79  full ablation
S8X-80  full Stage1–8 endurance

# 53. Hard Falsification Criteria

- LLM-only or simple anomaly clustering discovers equally useful mechanisms at lower complexity.
- Residual prioritization fails to predict research value.
- Generated hypotheses are mostly post-hoc narratives rather than predictive theories.
- ORACLE information-gain selection does not beat random/cheap baselines.
- Benign doppelgänger testing does not reduce false discoveries.
- Causal claims remain unidentifiable in most practical telemetry.
- FORGE cannot compress discoveries without losing critical detection capability.
- Compiled detectors add unacceptable FP/CPU/RAM burden.
- Stage 8 repeatedly rediscovers known ATT&CK/rule knowledge without useful extensions.
- Research-agent attack surface outweighs discovery benefit.

# 54. Acceptance Gate

- Every hypothesis has explicit falsification conditions.
- Free-form LLM text is never the canonical scientific state.
- All active emulation is isolated and authorized.
- Unknown/unidentifiable outcomes are preserved rather than forced into conclusions.
- Validated discoveries reproduce across predefined independent splits.
- Novelty is classified conservatively and not claimed without prior-art review.
- FORGE selects by measured security/resource Pareto performance.
- Every DiscoveryPackage has complete lineage and failure conditions.
- All endpoint adoption passes Stage 6.
- Stage 8 does not create a new direct path to Stage 5 authority.
- Research cost is allowed to be high offline; deployed intelligence remains lightweight.
- Advanced mechanisms beat or justify themselves against simpler baselines.

# 55. Deliverables

- D8.1 Discovery Constitution.
- D8.2 Residual Observatory + Priority Field.
- D8.3 Hypothesis Genome + Mechanism Grammar.
- D8.4 PROMETHEUS multi-generator engine.
- D8.5 Hypothesis Ecology + Lineage DAG.
- D8.6 ORACLE information-gain experiment planner.
- D8.7 Counterfactual/Metamorphic Laboratory.
- D8.8 Benign Doppelgänger Engine.
- D8.9 Adversarial Challenger.
- D8.10 Causal Identifiability Gate.
- D8.11 Theory Ledger + negative-result memory.
- D8.12 Reproducibility Gate.
- D8.13 Novelty/Prior-Art Audit pipeline.
- D8.14 FORGE discovery compiler.
- D8.15 Representation Tournament.
- D8.16 Discovery Package format.
- D8.17 Stage6/7 integration adapters.
- D8.18 Research Integrity + Sandbox package.
- D8.19 80-experiment benchmark suite.
- D8.20 Full Stage1–8 endurance/falsification report.

# 56. Novelty Boundary

Automated scientific discovery, multi-agent hypothesis generation, Bayesian experimental design, active learning, causal discovery, program synthesis, metamorphic testing, adversary emulation and model distillation are established research areas. PROMETHEUS, ORACLE, FORGE, Discovery Residual Field, Benign Doppelgänger Engine, the exact Hypothesis Genome/Mechanism Grammar, Discovery Compression Ratio and the Stage 6/7 bounded integration are proposed PocketSec constructs. Their novelty or patentability is not established by this document.

# 57. Final Principle

PocketSec should not call a pattern knowledge because an AI can explain it. It becomes knowledge only after the theory predicts reality, survives serious attempts to disprove it, reproduces outside the evidence that created it, and can be compressed into a defensive mechanism whose cost is justified by the security value it preserves.

# 58. Stage 9 Handoff

If Stage 8 succeeds, Stage 9 should investigate meta-architecture evolution: whether PocketSec can scientifically redesign parts of its own detection architecture, feature system and tiny models under formal resource/safety constraints. The target would not be unrestricted self-modifying AI; it would be verified architecture search where candidate designs are generated offline, benchmarked, falsified, compiled and admitted through the same Stage 6 conservation process.

# 59. ULTRA-ADVANCED EXTENSION — AION

The earlier Stage 8 is retained as the executable scientific-discovery foundation. This extension adds AION: an architecture-invention layer that searches for new compact representations and detector mechanisms rather than merely discovering new rules. It is intentionally separated from production authority: AION can propose mathematical objects, representations and micro-models, but cannot deploy them without the existing FORGE → Stage 6 path.
AION = Architecture Invention and Optimization NexusGoal: discover cheaper representations of security-relevant computation, not merely larger models.

# 60. The Deeper Problem

A conventional security model asks f(x) → threat class. AION asks a more fundamental question: what is the smallest state, transformation and memory required to preserve the security-relevant information in an event stream?
Find representation Z and transition Φ such that: Z_t = Φ(Z_(t-1), e_t)while minimizing: memory(Z) + compute(Φ) + latency + communicationsubject to: I(Z; security-relevant future) high I(Z; nuisance/identity detail) low detection/calibration/robustness constraints satisfied
This reframes lightweight AI as representation discovery rather than parameter-count reduction.

# 61. Security Sufficient-State Search

AION searches for a compact sufficient state: the smallest evolving state that retains enough information to predict security-relevant outcomes.
Z* = argmin_Z  Cost(Z)subject to: Risk(Y | Z) ≤ ε Robustness(Z) ≥ ρ Calibration(Z) ≥ κ PrivacyLeakage(Z) ≤ π
This is a proposed engineering objective, not a theorem that such a unique state always exists.

# 62. Predictive Information Bottleneck

The architecture should explicitly discard information that is expensive but irrelevant. Rather than encode entire command lines/process trees, it learns or synthesizes transformations that preserve only predictive security structure.
Objective candidate: L = SecurityLoss   + β * Complexity(Z)   + γ * ComputeCost   + δ * PrivacyLeakage   + η * InstabilityAcrossEpochs
This gives Stage 8 a mathematically testable route toward smaller-than-standard representations.

# 63. Causal Quotient State

Many event sequences are different syntactically but equivalent for detection. AION should quotient them into the same causal state.
e1 ~ e2  ifftheir differences do not change:  predicted security outcome,  causal role,  required investigation,  robustness under allowed transformationsState = equivalence class [e]~
Example: different usernames, PIDs and temporary filenames may collapse into one security mechanism if those identities are causally irrelevant.

# 64. Event Algebra

Instead of tokenizing Linux telemetry like language, define an algebra over security events.
Primitive operators: ⊕  concurrent composition →  temporal/causal succession ⊗  joint requirement ¬  contradiction/absence Δ  privilege/state transition @  host/user/process binding ≈  semantic equivalenceCandidate motif: AuthSuccess → ΔPrivilege → SensitiveRead ⊗ NewDestination
The research question becomes whether algebraic canonicalization can outperform text/token representations in bytes, latency and generalization.

# 65. Canonical Motif Compiler

raw event graph → remove nuisance identities → canonicalize node/edge types → collapse equivalent subgraphs → hash/canonical label → motif state → detector
This enables repeated behavior to be recognized without retaining the original verbose event sequence.

# 66. Hyperdimensional Security Memory

AION should benchmark hyperdimensional/vector-symbolic computing as a radically different compact representation. Events can be bound and superposed into fixed-width vectors; similarity then becomes cheap bit/integer operations. This is not assumed superior—it is a serious alternative to neural sequence models for low-memory hardware.
H(event) = bind(  type_vector,  role_vector,  path_class_vector,  privilege_vector,  temporal_position)Episode = superpose(H(e1), H(e2), ...)Compare: binary HDC bipolar HDC low-bit integer HDC learned compact embeddings

# 67. Sparse Associative Threat Memory

Instead of dense transformer attention, Stage 8 should test sparse content-addressable memory. Only a small number of prototypes/motifs become active for each episode.
query episode → compact signature → top-k sparse memory cells → local relation test → risk evidenceComplexity target: O(k) active cells rather than O(N) full knowledge scan
The memory must be bounded, mergeable, expirable and resistant to poisoning.

# 68. Learned Finite-State Transducer Synthesis

FORGE currently considers FSMs after discovery. AION should make state-machine synthesis itself a first-class learning problem.
positive episodes + hard benign counterexamples          ↓state merge/split search          ↓minimal deterministic/probabilistic transducer          ↓counterexample-guided refinement          ↓tiny executable detector
This can yield byte-scale or kilobyte-scale models when the underlying security mechanism is fundamentally sequential.

# 69. Counterexample-Guided Inductive Synthesis (CEGIS)

1. synthesize candidate detector D2. search for benign/malicious counterexample x3. if found: add x to constraints4. refine D5. repeat until budget/gateD* = smallest candidate surviving the accumulated counterexamples
CEGIS is especially appropriate for Stage 8 because falsification is built into the synthesis loop.

# 70. Differentiable-to-Symbolic Compilation

A large teacher can discover a boundary in a continuous representation. AION then attempts to compile that boundary into symbolic predicates or small state machines.
teacher representation → sensitivity/attribution analysis → candidate discrete predicates → symbolic/state-machine synthesis → equivalence testing → adversarial counterexamples → refine
The aim is not explainability alone; it is elimination of the heavy teacher from production.

# 71. Detector Supercompiler

AION should treat the entire detector as a program that can be partially evaluated against the host's stable configuration.
generic detector + host invariants + installed packages + service role + enabled sensors       ↓partial evaluation       ↓specialized detector binary/state table
A server with a fixed role should not pay runtime cost for branches that can never occur on that host.

# 72. Learned Feature ISA

Define a tiny security feature instruction set rather than hardcoding hundreds of Python features.
Instruction
Meaning
COUNT(type,window)
bounded event count
RARE(key,context)
rarity estimate
EDGE(a,b)
process/event relation
DELTA(state)
state/privilege transition
WITHIN(a,b,t)
temporal relation
FIRST_SEEN(x)
novelty
SENSITIVE(class)
sensitive semantic category
DEST_CLASS(x)
destination abstraction
DEPTH(tree)
bounded ancestry
MATCH(cell)
knowledge-cell activation
AION searches programs over this ISA. Production executes a tiny VM or ahead-of-time compiled Rust/C representation.

# 73. Feature-Program Search

Program P = sequence/DAG of Feature-ISA operationsFitness(P) = security utility - λ1*instruction_count - λ2*state_bytes - λ3*latency - λ4*false_positive_cost - λ5*fragility
Beam search, enumerative synthesis, evolutionary search and differentiable relaxation become competing search methods.

# 74. Architecture Genome v2

ArchitectureGenome { input sensors event abstractions state representation update operator memory structure feature program detector head calibration method uncertainty method evidence renderer resource contract invariance contract threat-model contract}
Mutation operates on typed architectural components, not arbitrary source code.

# 75. Pareto Architecture Evolution

A dominates B only if A is no worse in all required objectivesand strictly better in at least one:PR-AUCFP/host/daydetection latencypeak RSSCPU/eventbytes on diskrobustnesscalibrationprivacy leakageexplainability
There is no scalar 'best AI'. AION preserves a Pareto frontier and selects according to the Stage 0 deployment contract.

# 76. Resource-Lagrangian Search

J(θ) = DetectionLoss(θ) + λ_ram * max(0,RAM(θ)-B_ram) + λ_cpu * CPU(θ) + λ_lat * Latency(θ) + λ_fp  * FPcost(θ) + λ_adv * AdversarialRisk(θ)
Resource use is therefore part of training/search itself, not an optimization performed after the model is finished.

# 77. Hardware-in-the-Loop Architecture Search

Proxy FLOPs are insufficient. Candidate architectures should periodically execute on the actual low-spec target.
search candidate → compile/export → run on 2 GB reference host → measure RSS/PSS/cache misses/latency/energy proxy → return real measurements to search controller
This prevents Stage 8 from 'discovering' theoretically tiny models that are inefficient in their real runtime.

# 78. Anytime Cognition

PocketSec should produce progressively stronger conclusions as compute becomes available rather than requiring a fixed expensive pass.
budget 1: rules + motif cachebudget 2: sparse statistical modelbudget 3: temporal transducerbudget 4: optional neural/semantic reasoningAt every budget: return best calibrated answer currently available
This allows graceful operation during CPU pressure.

# 79. Adaptive Computation Depth

difficulty d(x) estimated cheaplyif d < τ1: exit after deterministic layerelif d < τ2: invoke tiny learned layerelif d < τ3: invoke temporal/world reasoningelse: queue optional expensive analysis
The innovation target is not just a smaller model; it is avoiding computation on easy events entirely.

# 80. Conditional Expert Microcells

Rather than a monolithic MoE, AION can discover dozens of extremely small experts with a deterministic/sparse router.
episode → router → {expert_3, expert_17}                      ↓                 evidence merge
Experts may be tiny trees, FSMs, prototypes or micro-MLPs. Inactive experts consume disk but near-zero inference compute.

# 81. Structural Sparsity Before Quantization

Quantization is useful, but a dense model with fewer bits may still perform unnecessary computation. AION prioritizes removing computation structurally.
canonicalization → state minimization → expert sparsity → pruning → distillation → quantization
This ordering is a research hypothesis to benchmark, not a universal rule.

# 82. Temporal Multi-Resolution Memory

Security processes operate at milliseconds, minutes, hours and days. One fixed context window is wasteful.
fast ring: seconds, exact sparse eventsmid sketch: minutes, aggregated motifsslow memory: hours/days, fossils/statisticscross-scale links preserve only significant transitions
This replaces an LLM-style ever-growing context with bounded multi-resolution memory.

# 83. Event Horizon Compression

Old raw events should collapse into progressively more abstract sufficient summaries.
raw events → motif → episode summary → baseline delta → long-term fossilinformation is discarded only after required invariants are preserved
The system should experimentally estimate what information can be forgotten without degrading future detection.

# 84. Semantic Conservation Law — Proposed

For compression C: SecurityMeaning(E) ≈ SecurityMeaning(C(E))while: Bytes(C(E)) << Bytes(E)Violation: if a counterfactual changes security outcome in E but not in C(E), compression destroyed a relevant distinction.
This gives compression a falsifiable security criterion.

# 85. Conservation Test Suite

- identity-preserving nuisance changes must not alter the compressed state
- causally important privilege changes must alter it
- removing a necessary event must reduce mechanism support
- telemetry-loss cases must expose uncertainty rather than silently preserve confidence
- benign doppelgängers must remain distinguishable where the full evidence distinguishes them

# 86. Mechanism Entropy

AION should estimate how many distinct compact mechanisms are needed to explain the endpoint's security behavior.
H_M = entropy over validated mechanism activationsHigh H_M: host needs richer modelLow H_M: many events compress to few mechanisms
This can guide whether a host needs neural capacity at all.

# 87. Epistemic Compute Allocation

ComputeBudget(h) ∝ uncertainty(h) × security impact(h) × novelty(h) × expected information gain(h) / current system pressure
CPU becomes an epistemic resource allocated to questions where additional computation can change the decision.

# 88. Confidence as a Vector, Not a Scalar

ConfidenceVector = [ data_coverage, model_agreement, causal_support, baseline_support, collective_support, calibration_quality, adversarial_robustness, epistemic_uncertainty]
A single 0.93 score hides why the system believes something. The vector can be collapsed for UI only after preserving the components internally.

# 89. Contradiction Tensor

Stage 8 should retain structured contradictions rather than averaging them away.
C[i,j,k] = contradiction between hypothesis i, evidence family j, context/epoch k
Persistent structured contradiction becomes a discovery signal and can trigger hypothesis splitting.

# 90. Open-World Recognition

AION must explicitly model 'none of the known mechanisms'.
known score low + residual structure high → UNKNOWN_MECHANISM → quarantine/researchnot: → force nearest known class
This is essential for unknown-unknown discovery.

# 91. Uncertainty Decomposition

Uncertainty
Interpretation
aleatoric
event/evidence ambiguity
epistemic
model lacks knowledge
visibility
sensor coverage insufficient
distributional
host/context outside training support
adversarial
evidence may be manipulated
causal
multiple mechanisms observationally equivalent
Each uncertainty type leads to a different next action.

# 92. Minimal Witness Sets

For every alert/discovery, compute the smallest subset of evidence that still supports the conclusion.
W* = argmin_W |W|subject to: decision(W) = decision(E) and robustness(W) ≥ threshold
Minimal witnesses reduce explanation size, incident storage and downstream reasoning cost.

# 93. Counterfactual Witness

For decision y: find smallest semantically valid change ΔE such that decision(E + ΔE) ≠ y
Together, minimal and counterfactual witnesses tell the analyst both why the decision holds and what would have changed it.

# 94. Self-Compression Loop

validated architecture A → profile real activations → identify dead/redundant state → synthesize A' → equivalence + adversarial tests → benchmark → Stage6 candidate
The system may propose a smaller successor, but cannot rewrite itself in place.

# 95. Architecture Fossils

Rejected architectures are not simply deleted. Their failure signatures are compressed so future search avoids equivalent dead ends.
Fossil { architecture signature failed constraints counterexample classes resource failure epochs tested}

# 96. Proof-Carrying Detector Package

Every synthesized detector should ship with machine-checkable evidence about its constraints, not only a model file.
DetectorPackage { executable artifact schema/hash required telemetry resource envelope validation metrics calibration profile counterexample suite invariance suite failure domains lineage signature}
This is 'proof-carrying' in an engineering sense; it is not a formal proof unless a formal verifier is actually used.

# 97. Formal-Methods Track

For small synthesized rules/FSMs, Stage 8 should test SMT/model-checking techniques.
- prove state-machine reachability properties
- prove absence of forbidden Stage-5 action edges
- verify bounded memory/state counts
- check mutually exclusive conditions
- find logical counterexamples to detector predicates
- verify deterministic behavior for canonical input classes
Z3-class SMT tooling is an offline research option; formal verification is focused on small compiled artifacts, not large neural models.

# 98. Dual Semantics

Every detector has two semantics: operational and evidential.
Operational semantics: how state changes and alert is producedEvidential semantics: which observations justify each conclusionA detector is invalid if it can emit a conclusionwithout a traceable evidential path.
This prevents a compressed architecture from becoming an opaque score generator.

# 99. Quantum-Inspired Boundary

Quantum physics does not provide a credible magical route to compress a classical Linux security model on ordinary hardware. However, mathematically inspired ideas—superposition-like vector-symbolic representations, tensor factorizations, low-rank state representations and probabilistic amplitude-style normalization—can be benchmarked as classical algorithms. They must be labeled quantum-inspired, not quantum computation.
No claim of quantum advantage is permitted without actual quantum hardware, a defined complexity model and an empirical/theoretical advantage demonstration.

# 100. Tensorized State Compression

AION should benchmark low-rank/tensor factorization when state interactions are approximately separable.
Large interaction table T≈ factor matrices / tensor trainaccept only if: detection loss ≤ ε runtime memory decreases CPU does not regress materially
This is useful only when runtime kernels exploit the factorization; smaller files alone do not count.

# 101. Neuromorphic/Event-Driven Track

Because Linux telemetry is event-driven, Stage 8 should test sparse event-triggered computation inspired by neuromorphic systems without assuming specialized hardware.
no event → no updateirrelevant event → O(1) filterrelevant event → update only touched state cells
The practical goal is near-zero idle compute.

# 102. Research Compiler Pipeline

Hypothesis Genome → Mechanism IR → candidate representations → optimization passes:    canonicalize    specialize    eliminate dead state    merge equivalent states    factorize    sparsify    quantize if useful → native/ONNX/bytecode artifact → equivalence tests → target benchmark
This turns FORGE into an actual compiler architecture rather than a model-export step.

# 103. Mechanism Intermediate Representation (MIR)

MIR { typed events state variables temporal constraints causal candidate edges uncertainty channels evidence requirements update equations alert predicates ATT&CK mapping metadata}
MIR becomes the bridge between scientific discovery and multiple executable forms.

# 104. Multi-Backend Code Generation

Backend
Use
Rust native
default production path
C
micro-runtime/embedded experiments
ONNX
learned components
table/FSM binary
ultra-small deterministic mechanisms
eBPF subset
only verifier-safe kernel-side prefiltering
WASM
optional sandboxed portable research backend
AION compares generated backends on the actual target.

# 105. eBPF Placement Optimizer

Some filtering can occur before userspace. Stage 8 may search which simple predicates are worth moving into eBPF, subject to verifier/safety constraints.
kernel placement only for: cheap deterministic filtering bounded maps simple counters event reductionno large learned reasoning in kernel
The optimizer measures whether reduced event volume outweighs kernel complexity.

# 106. Information-Per-Byte Metric

IPB = validated security information retained -------------------------------------- runtime state bytes + model bytes + buffer bytes
Because 'security information' is not directly measurable, Stage 8 operationalizes it through held-out predictive utility, calibration and counterfactual preservation. IPB is therefore an empirical proxy.

# 107. Security Utility per Joule/CPU-Cycle

Efficiency = calibrated detection utility ------------------------------------------ CPU cycles + memory traffic + wakeups + latency penalty
perf counters and target-machine measurements replace parameter count as the primary efficiency evidence.

# 108. Three-Tier Intelligence Architecture

TIER Ω0 — Reflex canonical motifs, rules, tiny FSMs microseconds / KB-MBTIER Ω1 — Adaptive Cognition sparse experts, statistical state, tiny learned models milliseconds / tens of MBTIER Ω2 — Research Cognition PROMETHEUS/ORACLE/AION, large teachers, simulation offline / development machineKnowledge flows Ω2 → FORGE → Ω1/Ω0.Authority never flows backward automatically.
This is the intended mature PocketSec architecture.

# 109. AION Search Controller

while research_budget:  choose unresolved residual R  generate architecture genomes G  reject genomes violating static resource/safety constraints  compile candidates  evaluate cheap proxy tests  promote Pareto candidates  run hardware-in-loop tests  generate counterexamples  refine  archive fossils  emit DiscoveryPackage only if acceptance gates pass

# 110. New Benchmark Families

Family
Purpose
Semantic Compression
does state preserve causal/security distinctions?
Architecture Search
can search beat hand-designed Stage 1–7 baselines?
Hardware Reality
RSS/PSS/cache/latency on 2 GB host
Counterexample Robustness
does synthesis survive targeted falsification?
Open World
does system abstain on unknown mechanisms?
Self-Compression
can it shrink without semantic loss?
Formal Artifact
can tiny outputs satisfy machine-checked invariants?

# 111. Additional 48 Experiments

S8X-081  predictive bottleneck beta sweep
S8X-082  causal quotient equivalence
S8X-083  event algebra canonicalization
S8X-084  motif hash collision impact
S8X-085  HDC binary representation
S8X-086  HDC low-bit representation
S8X-087  sparse associative memory
S8X-088  prototype poisoning
S8X-089  FSM synthesis
S8X-090  probabilistic transducer
S8X-091  CEGIS detector synthesis
S8X-092  CEGIS convergence budget
S8X-093  differentiable-to-symbolic compile
S8X-094  teacher shortcut removal
S8X-095  partial evaluation
S8X-096  host specialization
S8X-097  feature ISA interpreter
S8X-098  feature ISA AOT compile
S8X-099  beam program search
S8X-100  enumerative program search
S8X-101  evolutionary program search
S8X-102  architecture genome mutation
S8X-103  Pareto frontier stability
S8X-104  resource-Lagrangian search
S8X-105  hardware-in-loop feedback
S8X-106  proxy-vs-real resource correlation
S8X-107  anytime inference
S8X-108  adaptive depth routing
S8X-109  microexpert routing
S8X-110  expert poisoning
S8X-111  structural sparsity ordering
S8X-112  multi-resolution temporal memory
S8X-113  event horizon compression
S8X-114  semantic conservation tests
S8X-115  mechanism entropy
S8X-116  epistemic compute allocation
S8X-117  confidence vector calibration
S8X-118  contradiction tensor splitting
S8X-119  open-world unknown
S8X-120  uncertainty decomposition
S8X-121  minimal witness
S8X-122  counterfactual witness
S8X-123  self-compression loop
S8X-124  architecture fossil reuse
S8X-125  proof-carrying package
S8X-126  SMT/FSM verification
S8X-127  MIR backend equivalence
S8X-128  eBPF placement optimization

# 112. Ultra-Advanced Falsification Gates

- AION fails if architecture search cannot outperform carefully hand-designed lightweight baselines after accounting for search cost.
- Predictive bottlenecks fail if compression removes rare but causally important security evidence.
- Event algebra fails if canonicalization produces unacceptable semantic collisions.
- HDC/vector-symbolic memory fails if similarity produces excessive benign collisions or offers no resource advantage.
- FSM/CEGIS synthesis fails if realistic mechanisms require state explosion.
- Feature-program search fails if search complexity exceeds the value of the resulting microprograms.
- Hardware-in-loop NAS fails if target measurements are too noisy or search cost becomes impractical.
- Self-compression fails if successor artifacts cannot be independently equivalence-tested.
- Formal verification claims are prohibited for components not actually covered by the formal model.
- Quantum-inspired work is rejected if it is branding without measurable classical computational benefit.

# 113. Stage 8 Revised End State

Stage 8 is no longer only 'AI that invents detections'. Its end state is a bounded scientific compiler capable of discovering security mechanisms, inventing candidate compact representations, testing them against adversarial counterexamples, measuring them on real low-spec hardware, and crystallizing successful discoveries into proof-carrying tiny artifacts.
REALITY  ↓Residuals  ↓PROMETHEUS — theories  ↓ORACLE — falsification  ↓AION — representation/architecture invention  ↓MIR  ↓FORGE — supercompiler  ↓Pareto + hardware-in-loop + counterexamples  ↓DiscoveryPackage  ↓Stage 6 quarantine  ↓Ω0 / Ω1 lightweight cognition

# 114. Research Honesty Statement

The advanced mechanisms above combine established research ideas—information bottlenecks, causal abstraction, MDL, program synthesis, CEGIS, vector-symbolic computing, sparse computation, hardware-aware architecture search, formal methods, partial evaluation and multi-objective optimization—into a new proposed PocketSec composition. The names AION, Mechanism IR, Security Sufficient-State Search, Semantic Conservation Law, Epistemic Compute Allocation and the exact combined pipeline are project constructs. This document does not claim that the composition is scientifically novel, patentable or superior until the experimental program demonstrates that.

# 115. Final Stage 8 Research Objective

Do not ask how small an LLM can become. Ask how little computation and state are fundamentally necessary to preserve the security decisions, causal distinctions and evidence that matter.
