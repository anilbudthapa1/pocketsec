<!-- Extracted verbatim from the architecture source `PocketSec_Stage_9_ONTOGENESIS_Final_Architecture.docx`.
     Text-only conversion for tooling; the .docx remains the authoritative artefact. -->

POCKETSEC — STAGE 9
ONTOGENESIS
LAPLACE • DAEDALUS • GENESIS • ARGUS • GAIA • CHRONOS
Discovery of Minimum Sufficient Security Computation
Final Research Architecture v1.0 • September 2026

# 0. Final Scientific Thesis

Stage 9 does not search merely for a smaller neural network or a better arrangement of known PocketSec modules. It asks whether the computational structure required for Linux security can itself be discovered. The search space includes state variables, event abstractions, primitive operators, memory and forgetting laws, transition dynamics, learning rules, uncertainty representations, resource allocation policies and system topology.
Minimum Sufficient Security Computation (MSSC)C* = argmin_C [    DescriptionLength(C)  + RuntimeCost(C)  + UnexplainedSecurityEvidence(C)]subject to:  DetectionQuality >= Qmin  Robustness >= Rmin  Calibration >= Kmin  Privacy >= Pmin  RAM <= B_ram  CPU <= B_cpu  SafetyInvariants = TRUE
The result is allowed to be a neural model, but it is equally allowed to be a state machine, algebraic program, sparse memory, statistical process, event-driven controller, or a hybrid that does not resemble today's LLMs.

# 1. Research Boundary: What Is Established vs Proposed

Category
Status
Quality-Diversity / MAP-Elites
established evolutionary optimization family
program synthesis / symbolic regression / CEGIS
established research families
information bottleneck / MDL
established information-theoretic/model-selection ideas
hyperdimensional/vector-symbolic computing
established alternative representation family
causal discovery / state-space models
established research families with assumptions
hardware-aware search
established engineering/research direction
NIST adversarial-ML lifecycle threat model
established taxonomy/guidance
ONTOGENESIS composition
PocketSec proposed architecture
Security Renormalization
PocketSec proposed research program
Security State Physics
PocketSec metaphor + falsifiable mathematical program
Algorithmic Chemistry
PocketSec proposed search representation
MSSC objective
PocketSec proposed system-level objective
Physics-inspired terminology is used only where it creates a concrete, testable algorithm. The project does not claim that Linux telemetry literally obeys physical laws.

# 2. Stage 9 System Map

Layer
Engine
Responsibility
9.0
Constitution
immutable safety/resource laws
9.1
ONTOGENESIS
meta-controller for computational discovery
9.2
LAPLACE
discover state/transition/adaptation laws
9.3
Primitive Foundry
discover reusable computational operators
9.4
Algorithmic Chemistry
compose primitives into candidate mechanisms
9.5
Security Renormalizer
discover multiscale abstractions
9.6
Symmetry Laboratory
discover invariances and symmetry breaking
9.7
Conservation Search
find stable benign quantities
9.8
Causal Geometry
mechanism-distance representation
9.9
Phase Observatory
search regime changes/precursors
9.10
CHRONOS
discover memory/forgetting laws
9.11
DAEDALUS
synthesize complete computational systems
9.12
GENESIS
variation, speciation, morphogenesis
9.13
GAIA
quality-diversity ecology/niches
9.14
ARGUS
adversarial falsification
9.15
Convergence Observatory
identify repeatedly rediscovered primitives
9.16
Law Promotion Gate
promote only reproducible computational laws
9.17
Homeostatic Runtime
resource-elastic cognition
9.18
Proof/Contract Plane
machine-checkable constraints where feasible
9.19
Stage-8/6 Bridge
compile and quarantine every result

# 3. Immutable Constitution

- No research engine can directly replace the trusted production architecture.
- No generated computation can create a new Stage-5 response authority path.
- Every security conclusion must retain an evidential path.
- Foreign Stage-7 evidence remains untrusted.
- Resource contracts are hard constraints, not optional fitness terms.
- UNKNOWN and UNIDENTIFIABLE remain valid outcomes.
- Active adversarial experimentation remains isolated.
- Production promotion requires independent compilation, benchmark, quarantine and rollback artifacts.
- Constitutional invariants cannot be evolved by GENESIS.

# 4. Computational Genome

ComputationalGenome {  state_space  observation_map  primitive_alphabet  transition_law  memory_law  forgetting_law  learning_law  uncertainty_law  readout_law  routing_law  resource_control_law  compression_law  evidence_semantics  deployment_backend}
Stage 9 evolves typed computational genomes, not arbitrary source code.

# 5. LAPLACE — Computational Law Discovery

Given event stream e_t and target security variables y_t:discover:  z_t = O(e_t)  s_(t+1) = Φ(s_t, z_t)  y_hat_t = R(s_t)  θ_(t+1) = A(θ_t, error, novelty, uncertainty, resource_state)minimize:  security loss + state bytes + update cost + instability
The research objective is to determine whether very small transition systems can replace heavier sequence models for important security tasks.

# 6. State-Space Discovery

- continuous low-dimensional state
- integer/fixed-point state
- binary state
- sparse categorical state
- probabilistic belief state
- finite automaton state
- hybrid discrete/continuous state
- hyperdimensional state
State objective:S* = argmin_S Cost(S)subject to predictive security sufficiency and counterfactual preservation.
A candidate state is rejected if compression hides a distinction that changes a security outcome.

# 7. Primitive Foundry

Initial primitive set Π0:ADD SUB MUL MIN MAXAND OR XOR NOTCOMPARE CLIP SHIFTHASH LOOKUPCOUNT DECAYBIND SUPERPOSERARE FIRST_SEENTEMPORAL_WITHINGRAPH_EDGESTATE_DELTA
The initial alphabet is deliberately small. New primitives are promoted only when recurring subprograms demonstrate reusable utility and measurable resource benefit.

# 8. Primitive Promotion

subgraph g occurs independently in many successful systems        ↓canonicalize(g)        ↓measure unique contribution        ↓ARGUS counterexamples        ↓cross-host/epoch reproduction        ↓promote g → primitive P_new
Primitive growth therefore compresses the search language itself.

# 9. Algorithmic Chemistry

Candidate intelligence is represented as a typed reaction graph. Primitives combine into compounds; useful compounds become reusable motifs; dead compounds become fossils.
event → RARE ─┐                 ├→ BIND → DECAY → STATE_DELTA → evidenceprivilege ───────┘Reaction constraints: type-safe bounded state bounded loops deterministic resource ceiling evidence trace preserved

# 10. Autocatalytic Search — Strictly Bounded

A discovered primitive may improve the offline search controller that later discovers additional primitives. This is allowed only in the research environment and is evaluated like any other candidate.
search_t → primitive P → candidate search_(t+1) → benchmark → accept/reject
No research optimizer can rewrite the production optimizer in place.

# 11. Security Renormalization

Stage 9 searches transformations that progressively replace raw detail with coarser security representations while retaining relevant invariants.
X0 syscall/raw event R0 ↓X1 normalized event R1 ↓X2 process episode R2 ↓X3 causal motif R3 ↓X4 security mechanism R4 ↓X5 campaign-level invariant
Find R_k minimizing representation cost such that:SecurityDecision(X_k) ≈ SecurityDecision(R_k(X_k))and counterfactual distinctions remain preserved.

# 12. Fixed-Point Mechanism Search

If repeated abstraction yields:R^n(X) → X*then test whether X* is:  stable across syntactic variation,  discriminative against benign doppelgängers,  reproducible across hosts/epochs,  cheaper than original representation.
A stable fixed point is treated only as a candidate mechanism, not a physical law.

# 13. Symmetry Discovery

Find transformation group/set G such that:f(g(x)) ≈ f(x),  g ∈ Gcandidate transformations: user/PID renaming path-class substitution equivalent interpreter substitution timestamp translation host-identity permutation benign nuisance reordering
Discovered invariances define which variations the detector should ignore.

# 14. Symmetry-Breaking Detection

B_G(x) = aggregate_g distance(   representation(x),   inverse_g(representation(g(x))) )Large unexpected B_G → candidate structural anomaly.
The method survives only if it adds value beyond simpler rarity and graph-motif baselines.

# 15. Conservation Search

Search for compact quantities Q that remain stable under benign host dynamics but change under security-relevant transitions.
Normal:|Q(s_(t+1)) - Q(s_t)| ≈ smallCandidate transition:|ΔQ| >> calibrated benign envelope
Candidate quantities can be symbolic programs, low-dimensional projections or discrete invariants.

# 16. Noether-Inspired Search Boundary

Noether's theorem is not asserted to apply to Linux telemetry. Stage 9 only tests an analogous search heuristic: discovered invariance → search for a useful stable statistic → test whether its violation predicts security-relevant change. Failure is an expected possible outcome.

# 17. Topological/Relational State Track

Some security mechanisms depend more on relation shape than exact numeric values. Stage 9 benchmarks compact graph motifs and topological summaries against ordinary graph statistics and learned embeddings.
- component/bridge structure
- process-tree branching
- role-transition topology
- persistence of relational features across thresholds
- cycle/loop signatures where semantically meaningful
Topological machinery is discarded if simpler graph features perform equivalently.

# 18. Causal Geometry

Define mechanism distance:d_c(A,B) = minimum cost sequence of valid causal transformations converting mechanism A into BExamples of transformations: add/remove enabling event change causal ordering replace actor role alter privilege transition remove necessary evidence
This creates a security-specific distance unrelated to lexical similarity.

# 19. Geodesic Deviation

Normal mechanism manifold M_Ntrajectory τAnomaly candidate:D(τ, M_N) = min_m∈M_N d_c(τ,m)
This is benchmarked against Isolation Forest, nearest-neighbor embeddings and standard sequence anomaly models.

# 20. Phase Observatory

Stage 9 searches for low-dimensional order parameters that indicate transition between host-security regimes.
Ψ_t = h(compact host state)test: normal regime → Ψ distribution A pre-transition → precursor distribution B compromised regime → distribution C
No phase-transition language is accepted unless change-point baselines and ordinary temporal models are beaten.

# 21. Precursor Discovery

- variance change
- autocorrelation change
- transition-rate change
- entropy change
- causal-graph instability
- privilege-flow instability
- novelty accumulation
These are hypotheses to benchmark, not assumed universal attack precursors.

# 22. Minimum Security Description Length

MSDL(P,E) = L(P) + L(E | P) + λ_runtime RuntimeCost(P) + λ_fp FalsePositiveCost(P) + λ_adv AdversarialFragility(P)
P is a compact security theory/program. The objective penalizes both theory complexity and evidence the theory fails to explain.

# 23. Algorithmic Surprise

Surprise(e | P_normal) ≈ compressed description cost of e under the learned normal theoryHigh surprise + security-relevant structure→ research/detection candidate
Practical compressors/probabilistic codes are used as computable proxies; uncomputable Kolmogorov complexity is not claimed to be measured.

# 24. Predictive Compression

Seek z_t with: low retained past information high predictive information about security-relevant futureOperational objective:prediction utility- β * state bytes- γ * update cycles- δ * nuisance-information leakage
This directly targets the original PocketSec requirement: remember only what helps future security decisions.

# 25. CHRONOS — Memory-Law Discovery

M_(t+1) = F(M_t, e_t, uncertainty_t, resource_t)Search families: exact bounded ring exponential decay sketches sparse episodes prototypes hierarchical timescales state-machine memory hybrid memory
The memory architecture is selected by security utility per retained byte, not by convention.

# 26. Learned Forgetting

RetentionValue(m) = ExpectedFutureSecurityUtility(m) -------------------------------- bytes(m) × expected_retention_time × access_costdelete/abstract low-value memory only after counterfactual deletion tests.
Forgetting becomes an optimization target rather than an implementation accident.

# 27. Counterfactual Memory Deletion

World A: memory MWorld B: M \ {m}Replay adversarial + benign futures.If security difference is negligible within confidence bounds:  m becomes deletion/abstraction candidate.
Deletion remains reversible during canary evaluation.

# 28. Multiscale Temporal Memory

Scale
Representation
milliseconds–seconds
small exact event/ring state
minutes
motif/state counters
hours
episode summaries and sketches
days
baseline deltas and fossils
long-term
validated mechanisms, not raw history
Cross-scale links are stored only when they improve future detection.

# 29. Learning-Law Discovery

θ_(t+1) =F(θ_t,  prediction_error,  novelty,  confidence,  drift,  counterexamples,  resource_state)Candidate outcomes: parameter update prototype insert/merge state split/merge rule refinement no learning
Gradient descent is one candidate adaptation law, not an architectural assumption.

# 30. Objective-Law Adaptation

Hard safety constraints remain fixed, but trade-off weights can be host/context-specific.
J_host = α(host)*FN+ β(host)*FP+ γ(host)*latency+ δ(host)*RAM+ ε(host)*analyst_costConstraint:no learned weight may override constitutional safety/resource bounds.
This separates adaptable utility from immutable constraints.

# 31. DAEDALUS — Computational System Synthesis

DAEDALUS composes state, primitives, memory, learning and readout laws into executable candidate systems.
ComputationalGenome → type/resource validation → Mechanism IR → specialization → compile → unit/metamorphic tests → ARGUS → hardware benchmark

# 32. GENESIS — Variation Operators

Operator
Effect
replace
swap primitive/law/representation
merge
combine equivalent states/components
split
specialize overloaded state/component
factorize
decompose expensive interaction
sparsify
activate only required pathways
specialize
partial-evaluate for host niche
remove
subtractive evolution
move
change kernel/userspace/backend placement
compress
reduce state/precision/history
developmental
change phenotype-construction rule

# 33. Subtractive Evolution

Every generation includes deletion mutations. A component that does not provide unique marginal security value is a removal candidate.
UniqueUtility(c) = Utility(A) - Utility(A without c)if UniqueUtility(c) ≈ 0and removal improves resources/attack surface:  prefer descendant without c

# 34. GAIA — Quality-Diversity Ecology

Quality-Diversity research seeks collections of diverse, high-performing solutions rather than a single optimum. Stage 9 uses that principle to maintain multiple computational species for different endpoint niches.
Behavior dimension examples
Reason
RAM envelope
40 MB vs 100 MB vs 500 MB
host role
desktop/web/db/container/IoT
sensor availability
audit/eBPF/network subsets
latency requirement
reflex vs deep analysis
interpretability
symbolic vs learned
threat emphasis
credential/persistence/network/etc.
MAP-Elites is a baseline; Stage 9 must justify any custom ecology against standard QD methods.

# 35. Security MAP-Elites

cell coordinates =(host_niche, RAM_bin, sensor_profile, latency_bin, interpretability_bin)cell stores: best validated computational organism + lineage + ARGUS failures survived + resource measurements

# 36. Speciation

A universal architecture may be wasteful. GENESIS can create specialized species sharing a constitutional core.
- desktop phenotype
- web-server phenotype
- database phenotype
- container-host phenotype
- developer phenotype
- very-low-memory phenotype
Specialization is accepted only when it improves efficiency without unacceptable blind spots.

# 37. Morphogenesis

Architecture genome + host niche + resource envelope                  ↓           developmental rules                  ↓         verified module assembly                  ↓        host-specific phenotype
Morphogenesis selects only pre-validated components/artifacts; it is not arbitrary runtime code generation.

# 38. Developmental Program Search

Stage 9 can optimize the rules that map host niche to phenotype.
D*(niche, budget, sensors) → module configurationoptimize: security utility resource efficiency transition stability simplicity

# 39. Homeostatic Cognition

Maintain: RSS < R_max CPU_window < C_max queue_depth < Q_max disk_rate < D_maxwhile maximizing: expected security utility
Resource management is a closed-loop controller, not a static deployment setting.

# 40. Cognitive Regimes

Regime
Behavior
Ω-survival
critical rules/FSMs only
Ω-reflex
rules + motifs + sketches
Ω-adaptive
tiny models + temporal state
Ω-deep
optional expensive local analysis
Ω-research
offline Stage 8/9 only
Transitions are explicit, hysteretic and benchmarked to avoid oscillation.

# 41. Intelligence Thermostat

MarginalValue(step) = ExpectedΔSecurityUtility(step) ------------------------------ ExpectedComputeCost(step)execute optional cognition only when:MarginalValue > context threshold

# 42. Computational Economics

TotalCost = c_ram*RAM+c_cpu*cycles+c_io*disk_writes+c_net*network_bytes+c_human*analyst_attention+c_attack*added_attack_surface
Candidate systems are compared on security return per multidimensional cost, not parameter count.

# 43. Symbiosis Search

Synergy(A,B) = Utility(A+B) - Utility(A) - Utility(B)positive persistent synergy: preserve cooperative pairnegative marginal contribution: parasitic/redundant candidate
This supports ecosystems of tiny specialists rather than one general model.

# 44. Architecture Parasite Detection

A component consuming resources while contributing no unique detection or resilience is flagged for deletion. This includes fashionable AI components.
If Cost(c) high AND UniqueUtility(c) low → extinction candidate

# 45. Extinction and Fossils

ComputationalFossil { genome_hash niche ancestry mutation_history reason_for_failure counterexample_signature resource_failure security_regression epochs_tested}
Fossils reduce repeated search over previously disproven ideas.

# 46. Convergent Computational Evolution

Independent runs are used to identify primitives and structures that repeatedly emerge without being hardcoded.
Convergence(P) = independent successful runs containing P ----------------------------------------- independent runs where P was reachable
High convergence is evidence for usefulness, not proof of universality.

# 47. Law Promotion Gate

- independent rediscovery
- cross-host reproduction
- cross-epoch reproduction
- unique ablation contribution
- ARGUS robustness
- resource advantage
- simple baseline comparison
- explicit failure domain
Only after these tests may a recurring construct become a PocketSec computational-law candidate.

# 48. Law Half-Life

confidence_t = confidence_0 * exp(-λ * unsupported_time) + new_reproduction_evidence - contradiction_penalty
Promoted laws remain falsifiable and context-scoped.

# 49. Meta-Falsification

ONTOGENESIS must test its own design assumptions.
- sparsity is always cheaper
- causal models always generalize better
- specialization always reduces cost
- symbolic models are always more interpretable/useful
- more telemetry always improves security
- learned state is always better than engineered state
If a design doctrine repeatedly loses to a simpler alternative, it is removed from privileged search bias.

# 50. ARGUS — Adversarial Destruction

Attack surface
Test
data
poisoning, mislabeled episodes, corrupt baselines
input
evasion, mimicry, malformed/high-volume events
state
memory corruption/restart/stale state
model
backdoor/shortcut/parameter corruption
search
fitness hacking, benchmark overfit, hypothesis explosion
resource
RAM/CPU/disk/network starvation
sensors
partial loss/delay/reordering
supply chain
tampered artifact/rule/model
NIST's adversarial-ML taxonomy is used as a threat-model baseline; Stage 9 extends testing to the architecture-search lifecycle itself.

# 51. Fitness Hacking Defense

- hidden evaluation corpora
- rotating challenge sets
- multiple independent metrics
- cross-epoch and cross-host holdouts
- resource measurements from real target hardware
- counterexample generation
- manual audit of top candidates during research
A candidate that learns the benchmark rather than the security task is rejected.

# 52. Hardware-in-the-Loop Reality

candidate → compile → deploy to reference 2 GB Linux target → replay workload → measure:    RSS/PSS    cycles/event    cache misses    wakeups    latency    event loss    disk writes → feed measured values back to search
FLOPs and parameter count are secondary proxies.

# 53. Proof/Contract Plane

ComputationContract { max_rss max_cpu_window max_event_latency max_queue required_sensors failure_behavior evidence_guarantee offline_guarantee forbidden_authority_edges}
Small deterministic artifacts can additionally be subjected to SMT/model-checking. Neural components receive empirical assurance, not fictional formal proofs.

# 54. Proof-Carrying Successor Package

SuccessorPackage { computational_genome parent_lineage mutation_set executable_artifacts contracts measured_resources security_metrics counterexample_suite invariance_suite uncertainty_profile failure_domains rollback_artifact signatures}

# 55. Resource Elasticity

A phenotype must have validated degradation paths.
600 MB → full Ω-adaptive250 MB → reduced specialists100 MB → motifs/FSM/statistics 40 MB → critical reflex setEach transition has: preserved capabilities lost capabilities uncertainty increase rollback path

# 56. Graceful Cognitive Degradation

When resources disappear, PocketSec reports which capabilities were shed instead of silently pretending full coverage.
CoverageVector = [process, auth, persistence, network, file, temporal, semantic]resource transition → updated CoverageVector + confidence penalties

# 57. Self-Repair

Runtime repair is limited to substitution among pre-validated components.
component failure → isolate → locate compatible validated substitute → contract check → activate canary → monitor → retain/rollback
No arbitrary code synthesis occurs on the endpoint.

# 58. Architecture Transplantation

Stage 7 may distribute successful computational discoveries, but recipients treat them as untrusted candidates.
foreign Successor/Primitive → HIVELOCK → niche compatibility → ARGUS/local replay → Stage6 → canary

# 59. Intelligence Archaeology

The fossil and lineage corpus becomes a dataset for discovering recurring structural patterns in successful and failed computation.
- which primitives repeatedly re-evolve?
- which mutations repeatedly cause regressions?
- which niches share the same minimal state?
- which components are consistently deleted?
- which representations remain stable across software epochs?
These analyses can generate new Stage-8 hypotheses.

# 60. Theory of PocketSec Output

A successful Stage 9 research result should be capable of producing statements such as:
For niche N under sensor set S and budget B:  11 persistent state variables  6 primitive operators  3 temporal scales  2 sparse specialists  1 calibrated uncertainty channelare sufficient to preserve target security utility.Removing state q7 causes a reproducible credential-chain recall loss.Adding semantic generation does not improve detection under this niche.
Such claims require experimental evidence and confidence intervals; they are not assumed in advance.

# 61. Endpoint Architecture Target

Linux/eBPF/audit/journal        ↓cheap canonicalizer        ↓discovered sufficient state        ↓sparse computational ecology   ┌────┼─────┐ reflex temporal causal   └────┼─────┘        ↓homeostatic router        ↓evidence + uncertainty        ↓Stage 5 governed responsePROMETHEUS/ORACLE/AION/ONTOGENESIS:OFFLINE by default
This preserves the central goal: expensive intelligence discovery can produce extremely cheap intelligence execution.

# 62. Stage 9 Training/Research Architecture

datasets + Stage8 residuals + Stage7 collective evidence                      ↓                 ONTOGENESIS        ┌─────────────┼─────────────┐      LAPLACE      CHRONOS      Primitive Foundry        └─────────────┼─────────────┘                      ↓                  DAEDALUS                      ↓                   GENESIS                      ↓                     GAIA                      ↓                    ARGUS                      ↓           hardware-in-loop + proof                      ↓           convergence/law analysis                      ↓                MIR / FORGE                      ↓              SuccessorPackage                      ↓                Stage 6 gate

# 63. Tooling Strategy

Need
Research tooling
search controller
Python prototype; Rust for high-volume evaluators
QD baselines
MAP-Elites/RIBS-style implementations
program synthesis
custom typed DSL + enumerative/beam/CEGIS
symbolic regression
benchmark established libraries; do not make runtime dependency
causal tests
causal-learn/DoWhy-class research tooling where assumptions fit
formal checks
Z3/model checker for small artifacts
ML baselines
PyTorch/scikit-learn
edge inference
ONNX Runtime/native Rust/C
profiling
perf, smem, time, Criterion/hyperfine
sandbox
VM/namespaces/cgroups/seccomp
Production remains dependency-minimal.

# 64. RAM Research Budget

Subsystem
Endpoint incremental target
sufficient state
<1–10 MB depending niche
motif/FSM ecology
1–15 MB
sketches/baselines
5–20 MB
tiny learned specialists
0–50 MB only if justified
homeostatic controller
<5 MB
Stage 9 research engines
0 MB endpoint; offline by default
These are targets, not measured results. The experiments must replace them with empirical numbers.

# 65. Evaluation Axes

- PR-AUC and calibrated precision/recall
- false positives per host/day
- detection latency
- unknown-mechanism abstention quality
- cross-host/campaign/time generalization
- adversarial evasion/poison success
- RSS/PSS and peak memory
- cycles/event and wakeups
- disk/network/human-attention cost
- description length/state bytes
- counterfactual semantic preservation
- convergence across independent search runs
- resource-elastic degradation quality

# 66. Baseline Matrix

Baseline
Why required
rules + FSM
small deterministic reference
LightGBM/XGBoost/logistic
tabular lightweight ML
GRU/LSTM
sequence baseline
tiny transformer
modern compact sequence baseline
HDC/VSA
alternative fixed-width representation
hand-designed PocketSec Stage8 phenotype
expert baseline
NAS/HW-NAS
architecture-search baseline
MAP-Elites
quality-diversity baseline
symbolic regression/CEGIS
law/program discovery baseline
no Stage9
prove Stage9 is worth its research complexity

# 67. 120-Experiment Stage 9 Program

S9X-001  state dimension sweep
S9X-002  binary state
S9X-003  integer state
S9X-004  hybrid state
S9X-005  state sufficiency counterfactual
S9X-006  state identifiability
S9X-007  primitive ablation
S9X-008  primitive promotion
S9X-009  primitive collision
S9X-010  compound reuse
S9X-011  algorithmic chemistry typing
S9X-012  autocatalytic search isolation
S9X-013  renormalization level 1
S9X-014  level 2
S9X-015  level 3
S9X-016  semantic conservation
S9X-017  fixed-point convergence
S9X-018  fixed-point benign collision
S9X-019  symmetry user rename
S9X-020  PID symmetry
S9X-021  path-class symmetry
S9X-022  time-translation symmetry
S9X-023  learned symmetry
S9X-024  symmetry-breaking detector
S9X-025  conservation symbolic search
S9X-026  conservation projection search
S9X-027  stable-statistic benign test
S9X-028  attack ΔQ test
S9X-029  Noether-inspired heuristic
S9X-030  simple-statistic baseline
S9X-031  graph motif baseline
S9X-032  topological summary
S9X-033  persistent feature test
S9X-034  topology noise
S9X-035  causal geometry
S9X-036  geodesic anomaly
S9X-037  phase parameter search
S9X-038  change-point baseline
S9X-039  precursor variance
S9X-040  precursor autocorrelation
S9X-041  precursor causal instability
S9X-042  false phase transition
S9X-043  MSDL rule
S9X-044  MSDL FSM
S9X-045  MSDL learned model
S9X-046  compressor surprise
S9X-047  probabilistic surprise
S9X-048  rare benign surprise
S9X-049  predictive compression
S9X-050  nuisance leakage
S9X-051  future-information proxy
S9X-052  memory ring
S9X-053  memory decay
S9X-054  memory sketch
S9X-055  memory prototype
S9X-056  multiscale memory
S9X-057  forgetting value
S9X-058  counterfactual deletion
S9X-059  catastrophic deletion
S9X-060  long-term fossil
S9X-061  gradient adaptation
S9X-062  prototype adaptation
S9X-063  state split
S9X-064  rule refinement
S9X-065  no-learning policy
S9X-066  learning-law search
S9X-067  host objective weights
S9X-068  immutable constraint test
S9X-069  DAEDALUS compile
S9X-070  typed genome validation
S9X-071  GENESIS replace
S9X-072  GENESIS merge
S9X-073  GENESIS split
S9X-074  GENESIS remove
S9X-075  GENESIS specialize
S9X-076  GENESIS backend move
S9X-077  subtractive evolution
S9X-078  component unique utility
S9X-079  MAP-Elites baseline
S9X-080  QD niche coverage
S9X-081  speciation desktop/server
S9X-082  low-memory species
S9X-083  sensor-limited species
S9X-084  morphogenesis
S9X-085  developmental rule search
S9X-086  phenotype transition
S9X-087  homeostatic RAM
S9X-088  homeostatic CPU
S9X-089  queue pressure
S9X-090  cognitive regime hysteresis
S9X-091  marginal compute value
S9X-092  analyst-attention cost
S9X-093  symbiosis search
S9X-094  parasitism removal
S9X-095  extinction
S9X-096  fossil avoidance
S9X-097  independent evolution convergence
S9X-098  law promotion
S9X-099  law decay
S9X-100  meta-falsify sparsity
S9X-101  meta-falsify causality
S9X-102  meta-falsify specialization
S9X-103  poisoning ARGUS
S9X-104  evasion ARGUS
S9X-105  sensor-loss ARGUS
S9X-106  resource-starvation ARGUS
S9X-107  search fitness hacking
S9X-108  benchmark contamination
S9X-109  hardware-in-loop RSS
S9X-110  hardware-in-loop cycles
S9X-111  proxy-vs-real
S9X-112  proof contract
S9X-113  SMT FSM
S9X-114  successor signature
S9X-115  40MB survival mode
S9X-116  100MB reflex mode
S9X-117  250MB adaptive mode
S9X-118  600MB full mode
S9X-119  self-repair substitute
S9X-120  foreign architecture transplant
S9X-121  full Stage1–9 endurance
S9X-122  full ablation vs Stage8
S9X-123  MSSC final tournament
S9X-124  independent reproduction

# 68. Hard Falsification Criteria

- Stage 9 is rejected if hand-designed Stage 8 architectures match its security/resource Pareto frontier at far lower research cost.
- Security renormalization is rejected if abstraction destroys rare but important distinctions or provides no compression advantage.
- Symmetry/conservation/phase concepts are rejected individually if ordinary statistical/graph/change-point baselines match them.
- Primitive discovery is rejected if promoted primitives merely reproduce the hand-specified DSL.
- Learning-law search is rejected if standard adaptation rules dominate.
- QD ecology is rejected if one architecture dominates across practical niches.
- Morphogenesis is rejected if configuration complexity outweighs specialization gains.
- Homeostatic cognition is rejected if regime transitions create unacceptable detection gaps.
- Convergent evolution is not treated as proof of fundamental law without independent causal/ablation evidence.
- Stage 9 must never claim quantum, physical or mathematical laws beyond what experiments establish.

# 69. Acceptance Gate

- At least one Stage-9-discovered computation must beat the strongest Stage-8 hand-designed baseline on a meaningful Pareto dimension without violating another hard requirement.
- Every promoted primitive/law has independent-run reproduction and ablation evidence.
- Every abstraction has semantic-conservation and counterfactual tests.
- Every phenotype has measured 2 GB target-machine resource data.
- Every resource-degradation mode exposes lost coverage and uncertainty.
- Every successor is rollbackable.
- All architecture-search artifacts remain outside direct production authority.
- ARGUS adversarial tests cover the ML/search/system lifecycle.
- Novel physics-inspired mechanisms must beat simpler baselines or be removed.
- The final endpoint remains useful with Stage 7–9 networking/research completely absent.

# 70. Deliverables

- D9.1 MSSC formal research specification.
- D9.2 Computational Genome schema.
- D9.3 LAPLACE state/law discovery engine.
- D9.4 Primitive Foundry + promotion gate.
- D9.5 Algorithmic Chemistry typed IR.
- D9.6 Security Renormalization laboratory.
- D9.7 Symmetry/Conservation research suite.
- D9.8 Causal Geometry/Phase Observatory benchmarks.
- D9.9 MSDL/Predictive Compression suite.
- D9.10 CHRONOS memory/forgetting-law engine.
- D9.11 DAEDALUS system synthesizer.
- D9.12 GENESIS variation/speciation engine.
- D9.13 GAIA QD ecology.
- D9.14 ARGUS architecture adversary.
- D9.15 Homeostatic Runtime controller.
- D9.16 Convergence/Law Observatory.
- D9.17 Proof-Carrying Successor Package.
- D9.18 Hardware-in-loop benchmark harness.
- D9.19 120-experiment falsification program.
- D9.20 Final MSSC thesis report + Stage1–9 reproducibility package.

# 71. Research Grounding Notes

Quality-Diversity optimization is an established evolutionary-computation paradigm that aims to produce collections of diverse high-performing solutions; recent surveys cover MAP-Elites, NSLC, modular QD frameworks and related challenges. Stage 9 therefore treats MAP-Elites/QD as baselines rather than claiming the idea of architectural ecology as new.
NIST AI 100-2e2025 provides a current taxonomy covering evasion, poisoning, privacy and misuse attacks across predictive and generative AI lifecycles. Stage 9 adopts this as part of ARGUS's adversarial baseline and extends the threat model to search artifacts, evaluation corpora, computational genomes and promotion pipelines.
The remaining Stage 9 constructs are research proposals that must be compared against standard statistical, causal, symbolic, neural, program-synthesis and architecture-search methods.

# 72. Novelty Discipline

No claim in this document establishes scientific novelty or patentability. The research must conduct dedicated literature, code and patent searches before making such claims. A new name for a combination of known ideas is not evidence of novelty. Stage 9 succeeds only if its experiments establish a reproducible capability or efficiency advantage.

# 73. Final Stage 9 Architecture

REALITY                       │                 Stages 0–8                       │               unexplained residuals                       │                 ONTOGENESIS                       │        ┌──────────────┼──────────────┐        ▼              ▼              ▼     LAPLACE        CHRONOS      Primitive Foundry state/laws       memory laws      operators        │              │              │        └──────────────┼──────────────┘                       ▼            Security Renormalizer        symmetry / conservation / geometry                       │                       ▼                    DAEDALUS              system synthesis                       │                       ▼                    GENESIS          variation / morphogenesis                       │                       ▼                      GAIA             quality-diversity ecology                       │                       ▼                     ARGUS            adversarial falsification                       │              hardware-in-the-loop                       │             convergence/law gate                       │                      MIR                       │                     FORGE                       │              SuccessorPackage                       │                Stage 6 quarantine                       │             verified phenotype

# 74. Final Research Principle

The objective is not to compress today's AI architecture until it fits. The objective is to experimentally discover the smallest computational structure that still preserves the security distinctions, predictions, uncertainty and evidence that matter.

# 75. Stage 10 Boundary

Stage 10 should only be designed after Stage 9 establishes whether minimum sufficient security computation is empirically discoverable. If it succeeds, the next research problem is not 'more intelligence' but assurance: how independently verifiable, reproducible and trustworthy can an autonomously discovered computational system become across heterogeneous hardware, kernels and long operational lifetimes?
