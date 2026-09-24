<!-- Extracted verbatim from the architecture source `PocketSec_Stage_3_AICT_CRYSTAL_Final.docx`.
     Text-only conversion for tooling; the .docx remains the authoritative artefact. -->

POCKETSEC
Stage 3 — Adaptive Intelligence Crystallization
AICT + CRYSTAL: Reversible Learned-to-Executable Security Intelligence
Mission: make expensive learned reasoning temporary. Discover security-relevant behavioural invariants, determine their validity boundaries, crystallize sufficiently resolved knowledge into minimal executable Knowledge Cells, and melt only the invalidated regions back into learning when reality changes.
Final Research & Implementation Specification v1.0 • 22 September 2026

# 1. Stage 3 Mission

Stage 3 transforms PocketSec from a merely compressed learned detector into a self-compressing security intelligence system. Stage 2 DTL learns host dynamics and identifies stable Behaviour Atoms and predictive regions. Stage 3 asks a different question: when a region of behaviour is sufficiently resolved, can its required security intelligence be represented as a much cheaper executable object without preserving the original neural computation?
The working theory is Adaptive Intelligence Crystallization Theory (AICT). Its experimental mechanism is CRYSTAL. These are PocketSec research hypotheses and internal terminology, not claims that the underlying ideas are globally unprecedented. Existing automata learning, formal synthesis, neural-symbolic verification, state-machine inference and program synthesis are used as prior-art controls and mathematical reference points.

# 2. Central Hypothesis

For a learned transition function F_theta over behavioural region R:F_theta |_R  ~=  G_Rwhere G_R is not necessarily a smaller neural network.G_R may be a table, bounded state machine, arithmetic operator,decision structure, compact program, or another minimal executable object.
The hypothesis is that mature intelligence can undergo a representation phase change. Computation should remain expensive only while behaviour remains unresolved.
Computational complexity  ∝  unresolved security-relevant uncertainty

# 3. Intelligence Phases

Phase
Meaning
Runtime form
Fluid
Poorly resolved, novel, drifting or high-uncertainty behaviour
DTL predictive core
Structured
Repeated dynamics represented by stable atoms/relations
DTL lattice / prototype structure
Crystallized
Validity-bounded behaviour represented by minimal executable intelligence
Knowledge Cell
Stressed
Compiled knowledge accumulating disagreement/boundary pressure
Cell + increased audit
Melted
Cell no longer trusted for part/all of its domain
Returned to DTL learning
Fluid <-> Structured <-> Crystallized                 ^              |                 |--- stress ---|

# 4. Knowledge Is Not the Model

Stage 3 treats the neural model as one temporary encoding of knowledge. The object to preserve is the security-relevant predictive relationship, not the teacher's internal weights.
Knowledge != ModelKnowledge := invariant relationships that preserve requiredsecurity-state, future, uncertainty and evidence behaviour.Model := one representation capable of expressing that knowledge.
This distinction prevents Stage 3 from degenerating into ordinary model pruning or distillation.

# 5. Intelligence Density

Define an experimental efficiency quantity for region R:
ID(R) = SecurityRelevantPredictiveUtility(R) / MinimumMeasuredComputationalCost(R)
Computational cost must be measured, not inferred from parameter count alone. It includes CPU cycles, memory traffic, resident bytes, branch/state cost, cache behaviour and maintenance/audit cost.
The goal is not to maximize ID by deleting necessary reasoning. A representation is eligible only after satisfying its security-equivalence and validity constraints.

# 6. Resolution State: When Does PocketSec Understand?

Resolution(R) = (P, U, V, C, E, D)
Term
Meaning
P
predictive stability
U
calibrated uncertainty
V
validated breadth of the region
C
counterfactual consistency
E
evidence/teacher agreement
D
drift sensitivity / epoch stability
A region is not resolved merely because it has high observation count. It must predict consistently, expose uncertainty, survive perturbations, identify its validity boundary and preserve security decisions.

# 7. Security-Weighted Crystallization Threshold

Crystallize(R) only if Resolution(R) >= Theta_c(SecurityConsequence(R))
The required evidence rises with security consequence. Routine low-impact behaviour may crystallize with moderate support. Privilege, credential, persistence, boundary-crossing and other high-consequence behaviour requires stricter agreement, broader stress testing and potentially bounded exhaustive verification.

# 8. Behavioural Invariant

Stage 3 searches for generalized relationships that survive irrelevant identity changes. An invariant is a candidate relationship among Stage 1 semantics, Stage 2 state and security outcomes.
Observed:nginx -> interpreter -> credential accessapache -> interpreter -> credential accesscustom service -> interpreter -> credential accessCandidate invariant:NETWORK_SERVICE  -> CHILD_INTERPRETER  -> CREDENTIAL_EXPOSURE
An invariant must be falsifiable. It remains a hypothesis until its boundary and security-equivalence requirements are established.

# 9. Invariant Discovery

CRYSTAL searches for invariants across stable DTL regions using several experimental operators:
- Semantic anti-unification: replace differing exact identities with the most specific shared Stage 1 semantic properties.
- Transition motif extraction: find repeated causal/state-delta motifs across Behaviour Atoms.
- Predictive equivalence clustering: group histories that imply equivalent security futures.
- Minimal-feature search: remove conditions while security behaviour remains invariant.
- Cross-epoch validation: reject relationships that exist only because of one accidental configuration unless explicitly epoch-bound.
- Counterfactual substitution: rename/swap semantically equivalent actors and test whether required outcomes remain stable.

# 10. Knowledge Boundary

Every invariant must carry a validity region. A rule without a boundary is unsafe because it silently extrapolates.
B(K) = set of states/events/epochs for which the Knowledge Cell's required security behaviour is validated.
Boundaries can include semantic predicates, security-state ranges, epoch constraints, uncertainty ceilings, causal preconditions and forbidden combinations.

# 11. Boundary Pressure

Boundary Pressure is CRYSTAL's active falsification mechanism. It perturbs a candidate cell toward conditions where its behaviour may diverge from DTL or from ground-truth security requirements.
Start x in validated region  -> alter one semantic dimension  -> alter timing  -> alter causal predecessor  -> alter epoch  -> alter privilege/security state  -> substitute equivalent actor/object  -> inject missing/ambiguous evidence  -> move until security behaviour divergesDivergence point ~= empirical boundary evidence
Search strategies may borrow optimization ideas from active learning, CEGIS and formal synthesis, but Boundary Pressure remains defined by PocketSec's own security-state/evidence objectives.

# 12. Knowledge Cell

K_i = (  invariant I_i,  boundary B_i,  executable operator Omega_i,  resolution/confidence Gamma_i,  evidence lineage E_i,  security constraints Q_i,  epoch validity X_i,  audit policy A_i,  version V_i)
Field
Purpose
I
what relationship has been learned
B
where it is allowed to operate
Omega
minimal executable behaviour
Gamma
current resolution/certificate state
E
traceable evidence/teacher lineage
Q
non-negotiable security constraints
X
valid epochs/configuration regimes
A
teacher sampling and stress policy
V
safe evolution/rollback identity

# 13. Knowledge Cell Operator Forms

CRYSTAL does not force all intelligence into one representation:
Operator
Best use
Constant/state transition
fully deterministic local behaviour
Compact lookup table
small discrete state/event domains
Bitset/bitmap predicate
membership-heavy semantic tests
Decision DAG/tree
small conditional boundaries
Finite-state fragment
short deterministic temporal chains
Weighted transition fragment
bounded probabilistic dynamics
Linear/integer expression
simple calibrated risk/state update
Tiny bytecode program
composed bounded logic
Residual micro-model
only when symbolic/executable compression fails
The operator selector chooses the cheapest candidate satisfying the cell's validation constraints.

# 14. PocketSec Cell Bytecode (PCB) — Proposed

To avoid generating arbitrary native code, Stage 3 should prototype a tiny verified/interpreted instruction set for Knowledge Cells. This gives CRYSTAL one safe target even when source operators differ.
Candidate instructions:LOAD_STATE, LOAD_SEM, LOAD_REL, LOAD_DELTAEQ, NE, LT, GT, IN_SETAND, OR, NOTCOUNT_WINDOW, SEEN_WITHINTRANSITION, UPDATE_PHIRAISE_OBSERVATIONPRESERVE_EVIDENCERETURN_STATE, RETURN_RISK, ABSTAIN
No loops, recursion, dynamic allocation or unrestricted system calls in v1. Programs have statically bounded instruction count and memory access.

# 15. Knowledge Field

Crystallized intelligence is a field of modular Knowledge Cells rather than one monolithic automaton.
Input x  |  vBoundary Index  |  +--> K17  +--> K44  +--> K219          |          v    Cell Resolver          |          v security state / evidence / escalation
Multiple cells may activate. Stage 3 therefore requires deterministic composition and conflict rules.

# 16. Cell Composition Algebra

Initial composition constraints:
- Evidence preservation is monotonic: one cell cannot delete evidence required by another.
- Security consequence is conservative under conflict: a lower-confidence cell cannot silently downgrade a higher-consequence validated result.
- Observation escalation composes by maximum requested level within resource policy.
- State deltas must satisfy Stage 1 state-calculus invariants.
- Contradictory cells trigger abstention/DTL rather than arbitrary winner selection.
- Epoch-incompatible cells cannot compose.
- Composition depth is bounded to prevent rule explosion.

# 17. Knowledge Pressure

CRYSTAL prioritizes where compilation effort is worth spending:
KP(R) = Frequency(R) * MeasuredNeuralCost(R) * Predictability(R) * SecurityUtility(R)
High-frequency but unpredictable regions should not necessarily crystallize. Rare but security-critical regions may receive high validation priority even if their compute-saving value is low. Therefore implementation should maintain separate compute-pressure and security-pressure components rather than blindly multiplying arbitrary scores.

# 18. CRYSTAL Lifecycle

DTL experience   |   vRegion miner   |   vInvariant discovery   |   vBoundary hypothesis   |   vOperator synthesis   |   vBoundary Pressure / stress   |   vSecurity-equivalence evaluation   |   +-- fail --> refine / split / return to DTL   |   vShadow execution   |   vKnowledge Cell promotion   |   vCheap authoritative path   |   +--> sampled DTL audit   | drift/disagreement   vStress -> partial/full melting

# 19. Security Equivalence

Exact equality with DTL is neither always possible nor always desirable: DTL itself is not ground truth. Stage 3 therefore validates both teacher agreement and explicit security invariants.
D_sec(K, T, x) =  d_state_delta+ d_security_potential+ d_future_hazard+ d_uncertainty+ d_evidence_requirement+ d_causal_attributionsubject to hard constraints Q_i.
Distance weights are consequence-dependent and must be calibrated experimentally. Certain violations are hard failures rather than weighted errors, e.g. a cell may never suppress mandatory evidence or convert a validated high-consequence transition into a benign result solely to match a resource target.

# 20. Dual Oracle: Teacher + Security Specification

DTL is a teacher, not an unquestionable oracle. CRYSTAL compares a candidate against two sources:
Oracle A: DTL predictive behaviourOracle B: explicit Stage 1/3 security invariants + labelled ground truth where availableCandidate passes only if:  teacher divergence <= permitted envelope  AND  hard security properties hold
This prevents systematic teacher mistakes from being blindly crystallized.

# 21. Counterexample Memory

Every failed crystallization attempt produces a counterexample object that becomes permanent test material until superseded by a versioned specification.
Counterexample = {  cell_candidate,  SSIR sequence,  host/security state,  epoch,  expected behaviour,  candidate behaviour,  divergence type,  evidence refs}
Counterexamples are used to refine boundaries, split cells, improve DTL training and prevent regression.

# 22. Cell Fission

When one cell contains incompatible futures or boundary failures, split only the heterogeneous region.
K|-- stable domain A --> K_A remains crystallized|-- ambiguous domain B --> DTL / candidate K_B|-- invalid domain C --> rejected
Fission is preferred to adding unlimited branches to a single cell. The objective is locally simple intelligence.

# 23. Cell Fusion

Cells may merge when their invariants, security outputs and validity envelopes are sufficiently equivalent and fusion reduces total runtime/maintenance cost.
Fuse(K_i,K_j) only if SecurityFuture(K_i) ~= SecurityFuture(K_j) AND boundary union remains validated.
Fusion is reversible and must pass the same shadow/stress process as a newly synthesized cell.

# 24. Partial and Full Melting

Stress(K,t) = f(  teacher disagreement,  boundary violations,  epoch drift,  uncertainty rise,  counterexamples,  calibration decay)
If stress exceeds a local threshold, only the invalidated subregion melts. Full melting occurs when the cell's core invariant or validity envelope is no longer trustworthy.
Crystallized -> Stressed -> Partial Melt / Full Melt -> DTL -> new resolution -> possible recrystallization

# 25. Certificate State

Each cell carries a behavioural assurance record. It is not called a formal proof unless it actually has one.
Level
Meaning
A0
candidate only
A1
historical replay validated
A2
counterfactual/adversarial stress validated
A3
shadow-runtime validated
A4
bounded-domain exhaustive checks for specified properties
A5
formally verified property set, if actually proven
Recent neuro-symbolic work shows the practical value of learner/verifier loops and formal verification for generated artifacts, while also illustrating why empirical correctness and formal soundness must not be conflated.

# 26. Shadow Execution

event/state   |---------------------> DTL   |   +---------------------> candidate Knowledge Cell                              |                              v                         equivalence log
Candidates cannot become authoritative immediately. Shadow duration is consequence-dependent and can be based on minimum coverage, boundary coverage and number/diversity of transitions rather than a fixed event count.

# 27. Runtime Teacher Auditing

After promotion, DTL sleeps for most matching traffic but is sampled to detect drift.
p_audit(K) = f(SecurityConsequence, Stress, EpochAge, BoundaryDistance, RecentAgreement)
Stable low-consequence cells can have very low audit rates. Near-boundary or high-consequence cells keep higher teacher sampling.

# 28. Certificate Decay

Confidence is dynamic. Successful audits, broad stable coverage and consistent epochs strengthen a cell; age alone does not automatically make knowledge wrong, but untested change reduces trust.
Gamma_(t+1) =Gamma_t+ successful_audit_credit- disagreement_penalty- epoch_shift_penalty- boundary_violation_penalty- unobserved_change_penalty
Crossing the minimum assurance threshold raises audit frequency or melts the affected region.

# 29. Intelligence Garbage Collection

The Knowledge Field is bounded. Retention is based on measured utility:
Utility(K) = SavedCompute * Usage * Assurance * SecurityUtility / (Memory + AuditCost + MaintenanceCost)
Obsolete epochs, duplicate cells, unused transitions and superseded counterexamples are compacted under retention policy. Incident-linked evidence is preserved independently.

# 30. Safe Runtime Architecture

Stage 1 SSIR   |   vBoundary Index   |   +-- no cell / conflict / uncertain --> Stage 2 DTL   |   vKnowledge Cell VM   |   +--> state update   +--> risk/hazard output   +--> evidence requirements   +--> AOP request   |   vAudit sampler -----> DTL comparison
The Cell VM should run unprivileged where practical, consume only normalized Stage 1 data, use immutable/versioned cell packages and have no arbitrary file/network access.

# 31. Proposed Core Functional IDs

Core ID
Function
CRY-F01
mine_candidate_regions
CRY-F02
discover_invariant
CRY-F03
infer_boundary
CRY-F04
apply_boundary_pressure
CRY-F05
synthesize_operator
CRY-F06
select_operator_form
CRY-F07
evaluate_security_equivalence
CRY-F08
check_hard_security_constraints
CRY-F09
create_counterexample
CRY-F10
fission_cell
CRY-F11
fuse_cells
CRY-F12
shadow_execute
CRY-F13
promote_cell
CRY-F14
audit_cell
CRY-F15
compute_cell_stress
CRY-F16
partial_melt
CRY-F17
full_melt
CRY-F18
recrystallize
CRY-F19
garbage_collect_knowledge
CRY-F20
export_assurance_record

# 32. Prototype Repository Layout

stage3/├── theory/├── region_miner/├── invariants/├── boundaries/├── pressure/├── synthesis/│   ├── tables/│   ├── dags/│   ├── automata/│   ├── arithmetic/│   └── bytecode/├── cell_vm/├── equivalence/├── security_specs/├── counterexamples/├── shadow/├── assurance/├── audit/├── melt/├── fusion/├── fission/├── gc/├── baselines/├── benchmarks/└── tests/

# 33. CRYSTAL Candidate Algorithm

for region R selected by KnowledgePressure:    I = DiscoverInvariant(R)    B = InferBoundary(I, R)    candidates = SynthesizeOperators(I, B)    K = CheapestCandidateMeetingInitialConstraints(candidates)    while budget remains:        x = BoundaryPressure(K, DTL, security_spec)        if violates_hard_security_property(K, x):            K = RefineOrFission(K, x)            continue        if security_divergence(K, DTL, x) > epsilon(x):            K = RefineOrFission(K, x)            continue        if resolution_and_boundary_coverage_sufficient(K):            break    if not qualified(K):        return region_to_DTL(R)    ShadowExecute(K)    if assurance_gate_passes(K):        Promote(K)    else:        RefineOrReject(K)
This pseudocode is a research skeleton. Stage 3 experiments determine the actual invariant learner, boundary search, synthesis strategy and thresholds.

# 34. Search Strategy: Do Not Bet on One Synthesizer

For each candidate region, CRYSTAL should try multiple bounded operator families and choose on measured cost/security equivalence.
- Direct transition/table extraction from DTL atoms.
- Greedy semantic condition elimination.
- Decision-DAG induction.
- Bounded finite/weighted state fragments.
- Integer/linear expression fitting.
- Small enumerative synthesis over PocketSec Cell Bytecode.
- Residual micro-model as a fallback control.
Active automata learning, SMT-based weighted automata learning, and CEGIS are comparison baselines and may supply subroutines, but CRYSTAL's unit of optimization is the validity-bounded Knowledge Cell.

# 35. Research Baselines

Baseline
Comparison question
No Stage 3
What does pure DTL cost?
Static cache
Does crystallization beat simple memoization?
Decision-tree distillation
Does Knowledge Cell theory add value beyond a tree?
DFA/WFA extraction
Does region-bound compilation beat whole-model automata extraction?
Active automata learning
Does Boundary Pressure reduce queries/counterexamples?
CEGIS program synthesis
Does security-specific resolution improve convergence/cost?
Rule mining
Does causal/state semantics improve generalization?
Pruned/quantized DTL
Is compilation actually better than just compressing the model?

# 36. Stage 3 Experimental Program

S3-E01  Pure DTL runtime baselineS3-E02  Static transition cacheS3-E03  Invariant discovery accuracyS3-E04  Semantic anti-unificationS3-E05  Minimal-condition eliminationS3-E06  Knowledge Boundary inferenceS3-E07  Boundary Pressure search strategiesS3-E08  Table operator synthesisS3-E09  Decision DAG synthesisS3-E10  State-fragment synthesisS3-E11  PCB bytecode synthesisS3-E12  Operator selection Pareto frontierS3-E13  Teacher-only equivalenceS3-E14  Dual-oracle security equivalenceS3-E15  Counterexample memoryS3-E16  Cell fissionS3-E17  Cell fusionS3-E18  Shadow promotionS3-E19  Adaptive teacher auditingS3-E20  Certificate decayS3-E21  Partial meltingS3-E22  Full melting/recrystallizationS3-E23  Knowledge Pressure prioritizationS3-E24  Intelligence Density measurementS3-E25  Knowledge Field compositionS3-E26  Conflict/abstention behaviourS3-E27  Intelligence GCS3-E28  Epoch/drift stressS3-E29  Adversarial boundary evasionS3-E30  Full CRYSTAL ablation / falsification

# 37. Metrics

- Compilation coverage: percentage of eligible traffic handled by crystallized cells.
- Full-core wake rate: percentage requiring DTL after promotion.
- Security retention: precision, recall, PR-AUC, FP/host/day and detection latency relative to Stage 2 and ground truth.
- Equivalence: security-weighted divergence, hard-property violation count, teacher disagreement distribution.
- Boundary quality: false-inside rate, false-outside rate, boundary discovery cost and near-boundary error.
- Cell efficiency: bytes/cell, instructions/event, CPU cycles/event, branch count, cache hit rate.
- Assurance: shadow coverage, counterexamples found, audit disagreement rate, time-to-melt after drift.
- Repair locality: fraction of Knowledge Field re-opened after a localized failure.
- Compression: DTL wake reduction and total Stage 2+3 RSS/CPU savings.
- Analyst fidelity: evidence/causal attribution preserved after crystallization.

# 38. Resource Budget

Stage 3 must lower average cost, not merely add another subsystem. Initial research ceilings:
Component
Initial target
Boundary index
< 2–8 MB
Knowledge Cells + metadata
< 5–20 MB bounded
Cell VM/runtime
< 3–8 MB incremental RSS
Audit/certificate state
< 2–5 MB
Counterexample hot store
< 5–15 MB; disk-backed cold archive
Stage 3 normal incremental RSS
prefer < 25 MB
Stage 3 peak incremental RSS
initial ceiling < 60 MB
The decisive metric is total PocketSec cost after DTL wake reduction. A Stage 3 implementation that increases end-to-end CPU/RAM without sufficient security or explainability benefit fails.

# 39. Threat Model for Crystallized Intelligence

- Boundary evasion: attacker crafts inputs just inside a permissive cell boundary.
- Crystallization poisoning: attacker repeats malicious behaviour until it appears stable.
- Audit gaming: malicious behaviour is timed to avoid sampled teacher checks.
- Cell-conflict manipulation: attacker triggers contradictory cells to force abstention/DoS.
- Certificate rollback/tampering: old trusted cell version is restored.
- Bytecode abuse: malformed cell program attempts out-of-bounds/state corruption.
- Knowledge explosion: attacker induces endless cell fission and memory growth.
- Epoch manipulation: attacker forces configuration changes to invalidate/normalize knowledge.
- Counterexample poisoning: false or corrupted evidence drives unsafe refinement.

# 40. Security Controls

- High-consequence suspicious observations are never normalized solely by repetition.
- Promotion requires independent security constraints in addition to teacher agreement.
- Cell packages are signed/hashed and versioned; rollback policy is explicit.
- PCB verifier rejects unbounded control flow, invalid state access and excessive instruction count.
- Boundary indexes and cell counts are hard-capped.
- Audit sampling includes unpredictable scheduling within policy to reduce gaming.
- Near-boundary matches increase DTL/AOP activation.
- Adaptation and promotion run outside the privileged telemetry collector.
- Incident evidence is immutable with respect to cell GC/melting.
- On corruption or ambiguity, abstain and return to DTL/deterministic paths.

# 41. Falsification Criteria

AICT/CRYSTAL must be simplified or rejected if:
- A static cache achieves comparable wake-rate reduction with materially lower complexity.
- Quantized/pruned DTL remains cheaper end-to-end than the Knowledge Field.
- Invariant discovery over-generalizes and boundary search cannot control false negatives.
- Knowledge Cells require so much audit traffic that DTL rarely sleeps.
- Fission/fusion causes unstable behaviour or unbounded cell growth.
- Security-equivalence metrics fail to predict real detection regressions.
- Teacher errors are systematically crystallized despite the dual-oracle design.
- Drift is detected too slowly for security-sensitive cells.
- Cell VM/runtime overhead eliminates expected compute savings.
- CRYSTAL cannot stay within the 2 GB Edge profile and Stage 0 resource philosophy.

# 42. Acceptance Gate

- Stage 2 DTL baseline is frozen and reproducibly benchmarked before Stage 3 comparisons.
- At least four alternative compilation/distillation baselines are implemented.
- Knowledge Cells have versioned schema, bounded operator form and explicit validity boundary.
- Boundary Pressure finds counterexamples missed by naive random replay in at least controlled test classes, or it is removed.
- Dual-oracle validation prevents at least predefined teacher-error crystallization cases.
- Cell promotion, sampled auditing, partial melting and full melting work end-to-end.
- Localized drift can reopen a subregion without discarding unrelated crystallized knowledge.
- Crystallized execution preserves required evidence and causal attribution.
- End-to-end average CPU/event is materially lower than pure DTL at comparable security quality.
- Stage 3 incremental memory remains within the declared Edge budget.
- No surviving component lacks ablation-supported value.
- All claims of formal verification are limited to properties actually proven.
- Prior-art review is completed before any external novelty/patent claim.

# 43. Stage 3 Deliverables

- D3.1 — AICT theory specification and measurable definitions.
- D3.2 — CRYSTAL algorithm prototype.
- D3.3 — Behavioural Invariant discovery engine.
- D3.4 — Knowledge Boundary and Boundary Pressure engine.
- D3.5 — Knowledge Cell schema and Knowledge Field index.
- D3.6 — PocketSec Cell Bytecode + verifier + VM.
- D3.7 — Multi-operator synthesis and selector.
- D3.8 — Dual-oracle security-equivalence engine.
- D3.9 — Counterexample memory and regression corpus.
- D3.10 — Cell fission/fusion implementation.
- D3.11 — Shadow promotion and assurance-state pipeline.
- D3.12 — Adaptive DTL auditing and certificate decay.
- D3.13 — Partial/full melting and recrystallization.
- D3.14 — Intelligence GC and resource controller.
- D3.15 — Baseline comparison, ablation, threat-model and falsification report.
- D3.16 — Frozen Stage 3 interface for Stage 4 integration.

# 44. Stage 4 Handoff

Stage 4 should no longer focus on representation or compilation. It receives Stage 1 semantic reality, Stage 2 predictive intelligence and Stage 3 crystallized intelligence. Its likely problem is decision governance: combining deterministic evidence, DTL predictions and Knowledge Cells into calibrated incident-level threat hypotheses, response recommendations and human-verifiable explanations while preserving strict evidence provenance.

# 45. Prior-Art Research Anchors

Stage 3 is intentionally our own security-specific formulation, but it must be tested against established neighboring work. The following research anchors informed the controls and falsification strategy:
- Weiss, Goldberg & Yahav (2018): extracting automata from recurrent neural networks using queries and counterexamples.
- Isberner & Steffen (2014): counterexample analysis in active automata learning.
- Ferreira, Batz & Silva (2026): SMT-based active learning of weighted automata with minimality/termination results under stated conditions.
- Debauche et al. (2025): counterexample-guided inductive synthesis with a neural learner and SMT verifier for formally checked stability certificates.
- Yang, Neary & Topcu (2025): automaton-based task knowledge refined using verification counterexamples.
- Maehren et al. (USENIX Security 2025): practical large-scale state-machine learning for TLS and automated state-machine analysis.
- Sevenhuijsen et al. (2025): generated safety-critical C evaluated with formal verification and static analysis, illustrating the separation between generation and verified correctness.

# 46. Novelty Boundary

The terms AICT, CRYSTAL, Intelligence Density, Resolution State, Behavioural Invariant, Knowledge Boundary, Boundary Pressure, Knowledge Cell, Knowledge Field, Knowledge Pressure, Crystallization and Melting are used here as PocketSec research constructs. Similarity to prior concepts is expected because the system sits near automata learning, program synthesis, model extraction, continual learning and formal verification. Novelty must be established by systematic literature and patent review plus experimental evidence; terminology alone is not novelty.

# 47. Stage 3 Thesis

Intelligence should consume expensive computation only while the relevant part of reality remains unresolved. When security-relevant behaviour becomes predictively stable, boundary-known and sufficiently validated, PocketSec should crystallize that understanding into the cheapest safe executable form. When reality changes, only the invalid knowledge should melt.
