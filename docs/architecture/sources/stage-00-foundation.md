<!-- Extracted verbatim from the architecture source `PocketSec_Stage_0_Fundamental_Architecture_Discovery.docx`.
     Text-only conversion for tooling; the .docx remains the authoritative artefact. -->

POCKETSEC
Stage 0 — Fundamental Architecture Discovery
Novelty-Energy Relational Automaton (NERA) Research Foundation

Central research question: Can learned Linux security intelligence compile itself into a minimal executable behavioural machine so expensive neural computation is required primarily for novelty?
Research Specification v0.1 • 22 September 2026

# 1. Purpose

Stage 0 establishes the scientific foundation for PocketSec. The project is not intended to be another compressed chatbot, generic anomaly detector, or conventional neural classifier. PocketSec is a Linux security-event intelligence hub whose stable telemetry, evidence, rule, storage and user-interface layers remain independent of the replaceable learned model.
The core Stage 0 hypothesis is that routine host behaviour should become progressively cheaper to evaluate. A learned component is used to discover unfamiliar structure; stable learned behaviour can then be compiled into inexpensive executable transitions or detectors. The system therefore aims for computation proportional to security novelty rather than raw event volume.

# 2. Non-Negotiable Design Principles

- Security-event intelligence, not general language modelling.
- Stable PocketSec hub; replaceable AI/model slot with versioned interfaces.
- Do not learn what can be represented exactly by deterministic code, rules, metadata or external knowledge.
- Routine known behaviour should execute through cheap state transitions; expensive inference is reserved for ambiguity and novelty.
- Learned knowledge should be eligible for compilation into symbolic/executable detectors when sufficiently stable.
- Compiled knowledge must be reversible: degrading detectors can be demoted back to the learner.
- Every proposed mechanism must beat or complement strong conventional baselines under identical data and hardware conditions.
- No novelty claim without literature and, before publication/patenting, patent/prior-art review.
- No architecture component survives because it sounds advanced; it survives only if measured benefit justifies its cost.

# 3. Primary Research Hypothesis

Define the target model M* as:
M* = argmin_M [ L_security(M) + λ·|M| + μ·E[C(M,e)] + ν·S(M) ]
L_security measures security decision error; |M| measures stored intelligence/model complexity; E[C(M,e)] measures expected computation per event; S(M) represents state/storage cost. The objective is not maximum benchmark accuracy at any cost. It is the smallest executable intelligence that preserves an explicitly required security capability.

# 4. Novelty-Energy Principle

For a transition from state s using event e, estimate informational surprise:
I(e | s) = -log2 P(e | s)
Use surprise to allocate computation dynamically:
B_t = B0 + α·I(e_t | s_t)
Event regime
Surprise
Expected computation
Intent
Known/routine
Very low
Hash/table/state transition
Near-constant cheap path
Unusual
Moderate
Statistics + tiny learned scorer
Resolve ambiguity
Novel/high-risk
High
Relational/deep solver + correlation
Spend compute where information is new

# 5. JIT Intelligence / Knowledge Compilation

The defining Stage 0 research direction is a security analogue of just-in-time compilation. Learned inference discovers a stable behavioural relationship; once confidence and validation criteria are met, that relationship can be emitted as an inexpensive executable detector or state-machine transition.
TRAINING / DISCOVERYtelemetry -> learner -> latent behaviour -> validation -> minimisation -> compileRUNTIMEevent -> known transition?        |-- yes -> cheap executable transition        |-- no  -> novelty budget -> learned solver -> candidate knowledge -> validate -> compile
The inverse path is equally important. A compiled detector whose false-positive rate, calibration or environmental validity deteriorates can be demoted, its examples returned to the learner, and an improved representation rediscovered.

# 6. Learned Behaviour Machine

The runtime representation should be investigated as a Security Behaviour Machine rather than only as a neural weight file. The learner may discover states and transitions such as:
STATE 7  sudo -> STATE 18STATE 18  credential_read -> STATE 91STATE 91  unknown_external_network -> RISK_ESCALATION
State minimisation is a core research problem. Two states may be merged when their future security-relevant behaviour is sufficiently equivalent. Approximate equivalence can be defined by similarity of future risk/class distributions under relevant continuation sequences.

# 7. Adaptive Model Growth and Compression

PocketSec should investigate whether model complexity can follow the behavioural complexity of the host instead of shipping a universally fixed large model. New states/atoms are created when existing representations cannot explain behaviour; redundant states are merged; stale knowledge is compressed.
unexplained behaviour -> create state/atomequivalent states     -> mergestable learned pattern -> compilestale pattern          -> compressinvalid compiled rule  -> decompile/relearn

# 8. Hierarchical Behaviour Memory

Investigate a four-tier learned-memory hierarchy:
Tier
Representation
Purpose
HOT
Exact recent transitions / active host state
Fast exact decisions
WARM
Compressed behavioural transitions
Retain useful structure cheaply
COLD
Fingerprints / summaries / prototypes
Recognise old behaviour without full detail
FORGOTTEN
Removed
Bound memory and eliminate obsolete information

# 9. Stable PocketSec Hub Boundary

Stage 0 must freeze the boundary between the long-lived product and experimental intelligence. The hub should not depend on one model family.
Linux telemetry      |      vNormalizer / SecurityEventV1      |      +--> deterministic rules / IOC / host metadata      |      vMODEL SLOT  <--- replaceable      |      vThreatPredictionV1      |      vCorrelation / Risk / Evidence      |      vCLI / local API / alert presentation

# 10. Initial Versioned Model Contract

Stage 0 defines the contract; Stage 1 will research the exact ontology and field set.
SecurityEventSequenceV1 -> ModelSlot -> ThreatPredictionV1ThreatPredictionV1 minimum outputs:- threat/state identifier- calibrated confidence- anomaly/novelty score- evidence relevance references- optional next-event distribution / surprise- model state version- uncertainty / abstention signal

# 11. Competing Hypotheses to Carry Forward

ID
Hypothesis
Reason to test
H0
Conventional compact classifier/GRU
Establish a hard baseline.
H1
State-space / recurrent baseline
Test fixed-state temporal compression.
H2
Learned behavioural automaton
Determine whether security behaviour can compile into minimal transitions.
H3
Novelty-budgeted conditional compute
Test whether compute can scale with information novelty.
H4
Neural-to-symbolic JIT compilation
Test whether stable learned behaviour can become cheap executable detectors.
H5
Adaptive state growth + minimisation
Test host-dependent model complexity.
H6
Hierarchical reversible forgetting
Bound memory while retaining recognisable behaviour.
H7
Relational latent state
Represent process/user/file/network relations rather than raw event sequence.
H8
Combined NERA architecture
Combine only components independently justified by ablation.

# 12. Measurement Framework

Every later experiment must report both security quality and resource cost.
- Security: precision, recall, F1, PR-AUC, recall at fixed false-positive budget, false positives per host/day, unseen-technique performance, detection latency.
- Model: parameter count, executable state count, transition count, compiled-rule count, model/state bytes, quantisation/precision.
- Runtime: idle RSS, PSS where available, peak RSS, CPU/event, events/second, p50/p95/p99 latency, startup time.
- Novelty economics: percentage of events resolved without neural inference, learned-solver wake rate, average compute budget/event, recompilation/decompilation rate.
- Reliability: queue loss, overload behaviour, OOM behaviour, crash recovery and bounded-storage behaviour.

# 13. Fair Comparison Rules

- Same dataset version and leakage-resistant split.
- Same normalized input contract.
- Same hardware and operating conditions.
- Comparable training-token/event and optimization budgets where applicable.
- Report multiple seeds for stochastic models.
- Do not tune against the untouched final test set.
- Synthetic-data performance is labelled synthetic and never presented as real-world detection quality.
- A new method must improve the Pareto frontier or provide a justified capability unavailable to the cheaper baseline.

# 14. Resource Profiles

These are research targets to test, not promised final numbers.
Profile
Normal agent RAM target
Model/compiled intelligence target
Purpose
Nano
≤ 50 MB
≤ 5 MB
Extreme low-spec / embedded research target
Edge
≤ 100 MB
≤ 25 MB
Primary PocketSec target
Research Max
≤ 200 MB
Flexible
Higher-capability experimental ceiling

# 15. Stage 0 Deliverables

- D0.1 — PocketSec Stage 0 Research Specification (this document).
- D0.2 — Versioned SecurityEventSequenceV1 and ThreatPredictionV1 interface skeletons.
- D0.3 — Benchmark harness skeleton capable of recording security and resource metrics.
- D0.4 — Experiment registry and immutable experiment-ID convention.
- D0.5 — Architecture Decision Record (ADR) template.
- D0.6 — Reproducibility policy: seeds, environment, hardware, source commit, dataset version and checksums.
- D0.7 — Literature/prior-art ledger for every claimed architectural novelty.
- D0.8 — Repository structure and CI smoke tests.
- D0.9 — Formal Stage 1 entry criteria.

# 16. Recommended Repository Skeleton

pocketsec/├── docs/│   ├── stage-0-research-spec.md│   ├── architecture/│   ├── adr/│   └── prior-art/├── contracts/│   ├── security_event_v1.*│   └── threat_prediction_v1.*├── benchmarks/├── experiments/├── results/├── datasets/├── baselines/├── models/│   ├── experimental/│   └── compiled/├── runtime/├── training/├── pocketsec/└── tests/

# 17. Stage 0 Acceptance Gate

Stage 0 is complete only when all of the following are true:
- The research question and optimisation objective are frozen and versioned.
- The stable hub/model boundary is documented.
- Input/output interface skeletons are versioned.
- Hardware/resource profiles and benchmark metrics are fixed.
- Experiment naming, reproducibility and result-retention rules are operational.
- At least one conventional baseline path can run through the benchmark harness, even if only on a tiny fixture dataset.
- The novelty-energy, JIT compilation, adaptive-state and reversible-forgetting hypotheses are documented as hypotheses—not claimed results.
- A prior-art ledger exists and can be updated as research proceeds.
- Stage 1 can investigate the security ontology without changing Stage 0's measurement rules.

# 18. Explicit Non-Goals for Stage 0

- Do not train the final PocketSec AI.
- Do not claim NERA is novel or superior.
- Do not lock the project to quantum-inspired, Transformer, SSM, HDC, liquid or any other fashionable architecture.
- Do not build a chatbot or natural-language generation model.
- Do not optimize eBPF collection before the event ontology is defined.
- Do not hard-code a final threat taxonomy before Stage 1 research.
- Do not publish performance numbers from toy data as security results.

# 19. Stage 1 Handoff

After Stage 0 passes its acceptance gate, Stage 1 begins Security Ontology and Information-Minimisation Research. Its job is to determine the smallest event representation that preserves useful security information: which process, identity, file, privilege, network, temporal and relational fields matter; which are redundant; and which should remain raw evidence outside the learned model.

# 20. Research Motto

Do not make the neural network smaller. Discover how much neural computation can be eliminated.
