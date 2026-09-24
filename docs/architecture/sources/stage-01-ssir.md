<!-- Extracted verbatim from the architecture source `PocketSec_Stage_1_SSIR_Security_State_Final.docx`.
     Text-only conversion for tooling; the .docx remains the authoritative artefact. -->

POCKETSEC
Stage 1 — Security Reality Encoding
SSIR + Security State Calculus + Adaptive Observation
Mission: compile Linux reality into the minimum sufficient security language, preserve what is now true about the machine, and spend telemetry/representation cost only where uncertainty and security consequence justify it.
Final Research & Implementation Specification v1.0 • 22 September 2026

# 1. Stage 1 Mission

Stage 1 builds the semantic substrate on which every later PocketSec intelligence model will operate. It must not be tied to one neural architecture. Its job is to transform heterogeneous Linux telemetry into a compact, source-independent representation of security-relevant state transitions while separately maintaining the current security state of the host.
Stage 1 therefore produces four interoperable systems: (1) SSIR, the Security Semantic Intermediate Representation; (2) the Host Security State model; (3) the Behaviour Epoch model for concept drift; and (4) the Adaptive Observation Policy for selectively increasing telemetry resolution.

# 2. Stage 0 Principles Carried Forward

- Compute cost should scale with unresolved novelty, not raw event volume.
- Representation cost should scale with security information, not raw telemetry size.
- Observation cost should scale with decision uncertainty and security potential.
- Stable learned behaviour should eventually be compilable into cheaper executable intelligence.
- The model slot remains replaceable; Stage 1 must not encode assumptions specific to a Transformer, SSM, GRU, NERA, or future model.
- Raw evidence and model representation are separate: compression must never destroy the investigator's evidence trail.

# 3. Core Abstraction: Security State Transition

The fundamental intelligence unit is a transition, not a log line:
τ_t = (A, R, O, ΔS, U, N, P, T, E)
Symbol
Meaning
Role
A
Actor
Entity initiating or carrying the action
R
Relation / operation
Fundamental machine operation
O
Object
Entity affected by the action
ΔS
Security-state delta
What security-relevant truth changed
U
Uncertainty
How uncertain the semantic interpretation is
N
Conditional novelty
How unfamiliar the transition is in relevant contexts
P
Provenance / causal responsibility
Compressed causal ancestry and importance
T
Temporal relation
Time since relevant transitions / bucketed timing
E
Evidence reference
Pointer to lossless/raw evidence
SSIR answers: What changed? The Host Security State answers: What is now true?

# 4. Host Security State

Maintain a compact state S_t updated by each accepted transition:
S_(t+1) = T(S_t, τ_t)
Initial state dimensions to research, not blindly freeze:
Dimension
Examples
Why it matters
Privilege
user → elevated → root
Authority gained
Trust
known/trusted → uncertain → untrusted
Confidence in actor lineage
Credential exposure
none → metadata → readable → extracted
Secret access
Reachability
none → local → LAN → external
Ability to communicate
Persistence
none → user → service → boot/kernel
Survival across sessions/reboots
Execution control
limited → interpreter/spawner → privileged execution
Ability to create further activity
Modification capability
user files → config → system
Integrity impact
Discovery
none → local inventory → credential/system discovery
Knowledge acquisition
Isolation
host/container/namespace boundary state
Boundary crossing
Causal state
responsible ancestry / active attack spine
Why current state exists

# 5. Security State Calculus

Capabilities should be modelled as ordered or partially ordered states where possible. An event becomes an operator over the state rather than merely a categorical event ID.
Privilege:       user < elevated < rootReachability:    none < local < LAN < externalCredential:      none < metadata < readable < extractedPersistence:     none < user < service < boot/kernelExample trajectory:S0 --privilege↑--> S1 --credential exposure↑--> S2 --external reachability↑--> S3
Stage 1 must test whether this abstraction generalises better than string/process-name-centric features, especially under renamed tools and previously unseen binaries.

# 6. Security Potential Φ(S)

Static per-event severity is insufficient because individually legitimate capabilities can become dangerous in combination. Stage 1 will prototype a compositional security-potential function Φ(S).
ΔΦ_t = Φ(S_(t+1)) - Φ(S_t)
Φ is not a final threat score and must not be hand-waved into arbitrary weights. Initial implementations may use explicit monotonic rules and interaction terms, followed by calibration experiments. The key research question is whether state composition (for example root + credential exposure + external reachability) provides more robust signal than summing independent event severities.

# 7. Entity Model: Identity, Semantics, Evidence

Every entity is represented in three distinct layers:
Entity = (ExactIdentity, SemanticState, EvidencePointer)
Layer
Example
Consumed by
Exact identity
stable hash / executable identity / inode-aware key
Runtime correlation
Semantic state
PROCESS | INTERPRETER | USER_WRITABLE | NETWORK_CAPABLE
Intelligence
Evidence
path, PID, UID, hash, command line, source record
Investigation
Unknown entities must be first-class. The system must not require a fixed vocabulary of executable names.

# 8. Initial Entity Universe

UNKNOWN, PROCESS, THREAD, USER, SESSION, FILE, DIRECTORY,SOCKET, ENDPOINT, SERVICE, PACKAGE, DEVICE, CONTAINER,NAMESPACE, CREDENTIAL, KERNEL_OBJECT
These are starting hypotheses. Stage 1 experiments may merge or split them. Semantic properties remain orthogonal so that a FILE can simultaneously be CREDENTIAL, PERSISTENCE, ROOT_OWNED and AUTHORIZATION_DATA.

# 9. Security Relation Algebra

Begin with a deliberately small set of machine operations:
SPAWN, EXECUTE,READ, WRITE, CREATE, DELETE, RENAME,CONNECT, ACCEPT, LISTEN, SEND, RECEIVE,AUTHENTICATE, IMPERSONATE,GRANT, REVOKE,LOAD, MAP, MOUNT,SIGNAL, CONTROL,INSTALL, REMOVE, CHANGE
These are not ATT&CK techniques. They are low-level semantic relations intended to remain stable even as threat taxonomies evolve.

# 10. Progressive Semantic Resolution

Semantic classification must remain probabilistic or explicitly uncertain when evidence is incomplete. Unknown binaries can acquire meaning from observed behaviour rather than names alone.
Initial:  /tmp/x91 -> UNKNOWN_EXECUTABLEObserved:  socket -> connect -> send -> receiveUpdated semantic belief:  NETWORK_CLIENT probability risesLater:  exec children + sensitive readsUpdated:  PROCESS_SPAWNER + CREDENTIAL_READER
This prevents novelty from being mistaken for maliciousness and supports previously unseen software.

# 11. Three Independent Signals: Novelty, Potential, Confidence

Signal
Question
Example
Novelty N
How unfamiliar is this?
New compiler output may be highly novel
Security potential Φ
How security-sensitive is the resulting state?
Root + credential + external channel
Confidence U/C
How certain are the observations and semantics?
Unknown binary classification
These signals must remain separate. High novelty with low security potential should not automatically alert. High potential with low novelty may represent a known attack pattern. High potential plus high uncertainty should trigger deeper observation.

# 12. Conditional Novelty Tensor

Prototype contextual novelty rather than one rarity scalar:
N_t = [N_host, N_user, N_actor, N_parent-child, N_object, N_relation, N_time, N_causal]
The initial runtime should compare exact hot relationships with bounded approximate structures for the long tail. Candidate structures include Count-Min Sketch, Bloom/stable Bloom filters, compact histograms and bounded LRU exact caches.

# 13. Behaviour Epoch Model

Normal behaviour changes after legitimate system changes. PocketSec therefore models normality within a behavioural epoch rather than assuming one permanent baseline.
Epoch key candidates:kernel/build identitypackage-set digestenabled-service digestcontainer/workload identityrelevant policy/config digestuser-role changesMajor legitimate change -> candidate new epochnew epoch -> cautious baseline adaptationold epoch -> retained/compressed according to policy
The epoch mechanism must distinguish 'new because the system legitimately changed' from 'unexpected under the current configuration' and must resist attacker-induced baseline poisoning.

# 14. Provenance and Causal Responsibility

PocketSec needs causality without retaining an unbounded provenance graph. Stage 1 will implement multi-resolution causal memory and test whether the security-carrying causal spine can be retained while irrelevant branches are compressed.
L0: exact recent responsible relationsL1: compact summary of near ancestryL2: fingerprint/sketch of older ancestryL3: long-horizon causal signature + extremaCausal signature:P_t = H(P_parent, actor_semantics, relation, object_semantics, state_delta)
A responsibility score will be approximated by how strongly removal or masking of a transition changes downstream security state/potential. High-responsibility transitions are retained at higher fidelity.

# 15. Adaptive Observation Policy (AOP)

Stage 1 introduces selective telemetry escalation. Low-risk, well-understood regions remain cheaply observed; uncertain high-potential causal regions can temporarily receive higher-resolution collection.
ObservationBudget_t ∝ Uncertainty_t × SecurityPotential_t × CausalRelevance_t
AOP must never silently disable mandatory deterministic security signals. It controls optional/high-resolution observation only. It must have strict CPU, memory, event-rate and duration budgets to prevent telemetry amplification from becoming a denial-of-service vector.

# 16. Semantic Compiler

Linux sources  eBPF / LSM / tracepoints / audit / journald / procfs                    |                    v           Raw Event Assembler                    |                    v           Semantic Compiler       /        |        |       \ Entity      Relation   State    Evidence compiler    compiler   delta     linker       \        |        |       /                    v              SSIR transition                    |          +---------+----------+          |                    |          v                    v Host Security State      Evidence Store
The compiler is the compatibility boundary. Different sensors describing equivalent behaviour should converge toward equivalent SSIR transitions.

# 17. Event Fusion and Source Independence

Compound telemetry records representing one logical operation must be fused before intelligence processing. Stage 1 will define short-lived assembly keys, expiry rules, incomplete-record handling, ordering repair and evidence linkage.
Cross-sensor equivalence tests will replay the same controlled action through different telemetry paths and compare resulting SSIR semantics.

# 18. Representation Levels

Level
Contents
Use
L0
Actor + relation + object
Known low-information transition
L1
L0 + ΔS + novelty + temporal context
Unusual transition
L2
L1 + uncertainty + richer semantics + causal context
Suspicious/ambiguous transition
L3
Evidence linkage + preserved raw/high-fidelity context
Incident/investigation path
Escalation between levels is policy-driven. Representation richness should increase when novelty, security potential, uncertainty or causal responsibility justify the cost.

# 19. Semantic Aggregation

Repetitive benign transitions should be coalesced only under a strict conservation rule:
Aggregate(e) iff LowNovelty(e) AND LowSecurityPotential(e) AND LowUncertainty(e) AND SameSemanticRelation(e)
Aggregated records retain count, interval, extrema and evidence references sufficient for later investigation. Privilege, credential, persistence, boundary-crossing and other high-consequence transitions are never hidden merely because they repeat.

# 20. Security Conservation Principle

Compression may remove representational redundancy, but it must not silently remove information necessary for security decisions.
Desired:I(C(X); Y_security) ≈ I(X; Y_security)Operational test:Performance(compressed) >= Performance(rich) - εunder predefined detection and false-positive constraints.

# 21. Information Guillotine

Stage 1 will start from a deliberately rich research representation and systematically remove information families. The objective is to find the knee of the security-information/byte-cost frontier.
Rich representation  -> remove exact identity  -> remove path semantics  -> remove process semantics  -> remove capability delta  -> remove uncertainty  -> remove novelty dimensions  -> remove timing  -> remove causal memory  -> reduce bit widths  -> reduce representation levelAt every cut:PR-AUC / recall / precision / FP-host-day / latency / bytes-event / CPU-event

# 22. Adversarial Representation Tests

- Rename common tools and executables; semantics should not collapse to identity memorisation.
- Use previously unseen binaries that exhibit known capability patterns.
- Obfuscate command lines while preserving behaviour.
- Shift timing and fragment attack chains.
- Generate high-novelty benign developer/build workloads.
- Attempt baseline/epoch poisoning through gradual malicious behaviour.
- Flood low-value events to test bounded sketches, queues and aggregation.
- Create sensor disagreement/incomplete telemetry and verify uncertainty increases rather than false certainty.

# 23. Initial Binary SSIR Prototype

The first implementation should be concrete enough to benchmark, but explicitly provisional:
struct ssir_transition_v1 {    uint64_t causal_sig;    uint32_t actor_id;    uint32_t object_id;    uint32_t evidence_id;    uint16_t actor_sem;    uint16_t object_sem;    uint16_t state_delta;    uint16_t invariant_delta;    uint8_t relation;    uint8_t novelty_host;    uint8_t novelty_actor;    uint8_t novelty_relation;    uint8_t novelty_object;    uint8_t uncertainty;    uint8_t time_bucket;    uint8_t epoch_id_low;    uint8_t flags;};
The exact packing, widths and fields are not frozen. Stage 1 must challenge 64, 48, 36/40, 32, 24, 16 and smaller byte targets and measure the security loss associated with each.

# 24. Runtime Data-Structure Strategy

Need
Initial candidate
Constraint
Hot entity/relationship state
bounded hash/LRU
Hard memory cap
Long-tail frequency
Count-Min Sketch
Approximate; bounded
Seen membership
Bloom/stable Bloom
False positives measured
Temporal statistics
EWMA / compact histograms
No unbounded series
Evidence metadata
bounded indexed store
Retention/rotation
Causal state
multi-resolution signature
No unbounded graph
Epoch state
small versioned registry
Poisoning-resistant transitions

# 25. Stage 1 Sub-Stages

Sub-stage
Purpose
Exit artifact
1.0 Telemetry Lab
Controlled Linux behaviours and synchronized ground truth
Replay corpus
1.1 Canonical Raw Event
Lossless source-neutral assembly layer
RawEventV1
1.2 Entity Compiler
Identity + semantics + uncertainty
EntitySemanticsV1
1.3 Relation Algebra
Minimal useful operation vocabulary
RelationV1
1.4 Security State Calculus
Capability/state deltas and Φ prototype
SecurityStateV1
1.5 Novelty Engine
Conditional novelty with bounded memory
NoveltyV1
1.6 Epoch Model
Concept-drift/regime handling
EpochV1
1.7 Causal Compression
Responsibility-aware provenance
CausalStateV1
1.8 Adaptive Observation
Selective high-resolution telemetry
AOPv1
1.9 Binary SSIR
L0-L3 serialization and versioning
SSIRv1
1.10 Aggregation
Safe repetitive-event coalescing
AggregationPolicyV1
1.11 Information Guillotine
Ablation + bit/byte minimisation
Pareto report
1.12 Adversarial Tests
Renaming, obfuscation, poisoning, flooding
Robustness report
1.13 Freeze
Select justified fields and contracts
PocketSec Stage 1 v1.0

# 26. Experimental Matrix

S1-E01  Raw telemetry baselineS1-E02  Traditional flat security vectorS1-E03  Actor-Relation-Object SSIRS1-E04  + Security-state deltasS1-E05  + Security potential ΦS1-E06  + Explicit uncertaintyS1-E07  + Conditional novelty tensorS1-E08  + Behaviour epochsS1-E09  + Causal signatureS1-E10  + Responsibility-aware retentionS1-E11  + Adaptive observationS1-E12  + Semantic aggregationS1-E13  Information GuillotineS1-E14  Bit-width/byte frontierS1-E15  Cross-sensor equivalenceS1-E16  Renamed/unseen executable generalisationS1-E17  Timing/obfuscation robustnessS1-E18  Baseline-poisoning resistanceS1-E19  High-rate flood/backpressureS1-E20  Full SSIR v1 ablation

# 27. Metrics

- Security retention: PR-AUC, precision, recall, F1, recall at fixed FP budget, false positives/host/day.
- Representation: bytes/transition, semantic dictionary size, evidence-link overhead, compression ratio.
- Runtime: CPU/event, events/sec, p50/p95/p99 compile latency, idle/peak RSS and PSS.
- Novelty engine: memory per host, collision/approximation error, adaptation latency.
- Causality: attack-spine retention, attribution fidelity, causal-state bytes.
- Adaptive observation: escalation frequency, extra events collected, CPU/RAM amplification, uncertainty reduction.
- Robustness: renamed-tool degradation, unseen-binary degradation, concept-drift recovery, poisoning resistance.
- Source independence: semantic equivalence rate across sensor paths.

# 28. Hard Safety and Reliability Requirements

- All queues and caches are bounded; overload must degrade observability predictably rather than OOM the host.
- Evidence IDs cannot be reused while referenced by retained alerts/incidents.
- Malformed telemetry cannot corrupt state-machine memory.
- Unknown/incomplete semantics increase uncertainty; they do not default to benign or malicious.
- Adaptive observation has rate, duration and memory caps.
- Epoch changes require corroborating system-change evidence and cannot be triggered solely by behavioural novelty.
- No generative model participates in evidence creation.
- If the learned/intelligence component is unavailable, deterministic collection and critical state transitions continue where possible.

# 29. Stage 1 Acceptance Gate

Stage 1 is complete only when:
- At least two telemetry paths can represent equivalent controlled behaviours as semantically equivalent SSIR transitions.
- SSIR and Host Security State are separate, versioned interfaces.
- Unknown entities and incomplete observations are represented with explicit uncertainty.
- Novelty is demonstrably separate from maliciousness/security potential.
- Behaviour epochs handle at least one legitimate regime change without simply resetting all history.
- Causal compression retains the attack-relevant spine in controlled multi-branch scenarios.
- Adaptive observation measurably reduces uncertainty in selected scenarios while remaining inside hard resource caps.
- Repetitive low-risk activity can be aggregated without hiding predefined high-consequence transitions.
- The Information Guillotine produces a measured Pareto frontier rather than an arbitrary field list.
- Renaming/unseen-binary tests demonstrate meaningful behaviour-based generalisation.
- Every field retained in SSIRv1 has experimental justification.
- Normal and peak resource costs are measured on the Stage 0 hardware profiles.
- The final Stage 1 representation can be consumed by multiple model families without changing its semantics.

# 30. Explicit Non-Goals

- Do not build the final NERA intelligence algorithm in Stage 1.
- Do not claim SSIR or the state calculus is novel before formal prior-art review.
- Do not encode ATT&CK as the fundamental event language.
- Do not make executable names or raw command strings mandatory model vocabulary.
- Do not retain an unlimited provenance graph.
- Do not equate rare with malicious.
- Do not perform full ML inference inside kernel/eBPF programs.
- Do not optimize for byte count at the expense of unmeasured security loss.

# 31. Stage 1 Final Deliverables

- D1.1 — SSIR v1 binary specification and versioning rules.
- D1.2 — RawEventV1 and EvidenceEvent interfaces.
- D1.3 — Entity and Relation semantic compiler.
- D1.4 — Host Security State v1 and transition calculus.
- D1.5 — Security Potential Φ prototype and calibration report.
- D1.6 — Conditional Novelty Engine with bounded data structures.
- D1.7 — Behaviour Epoch Model.
- D1.8 — Multi-resolution causal state and responsibility prototype.
- D1.9 — Adaptive Observation Policy prototype.
- D1.10 — Semantic aggregation policy.
- D1.11 — Information Guillotine and representation Pareto report.
- D1.12 — Cross-sensor, adversarial and concept-drift test reports.
- D1.13 — Stage 2 model-facing interface fixtures and replay corpus.

# 32. Stage 2 Handoff

Stage 2 receives a measured, minimized representation of Linux security reality rather than raw logs. It can then research the intelligence mechanism itself: which predictive/state/automaton architecture best learns transitions, allocates novelty-driven compute, and eventually compiles stable understanding into executable behaviour.

# 33. Stage 1 Thesis

Observe only what uncertainty justifies. Represent only what changes security decisions. Maintain what is now true, not merely what happened. Preserve the causal reason it became true.

# 34. Reference Anchors for Implementation Research

Stage 1 implementation research should continue against authoritative Linux kernel BPF/LSM and ring-buffer documentation, Linux Audit semantics, provenance/causal IDS literature, continual-learning/concept-drift work, and information-bottleneck research. These references constrain implementation choices; they do not establish novelty for PocketSec.
- Linux kernel documentation — BPF LSM programs.
- Linux kernel documentation — BPF ring buffer.
- Linux Audit userspace documentation and compound-event semantics.
- DARPA Transparent Computing — provenance/causal dependency research context.
- Recent provenance IDS research on graph reduction, lifelong adaptation and deployment scalability.
- Information Bottleneck principle — minimum sufficient representations.
