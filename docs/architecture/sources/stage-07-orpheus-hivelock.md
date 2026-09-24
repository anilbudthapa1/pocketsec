<!-- Extracted verbatim from the architecture source `PocketSec_Stage_7_ORPHEUS_HIVELOCK_Final_Research_Architecture.docx`.
     Text-only conversion for tooling; the .docx remains the authoritative artefact. -->

POCKETSEC — STAGE 7
ORPHEUS + HIVELOCK
Zero-Trust Collective Security Intelligence for Ultra-Lightweight Linux Agents
Final Advanced Research Architecture v1.0 • September 2026

# 0. Final Stage 7 Thesis

Stage 7 does not build a conventional federated-learning IDS. It builds a zero-trust collective epistemic fabric in which hosts exchange compact, provenance-bearing security knowledge while retaining local sovereignty. Foreign knowledge can suggest, corroborate, challenge, or accelerate learning, but can never directly become trusted cognition or Stage 5 execution authority.
Shared knowledge ≠ shared truthConsensus ≠ correctnessPrivacy ≠ robustnessRemote confidence ≠ local authority

# 1. Research Result — Why Ordinary Federated Learning Is Not Enough

Current federated IDS research confirms three persistent problems: non-IID host data, privacy leakage from model updates, and poisoning/Byzantine/Sybil behavior. Secure aggregation protects individual contributions from direct inspection, but by itself does not establish that those contributions are benign. Recent surveys also identify scalable verifiable aggregation, adaptive defenses, heterogeneity, privacy and energy efficiency as open deployment problems. Stage 7 therefore treats FedAvg-style model aggregation as a baseline, not the primary architecture.

# 2. Stage 7 Layer Map

Layer
Subsystem
Purpose
7.0
Collective Constitution
hard laws for external knowledge
7.1
Peer Identity Plane
cryptographic host/service identity
7.2
Knowledge Capsule Compiler
distill transferable knowledge
7.3
Privacy Distiller
remove host-specific sensitive detail
7.4
Epistemic Distance Engine
measure transfer relevance
7.5
Knowledge Gravity Engine
estimate usefulness without granting trust
7.6
HIVELOCK Ingress
authenticate, rate-limit, quarantine
7.7
Dependence/Sybil Graph
detect correlated identities/evidence
7.8
Byzantine Evidence Engine
robust evidence aggregation
7.9
Antibody Forge
create minimal portable defensive invariants
7.10
Partial-World Reconstructor
join weak distributed fragments
7.11
Collective Novelty Engine
find patterns invisible locally
7.12
Campaign Hypergraph
cross-host temporal/causal campaign structure
7.13
Consensus Falsifier
actively challenge collective beliefs
7.14
Cross-Host Lineage DAG
track knowledge ancestry and revocation
7.15
Revocation Plane
propagate invalidation safely
7.16
Stage-6 Local Gate
all imports re-enter quarantine
7.17
Optional Secure Aggregation
only for tasks where aggregate math is useful
7.18
Privacy Budget Plane
bound disclosure across repeated exchange
7.19
Communication Governor
bounded bandwidth/energy
7.20
Offline/Partition Mode
retain full local operation
7.21
Assurance & Falsification
prove value against simpler FL

# 3. Collective Constitution

- Stage 7 can never directly modify trusted Stage 1–5 cognition.
- Stage 7 can never directly invoke Stage 5 actions.
- Every foreign object is untrusted input even when signed.
- Majority vote is never treated as ground truth.
- One physical/administrative source cannot gain unlimited influence by spawning identities.
- Raw command history, credentials, sensitive filenames and raw host telemetry are not shared by default.
- Every imported object must be locally rejectable, expirable and revocable.
- Loss of the Stage 7 network must not reduce local Stage 1–6 protection.

# 4. Knowledge Capsule — Primary Transfer Unit

KnowledgeCapsule { capsule_id schema_version knowledge_type semantic_invariant compact_feature_signature causal_motif ATT&CK/D3FEND mappings if evidenced epoch_context source_context_sketch validation_summary falsification_summary provenance_commitment independence_group privacy_class expiry parent_capsules signature}
The default exchanged object is not a gradient and not a raw log. It is a compact claim with evidence lineage and explicit uncertainty.

# 5. Capsule Types

Type
Example
Default handling
ANTIBODY
portable malicious-behavior invariant
quarantine + local replay
NOVELTY
previously unseen motif
low trust; corroboration required
CAMPAIGN_FRAGMENT
partial cross-host incident structure
collective reconstruction
NEGATIVE_EVIDENCE
expected observation absent under stated visibility
visibility-aware
DRIFT_NOTICE
software/workload epoch shift
context only
REVOCATION
prior capsule/model/cell invalid
verify ancestry then propagate
MODEL_DELTA
optional bounded adapter/head update
strongest gate

# 6. Privacy Distillation

Before export, host-specific identity is stripped or generalized while preserving security semantics.
raw episode → causal/behavioral invariant → k-anonymized/generalized context where applicable → privacy leakage tests → signed capsule
- Replace exact usernames/paths with semantic classes where possible.
- Use keyed/local pseudonyms only when relation persistence is necessary.
- Quantize timestamps to the minimum useful resolution.
- Never export secrets or raw credential material.
- Measure membership/inference leakage on capsule representations.
- Apply differential privacy only where its noise/utility trade-off is justified; do not use DP as a decorative privacy label.

# 7. Epistemic Distance

D_E(A,B) = w1*role_distance+w2*software_epoch_distance+w3*telemetry_visibility_distance+w4*behavior_distribution_distance+w5*policy_distance+w6*architecture_distance
Distance is used for transfer relevance, not truth. A web server should not strongly redefine a developer workstation's normality simply because many web servers agree.

# 8. Knowledge Gravity — Proposed Transfer Utility

G(K,H) = Validation(K) * Independence(K) * SemanticCompatibility(K,H) * RecencyFit(K,H) --------------------------------------------------------------------------- 1 + EpistemicDistance(K,H) + PoisonSuspicion(K) + PrivacyCost(K)
G determines whether a capsule deserves expensive local validation. It never bypasses Stage 6.

# 9. Evidence Independence Graph

A critical improvement over naive voting is to model dependence between contributions.
Nodes = capsules / peers / provenance rootsEdges = same software image, same upstream detector,        shared administrator, repeated derived source,        near-identical update, common parent capsuleEffective evidence mass is discounted for correlated clusters.
Ten thousand copies of one poisoned source should remain approximately one source of evidence, not ten thousand independent confirmations.

# 10. Sybil Resistance

- Cryptographic identity where administratively feasible.
- Administrative/domain provenance classes.
- Rate/influence caps per provenance root.
- Similarity clustering of behavior/update/capsule fingerprints.
- Temporal birth-pattern and collusion analysis.
- Independence-weighted evidence rather than identity count.
- Local validation remains mandatory even for high-reputation peers.
No Sybil detector is assumed perfect. HIVELOCK therefore makes Sybil resistance one layer in a defense-in-depth stack.

# 11. Byzantine Evidence Aggregation

Stage 7 benchmarks coordinate-wise median, trimmed mean, Krum/Multi-Krum/Bulyan-style families, validation filtering and trust/dependence-aware aggregation where their assumptions apply. It does not declare one robust aggregator universally best: non-IID benign clients can resemble adversaries, while colluding attackers can imitate benign statistics.
RobustCollectiveEvidence = robust_location_or_consensus(   contributions,   weights = independence × relevance × validated_history,   constraints = local evidence + protected semantics )

# 12. Why Secure Aggregation Is Optional, Not the Core

Secure aggregation is valuable when PocketSec genuinely needs an aggregate statistic or model update without revealing individual inputs. The classic Bonawitz protocol demonstrates practical privacy-preserving aggregation and dropout tolerance, but hiding individual updates also complicates per-client malicious-update inspection. Stage 7 therefore uses secure aggregation selectively, not as the universal transport.

# 13. Antibody Forge

Resolved incident   ↓remove host identity   ↓extract minimal causal/behavioral invariant   ↓counterfactual mutation tests   ↓retain only stable discriminative core   ↓Knowledge Antibody
An antibody should be smaller and more transferable than a rule copied from the original host.

# 14. Antibody Matching

match = structural_similarity      × causal_consistency      × context_compatibility      × local_evidence_support      × visibility_adjustment
The receiving host may use the antibody as a Stage 6 candidate detector/cell seed only after local validation.

# 15. Distributed Partial-World Reconstruction

The most ambitious Stage 7 capability is reconstructing a latent campaign from individually weak host fragments.
Host A: auth anomalyHost B: rare interpreter ancestryHost C: destination noveltyHost D: persistence motif          ↓privacy-distilled fragments          ↓temporal + semantic + causal join          ↓candidate Distributed World W*          ↓falsification against coincidence / common benign causes

# 16. Campaign Hypergraph

Vertices: hosts, roles, motifs, destinations, software epochs, antibodiesHyperedges: temporally/causally compatible multi-host relationsWeights: provenance independence semantic compatibility temporal coherence visibility falsification survival
A hypergraph is preferable to a simple graph when one campaign hypothesis depends jointly on several heterogeneous observations.

# 17. Collective Novelty Engine

The engine searches for distributed rarity rather than local rarity alone.
CollectiveNovelty(pattern) = rarity_across_relevant_population × cross-host coherence × causal_surprise × persistence × independent_support / benign_epoch_explanation
Population rarity is conditioned on epistemically similar hosts to avoid calling ordinary role-specific behavior globally anomalous.

# 18. Consensus Falsifier

Every strong collective belief gets an adversarial counter-hypothesis.
Claim: distributed campaign existsGenerate: H0 coincidence H1 shared benign software update H2 common admin automation H3 telemetry artifact H4 poisoned/colluding peers H5 real campaignRequest/seek the cheapest privacy-safe observationsthat maximally distinguish these worlds.
This prevents consensus from hardening merely because it is popular.

# 19. Collective Negative Evidence

Absence can be useful only when visibility is known.
NegativeEvidenceWeight = expected_observability × sensor_health × temporal_coverage × host_relevance
A peer that could not observe a behavior contributes no meaningful negative evidence.

# 20. Cross-Host Temporal Correlation

- Use bounded windows and approximate clocks; never assume perfect synchronization.
- Track event-time uncertainty explicitly.
- Prefer motif ordering and coarse temporal constraints when privacy prevents exact timestamps.
- Use interval overlap/causal ordering rather than millisecond equality.
- Benchmark streaming sketches before heavy graph state.

# 21. HIVELOCK Ingress Pipeline

network object → size/rate gate → schema gate → signature/integrity → replay/expiry check → provenance classification → privacy policy → Sybil/dependence graph → poisoning suspicion → epistemic relevance → Stage6 quarantine → local shadow/conservation gate

# 22. Peer Trust Is Contextual

Trust(peer, task, epoch) ≠ global reputationA peer may be historically reliable for:  Linux web-server persistence motifsbut irrelevant for:  desktop authentication normality.
Trust decays, is task-specific and never removes local validation.

# 23. Cross-Host Knowledge Lineage DAG

Every derivative collective object records all parent capsules and transformations. This enables forensic reconstruction and targeted revocation rather than deleting an entire global model.

# 24. Revocation Propagation

bad capsule K detected   ↓verify revocation authority/evidence   ↓find descendants(K)   ↓mark suspect   ↓local Stage6 re-evaluation   ↓rollback only affected promoted knowledge
Revocation is itself untrusted input until verified; attackers must not be able to erase knowledge by sending forged revocations.

# 25. Knowledge Conflict Resolution

Conflict
Resolution
foreign vs local strong evidence
local evidence dominates; retain foreign as challenged
two trusted peer groups disagree
split by epistemic context/epoch before averaging
majority vs high-quality minority
compare independent evidence and falsification survival
new capsule vs protected semantic invariant
protected invariant wins unless explicitly revalidated through Stage 6
old campaign vs new epoch
contextualize rather than overwrite

# 26. Model Exchange Policy

Full model-weight federation is not the default. Priority order:
Priority
Exchange object
1
knowledge antibody / semantic invariant
2
calibrated population statistic/sketch
3
compact prototype/centroid
4
small classifier head/adapter candidate
5
securely aggregated update for a justified task
6
full model replacement only as an offline research artifact

# 27. Communication-Efficient Structures

- Count-Min Sketch for approximate frequency signals.
- Bloom/Cuckoo filters for compact membership indicators where false-positive semantics are acceptable.
- HyperLogLog for cardinality estimates.
- Top-k heavy-hitter summaries.
- Quantized prototypes/centroids.
- Delta-encoded capsule batches.
- zstd compression.
- Content-addressed deduplication.

# 28. Communication Budget

Mode
Target concept
idle
zero required peer traffic
routine
small signed capsule batches; KB-scale where practical
incident
bounded burst under policy
model/update research
explicit opt-in; MB-scale allowed only off critical path
The endpoint remains useful offline indefinitely; Stage 7 is an intelligence accelerator, not a dependency.

# 29. Privacy Budget Plane

Repeated harmless-looking exports can cumulatively leak information. Stage 7 tracks disclosure over time.
PrivacyLedger { representation_type sensitivity_class recipient_scope release_count DP_epsilon/delta if DP used inference_test_results expiry}

# 30. Optional Differential Privacy

Differential privacy is evaluated per exported statistic/model task. Stronger privacy can reduce rare-attack utility, so Stage 7 measures privacy loss against detection loss rather than blindly maximizing noise.

# 31. Secure Transport & Identity

- Mutual authenticated transport for managed deployments.
- Ed25519-class signatures or platform-approved equivalent for capsule integrity.
- Key rotation and revocation.
- Monotonic/replay-resistant capsule IDs.
- No inbound privileged control channel.
- Network parser runs unprivileged and separate from Stages 1–5.

# 32. ORPHEUS Runtime Architecture

ORPHEUS FABRIC      ┌──────────┬──────────┐      │          │          │   Capsule    Campaign   Novelty   Router      Builder    Engine      │          │          │      └──────┬───┴────┬─────┘             │ HIVELOCK│             └────┬────┘                  │            Stage 6 Quarantine                  │             local cognition

# 33. Endpoint Tool Stack

Function
Preferred direction
agent/runtime
Rust
async networking
Tokio or equivalent benchmarked runtime
transport
QUIC/TLS or mTLS HTTP/2 benchmark; no mandatory cloud broker
signatures
well-audited Rust crypto library / OS crypto policy
serialization
Protobuf/FlatBuffers benchmark
local state
SQLite WAL or LMDB winner from Stage 6
compression
zstd
graph state
custom bounded adjacency/hyperedge store; avoid Neo4j
sketches
small native Rust implementations
ML inference
ONNX Runtime/tract path retained from Stage 6
Kafka, Redis clusters, Elasticsearch and heavyweight graph databases remain outside the endpoint architecture.

# 34. Research/Simulation Tool Stack

Need
Tools
federated baselines
Flower / FedML research harness, not endpoint dependency
ML
PyTorch + scikit-learn
graph experiments
NetworkX offline; custom Rust runtime if useful
privacy experiments
Opacus or equivalent DP research tooling
attack simulation
custom Byzantine/Sybil/poison harness
network emulation
Linux namespaces + tc/netem
property testing
Hypothesis + proptest
performance
Criterion.rs, perf, hyperfine, smem/time -v

# 35. Stage 7 Primary Algorithm — ECHO

ECHO (Evidence-Causal Heterogeneity-aware Orchestration) is the proposed collective inference algorithm.
for incoming capsule k:  verify_integrity(k)  quarantine(k)  d = epistemic_distance(k, local_context)  dep = dependence_mass(k, provenance_graph)  q = poison_suspicion(k)  g = knowledge_gravity(k,d,dep,q)  if g < validation_floor:      retain metadata or discard  else:      local_test = Stage6.validate(k)      if local_test survives:          attach as candidate evidenceperiodically:  build relevance-conditioned evidence clusters  reconstruct candidate distributed worlds  generate benign + adversarial counter-worlds  choose privacy-safe discriminating observations  update collective belief only from independent surviving evidence

# 36. ECHO Is Not Majority Voting

ECHO's evidence mass is bounded by provenance independence and host relevance. A large colluding cluster cannot gain proportional influence merely by increasing identity count.

# 37. Proposed Robust Evidence Mass

M(K) = Σ_cluster c [  min(cap_c,      reliability_c    × relevance_c    × falsification_survival_c    × local_validation_c)]
The formula is a research construct. Caps and reliability must be empirically calibrated.

# 38. Anti-Collusion Challenge

HIVELOCK periodically constructs challenge sets designed to separate independently learned knowledge from coordinated mimicry: semantic-preserving perturbations, hidden holdouts, epoch shifts, and cross-context tests. Peers do not receive privileged ground truth.

# 39. Non-IID Host Handling

- Cluster or condition evidence by role/context before aggregation.
- Prefer personalization/local calibration over one global model.
- Measure epistemic distance explicitly.
- Maintain global invariants only when they survive heterogeneous contexts.
- Treat rare legitimate host roles as first-class, not outliers to be averaged away.
This responds directly to a major weakness documented in federated IDS literature.

# 40. Drift-Aware Collective Learning

Stage 7 inherits Stage 6 epochs. Collective knowledge is indexed by context/epoch and can be dormant rather than overwritten. Recent FL malware work uses lightweight drift detectors such as ADWIN/DDM/EDDM/HDDM; these become baselines, while PocketSec evaluates whether its Stage-6 epoch model plus population evidence performs better.

# 41. Local Sovereignty Gate

foreign knowledge   ↓HIVELOCK   ↓Stage6 Experience Quarantine   ↓Shadow Mind   ↓Knowledge Conservation Gate   ↓local canary   ↓trusted locallyNO bypass path exists.
Even a cryptographically authenticated central administrator package remains a candidate unless local policy explicitly defines a separate managed-update authority.

# 42. Threat Model

- Byzantine peers sending arbitrary capsules/updates.
- Sybil farms.
- Colluding compromised hosts.
- Model poisoning and model replacement.
- Backdoor capsules/adapters.
- Gradient/update inference attacks.
- Membership/property inference.
- Malicious or compromised aggregation service.
- Replay and rollback attacks.
- False revocations.
- Consensus flooding.
- Non-IID benign clients misclassified as malicious.
- Campaign fabrication through coordinated timestamps.
- Suppression attacks where peers omit critical evidence.
- Network partitions and stale collective knowledge.

# 43. Failure-Safe Behavior

- Stage 7 unavailable → local Stage 1–6 unchanged.
- Peer trust store corrupt → disable exchange, preserve local cognition.
- Capsule flood → bounded queue + source caps.
- Collective reconstruction OOM → prune graph, never degrade local detector.
- Secure aggregation failure → abort round; no partial unsafe update.
- Unknown schema/version → reject.
- Revocation ambiguity → quarantine descendants, do not silently delete.

# 44. Resource Budget

Component
Normal incremental target
Peak research ceiling
network/crypto
5–12 MB
20 MB
capsule cache
5–15 MB
30 MB
dependence/trust graph
5–20 MB bounded
35 MB
campaign reconstruction
normally dormant
30–60 MB on demand
sketches/privacy ledger
3–10 MB
15 MB
Stage 7 total incremental
prefer 25–55 MB
<120 MB initial ceiling
These are engineering targets requiring measurement, not published facts.

# 45. Bandwidth/Disk Targets

- Capsule cache bounded by count and bytes.
- Lineage metadata retained longer than bulky payloads.
- Campaign graphs expire unless incident-preserved.
- Deduplicate content-addressed capsules.
- Benchmark 1 KB, 10 KB, 100 KB and 1 MB capsule/update classes.
- Test 10, 100, 1,000 and simulated 10,000 peers without requiring each endpoint to maintain all peers.

# 46. Evaluation Metrics

- collective detection gain over best local Stage 1–6 detector
- time-to-detect distributed campaign
- false collective campaign rate
- poison/backdoor attack success rate
- Sybil influence amplification factor
- benign non-IID rejection rate
- privacy leakage under membership/property inference
- bytes transferred per useful new capability
- CPU/RAM per capsule and per campaign hypothesis
- knowledge transfer precision by epistemic distance
- revocation propagation accuracy/latency
- offline degradation: target none for local detection
- percentage of foreign capsules rejected by local Stage 6

# 47. Baselines

Baseline
Question
no Stage 7
does collective intelligence add real value?
central raw-log SIEM
what privacy/resource capability is sacrificed/gained?
FedAvg
does capsule intelligence beat ordinary global averaging?
FedProx/personalized FL
does heterogeneity handling suffice?
median/trimmed mean
does ECHO improve robust aggregation?
Krum/Multi-Krum/Bulyan families
Byzantine baseline
secure aggregation only
privacy without robustness baseline
majority voting
why independence-aware evidence matters
central threat-intel feed
does bidirectional collective discovery add value?

# 48. 72-Experiment Program

S7X-01  capsule schema/versioning
S7X-02  privacy distillation
S7X-03  semantic invariance after redaction
S7X-04  signature/replay protection
S7X-05  epistemic distance calibration
S7X-06  knowledge gravity calibration
S7X-07  dependence graph
S7X-08  duplicate evidence discount
S7X-09  Sybil identity burst
S7X-10  Sybil slow growth
S7X-11  colluding peer cluster
S7X-12  honest rare-role clients
S7X-13  median baseline
S7X-14  trimmed mean baseline
S7X-15  Krum-family baseline
S7X-16  Bulyan-family baseline
S7X-17  validation-filter baseline
S7X-18  ECHO aggregation
S7X-19  secure aggregation prototype
S7X-20  secure aggregation dropout
S7X-21  non-IID web/desktop/server split
S7X-22  role-conditioned aggregation
S7X-23  cross-epoch transfer
S7X-24  bad cross-role transfer
S7X-25  antibody extraction
S7X-26  antibody counterfactual mutation
S7X-27  antibody local validation
S7X-28  poisoned antibody
S7X-29  partial-world reconstruction 2 hosts
S7X-30  4 hosts
S7X-31  10 hosts
S7X-32  benign coincidence falsification
S7X-33  shared software-update false campaign
S7X-34  campaign hypergraph
S7X-35  temporal uncertainty
S7X-36  negative evidence visibility
S7X-37  collective novelty
S7X-38  rare benign population event
S7X-39  unknown attack campaign
S7X-40  campaign suppression
S7X-41  consensus falsifier
S7X-42  majority-poison scenario
S7X-43  high-quality minority scenario
S7X-44  false revocation
S7X-45  revocation descendant tracing
S7X-46  lineage tamper
S7X-47  malicious aggregator
S7X-48  model replacement
S7X-49  backdoor adapter
S7X-50  membership inference
S7X-51  property inference
S7X-52  privacy budget exhaustion
S7X-53  DP utility/privacy curve
S7X-54  capsule flood
S7X-55  graph OOM pressure
S7X-56  network partition
S7X-57  stale peer recovery
S7X-58  offline operation
S7X-59  1k peer simulation
S7X-60  10k peer simulation
S7X-61  1 KB capsule benchmark
S7X-62  100 KB capsule benchmark
S7X-63  crypto CPU benchmark
S7X-64  compression benchmark
S7X-65  Stage6 import gate
S7X-66  Shadow Mind foreign candidate
S7X-67  Conservation Gate rejection
S7X-68  canary rollback
S7X-69  full Stage1–7 endurance
S7X-70  month-scale peer churn
S7X-71  full ablation
S7X-72  falsification vs FedAvg/playbook feed

# 49. Hard Falsification Criteria

- FedAvg/personalized FL achieves equivalent distributed detection at lower privacy/resource complexity.
- Knowledge Capsules lose too much signal after privacy distillation.
- Epistemic Distance does not predict transfer usefulness.
- Dependence-aware evidence does not materially improve Sybil/collusion resistance.
- Partial-world reconstruction produces unacceptable false campaigns.
- Collective novelty adds mostly population noise.
- Foreign knowledge rarely survives Stage 6 local validation.
- Secure communication/crypto overhead violates the 2 GB edge objective.
- Revocation/lineage complexity exceeds its forensic value.
- Stage 7 increases poisoning risk more than collective detection benefit.

# 50. Acceptance Gate

- No remote object can bypass Stage 6 quarantine.
- No Stage 7 path can directly execute Stage 5 response.
- Local detection remains fully operational with network disabled.
- Sybil influence is bounded by provenance/dependence controls.
- Non-IID legitimate hosts are not treated as malicious merely for statistical difference.
- Distributed campaigns are validated against benign common-cause hypotheses.
- Privacy leakage is measured, not assumed absent because raw data stays local.
- All promoted foreign knowledge has cross-host and local lineage.
- Revocation is targeted and reversible.
- Stage 7 remains inside the Stage 0 resource envelope.
- ECHO/ORPHEUS survives ablation against simpler FL and threat-intel baselines.

# 51. Deliverables

- D7.1 Collective Constitution.
- D7.2 Knowledge Capsule schema/compiler.
- D7.3 Privacy Distiller + Privacy Ledger.
- D7.4 Peer Identity/Integrity plane.
- D7.5 Epistemic Distance engine.
- D7.6 Knowledge Gravity engine.
- D7.7 HIVELOCK ingress/quarantine.
- D7.8 Dependence/Sybil graph.
- D7.9 Byzantine evidence benchmark suite.
- D7.10 ECHO collective inference engine.
- D7.11 Knowledge Antibody Forge.
- D7.12 Partial-World Reconstructor.
- D7.13 Campaign Hypergraph.
- D7.14 Collective Novelty engine.
- D7.15 Consensus Falsifier.
- D7.16 Cross-host lineage/revocation.
- D7.17 Optional secure aggregation module.
- D7.18 Communication/resource governor.
- D7.19 72-experiment adversarial benchmark.
- D7.20 Stage 1–7 endurance/falsification report.

# 52. Research Grounding

Research reviewed for this stage shows that federated IDS remains challenged by non-IID data, privacy leakage from updates, poisoning, Byzantine behavior, Sybil attacks and communication/resource constraints. SAFE-IDS (2025) explicitly targets non-IID and privacy challenges in federated IDS. A 2026 privacy-preserving FL-IDS survey reports that keeping raw data local is insufficient by itself and highlights additional privacy/security trade-offs. A broad 2026 FL security/privacy survey covering 203 papers identifies poisoning, backdoors, Sybil attacks, inference, scalable verifiable aggregation and energy-efficient adaptive defenses as continuing issues. NIST's adversarial-ML taxonomy includes poisoning/privacy attacks across federated learning. Classic secure aggregation demonstrates that private aggregate computation is practical, but it solves privacy of individual inputs rather than malicious-client truthfulness. These findings motivate Stage 7's separation of privacy, provenance, robustness, relevance and local trust.

# 53. Novelty Boundary

Federated learning, Byzantine-robust aggregation, secure aggregation, differential privacy, trust/reputation systems, Sybil defenses, graph correlation, threat-intelligence sharing and collaborative IDS are established areas. ORPHEUS, HIVELOCK, ECHO, Knowledge Gravity, Epistemic Distance as used here, Knowledge Antibodies, independence-bounded evidence mass, and the exact Stage 6 local-sovereignty composition are proposed PocketSec research constructs. Novelty and patentability are not established without a dedicated literature and patent search.

# 54. Stage 7 Final Principle

The collective may know more than one host, but it must never be allowed to become more trusted than the evidence.

# 55. Stage 8 Handoff

If Stage 7 demonstrates safe collective intelligence, Stage 8 should investigate autonomous scientific discovery inside the defensive boundary: generation of new detection hypotheses, synthetic adversarial worlds, automated falsification, mechanism discovery and compact student-model invention—while retaining Stages 5–7 authority, quarantine and conservation constraints.
