<!-- Extracted verbatim from the architecture source `PocketSec_Stage_5_SAFE_AEGIS_Final_Final_v2.docx`.
     Text-only conversion for tooling; the .docx remains the authoritative artefact. -->

POCKETSEC
STAGE 5 — FINAL-FINAL
SAFE + AEGIS + SENTINEL
Evidence-Governed, Reversible, Self-Verifying Defensive Intervention Intelligence
Stage 5 is not a playbook runner and not an autonomous shell agent. It is the bounded control layer that decides whether PocketSec should observe, preserve, restrict, contain, defer, escalate, roll back, or do nothing—while explicitly reasoning across Stage 4's competing worlds and proving that every executable action stays inside a machine-enforced safety envelope.
Upgraded Reference Specification v2.0 • 23 September 2026

# 0. Final Stage 5 Layer List

Layer
Name
Core job
5.0
Response Constitution
immutable safety, authority and prohibited-action laws
5.1
Mission & Asset Invariants
define what must remain available/protected
5.2
World-to-Action Interface
consume Stage 4 CBF without collapsing uncertainty
5.3
SAFE Action Field
generate bounded candidate interventions
5.4
Defensive Operator Algebra
typed actions; no arbitrary shell
5.5
SENTINEL Constraint Kernel
hard pre-execution safety verification
5.6
Counterfactual Response Twin
predict effects across plausible worlds
5.7
Intervention Cone
model post-action security/operational futures
5.8
Action Shadow
represent unmodelled/unknown consequences
5.9
Pareto + Regret Planner
choose minimally harmful non-dominated action
5.10
Evidence Preservation Gate
prevent response from erasing justification/evidence
5.11
Authority & Capability Plane
least-privilege, scoped, expiring execution authority
5.12
Transactional Executor
prepare/commit/verify/rollback action protocol
5.13
Lease + Hysteresis Control
time-bounded containment and anti-oscillation
5.14
Post-Action Verification
prove the action had the intended effect
5.15
Intervention Residual
measure model-vs-reality mismatch
5.16
Recovery & Safe-State Planner
restore service/security after containment
5.17
Response Knowledge Cells
crystallize verified recurring responses
5.18
Response Melting
invalidate stale response knowledge under drift
5.19
Effectiveness Memory
learn local outcome statistics without unsafe exploration
5.20
D3FEND Knowledge Adapter
external countermeasure vocabulary, not decision oracle
5.21
Human Decision Contract
present trade-offs, uncertainty, rollback and alternatives
5.22
Adversarial Response Defense
protect the defender from induced self-harm
5.23
Resource Governor
bound CPU/RAM/state/action fan-out
5.24
Formal/Empirical Assurance
separate proven properties from measured properties
5.25
Benchmark & Falsification
kill mechanisms that do not beat simpler baselines

# 1. Stage 5 Mission

Stage 5 converts Stage 4's Causal Belief Field into defensive control without pretending uncertainty has disappeared. Its objective is not maximum intervention; it is minimum sufficient, authorized, reversible and verifiable intervention.
Stage 4:  {possible worlds, support, consequence, uncertainty, identifiability, evidence}Stage 5:  {candidate actions}      -> hard safety constraints      -> counterfactual evaluation      -> non-dominated safe frontier      -> authority gate      -> transactional execution      -> post-action verification      -> rollback / recovery / learning

# 2. Stage 5 Constitutional Invariants

- No model confidence grants execution authority.
- No arbitrary natural-language instruction can become a privileged action.
- No autonomous action may exceed its declared target, duration or capability.
- UNKNOWN is never converted into permission for destructive action.
- An action that cannot be verified cannot be considered successfully completed.
- An action that cannot be rolled back must cross a higher authority boundary.
- Evidence required to justify an intervention must be preserved before the intervention where feasible.
- PocketSec must be able to choose NO ACTION when every candidate is unsafe.
- Stage 5 failure must not stop Stages 1–4 monitoring/detection.
- Offensive/counterattack behavior is outside the PocketSec defensive boundary.

# 3. SAFE Action Field

A_j = ( operator, target_scope, preconditions, world_applicability, expected_security_delta, expected_operational_delta, evidence_effect, reversibility, rollback_plan, authority_class, verification_predicates, lease, uncertainty, action_shadow)
The Action Field remains small and bounded. Candidate generation is constrained by the typed operator catalog and local policy; it is not open-ended planning.

# 4. SENTINEL — Safety Constraint Kernel

The major missing layer in v1 was a tiny independent verifier between reasoning and privilege. SENTINEL is deliberately simpler than AEGIS.
AEGIS proposes ActionObject        |        vSENTINEL verifies:  schema  signature/version  authority  scope  target  preconditions  protected-asset invariants  evidence-preservation requirements  rollback/expiry  resource limits  forbidden combinations        |  PASS / DENY        |        vminimal executor
SENTINEL should be small enough for exhaustive testing and, for selected properties, formal verification. AEGIS cannot bypass it.

# 5. Defensive Operator Algebra

Class
Operator examples
Autonomy
O0 Observe
inspect bounded state, hash metadata, temporary trace
policy eligible
O1 Preserve
snapshot incident metadata, preserve volatile evidence
policy eligible
O2 Reversible restrict
temporary local communication/resource restriction
strict gate
O3 Suspend
pause process/workload with validated resume
strict gate
O4 Local revoke
invalidate a local session/capability where supported
usually approval
O5 Service containment
temporarily constrain a service boundary
human by default
O6 Disruptive
terminate/disable
human approval by default
O7 Irreversible/destructive
delete/wipe/destructive remediation
not autonomous
The catalog contains semantic operators. OS-specific adapters translate them into supported Linux mechanisms.

# 6. No Arbitrary Shell Principle

Forbidden ActionObject:  {"command": "some shell string"}Allowed:  {    operator: SUSPEND_PROCESS,    target_pid: ...,    target_identity_hash: ...,    ttl: ...,    rollback: RESUME_PROCESS,    incident: ...  }
This removes an entire class of prompt/log injection and command-generation failures.

# 7. Response Identifiability

ActionIdentifiable(A) iff:for every material Stage-4 world W where A causes unacceptable harm,W has been sufficiently ruled outOR explicit policy accepts that residual risk.
This makes epistemic uncertainty an execution constraint rather than a warning label.

# 8. Counterfactual Response Twin

The twin is intentionally narrow. It models only state relevant to a proposed intervention.
State family
Examples
process
identity, ancestry, owner, lifecycle
service
unit/dependency/restart semantics
session
user/session ownership and continuity
communication
local/outbound edges relevant to incident
security
Stage 4 worlds and security-state deltas
evidence
which observations would be lost by action
recovery
what state is needed to undo action
Unknown dependencies increase Action Shadow and may make autonomous execution ineligible.

# 9. Intervention Cone

Cone(A,W): current state   | apply A   +--> intended security effect   +--> attacker adaptation   +--> service degradation   +--> evidence loss   +--> persistence-triggered restart   +--> rollback path   +--> unknown branch (Action Shadow)
Cone depth and branching are hard bounded.

# 10. Action Shadow

AS(A) = unmodelled dependencies + uncertain side effects + unobservable post-action effects
High Action Shadow pushes the action toward observe/defer/human approval even when predicted security benefit is large.

# 11. Minimum Effective Intervention

minimize:  scope(A)+ irreversibility(A)+ collateral(A)+ evidence_loss(A)+ ActionShadow(A)+ operational_cost(A)subject to:  required_security_risk_reduction  hard safety invariants  authority  verification  rollback/expiry policy

# 12. Pareto Frontier Before Scalar Utility

AEGIS first removes dominated actions rather than hiding trade-offs inside arbitrary weights.
Dimension
Goal
security benefit
maximize
worst-world security benefit
maximize
collateral
minimize
scope
minimize
irreversibility
minimize
evidence loss
minimize
action shadow
minimize
downtime
minimize
verification latency
minimize
Policy chooses among the surviving frontier. Alternative minimax-regret and distributionally robust selectors are benchmarked.

# 13. Evidence Preservation Gate

PRE-ACTION BUNDLE:  incident ID  evidence references  volatile evidence required by policy  pre-action process/service/session state  action rationale  action/policy/model versions  rollback state  integrity digest
The gate blocks actions that would destroy uniquely necessary evidence unless an explicit higher-authority exception exists.

# 14. Authority Plane

Authority
Meaning
A0
read-only observation
A1
bounded evidence preservation
A2
local fully reversible intervention
A3
local disruptive intervention
A4
host-wide containment
A5
administrator-only
AX
prohibited autonomous action
Authority classes are encoded into policy and action schemas, not inferred by a language model.

# 15. Capability Tokens

CapabilityToken { action_id incident_id operator target_scope valid_from expiry max_duration rollback_required policy_version nonce signer}
The executor has no standing permission to perform arbitrary actions; it receives only a narrow capability.

# 16. Transactional Response Protocol

PREPARE  validate target identity  re-check preconditions  preserve required evidence  capture rollback stateCOMMIT  apply one typed operatorVERIFY  test postconditionsif failure / harmful residual:  ROLLBACKFINALIZE  write immutable ResponseRecord
This addresses TOCTOU between planning and execution.

# 17. Target Identity Binding

PID alone is unsafe because processes can exit and PIDs can be reused. Action targets require stronger identity binding.
ProcessTarget = { pid, start_time, executable identity/hash where available, uid, namespace/cgroup identity where relevant}
The executor revalidates identity immediately before action.

# 18. Lease-Based Intervention

Lease { TTL renewal_predicate rollback_predicate maximum_lifetime owner_incident}
Temporary restrictions expire by design unless evidence justifies renewal. This reduces forgotten containment state.

# 19. Hysteresis and Anti-Oscillation

enter_threshold > exit_thresholdminimum_dwell_timecooldownmax_action_cyclesescalate_if_repeated_rollback
The system must not thrash a process/service because belief fluctuates around a threshold.

# 20. Post-Action Verification

Command success is not security success.
Verify:  intended state changed?  malicious trajectory reduced?  service health acceptable?  evidence visibility retained?  attacker shifted path?  rollback still possible?

# 21. Intervention Residual

IR(A) =distance( predicted post-action state, observed post-action state)
Residual decomposition identifies enforcement failure, hidden dependency, attacker adaptation or model error. It is fed backward to Stage 4 CBF, Stage 3 CRYSTAL and local effectiveness memory.

# 22. Recovery Is Part of Response

Containment without recovery is incomplete. Stage 5 adds a Safe-State Planner.
unsafe/contained state      |      vminimum safe operational state      |verify dependencies      |restore one bounded capability      |observe      |continue / rollback / escalate
Recovery proceeds incrementally rather than restoring everything at once.

# 23. Safe-State Manifold — Research Construct

Instead of one binary healthy/compromised state, Stage 5 models a set of acceptable operating states satisfying mission and security invariants.
M_safe = { x :  critical invariants hold  known malicious trajectory blocked/reduced  recovery path exists  observation remains sufficient}
The response objective is to move the host toward this manifold with minimum intervention.

# 24. Protected Mission Invariants

- critical services that must not be autonomously interrupted
- minimum administrative recovery access
- evidence/retention requirements
- network or namespace boundaries that may not be crossed
- maximum autonomous downtime
- maximum containment duration
- forbidden kernel/boot modifications
- host-local defensive scope

# 25. Adversary Adaptation Model

An attacker may react to containment. The Intervention Cone includes bounded adaptation branches such as process replacement, alternate destination, persistence restart or session migration. PocketSec does not attempt unrestricted game-theoretic search; only observed/learned security-relevant adaptations are represented.

# 26. Defensive Regret

Regret(A,W) =Loss(A,W) - Loss(best admissible action in hindsight,W)
Minimax-regret is particularly useful when Stage 4 cannot distinguish a benign administrative world from a compromised one.

# 27. Local Effectiveness Memory

EffectStats(context, operator) { n verified_security_effect no_effect collateral rollback_success time_to_effect residual_distribution epoch}
The system learns what actually works on this host rather than treating an external defensive ontology as an effectiveness oracle.

# 28. D3FEND Adapter

MITRE D3FEND is integrated as a versioned external knowledge graph adapter. It standardizes countermeasure vocabulary and links defensive techniques to offensive concepts, but MITRE explicitly states that D3FEND does not prescribe, prioritize or characterize countermeasure effectiveness. Therefore D3FEND can propose vocabulary/candidate relationships; SAFE/AEGIS must determine local feasibility and measured effect.

# 29. Response Knowledge Cells

Repeated:  incident invariant  + action  + verified effect  + stable rollback  + stable constraints        ↓Response Knowledge Cell
A response cell is stricter than a detection cell. It carries operator, boundary, authority, mission invariants, rollback and postcondition verifier.

# 30. Response Cell Melting

Trigger:  dependency drift  changed service epoch  residual increase  collateral increase  rollback degradation  authority/policy change        ↓partial/full melt
Previously safe responses never become permanent unquestionable automation.

# 31. Safe Learning Rule

PocketSec does not learn high-impact responses by trial-and-error on production systems.
Source
Allowed learning
offline replay
full planning experiments
lab/sandbox
controlled interventions
production observation
effect estimation without disruptive exploration
human-approved action
post-action outcome learning
autonomous low-impact action
only inside validated SAFE envelope
Reinforcement-learning response systems are a research baseline, not the default production architecture.

# 32. Human Decision Contract

PROPOSAL  Temporary reversible restriction on target XEFFECT ACROSS STAGE-4 WORLDS  W1: ...  W2: ...  W3: ...EXPECTED BENEFITCOLLATERALACTION SHADOWEVIDENCE PRESERVEDROLLBACKLEASEWHY HUMAN APPROVAL IS / IS NOT REQUIREDSAFER ALTERNATIVE
The human sees the decision structure, not just an AI recommendation.

# 33. Adversarial Response Defense

- self-denial-of-service induction
- critical-process baiting
- log/prompt action injection
- PID reuse / target substitution
- TOCTOU between plan and execution
- capability-token replay
- rollback sabotage
- dependency poisoning
- action oscillation
- candidate-action explosion
- false Stage-4 certainty designed to trigger containment
Each attack family has a required regression test.

# 34. Resource Governor

hard caps:  candidate actions  worlds evaluated/action  intervention-cone depth  dependency nodes  simulation milliseconds  concurrent leases  rollback journal bytes  autonomous actions/time window
On budget exhaustion, Stage 5 prunes planning or escalates; it does not relax safety constraints.

# 35. Minimal Privileged Executor

The privileged component should contain no ML, no LLM, no hypothesis generation and no network-facing API.
Unprivileged:  AEGIS planner  response twin  D3FEND adapter  rendererPrivilege boundaryPrivileged:  SENTINEL verifier  tiny typed executor  rollback journal  postcondition probe
This separation sharply reduces the trusted computing base.

# 36. Formal Assurance Targets

Property
Target
bytecode/operator boundedness
formal/static proof where practical
authority non-escalation
formal/state-machine verification candidate
scope confinement
formal + adversarial tests
lease expiry
state-machine verification
rollback protocol
model checking + empirical fault injection
no arbitrary command path
schema/static verification
evidence lineage
integrity/property tests
security effectiveness
empirical; never falsely called formally proven
Stage 5 explicitly separates safety properties that can be proven from effectiveness claims that require empirical evidence.

# 37. Full Stage 5 Runtime

Stage 4 Causal Belief Field          |          v     Action Generator          |          v     SAFE Action Field          |    Counterfactual Twin          | Intervention Cones + Shadows          | Pareto / Regret Frontier          |      Policy Decision          |   +------v------+   |  SENTINEL  |   +------|------+          | capability token          | Transactional Executor          |   Post-Action Verify      /        \ success      residual/failure   |             | lease/recover  rollback/escalate   |             |   +------ feedback to Stages 4/3 ------+

# 38. Core Functional IDs

ID
Function
S5-F01
generate_safe_action_field
S5-F02
bind_target_identity
S5-F03
check_response_identifiability
S5-F04
build_counterfactual_twin
S5-F05
build_intervention_cone
S5-F06
estimate_action_shadow
S5-F07
calculate_action_regret
S5-F08
construct_pareto_frontier
S5-F09
check_mission_invariants
S5-F10
preserve_evidence
S5-F11
sentinel_verify
S5-F12
issue_capability_token
S5-F13
prepare_transaction
S5-F14
commit_typed_action
S5-F15
verify_postconditions
S5-F16
calculate_intervention_residual
S5-F17
rollback_transaction
S5-F18
manage_action_lease
S5-F19
plan_safe_recovery
S5-F20
update_effectiveness_memory
S5-F21
crystallize_response_cell
S5-F22
melt_response_cell
S5-F23
map_d3fend_knowledge
S5-F24
export_response_record

# 39. Repository Layout

stage5/├── constitution/├── mission_invariants/├── action_field/├── operators/├── sentinel/├── authority/├── capabilities/├── twin/├── intervention_cones/├── action_shadow/├── pareto/├── regret/├── evidence_gate/├── executor/├── transaction/├── leases/├── rollback/├── verification/├── recovery/├── effectiveness/├── response_cells/├── d3fend/├── assurance/├── benchmarks/└── tests/

# 40. Baselines

Baseline
Purpose
no automated response
safety/control baseline
static playbooks
complexity/value baseline
simple if/then containment
context-awareness baseline
always isolate/kill
collateral baseline
D3FEND lookup only
ontology-vs-decision baseline
single scalar utility
Pareto/regret baseline
model-free safe controller
twin-value baseline
RL response planner
adaptive-policy research baseline
human-only response
operational benefit baseline

# 41. Expanded 50-Experiment Program

S5X-01  response constitution testsS5X-02  typed operator verifierS5X-03  arbitrary-shell impossibility testS5X-04  target identity / PID reuseS5X-05  TOCTOU precondition recheckS5X-06  authority type enforcementS5X-07  capability token scopeS5X-08  token replay resistanceS5X-09  SENTINEL independent denialS5X-10  evidence preservationS5X-11  response identifiabilityS5X-12  counterfactual twin fidelityS5X-13  intervention cone accuracyS5X-14  action-shadow calibrationS5X-15  mission invariant enforcementS5X-16  dependency graph boundsS5X-17  Pareto selectionS5X-18  minimax regretS5X-19  minimum interventionS5X-20  observe-vs-act choiceS5X-21  suspend/resume labS5X-22  temporary local restriction labS5X-23  service containment labS5X-24  benign-admin ambiguityS5X-25  critical-service baitS5X-26  attacker adaptationS5X-27  lease expiryS5X-28  lease renewalS5X-29  hysteresisS5X-30  transactional executionS5X-31  failed enforcement detectionS5X-32  postcondition verificationS5X-33  intervention residualS5X-34  automatic rollbackS5X-35  rollback fault injectionS5X-36  safe-state recoveryS5X-37  staged restorationS5X-38  effectiveness memoryS5X-39  epoch-conditioned effectivenessS5X-40  D3FEND adapterS5X-41  response crystallizationS5X-42  response meltingS5X-43  prompt/log injectionS5X-44  action-field DoSS5X-45  executor compromise containmentS5X-46  planner crash independenceS5X-47  resource benchmarkS5X-48  operational availability benchmarkS5X-49  full ablationS5X-50  falsification against static/simple response

# 42. Metrics

- verified risk reduction per intervention
- false/disruptive intervention rate on benign worlds
- missed containment on malicious worlds
- collateral incidents per 1,000 actions
- rollback success and p95 rollback latency
- lease-expiry correctness
- evidence-preservation violations
- mission-invariant violations: target zero
- authority/scope violations: target zero
- intervention residual distribution
- counterfactual twin prediction error
- Action Shadow calibration
- response regret
- operational downtime attributable to PocketSec
- human approvals avoided safely
- CPU/RAM/planning latency/executor footprint
- response-cell drift and melt latency

# 43. Edge Resource Budget

Component
Target
AEGIS planning state
5–15 MB
counterfactual twin/dependency state
5–20 MB bounded
simulation workspace
10–30 MB on demand
SENTINEL + executor
prefer < 10 MB incremental RSS
rollback/evidence hot state
5–15 MB
normal Stage 5 incremental RSS
prefer < 35–50 MB
peak Stage 5 without optional LM
initial ceiling < 110 MB
Stage 5 must remain small enough that Stages 1–4 continue comfortably within the 2 GB endpoint target.

# 44. Falsification Criteria

- Static playbooks match AEGIS on security outcome and collateral at materially lower complexity.
- The response twin cannot predict enough operational consequence to affect decisions.
- Action Shadow cannot be calibrated sufficiently to gate autonomy.
- Pareto/regret planning does not reduce unnecessary disruption.
- SENTINEL cannot remain small/independent enough to meaningfully reduce trusted computing base.
- Rollback reliability is insufficient for an operator proposed as autonomous.
- Active response causes more operational harm than recommendation-only mode.
- Response Knowledge Cells become stale faster than they save compute/decision effort.
- Local effectiveness memory overfits and degrades safety across epochs.
- Stage 5 violates the Stage 0 resource envelope.

# 45. Final Acceptance Gate

- Stages 0–4 remain unchanged/frozen interfaces for Stage 5 evaluation.
- Only typed operators reach privilege.
- SENTINEL can independently deny every action regardless of planner output.
- No model/LLM/text field can grant authority or construct arbitrary privileged commands.
- Target identity is revalidated immediately before intervention.
- Every autonomous intervention is scoped, expiring, observable and rollback-aware.
- Every autonomous operator meets a predefined rollback reliability threshold.
- Evidence and mission invariants are machine-enforced.
- Multi-world evaluation demonstrably reduces collateral in ambiguous incidents.
- Post-action verification detects ineffective or divergent actions.
- Safe recovery is demonstrated after containment.
- Resource and action fan-out remain bounded under adversarial load.
- At least the safety-critical executor properties targeted for formal verification are proven or explicitly downgraded to empirical claims.
- Advanced mechanisms survive ablation against simpler playbooks/controllers.
- No external novelty claim is made before literature/patent review.

# 46. Final Deliverables

- D5.1 — Response Constitution + mission invariant schema.
- D5.2 — SAFE Action Field engine.
- D5.3 — AEGIS planner.
- D5.4 — SENTINEL independent constraint kernel.
- D5.5 — Typed Defensive Operator Algebra.
- D5.6 — Authority + capability-token plane.
- D5.7 — Counterfactual Response Twin.
- D5.8 — Intervention Cone + Action Shadow engine.
- D5.9 — Pareto/regret selector.
- D5.10 — Evidence Preservation Gate.
- D5.11 — Transactional privileged executor.
- D5.12 — Lease/hysteresis controller.
- D5.13 — Post-action verification + Intervention Residual.
- D5.14 — Safe-State Recovery Planner.
- D5.15 — Local Effectiveness Memory.
- D5.16 — D3FEND adapter.
- D5.17 — Response Knowledge Cells + melting.
- D5.18 — Formal/empirical assurance package.
- D5.19 — 50-experiment benchmark and ablation corpus.
- D5.20 — Final Stage 5 falsification report.

# 47. Stage 6 Handoff

Stage 6 should begin only after Stage 5 proves that safe intervention is useful. Its focus should be long-horizon intelligence consolidation: continual learning across epochs, anti-poisoning, bounded self-improvement, knowledge aging, model/cell lifecycle management and optional privacy-preserving fleet learning—without increasing the endpoint into a heavyweight retraining machine.

# 48. Research Grounding

NIST SP 800-61 Rev. 3, finalized in April 2025, treats incident response as an integrated cybersecurity risk-management activity intended to reduce incident number/impact and improve detection, response and recovery. Stage 5 therefore evaluates response as a verified risk-reduction and recovery loop, not a command-dispatch feature.
MITRE D3FEND defines a semantically rigorous knowledge graph of cyber countermeasure techniques. MITRE explicitly states that D3FEND does not prescribe countermeasures, prioritize them or characterize their effectiveness. This is why PocketSec uses D3FEND as external defensive knowledge while SAFE/AEGIS measures local applicability and outcomes.
Recent automated-response research includes reinforcement-learning strategy optimization and real-time attack-defense graph generation. These are useful baselines, but Stage 5 deliberately avoids unconstrained production exploration and treats safe execution, rollback, evidence conservation and authority as first-class constraints.

# 49. Novelty Boundary

SAFE, AEGIS, SENTINEL, Action Shadow, Intervention Cone, Response Identifiability, Safe-State Manifold, Intervention Residual and the exact composition of typed capability-bound transactional response are PocketSec research constructs. Neighboring ideas exist in safe control, robust planning, policy enforcement, automated incident response, attack-defense graphs, rollback systems and cyber-defense ontologies. Novelty is an empirical/legal research question, not established by terminology.

# 50. Final Stage 5 Thesis

PocketSec must never equate intelligence with permission. Stage 5 exists to convert uncertain security knowledge into the smallest defensive change that is justified across plausible worlds, bounded by machine-enforced authority, reversible where autonomy is allowed, evidence-preserving, operationally survivable, and continuously checked against what actually happened after the intervention.
