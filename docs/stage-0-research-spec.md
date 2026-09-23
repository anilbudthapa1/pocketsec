# PocketSec — Stage 0 Research Specification (D0.1)

**Specification version:** 0.1
**Source of truth:** `PocketSec_Stage_0_Fundamental_Architecture_Discovery.docx`
**Status:** frozen for Stage 0. Changes here require an ADR.

This file is the in-repo, executable-adjacent restatement of the Stage 0
architecture document. Where the two disagree, the DOCX wins and this file is a
bug.

---

## 1. Central research question

> Can learned Linux security intelligence compile itself into a minimal
> executable behavioural machine, so expensive neural computation is required
> primarily for novelty?

PocketSec is a Linux **security-event intelligence hub**, not a compressed
chatbot, not a generic anomaly detector, not a conventional neural classifier.
Its telemetry, evidence, rule, storage and interface layers stay independent of
the replaceable learned model.

## 2. Frozen optimisation objective

```
M* = argmin_M [ L_security(M) + λ·|M| + μ·E[C(M,e)] + ν·S(M) ]
```

| Term | Meaning |
|---|---|
| `L_security(M)` | security decision error |
| `\|M\|` | stored intelligence / model complexity |
| `E[C(M,e)]` | expected computation per event |
| `S(M)` | state / storage cost |

The target is **not** maximum benchmark accuracy at any cost. It is the smallest
executable intelligence that preserves an explicitly required security
capability. Security quality and resource cost are co-equal acceptance
dimensions.

## 3. Novelty-energy principle

Informational surprise for a transition from state `s` under event `e`:

```
I(e | s) = -log2 P(e | s)
B_t      = B0 + α · I(e_t | s_t)
```

| Event regime | Surprise | Expected computation | Compute path |
|---|---|---|---|
| Known / routine | very low | hash / table / state transition | `CHEAP_TRANSITION` |
| Unusual | moderate | statistics + tiny learned scorer | `STATISTICAL` |
| Novel / high-risk | high | relational / deep solver + correlation | `LEARNED_SOLVER` |

`ComputePath` in `ThreatPredictionV1` is exactly these three tiers, which is what
turns "computation scales with novelty" from a claim into a measurement.

## 4. JIT intelligence / knowledge compilation

Stable learned relationships may be emitted as inexpensive executable detectors
or state-machine transitions. **The inverse path is equally required:** a
compiled detector whose false-positive rate, calibration or environmental
validity deteriorates is demoted, its examples returned to the learner, and a
better representation rediscovered. Compilation without decompilation is not in
scope.

## 5. Non-negotiable design principles

- Security-event intelligence, not general language modelling.
- Stable hub; replaceable model slot behind versioned interfaces.
- Do not learn what deterministic code, rules, metadata or external knowledge
  represents exactly.
- Routine behaviour executes through cheap transitions; expensive inference is
  reserved for ambiguity and novelty.
- Stable learned knowledge is eligible for compilation — and compiled knowledge
  must be reversible.
- Every mechanism must beat or complement strong conventional baselines under
  identical data and hardware.
- No novelty claim without literature and, before publication or patenting,
  patent/prior-art review.
- No component survives because it sounds advanced. It survives only if measured
  benefit justifies measured cost.

## 6. Measurement framework

Every experiment reports **both** security quality and resource cost.

- **Security:** precision, recall, F1, PR-AUC, recall at a fixed false-positive
  budget, false positives per host-day, unseen-technique performance, detection
  latency.
- **Model:** parameter count, executable state count, transition count,
  compiled-rule count, model/state bytes, quantisation.
- **Runtime:** idle RSS, PSS, peak RSS, CPU/event, events/second, p50/p95/p99
  latency, startup time.
- **Novelty economics:** share of events resolved without neural inference,
  learned-solver wake rate, mean compute budget per event, recompilation and
  decompilation rate.
- **Reliability:** queue loss, overload behaviour, OOM behaviour, crash recovery,
  bounded-storage behaviour.

Implemented in `pocketsec.stage0.benchmark`. A figure that could not be measured
on this platform is reported as `null` and named in `unavailable` — never
back-filled with a plausible number.

## 7. Fair comparison rules

1. Same dataset version and leakage-resistant split.
2. Same normalised input contract.
3. Same hardware and operating conditions.
4. Comparable training and optimisation budgets.
5. Multiple seeds for stochastic models.
6. Do not tune against the untouched final test set.
7. Synthetic-data performance is labelled synthetic and never presented as
   real-world detection quality.
8. A new method must improve the Pareto frontier, or provide a justified
   capability the cheaper baseline cannot offer.

Rules 1, 3 and 7 are enforced in code: datasets are checksum-bound,
`EnvironmentFingerprint` is captured per run, and `run_benchmark` requires an
explicit `synthetic_data` flag that travels with the result.

## 8. Resource profiles

Research targets to test, **not** promised numbers.

| Profile | Agent RAM target | Model target | Purpose |
|---|---|---|---|
| Nano | ≤ 50 MB | ≤ 5 MB | extreme low-spec / embedded |
| Edge | ≤ 100 MB | ≤ 25 MB | primary PocketSec target |
| Research Max | ≤ 200 MB | flexible | experimental ceiling |

The host constraint is ~2 GB total RAM. Offline research may be heavier;
deployed intelligence may not.

## 9. Competing hypotheses

H0–H8 are carried forward as **hypotheses**, registered in
`pocketsec/stage0/hypotheses.py`. None may be marked `SUPPORTED` or `REFUTED`
without a registered experiment id, and the Stage 0 gate fails if one is.

## 10. Stage 0 deliverables

| ID | Deliverable | Where |
|---|---|---|
| D0.1 | Research specification | this file |
| D0.2 | Versioned interface skeletons | `contracts/`, `pocketsec/stage0/contracts/` |
| D0.3 | Benchmark harness | `pocketsec/stage0/benchmark/` |
| D0.4 | Experiment registry + immutable IDs | `pocketsec/stage0/experiments/` |
| D0.5 | ADR template | `docs/adr/0000-adr-template.md` |
| D0.6 | Reproducibility policy | `docs/reproducibility-policy.md` |
| D0.7 | Prior-art ledger | `docs/prior-art/` |
| D0.8 | Repository structure + CI smoke tests | `pyproject.toml`, `.github/workflows/ci.yml` |
| D0.9 | Stage 1 entry criteria | `docs/stage-1-entry-criteria.md` |

## 11. Explicit non-goals

Do not train the final PocketSec AI. Do not claim NERA is novel or superior. Do
not lock the project to Transformer, SSM, HDC, liquid, quantum-inspired or any
other fashionable architecture. Do not build a chatbot. Do not optimise eBPF
collection before the event ontology exists. Do not hard-code a final threat
taxonomy. Do not publish toy-data numbers as security results.

## 12. Research motto

> Do not make the neural network smaller. Discover how much neural computation
> can be eliminated.
