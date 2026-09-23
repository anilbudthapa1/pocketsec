# D0.9 — Formal Stage 1 entry criteria

**Stage 1:** SSIR + Security State — Security Ontology and Information-Minimisation Research.

Stage 1's job is to determine the smallest event representation that preserves
useful security information: which process, identity, file, privilege, network,
temporal and relational fields matter, which are redundant, and which should
remain raw evidence outside the learned model.

## Entry criteria

Stage 1 may begin only when **all** of the following hold. They are checked by
`pocketsec-stage0 gate` (exit 0), which is the authoritative test.

1. `G0.1` The research question and the optimisation objective `M*` are frozen
   and versioned in `docs/stage-0-research-spec.md`.
2. `G0.2` The hub/model boundary is documented and names both contract schema
   ids.
3. `G0.3` Both interface skeletons are versioned, and the JSON Schema files
   agree with the Python contracts.
4. `G0.4` Resource profiles and the benchmark metric set are fixed in code.
5. `G0.5` Experiment naming, reproducibility and retention rules are
   operational, and the registry's digest chain verifies.
6. `G0.6` At least one conventional baseline (H0) runs end to end through the
   benchmark harness.
7. `G0.7` H0–H8 are carried as hypotheses, with no unevidenced result claims.
8. `G0.8` A prior-art ledger exists, covers every hypothesis, and is updatable.
9. `G0.9` This document exists and states the ontology extension point.

## The ontology extension point

This is the clause that lets Stage 1 proceed **without changing Stage 0's
measurement rules**.

Stage 1 formalises the security ontology inside the **`attributes`** map of
`SecurityEventV1`. That field is a deliberately opaque `string -> string`
mapping precisely so the ontology can be defined, revised and minimised without
renegotiating the frozen envelope, the model-slot protocol, or any metric.

Concretely, Stage 1 **may**:

- define, document and version the `attributes` key set;
- add new `kind` values and `source` values;
- publish a Stage 1 ontology document plus fixtures and validators;
- introduce its own richer representation *behind* the model slot;
- propose new deterministic-path rules that keep work out of the model.

Stage 1 **may not**, without an ADR and a new schema `$id`:

- change or remove any envelope field (`event_id`, `host_id`, `boot_id`,
  `observed_at_ns`, `monotonic_ns`, `source`, `kind`, `evidence`);
- change the bounded-window semantics (`window_capacity`, `truncated`);
- add any field to `ThreatPredictionV1` that conveys response authority;
- inline raw evidence instead of referencing it by digest;
- alter the metric definitions, the resource profiles, the fair-comparison rules
  or the experiment-id convention.

## Frozen measurement contract

Stage 0's measurement rules bind Stage 1 and every later stage:

- All results go through `pocketsec.stage0.benchmark.harness.run_benchmark`.
- Security **and** resource cost are reported together, always.
- Datasets are checksum-bound; synthetic data is labelled synthetic.
- Unmeasurable figures are `null`, never estimated.
- Experiment ids are immutable; the registry is append-only.

## Stage 1 exit expectation

Stage 1 hands back a minimal, justified event representation with evidence that
discarded fields carry no useful security information — measured on this
harness, against the H0 baseline, on the same hardware.
