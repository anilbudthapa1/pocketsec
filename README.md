# PocketSec

Ultra-lightweight Linux **security-event intelligence** for hosts with ~2 GB of
RAM. Not a chatbot, not a generic anomaly detector.

> **Central research question.** Can learned Linux security intelligence compile
> itself into a minimal executable behavioural machine, so expensive neural
> computation is required primarily for novelty?

> **Motto.** Do not make the neural network smaller. Discover how much neural
> computation can be eliminated.

## Status

- **Stage 0 — Fundamental Architecture Discovery:** implemented, gate passing.
- **Stage 1 — SSIR + Security State:** implemented, gate passing, with the
  D1.13 field freeze explicitly **incomplete** (see below).
- **Stages 2–12:** architecture documents only; no implementation is claimed.

`planning/PROGRESS.md` is the authoritative ledger — documentation existing is
never evidence that code exists.

## Quick start

```bash
python -m pocketsec.stage0.cli gate         # Stage 0 gate (exit 0 = pass)
python -m pocketsec.stage0.cli smoke        # H0 baseline through the harness
python -m pocketsec.stage1.cli gate         # Stage 1 gate, 13 criteria
python -m pocketsec.stage1.cli adversarial  # 8 adversarial representation tests
python -m pocketsec.stage1.cli guillotine   # measured representation frontier
PYTHONHASHSEED=0 python -m pytest -q        # test suite
```

The runtime has **zero** third-party dependencies (ADR-0001), so the first three
need nothing installed beyond Python 3.11+.

## What Stage 0 froze

| Thing | Where |
|---|---|
| Research question and objective `M*` | `docs/stage-0-research-spec.md` |
| Hub / model-slot boundary | `docs/architecture/hub-model-boundary.md` |
| Versioned I/O contracts | `contracts/*.schema.json`, `pocketsec/stage0/contracts/` |
| Benchmark harness and metric set | `pocketsec/stage0/benchmark/` |
| Immutable experiment ids + append-only ledger | `pocketsec/stage0/experiments/` |
| Reproducibility and retention policy | `docs/reproducibility-policy.md` |
| Prior-art ledger | `docs/prior-art/ledger.json` |
| Stage 1 entry criteria | `docs/stage-1-entry-criteria.md` |

## The invariants that are enforced in code

These are not prose commitments; each one fails a test or the gate if broken.

- **A model output carries no response authority.** No action, command, shell or
  privilege field exists, and the schema is closed so one cannot be added.
  Response is Stage 5's under SENTINEL. (ADR-0003)
- **Abstention is an answer.** `UNKNOWN`, `UNIDENTIFIABLE` and
  `INSUFFICIENT_EVIDENCE` are valid verdicts, and novelty is not maliciousness —
  a novel-but-non-committal prediction scores zero, never manufactured recall.
- **Evidence keeps its lineage.** Evidence is referenced by SHA-256 digest,
  never inlined, so raw bytes stay distinct from any model representation.
- **State is bounded.** Windows are capped and truncation is explicit, so a
  bounded buffer cannot silently become a false negative.
- **Unmeasured is not measured.** A figure that could not be measured is `null`,
  and a profile target that could not be checked reports `None`, never "within
  target".
- **Synthetic is labelled synthetic.** `run_benchmark` requires the flag
  explicitly and it travels with the result.
- **Nothing is deleted.** The experiment ledger is append-only and
  digest-chained; refuted experiments and counterexamples stay.

## What Stage 1 added

SSIR — the Security Semantic Intermediate Representation — plus the security
state calculus. The fundamental unit is a **transition, not a log line**:
τ = (A, R, O, ΔS, U, N, P, T, E). See `docs/stage-1-ssir-spec.md`.

Measured on the synthetic corpus: cross-sensor equivalence 20/20 between eBPF
and auditd paths, peak RSS 24.6 MB against the 100 MB Edge target, Φ separating
benign 0.62 from malicious 9.46 with a +4.75 composition gain over an additive
severity control, and 8/8 adversarial representation tests passing.

Three more invariants enforced in code:

- **Novelty, security potential and confidence stay three separate signals.**
  A novel benign build scores novelty 1.00 / Φ 0.75. Rare is not malicious.
- **An epoch needs corroborating system-change evidence.** Behavioural novelty
  alone can never open one — that is the whole anti-poisoning mechanism.
- **Semantics are earned by behaviour.** Renaming a binary to `/tmp/.x91`
  produces an identical Φ of 13.75.

## An honest note on the Stage 1 numbers

The Information Guillotine frontier is **degenerate** on the current corpus:
only 1 of 9 cuts measurably costs security retention, because the synthetic
scenarios are separable by too many redundant signals. The report says so
itself (`ParetoReport.degenerate`), and **the 11-byte knee must not be used to
justify dropping SSIR fields.** The D1.13 field freeze stays open until a harder
corpus exists.

## An honest note on the Stage 0 numbers

The smoke benchmark reports PR-AUC 1.0. **This is not a detection result.** The
fixture is synthetic and trivially separable by construction; the attack chain
uses event kinds that appear nowhere in training. The number demonstrates that
the harness runs end to end, which is all acceptance clause 17.6 asks for. It
must never be cited as detection quality.

## Layout

All code lives in `pocketsec/`, namespaced by stage. Top-level directories are
artifact and definition stores, not import roots (ADR-0002).

```
contracts/    language-neutral JSON Schema for the frozen boundary
benchmarks/   benchmark case + fixture definitions
experiments/  the append-only experiment ledger (tracked in git)
results/      benchmark result records          (contents git-ignored)
datasets/     checksum-bound splits             (contents git-ignored)
baselines/    baseline configs and results
models/       experimental/ and compiled/       (contents git-ignored)
runtime/      reserved for Stage 1+ (the deployed hub)
training/     reserved for Stage 1+ (offline pipelines)
docs/         spec, ADRs, prior art, policies
planning/     stage prompts, PROGRESS.md, MEMORY.md
pocketsec/    all Python code, namespaced stage0/ ... stage12/
tests/        test suite
```

## Contributing rules that are not negotiable

1. Read `planning/MEMORY.md` and `planning/PROGRESS.md` before changing code.
2. An ADR is required for any change to a contract, a persistence format, an
   authority boundary, or the resource model. Template:
   `docs/adr/0000-adr-template.md`.
3. Never claim a security or performance result that was not measured.
4. Do not weaken a contract to make a test pass.
5. Do not advance a stage because the code compiles. The gate decides.
