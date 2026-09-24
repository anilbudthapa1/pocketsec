# Stage 2 — DTL interim findings (D2.1–D2.5)

**Status:** D2.1–D2.5 implemented and measured. The recurrent core failed
falsification criterion 1; it was **replaced with a convolutional core
(ADR-0009)** which now matches the best baseline. D2.6–D2.15 remain unstarted.

**Resolution in one line:** DTL-C scores **1.0000**, equal to the best baseline,
but only after detaching the predictive heads — and only max-pooling has an
ablation-supported reason to exist.

> DTL is a research architecture, not a claim of novelty or superiority. Every
> component must be compared against strong simple baselines and removed if it
> does not improve the measured Pareto frontier. — Stage 2 spec, section 2

This document reports a negative result. That is the mechanism working.

## What was built

| Deliverable | Status |
|---|---|
| D2.1 DTL core IDs (DTL-F01..F20) | done — 20 versioned functional IDs, REQUIRED/OPTIONAL |
| D2.2 Baseline suite + harness | done — 8 baselines, identical splits and budget |
| D2.3 Multi-timescale predictive core | done — 6 blocks, independent gates and decay |
| D2.4 Need-to-Compute router | done — soft gates when training, hard at inference |
| D2.5 Multi-head predictive engine | done — 5 active heads, structured surprise vector |

## The measurement

Two corpora, each with two disjoint labelled splits built from separate Stage 1
pipelines (a shared pipeline would let the fit split warm the novelty engine
that scores the eval split).

All numbers below are with **mini-batch SGD**, after the training-budget defect
described later was fixed. The earlier full-batch numbers are not reported as
results: they measured optimisation depth, not architecture.

### Hard corpus — mean 4.14 transitions per scenario

| model | PR-AUC | params |
|---|---|---|
| mlp-pooled | 0.9992 | 4,657 |
| gru | 0.9992 | 8,737 |
| lstm | 0.9992 | 11,641 |
| tcn | 0.9992 | 6,961 |
| dtl | 0.9992 | 13,399 |
| tiny-transformer | 0.9986 | 7,537 |
| selective-ssm | 0.9986 | 7,009 |
| vq-prototype | 0.8164 | 1,152 |
| markov-bigram | 0.6851 | 20 |

**This corpus is saturated.** Five architectures tie exactly at 0.9992,
including a pooled bag-of-features model that ignores order entirely. It cannot
discriminate between predictive architectures and must not be used to justify
one. It remains useful for Stage 1 representation work, which is what it was
built for.

### Long-horizon corpus — mean 93 transitions per session

Built specifically because the hard corpus could not test DTL's central claim:
`z_host` operates on hours-to-days and `z_epoch` on configuration regimes, and
neither has anything to do across four events.

| model | PR-AUC | params |
|---|---|---|
| **tcn** | **1.0000** | 6,961 |
| markov-bigram | 0.5654 | 46 |
| **dtl** | **0.4736** | **13,399** |
| tiny-transformer | 0.4686 | 7,537 |
| vq-prototype | 0.3930 | 1,152 |
| lstm | 0.3527 | 11,641 |
| selective-ssm | 0.3407 | 7,009 |
| gru | 0.3344 | 8,737 |
| mlp-pooled | 0.3333 | 4,657 |

Base rate 0.333. A pooled bag-of-features model lands *exactly* on the base
rate, confirming the corpus carries no vocabulary signal — the difference
between benign and malicious is structural, as designed.

## Verdict against the falsification criteria

**Criterion 1 — "a simple baseline achieves statistically comparable security
performance with materially lower cost" → DTL must be simplified or rejected.**

On the long-horizon corpus TCN scores **1.0000** against DTL's **0.4736** — a
gap of **0.53 PR-AUC** — using **half** the parameters (6,961 vs 13,399). DTL is
barely above the 0.333 base rate. This is not marginal, and it is the corpus
built specifically to give DTL's multi-timescale design its best chance.

On the hard corpus the criterion cannot be applied: five architectures tie at
0.9992, so no conclusion about DTL is supportable there either way.

**Criterion 2 — discrete atoms.** Not yet testable: D2.6 is unbuilt. The
VQ-prototype baseline, the cheap proxy for that idea, is second-worst on both
corpora, which is weak prior evidence against the atom layer.

## What the negative result actually shows

Three findings, in decreasing confidence:

1. **Local temporal convolution with max-pooling is the right inductive bias
   for this task, and recurrence is not.** The security signal is a short
   escalating chain embedded in a long benign session. TCN's fixed receptive
   field finds it wherever it sits and scores a perfect 1.0000; every recurrent
   model must carry the signal across ~90 steps and none does. GRU (0.334), SSM
   (0.341) and LSTM (0.353) all sit within 0.02 of the base rate — they learn
   essentially nothing.

2. **DTL's machinery does help relative to plain recurrence.** On long sessions
   DTL (0.474) is the best non-convolutional model in the suite, beating GRU,
   LSTM, the SSM and the pooled MLP by 0.12–0.14. Its multi-timescale
   factorisation and gating are doing something real. It simply does not come
   close to a convolutional model.

3. **The order-shuffle probe confirms DTL uses sequence structure most.**
   Shuffling step order costs DTL −0.138 PR-AUC, GRU −0.117, TCN −0.035 and
   the pooled MLP exactly 0.000. So DTL is the most order-sensitive model in
   the suite — and still loses.

## Methodology defects found and fixed along the way

Each of these produced a confident wrong number first.

1. **The tiny Transformer computed Q/K/V from `.data`**, detaching all three
   projections, so it could not learn what to attend to. 0.5502 → 0.9373 once
   reconnected through a new batched-matmul op. A broken baseline would have
   flattered DTL.
2. **Full-batch training gave 30 gradient steps total.** Shallow models coped;
   deep recurrent ones learned nothing, and DTL scored *below* the base rate at
   0.2841. Mini-batch SGD lifted it to 0.4736. Comparing architectures under
   that budget measured depth-of-optimisation, not architecture.
3. **The autodiff used a recursive topological sort** and blew the interpreter
   stack on 90-step graphs. Long sequences are the normal case here.
4. **The long-horizon corpus leaked its answer.** Attacks ran interpreters
   (`python3`, `perl`) that never appeared in benign sessions, so a
   bag-of-features model scored a perfect 1.0000. After putting interpreters,
   SSH-key reads and cron writes into benign traffic too, the same model scores
   0.4925. The difference between benign and malicious is now structure, not
   vocabulary.
5. **The DTL wake penalty only saw the final step's gates**, so the router
   could wake every block for a whole sequence almost free — and did.
6. **The execution-path head had no supervision.** There is no ground-truth
   label for "which path should this event have taken", so it was fitting
   noise. Replaced with a deterministic, auditable policy over the Need signal,
   per spec section 6.
7. **Feature indices into the frozen encoder layout were hardcoded and wrong.**
   Now derived from the layout via `NEED_SIGNAL_INDICES`.

## Resolution: the convolutional redesign (ADR-0009)

Option 1 was taken: replace the recurrent core, keep what was independently
justified. Multi-timescale state became **multi-dilation causal convolution**
(dilations 1, 2, 4, 8, 16, 32 — one per timescale block), max-pooling over time
was added, and the Need router, decay and surprise vector were retained.

### The decisive finding: predictive heads must be detached

| configuration | PR-AUC |
|---|---|
| joint heads on a shared representation | 0.3333 |
| **detached heads** | **1.0000** |

Not a weighting problem: `w_detect=8.0` with joint heads still scored 0.3333,
and cutting head weights tenfold only reached 0.5537. The heads optimise the
convolutional features for next-step prediction — dominated by frequent benign
patterns — and that representation collapses the attack signal.

**This contradicts the Stage 2 thesis as implemented.** The spec's premise is
that detection emerges from prediction. On this data, jointly training the
predictive machinery makes detection catastrophically worse, and the
detection-only model matches the best baseline exactly. That is not a general
refutation — it says that on a task a local pattern detector already solves
perfectly, a shared predictive representation is pure cost.

### Ablation: what actually earns its place

Measured with detached heads, on the long-horizon corpus:

| component | PR-AUC without it | verdict |
|---|---|---|
| max-pool over time | 0.3396 | **justified** |
| multi-timescale (6 dilations → 1) | 1.0000 | no measured benefit |
| Need router | 1.0000 | no measured benefit |
| surprise vector | 1.0000 | no measured benefit |

Only max-pooling is load-bearing. Acceptance criterion 12 requires every
surviving component to have an ablation-supported reason to exist, and three do
not have one yet.

**The honest qualifier: this corpus saturates at 1.0000.** A task that is
already perfectly solved has no headroom in which a richer representation could
show benefit. Those three components are therefore *not yet justified* rather
than *disproven*. They are retained, flagged in ADR-0009, and must be re-tested
on the first non-saturated corpus. If they still show nothing there, criterion
12 says remove them.

## Recommendation

1. **Ship the convolutional core.** DTL-C matches the best baseline at 1.0000
   and the recurrent core is superseded.
2. **Keep heads detached.** Joint training is a −0.67 PR-AUC defect, not a
   tuning choice.
3. **Build a non-saturated corpus before D2.6–D2.15.** Both existing corpora are
   saturated — the hard one ties five architectures at 0.9992, the long one lets
   two models reach 1.0000. Until a corpus has headroom, no further DTL
   component can be justified by measurement, and building Behaviour Atoms, the
   lattice and Future Cones on top would repeat the mistake this stage just
   caught.

## What is not yet measured

- Calibration, abstention, Future Cone value, counterfactual attribution,
  causal credit, epoch-conditioned adaptation, poisoning resistance, the
  transition cache and compile candidates (D2.6–D2.15).
- The latent-dimension sweep and full ablation exist in
  `research/experiments.py` but have only been run at a single configuration.
- The sleeping-brain benchmark runs, but its compute-per-event figure is driven
  by the input-derived Need policy and is therefore unaffected by training —
  correct by design, but it means the current number measures the policy, not
  the model.
- All corpora remain synthetic. No result here is a detection claim.
