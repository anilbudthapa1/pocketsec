# Stage 2 — DTL interim findings (D2.1–D2.5)

**Status:** D2.1–D2.5 implemented and measured. **DTL currently fails Stage 2
falsification criterion 1 on both corpora.** D2.6–D2.15 are not started, and
should not be started until the decision below is taken.

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

## Recommendation

**Do not build D2.6–D2.15 on the current core.** Adding Behaviour Atoms, the
lattice, Future Cones, the counterfactual twin and the compile-candidate
exporter on top of a predictive core that loses to a TCN by 0.39 PR-AUC would be
building machinery on a foundation the evidence does not support.

Three options, in the order I would take them:

1. **Replace DTL's recurrent core with a convolutional or hybrid one**, keeping
   the parts that are independently justified — the Need router, the
   multi-timescale decay, the structured surprise vector — and re-measure. The
   spec permits this: DTL is a research architecture, and section 36 explicitly
   anticipates simplification.
2. **Keep the recurrent core but fix the long-horizon learning problem**
   (per-lineage state, attention over the causal spine, or hierarchical
   chunking) and re-measure. Higher risk, since three separate recurrent
   baselines fail the same way.
3. **Accept the finding and reduce Stage 2's scope** to a TCN-based predictive
   core plus the DTL components that ablate well, dropping the rest.

The measurement harness, baselines, corpora and falsification machinery are all
in place, so any of these can be evaluated quickly.

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
