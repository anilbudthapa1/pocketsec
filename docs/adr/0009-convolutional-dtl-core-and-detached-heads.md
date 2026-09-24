# ADR-0009 — DTL's core becomes convolutional, and its heads are detached

- **Status:** Accepted
- **Date:** 2026-09-24
- **Stage:** 2
- **Deciders:** Stage 2 implementation session
- **Supersedes:** the recurrent core described in D2.3

## Context

The recurrent DTL core failed Stage 2 falsification criterion 1. On
long-horizon sessions (mean 93 transitions, base rate 0.333) a plain TCN scored
**1.0000** against DTL's **0.4736**, using half the parameters. Every recurrent
baseline — GRU 0.334, SSM 0.341, LSTM 0.353 — sat within 0.02 of the base rate.
Recurrence does not work for this task, and spec section 36 requires
simplification rather than persistence.

Two things had to be established before redesigning: *why* recurrence failed,
and whether anything else was also broken.

## Decision

### 1. Multi-timescale state becomes multi-dilation convolution

The six state blocks stop being recurrent cells and become dilated causal
convolutions, one dilation per timescale:

| block | dilation | timescale |
|---|---|---|
| `z_fast` | 1 | process/file/network micro-dynamics |
| `z_uncertainty` | 2 | what the model does not yet know |
| `z_session` | 4 | login/session/privilege trajectory |
| `z_causal` | 8 | the security-carrying causal spine |
| `z_host` | 16 | stable host behavioural dynamics |
| `z_epoch` | 32 | configuration regime |

This is the spec's factorisation with an implementation the measurement
supports. A dilation-16 kernel reaches 32 events back without carrying anything
through 90 steps of gradient.

### 2. Max-pooling over time is a first-class component

The security signal is a short escalating chain anywhere inside a long benign
session. Max-pooling is what finds it positionally-invariantly, and its absence
is the clearest single reason the recurrent core lost. Measured: removing it
drops DTL-C from **1.0000 to 0.3396**, barely above the base rate. It is the
only component with a large measured benefit.

### 3. The predictive heads train on a DETACHED representation

This is the substantive finding. Trained jointly on a shared representation,
the five prediction heads **destroy** detection:

| configuration | PR-AUC |
|---|---|
| joint heads, shared representation | 0.3333 |
| detached heads | **1.0000** |

It is not a weighting problem. `w_detect=8.0` with joint heads still scored
0.3333, and reducing head weights tenfold only reached 0.5537. The heads
optimise the convolutional features for next-step prediction — which is
dominated by frequent benign patterns — and that representation collapses the
attack signal. Detaching keeps the heads and the surprise vector they produce
without letting them corrupt the features detection depends on.

## Consequences for the Stage 2 thesis

The spec's thesis is that detection emerges from prediction. **On this data it
does not.** Jointly training the predictive machinery makes detection
catastrophically worse, and the detection-only model matches the best baseline
exactly.

This does not refute the thesis in general. It says: on a task a local pattern
detector already solves perfectly, a shared predictive representation is a pure
cost. Whether prediction helps when detection is *not* saturated remains
untested, and needs a corpus with headroom.

## Components with no ablation-supported reason to exist

Acceptance criterion 12 requires every surviving component to be justified by
ablation. Measured with detached heads:

| component | PR-AUC without it | verdict |
|---|---|---|
| max-pool | 0.3396 | **justified** |
| multi-timescale (6 dilations → 1) | 1.0000 | no measured benefit |
| Need router | 1.0000 | no measured benefit |
| surprise vector | 1.0000 | no measured benefit |

**The corpus saturates at 1.0000, so it has no headroom to demonstrate benefit
from a richer representation.** These three components are therefore *not yet*
justified rather than *disproven*, and they must not be presented as validated.
They are retained, flagged, and re-tested on the first corpus that is not
saturated. If they still show nothing, criterion 12 says remove them.

## Verification

`tests/test_stage2_dtl_conv.py`, and
`research/experiments.ablation_study`.

## Prior art

No novelty claimed. Dilated causal convolutions (WaveNet/TCN), max-over-time
pooling and stop-gradient auxiliary heads are all established. See
`docs/prior-art/ledger.json` entry H8.
