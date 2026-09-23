# baselines/

Baseline configurations and recorded baseline results.

Baseline *implementations* live in `pocketsec/stage0/baselines/` (ADR-0002).
H0 (`FrequencyBaselineSlot`) is the current hard baseline: a smoothed bigram
model over event kinds, deterministic and dependency-free.

Every proposed mechanism must beat or complement these under identical data and
hardware, or improve the Pareto frontier. `NullModelSlot` is the absolute floor:
a slot that always abstains.
