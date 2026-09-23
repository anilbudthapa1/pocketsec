# benchmarks/

Benchmark case definitions and fixture specifications.

Harness code lives in `pocketsec/stage0/benchmark/` (ADR-0002).

## Stage 0 smoke case

`pocketsec.stage0.smoke` defines `stage0-smoke`: the H0 baseline over a
deterministically generated fixture, satisfying acceptance clause 17.6.

> **The fixture is synthetic and trivially separable by construction.** Its
> scores demonstrate that the harness runs end to end. They are not a detection
> result and must never be cited as one. Every result carries
> `synthetic_data: true`.
