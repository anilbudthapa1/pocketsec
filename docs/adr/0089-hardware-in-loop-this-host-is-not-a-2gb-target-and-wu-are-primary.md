# ADR-0089 — Hardware-in-loop: this host is not a 2 GB target; work units are primary; `ResourceSampler` directly, not `run_benchmark`

- **Status:** Accepted
- **Date:** 2026-09-26
- **Stage:** 9
- **Deciders:** Stage 9 integrator (decided at spec time, `docs/stage-9-spec.md` §4.20, M0.13; measured on the gate run)
- **Supersedes / superseded by:** none

> Resource-model ADR. It fixes what G9.4's figures are, and what they are not.

## Context

G9.4: "Every phenotype has measured 2 GB target-machine resource data." The host has
`MemTotal: 16066696 kB` (16,452,296,704 B, read by `harness.hardware_in_loop.host_mem_total_bytes`
in the gate run) and 8 cores. Another wave shares it, and a Stage 2 gate once measured a 7x
timing inflation under load. Stage 0's `run_benchmark` needs a `SecurityEventSequenceV1` slot, and
no SSIR → `SecurityEventSequenceV1` path exists for a Stage 9 phenotype (only `stage0/smoke.py`
calls it).

## Decision

1. `measure_phenotype` replays the held-out clean split (240 sessions) through the phenotype, under
   `stage0.benchmark.resource_metrics.ResourceSampler`, best of 5 repetitions. In the **same run**
   it replays a direct Python loop computing the Φ-oracle, and reports the ratio. Absolute
   microseconds are labelled "host-contended, not a device measurement". `loadavg` is recorded
   before and after.
2. `is_reference_target` is `MemTotal ≤ 2 GiB × 1.10`. On this host it is `False`, so **G9.4
   fails by construction** (B9-4), and says so.
3. Work units are the primary cost axis: static, exact, host-independent. The gate reports the
   Spearman correlation of static WU/event against measured wall time as a check on the proxy.
4. Cache misses, wakeups and disk writes are `None` (UNMEASURED: no perf-counter access), never 0.
5. **Incremental RSS**, not peak, is the phenotype-attributable figure. Inside the gate process the
   sampled peak is the *whole gate's* resident set, which holds 14 compiled variants.

Gate run 2 (2026-09-26, `gate --save`), held-out clean split, load 4.79 / 4.20 / 4.24 at measurement:

| phenotype | WU/event | incremental RSS | wall µs/event (host-contended) | direct Φ-oracle loop µs/event, same run | ratio |
|---|---|---|---|---|---|
| H1 (`6897396d…`) | 4 | 4096 B | 1.64 | 0.109 | 15.1x |
| Φ-oracle (`717e9f47…`) | 3 | 4096 B | 1.42 | 0.094 | 15.1x |
| H2 (`1ba910ff…`) | 3 | 4096 B | 1.01 | 0.069 | 14.7x |

The final gate run, concurrent with the full pytest suite (load 6.38 / 5.19 / 4.71), read the same
three ratios as 16.95x, 18.25x and 16.54x. The ratio moves with load, which is why no absolute
figure is quoted as a device result. Sampled peak RSS of the gate process: 1,354,952,704 B (run 2),
not phenotype-attributable. Spearman
(WU/event vs wall µs/event) = 0.866 over n = 3, far too few points to validate the proxy.

## Options considered

| Option | Security cost | Complexity | Measured consequence | Why not chosen |
|---|---|---|---|---|
| A. Report host figures as the 2 GB result | a false device claim | none | — | forbidden |
| B. `run_benchmark` | none | needs an SSIR→`SecurityEventSequenceV1` adapter nobody has built | not measurable | no path exists |
| C. `ResourceSampler` directly, ratios within one run, `is_reference_target` explicit (chosen) | none | low | the table above; G9.4 fails as expected | chosen (the Stage 5-7 precedent) |
| D. Emulate 2 GB with cgroups | a resource cap is not a slower machine | medium | not run | not a reference target either |

## Consequences

**Accepted costs.** No figure here says anything about a 2 GB device. The interpreted phenotype is
about 15x a hand loop on this host and run. That ratio, not the microseconds, is the comparable
figure.

**Bounded state.** A phenotype's own incremental RSS was one 4 KiB page for all three.

**Reversibility.** Run `measure_phenotype` on a 2 GB machine and G9.4 can pass. No code changes
are needed.

**Authority.** None.

## Verification

Gate G9.4; `tests/test_stage9_runtime.py` (HIL record shape, `None` when unmeasured, the
reference-target check).

## Prior art

None claimed.
