# ADR-0008 — Offline research may use numpy; the runtime may not

- **Status:** Accepted
- **Date:** 2026-09-24
- **Stage:** 2
- **Deciders:** Stage 2 implementation session

## Context

ADR-0001 froze the endpoint runtime at zero third-party dependencies, and
measured the benefit: ~25 MB peak RSS against a 100 MB Edge target. It also
anticipated this moment — "offline research and training components may take
heavier dependencies, but only outside the deployed agent path."

Stage 2 forces the issue. Its acceptance gate requires **at least five strong
baselines** (GRU, LSTM, TCN, tiny Transformer, selective SSM, …) trained under
identical inputs and splits, plus a nine-point latent-dimension sweep and a full
ablation program. Implementing recurrent backpropagation in pure Python is
possible but would be slow enough to force a smaller corpus, fewer epochs and
weaker models — which would rig the comparison in DTL's favour. A baseline that
lost because it was starved of compute would tell us nothing, and the Stage 2
falsification criteria depend on baselines being genuinely strong.

The spec is explicit (section 27): "Training occurs on a development machine.
The 2 GB endpoint performs inference, bounded baseline statistics and only
carefully gated adaptation."

## Decision

A single, enforced boundary:

- **`pocketsec/stage2/research/`** is offline training and evaluation code. It
  may import numpy and other heavy dependencies. It never runs on an endpoint.
- **Everything else under `pocketsec/`** stays stdlib-only, as ADR-0001 requires.
- **No runtime module may import from `research`.** Training emits plain data
  artifacts — weights, codebooks, transition tables — which the stdlib inference
  path loads. The model is data; inference is cheap.

numpy and scipy are already present in the environment, so this adds no install
step and no supply-chain surface to the deployed agent, which carries neither.

## Options considered

| Option | Baseline quality | Endpoint cost | Why not chosen |
|---|---|---|---|
| numpy in `research/` only | strong baselines, real comparison | unchanged (0 deps) | **chosen** |
| Pure Python everywhere | weak: smaller corpus, fewer epochs | unchanged | would rig the comparison by starving baselines |
| numpy everywhere | strong | +~40 MB RSS, breaks ADR-0001 | destroys the Edge budget for no inference benefit |

## Consequences

**Accepted costs.** Two dependency regimes in one package, which is a real
cognitive cost. It is paid down by making the boundary mechanical rather than a
convention: the test suite fails if the runtime gains a third-party import, and
fails again if any runtime module imports `research`.

**Bounded state.** No effect on the endpoint. The deployed agent's dependency
count remains zero, and its measured RSS is unchanged.

**Reversibility.** Deleting `research/` would remove the ability to train, not
the ability to run. That asymmetry is the point.

**Authority.** None. Research components have no production authority — a
Stage 0 invariant, and the reason this boundary is one-directional.

## Verification

`tests/test_repository_structure.py::test_runtime_has_no_third_party_imports`
(excluding `research`) and
`::test_runtime_never_imports_research_code`.

## Prior art

No novelty claimed. Standard train-offline / infer-on-device separation.
