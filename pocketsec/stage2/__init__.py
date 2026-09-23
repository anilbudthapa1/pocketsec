"""Stage 2 — the DTL Intelligence Core (Dynamic Transition Lattice).

PocketSec's first real learning core. It consumes Stage 1 SSIR transitions, host
security state, behaviour epochs, causal state and uncertainty, and learns the
*dynamics* of a Linux host: what states exist, how they change, which futures
are plausible, what remains uncertain, and which learned transitions could
eventually execute without expensive inference.

> Do not make a tiny model imitate a giant model. Build the smallest adaptive
> machine that knows what security future to expect, knows when it does not
> know, and turns repeated understanding into structure that can eventually
> execute without the model.

**DTL is a research architecture, not a claim of novelty or superiority.** Every
component is compared against strong simple baselines and removed if it does not
improve the measured Pareto frontier (spec section 36).

Dependency boundary (ADR-0008): everything here is stdlib-only **except**
`pocketsec.stage2.research`, which is offline training and evaluation code and
may use numpy. The inference path must never import it.
"""
