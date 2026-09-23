"""Offline research and training code for Stage 2 (ADR-0008).

**This package may import numpy and other heavy dependencies.** It runs on a
development machine, never on the 2 GB endpoint.

Nothing under `pocketsec/` outside this package may import from it, and
`tests/test_repository_structure.py` enforces that in both directions: the
runtime must stay stdlib-only, and this package must not leak into it.

Training produces plain data artifacts (weights, codebooks, transition tables)
that the stdlib inference path loads. That is the Stage 0 hub/model-slot
boundary applied to Stage 2: the model is data, inference is cheap.
"""
