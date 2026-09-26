"""Stage 7 labs: the SIMULATED fleet corpus, fleet, adversaries and benchmark runners.

Nothing outside ``labs/`` and the integrator's harness may import this package: a lab
holds ground truth, and runtime code that could read ground truth is a label leak.
Consumers import the leaf modules; this package deliberately re-exports nothing.
"""

from __future__ import annotations

__all__: list[str] = []
