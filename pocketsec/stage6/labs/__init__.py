"""Stage 6 labs: the experiment catalogue, the endurance corpus, the attacks, the baselines.

Deliberately empty of code: consumers import the leaf module. Nothing outside
``labs/`` may import this package (boundary rule 6) — a runtime path that can reach
a corpus builder or a poisoning arm is a runtime path an experiment can steer.
"""

from __future__ import annotations

__all__: tuple[str, ...] = ()
