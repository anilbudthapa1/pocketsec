"""SAFE — the bounded, typed candidate-action field Stage 5 plans over (D5.2).

Deliberately empty of code: consumers import the leaf module
(``from pocketsec.stage5.safe.action_field import generate_action_field``), which is the
convention in every existing runtime module. A re-export chain here would give a second
name for types whose identity is part of the security boundary.
"""

from __future__ import annotations

__all__: tuple[str, ...] = ()
