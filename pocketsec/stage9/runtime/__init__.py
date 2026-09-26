"""Stage 9 endpoint-side runtime: the homeostatic regime controller (``runtime.homeostatic``).

This is the one Stage 9 subpackage meant to run beside detection rather than offline, so it
imports no search, law or physics module. Consumers import the leaf module; this package
re-exports nothing.
"""

from __future__ import annotations

__all__: list[str] = []
