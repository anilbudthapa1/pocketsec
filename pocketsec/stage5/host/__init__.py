"""Stage 5 host models. Only a SIMULATED host exists, deliberately (ADR-0046).

Deliberately empty of code: consumers import
``pocketsec.stage5.host.simulated``. There is no ``RealHost``, not even a stub, so there is
nothing here that a later change could quietly point at a real kernel.
"""

from __future__ import annotations

__all__: tuple[str, ...] = ()
