"""The two D3FEND names the operator algebra needs, and nothing that can load a gate.

``OperatorSpec.__post_init__`` checks every catalog entry's ``d3fend_technique_id`` against
:data:`UNMAPPED` and :data:`D3FEND_ID_PATTERN`. Those used to be read from
``operators/d3fend.py`` by a deferred import, and that module imports ``stage0.gate`` for
its snapshot path — so building the catalog loaded the experiment registry, the prior-art
ledger and the benchmark profiles into the process SENTINEL and the executor run in
(finding S5-SEC-11). This module imports only ``re``; ``d3fend.py`` re-exports both names.
"""

from __future__ import annotations

import re

__all__ = ["D3FEND_ID_PATTERN", "UNMAPPED"]

#: The value every catalog entry ships. Not a placeholder to be replaced by a guess.
UNMAPPED: str = "UNMAPPED"

#: The shape of a published D3FEND technique id (``D3-PSEP``, ``D3-PROCTERM``). The
#: pattern is a *format* check; it says nothing about whether the id exists, which is
#: exactly why a snapshot is also required.
D3FEND_ID_PATTERN = re.compile(r"^D3-[A-Z]{2,7}$")
