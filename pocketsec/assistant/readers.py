"""Field readers for the alert handoff: every value is checked where it enters.

What this module is FOR: the handoff is external data (a file, a live feed), so each
field is validated at the boundary and nothing downstream re-checks it. Kept separate
from ``handoff.py`` so the Stage 4 and Stage 5 row readers share one set of rules.

Strings are the interesting case. A recorded file path or endpoint is chosen by
whoever controls the host, and it ends up printed on an analyst's terminal, so control
characters (ANSI escapes, bells, carriage returns) are replaced and the length is cut
to ``MAX_TEXT``. Error messages name the field and never quote the offending value.
"""

from __future__ import annotations

import math
import re
import sys
import unicodedata
from collections.abc import Mapping, Sequence
from typing import Any

from pocketsec.assistant.facts import MAX_TEXT

__all__ = [
    "DIGEST_RE",
    "HandoffError",
    "clean_text",
    "digest",
    "integer",
    "names",
    "number",
    "opt_bool",
    "opt_integer",
    "opt_text",
    "rows",
]

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
#: The largest integer ``float()`` converts without overflow.
_FLOAT_INT_LIMIT = int(sys.float_info.max)


class HandoffError(ValueError):
    """The handoff was refused. The message names the field; the payload is never quoted."""


def clean_text(value: object, field: str, *, limit: int = MAX_TEXT) -> str:
    """A bounded, printable string. Control characters become ``?``; long text is cut."""
    if not isinstance(value, str):
        raise HandoffError(f"{field} must be a string")
    scrubbed = "".join(
        "?" if unicodedata.category(ch).startswith("C") else ch for ch in value
    ).strip()
    return scrubbed[:limit]


def opt_text(value: object, field: str, *, limit: int = MAX_TEXT) -> str | None:
    return None if value is None else clean_text(value, field, limit=limit)


def number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise HandoffError(f"{field} must be a number")
    # JSON integers are unbounded; float() on one past ~1.8e308 raises OverflowError,
    # which is not a refusal a caller expects. Check the range first.
    if isinstance(value, int) and abs(value) > _FLOAT_INT_LIMIT:
        raise HandoffError(f"{field} is out of range")
    if not math.isfinite(float(value)):
        raise HandoffError(f"{field} must be finite")
    return float(value)


def integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise HandoffError(f"{field} must be an integer")
    return value


def opt_integer(value: object, field: str) -> int | None:
    return None if value is None else integer(value, field)


def opt_bool(value: object, field: str) -> bool | None:
    if value is not None and not isinstance(value, bool):
        raise HandoffError(f"{field} must be a bool or null")
    return value


def digest(value: object, field: str) -> str:
    if not isinstance(value, str) or not DIGEST_RE.match(value):
        raise HandoffError(f"{field} must be a sha256:<64 hex> digest")
    return value


def rows(value: object, field: str) -> Sequence[Mapping[str, Any]]:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)) or not all(isinstance(r, Mapping) for r in value):
        raise HandoffError(f"{field} must be a list of objects")
    return value


def names(value: object, field: str, *, limit: int = 16) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise HandoffError(f"{field} must be a list of strings")
    return tuple(clean_text(item, field, limit=64) for item in value[:limit])
