"""D0.4 — the immutable experiment-ID convention.

Format::

    PS-S<stage>-<YYYYMMDD>-<hypothesis>-<slug>-<seq>
    PS-S0-20260924-H0-frequency-baseline-0001

The id is assigned once and never reused, rewritten or recycled. It is the join
key between a result record, its registry entry and its retained artifacts, so
mutating one would silently detach a measurement from its provenance.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime

__all__ = [
    "EXPERIMENT_ID_PATTERN",
    "ExperimentId",
    "format_experiment_id",
    "parse_experiment_id",
]

EXPERIMENT_ID_PATTERN = re.compile(
    r"^PS-S(?P<stage>\d{1,2})"
    r"-(?P<date>\d{8})"
    r"-(?P<hypothesis>H\d{1,2}|BASE)"
    r"-(?P<slug>[a-z0-9]+(?:-[a-z0-9]+)*)"
    r"-(?P<sequence>\d{4})$"
)

_SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_HYPOTHESIS_RE = re.compile(r"^(H\d{1,2}|BASE)$")


@dataclass(frozen=True, slots=True)
class ExperimentId:
    stage: int
    date: str
    hypothesis: str
    slug: str
    sequence: int

    def __str__(self) -> str:
        return format_experiment_id(
            stage=self.stage,
            hypothesis=self.hypothesis,
            slug=self.slug,
            sequence=self.sequence,
            date=self.date,
        )


def format_experiment_id(
    *, stage: int, hypothesis: str, slug: str, sequence: int, date: str | None = None
) -> str:
    """Build a well-formed experiment id, validating every component."""
    if not 0 <= stage <= 12:
        raise ValueError(f"stage must be within [0, 12], got {stage}")
    if not _HYPOTHESIS_RE.fullmatch(hypothesis):
        raise ValueError(f"hypothesis must look like 'H3' or 'BASE', got {hypothesis!r}")
    if not _SLUG_RE.fullmatch(slug):
        raise ValueError(f"slug must be lowercase kebab-case, got {slug!r}")
    if not 0 <= sequence <= 9999:
        raise ValueError(f"sequence must be within [0, 9999], got {sequence}")
    stamp = date or datetime.now(UTC).strftime("%Y%m%d")
    if not re.fullmatch(r"\d{8}", stamp):
        raise ValueError(f"date must be YYYYMMDD, got {stamp!r}")
    datetime.strptime(stamp, "%Y%m%d")  # rejects 20260231
    return f"PS-S{stage}-{stamp}-{hypothesis}-{slug}-{sequence:04d}"


def parse_experiment_id(value: str) -> ExperimentId:
    match = EXPERIMENT_ID_PATTERN.fullmatch(value)
    if match is None:
        raise ValueError(f"malformed experiment id: {value!r}")
    return ExperimentId(
        stage=int(match["stage"]),
        date=match["date"],
        hypothesis=match["hypothesis"],
        slug=match["slug"],
        sequence=int(match["sequence"]),
    )
