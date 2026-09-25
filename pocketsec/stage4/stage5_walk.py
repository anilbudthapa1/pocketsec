"""The export-time claim walk over a ``CBFResolutionV1``'s wire rows.

This module is FOR checking the Stage 5 handoff independently of the objects that
produced it: the rows are plain JSON, so the walk re-derives from them — rather than
trusting the graph's own ``unsupported_authoritative`` field — whether every
authoritative claim is rooted in digested OBS rows, whether an inference was
smuggled into the authoritative set, whether a hypothesis cites a claim the graph
does not hold, and whether a row carries a key naming response authority.

Split out of ``stage5_interface.py`` for size, and hardened in the process: a
duplicated claim id is refused rather than resolved last-wins (S4-REV-12), the
walk is memoised so a crafted payload cannot make it exponential (S4-SEC-08), and
the authority-key refusal now holds on every construction path (S4-SEC-03).
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS

__all__ = [
    "MAX_EXPORT_CHAIN_DEPTH",
    "refuse_authority_keys",
    "refuse_dangling_citations",
    "refuse_laundered_kinds",
    "row_index",
    "unsupported_authoritative_rows",
]

#: Longest premise chain the export walk follows before failing the claim.
MAX_EXPORT_CHAIN_DEPTH: int = 16

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def row_index(claim_graph: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    """Rows by ``claim_id``. Two rows under one id are refused, not resolved.

    The first version kept the LAST row per id, so a graph carrying an INF row and
    then an OBS row under the same id passed both export walks with the INF marked
    authoritative (S4-REV-12). Which of two contradictory rows is "the" claim is not
    a question an exporter may answer silently.
    """
    rows: dict[str, Mapping[str, Any]] = {}
    for row in claim_graph.get("claims", ()) or ():
        if isinstance(row, Mapping) and isinstance(row.get("claim_id"), str):
            claim_id = str(row["claim_id"])
            if claim_id in rows:
                raise ContractError(
                    f"exported claim graph carries two rows for claim {claim_id!r}; an id "
                    "must name one claim"
                )
            rows[claim_id] = row
    return rows


def _row_height(
    claim_id: str,
    rows: Mapping[str, Mapping[str, Any]],
    memo: dict[str, int | None],
) -> int | None:
    """Chain height below ``claim_id`` if it traces to digested OBS rows, else ``None``.

    Memoised per id: the first version re-walked every shared premise once per path
    with no bound on premises per row, so a small crafted payload made the walk
    exponential (S4-SEC-08). A row met again while still being walked is a cycle,
    which traces to nothing.
    """
    if claim_id in memo:
        return memo[claim_id]
    memo[claim_id] = None  # in progress: a cycle back here fails
    row = rows.get(claim_id)
    height: int | None = None
    if row is not None and row.get("kind") == "OBS":
        evidence = row.get("evidence") or ()
        if evidence and all(
            isinstance(ref, Mapping) and bool(_DIGEST_RE.fullmatch(str(ref.get("digest", ""))))
            for ref in evidence
        ):
            height = 0
    elif row is not None and row.get("kind") == "DER":
        premises = tuple(row.get("premises") or ())
        below = [_row_height(str(premise), rows, memo) for premise in premises]
        if premises and all(item is not None for item in below):
            height = 1 + max(item for item in below if item is not None)
    memo[claim_id] = height
    return height


def _row_traces_to_observation(
    claim_id: str,
    rows: Mapping[str, Mapping[str, Any]],
    *,
    depth: int,
    memo: dict[str, int | None] | None = None,
) -> bool:
    """True when this exported row's premise chain terminates in digested OBS rows.

    Re-derived from the rows rather than read out of the graph's own
    ``unsupported_authoritative`` field, because that field is data the exporter
    would be trusting about itself. This walk is the independent one. A chain longer
    than ``MAX_EXPORT_CHAIN_DEPTH`` fails, as it always did.
    """
    height = _row_height(claim_id, rows, memo if memo is not None else {})
    return height is not None and depth + height <= MAX_EXPORT_CHAIN_DEPTH


def unsupported_authoritative_rows(claim_graph: Mapping[str, Any]) -> tuple[str, ...]:
    """G4.8, measured on the exported rows: authoritative ids not rooted in OBS.

    Returns the offending ids. ``()`` is the pass condition, and
    :meth:`CBFResolutionV1.to_dict` raises on anything else.
    """
    rows = row_index(claim_graph)
    memo: dict[str, int | None] = {}
    authoritative = claim_graph.get("authoritative", ()) or ()
    return tuple(
        sorted(
            str(claim_id)
            for claim_id in authoritative
            if not _row_traces_to_observation(str(claim_id), rows, depth=0, memo=memo)
        )
    )


def refuse_authority_keys(rows: Sequence[Mapping[str, Any]], *, field: str) -> None:
    """No hypothesis or gap row may carry a key naming response authority (T5).

    The dataclasses that normally build these rows refuse such fields, but
    ``CBFResolutionV1`` accepted any row handed to it directly or read back by
    ``from_dict`` — the refusal only held on one construction path (S4-SEC-03).
    """
    for index, row in enumerate(rows):
        for key in row:
            lowered = str(key).lower()
            if any(token in lowered for token in FORBIDDEN_AUTHORITY_FIELDS):
                raise ContractError(
                    f"{field}[{index}] carries key {key!r}, which names response authority; "
                    "a Stage 4 output carries none (ADR-0003)"
                )


_NON_AUTHORITATIVE_KINDS = frozenset({"INF", "CF", "EXT", "UNK"})


def refuse_laundered_kinds(claim_graph: Mapping[str, Any]) -> None:
    rows = row_index(claim_graph)
    laundered = sorted(
        str(claim_id)
        for claim_id in (claim_graph.get("authoritative", ()) or ())
        if str(rows.get(str(claim_id), {}).get("kind", "")) in _NON_AUTHORITATIVE_KINDS
    )
    if laundered:
        raise ContractError(
            f"CBFResolutionV1 marks {laundered} authoritative while they are inferred, "
            "counterfactual, external or unknown claims; an inference may never leave this "
            "stage as an observation"
        )


def refuse_dangling_citations(
    hypotheses: Sequence[Mapping[str, Any]], claim_graph: Mapping[str, Any]
) -> None:
    rows = row_index(claim_graph)
    for index, row in enumerate(hypotheses):
        for claim_id in row.get("claim_ids", ()) or ():
            if str(claim_id) not in rows:
                raise ContractError(
                    f"hypotheses[{index}] cites claim {claim_id!r}, which is not in the "
                    "exported claim graph; a citation Stage 5 cannot resolve is an "
                    "unauditable factual claim"
                )
