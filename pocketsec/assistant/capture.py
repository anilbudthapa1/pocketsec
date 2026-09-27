"""Project a Stage 4 engine run into the alert handoff, keeping the Stage 1 events.

What this module is FOR: Stage 4's ``CBFResolutionV1`` export alone cannot say what
happened on the host — it holds claim ids, digests and uniform "unresolved novel
mechanism" hypotheses. The actor, relation, object and state change of each piece of
evidence live in Stage 1's transitions, which the export references only by digest.
This module resolves those digests at capture time and writes the result into the
handoff, so the explainer never needs the live pipeline again.

What it reads, and what it must never read:

* ``run.export`` (the handoff), ``run.resolution`` (confidence, horizon, the engine's
  own detail line), ``run.replay.result.transitions`` and
  ``run.replay.pipeline.compiler.lineage_state`` — nothing else.
* **Never** ``run.case`` or ``run.replay.case``: ``IncidentCase.truth`` is corpus
  ground truth, and the corpus docstring forbids the engine from reading it. An
  explainer that read it would be manufacturing certainty. A test wraps ``case`` in a
  tripwire to hold this.
* **Never** ``ScenarioResult.final_state``: it is read for a fixed lineage the
  re-identified Stage 4 corpus never uses, so it is all-default there. Per-lineage
  state comes from ``compiler.lineage_state(actor)`` instead.

Duck-typed on purpose (``Any``): this is a projection of whatever object carries those
attributes, so a live system can call it without constructing an ``EngineRun``.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from pocketsec.assistant.facts import MAX_LINEAGES
from pocketsec.assistant.handoff import HANDOFF_SCHEMA, MAX_DIGESTS_PER_FACT, select_event_rows
from pocketsec.stage1.state.potential import phi
from pocketsec.stage1.state.security_state import DIMENSIONS

__all__ = ["actor_label", "handoff_from_run"]

_PROCESS_PREFIX = "proc:"


def actor_label(identity: str) -> str:
    """``proc:boot-0001:10000604:10000604`` -> ``10000604``, the lineage's process id.

    Stage 1 names processes by boot, pid and start time, never by program name
    (``entities.py``: a process display name is empty by design). The pid is the part
    a person can match against ``ps`` output; the full identity stays in the record.
    """
    parts = identity.split(":")
    if identity.startswith(_PROCESS_PREFIX) and len(parts) >= 3 and parts[2].isdigit():
        return parts[2]
    return identity


def _event_row(transition: Any) -> dict[str, Any] | None:
    if not transition.evidence:
        return None
    ref = transition.evidence[0]
    return {
        "digest": ref.digest,
        "store": ref.store,
        "locator": ref.locator,
        "sequence": int(transition.sequence),
        "actor": actor_label(transition.actor.identity),
        "relation": transition.relation.name,
        "object_kind": transition.object.kind.name,
        "object_name": transition.object.display_name,
        "actor_properties": sorted(p.value for p in transition.actor.semantics.asserted),
        "object_properties": sorted(p.value for p in transition.object.semantics.asserted),
        "raised": [
            [dimension, int(before), int(after)]
            for dimension, (before, after) in sorted(transition.state_delta.raised.items())
        ],
        "delta_phi": float(transition.delta_phi),
    }


def _lineage_rows(transitions: Iterable[Any], compiler: Any) -> list[dict[str, Any]]:
    by_actor: dict[str, list[Any]] = {}
    for transition in transitions:
        by_actor.setdefault(transition.actor.identity, []).append(transition)
    out: list[dict[str, Any]] = []
    for identity, owned in by_actor.items():
        state = compiler.lineage_state(identity)
        runs = [t for t in owned if t.relation.name == "EXECUTE" and t.object.display_name]
        capabilities = sorted({p.value for t in owned for p in t.actor.semantics.asserted})
        out.append(
            {
                "actor": actor_label(identity),
                "phi": float(phi(state).total),
                "state": [
                    [name, getattr(state, name).name]
                    for name in DIMENSIONS
                    if state.level(name) > 0
                ],
                "binary": runs[0].object.display_name if runs else None,
                "capabilities": capabilities,
                "digests": [t.evidence[0].digest for t in owned if t.evidence][
                    :MAX_DIGESTS_PER_FACT
                ],
            }
        )
    out.sort(key=lambda row: (-row["phi"], row["actor"]))
    return out[:MAX_LINEAGES]


def _assessment(resolution: Any) -> dict[str, Any]:
    return {
        "confidence": float(resolution.confidence),
        "horizon": resolution.horizon_outcome.value,
        "detail": resolution.verdict.detail,
    }


def handoff_from_run(run: Any, *, synthetic: bool, provenance: str) -> dict[str, Any]:
    """One engine run as a JSON-ready alert handoff. Reads no ground truth."""
    export = run.export.to_dict()
    transitions = tuple(run.replay.result.transitions)
    cited = frozenset(
        ref["digest"]
        for row in export["claim_graph"].get("claims", ())
        if row.get("kind") == "OBS"
        for ref in row.get("evidence", ())
    )
    rows = [row for row in (_event_row(t) for t in transitions) if row is not None]
    return {
        "schema": HANDOFF_SCHEMA,
        "synthetic": synthetic,
        "provenance": provenance,
        "resolution": export,
        "assessment": _assessment(run.resolution),
        "events": [dict(row) for row in select_event_rows(rows, cited)],
        "events_total": len(rows),
        "lineages": _lineage_rows(transitions, run.replay.pipeline.compiler),
        "response": None,
        "leases": [],
    }
