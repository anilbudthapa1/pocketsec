"""HEL-F24 target selection — which retained fossil a rollback may restore, and when it must refuse.

The controller (``promotion.controller``) is the only writer of trusted state; this module
only *chooses* and *verifies* the state it will install. It exists because two review
findings (S6-R1, honesty F2) showed the old in-line selector did the wrong thing in the
one case that matters most: an operator naming an exact digest.

What it refuses to do, and why:

* **It never substitutes a requested digest.** ``rollback_learning(to_digest=X)`` restores
  X byte-identically or raises; it never falls through to "the newest fossil that happens
  to verify". Substitution returned success for a state nobody asked for, with a
  ``restored_bytes_identical`` flag that described the wrong target.
* **It never re-trusts a state the controller already judged bad.** A digest rolled back
  for a regression, or the proposal of a REJECTED / ROLLED_BACK candidate, is refused as an
  explicit target (review S6-AUTH-02): re-trusting it needs a new candidate through the
  conservation gate, shadow and canary, not a rollback that runs none of them.
* **It does not call a lineage fold corruption.** A fossil whose bytes are intact but whose
  items' lineage was folded is *unverifiable*, not corrupt; only a byte-integrity failure
  makes the recorded trigger ``FOSSIL_CORRUPTION``.

Automatic selection (no digest requested) keeps its order: the probation target, then the
newest retained fossil not known bad, skipping — and naming — any that do not verify.
"""

from __future__ import annotations

from collections.abc import Collection, Sequence
from dataclasses import dataclass

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage6.fossils.lineage import KnowledgeLineageDAG
from pocketsec.stage6.fossils.store import FossilIntegrityError, FossilStore
from pocketsec.stage6.memory.semantic import LineageError, TrustedKnowledgeState

__all__ = ["RestoreTarget", "select_restore_target", "verified_fossil"]


@dataclass(frozen=True, slots=True)
class RestoreTarget:
    """The fossil a rollback will install, and what was passed over to reach it."""

    digest: str
    state: TrustedKnowledgeState
    skipped: tuple[str, ...]  # fossils passed over, newest first
    corrupt: bool  # True iff at least one skipped fossil failed *byte* integrity


def verified_fossil(fossils: FossilStore, lineage: KnowledgeLineageDAG,
                    digest: str) -> TrustedKnowledgeState:
    """Load ``digest`` with lineage and prove it rebuilds to its exact stored bytes."""
    state = fossils.load(digest, lineage=lineage)
    if state.canonical_bytes() != fossils.payload(digest):
        raise FossilIntegrityError(f"{digest} rebuilt to different bytes")
    return state


def _explicit(fossils: FossilStore, lineage: KnowledgeLineageDAG, requested: str,
              refused: Collection[str]) -> RestoreTarget:
    if requested in refused:
        raise ContractError(
            f"refused: {requested} was rolled back or rejected by this controller; re-trusting "
            "it needs a new candidate through conservation, shadow and canary"
        )
    try:
        state = verified_fossil(fossils, lineage, requested)
    except LineageError as exc:
        raise ContractError(
            f"refused: fossil {requested} is held but its lineage no longer verifies ({exc}); "
            "the trusted state is unchanged and no other fossil was substituted"
        ) from exc
    return RestoreTarget(requested, state, (), False)


def select_restore_target(
    fossils: FossilStore, lineage: KnowledgeLineageDAG, *, requested: str | None,
    from_digest: str, preferred: Sequence[str], refused: Collection[str],
) -> RestoreTarget:
    """The explicit ``requested`` fossil exactly, else the first automatic one that verifies.

    ``preferred`` is tried first in automatic mode (the probation target); ``refused``
    holds digests known bad. Raises ``ContractError`` for a refused or unverifiable explicit
    target and ``FossilIntegrityError`` when no automatic candidate verifies. Either way
    nothing is installed, because the caller installs only what this returns.
    """
    if requested is not None:
        return _explicit(fossils, lineage, requested, refused)
    excluded = {from_digest, *refused}
    ordered = sorted(enumerate(fossils.fossils()),
                     key=lambda pair: (pair[1].created_sequence, pair[0]), reverse=True)
    rest = [f.artifact_hash for _, f in ordered if f.artifact_hash not in excluded]
    skipped: list[str] = []
    corrupt = False
    for artifact in dict.fromkeys([*preferred, *rest]):
        if artifact == from_digest:
            continue
        try:
            state = verified_fossil(fossils, lineage, artifact)
        except FossilIntegrityError:
            skipped.append(artifact)
            corrupt = True
            continue
        except LineageError:
            skipped.append(artifact)
            continue
        return RestoreTarget(artifact, state, tuple(skipped), corrupt)
    raise FossilIntegrityError(f"no retained fossil verifies (skipped {skipped}); "
                               "the trusted state is unchanged")
