"""Two counter-corpora that test what ``response_corpus`` cannot, and why each exists.

Both are **measurement fixtures**, deterministic from their seed, built from the same
private builders as :mod:`pocketsec.stage5.labs.response_corpus` so the identity
arithmetic (rule 1: session-unique ``(pid, start_time_ticks)``) has exactly one copy.
Neither changes any case in ``response_corpus``; each re-hosts or re-resolves cases
that module already knows how to build.

**Why a counter-corpus at all.** Two properties of ``build_response_corpus`` were
measured in the measurement wave (``docs/stage-5-findings.md``, §M):

1. *The fixed playbook's only input carries the label.* The host's
   ``security_state`` is ``_BENIGN_ADMIN_STATE`` (Phi 4.0) on every benign case and
   ``_COMPROMISED_STATE`` (Phi 10.0) on every hostile one, so B2's single
   ``Phi > 6.0`` test is the answer on 20 of 20 cases. A split a one-field rule solves
   exactly cannot show that any mechanism helps (MEMORY.md trap 9).
   :func:`build_decoupled_phi_corpus` keeps every resolution and every ``truth``
   and changes only the host state, on a fixed quarter of each class, so the
   playbook's input and the ground truth disagree there. It does **not** make the
   planner's input noisier: the Stage 4 resolution still leads with the true world,
   which is the corpus author's choice and is stated wherever it is used.
2. *Every ambiguous pair leads with the benign world.* A single-world planner then
   picks the benign world on both halves and is exactly as cautious as the multi-world
   planner, so G5.9's comparison cannot separate them. :func:`build_hostile_leading_pairs`
   is the same indistinguishable pair with the hostile world leading, which is the
   configuration in which committing to the leading world costs collateral.

Neither counter-corpus can make G5.9 satisfiable, and that is stated rather than
designed around: on an indistinguishable pair no operator is sufficient on the
compromised half and harmless on the benign half (``truth`` tables below), so every
policy either acts on both halves or on neither.
"""

from __future__ import annotations

from dataclasses import replace

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage5.executor.identity import ManualClock
from pocketsec.stage5.host.simulated import SimulatedHost
from pocketsec.stage5.labs import response_corpus as rc
from pocketsec.stage5.labs.response_corpus import ResponseCase

__all__ = [
    "COUNTER_CORPORA_VERSION",
    "DECOUPLED_BENIGN_RESIDUE",
    "DECOUPLED_HOSTILE_RESIDUE",
    "DECOUPLING_MODULUS",
    "HOSTILE_LEADING_SUPPORT_GAP",
    "build_decoupled_phi_corpus",
    "build_hostile_leading_pairs",
    "decoupled_indices",
]

COUNTER_CORPORA_VERSION: str = f"stage5-counter-corpora-v0.1.0+{rc.RESPONSE_CORPUS_VERSION}"

#: One case in every ``DECOUPLING_MODULUS`` of each class is re-hosted. A **chosen**
#: fraction, not a measured one: it is large enough that a playbook reading only Phi
#: must lose cases, and small enough that the corpus is still mostly the original.
DECOUPLING_MODULUS: int = 4
#: ``build_response_corpus`` alternates benign (even index) and hostile (odd index), so
#: residue 0 selects one benign case in four and residue 1 one hostile case in four.
DECOUPLED_BENIGN_RESIDUE: int = 0
DECOUPLED_HOSTILE_RESIDUE: int = 1

#: Same gap as the benign-leading pairs, mirrored: the hostile world leads by 0.10,
#: inside ``IDENTIFIABILITY_MARGIN`` (0.15), so the pair is still not separable.
HOSTILE_LEADING_SUPPORT_GAP: float = rc.AMBIGUOUS_SUPPORT_GAP


def decoupled_indices(count: int) -> frozenset[int]:
    """The case indices whose host state contradicts their ``truth``."""
    return frozenset(
        index
        for index in range(count)
        if index % DECOUPLING_MODULUS in (DECOUPLED_BENIGN_RESIDUE, DECOUPLED_HOSTILE_RESIDUE)
    )


def _rehost(case: ResponseCase, *, benign_state: bool) -> ResponseCase:
    """The same case on a host whose security state is the *other* class's fixture."""
    snapshot = case.host.snapshot()
    host = SimulatedHost(
        processes=snapshot.processes,
        services=snapshot.services,
        sessions=snapshot.sessions,
        security_state=rc._BENIGN_ADMIN_STATE if benign_state else rc._COMPROMISED_STATE,
        faults=case.faults,
        clock=ManualClock(at=snapshot.at),
    )
    return replace(case, case_id=f"{case.case_id}-decoupled", host=host)


def build_decoupled_phi_corpus(*, count: int, seed: int) -> tuple[ResponseCase, ...]:
    """``build_response_corpus`` with a quarter of each class re-hosted against its truth.

    A benign-administrator case in :func:`decoupled_indices` runs on a Phi-10 host (an
    administrator holding root, untrusted tooling and a persistence change during
    maintenance); a hostile case there runs on a Phi-4 host (a low-footprint attacker).
    Resolutions, ``truth``, harm models, invariants and fault profiles are untouched, so
    the only input that moved is the one the fixed playbook reads.
    """
    base = rc.build_response_corpus(count=count, seed=seed)
    chosen = decoupled_indices(count)
    return tuple(
        _rehost(case, benign_state=not case.truth.benign_admin) if index in chosen else case
        for index, case in enumerate(base)
    )


def build_hostile_leading_pairs(
    *, count: int, seed: int
) -> tuple[tuple[ResponseCase, ResponseCase], ...]:
    """Indistinguishable benign/compromised pairs whose **hostile** world leads.

    Identical to ``build_ambiguous_pairs`` except for which mechanism the shared
    resolution puts first. Identities come from the ``ambiguous`` builder slice with an
    index offset of ``count`` past the benign-leading pairs' range, so the two pair
    corpora can be run in one process without reusing a ``(pid, start_time_ticks)``.
    """
    rc._require_count(count)
    if 2 * count > rc.MAX_CORPUS_CASES:
        raise ContractError(
            f"count {count} would push the ambiguous slice past MAX_CORPUS_CASES="
            f"{rc.MAX_CORPUS_CASES}; a reused identity erases the signal (rule 1)"
        )
    pairs: list[tuple[ResponseCase, ResponseCase]] = []
    for index in range(count):
        benign_id, hostile_id = rc._world_pair(index, benign=True)
        case_id = f"hlead-{seed:03d}-{index:03d}"
        rows = rc._rows_for(
            "ambiguous",
            count + index,
            seed=seed,
            unit=rc.ORDINARY_UNIT,
            volatile=rc.ORDINARY_VOLATILE,
            session=None,
        )
        resolution = rc._resolution(
            case_id=case_id,
            epoch_id=1,
            leading=hostile_id,
            rival=benign_id,
            gap=HOSTILE_LEADING_SUPPORT_GAP,
            rows=rows,
            uncertainty=0.45,
            identifiability="SEPARABLE",
        )
        faults = rc._faults(seed, index)
        benign_half, compromised_half = (
            rc._pair_member(case_id, resolution, rows, benign_id, hostile_id, faults, benign=benign)
            for benign in (True, False)
        )
        pairs.append((benign_half, compromised_half))
    return tuple(pairs)
