"""ARGUS [SUPPLY_CHAIN]: three tamperings of a genome artefact, each of which must be refused.

A tampering is only evidence about a defence if the defence is what refused it. So the
attacker's artefact is built OUTSIDE the refusal under test: an artefact the attacker cannot
build, or one refused for some other reason, is a trial that did not exercise the defence
and counts as NOT refused (S9-R3). ``argus.adversary`` re-exports :func:`tampered_genome`,
which is the runner name the lifecycle catalogue records.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage9.argus.findings import DEFENCE, ArgusFinding, ArgusSurface
from pocketsec.stage9.chemistry.typed_ir import IRNode, IRProgram, IRType, NodeKind
from pocketsec.stage9.foundry.primitives import SEED_ALPHABET
from pocketsec.stage9.genome.computational import ComputationalGenomeV1

__all__ = ["tampered_genome"]


def _first_apply(program: IRProgram) -> int | None:
    for index, node in enumerate(program.nodes):
        if node.kind is NodeKind.APPLY and node.args:
            return index
    return None


def _swapped_primitive(name: str) -> str | None:
    """Another seed primitive with the same signature, so only the digest can tell.

    ``None`` when there is none (COUNT, SELECT, DECAY, B2F, the side-table primitives...):
    falling back to an arbitrary primitive built an ill-typed genome whose IRError was then
    counted as the digest check refusing it (S9-R3).
    """
    original = SEED_ALPHABET.get(name)
    if original.macro is not None:
        return None  # a macro call site is bound to ``macro_uses``; swapping it is not silent
    signature = (original.arg_types, original.result_type, original.side_table)
    for other in SEED_ALPHABET.names():
        candidate = SEED_ALPHABET.get(other)
        if other != name and candidate.macro is None and (
            candidate.arg_types, candidate.result_type, candidate.side_table
        ) == signature:
            return other
    return None


def _swap_an_apply(program: IRProgram) -> IRProgram | None:
    """The first APPLY node that HAS a same-signature partner, swapped; else ``None``."""
    for index, node in enumerate(program.nodes):
        if node.kind is not NodeKind.APPLY or not node.args:
            continue
        other = _swapped_primitive(node.primitive)
        if other is not None:
            nodes = list(program.nodes)
            nodes[index] = replace(node, primitive=other)
            return replace(program, nodes=tuple(nodes))
    return None


def _changed_init(value: float | int | bool, type_: IRType) -> float | int | bool:
    """A different, in-range init: flipped BOOL, low bit of an INT, 0.0 <-> 1.0 for FLOAT."""
    if type_ is IRType.BOOL:
        return not value
    if type_ is IRType.INT:
        return int(value) ^ 1
    return 0.0 if value else 1.0


def _semantic_swap(genome: ComputationalGenomeV1) -> ComputationalGenomeV1:
    """A well-typed change: a same-signature primitive swap, else a register init change."""
    update = _swap_an_apply(genome.update)
    if update is not None:
        return replace(genome, update=update)
    readout = _swap_an_apply(genome.readout)
    if readout is not None:
        return replace(genome, readout=readout)
    first = genome.registers[0]
    registers = (replace(first, init=_changed_init(first.init, first.type)), *genome.registers[1:])
    return replace(genome, registers=registers)


class _TrialNotConstructed(Exception):
    """The attacker's own artefact could not be built, or was refused for another reason.

    Deliberately NOT a ``ContractError``: ``tampered_genome`` counts it as a trial that did
    not exercise the defence, never as a refusal (S9-R3).
    """


def _forward_reference(genome: ComputationalGenomeV1) -> ComputationalGenomeV1:
    """An APPLY argument pointed at a later node: a loop, which the IR cannot express."""
    program = genome.update
    index = _first_apply(program)
    nodes = list(program.nodes)
    if index is None:
        nodes.append(
            IRNode(kind=NodeKind.APPLY, type=IRType.FLOAT, primitive="ABS", args=(len(nodes) + 1,))
        )
    else:
        node = nodes[index]
        nodes[index] = replace(node, args=(index + 1, *node.args[1:]))
    return replace(genome, update=replace(program, nodes=tuple(nodes)))


def _trial_digest_kept(genome: ComputationalGenomeV1) -> tuple[bool, str]:
    # Build the tampered artefact OUTSIDE the refusal being tested: a ContractError here is
    # the attacker failing, not the digest check succeeding (S9-R3).
    try:
        swapped = _semantic_swap(genome)
        payload = swapped.to_dict()
    except ContractError as error:
        raise _TrialNotConstructed(
            f"tampered artefact not constructible ({type(error).__name__}: {error}); the "
            "digest check never ran"
        ) from error
    if swapped.digest == genome.digest:
        return False, "the swap did not change the genome's content: not a tampering"
    payload["digest"] = genome.digest  # the attacker keeps the trusted digest
    try:
        ComputationalGenomeV1.from_dict(payload)
    except ContractError as error:
        if "digest mismatch" in str(error):
            raise  # the designed refusal: the content no longer matches the digest
        raise _TrialNotConstructed(
            f"refused, but not by the digest check ({type(error).__name__}: {error})"
        ) from error
    return False, "a same-signature swap carrying the original digest was ACCEPTED"


def _trial_forward_reference(genome: ComputationalGenomeV1) -> tuple[bool, str]:
    _forward_reference(genome)
    return False, "an APPLY argument pointing forward was ACCEPTED"


def _trial_bound_understated(genome: ComputationalGenomeV1) -> tuple[bool, str]:
    understated = genome.bounds.max_steps_per_event - 1
    replace(genome, declared_max_steps_per_event=understated)
    return False, f"declared_max_steps_per_event={understated} (understated) was ACCEPTED"


_TAMPERINGS: tuple[tuple[str, Callable[[ComputationalGenomeV1], tuple[bool, str]]], ...] = (
    ("op_swap_digest_kept", _trial_digest_kept),
    ("arg_forward_reference", _trial_forward_reference),
    ("declared_bound_understated", _trial_bound_understated),
)


def tampered_genome(genome: ComputationalGenomeV1) -> ArgusFinding:
    """[SUPPLY_CHAIN] Three tamperings; each must raise ``ContractError`` (IRError is one).

    1. a same-signature primitive swap (else a register-init change) re-serialised with the
       ORIGINAL digest — the IR accepts the program, so only the digest check can refuse it,
       and only a ``digest mismatch`` refusal counts;
    2. an APPLY argument turned into a forward reference — a loop, refused by the IR;
    3. ``declared_max_steps_per_event`` set below the computed static bound.
    Any other exception, or none, is not a designed refusal and counts as not refused; so
    does a tampered artefact the attacker could not build (the defence never ran).
    """
    outcomes: list[str] = []
    refused = 0
    for name, trial in _TAMPERINGS:
        try:
            _, reason = trial(genome)
        except ContractError as error:
            refused += 1
            outcomes.append(f"{name}: refused ({type(error).__name__}: {error})")
        except Exception as error:
            outcomes.append(f"{name}: NOT a designed refusal ({type(error).__name__}: {error})")
        else:
            outcomes.append(f"{name}: {reason}")
    return ArgusFinding(
        attack_id="tampered_genome",
        surface=ArgusSurface.SUPPLY_CHAIN,
        kind=DEFENCE,
        fired=refused,
        total=len(_TAMPERINGS),
        inert=refused == 0,
        metric_before=None,
        metric_after=None,
        detail="; ".join(outcomes),
        measured_by="argus.adversary:tampered_genome",
    )
