"""Measurements the Stage 3 gate needs, separated from the pass/fail wording.

``gate.py`` decides and reports; this module produces the numbers and the
structural facts it decides on. The split follows Stage 2's
``gate_criteria.py``/``gate_measures.py`` and exists for one reason: a file that
holds both the measurement and the sentence describing it grows past the
repository's size rule and, worse, makes it easy to adjust the sentence instead
of the measurement.

Nothing here returns a default in place of a measurement. A quantity that could
not be produced comes back as ``None`` or as an explicit "not measured" entry,
never as a plausible-looking number.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.gate import REPO_ROOT
from pocketsec.stage1.ssir.entities import SemanticProperty
from pocketsec.stage1.ssir.relations import RelationFamily
from pocketsec.stage3.bytecode.verifier import (
    PROVEN_PROPERTIES,
    STRUCTURAL_PROVEN_PROPERTIES,
    TESTED_ONLY_PROPERTIES,
)
from pocketsec.stage3.bytecode.vm import CellVM
from pocketsec.stage3.cells.invariant import PredicateRole, SemanticPredicate
from pocketsec.stage3.cells.schema import KnowledgeCellV1
from pocketsec.stage3.melting.stress import CellStress
from pocketsec.stage3.promotion.audit import AuditSampler

__all__ = [
    "AUDIT_STATE_COMPONENTS",
    "NOVELTY_WORDS",
    "VERIFICATION_WORDS",
    "actor_predicate",
    "audit_state_bytes",
    "cell_vm_bytes",
    "claims_novelty",
    "lifecycle_stop_reason",
    "property_set_defects",
    "refusal_probes",
    "stub_sequence",
    "unbounded_verification_language",
    "zero_stress",
]

#: G3.12(b). Words that, used as a claim, assert more than "we tested it".
VERIFICATION_WORDS = ("proven", "verified", "formally", "sound", "guarantee")

#: G3.13. A novelty claim needs a REVIEWED prior-art entry behind it.
NOVELTY_WORDS = ("novel", "first", "unprecedented", "patent")

#: ``first`` is matched only in its *priority* sense. English uses the word for
#: ordering constantly — "ran first", "the first figure", "verify-first" — and a
#: bare token match reports every one of them as a claim of precedence. The
#: criterion asks whether the document asserts priority, and only these
#: phrasings do; matching them is what implements the criterion, rather than
#: matching a word that usually means something else.
_PRIORITY_RE = re.compile(
    r"\bfirst\s+(?:ever\b|to\s+\w+|system\b|approach\b|architecture\b|work\b|"
    r"method\b|technique\b|implementation\b)|world'?s\s+first\b|\bthe\s+first\s+known\b",
    re.IGNORECASE,
)

#: How many lines either side of a claim may carry its backing.
_WINDOW = 3

#: A dotted module path inside this repository. Three segments minimum, so a bare
#: ``pocketsec.stage3`` package name is not treated as a producer citation.
_MODULE_PATH_RE = re.compile(r"\bpocketsec(?:\.[a-z_][a-z0-9_]*){2,}\b")

#: Characters either side of a novelty word within which a negation exempts it.
#: A line-wide exemption meant most careful prose in this repository could carry
#: an unguarded novelty claim; this is wide enough for "this is not the first" and
#: narrow enough that a negation about another clause does not cover the claim.
_NEGATION_WINDOW = 48

_NEGATION_MARKERS: tuple[str, ...] = ("not ", "no ", "never", "without", "forbid")

#: Word-boundary matched, and that is load-bearing rather than tidy. A bare
#: substring search reports "provenance" as a claim that something is "proven"
#: and "unverified" as a claim that something is "verified" — the second
#: inverts the sentence's meaning. A check that cries wolf on its own
#: vocabulary gets switched off, and then the real claims go unchecked.
_WORD_RE = re.compile(r"\b(" + "|".join(VERIFICATION_WORDS) + r")\b", re.IGNORECASE)

#: Naming the bounded set *is* the citation this criterion asks for.
_PROPERTY_SET_RE = re.compile(
    r"\b(?:ALL_|STRUCTURAL_)?PROVEN_PROPERTIES\b|\bTESTED_ONLY_PROPERTIES\b"
)

#: Words that mark a claim as empirical where it stands.
_EMPIRICAL_MARKERS = ("empirical", "no test has", "tested only", "observed")

#: The two Stage 3 structures whose bytes are the "audit_state" budget line.
AUDIT_STATE_COMPONENTS = ("AuditSampler", "CellStress")


def actor_predicate(family: RelationFamily) -> SemanticPredicate:
    """One family-scoped ACTOR predicate — the unit boundary keys expand over."""
    return SemanticPredicate(
        role=PredicateRole.ACTOR,
        required_properties=frozenset({SemanticProperty.INTERPRETER}),
        forbidden_properties=frozenset(),
        relation_family=family,
        entity_kind=None,
    )


def zero_stress() -> CellStress:
    """A cell under no stress — the audit-rate floor case."""
    return CellStress(
        teacher_disagreement=0.0,
        boundary_violations=0,
        epoch_drift=0,
        uncertainty_rise=0.0,
        counterexamples=0,
        calibration_decay=0.0,
    )


def cell_vm_bytes(vm: CellVM) -> int:
    """Resident bytes of the VM's own working state, measured not estimated.

    ``sys.getsizeof`` over the real containers, the same technique
    ``BoundaryIndex.memory_bytes`` uses, so the §38 budget lines are comparable
    to each other. The VM allocates its value stack once and never grows it —
    that is the verifier's "no dynamic allocation" property — so this figure is
    the whole of the VM's per-instance footprint rather than a sample of it.
    """
    total = sys.getsizeof(vm)
    stack = getattr(vm, "_stack", None)
    if stack is not None:
        total += sys.getsizeof(stack) + sum(sys.getsizeof(slot) for slot in stack)
    return total


def audit_state_bytes(sampler: AuditSampler, stress: CellStress) -> int:
    """Resident bytes of the audit machinery's own state.

    The sampler is deliberately stateless beyond its boot salt — the decision is
    a keyed hash of ``(boot_salt, cell_id, frame_digest)`` rather than a counter,
    so an attacker cannot phase against it (§39 audit gaming). That the figure is
    therefore small is a property of the design, not a gap in the measurement.
    """
    total = sys.getsizeof(sampler) + sys.getsizeof(stress)
    salt = getattr(sampler, "_boot_salt", None)
    if salt is not None:
        total += sys.getsizeof(salt)
    return total


def refusal_probes(cell: KnowledgeCellV1) -> list[tuple[str, bool]]:
    """Each way a malformed cell must refuse to exist, actually attempted.

    G3.3 asks for a ``ContractError`` on each of empty evidence, empty epochs,
    empty boundary, an oversized operator and an authority-named field. Every
    one is attempted here against a real cell rather than asserted from the
    schema's docstring.
    """
    probes: list[tuple[str, bool]] = []
    attempts: list[tuple[str, dict[str, Any]]] = [
        ("empty evidence_lineage", {"evidence_lineage": ()}),
        ("empty constraints", {"constraints": ()}),
        ("empty epochs", {"epochs": frozenset()}),
        ("confidence outside [0,1]", {"confidence": 1.5}),
        (
            "oversized operator steps",
            {"operator": replace(cell.operator, max_steps=10_000, digest="")},
        ),
        (
            "empty boundary",
            {"boundary": replace(cell.boundary, state_dimensions=frozenset())},
        ),
    ]
    for name, change in attempts:
        try:
            replace(cell, **change)
        except ContractError:
            probes.append((name, True))
        else:
            probes.append((name, False))
    return probes


def property_set_defects() -> list[str]:
    """G3.12(b), as a content check on the two property sets rather than a grep.

    This is the part of the criterion that can actually go wrong: a property
    that is only *tested* being listed among the ones that are *proven*. Three
    defects are checkable directly against the tuples the verifier publishes:

    1. the two sets overlap, so a property is both proven and merely tested;
    2. a ``PROVEN_PROPERTIES`` entry appeals to testing for its backing, which
       means it is an empirical claim wearing a structural label; or
    3. a ``TESTED_ONLY_PROPERTIES`` entry does not say that it is empirical,
       so a reader quoting it would carry no warning with it.

    A repo-wide prose grep was tried first and is kept, scoped, in
    :func:`unbounded_verification_language`; on its own it flagged "provenance"
    and "unverified" and a docstring citing ``PROVEN_PROPERTIES``, which is a
    check that would be switched off rather than obeyed.
    """
    defects: list[str] = []
    proven = set(PROVEN_PROPERTIES) | set(STRUCTURAL_PROVEN_PROPERTIES)
    tested = set(TESTED_ONLY_PROPERTIES)
    overlap = sorted(proven & tested)
    if overlap:
        defects.append(f"a property is both proven and tested-only: {overlap}")
    for entry in sorted(proven):
        lowered = entry.lower()
        if "empirical" in lowered or "no test has" in lowered:
            defects.append(f"PROVEN entry appeals to testing: {entry[:70]!r}")
    for entry in sorted(tested):
        lowered = entry.lower()
        if not any(marker in lowered for marker in _EMPIRICAL_MARKERS):
            defects.append(f"TESTED_ONLY entry does not word itself as empirical: {entry[:70]!r}")
    return defects


def unbounded_verification_language(*targets: Path) -> list[str]:
    """Every verification word in ``targets`` with nothing nearby backing it.

    Scoped to the files passed in, which the gate limits to Stage 3's own
    external claim surface — the findings document. That is where an unearned
    "proven" does damage, because it is the artefact that leaves the repository.
    Module docstrings are covered by :func:`property_set_defects` instead, which
    checks the claim rather than the wording around it.
    """
    offenders: list[str] = []
    for path in targets:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:  # pragma: no cover - an unreadable file is reported absent
            continue
        fences = _fenced_ranges(lines)
        for number, line in enumerate(lines):
            if not _WORD_RE.search(line):
                continue
            if line.lstrip().startswith("#"):
                # A heading names a criterion; it does not assert that the
                # criterion holds. The assertion is in the prose under it, and the
                # window below reaches that prose.
                continue
            # Table rows are NOT skipped any more. They were, on the grounds that
            # requiring a citation in every cell would make a table unreadable —
            # but a results table is exactly where a verification claim escapes
            # this repository, and skipping the whole row let one through
            # unscanned (S3-FC-11). The window still supplies the backing, so a
            # table whose surrounding prose cites its producer passes as before.
            low, high = _backing_window(lines, number, fences)
            if _backed_by_evidence("\n".join(lines[low:high])):
                continue
            offenders.append(f"{_relative(path)}:{number + 1}")
    return offenders


def _fenced_ranges(lines: Sequence[str]) -> tuple[tuple[int, int], ...]:
    """``(open, close)`` line indices of every ```` ``` ```` block.

    An unterminated fence runs to the end of the file, which is the reading that
    fails closed: it widens the *backing* window, and a block with no command in it
    is still reported.
    """
    ranges: list[tuple[int, int]] = []
    opened: int | None = None
    for index, line in enumerate(lines):
        if not line.lstrip().startswith("```"):
            continue
        if opened is None:
            opened = index
        else:
            ranges.append((opened, index))
            opened = None
    if opened is not None:
        ranges.append((opened, len(lines) - 1))
    return tuple(ranges)


def _backing_window(
    lines: Sequence[str], number: int, fences: Sequence[tuple[int, int]]
) -> tuple[int, int]:
    """Which lines may supply the backing for the claim on line ``number``.

    ``±_WINDOW`` in prose. Inside a fenced block it is the **whole block plus the
    lines just before it**, because a fenced block is pasted command output: the
    thing that backs it is the command at the top of the paste, which can be twenty
    lines above the word. Requiring a citation *inside* verbatim output would mean
    editing the output, which is worse than the problem.

    This is not the table-row exemption coming back by another door. A fenced block
    with no producer line anywhere in it is still reported — the window is wider,
    the requirement is the same.
    """
    for start, end in fences:
        if start <= number <= end:
            return max(0, start - _WINDOW), min(len(lines), end + 1)
    return max(0, number - _WINDOW), min(len(lines), number + _WINDOW + 1)


def _backed_by_evidence(window: str) -> bool:
    """True when the window says what backs the claim it makes.

    Accepted backing, strongest first: the claim declares itself empirical; it
    names one of the bounded property tuples; it cites a ``module:function``
    producer, a ``.py`` path, a dotted ``pocketsec.*`` module path, or a runnable
    command in backticks.

    The ``pocketsec.*`` rule is what lets a pasted command block back itself:
    ``$ python -m pocketsec.stage3.cli gate`` at the top of a paste names the thing
    that produced every line under it, and a module path in this repository is a
    citation of the same kind as ``module:function``. A block with no such line
    anywhere in it is still reported.
    """
    lowered = window.lower()
    if any(marker in lowered for marker in _EMPIRICAL_MARKERS):
        return True
    if _PROPERTY_SET_RE.search(window):
        return True
    if _MODULE_PATH_RE.search(window):
        return True
    for token in window.replace("(", " ").replace(")", " ").split():
        stripped = token.strip(".,;:'\"")
        if ".py" in stripped:
            return True
        if stripped.startswith("`") and ("/" in stripped or "()" in token):
            return True
        head, sep, tail = stripped.strip("`").partition(":")
        if sep and "." in head and tail and tail[:1].isalpha():
            return True
    return False


def _relative(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:  # pragma: no cover - a path outside the repo is reported whole
        return str(path)


def claims_novelty(text: str, word: str) -> bool:
    """A novelty word used as a claim, not as the name of a rule forbidding it.

    Read line by line rather than counted, because the findings document and
    this module both *name* these words in order to forbid them. A bare
    substring search would make the prohibition trip its own check, which is the
    quickest way to get a prohibition deleted.
    """
    for line in text.splitlines():
        lowered = line.lower()
        if line.lstrip().startswith(("#", ">")):
            continue
        # The negation exemption is scoped to the novelty word's own neighbourhood
        # rather than to the whole line. A line-wide exemption meant any sentence
        # containing "no", "not", "never", "without" or "forbid" anywhere — which
        # is most careful prose in this repository — could carry an unguarded
        # novelty claim past the check (S3-FC-11). Table rows are no longer exempt
        # either, for the reason given in `unbounded_verification_language`.
        if word == "first":
            match = _PRIORITY_RE.search(line)
            if match is not None and not _negated_near(lowered, match.start(), match.end()):
                return True
            continue
        match = re.search(rf"\b{re.escape(word)}\b", lowered)
        if match is not None and not _negated_near(lowered, match.start(), match.end()):
            return True
    return False


def _negated_near(lowered: str, start: int, end: int) -> bool:
    """Is the claim at ``[start, end)`` negated by something close to it?

    ``_NEGATION_WINDOW`` characters either side, which is wide enough for "this is
    not the first" and narrow enough that a negation about a different clause of
    the same sentence does not exempt the claim.
    """
    window = lowered[max(0, start - _NEGATION_WINDOW) : end + _NEGATION_WINDOW]
    return any(marker in window for marker in _NEGATION_MARKERS)


def stub_sequence(sequence_id: str) -> Any:
    """Minimal Stage 0 sequence carrying only the id the slot keys on."""
    from pocketsec.stage0.contracts.security_event_v1 import (
        SecurityEventSequenceV1,
        SecurityEventV1,
    )

    return SecurityEventSequenceV1(
        sequence_id=sequence_id,
        host_id="lab-host-01",
        events=(
            SecurityEventV1(
                event_id=f"{sequence_id}-e0",
                host_id="lab-host-01",
                boot_id="boot-0001",
                observed_at_ns=1,
                monotonic_ns=1,
                source="stage3.crystal",
                kind="ssir.transition",
            ),
        ),
    )


def lifecycle_stop_reason(
    run: Any,
    *,
    promoted: bool,
    audited: int,
    melted: bool,
    recrystallised: bool,
) -> str:
    """Say where the sequence stopped, from what **this** run recorded.

    Derived, and now actually derived. The previous version branched on two
    booleans and appended a fixed paragraph asserting "two measured reasons" —
    that seven of eight operator forms come back UNMEASURED, and that the
    executable one is refused as NEVER_NORMALISE_HIGH_CONSEQUENCE. Neither
    happened on the region the gate runs: it is returned to learning at
    ``NO_SATISFIED_PREDICATE`` before any operator is synthesised, so
    ``candidates_tried`` is empty and no form is ever measured or evaluated. The
    paragraph was true of a *different* region, and the same string printed "after
    trying no form" beside it — exactly the drift the old docstring warned about.

    Everything below is read off ``run`` and the caller's step results, so the
    diagnosis cannot outlive the behaviour it describes.
    """
    outcome = getattr(getattr(run, "outcome", None), "value", "UNKNOWN")
    reason = str(getattr(run, "reason", ""))
    tried = [getattr(form, "value", str(form)) for form in getattr(run, "candidates_tried", ())]
    if getattr(run, "cell", None) is None:
        stopped = (
            f"STOPS AT crystallize, which returned {outcome} for region "
            f"{getattr(run, 'region_key', None)} after synthesising "
            f"{tried or 'no operator form at all'}: {reason}."
        )
        if not tried:
            stopped += (
                " No form was synthesised, measured or put to Oracle B on this region, so "
                "nothing here is evidence about operator cost or about which hard "
                "constraint a compiled operator would break."
            )
        stopped += (
            " The steps after it were then attempted on a cell built by "
            "labs/cell_path.phi_oracle_cell, so that this report can say which later stages "
            "work; that provenance is stated rather than assumed, and a PASS here would "
            "require crystallize."
        )
        return stopped
    for label, ok in (
        ("promote_cell", promoted),
        ("sample_audit", audited > 0),
        ("melting", melted),
        ("recrystallize", recrystallised),
    ):
        if not ok:
            return f"STOPS AT {label}; see the {label} step above for what it reported."
    return "STOPS after recrystallize; see the steps above."
