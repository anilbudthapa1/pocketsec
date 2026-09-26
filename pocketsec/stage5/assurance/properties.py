"""D5.18 — the executor properties, split honestly into proven, tested and unmeasured.

Stage 3 shipped ADR-0022 under the title *"five properties proven, four only tested"*.
That is the discipline this module enforces in code rather than in a document: every
safety-critical executor property is one of three things, the type refuses to let a
row be mislabelled, and the counts are whatever they honestly turn out to be.

**The three kinds, and what each one costs to claim.**

* ``PROVEN_BY_CONSTRUCTION`` requires a ``construction`` — a dotted path that must
  resolve to a real symbol — **and** a ``mutation``: the exact edit that makes the
  property fail. A property whose mutation breaks nothing is not proven, it is merely
  untested in an interesting way; the out-of-package mutation test fails for it and the
  row must be downgraded to ``TESTED``. Naming the mutation is what makes the claim
  falsifiable.
* ``TESTED`` requires a ``test_name`` and **may not use verification language**. The
  word "verified" may not describe a property whose only evidence is that no test broke
  it, and :func:`ExecutorProperty.__post_init__` raises on a statement that tries.
* ``UNMEASURED`` requires a ``why_not``. An unmeasured property with no reason is a
  to-do list entry wearing a result's clothes.

**Why the word check is word-boundary matched.** A bare substring search reports
"provenance" as a claim that something is "proven" and "unverified" as a claim that it
is "verified" — and the second inverts the sentence's meaning. A check that cries wolf
on its own vocabulary gets switched off, and then the real claims go unchecked. The
technique is ``stage3/gate_criteria.py``'s, deliberately: two implementations of one
rule is how S2-AUTH-01 stayed open in neither.

**What this module does not claim.** It does not run the mutations — the out-of-package
test ``tests/test_stage5_gate.py::test_every_mutation_edit_breaks_its_named_test`` does,
from :data:`MUTATION_EDITS` and :data:`SENSITIVITY_EDITS` — and it does not assert that the
named tests pass. G5.13's in-process run is a *behavioural* check of each proven row, not a
replay of these edits (finding F2: an earlier version patched the very surface each probe
read, so it could not report a surviving mutation). This module asserts that each row is
*shaped* like the claim it makes, and that every construction path resolves to something
real. A table whose paths do not resolve is a table of
aspirations, and Stage 4's ``theory.py`` learned the same lesson for its own bindings.
"""

from __future__ import annotations

import importlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import ContractError

__all__ = [
    "BACKING_WINDOW_LINES",
    "DOWNGRADED",
    "EXECUTOR_PROPERTIES",
    "MUTATION_EDITS",
    "PROPERTIES_BY_ID",
    "SENSITIVITY_EDITS",
    "VERIFICATION_WORDS",
    "AssuranceKind",
    "ExecutorProperty",
    "construction_paths",
    "counts",
    "mutated_source",
    "proven",
    "resolve_construction",
    "tested",
    "unearned_verification_language",
    "unmeasured",
    "unresolvable_constructions",
]


class AssuranceKind(StrEnum):
    """Three kinds, and the distance between them is the deliverable."""

    PROVEN_BY_CONSTRUCTION = "PROVEN_BY_CONSTRUCTION"
    TESTED = "TESTED"
    UNMEASURED = "UNMEASURED"


#: Words that assert more than "we tested it".
VERIFICATION_WORDS: frozenset[str] = frozenset({"proven", "verified", "formally", "guaranteed"})

#: How many lines either side of a verification word may carry its backing. Three, the
#: same window ``stage3/gate_criteria.py`` uses, so a table row whose surrounding prose
#: cites its producer passes and a bare assertion does not.
BACKING_WINDOW_LINES: int = 3

_WORD_RE = re.compile(r"\b(" + "|".join(sorted(VERIFICATION_WORDS)) + r")\b", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class ExecutorProperty:
    """One safety-critical property, and the exact evidence behind it."""

    property_id: str
    statement: str
    kind: AssuranceKind
    construction: str
    mutation: str
    test_name: str
    why_not: str

    def __post_init__(self) -> None:
        if not self.property_id or not self.statement.strip():
            raise ContractError("ExecutorProperty needs an id and a statement")
        self._require_evidence()
        self._refuse_unearned_language()

    def _require_evidence(self) -> None:
        """Each kind's evidence is required, so a row cannot claim more than it holds."""
        match self.kind:
            case AssuranceKind.PROVEN_BY_CONSTRUCTION:
                missing = [
                    name for name in ("construction", "mutation") if not getattr(self, name).strip()
                ]
                if missing:
                    raise ContractError(
                        f"{self.property_id} claims PROVEN_BY_CONSTRUCTION with no {missing}; a "
                        "construction nobody can point at and an edit nobody can make is a "
                        "claim, not a proof"
                    )
            case AssuranceKind.TESTED:
                if not self.test_name.strip():
                    raise ContractError(
                        f"{self.property_id} claims TESTED with no test_name; the evidence for a "
                        "tested property is the test"
                    )
            case AssuranceKind.UNMEASURED:
                if not self.why_not.strip():
                    raise ContractError(
                        f"{self.property_id} is UNMEASURED with no why_not; an unmeasured "
                        "property with no reason is a to-do list entry wearing a result's clothes"
                    )

    def _refuse_unearned_language(self) -> None:
        """A TESTED or UNMEASURED statement may not call itself proven."""
        if self.kind is AssuranceKind.PROVEN_BY_CONSTRUCTION:
            return
        found = sorted({match.group(1).lower() for match in _WORD_RE.finditer(self.statement)})
        if found:
            raise ContractError(
                f"{self.property_id} is {self.kind.value} and its statement uses {found}; the "
                "word 'verified' may not describe a property whose only evidence is that no "
                "test broke it"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "property_id": self.property_id,
            "statement": self.statement,
            "kind": self.kind.value,
            "construction": self.construction,
            "mutation": self.mutation,
            "test_name": self.test_name,
            "why_not": self.why_not,
        }


_ALGEBRA = "pocketsec.stage5.operators.algebra"
_TX = "pocketsec.stage5.executor.transactional"

#: P1 … P15. The spec's target split was 9 PROVEN_BY_CONSTRUCTION / 4 TESTED / 2
#: UNMEASURED. The integrator's table read 8 / 5 / 2 (P3 downgraded); the fix wave of
#: 2026-09-26 downgraded P1 and P2 as well (:data:`DOWNGRADED`), so the table now reads
#: **6 / 7 / 2**. :func:`counts` reports whatever the table holds, and ADR-0042's addendum
#: records the real numbers, whichever way they fall.
EXECUTOR_PROPERTIES: tuple[ExecutorProperty, ...] = (
    # DOWNGRADED from PROVEN_BY_CONSTRUCTION (finding F5-honesty). The annotation is not
    # type-checked by any gate, so the only enforcement is _refuse_untyped, a runtime
    # check that can be deleted; its evidence is therefore a test, and SENSITIVITY_EDITS
    # records that deleting the guard breaks that test.
    ExecutorProperty(
        "P1",
        "the executor's entry point refuses anything but a catalog-bound DefensiveOperator "
        "with a TypeError or ContractError raised by _refuse_untyped, before any host call",
        AssuranceKind.TESTED,
        "",
        "",
        "tests/test_stage5_executor.py::test_a_string_cannot_reach_the_executor",
        "",
    ),
    # DOWNGRADED from PROVEN_BY_CONSTRUCTION (finding S5-SEC-09). The scan is static: it
    # now also sees aliased os/posix/nt imports, __import__, a literal import_module of a
    # launcher root and getattr on an os alias, but a dynamic import_module(name) with a
    # computed name — which four Stage 5 modules use for lazy exports and bindings — is
    # not decidable by it. Absence under dynamic dispatch is tested, not proven.
    ExecutorProperty(
        "P2",
        "the static scan no_arbitrary_command_path finds no subprocess, pty, posix, "
        "ctypes, asyncio or multiprocessing import, no os/posix process call under any "
        "alias, no eval, exec, compile or __import__, and no literal import of a launcher "
        "root anywhere under pocketsec/stage5/",
        AssuranceKind.TESTED,
        "",
        "",
        "tests/test_stage5_boundary.py::test_no_arbitrary_command_path_exists_under_stage5",
        "",
    ),
    # DOWNGRADED from PROVEN_BY_CONSTRUCTION — see DOWNGRADED below. Its stated mutation
    # (add ``str`` to the ArgvAtom union) was applied in a scratch copy and the named test
    # still passed: the construction it relied on is only detected by ``mypy --strict``,
    # which is not installed in this environment and has never run in this repository.
    ExecutorProperty(
        "P3",
        "no string reaches argument assembly: assemble_argv refuses any atom that is not a "
        "LiteralAtom or a FieldAtom before its match, and every token it emits passes the "
        "literal-atom pattern",
        AssuranceKind.TESTED,
        "",
        "",
        "tests/test_stage5_operators.py::test_assemble_argv_refuses_a_string_atom",
        "",
    ),
    ExecutorProperty(
        "P4",
        "authority cannot escalate: every operator class maps to one authority class "
        "and GrantSource has no MODEL member",
        AssuranceKind.PROVEN_BY_CONSTRUCTION,
        "pocketsec.stage5.authority.capability:AUTHORITY_BY_OPERATOR_CLASS",
        "remove one mapping from AUTHORITY_BY_OPERATOR_CLASS, so the module-level "
        "totality assert fails at import",
        "tests/test_stage5_foundation.py::"
        "test_the_authority_and_autonomy_tables_are_total_over_operator_class",
        "",
    ),
    ExecutorProperty(
        "P5",
        "no O7_DESTRUCTIVE operator can be constructed: the catalog holds no O7 entry and "
        "a DefensiveOperator accepts only a catalog entry by identity",
        AssuranceKind.PROVEN_BY_CONSTRUCTION,
        "pocketsec.stage5.operators.catalog:CATALOG_BY_CLASS",
        "add an O7 entry to the catalog (MUTATION_EDITS['P5']). Measured: the import then "
        "fails on the simulated host's handler-agreement guard, and with that guard also "
        "removed the empty-class test still fails. The catalog itself does not refuse an "
        "O7 entry, so the construction is 'none exists and identity is required', not "
        "'the catalog cannot hold one'",
        "tests/test_stage5_operators.py::test_o7_has_no_catalog_entries",
        "",
    ),
    ExecutorProperty(
        "P6",
        "SENTINEL has no bypass: three constructor parameters and no caller-supplied "
        "switch, a raising check denies rather than abstains, and a PASS verdict cannot "
        "be built unless every _check_ method the kernel defines was evaluated",
        AssuranceKind.PROVEN_BY_CONSTRUCTION,
        "pocketsec.stage5.sentinel.kernel:SentinelKernel",
        "add a module-level switch that makes SentinelKernel._run return PASS before any "
        "check runs (the finding F2/F4 bypass), so the 182-case denial matrix passes a "
        "non-compliant input",
        "tests/test_stage5_sentinel.py::"
        "test_sentinel_denies_every_operator_on_every_non_compliant_input",
        "",
    ),
    ExecutorProperty(
        "P7",
        "lease expiry is a pure function of the lease's own frozen fields",
        AssuranceKind.PROVEN_BY_CONSTRUCTION,
        "pocketsec.stage5.executor.lease:Lease.expired",
        "read a registry attribute inside Lease.expired, so the ManualClock test that "
        "never calls the registry fails",
        "tests/test_stage5_executor.py::test_a_lease_is_expired_by_data_not_by_a_call",
        "",
    ),
    ExecutorProperty(
        "P8",
        "COMMIT is unreachable without an evidence-preservation bundle",
        AssuranceKind.PROVEN_BY_CONSTRUCTION,
        f"{_TX}:TransactionalExecutor",
        "give _commit's bundle parameter a None default, so the required-positional "
        "test and mypy --strict both fail",
        "tests/test_stage5_executor.py::test_commit_requires_a_preservation_bundle_positionally",
        "",
    ),
    ExecutorProperty(
        "P9",
        "every transaction receipt states whether its host was simulated",
        AssuranceKind.PROVEN_BY_CONSTRUCTION,
        f"{_TX}:TransactionReceipt",
        "give TransactionReceipt.simulated a default, so a receipt can omit it and the "
        "host_kind cross-check in __post_init__ stops being reachable",
        "tests/test_stage5_benchmarks.py::"
        "test_a_transaction_receipt_cannot_omit_whether_it_was_simulated",
        "",
    ),
    ExecutorProperty(
        "P10",
        "the rollback protocol restores the pre-action state inside the simulated host, "
        "at injected rollback failure rates of 0.0, 0.1 and 0.5",
        AssuranceKind.TESTED,
        "",
        "",
        "tests/test_stage5_executor.py::test_rollback_restores_the_pre_action_snapshot",
        "",
    ),
    ExecutorProperty(
        "P11",
        "a redeemed capability token cannot be redeemed again within the last 256 "
        "tokens, which is where MAX_SPENT_NONCES bounds the claim",
        AssuranceKind.TESTED,
        "",
        "",
        "tests/test_stage5_foundation.py::test_a_redeemed_token_is_single_use",
        "",
    ),
    ExecutorProperty(
        "P12",
        "target identity is revalidated immediately before the host call, with no "
        "intervening call in _commit's body",
        AssuranceKind.TESTED,
        "",
        "",
        "tests/test_stage5_executor.py::test_identity_is_revalidated_inside_commit",
        "",
    ),
    ExecutorProperty(
        "P13",
        "evidence lineage survives every transaction: each receipt resolves to a digest "
        "the pre-action bundle carried",
        AssuranceKind.TESTED,
        "",
        "",
        "tests/test_stage5_benchmarks.py::test_every_receipt_resolves_to_a_digest_in_the_bundle",
        "",
    ),
    ExecutorProperty(
        "P14",
        "rollback reliability against a real Linux host",
        AssuranceKind.UNMEASURED,
        "",
        "",
        "",
        "no real host, no real telemetry, and no RealHost implementation exists by "
        "design (ADR-0046). What would measure it: paired containment and restore "
        "drills on an instrumented Linux host with injected ground-truth actions, at "
        "eight or more repetitions per operator per kernel version",
    ),
    ExecutorProperty(
        "P15",
        "security effectiveness of any operator",
        AssuranceKind.UNMEASURED,
        "",
        "",
        "",
        "every corpus in this repository is synthetic and the harm model is authored by "
        "the same wave as the planner (§6.1, §9.2), so a containment rate measured here "
        "is a property of those tables. What would measure it: response outcomes on "
        "real telemetry with independently established ground truth",
    ),
)

PROPERTIES_BY_ID: Mapping[str, ExecutorProperty] = MappingProxyType(
    {row.property_id: row for row in EXECUTOR_PROPERTIES}
)

#: Rows the spec targeted as PROVEN_BY_CONSTRUCTION that are recorded as TESTED, and why.
#: A downgrade is a result, so it is data the findings can quote rather than a comment.
DOWNGRADED: Mapping[str, str] = MappingProxyType(
    {
        "P1": (
            "fix wave 2026-09-26 (finding F5-honesty): the construction named was "
            "TransactionalExecutor.execute, but its annotation is never type-checked "
            "(mypy --strict is not in the gate) and its stated mutation edited "
            "DefensiveOperator.__post_init__, not the entry. Deleting _refuse_untyped in a "
            "scratch copy left the named test passing, because it accepted AttributeError. "
            "The only enforcement at the entry is that runtime check, so the row is TESTED; "
            "the named test no longer accepts AttributeError and SENSITIVITY_EDITS['P1'] "
            "deletes the guard"
        ),
        "P2": (
            "fix wave 2026-09-26 (finding S5-SEC-09): the scan was a lexical denylist that "
            "missed 'import os as o; o.system', posix.system, __import__('subprocess'), "
            "getattr(os, 'system') and asyncio.create_subprocess_shell. Those are now "
            "detected, but importlib.import_module(name) with a computed name is used by "
            "four Stage 5 modules and a static scan cannot decide where it leads"
        ),
        "P3": (
            "the stated mutation — add str to the ArgvAtom union — was applied to a scratch "
            "copy and tests/test_stage5_operators.py::test_assemble_argv_refuses_a_string_atom "
            "still passed, because the runtime guard is the isinstance check before the match, "
            "not the union; the construction's own detector is mypy --strict, which is not "
            "installed here and has never run in this repository"
        ),
    }
)

#: Each PROVEN_BY_CONSTRUCTION row's mutation as an exact edit: ``(repo-relative path,
#: anchor, replacement)``. ``anchor`` must occur exactly once in today's source, and
#: :func:`mutated_source` refuses otherwise, so a refactor elsewhere that moves the
#: construction makes the mutation fail loudly rather than silently become a no-op.
#: ``None`` as the anchor means "append". P7's edit makes ``expired`` read a flag only
#: something outside the lease could set — the concrete form of "expiry waits for
#: somebody to call in".
#:
#: Each edit is exercised out of package by ``tests/test_stage5_gate.py::
#: test_every_mutation_edit_breaks_its_named_test``: the row's ``test_name`` must pass on
#: an unmutated scratch copy and fail on the mutated one. Nothing in this package runs
#: them — trust rule P2 forbids a process launcher under ``pocketsec/stage5/`` — and
#: G5.13's in-process run is a separate behavioural check, not a replay of these edits.
MUTATION_EDITS: Mapping[str, tuple[str, str | None, str]] = MappingProxyType(
    {
        "P4": (
            "pocketsec/stage5/authority/capability.py",
            "        OperatorClass.O3_SUSPEND: AuthorityClass.A2,\n",
            "",
        ),
        "P5": (
            "pocketsec/stage5/operators/catalog.py",
            '    _entry(\n        operator_id="TERMINATE_PROCESS",',
            '    _entry(\n        operator_id="WIPE_HOST",\n'
            "        operator_class=OperatorClass.O7_DESTRUCTIVE,\n"
            "        target_kind=TargetKind.PROCESS,\n"
            '        argv_template=(LiteralAtom("host.wipe"), FieldAtom(TargetField.PID)),\n'
            "        rollback_operator_id=None,\n"
            "        reversibility=Reversibility.IRREVERSIBLE,\n"
            "        evidence_effect=EvidenceEffect.DESTROYS,\n"
            "        authority=AuthorityClass.AX,\n"
            "        preconditions=_INTERVENTION_PRECONDITIONS,\n"
            "        postconditions=(PostconditionKind.TRAJECTORY_REDUCED,),\n"
            "        max_duration_seconds=60,\n"
            "    ),\n"
            '    _entry(\n        operator_id="TERMINATE_PROCESS",',
        ),
        "P6": (
            "pocketsec/stage5/sentinel/kernel.py",
            "    def _run(self, request: _Request, operator_id: str, target_digest: str) -> "
            "SentinelVerdict:\n",
            "    def _run(self, request: _Request, operator_id: str, target_digest: str) -> "
            "SentinelVerdict:\n        if not globals().get('ENFORCING', False):\n"
            "            return SentinelVerdict(Decision.PASS, (), 'off', operator_id, "
            "target_digest, CHECK_ORDER)\n",
        ),
        "P7": (
            "pocketsec/stage5/executor/lease.py",
            "        return now >= self.expires_at() or now >= self.hard_deadline()",
            "        return bool(getattr(self, '_swept_by_registry', False)) and (now >= "
            "self.expires_at() or now >= self.hard_deadline())",
        ),
        "P8": (
            "pocketsec/stage5/executor/transactional.py",
            "def _commit(self, operator: DefensiveOperator, bundle: PreActionBundle) -> HostEffect:",
            "def _commit(self, operator: DefensiveOperator, bundle: PreActionBundle | None = None) "
            "-> HostEffect:",
        ),
        "P9": (
            "pocketsec/stage5/executor/transactional.py",
            "    simulated: bool\n    work_units: int",
            "    simulated: bool = __import__('dataclasses').field(default=True, kw_only=True)\n"
            "    work_units: int",
        ),
    }
)


#: TESTED rows whose named test has been shown to notice the edit that removes the
#: behaviour. Not a proof — the row stays TESTED — but a test nobody has tried to break
#: is weaker evidence than one that fails when the guard it names is deleted. Same shape
#: and same out-of-package run as :data:`MUTATION_EDITS`.
SENSITIVITY_EDITS: Mapping[str, tuple[str, str | None, str]] = MappingProxyType(
    {
        "P1": (
            "pocketsec/stage5/executor/transactional.py",
            "        _refuse_untyped(operator, token)\n",
            "        pass  # sensitivity edit P1: the entry guard deleted\n",
        ),
        "P2": (
            "pocketsec/stage5/governor.py",
            None,
            "\nimport os as _o  # sensitivity edit P2\n_launch = _o.system\n",
        ),
    }
)


def mutated_source(property_id: str, source: str) -> str:
    """``source`` with ``property_id``'s mutation applied, or a refusal.

    Refuses an unknown row, and an anchor that is absent or ambiguous: a mutation that
    edits nothing would leave the test passing and read as "not broken". Proven rows
    carry a :data:`MUTATION_EDITS` entry; some TESTED rows a :data:`SENSITIVITY_EDITS` one.
    """
    edits = {**SENSITIVITY_EDITS, **MUTATION_EDITS}
    if property_id not in edits:
        raise ContractError(
            f"{property_id} has no mutation edit; only proven rows and sensitivity-checked "
            "tested rows carry one"
        )
    _path, anchor, replacement = edits[property_id]
    if anchor is None:
        return source + replacement
    found = source.count(anchor)
    if found != 1:
        raise ContractError(
            f"{property_id}'s mutation anchor occurs {found} times; the construction moved and "
            "the mutation must be rewritten before the property can be called proven"
        )
    return source.replace(anchor, replacement, 1)


def proven() -> tuple[ExecutorProperty, ...]:
    return tuple(
        row for row in EXECUTOR_PROPERTIES if row.kind is AssuranceKind.PROVEN_BY_CONSTRUCTION
    )


def tested() -> tuple[ExecutorProperty, ...]:
    return tuple(row for row in EXECUTOR_PROPERTIES if row.kind is AssuranceKind.TESTED)


def unmeasured() -> tuple[ExecutorProperty, ...]:
    return tuple(row for row in EXECUTOR_PROPERTIES if row.kind is AssuranceKind.UNMEASURED)


def counts() -> Mapping[str, int]:
    """The three counts, for the findings table. Whatever they honestly are."""
    return MappingProxyType(
        {
            AssuranceKind.PROVEN_BY_CONSTRUCTION.value: len(proven()),
            AssuranceKind.TESTED.value: len(tested()),
            AssuranceKind.UNMEASURED.value: len(unmeasured()),
            "TOTAL": len(EXECUTOR_PROPERTIES),
        }
    )


def resolve_construction(path: str) -> object:
    """Resolve ``module.path:Symbol`` or ``module.path:Class.member`` to a live object.

    Raises rather than returning ``None``, because "missing" and "bound to None" must
    stay distinguishable — the same reason Stage 4's ``theory.resolve_binding`` raises.
    """
    if ":" not in path:
        raise ContractError(f"construction {path!r} must be 'module.path:Symbol'")
    module_name, _, attribute_path = path.partition(":")
    target: object = importlib.import_module(module_name)
    for attribute in attribute_path.split("."):
        target = getattr(target, attribute)
    return target


def construction_paths() -> tuple[str, ...]:
    """Every non-empty construction path in the table, in table order."""
    return tuple(row.construction for row in EXECUTOR_PROPERTIES if row.construction)


def unresolvable_constructions() -> tuple[str, ...]:
    """Construction paths that do not resolve. ``()`` is the property G5.13 asserts."""
    broken: list[str] = []
    for path in construction_paths():
        try:
            resolve_construction(path)
        except (ImportError, AttributeError, ContractError):
            broken.append(path)
    return tuple(broken)


def unearned_verification_language(text: str) -> tuple[str, ...]:
    """Every verification word in ``text`` with no construction path nearby backing it.

    "Nearby" is :data:`BACKING_WINDOW_LINES` lines either side, and the backing is the
    literal presence of a path this table names — so a findings row that says "proven"
    beside the construction it rests on passes, and one that says it on its own does
    not. Returned as ``line:word`` so a reader can go straight to the claim.
    """
    lines = text.splitlines()
    paths = construction_paths()
    offenders: list[str] = []
    for number, line in enumerate(lines):
        matches = sorted({match.group(1).lower() for match in _WORD_RE.finditer(line)})
        if not matches:
            continue
        low = max(0, number - BACKING_WINDOW_LINES)
        high = min(len(lines), number + BACKING_WINDOW_LINES + 1)
        window = "\n".join(lines[low:high])
        if any(path in window for path in paths):
            continue
        offenders.extend(f"{number + 1}:{word}" for word in matches)
    return tuple(offenders)


def _row_ids() -> Sequence[str]:
    return [f"P{index}" for index in range(1, len(EXECUTOR_PROPERTIES) + 1)]


assert [row.property_id for row in EXECUTOR_PROPERTIES] == list(_row_ids()), (
    "EXECUTOR_PROPERTIES must be P1..Pn dense and in order; a gap is a property somebody "
    "removed without saying so"
)
assert len(PROPERTIES_BY_ID) == len(EXECUTOR_PROPERTIES), "property ids must be unique"
