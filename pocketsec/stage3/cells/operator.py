"""D3.5 (part) — ``OperatorProgram``: the bounded executable form of a cell.

``Omega`` in ``K_i = (I, B, Omega, Gamma, E, Q, X, A, V)``. Every operator
declares its own step and state bounds *as data*, so the verifier and the VM can
check them statically before anything runs, and so a cell's cost is attributable
to a named artefact rather than to "the model".

``OperatorForm`` lists eight forms. ``RESIDUAL_MICRO_MODEL`` — which the
architecture (§13) offers as the fallback "only when symbolic/executable
compression fails" — is **deliberately absent** this wave. It requires a weights
blob and a numpy producer; Stage 3 ships no ``research/`` package and imports no
third-party module (ADR-0020), so there is no honest way to produce one here.
ADR-0021 records the omission as a decision rather than an oversight: if
symbolic compression fails, this wave's answer is that the region does not
crystallise, not that it crystallises into something unverifiable.

The digest is recomputed at construction and compared against any digest handed
in. A program whose stored digest disagrees with its own bytes is refused, so a
cell cannot carry a stale or forged operator identity across a reload.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    digest_of_bytes,
    require_non_negative_int,
)
from pocketsec.stage2.compile_candidates.candidate import (
    forbidden_authority_keys,
    require_json_payload,
)

__all__ = [
    "CONSTANT_KEY_PREFIX",
    "MAX_CELL_STEPS",
    "MAX_OPERATOR_STATE_BYTES",
    "MAX_OPERATOR_TABLE_ENTRIES",
    "MAX_OPERATOR_WORDS",
    "OperatorForm",
    "OperatorProgram",
    "SET_KEY_PREFIX",
]

#: The only table-key prefixes a BYTECODE program may use, because they are the
#: only ones the ISA reads and the verifier range-checks. Defined here rather
#: than in ``bytecode/isa.py`` for the same reason ``MAX_CELL_STEPS`` is: the
#: work-package order (spec §5) has ``bytecode`` depending on ``foundation``, so
#: the shared vocabulary lives on the foundation side and ``isa.py`` imports and
#: re-exports it. Two independent spellings of ``"const."`` would be a constant
#: pool that silently loads empty.
CONSTANT_KEY_PREFIX = "const."
SET_KEY_PREFIX = "set."

#: Hard step cap for any cell operator. ``bytecode/isa.py`` declares the same
#: number as ``MAX_INSTRUCTIONS``; it must import this constant rather than
#: redefine it, or the schema and the VM could disagree about what "bounded"
#: means. Defined here because ``foundation`` may not depend on ``bytecode``.
MAX_CELL_STEPS = 64

#: Ceiling on declared per-execution scratch state. The 2 GB host target is a
#: hard constraint and a field of 512 cells must stay bounded in aggregate.
MAX_OPERATOR_STATE_BYTES = 4096

#: Table and word-array caps. A "compiled" artefact larger than these is not a
#: compression of the learned path, it is a copy of the training data.
MAX_OPERATOR_TABLE_ENTRIES = 1024
MAX_OPERATOR_WORDS = 512

_UINT32_CEILING = 1 << 32


class OperatorForm(StrEnum):
    """The executable shapes a Knowledge Cell may take (architecture §13)."""

    CONSTANT = "CONSTANT"
    LOOKUP_TABLE = "LOOKUP_TABLE"
    BITSET_PREDICATE = "BITSET_PREDICATE"
    DECISION_DAG = "DECISION_DAG"
    FSM_FRAGMENT = "FSM_FRAGMENT"
    WEIGHTED_TRANSITION = "WEIGHTED_TRANSITION"
    LINEAR_EXPRESSION = "LINEAR_EXPRESSION"
    BYTECODE = "BYTECODE"


@dataclass(frozen=True, slots=True)
class OperatorProgram:
    """One bounded operator, as plain data. Called ``CellBytecode`` by the plan."""

    form: OperatorForm
    words: tuple[int, ...]
    table: Mapping[str, float]
    max_steps: int
    max_state_bytes: int
    digest: str = field(default="")

    def __post_init__(self) -> None:
        if not isinstance(self.form, OperatorForm):
            raise ContractError(f"OperatorProgram.form must be an OperatorForm, got {self.form!r}")
        object.__setattr__(self, "words", _require_words(self.words))
        object.__setattr__(self, "table", _require_table(self.table))
        self._require_form_shape()
        require_non_negative_int(self.max_steps, "OperatorProgram.max_steps")
        if self.max_steps < 1:
            raise ContractError(
                "OperatorProgram.max_steps must be >= 1; an operator that may take zero "
                "steps cannot produce an answer and would silently abstain"
            )
        require_non_negative_int(self.max_state_bytes, "OperatorProgram.max_state_bytes")
        if self.max_state_bytes > MAX_OPERATOR_STATE_BYTES:
            raise ContractError(
                f"OperatorProgram.max_state_bytes {self.max_state_bytes} is above "
                f"MAX_OPERATOR_STATE_BYTES={MAX_OPERATOR_STATE_BYTES}"
            )
        self._bind_digest()

    def _require_form_shape(self) -> None:
        """Keep each form's payload where the VM expects to find it.

        A BYTECODE program *may* carry a table, and it must be nothing but the
        constant and set-literal pools. This rule originally refused a table on a
        BYTECODE program outright, on the reasoning that "the VM reads constants
        from the program, and a second data path would be unverified". That was
        measurably wrong about where the VM reads: ``bytecode/isa.py`` pulls both
        pools out of ``program.table`` via ``load_constants``/``load_sets``, and
        the verifier range-checks every ``LOAD_CONST`` and ``IN_SET`` operand
        against the loaded pool length. The table *is* the verified data path.

        The cost of the contradiction was not cosmetic: with the table forced
        empty, the constant pool was always length 0, so ``LOAD_CONST`` could
        never pass its range check, ``IN_SET`` could never name a set, and the
        bounded enumerative synthesiser could not emit a literal at all.

        The original rule's *intent* — no second, unverified data path — is kept
        by refusing any key the ISA does not recognise, rather than by refusing
        the table. An unrecognised key would be data the verifier never looks at.
        """
        if self.form is OperatorForm.BYTECODE:
            if not self.words:
                raise ContractError("OperatorProgram of form BYTECODE must carry words")
            unknown = sorted(
                key
                for key in self.table
                if not (
                    key.startswith(CONSTANT_KEY_PREFIX) or key.startswith(SET_KEY_PREFIX)
                )
            )
            if unknown:
                raise ContractError(
                    f"OperatorProgram of form BYTECODE carries table keys the ISA does not "
                    f"read: {unknown}. Only {CONSTANT_KEY_PREFIX!r} and {SET_KEY_PREFIX!r} "
                    "entries are verified; anything else is an unverified data path"
                )
            return
        if self.words:
            raise ContractError(
                f"OperatorProgram of form {self.form.value} must have empty words; only "
                "BYTECODE is executed by the VM"
            )

    def _bind_digest(self) -> None:
        computed = digest_of_bytes(self._canonical_bytes())
        if self.digest and self.digest != computed:
            raise ContractError(
                f"OperatorProgram.digest {self.digest!r} does not match its own bytes "
                f"({computed!r}); a stale operator identity would survive a reload unnoticed"
            )
        object.__setattr__(self, "digest", computed)

    def _canonical_bytes(self) -> bytes:
        payload = {
            "form": self.form.value,
            "words": list(self.words),
            "table": dict(self.table),
        }
        return json.dumps(payload, sort_keys=True, allow_nan=False, separators=(",", ":")).encode(
            "utf-8"
        )

    def size_bytes(self) -> int:
        """Resident size of the operator's own data, in canonical form.

        Measured from the bytes, not estimated from a parameter count: G3.9
        compares a cell's bytes against the Φ-oracle's directly, and an
        estimated denominator would make that comparison meaningless.
        """
        return len(self._canonical_bytes())

    def to_dict(self) -> dict[str, Any]:
        return {
            "form": self.form.value,
            "words": list(self.words),
            "table": dict(self.table),
            "max_steps": self.max_steps,
            "max_state_bytes": self.max_state_bytes,
            "digest": self.digest,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> OperatorProgram:
        try:
            return cls(
                form=OperatorForm(str(payload["form"])),
                words=tuple(int(word) for word in payload["words"]),
                table={str(key): float(value) for key, value in payload["table"].items()},
                max_steps=int(payload["max_steps"]),
                max_state_bytes=int(payload["max_state_bytes"]),
                digest=str(payload.get("digest", "")),
            )
        except KeyError as exc:
            raise ContractError(f"OperatorProgram missing field {exc.args[0]!r}") from exc
        except (AttributeError, OverflowError, TypeError, ValueError) as exc:
            # OverflowError because ``float()`` raises it — not ValueError — on an
            # out-of-range int in the table, and a deserialisation boundary that
            # leaks a non-ContractError escapes every caller's guard.
            raise ContractError(f"OperatorProgram could not be rebuilt: {exc}") from exc


def _require_words(value: object) -> tuple[int, ...]:
    if not isinstance(value, tuple):
        raise ContractError(
            f"OperatorProgram.words must be a tuple, got {type(value).__name__}"
        )
    if len(value) > MAX_OPERATOR_WORDS:
        raise ContractError(
            f"OperatorProgram.words holds {len(value)} words, above "
            f"MAX_OPERATOR_WORDS={MAX_OPERATOR_WORDS}"
        )
    for word in value:
        if not isinstance(word, int) or isinstance(word, bool):
            raise ContractError(f"OperatorProgram.words entries must be ints, got {word!r}")
        if not 0 <= word < _UINT32_CEILING:
            raise ContractError(
                f"OperatorProgram.words entries must fit in a uint32, got {word!r}"
            )
    return value


def _require_table(value: object) -> Mapping[str, float]:
    """Normalise the table through JSON, exactly as ``CompileCandidateV1`` does.

    ``allow_nan=False`` inside ``require_json_payload`` is the point: a table
    carrying a NaN score would serialise here and fail at every other seam.
    Authority-named keys are refused for the same reason a candidate payload
    refuses them — a compiled artefact may not name an action (ADR-0003).
    """
    if not isinstance(value, Mapping):
        raise ContractError(
            f"OperatorProgram.table must be a mapping, got {type(value).__name__}"
        )
    if len(value) > MAX_OPERATOR_TABLE_ENTRIES:
        raise ContractError(
            f"OperatorProgram.table holds {len(value)} entries, above "
            f"MAX_OPERATOR_TABLE_ENTRIES={MAX_OPERATOR_TABLE_ENTRIES}"
        )
    for key, entry in value.items():
        if isinstance(entry, bool) or not isinstance(entry, (int, float)):
            raise ContractError(
                f"OperatorProgram.table[{key!r}] must be a number, got {entry!r}"
            )
    normalised = require_json_payload(
        {str(key): float(entry) for key, entry in value.items()},
        field="OperatorProgram.table",
    )
    offenders = forbidden_authority_keys(normalised, prefix="OperatorProgram.table")
    if offenders:
        raise ContractError(
            f"OperatorProgram.table carries response-authority key names {list(offenders)}; "
            "a compiled artefact may not name an action (ADR-0003)"
        )
    return normalised
