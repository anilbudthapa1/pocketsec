"""The strict JSON reading layer of ``KnowledgeCapsuleV1``: exact keys, exact types, no coercion.

A capsule arrives as foreign bytes, so its reader must give one byte string exactly one
meaning: a JSON ``1.0`` is not an integer, ``true`` is not ``1``, a numeric string is not a
number, a duplicated key is refused rather than last-one-wins, and ``NaN``/``Infinity``/
``1e999`` are refused rather than parsed. These readers are generic — they know no capsule
field — so the schema module (``capsule/knowledge_capsule.py``) composes them into its
per-record parser table, and nothing here can drift from that table.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from enum import StrEnum
from typing import Any, TypeVar

from pocketsec.stage0.contracts.common import ContractError

__all__ = [
    "Parser",
    "enum_of",
    "exact_keys",
    "finite_float",
    "json_enum",
    "json_float",
    "json_int",
    "json_list",
    "json_str",
    "key_text",
    "optional_of",
    "refuse_duplicate_keys",
    "tuple_of",
]

#: A field reader: ``(raw JSON value, where) -> parsed value``; raises ``ContractError``.
Parser = Callable[[object, str], Any]
_E = TypeVar("_E", bound=StrEnum)


def exact_keys(payload: object, keys: frozenset[str], where: str) -> Mapping[str, Any]:
    if not isinstance(payload, Mapping):
        raise ContractError(f"{where} must be an object, got {type(payload).__name__}")
    if set(payload) != keys:
        missing = sorted(keys - set(payload))
        extra = sorted(key_text(k) for k in set(payload) - keys)
        raise ContractError(f"{where}: missing keys {missing}, unexpected keys {extra}")
    return payload


def json_int(value: object, where: str) -> int:
    if type(value) is not int:  # a bool, a float 1.0 or a numeric string is not an int
        raise ContractError(f"{where} must be a JSON integer, got {value!r}")
    return value


def json_float(value: object, where: str) -> float:
    if type(value) is not float:  # a JSON int is not a float
        raise ContractError(f"{where} must be a JSON float, got {value!r}")
    return value


def json_str(value: object, where: str) -> str:
    if not isinstance(value, str):
        raise ContractError(f"{where} must be a string, got {type(value).__name__}")
    return value


def json_list(value: object, where: str) -> Sequence[Any]:
    if not isinstance(value, (list, tuple)):
        raise ContractError(f"{where} must be an array, got {type(value).__name__}")
    return value


def json_enum(enum_type: type[_E], value: object, where: str) -> _E:
    text = json_str(value, where)
    try:
        return enum_type(text)
    except ValueError:
        raise ContractError(f"{where}: unknown {enum_type.__name__} {text!r}") from None


def enum_of(enum_type: type[StrEnum]) -> Parser:
    return lambda value, where: json_enum(enum_type, value, where)


def tuple_of(parse: Parser, *, length: int | None = None) -> Parser:
    def parse_all(value: object, where: str) -> tuple[Any, ...]:
        items = json_list(value, where)
        if length is not None and len(items) != length:
            raise ContractError(f"{where} must hold exactly {length} items")
        return tuple(parse(item, f"{where}[{i}]") for i, item in enumerate(items))

    return parse_all


def optional_of(parse: Parser) -> Parser:
    return lambda value, where: None if value is None else parse(value, where)


def refuse_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Two values for one key would give one byte string two readings."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate key {key!r}")
        result[key] = value
    return result


def finite_float(text: str) -> float:
    """``parse_float`` and ``parse_constant``: ``1e999``, ``NaN`` and ``Infinity`` refused."""
    value = float(text)
    if value != value or value in (float("inf"), float("-inf")):
        raise ContractError(f"non-finite JSON number {text!r}")
    return value


def key_text(key: object) -> str:
    """A key as text for an error message (a non-string key is shown by ``repr``)."""
    return key if isinstance(key, str) else repr(key)
