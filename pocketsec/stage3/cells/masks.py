"""Property bitmasks and the boundary index key — Stage 3's wire-level vocabulary.

A Knowledge Cell must decide, in the cheap path, whether a frame is inside its
boundary. Comparing frozensets of ``SemanticProperty`` per event would put string
hashing on the hot path, so semantics are packed into a 16-bit mask and the
boundary index is keyed on three small integers.

``PROPERTY_ORDER`` is therefore a **wire commitment**, not a convenience: a cell
compiled today stores masks that a later process must decode the same way.
Reordering it silently reinterprets every stored cell, so it is written out as a
literal and the assertion below breaks loudly the moment a property is added.
Appending is the only safe change, and the appended property takes the next bit.
"""

from __future__ import annotations

from collections.abc import Iterable

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.ssir.entities import SemanticProperty

__all__ = [
    "BoundaryKey",
    "PROPERTY_ORDER",
    "PROPERTY_MASK_WIDTH",
    "mask_properties",
    "property_mask",
    "require_property_mask",
]

#: Pinned bit order, sorted by name so a reader can reconstruct it by hand.
#: Index i is bit ``1 << i``.
PROPERTY_ORDER: tuple[SemanticProperty, ...] = (
    SemanticProperty.AUTHORIZATION_DATA,
    SemanticProperty.CREDENTIAL,
    SemanticProperty.CREDENTIAL_READER,
    SemanticProperty.EXTERNAL_ENDPOINT,
    SemanticProperty.INTERPRETER,
    SemanticProperty.NETWORK_CAPABLE,
    SemanticProperty.NETWORK_CLIENT,
    SemanticProperty.NETWORK_SERVER,
    SemanticProperty.PERSISTENCE,
    SemanticProperty.PERSISTENCE_WRITER,
    SemanticProperty.PRIVILEGE_CHANGER,
    SemanticProperty.PROCESS_SPAWNER,
    SemanticProperty.ROOT_OWNED,
    SemanticProperty.SYSTEM_BINARY,
    SemanticProperty.TEMP_LOCATION,
    SemanticProperty.USER_WRITABLE,
)

PROPERTY_MASK_WIDTH = len(PROPERTY_ORDER)

_BIT_OF: dict[SemanticProperty, int] = {
    prop: 1 << index for index, prop in enumerate(PROPERTY_ORDER)
}

#: ``(RelationFamily.value, actor property mask, StateDelta.bitmask())``.
#: Three ints, so a boundary lookup is a tuple hash and nothing else.
BoundaryKey = tuple[int, int, int]


def property_mask(props: Iterable[SemanticProperty]) -> int:
    """Pack semantic properties into the pinned bit order.

    Raises on anything that is not a ``SemanticProperty``: a mask built from a
    bare string would look correct and index the wrong bit forever.
    """
    mask = 0
    for prop in props:
        # `isinstance` first, deliberately: SemanticProperty is a StrEnum, so a
        # bare "INTERPRETER" would hash equal to the member and slip through a
        # dict lookup. A mask built from strings looks right until one is
        # misspelled, and then it silently indexes nothing.
        if not isinstance(prop, SemanticProperty):
            raise ContractError(
                f"property_mask expects SemanticProperty members, got {prop!r}; "
                "PROPERTY_ORDER is a wire commitment and cannot absorb bare strings"
            )
        mask |= _BIT_OF[prop]
    return mask


def mask_properties(mask: int) -> frozenset[SemanticProperty]:
    """Unpack a mask. The inverse of :func:`property_mask` by construction."""
    require_property_mask(mask, "mask")
    return frozenset(prop for prop, bit in _BIT_OF.items() if mask & bit)


def require_property_mask(value: object, field: str) -> int:
    """Refuse a mask with bits set outside ``PROPERTY_ORDER``.

    A stray high bit means the producer used a different property ordering, i.e.
    a different build. Letting it through would make a cell answer for semantics
    it never saw.
    """
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ContractError(f"{field} must be a non-negative int mask, got {value!r}")
    if value >> PROPERTY_MASK_WIDTH:
        raise ContractError(
            f"{field} has bits set above PROPERTY_ORDER width {PROPERTY_MASK_WIDTH}: "
            f"{value:#x}; the mask was built against a different property ordering"
        )
    return value


assert len(PROPERTY_ORDER) == len(SemanticProperty), (
    "PROPERTY_ORDER must cover every SemanticProperty exactly once; adding a "
    "property is a wire change and must append a bit here deliberately"
)
assert len(set(PROPERTY_ORDER)) == len(PROPERTY_ORDER), "PROPERTY_ORDER must not repeat a property"
