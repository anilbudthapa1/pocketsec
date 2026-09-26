"""D7.3 / ORPH-F04 — the Privacy Distiller: exactly what may leave the host, by field.

Stage 7 is where host knowledge first crosses a host boundary, so "raw data stays local"
is not a property it may assume; it has to be a property the export path *cannot*
violate. This module holds the three pieces that make it so:

* **The export field table** (:data:`EXPORT_FIELD_TABLE`, ADR-0065). Every wire key path
  of ``KnowledgeCapsuleV1.to_dict()`` is declared here with a disclosure class and the
  reason it is allowed out. A path not in the table is an undeclared field and cannot
  leave (:func:`undeclared_wire_paths`); a table row no knowledge type emits is a stale
  declaration and a test fails on it. The table is a disclosure, not a promise of
  secrecy: ``software_epoch`` is linkable across hosts that share an image,
  ``contributor`` links every capsule one host sends in one scope, ``role`` and
  ``family_profile`` are disclosed by design. They are declared so that nobody can later
  claim they were hidden.
* **Generalisation** (:func:`distil_context`, :func:`software_epoch_class`,
  :func:`contributor_pseudonym`, :func:`evidence_commitment`). Host facts are coarsened
  (3-level visibility, 4-level family shares), hashed (software image) or keyed with the
  host secret (pseudonym, evidence commitments) before they are allowed near the wire.
  A commitment is ``HMAC(host_secret, "evidence:" + digest)``: a peer who guesses an
  evidence digest cannot test it against the capsule without the host's secret, and the
  contributor can later open the commitment. That is a keyed commitment, not
  authentication of anything: HMAC proves key possession, never host identity.
* **The constructive residual screen** (:func:`residual_identifier_hits`). Every string
  value on the wire must fit the closed vocabulary ``WIRE_STRING_SHAPES`` (ids, enum
  values, a semver) and must not match Stage 6's secret screen. A path, user name,
  address, command line, raw ``sha256:`` digest, Stage 6 ``cap-``/``grp-`` id or clear
  ``SystemIdentity`` field is not a shape the wire admits, so it cannot leave IN CLEAR
  even if a later edit tries to put it there. **It is a shape check, not a content check
  (review finding S7-AUTH-09):** hex fields the receiver cannot verify
  (``evidence_commitments``, ``provenance_root``, ``software_epoch`` and the like) would
  carry a HEX-ENCODED path or name straight through both this screen and the canary scan.
  What keeps them clean is the compiler that fills them (keyed HMACs and hashes), not this
  screen. :func:`canary_hits` is the empirical cross-check: the labs plant canaries in every
  raw field and search every exported byte for them (in clear, not hex-encoded).

What this module refuses to do: it never exports ``EncodedStep`` features, time buckets,
ΔΦ, source groups, signatures or labels (none has a table row), it never claims
differential privacy for a capsule (DP is claimed only for the population count release
in :mod:`pocketsec.stage7.privacy.ledger`), and it never widens the vocabulary to make a
value fit — a string that does not fit is a hit, and the compiler refuses the capsule.

Stdlib only. Stage 6 names used: ``SECRET_PATTERN`` (the one secret screen, ADR-0061).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_finite_unit_interval,
    require_identifier,
)
from pocketsec.stage1.epoch.model import SystemIdentity
from pocketsec.stage1.ssir.relations import RelationFamily
from pocketsec.stage6.capsule.experience_capsule import SECRET_PATTERN
from pocketsec.stage7.capsule.knowledge_capsule import (
    FAMILY_PROFILE_LEVELS,
    WIRE_STRING_SHAPES,
    EpochContext,
    RoleClass,
    SourceContextSketch,
    VisibilityClass,
)

__all__ = [
    "EXPORT_FIELD_TABLE",
    "FAMILY_LEVEL_EDGES",
    "GENERALISED_FIELDS",
    "MAX_CANARY_REPORT",
    "MIN_HOST_SECRET_BYTES",
    "NULLABLE_RECORDS",
    "VISIBILITY_FULL_AT",
    "VISIBILITY_PARTIAL_AT",
    "Disclosure",
    "DistillationReport",
    "FieldDisclosure",
    "audit_payload",
    "canary_hit_count",
    "canary_hits",
    "contributor_pseudonym",
    "distil_context",
    "evidence_commitment",
    "expected_wire_paths",
    "family_profile",
    "flatten_keys",
    "residual_identifier_hits",
    "software_epoch_class",
    "undeclared_wire_paths",
    "visibility_class",
]

# Chosen parameters (spec D7.3), not measurements.
VISIBILITY_FULL_AT: float = 0.9
VISIBILITY_PARTIAL_AT: float = 0.5
#: Upper edges of family-profile levels 1 and 2; level 0 is exactly 0, level 3 is above.
FAMILY_LEVEL_EDGES: tuple[float, float] = (0.1, 0.4)
#: Canary names one scan reports; the count is always available from canary_hit_count.
MAX_CANARY_REPORT: int = 32
#: The HMAC key floor. Same value as Stage 6's ``MIN_KEY_BYTES`` (128 bits); restated,
#: not imported, because §2.3 admits that name only in identity/ and the bridge.
MIN_HOST_SECRET_BYTES: int = 16

if FAMILY_PROFILE_LEVELS != len(FAMILY_LEVEL_EDGES) + 2:
    # The schema bounds each level at FAMILY_PROFILE_LEVELS - 1; a disagreement would make
    # every sketch fail construction, so fail at import instead.
    raise ContractError(
        f"distiller quantises to {len(FAMILY_LEVEL_EDGES) + 2} levels but the schema "
        f"declares FAMILY_PROFILE_LEVELS={FAMILY_PROFILE_LEVELS}"
    )

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class Disclosure(StrEnum):
    PROTOCOL = "PROTOCOL"
    SEMANTIC_CLASS = "SEMANTIC_CLASS"
    COARSE_CONTEXT = "COARSE_CONTEXT"
    SELF_REPORTED_COUNT = "SELF_REPORTED_COUNT"
    PSEUDONYM = "PSEUDONYM"
    COMMITMENT = "COMMITMENT"


@dataclass(frozen=True, slots=True)
class FieldDisclosure:
    """One wire key path, its disclosure class, and why it may leave."""

    path: str
    disclosure: Disclosure
    rationale: str

    def __post_init__(self) -> None:
        if not isinstance(self.path, str) or not self.path:
            raise ContractError("FieldDisclosure.path must be a non-empty string")
        if not isinstance(self.disclosure, Disclosure):
            raise ContractError(f"FieldDisclosure.disclosure must be a Disclosure: {self.path}")
        if not isinstance(self.rationale, str) or not self.rationale.strip():
            raise ContractError(f"an exported field needs a stated reason: {self.path}")


_P, _S, _C = Disclosure.PROTOCOL, Disclosure.SEMANTIC_CLASS, Disclosure.COARSE_CONTEXT
_R, _N, _M = Disclosure.SELF_REPORTED_COUNT, Disclosure.PSEUDONYM, Disclosure.COMMITMENT

_ROWS: tuple[tuple[str, Disclosure, str], ...] = (
    ("schema_id", _P, "protocol constant"),
    ("schema_version", _P, "protocol constant"),
    ("knowledge_type", _P, "protocol enum"),
    ("stance", _P, "protocol enum"),
    ("capsule_id", _P, "content address of this Stage 7 object"),
    ("signature", _P, "HMAC over the unsigned bytes; proves key possession only"),
    ("key_id", _P, "the signing key's id"),
    ("sequence", _P, "replay counter; reveals this host's export volume (declared)"),
    ("created_round", _P, "exchange round, not a timestamp"),
    ("expiry_round", _P, "exchange round, not a timestamp"),
    ("semantic_invariant", _S,
     "relation id and property/dimension bitmasks only: no path, name, address, uid, "
     "pid, time or count"),
    ("compact_feature_signature", _S, "hash of the invariant"),
    ("causal_motif", _S, "chain-stage class per invariant row"),
    ("epoch_context.software_epoch", _C,
     "unkeyed hash of (kernel_id, package_digest): linkable across hosts sharing an "
     "image, by design (the same-software-image signal)"),
    ("epoch_context.visibility", _C, "3-level visibility class"),
    ("source_context_sketch.role", _C, "role class, disclosed by design (epistemic distance)"),
    ("source_context_sketch.family_profile", _C,
     "4-level quantised share per relation family; a property-inference channel that "
     "the labs measure"),
    ("validation_summary.episodes_replayed", _R, "small self-reported count"),
    ("validation_summary.true_matches", _R, "small self-reported count"),
    ("validation_summary.false_matches", _R, "small self-reported count"),
    ("falsification_summary.mutations_tried", _R, "small self-reported count"),
    ("falsification_summary.mutations_survived", _R, "small self-reported count"),
    ("falsification_summary.counter_hypotheses", _R, "closed-vocabulary hypothesis names"),
    ("provenance_commitment.contributor", _N,
     "HMAC(host_secret, contributor:scope) pseudonym; every capsule from one host in one "
     "scope is linkable, by design (replay and independence need it)"),
    ("provenance_commitment.provenance_root", _N, "declared administrative-domain id"),
    ("independence_group", _N, "equals provenance_root"),
    ("provenance_commitment.evidence_commitments", _M,
     "HMAC(host_secret, evidence:digest) commitments; untestable without the secret"),
    ("provenance_commitment.aggregation_decision", _P, "id of a Stage 7 ECHO decision"),
    ("parent_capsules", _P, "ids of Stage 7 capsules"),
    ("revocation_target", _P, "id of a Stage 7 capsule"),
    ("revocation_ground", _P, "protocol enum"),
    ("time_window", _C, "round interval: the minimum useful resolution, no timestamps"),
    ("observability", _C, "null on every type but NEGATIVE_EVIDENCE"),
    ("observability.expected_observability", _C, "a [0,1] float"),
    ("observability.sensor_health", _C, "a [0,1] float"),
    ("observability.temporal_coverage", _C, "a [0,1] float"),
    ("attack_mappings", _P, "always () in v1 (nothing is evidenced)"),
    ("privacy_class", _P, "always PUBLIC_DERIVED"),
)

#: ADR-0065's by-field table. The ONLY key paths a knowledge capsule may put on the wire.
EXPORT_FIELD_TABLE: Mapping[str, FieldDisclosure] = MappingProxyType(
    {path: FieldDisclosure(path, klass, why) for path, klass, why in _ROWS}
)
if len(EXPORT_FIELD_TABLE) != len(_ROWS):
    raise ContractError("EXPORT_FIELD_TABLE declares a path twice")

#: A record that is null on some knowledge types: when null, the record path itself is
#: the wire leaf; when present, its children are. Nothing else in the schema is optional
#: *as a record* (null scalars are leaves either way).
NULLABLE_RECORDS: Mapping[str, tuple[str, ...]] = MappingProxyType({
    "observability": (
        "observability.expected_observability",
        "observability.sensor_health",
        "observability.temporal_coverage",
    ),
})

#: Wire paths whose value is a generalisation of a host fact, never the fact.
GENERALISED_FIELDS: tuple[str, ...] = (
    "epoch_context.software_epoch",          # SystemIdentity -> unkeyed image hash
    "epoch_context.visibility",              # visibility share -> 3 levels
    "source_context_sketch.family_profile",  # per-family counts -> 4-level shares
    "provenance_commitment.contributor",     # host secret -> scoped pseudonym
    "provenance_commitment.evidence_commitments",  # sha256 digests -> keyed commitments
)


# --- key paths -------------------------------------------------------------------


def _join(prefix: str, key: str) -> str:
    return f"{prefix}.{key}" if prefix else key


def _walk_keys(value: Any, path: str, out: list[str]) -> None:
    if isinstance(value, Mapping):
        if not value:
            out.append(path)
        for key, item in value.items():
            if not isinstance(key, str) or not key:
                raise ContractError(f"wire keys must be non-empty strings, got {key!r} at {path!r}")
            _walk_keys(item, _join(path, key), out)
        return
    if isinstance(value, (list, tuple)):
        # List items share their parent's path: an index is not a field.
        if not value or any(not isinstance(i, (Mapping, list, tuple)) for i in value):
            out.append(path)
        for item in value:
            if isinstance(item, (Mapping, list, tuple)):
                _walk_keys(item, path, out)
        return
    out.append(path)


def flatten_keys(payload: Mapping[str, Any], *, prefix: str = "") -> tuple[str, ...]:
    """Every leaf key path of ``payload`` as ``"a.b"``, sorted and distinct.

    A leaf is any value that is not a non-empty mapping: a scalar, ``None``, a list of
    scalars, or an empty record. List items share their parent's path.
    """
    if not isinstance(payload, Mapping):
        raise ContractError(f"flatten_keys needs a mapping, got {type(payload).__name__}")
    out: list[str] = []
    for key, item in payload.items():
        if not isinstance(key, str) or not key:
            raise ContractError(f"wire keys must be non-empty strings, got {key!r}")
        _walk_keys(item, _join(prefix, key), out)
    return tuple(sorted(set(out)))


def _lookup(payload: Mapping[str, Any], path: str) -> tuple[bool, Any]:
    node: Any = payload
    for part in path.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return False, None
        node = node[part]
    return True, node


def expected_wire_paths(payload: Mapping[str, Any]) -> frozenset[str]:
    """The table's paths this particular payload must carry, given its null records.

    ``flatten_keys(payload) == expected_wire_paths(payload)`` is the exact field check:
    no undeclared path and no declared path missing. It differs from the full table only
    by :data:`NULLABLE_RECORDS` — the schema itself makes ``observability`` null on four
    of five knowledge types, so the literal "every type emits the whole table" cannot
    hold and is not what is checked.
    """
    expected = set(EXPORT_FIELD_TABLE)
    for record, children in NULLABLE_RECORDS.items():
        present, value = _lookup(payload, record)
        if present and value is None:
            expected.difference_update(children)
        else:
            expected.discard(record)
    return frozenset(expected)


def undeclared_wire_paths(payload: Mapping[str, Any]) -> tuple[str, ...]:
    """Key paths in ``payload`` that the export table does not declare. () = none."""
    return tuple(p for p in flatten_keys(payload) if p not in EXPORT_FIELD_TABLE)


# --- generalisation ----------------------------------------------------------------


def _require_secret(host_secret: object) -> bytes:
    if not isinstance(host_secret, bytes) or len(host_secret) < MIN_HOST_SECRET_BYTES:
        raise ContractError(f"host_secret must be >= {MIN_HOST_SECRET_BYTES} bytes")
    return host_secret


def _keyed_hex(host_secret: bytes, message: str) -> str:
    return hmac.new(_require_secret(host_secret), message.encode("utf-8"), hashlib.sha256).hexdigest()


def software_epoch_class(identity: SystemIdentity) -> str:
    """``"se-"`` + 16 hex of sha256(kernel_id | package_digest). Unkeyed: linkable by design."""
    if not isinstance(identity, SystemIdentity):
        raise ContractError(f"software_epoch_class needs a SystemIdentity, got {type(identity)}")
    material = f"{identity.kernel_id}|{identity.package_digest}".encode()
    return "se-" + hashlib.sha256(material).hexdigest()[:16]


def contributor_pseudonym(host_secret: bytes, fleet_scope: str) -> str:
    """``"peer-"`` + 16 hex of HMAC(host_secret, "contributor:" + scope).

    A new scope gives an unlinkable id; within one scope every capsule is linkable.
    """
    require_identifier(fleet_scope, "fleet_scope")
    return "peer-" + _keyed_hex(host_secret, "contributor:" + fleet_scope)[:16]


def evidence_commitment(host_secret: bytes, digest: str) -> str:
    """``"hc-"`` + 32 hex of HMAC(host_secret, "evidence:" + digest). Refuses a non-digest.

    Only a real ``sha256:<64 hex>`` evidence digest is committed: committing to an
    arbitrary string would let a caller launder a path through the commitment slot.
    """
    if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
        raise ContractError(f"evidence_commitment needs a sha256:<64 hex> digest, got {digest!r}")
    return "hc-" + _keyed_hex(host_secret, "evidence:" + digest)[:32]


def visibility_class(visibility_share: float) -> VisibilityClass:
    """FULL >= 0.9, PARTIAL >= 0.5, else LOW (chosen edges)."""
    share = require_finite_unit_interval(visibility_share, "visibility_share")
    if share >= VISIBILITY_FULL_AT:
        return VisibilityClass.FULL
    if share >= VISIBILITY_PARTIAL_AT:
        return VisibilityClass.PARTIAL
    return VisibilityClass.LOW


def _level(share: float) -> int:
    if share <= 0.0:
        return 0
    if share <= FAMILY_LEVEL_EDGES[0]:
        return 1
    if share <= FAMILY_LEVEL_EDGES[1]:
        return 2
    return 3


def family_profile(family_counts: Mapping[int, int]) -> tuple[int, ...]:
    """Per ``RelationFamily``, the 4-level quantised share of local transitions.

    Levels: 0 for exactly 0, 1 for (0, 0.1], 2 for (0.1, 0.4], 3 above 0.4. An unknown
    family index is refused, not dropped: silently discarding a count would change every
    other family's share without saying so.
    """
    if not isinstance(family_counts, Mapping):
        raise ContractError("family_counts must be a mapping of family index -> count")
    width = len(RelationFamily)
    counts = [0] * width
    for key, value in family_counts.items():
        if isinstance(key, bool) or not isinstance(key, int) or not 0 <= key < width:
            raise ContractError(f"family_counts key must be a RelationFamily index, got {key!r}")
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ContractError(f"family_counts[{key}] must be a non-negative int, got {value!r}")
        counts[key] = value
    total = sum(counts)
    if total == 0:
        return (0,) * width
    return tuple(_level(count / total) for count in counts)


def distil_context(
    *,
    identity: SystemIdentity,
    role: RoleClass,
    visibility_share: float,
    family_counts: Mapping[int, int],
) -> tuple[EpochContext, SourceContextSketch]:
    """Coarsen host facts into the two context records a capsule carries."""
    if not isinstance(role, RoleClass):
        raise ContractError(f"role must be a RoleClass, got {role!r}")
    epoch = EpochContext(
        software_epoch=software_epoch_class(identity),
        visibility=visibility_class(visibility_share),
    )
    sketch = SourceContextSketch(role=role, family_profile=family_profile(family_counts))
    return epoch, sketch


# --- the residual screen and canaries ---------------------------------------------


def _screen(value: Any, path: str, out: list[str]) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            _screen(item, f"{path}.{key}", out)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _screen(item, f"{path}[{index}]", out)
    elif isinstance(value, str):
        if not any(shape.fullmatch(value) for shape in WIRE_STRING_SHAPES):
            out.append(f"{path}: outside WIRE_STRING_SHAPES")
        if SECRET_PATTERN.search(value):
            out.append(f"{path}: matches SECRET_PATTERN")
    elif value is None or isinstance(value, (bool, int)):
        return
    elif isinstance(value, float):
        if not math.isfinite(value):
            out.append(f"{path}: non-finite float")
    else:
        out.append(f"{path}: {type(value).__name__} is not plain JSON")


def residual_identifier_hits(payload: object, *, prefix: str = "capsule") -> tuple[str, ...]:
    """Every string value outside ``WIRE_STRING_SHAPES``, plus every secret-screen match.

    The constructive privacy screen: the wire admits a closed vocabulary of shapes, so
    anything host-identifying is a hit by default rather than by enumeration. () = clean.
    """
    out: list[str] = []
    _screen(payload, prefix, out)
    return tuple(out)


def _canary_bytes(canaries: Iterable[str]) -> list[tuple[str, bytes]]:
    pairs: list[tuple[str, bytes]] = []
    for canary in sorted(set(canaries)):
        if not isinstance(canary, str) or not canary:
            # An empty canary matches every blob: a scan with one would report nothing useful.
            raise ContractError(f"a canary must be a non-empty string, got {canary!r}")
        pairs.append((canary, canary.encode("utf-8")))
    return pairs


def canary_hits(blob: bytes, canaries: Iterable[str]) -> tuple[str, ...]:
    """Canaries found in ``blob`` by substring search: at most ``MAX_CANARY_REPORT`` names."""
    if not isinstance(blob, (bytes, bytearray)):
        raise ContractError(f"canary_hits scans bytes, got {type(blob).__name__}")
    found: list[str] = []
    for name, needle in _canary_bytes(canaries):
        if needle in blob:
            found.append(name)
            if len(found) >= MAX_CANARY_REPORT:
                break
    return tuple(found)


def canary_hit_count(blob: bytes, canaries: Iterable[str]) -> int:
    """How many distinct canaries occur in ``blob``; unbounded by the report cap."""
    if not isinstance(blob, (bytes, bytearray)):
        raise ContractError(f"canary_hit_count scans bytes, got {type(blob).__name__}")
    return sum(1 for _, needle in _canary_bytes(canaries) if needle in blob)


@dataclass(frozen=True, slots=True)
class DistillationReport:
    """What the distiller generalised, and what the two screens found (empty = clean)."""

    fields_generalised: tuple[str, ...]
    residual_hits: tuple[str, ...]
    canary_hits: tuple[str, ...]

    @property
    def clean(self) -> bool:
        return not self.residual_hits and not self.canary_hits


def audit_payload(payload: Mapping[str, Any], *, canaries: Iterable[str] = ()) -> DistillationReport:
    """Screen one wire payload: residual shapes, plus canaries over its canonical bytes."""
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return DistillationReport(
        fields_generalised=GENERALISED_FIELDS,
        residual_hits=residual_identifier_hits(payload),
        canary_hits=canary_hits(blob.encode("utf-8"), canaries),
    )
