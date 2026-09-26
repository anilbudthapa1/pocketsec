"""D6.19 — the optional fleet knowledge package, IMPORT side only, OFF by default.

Architecture §36-§38: no fleet exchange by default; explicit configuration before
cross-host knowledge moves; reject unsigned and unversioned artefacts; package size
limits; no vote amplification from duplicate or correlated hosts; and **a remote
majority never overrides a local invariant**. This module turns a received package into
capsules and nothing else. Capsules go to ``QuarantineGateway.admit`` like everything
else — they are candidates, never authority — and this module imports neither
``memory/`` stores nor ``promotion/``: it cannot write trusted state.

What HMAC does and does not prove, because the difference is the whole threat model:
``HMAC-SHA256`` over the canonical bytes proves that *someone holding the key for
``key_id``* produced this package unaltered. It proves **key membership, not host
identity**: every host sharing one symmetric key is indistinguishable, and
``source_host`` is an unverified claim. So the vote is bound to the key, not the host —
``independence_group = "fleet:" + key_id`` — and N Sybil hosts sharing one key are ONE
vote. Asymmetric per-host signatures need a third-party library (ADR-0001) and are
UNMEASURED here; Stage 7 owns the real collective protocol.

Three foreign claims are **rewritten, not trusted**, each because trusting it would let
one package defeat a local check:

* every step's ``source_group`` becomes the hash of the fleet group, or a package could
  mint as many "independent lineages" as it has steps and walk through the gateway's
  source-independence check;
* every step's ``epoch_id`` becomes the local epoch, or a package could claim the two
  corroborated epochs Stage 2's epoch rule requires;
* the label origin is ``WEAK`` whatever the package says (§37: candidate only).

Refusals in :func:`verify_package` are reported as reasons, never raised, so an
auditor sees every reason a package failed rather than only the first.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    digest_of_bytes,
    register_schema,
    require_identifier,
)
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage1.epoch.model import Epoch
from pocketsec.stage6.capsule.experience_capsule import (
    MAX_EVIDENCE_REFS_PER_CAPSULE,
    MAX_STEPS_PER_CAPSULE,
    SECRET_PATTERN,
    CapsuleKind,
    ContaminationFlag,
    EncodedStep,
    ExperienceCapsuleV1,
    LabelAssertion,
    LabelOrigin,
    PrivacyClass,
    SourceClass,
    SourceProvenance,
    source_group_of,
    step_draft_fields,
)
from pocketsec.stage6.memory.semantic import context_id_for

__all__ = [
    "FLEET_EXCHANGE_ENABLED",
    "KNOWLEDGE_PACKAGE_V1_ID",
    "KNOWLEDGE_PACKAGE_V1_VERSION",
    "MAX_PACKAGE_BYTES",
    "MAX_PACKAGE_ITEMS",
    "MIN_KEY_BYTES",
    "FleetDisabledError",
    "KnowledgePackageV1",
    "PackageVerification",
    "fleet_group_of",
    "package_to_capsules",
    "sign_package",
    "verify_package",
]

#: Architecture §36: no fleet exchange by default. Turning it on is a deployment
#: decision recorded in ADR-0059, not a code path anyone reaches by accident.
FLEET_EXCHANGE_ENABLED: bool = False
KNOWLEDGE_PACKAGE_V1_ID = "pocketsec.knowledge_package.v1"
KNOWLEDGE_PACKAGE_V1_VERSION = register_schema(KNOWLEDGE_PACKAGE_V1_ID, "1.0.0")
#: §4.21. Chosen parameters.
MAX_PACKAGE_BYTES: int = 65536
MAX_PACKAGE_ITEMS: int = 64
#: Not in §4.21. A 128-bit floor on HMAC keys; chosen, not measured.
MIN_KEY_BYTES: int = 16

_ITEM_REQUIRED = frozenset({"privacy_class", "steps", "evidence_refs"})
_ITEM_OPTIONAL = frozenset({"verdict"})


class FleetDisabledError(RuntimeError):
    """Raised when package import is attempted while fleet exchange is off."""


def fleet_group_of(key_id: str) -> str:
    """The ONE vote every host holding ``key_id`` shares."""
    return "fleet:" + key_id


def _freeze(value: Any, field: str) -> Any:
    """Deep-copy plain JSON into read-only containers, refusing anything else."""
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if value != value or abs(value) == float("inf"):
            raise ContractError(f"{field} must be finite")
        return value
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise ContractError(f"{field} keys must be strings")
        return MappingProxyType({k: _freeze(v, f"{field}.{k}") for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item, f"{field}[{i}]") for i, item in enumerate(value))
    raise ContractError(f"{field} holds {type(value).__name__}, which is not plain JSON")


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _canonical(payload: Mapping[str, Any]) -> bytes:
    text = json.dumps(payload, sort_keys=True, allow_nan=False, separators=(",", ":"))
    return text.encode("utf-8") + b"\n"


@dataclass(frozen=True, slots=True)
class KnowledgePackageV1:
    """A signed bundle of PUBLIC_DERIVED projections from another host.

    Construction checks types only. Every *policy* refusal (unsigned, unversioned,
    oversize, non-public, unknown key) lives in :func:`verify_package`, so a hostile
    package can still be judged and every reason it fails recorded.
    """

    package_id: str
    source_host: str
    key_id: str
    created_sequence: int
    items: tuple[Mapping[str, Any], ...]
    lineage_digests: tuple[str, ...]
    signature: str
    schema_version: str

    def __post_init__(self) -> None:
        for name in ("package_id", "source_host", "key_id"):
            require_identifier(getattr(self, name), f"KnowledgePackageV1.{name}")
        seq = self.created_sequence
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise ContractError("KnowledgePackageV1.created_sequence must be a non-negative int")
        if not isinstance(self.items, (list, tuple)) or not all(
            isinstance(item, Mapping) for item in self.items
        ):
            raise ContractError("KnowledgePackageV1.items must be a list of mappings")
        items = tuple(_freeze(item, f"items[{i}]") for i, item in enumerate(self.items))
        object.__setattr__(self, "items", items)
        lineage = tuple(self.lineage_digests)
        if not all(isinstance(d, str) for d in lineage):
            raise ContractError("KnowledgePackageV1.lineage_digests must be strings")
        object.__setattr__(self, "lineage_digests", lineage)
        for name in ("signature", "schema_version"):
            if not isinstance(getattr(self, name), str):
                raise ContractError(f"KnowledgePackageV1.{name} must be a string ('' if absent)")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_id": KNOWLEDGE_PACKAGE_V1_ID,
            "schema_version": self.schema_version,
            "package_id": self.package_id,
            "source_host": self.source_host,
            "key_id": self.key_id,
            "created_sequence": self.created_sequence,
            "items": [_thaw(item) for item in self.items],
            "lineage_digests": list(self.lineage_digests),
            "signature": self.signature,
        }

    def unsigned_bytes(self) -> bytes:
        """What the HMAC covers: the canonical payload without ``signature``."""
        payload = self.to_dict()
        del payload["signature"]
        return _canonical(payload)

    def canonical_bytes(self) -> bytes:
        return _canonical(self.to_dict())

    def digest(self) -> str:
        return digest_of_bytes(self.canonical_bytes())

    @classmethod
    def from_bytes(cls, data: bytes) -> KnowledgePackageV1:
        """Refuse oversize input *before* parsing it: the bound is on what we read."""
        if not isinstance(data, bytes) or len(data) > MAX_PACKAGE_BYTES:
            raise ContractError(f"package payload must be bytes <= {MAX_PACKAGE_BYTES}")
        return cls.from_dict(json.loads(data.decode("utf-8")))

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> KnowledgePackageV1:
        expected = {"schema_id", "schema_version", "package_id", "source_host", "key_id",
                    "created_sequence", "items", "lineage_digests", "signature"}
        if not isinstance(payload, Mapping) or set(payload) != expected:
            raise ContractError(f"KnowledgePackageV1 payload must have exactly {sorted(expected)}")
        if payload["schema_id"] != KNOWLEDGE_PACKAGE_V1_ID:
            raise ContractError(f"schema_id {payload['schema_id']!r} is not a knowledge package")
        for name in ("items", "lineage_digests"):
            if not isinstance(payload[name], list):
                raise ContractError(f"KnowledgePackageV1.{name} must be a list")
        return cls(**{key: payload[key] for key in expected - {"schema_id"}})


@dataclass(frozen=True, slots=True)
class PackageVerification:
    """The verdict on one package. ``package_digest`` binds it to that package, so a valid
    verification of one package cannot be replayed to import another."""

    valid: bool
    reasons: tuple[str, ...]
    fleet_group: str
    package_digest: str


#: package digest -> the verification ``verify_package`` issued for it. Module-private and
#: bounded; ``package_to_capsules`` accepts only a verification found here, so a hand-built
#: ``PackageVerification(valid=True, ...)`` cannot import an unsigned, unknown-key or
#: unlineaged package (review S6-AUTH-09).
_MAX_ISSUED_VERIFICATIONS = 64
_issued_verifications: OrderedDict[str, PackageVerification] = OrderedDict()


def _require_key(key: object) -> bytes:
    if not isinstance(key, bytes) or len(key) < MIN_KEY_BYTES:
        raise ContractError(f"an HMAC key must be bytes of at least {MIN_KEY_BYTES}")
    return key


def _mac(package: KnowledgePackageV1, key: bytes) -> str:
    return hmac.new(key, package.unsigned_bytes(), hashlib.sha256).hexdigest()


def sign_package(package: KnowledgePackageV1, *, key: bytes) -> KnowledgePackageV1:
    """A copy carrying the hex HMAC-SHA256 of its unsigned canonical bytes."""
    if not isinstance(package, KnowledgePackageV1):
        raise ContractError("sign_package signs a KnowledgePackageV1")
    return replace(package, signature=_mac(package, _require_key(key)))


def _item_problems(index: int, item: Mapping[str, Any]) -> list[str]:
    """Why one item may not be imported: not public, malformed, or secret-bearing."""
    where = f"item[{index}]"
    keys = set(item)
    if item.get("privacy_class") != PrivacyClass.PUBLIC_DERIVED.value:
        return [f"{where}:not_public_derived"]
    if not keys >= _ITEM_REQUIRED or keys - _ITEM_REQUIRED - _ITEM_OPTIONAL:
        return [f"{where}:malformed_keys"]
    problems: list[str] = []
    try:
        steps = item["steps"]
        if not isinstance(steps, tuple) or not 1 <= len(steps) <= MAX_STEPS_PER_CAPSULE:
            raise ContractError("steps count")
        for step in steps:
            EncodedStep.from_dict(step)
        refs = item["evidence_refs"]
        if not isinstance(refs, tuple) or not refs or len(refs) > MAX_EVIDENCE_REFS_PER_CAPSULE:
            raise ContractError("evidence_refs count")
        if "verdict" in item and item["verdict"] not in Verdict.__members__:
            raise ContractError("verdict")
    except (ContractError, TypeError) as error:
        problems.append(f"{where}:malformed:{str(error)[:60]}")
    if any(SECRET_PATTERN.search(text) for text in _all_strings(item)):
        problems.append(f"{where}:secret_bearing")
    return problems


def _all_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        return [text for item in value.values() for text in _all_strings(item)]
    if isinstance(value, (list, tuple)):
        return [text for item in value for text in _all_strings(item)]
    return []


def verify_package(
    package: KnowledgePackageV1, *, keyring: Mapping[str, bytes]
) -> PackageVerification:
    """Every refusal §38 names, collected: unversioned, unsigned, unknown key, bad
    signature, oversize, too many items, unlineaged, and per-item non-public / malformed /
    secret-bearing. ``valid`` is True only when there is no reason at all."""
    if not isinstance(package, KnowledgePackageV1):
        raise ContractError("verify_package judges a KnowledgePackageV1")
    reasons: list[str] = []
    if package.schema_version != KNOWLEDGE_PACKAGE_V1_VERSION:
        reasons.append("unversioned")
    key = keyring.get(package.key_id)
    if not package.signature:
        reasons.append("unsigned")
    elif key is None:
        reasons.append("unknown_key")
    elif not hmac.compare_digest(package.signature, _mac(package, _require_key(key))):
        reasons.append("bad_signature")
    if len(package.canonical_bytes()) > MAX_PACKAGE_BYTES:
        reasons.append("oversize")
    if not package.items:
        reasons.append("empty")
    if len(package.items) > MAX_PACKAGE_ITEMS:
        reasons.append("too_many_items")
    else:
        for index, item in enumerate(package.items):
            reasons.extend(_item_problems(index, item))
    if not package.lineage_digests or not all(
        d.startswith("sha256:") and len(d) == 71 for d in package.lineage_digests
    ):
        reasons.append("unlineaged")
    verification = PackageVerification(
        valid=not reasons, reasons=tuple(reasons),
        fleet_group=fleet_group_of(package.key_id), package_digest=package.digest(),
    )
    _issued_verifications[verification.package_digest] = verification
    _issued_verifications.move_to_end(verification.package_digest)
    while len(_issued_verifications) > _MAX_ISSUED_VERIFICATIONS:
        _issued_verifications.popitem(last=False)
    return verification


def _foreign_capsule(
    item: Mapping[str, Any], *, package: KnowledgePackageV1, epoch: Epoch, sequence: int
) -> ExperienceCapsuleV1:
    """One item as a FOREIGN_PACKAGE capsule, with the three foreign claims rewritten."""
    group = fleet_group_of(package.key_id)
    local_group = source_group_of(group)
    steps = tuple(
        replace(EncodedStep.from_dict(step), source_group=local_group, epoch_id=epoch.epoch_id)
        for step in item["steps"]
    )
    derived = step_draft_fields(steps, cut=False)
    # The item's own evidence first: those digests travel on no step, so cutting them is
    # real loss and is flagged; step digests past the cap remain on their steps.
    own = tuple(dict.fromkeys(item["evidence_refs"]))
    refs = tuple(dict.fromkeys([*own, *derived["evidence_refs"]]))
    truncated = derived["truncated"] or len(own) > MAX_EVIDENCE_REFS_PER_CAPSULE
    flags = set(derived["contamination_flags"]) | {ContaminationFlag.FOREIGN_ORIGIN}
    if truncated:
        flags.add(ContaminationFlag.TRUNCATED)
    verdict = item.get("verdict")
    return ExperienceCapsuleV1(
        capsule_id="", kind=CapsuleKind.FOREIGN_PACKAGE, epoch_id=epoch.epoch_id,
        context_id=context_id_for(epoch.identity),
        evidence_refs=refs[:MAX_EVIDENCE_REFS_PER_CAPSULE],
        source_provenance=SourceProvenance(
            source_class=SourceClass.FOREIGN_HOST, source_id=package.source_host,
            independence_group=group, label_origin=LabelOrigin.WEAK,
            transformation_lineage=("stage6.fleet.package", package.package_id),
            host_id=package.source_host,
        ),
        security_worlds=(), resolution_state=Verdict.UNKNOWN, response_outcome=None,
        visibility=derived["visibility"],
        confidence_components=tuple(sorted(derived["confidence_components"])),
        contradiction_history=(), privacy_class=PrivacyClass.PUBLIC_DERIVED,
        contamination_flags=frozenset(flags), steps=steps,
        label=None if verdict is None else LabelAssertion(
            verdict=Verdict(verdict), origin=LabelOrigin.WEAK, asserted_by=group,
            target_capsule_id="",
        ),
        procedure_rows=(), truncated=truncated, created_sequence=sequence,
    )


def package_to_capsules(
    package: KnowledgePackageV1, *, verification: PackageVerification, epoch: Epoch,
    sequence: int, enabled: bool = FLEET_EXCHANGE_ENABLED,
) -> tuple[ExperienceCapsuleV1, ...]:
    """A verified package as FOREIGN_PACKAGE capsules for the gateway — never further.

    Raises :class:`FleetDisabledError` unless ``enabled``; refuses a verification that is
    invalid or belongs to another package. Capsule ``created_sequence`` values are
    ``sequence``, ``sequence + 1``, ... in item order.
    """
    if enabled is not True:
        raise FleetDisabledError(
            "fleet exchange is disabled (FLEET_EXCHANGE_ENABLED=False); architecture §36 "
            "requires explicit configuration before foreign knowledge is imported"
        )
    if not isinstance(verification, PackageVerification) or not verification.valid:
        raise ContractError("package_to_capsules needs a valid PackageVerification")
    if verification.package_digest != package.digest():
        raise ContractError("the verification was issued for a different package")
    if verification.fleet_group != fleet_group_of(package.key_id):
        raise ContractError("the verification names a different fleet group")
    if _issued_verifications.get(verification.package_digest) != verification:
        raise ContractError("the verification was not issued by verify_package (or was "
                            "forgotten); verify the package again")
    if not isinstance(epoch, Epoch):
        raise ContractError("epoch must be the LOCAL Stage 1 Epoch")
    return tuple(
        _foreign_capsule(item, package=package, epoch=epoch, sequence=sequence + index)
        for index, item in enumerate(package.items)
    )
