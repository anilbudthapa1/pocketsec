"""D5.6 — capability tokens: the narrow, expiring permission the executor runs on.

Architecture §15: *"The executor has no standing permission to perform arbitrary
actions; it receives only a narrow capability."* A :class:`CapabilityToken` binds
one action id to one operator id, one target **identity digest**, one authority
class and one validity window, and :meth:`TokenStore.redeem` consumes it. There is
no token that authorises "the incident", and no token that survives its own use.

Three properties this module gets by construction:

* **Single use.** ``redeem()`` records the nonce. A second redemption of the same
  token returns ``REPLAYED`` — it does not return ``VALID`` with a warning.
* **Bound to one identity.** The token's ``target_digest`` is produced by the same
  ``identity_digest`` function the executor uses on the live target, so a token
  minted for pid 4011-at-start-time-T cannot be redeemed against pid 4011 after a
  reuse. A pid is not an identity (§17), and the key space is one function
  (spec §4.9 rule A).
* **Bound to one subject, one ttl and one grant source** (schema v2). v1 bound the
  process identity only, so a token minted for ``CONSTRAIN_SERVICE`` on one unit
  redeemed VALID for the same operator aimed at another unit of the same process — a
  human approval for X spent on Y (findings F1 / S5-SEC-04, reproduced before the
  fix). ``binding_digest`` is :meth:`DefensiveOperator.binding_digest`, which covers
  the whole scope and the ttl, and ``granted_by`` records whether a person or policy
  granted it, so SENTINEL can hold the human-required rule itself instead of trusting
  that the token "is evidence of the grant source". The v1 id stays registered so an
  old payload is recognised and refused by :meth:`CapabilityToken.from_dict`, never
  silently upgraded.
* **Bounded replay memory, stated rather than pretended.** The spent-nonce set
  holds :data:`MAX_SPENT_NONCES` entries because endpoint state is bounded. When
  eviction has happened, a token old enough to have been forgotten returns
  :attr:`TokenVerdict.NONCE_EVICTED`, which callers treat as a **refusal**. The
  honest answer to "was this replayed?" is sometimes "I can no longer tell", and
  the enum says so instead of an unbounded set pretending to perfect replay
  resistance.

What this module refuses to do: sign anything outside :meth:`TokenStore.mint`.
The MAC function is private, so every valid token in existence went through
mint()'s four refusals. A public signing helper would be a bypass of all of them.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol

from pocketsec.stage0.contracts.common import (
    ContractError,
    register_schema,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage5.authority.capability import (
    HUMAN_REQUIRED_AUTONOMY,
    AuthorityGrant,
    GrantSource,
    autonomy_of,
    escalates,
    required_authority,
)
from pocketsec.stage5.constitution.invariants import AuthorityClass, canonical_bytes

if TYPE_CHECKING:  # pragma: no cover - annotations only
    from pocketsec.stage5.operators.algebra import DefensiveOperator, OperatorSpec

__all__ = [
    "CAPABILITY_TOKEN_V1_ID",
    "CAPABILITY_TOKEN_V1_VERSION",
    "CAPABILITY_TOKEN_V2_ID",
    "CAPABILITY_TOKEN_V2_VERSION",
    "MAX_SPENT_NONCES",
    "MAX_TOKEN_BYTES",
    "MAX_TOKEN_LIFETIME_SECONDS",
    "NONCE_BYTES",
    "REFUSAL_VERDICTS",
    "CapabilityToken",
    "ClockLike",
    "TokenStore",
    "TokenVerdict",
]

#: RETIRED. v1 tokens bound only the process identity digest (F1 / S5-SEC-04). The id
#: stays registered so a v1 payload is recognised by name and refused, not re-read.
CAPABILITY_TOKEN_V1_ID = "pocketsec.capability_token.v1"
CAPABILITY_TOKEN_V1_VERSION = register_schema(CAPABILITY_TOKEN_V1_ID, "1.0.0")
#: The live schema: v1 plus ``binding_digest`` and ``granted_by``, both MAC-covered.
CAPABILITY_TOKEN_V2_ID = "pocketsec.capability_token.v2"
CAPABILITY_TOKEN_V2_VERSION = register_schema(CAPABILITY_TOKEN_V2_ID, "1.0.0")

#: Bounded endpoint state: the spent-nonce set never grows past this, and
#: eviction is explicit rather than silent (see :attr:`TokenVerdict.NONCE_EVICTED`).
MAX_SPENT_NONCES: int = 256
#: 16 random bytes -> 32 lowercase hex characters.
NONCE_BYTES: int = 16
#: Fifteen minutes. A capability that outlives the incident is a standing permission.
MAX_TOKEN_LIFETIME_SECONDS: int = 900
#: A token is a small record; the bound keeps it that way.
MAX_TOKEN_BYTES: int = 1024

_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class TokenVerdict(StrEnum):
    """Why a redemption succeeded or, far more usefully, why it did not."""

    VALID = "VALID"
    BAD_MAC = "BAD_MAC"
    EXPIRED = "EXPIRED"
    NOT_YET_VALID = "NOT_YET_VALID"
    REPLAYED = "REPLAYED"
    UNKNOWN_SIGNER = "UNKNOWN_SIGNER"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    NONCE_EVICTED = "NONCE_EVICTED"
    """The bound was reached, so replay cannot be excluded. A refusal, not a pass."""


#: Every verdict that is not permission. Callers test membership here rather than
#: ``verdict != VALID``: the second spelling is one added enum member away from
#: treating a new failure mode as success.
REFUSAL_VERDICTS: frozenset[TokenVerdict] = frozenset(
    verdict for verdict in TokenVerdict if verdict is not TokenVerdict.VALID
)


class ClockLike(Protocol):
    """The one member a token needs from a clock: whole monotonic seconds.

    A structural view of ``executor.identity.Clock`` (``ManualClock`` and
    ``SystemClock`` both satisfy it). Stated as a Protocol rather than imported
    because ``executor/`` is a downstream package and a token store must be
    testable — with a clock that does **not** advance on its own — before an
    executor exists.
    """

    def now(self) -> int: ...


@dataclass(frozen=True, slots=True)
class CapabilityToken:
    """One action's worth of privilege, and not one field more.

    ``mac`` is excluded from :meth:`canonical_bytes`, which is what the MAC is
    computed over: every other field is therefore authenticated, including the
    authority class and the target digest.
    """

    action_id: str
    incident_id: str
    operator_id: str
    target_digest: str
    binding_digest: str
    granted_by: GrantSource
    authority: AuthorityClass
    valid_from: int
    expiry: int
    max_duration_seconds: int
    rollback_required: bool
    policy_version: str
    nonce: str
    signer: str
    mac: str
    schema_version: str = CAPABILITY_TOKEN_V2_VERSION

    def __post_init__(self) -> None:
        for field, value in (
            ("action_id", self.action_id),
            ("incident_id", self.incident_id),
            ("operator_id", self.operator_id),
            ("policy_version", self.policy_version),
            ("signer", self.signer),
            ("schema_version", self.schema_version),
        ):
            require_identifier(value, f"CapabilityToken.{field}")
        for field, digest in (
            ("target_digest", self.target_digest),
            ("binding_digest", self.binding_digest),
        ):
            if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
                raise ContractError(f"CapabilityToken.{field} must be sha256:<hex>, got {digest!r}")
        if not isinstance(self.granted_by, GrantSource):
            raise ContractError(
                f"CapabilityToken.granted_by must be a GrantSource, got {self.granted_by!r}"
            )
        if not _NONCE_RE.fullmatch(self.nonce):
            raise ContractError(
                f"CapabilityToken.nonce must be {NONCE_BYTES * 2} lowercase hex characters"
            )
        if self.authority is AuthorityClass.AX:
            raise ContractError("no token may carry AX; AX is prohibited autonomous action")
        require_non_negative_int(self.valid_from, "CapabilityToken.valid_from")
        require_non_negative_int(self.expiry, "CapabilityToken.expiry")
        require_non_negative_int(self.max_duration_seconds, "CapabilityToken.max_duration_seconds")
        lifetime = self.expiry - self.valid_from
        if lifetime <= 0:
            raise ContractError("a token that expires when it is minted authorises nothing")
        if lifetime > MAX_TOKEN_LIFETIME_SECONDS:
            raise ContractError(
                f"token lifetime {lifetime}s exceeds {MAX_TOKEN_LIFETIME_SECONDS}s"
            )
        if self.max_duration_seconds < lifetime:
            raise ContractError(
                "a token may not be valid for longer than the action it authorises may run"
            )
        if not isinstance(self.mac, str) or not self.mac:
            raise ContractError("CapabilityToken.mac is required")
        size = len(canonical_bytes(self.to_dict()))
        if size > MAX_TOKEN_BYTES:
            raise ContractError(f"token is {size} canonical bytes, over {MAX_TOKEN_BYTES}")

    def _payload(self) -> dict[str, Any]:
        """Every authenticated field, in one place, so the MAC and the wire form agree."""
        return {
            "action_id": self.action_id,
            "authority": self.authority.value,
            "binding_digest": self.binding_digest,
            "expiry": self.expiry,
            "granted_by": self.granted_by.value,
            "incident_id": self.incident_id,
            "max_duration_seconds": self.max_duration_seconds,
            "nonce": self.nonce,
            "operator_id": self.operator_id,
            "policy_version": self.policy_version,
            "rollback_required": self.rollback_required,
            "schema": CAPABILITY_TOKEN_V2_ID,
            "schema_version": self.schema_version,
            "signer": self.signer,
            "target_digest": self.target_digest,
            "valid_from": self.valid_from,
        }

    def canonical_bytes(self) -> bytes:
        """The MAC's input: every field except ``mac``, sorted, no floats."""
        return canonical_bytes(self._payload())

    def to_dict(self) -> dict[str, Any]:
        payload = self._payload()
        payload["mac"] = self.mac
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> CapabilityToken:
        """Rebuild a token from JSON.

        Deserialisation does **not** confer validity: the result is an unverified
        claim until :meth:`TokenStore.redeem` checks the MAC against the key. A payload
        that names another schema — the retired v1 in particular, which carried no
        subject binding — is refused here rather than read with a default binding.
        """
        schema = payload.get("schema")
        if schema != CAPABILITY_TOKEN_V2_ID:
            raise ContractError(
                f"token payload names schema {schema!r}; only {CAPABILITY_TOKEN_V2_ID} is "
                "accepted (v1 did not bind the scope subject)"
            )
        return cls(
            action_id=str(payload["action_id"]),
            incident_id=str(payload["incident_id"]),
            operator_id=str(payload["operator_id"]),
            target_digest=str(payload["target_digest"]),
            binding_digest=str(payload["binding_digest"]),
            granted_by=GrantSource(payload["granted_by"]),
            authority=AuthorityClass(payload["authority"]),
            valid_from=int(payload["valid_from"]),
            expiry=int(payload["expiry"]),
            max_duration_seconds=int(payload["max_duration_seconds"]),
            rollback_required=bool(payload["rollback_required"]),
            policy_version=str(payload["policy_version"]),
            nonce=str(payload["nonce"]),
            signer=str(payload["signer"]),
            mac=str(payload["mac"]),
            schema_version=str(payload.get("schema_version", CAPABILITY_TOKEN_V2_VERSION)),
        )


def _catalog_owns(spec: OperatorSpec) -> bool:
    """Whether the operator catalog owns this exact spec object, by identity.

    Identity, not equality: a structurally-equal forged spec is not a catalog
    entry. The import is deferred because ``operators/catalog.py`` imports the
    authority plane, and a module-scope import here would close the cycle; it is
    **not** optional — an ``ImportError`` propagates to mint()'s caller as a
    refusal rather than being swallowed into a permissive default.
    """
    from pocketsec.stage5.operators.catalog import CATALOG

    return any(spec is entry for entry in CATALOG.values())


class TokenStore:
    """Mints and redeems capability tokens against one key and one clock.

    The store holds the key. Nothing else in Stage 5 does, and no method hands it
    out, so the only way to obtain a token that redeems is to pass mint()'s
    refusals.
    """

    def __init__(
        self,
        *,
        key: bytes,
        signer: str,
        clock: ClockLike,
        max_spent_nonces: int = MAX_SPENT_NONCES,
    ) -> None:
        if not isinstance(key, (bytes, bytearray)) or len(key) < NONCE_BYTES:
            raise ContractError(f"TokenStore key must be at least {NONCE_BYTES} bytes")
        require_identifier(signer, "TokenStore.signer")
        if max_spent_nonces < 1 or max_spent_nonces > MAX_SPENT_NONCES:
            raise ContractError(
                f"max_spent_nonces must be in 1..{MAX_SPENT_NONCES}, got {max_spent_nonces}"
            )
        self._key = bytes(key)
        self._signer = signer
        self._clock = clock
        self._capacity = max_spent_nonces
        self._spent: deque[tuple[str, int]] = deque()
        self._spent_index: set[str] = set()
        self._evictions = 0
        #: The newest ``valid_from`` this store has forgotten. A token at or below
        #: it cannot be proven un-replayed, so it is refused.
        self._evicted_horizon: int | None = None

    def _mac(self, token: CapabilityToken) -> str:
        return hmac.new(self._key, token.canonical_bytes(), hashlib.sha256).hexdigest()

    def mint(
        self,
        *,
        grant: AuthorityGrant,
        operator: DefensiveOperator,
        action_id: str,
        ttl_seconds: int,
    ) -> CapabilityToken:
        """Issue one token, or refuse.

        The refusals, in this order: the grant must name this operator, the grant
        must not be escalated, a POLICY grant may not cover an operator §5 says a
        person must authorise, and the lifetime must be inside both the token
        ceiling and the operator's own maximum duration.
        The catalog-identity check runs last and raises even when the catalog
        module cannot be loaded — on an endpoint that means the package is broken,
        and a broken package mints nothing.
        """
        spec = operator.spec
        required = required_authority(spec)
        self._refuse_bad_grant(grant, spec, required)
        self._refuse_bad_lifetime(ttl_seconds, spec)
        if not _catalog_owns(spec):
            raise ContractError(
                f"{spec.operator_id} is not a CATALOG entry by identity; "
                "a forged operator specification is not a capability"
            )
        now = self._clock.now()
        unsigned = CapabilityToken(
            action_id=action_id,
            incident_id=operator.incident_id,
            operator_id=spec.operator_id,
            target_digest=operator.target.identity.digest(),
            binding_digest=operator.binding_digest(),
            granted_by=grant.granted_by,
            authority=required,
            valid_from=now,
            expiry=now + ttl_seconds,
            max_duration_seconds=spec.max_duration_seconds,
            rollback_required=spec.rollback_operator_id is not None,
            policy_version=grant.policy_version,
            nonce=secrets.token_hex(NONCE_BYTES),
            signer=self._signer,
            mac="unsigned",
        )
        return CapabilityToken(**{**_fields(unsigned), "mac": self._mac(unsigned)})

    def _refuse_bad_grant(
        self, grant: AuthorityGrant, spec: OperatorSpec, required: AuthorityClass
    ) -> None:
        if grant.subject_operator_id != spec.operator_id:
            raise ContractError(
                f"grant covers {grant.subject_operator_id!r}, not {spec.operator_id!r}; "
                "a grant is scoped to one operator"
            )
        if escalates(grant.authority, required):
            raise ContractError(
                f"{spec.operator_id} requires {required.value} and the grant carries "
                f"{grant.authority.value}; authority does not escalate"
            )
        if grant.granted_by is GrantSource.POLICY and autonomy_of(spec) in HUMAN_REQUIRED_AUTONOMY:
            raise ContractError(
                f"{spec.operator_id} is {autonomy_of(spec).value} and needs a HUMAN grant; "
                "policy cannot grant it"
            )

    def _refuse_bad_lifetime(self, ttl_seconds: int, spec: OperatorSpec) -> None:
        require_non_negative_int(ttl_seconds, "ttl_seconds")
        if ttl_seconds == 0:
            raise ContractError("a zero-lifetime token authorises nothing")
        if ttl_seconds > MAX_TOKEN_LIFETIME_SECONDS:
            raise ContractError(
                f"ttl {ttl_seconds}s exceeds the {MAX_TOKEN_LIFETIME_SECONDS}s token ceiling"
            )
        if ttl_seconds > spec.max_duration_seconds:
            raise ContractError(
                f"ttl {ttl_seconds}s exceeds {spec.operator_id}'s "
                f"{spec.max_duration_seconds}s maximum duration"
            )

    def redeem(self, token: CapabilityToken, *, operator: DefensiveOperator) -> TokenVerdict:
        """Check one token against one operator, consuming it if it is valid.

        Every check is a refusal with a name. The order matters only in that the
        cheap, key-independent checks cannot be used as an oracle: the signer and
        MAC are settled before anything about the operator is read.
        """
        if not hmac.compare_digest(token.signer, self._signer):
            return TokenVerdict.UNKNOWN_SIGNER
        if not hmac.compare_digest(token.mac, self._mac(token)):
            return TokenVerdict.BAD_MAC
        now = self._clock.now()
        if now < token.valid_from:
            return TokenVerdict.NOT_YET_VALID
        if now >= token.expiry:
            return TokenVerdict.EXPIRED
        if token.target_digest != operator.target.identity.digest():
            return TokenVerdict.SCOPE_MISMATCH
        if token.operator_id != operator.spec.operator_id:
            return TokenVerdict.SCOPE_MISMATCH
        if token.binding_digest != operator.binding_digest():
            # Same process, different subject or ttl: the approval named another object.
            return TokenVerdict.SCOPE_MISMATCH
        if token.nonce in self._spent_index:
            return TokenVerdict.REPLAYED
        if self._evicted_horizon is not None and token.valid_from <= self._evicted_horizon:
            return TokenVerdict.NONCE_EVICTED
        self._consume(token)
        return TokenVerdict.VALID

    def _consume(self, token: CapabilityToken) -> None:
        """Record the nonce, evicting the oldest and raising the horizon when full.

        The horizon is a ``valid_from``, and the clock is whole seconds, so after
        the first eviction **every** token minted in that same second is refused
        with ``NONCE_EVICTED`` — including one minted a moment ago. That is the
        intended direction of the error: the store would otherwise have to answer
        "was this replayed?" with a guess. It is reachable only by redeeming more
        than ``max_spent_nonces`` tokens inside one second, which the governor's
        rate limit (8 autonomous actions per hour) says is not a legitimate
        workload; a redemption burst that large is itself the thing to escalate.
        """
        self._spent.append((token.nonce, token.valid_from))
        self._spent_index.add(token.nonce)
        while len(self._spent) > self._capacity:
            nonce, valid_from = self._spent.popleft()
            self._spent_index.discard(nonce)
            self._evictions += 1
            horizon = self._evicted_horizon
            self._evicted_horizon = valid_from if horizon is None else max(horizon, valid_from)

    def spent_count(self) -> int:
        """Nonces currently remembered — bounded by ``max_spent_nonces``, by construction."""
        return len(self._spent_index)

    def evictions(self) -> int:
        """How many nonces were forgotten. Non-zero means replay detection is partial."""
        return self._evictions


def _fields(token: CapabilityToken) -> dict[str, Any]:
    """The token's constructor arguments, so signing does not restate the field list."""
    return {
        "action_id": token.action_id,
        "incident_id": token.incident_id,
        "operator_id": token.operator_id,
        "target_digest": token.target_digest,
        "binding_digest": token.binding_digest,
        "granted_by": token.granted_by,
        "authority": token.authority,
        "valid_from": token.valid_from,
        "expiry": token.expiry,
        "max_duration_seconds": token.max_duration_seconds,
        "rollback_required": token.rollback_required,
        "policy_version": token.policy_version,
        "nonce": token.nonce,
        "signer": token.signer,
        "schema_version": token.schema_version,
    }


assert len(REFUSAL_VERDICTS) == len(TokenVerdict) - 1, "VALID is the only non-refusal"
assert TokenVerdict.NONCE_EVICTED in REFUSAL_VERDICTS, "a forgotten nonce is a refusal"
