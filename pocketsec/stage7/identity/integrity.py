"""D7.4 — the keyring, HMAC signing/verification and the replay guard for knowledge capsules.

**What HMAC proves (ADR-0064), and what it does not.** A valid ``HMAC-SHA256`` over a
capsule's ``unsigned_bytes()`` proves that *someone holding the key registered as
``key_id``* produced those bytes unaltered. With simulated pre-provisioned keys that is
**key possession, not host identity**: whoever holds the key is indistinguishable from
the host it was provisioned for, and a stolen key is a full impersonation. It is not
authentication of a host and nothing in Stage 7 calls it that. Asymmetric per-host
signatures (Ed25519) need a third-party library (ADR-0001); real identity binding is
UNMEASURED.

What the keyring does enforce, because each gap is a concrete attack:

* **Key-to-contributor binding.** Every key is registered to one contributor pseudonym,
  and :meth:`Keyring.verify` refuses a capsule whose ``provenance_commitment.contributor``
  is not the key's owner (``contributor_key_mismatch``). Without it, one key could sign
  capsules under any number of contributor names and mint "independent" peers.
* **Rotation with a bounded grace window.** A rotated key keeps verifying until
  ``not_after_round = rotation round + KEY_GRACE_ROUNDS`` so capsules in flight survive a
  rotation, and then fails with ``expired_key``. It never signs again.
* **Revocation is immediate and final.** A revoked key fails with ``revoked_key`` and its
  material is dropped from memory: a key that is never checked again need not be kept.
* **No resurrection by re-registration.** A ``key_id`` can be registered once. Replacing
  a revoked key's material under its old id would silently un-revoke it.
* **Dead records are reclaimed, never live ones (R7-4).** A full ring used to refuse every
  later registration and rotation forever, because REVOKED and expired-ROTATED records
  counted against ``MAX_KEYS`` for good: after 1024 lifetime key ids a host could revoke a
  compromised key but never replace it. When full, :meth:`Keyring.register` now reclaims the
  OLDEST record that can never verify again (REVOKED, or ROTATED past its grace). A reclaimed
  id then fails as ``unknown_key`` instead of ``revoked_key``/``expired_key`` — still
  refused. Its id is added to a fixed-size Bloom filter (no false negatives, so a reclaimed id
  can never be re-registered; a false positive only refuses a fresh id, fail-closed), and the
  reclaim is chained into a tombstone digest that :meth:`Keyring.state_digest` carries.
* **A corrupt trust store is detectable.** :meth:`Keyring.state_digest` hashes the sorted
  records with each key *hashed*, so the fabric can disable exchange when the store no
  longer matches the digest it recorded (architecture §43) without the digest ever
  carrying key material.

**The replay guard** keeps, per ``key_id``, the highest sequence it admitted, and the set
of capsule ids it admitted; both tables are LRU-bounded and their evictions counted.
**Known residual (tested):** once a key's high-water entry *and* a capsule's seen-id entry
have both been evicted, a replay of that capsule is caught only by its ``expiry_round``.
The replay window is therefore bounded by ``MAX_EXPIRY_HORIZON_ROUNDS``, not closed.

Time is rounds. A capsule is valid for ``created_round <= round < expiry_round``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import sys
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, replace
from enum import StrEnum

from pocketsec.stage0.contracts.common import ContractError, require_non_negative_int
from pocketsec.stage6.fleet.package import MIN_KEY_BYTES
from pocketsec.stage7.capsule.knowledge_capsule import KnowledgeCapsuleV1

__all__ = [
    "INTEGRITY_REASONS",
    "KEY_GRACE_ROUNDS",
    "KEY_TOMBSTONE_BITS",
    "MAX_KEYS",
    "MAX_REPLAY_KEYS",
    "MAX_SEEN_CAPSULES",
    "REPLAY_REASONS",
    "IntegrityVerdict",
    "KeyRecord",
    "KeyState",
    "Keyring",
    "ReplayGuard",
]

#: §4.23. Chosen parameters, not measurements.
MAX_KEYS: int = 1024
KEY_GRACE_ROUNDS: int = 8
MAX_REPLAY_KEYS: int = 4096
MAX_SEEN_CAPSULES: int = 8192
#: Size of the reclaimed-id Bloom filter, in bits (64 KiB). Chosen, not measured.
KEY_TOMBSTONE_BITS: int = 1 << 19
_TOMBSTONE_HASHES = 4

#: The exact reason vocabulary of :class:`IntegrityVerdict`; ``"ok"`` is the only valid one.
INTEGRITY_REASONS: tuple[str, ...] = (
    "ok",
    "unsigned",
    "unknown_key",
    "revoked_key",
    "expired_key",
    "bad_signature",
    "contributor_key_mismatch",
)
#: The exact refusal vocabulary of :meth:`ReplayGuard.check`.
REPLAY_REASONS: tuple[str, ...] = (
    "duplicate_capsule",
    "replayed_sequence",
    "expired",
    "not_yet_valid",
)

_KEY_ID = re.compile(r"^key-[0-9a-f]{16}$")
_PEER_ID = re.compile(r"^peer-[0-9a-f]{16}$")
_SIGNATURE = re.compile(r"^[0-9a-f]{64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class KeyState(StrEnum):
    ACTIVE = "ACTIVE"
    ROTATED = "ROTATED"
    REVOKED = "REVOKED"


@dataclass(frozen=True, slots=True)
class KeyRecord:
    """The public half of one registered key. The key material is never part of it."""

    key_id: str
    owner: str
    state: KeyState
    not_after_round: int | None

    def __post_init__(self) -> None:
        if not isinstance(self.key_id, str) or not _KEY_ID.fullmatch(self.key_id):
            raise ContractError(f"KeyRecord.key_id has the wrong shape: {self.key_id!r}")
        if not isinstance(self.owner, str) or not _PEER_ID.fullmatch(self.owner):
            raise ContractError(f"KeyRecord.owner has the wrong shape: {self.owner!r}")
        if not isinstance(self.state, KeyState):
            raise ContractError(f"KeyRecord.state must be a KeyState: {self.state!r}")
        if self.state is KeyState.ACTIVE and self.not_after_round is not None:
            raise ContractError("an ACTIVE key has no not_after_round")
        if self.state is not KeyState.ACTIVE:
            require_non_negative_int(self.not_after_round, "KeyRecord.not_after_round")


@dataclass(frozen=True, slots=True)
class IntegrityVerdict:
    """Whether a capsule's bytes are unaltered under a key its contributor owns.

    ``valid`` proves key possession by *someone*, never host identity (ADR-0064).
    """

    valid: bool
    reason: str

    def __post_init__(self) -> None:
        if self.reason not in INTEGRITY_REASONS:
            raise ContractError(f"IntegrityVerdict.reason {self.reason!r} is not in the vocabulary")
        if self.valid is not (self.reason == "ok"):
            raise ContractError(f"IntegrityVerdict valid={self.valid} contradicts {self.reason!r}")


def _hmac_hex(key: bytes, payload: bytes) -> str:
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


class Keyring:
    """Registered HMAC keys, each bound to exactly one contributor pseudonym.

    Signing and verification here prove possession of a key, not host identity.
    """

    __slots__ = (
        "_capacity", "_key_hashes", "_keys", "_reclaimed", "_records", "_tomb_bits",
        "_tomb_chain",
    )

    def __init__(self, *, capacity: int = MAX_KEYS) -> None:
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 1:
            raise ContractError(f"Keyring capacity must be an int >= 1, got {capacity!r}")
        self._capacity = capacity
        self._records: dict[str, KeyRecord] = {}
        self._keys: dict[str, bytes] = {}
        self._key_hashes: dict[str, str] = {}
        self._tomb_bits = bytearray(KEY_TOMBSTONE_BITS // 8)
        self._tomb_chain = ""
        self._reclaimed = 0

    def register(self, key_id: str, key: bytes, *, owner: str, round_index: int) -> None:
        """Provision ``key`` as ``key_id`` for ``owner``. Never evicts a LIVE key.

        A full ring reclaims its oldest DEAD record (REVOKED, or ROTATED past grace at
        ``round_index``); if there is none it raises. Evicting a live key would turn a live
        peer's key into a refusal; provisioning is a local decision, so that is reported to
        the caller instead.
        """
        require_non_negative_int(round_index, "round_index")
        if not isinstance(key, bytes) or len(key) < MIN_KEY_BYTES:
            raise ContractError(f"an HMAC key must be bytes of at least {MIN_KEY_BYTES}")
        if key_id in self._records or self._tombstoned(key_id):
            raise ContractError(f"key {key_id!r} is already registered; a key id is never reused")
        if len(self._records) >= self._capacity and not self._reclaim_one(round_index):
            raise ContractError(f"keyring is full ({self._capacity} keys)")
        self._records[key_id] = KeyRecord(key_id, owner, KeyState.ACTIVE, None)
        self._keys[key_id] = bytes(key)
        self._key_hashes[key_id] = hashlib.sha256(key).hexdigest()

    def rotate(
        self,
        old_key_id: str,
        new_key_id: str,
        new_key: bytes,
        *,
        round_index: int,
        grace_rounds: int = KEY_GRACE_ROUNDS,
    ) -> None:
        """Replace an ACTIVE key; the old one verifies until ``round_index + grace_rounds``."""
        require_non_negative_int(grace_rounds, "grace_rounds")
        old = self._records.get(old_key_id)
        if old is None or old.state is not KeyState.ACTIVE:
            raise ContractError(f"only an ACTIVE registered key can be rotated: {old_key_id!r}")
        # Register first: if the new key is refused, the old key must still be ACTIVE.
        self.register(new_key_id, new_key, owner=old.owner, round_index=round_index)
        self._records[old_key_id] = replace(
            old, state=KeyState.ROTATED, not_after_round=round_index + grace_rounds
        )

    def _reclaim_one(self, round_index: int) -> bool:
        victim = next(
            (
                rec for rec in self._records.values()
                if rec.state is KeyState.REVOKED
                or (rec.state is KeyState.ROTATED and round_index > (rec.not_after_round or 0))
            ),
            None,
        )
        if victim is None:
            return False
        kid = victim.key_id
        row = [kid, victim.owner, victim.state.value, victim.not_after_round, self._key_hashes[kid]]
        text = json.dumps([self._tomb_chain, row], separators=(",", ":"), allow_nan=False)
        self._tomb_chain = hashlib.sha256(text.encode("utf-8")).hexdigest()
        for position in self._tomb_positions(kid):
            self._tomb_bits[position >> 3] |= 1 << (position & 7)
        del self._records[kid]
        del self._key_hashes[kid]
        self._keys.pop(kid, None)
        self._reclaimed += 1
        return True

    @staticmethod
    def _tomb_positions(key_id: str) -> tuple[int, ...]:
        digest = hashlib.sha256(f"stage7:key-tombstone:{key_id}".encode()).digest()
        return tuple(
            int.from_bytes(digest[4 * i : 4 * i + 4], "big") % KEY_TOMBSTONE_BITS
            for i in range(_TOMBSTONE_HASHES)
        )

    def _tombstoned(self, key_id: str) -> bool:
        if not self._reclaimed:
            return False
        return all(
            self._tomb_bits[p >> 3] & (1 << (p & 7)) for p in self._tomb_positions(key_id)
        )

    def reclaimed(self) -> int:
        """Dead records reclaimed to make room (each one chained into the tombstone digest)."""
        return self._reclaimed

    def revoke(self, key_id: str, *, round_index: int) -> None:
        """Revoke a key now. Its material is dropped: it will never be checked again."""
        require_non_negative_int(round_index, "round_index")
        record = self._records.get(key_id)
        if record is None:
            raise ContractError(f"cannot revoke unknown key {key_id!r}")
        if record.state is KeyState.REVOKED:
            return
        self._records[key_id] = replace(record, state=KeyState.REVOKED, not_after_round=round_index)
        self._keys.pop(key_id, None)

    def sign(self, capsule: KnowledgeCapsuleV1, *, key_id: str) -> KnowledgeCapsuleV1:
        """Return ``capsule`` with an HMAC-SHA256 signature over its ``unsigned_bytes()``.

        The signature proves possession of the key, not host identity. Only an ACTIVE key
        signs, and only for a capsule whose contributor owns it: this host never emits a
        capsule it would itself refuse as ``contributor_key_mismatch``.
        """
        record = self._records.get(key_id)
        if record is None or record.state is not KeyState.ACTIVE:
            raise ContractError(f"only an ACTIVE registered key can sign: {key_id!r}")
        if capsule.key_id != key_id:
            raise ContractError(f"capsule names key {capsule.key_id!r}, not {key_id!r}")
        if capsule.provenance_commitment.contributor != record.owner:
            raise ContractError("a key signs only for the contributor that owns it")
        return replace(capsule, signature=_hmac_hex(self._keys[key_id], capsule.unsigned_bytes()))

    def verify(self, capsule: KnowledgeCapsuleV1, *, round_index: int) -> IntegrityVerdict:
        """Check the signature and the key-to-contributor binding at ``round_index``.

        A valid verdict proves that a holder of the key produced these bytes; it proves
        nothing about which host that holder is.
        """
        require_non_negative_int(round_index, "round_index")
        reason = self._refusal(capsule, round_index)
        return IntegrityVerdict(valid=reason is None, reason="ok" if reason is None else reason)

    def _refusal(self, capsule: KnowledgeCapsuleV1, round_index: int) -> str | None:
        if not capsule.signature:
            return "unsigned"
        record = self._records.get(capsule.key_id)
        if record is None:
            return "unknown_key"
        if record.state is KeyState.REVOKED:
            return "revoked_key"
        if record.state is KeyState.ROTATED and round_index > (record.not_after_round or 0):
            return "expired_key"
        if not _SIGNATURE.fullmatch(capsule.signature):
            return "bad_signature"
        expected = _hmac_hex(self._keys[capsule.key_id], capsule.unsigned_bytes())
        if not hmac.compare_digest(expected, capsule.signature):
            return "bad_signature"
        if capsule.provenance_commitment.contributor != record.owner:
            return "contributor_key_mismatch"
        return None

    def owner_of(self, key_id: str) -> str | None:
        record = self._records.get(key_id)
        return None if record is None else record.owner

    def record(self, key_id: str) -> KeyRecord | None:
        return self._records.get(key_id)

    def __len__(self) -> int:
        return len(self._records)

    def __bool__(self) -> bool:
        # A store is not a flag: without this, an EMPTY Keyring is falsy and
        # ``keyring or Keyring()`` silently swaps the caller's instance for a fresh one.
        return True

    def state_digest(self) -> str:
        """``sha256:`` over the sorted records, each key hashed; no key material is exposed."""
        rows: list[object] = [
            [rec.key_id, rec.owner, rec.state.value, rec.not_after_round, self._key_hashes[kid]]
            for kid, rec in sorted(self._records.items())
        ]
        if self._reclaimed:  # unchanged format until the first reclaim; then it is carried
            rows.append(["tombstones", self._reclaimed, self._tomb_chain])
        text = json.dumps(rows, separators=(",", ":"), allow_nan=False)
        return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()

    def verify_state(self, expected_digest: str) -> bool:
        """Whether the trust store still matches a digest recorded earlier (§43)."""
        if not isinstance(expected_digest, str) or not _DIGEST.fullmatch(expected_digest):
            return False
        return hmac.compare_digest(self.state_digest(), expected_digest)

    def memory_bytes(self) -> int:
        """An upper-bound estimate of the ring's footprint, in bytes."""
        per_key = sum(
            sys.getsizeof(rec) + sys.getsizeof(kid) * 2 + sys.getsizeof(rec.owner) + 97 + 64
            for kid, rec in self._records.items()
        )
        material = sum(sys.getsizeof(key) for key in self._keys.values())
        return (
            per_key
            + material
            + sys.getsizeof(self._tomb_bits)
            + sys.getsizeof(self._records)
            + sys.getsizeof(self._keys)
            + sys.getsizeof(self._key_hashes)
        )


class ReplayGuard:
    """Refuse duplicates, stale sequences and capsules outside their validity window.

    Both tables are LRU-bounded. Evicting an entry forgets that one replay defence for
    that key or capsule; the expiry window still bounds how long a replay can succeed.

    :meth:`prune` reclaims DEAD entries (R7-4): a seen id whose capsule has expired (a replay
    of it is refused as ``expired`` anyway, or by the high-water mark first), and every entry
    of a key that no longer verifies (integrity refuses its capsules before replay is asked).
    Without it, churn filled both tables with the history of peers that had left.
    """

    __slots__ = (
        "_high_water",
        "_max_keys",
        "_max_seen",
        "_pruned",
        "_seen",
        "_seen_evictions",
        "_water_evictions",
    )

    def __init__(
        self, *, max_keys: int = MAX_REPLAY_KEYS, max_seen: int = MAX_SEEN_CAPSULES
    ) -> None:
        for label, value in (("max_keys", max_keys), ("max_seen", max_seen)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ContractError(f"ReplayGuard {label} must be an int >= 1, got {value!r}")
        self._max_keys = max_keys
        self._max_seen = max_seen
        self._high_water: OrderedDict[str, int] = OrderedDict()
        self._seen: OrderedDict[str, tuple[str, int]] = OrderedDict()  # id -> (key, expiry)
        self._water_evictions = 0
        self._seen_evictions = 0
        self._pruned = 0

    def check(self, capsule: KnowledgeCapsuleV1, *, round_index: int) -> str | None:
        """The first replay/expiry refusal that applies, or ``None``. Changes no state."""
        require_non_negative_int(round_index, "round_index")
        if capsule.capsule_id in self._seen:
            return "duplicate_capsule"
        high_water = self._high_water.get(capsule.key_id)
        if high_water is not None and capsule.sequence <= high_water:
            return "replayed_sequence"
        if round_index >= capsule.expiry_round:
            return "expired"
        if round_index < capsule.created_round:
            return "not_yet_valid"
        return None

    def admit(self, capsule: KnowledgeCapsuleV1) -> None:
        """Record the capsule's id and raise its key's high-water mark. Refuses a replay."""
        if capsule.capsule_id in self._seen:
            raise ContractError(f"capsule {capsule.capsule_id} was already admitted")
        high_water = self._high_water.get(capsule.key_id)
        if high_water is not None and capsule.sequence <= high_water:
            raise ContractError(f"sequence {capsule.sequence} does not exceed {high_water}")
        self._high_water[capsule.key_id] = capsule.sequence
        self._high_water.move_to_end(capsule.key_id)
        while len(self._high_water) > self._max_keys:
            self._high_water.popitem(last=False)
            self._water_evictions += 1
        self._seen[capsule.capsule_id] = (capsule.key_id, capsule.expiry_round)
        while len(self._seen) > self._max_seen:
            self._seen.popitem(last=False)
            self._seen_evictions += 1

    def prune(self, *, round_index: int, key_live: Callable[[str], bool]) -> int:
        """Drop dead entries (see the class docstring); returns how many, also counted."""
        require_non_negative_int(round_index, "round_index")
        dead_keys = [k for k in self._high_water if key_live(k) is not True]
        for key_id in dead_keys:
            del self._high_water[key_id]
        dead_ids = [
            cid for cid, (key_id, expiry) in self._seen.items()
            if expiry <= round_index or key_live(key_id) is not True
        ]
        for capsule_id in dead_ids:
            del self._seen[capsule_id]
        self._pruned += len(dead_keys) + len(dead_ids)
        return len(dead_keys) + len(dead_ids)

    def pruned(self) -> int:
        return self._pruned

    def evictions(self) -> tuple[int, int]:
        """``(high-water entries evicted, seen-id entries evicted)`` over the guard's lifetime."""
        return (self._water_evictions, self._seen_evictions)

    def sizes(self) -> tuple[int, int]:
        """``(keys tracked, capsule ids tracked)``; each is at most its cap."""
        return (len(self._high_water), len(self._seen))

    def memory_bytes(self) -> int:
        """An upper-bound estimate of both tables, in bytes."""
        water = sum(sys.getsizeof(k) + 32 + 64 for k in self._high_water)
        seen = sum(sys.getsizeof(k) + sys.getsizeof(v[0]) + 96 for k, v in self._seen.items())
        return water + seen + sys.getsizeof(self._high_water) + sys.getsizeof(self._seen)
