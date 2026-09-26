"""D7.4 — the bounded table of pseudonymous peers a receiving host has heard from.

A *peer* here is a contributor pseudonym (``"peer-" + 16 hex``) together with the key
it signed with and the two things it **declared** about itself: an administrative
provenance root and a role class. None of the three is verified by this table. The key
binding is checked by :class:`~pocketsec.stage7.identity.integrity.Keyring` (and that
proves key possession, not host identity); the root and role are claims the dependence
graph weighs and the lab alone knows the truth of. Stage 12's trust graph reads this
table as input, never as a verdict.

Why the table exists at all: every later stage keys its state on a peer, so the number
of peers is the number an adversary most wants to inflate. The table is therefore
bounded (:data:`MAX_PEERS`), and its eviction rule is chosen so that **a flood of fresh
identities can never displace established peers**:

* a known peer refreshes its ``last_seen_round``;
* a newcomer takes a free slot if there is one;
* on a full table the least-recently-seen entry is evicted **only if it has been idle
  for more than** :data:`PEER_IDLE_ROUNDS` rounds, and the eviction is recorded;
* otherwise the newcomer is **refused** (``None``) and counted.

An LRU that always evicted would hand the table to whoever sends the most identities
per round; refusing newcomers instead costs the flood's identities, not the honest
peers'. The price is stated plainly: while the table is full of active peers, a new
honest peer is refused too. That is the bound doing its job, and ``refused()`` makes it
visible.

What the first declaration binds: ``provenance_root`` and ``role_claim`` are fixed at
first sight. A later capsule that declares a different root or role under the same
pseudonym does not rewrite the record — otherwise a peer could hop roots after being
clustered and launder its dependence edges — and the disagreement is counted in
``claim_conflicts()``. The signing ``key_id`` does follow the latest capsule, because
key rotation is legitimate and the keyring already bound the key to this pseudonym.

Time is rounds, never wall clock, and rounds may not run backwards.
"""

from __future__ import annotations

import re
import sys
from collections import OrderedDict, deque
from dataclasses import dataclass, replace

from pocketsec.stage0.contracts.common import ContractError, require_non_negative_int
from pocketsec.stage7.capsule.knowledge_capsule import RoleClass

__all__ = [
    "MAX_PEERS",
    "MAX_PEER_EVICTION_LOG",
    "PEER_IDLE_ROUNDS",
    "PeerIdentity",
    "PeerTable",
]

#: §4.23. Chosen parameters, not measurements.
MAX_PEERS: int = 1024
PEER_IDLE_ROUNDS: int = 64
MAX_PEER_EVICTION_LOG: int = 256

_PEER_ID = re.compile(r"^peer-[0-9a-f]{16}$")
_KEY_ID = re.compile(r"^key-[0-9a-f]{16}$")
_ROOT_ID = re.compile(r"^root-[0-9a-f]{16}$")

#: A rough per-entry cost of one ``PeerIdentity`` plus its table slot, used only when
#: ``sys.getsizeof`` cannot see through a slotted object's referents.
_ENTRY_OVERHEAD_BYTES: int = 104


def _require_shape(value: object, pattern: re.Pattern[str], field: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ContractError(f"{field} has the wrong shape: {value!r}")
    return value


@dataclass(frozen=True, slots=True)
class PeerIdentity:
    """One pseudonymous peer as this host has seen it. Every claim in it is declared."""

    peer_id: str
    key_id: str
    provenance_root: str
    role_claim: RoleClass
    first_seen_round: int
    last_seen_round: int

    def __post_init__(self) -> None:
        _require_shape(self.peer_id, _PEER_ID, "PeerIdentity.peer_id")
        _require_shape(self.key_id, _KEY_ID, "PeerIdentity.key_id")
        _require_shape(self.provenance_root, _ROOT_ID, "PeerIdentity.provenance_root")
        if not isinstance(self.role_claim, RoleClass):
            raise ContractError(f"PeerIdentity.role_claim must be a RoleClass: {self.role_claim!r}")
        require_non_negative_int(self.first_seen_round, "PeerIdentity.first_seen_round")
        require_non_negative_int(self.last_seen_round, "PeerIdentity.last_seen_round")
        if self.last_seen_round < self.first_seen_round:
            raise ContractError("PeerIdentity.last_seen_round precedes first_seen_round")


class PeerTable:
    """A bounded peer table whose eviction can never be driven by a flood of newcomers.

    Entries are kept in recency order (an ``OrderedDict`` moved-to-end on every
    observation), so the first entry is always the least-recently-seen one and the
    eviction decision looks at exactly one candidate.
    """

    __slots__ = (
        "_capacity",
        "_claim_conflicts",
        "_eviction_log",
        "_evictions",
        "_idle_rounds",
        "_latest_round",
        "_peers",
        "_refused",
    )

    def __init__(self, *, capacity: int = MAX_PEERS, idle_rounds: int = PEER_IDLE_ROUNDS) -> None:
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 1:
            raise ContractError(f"PeerTable capacity must be an int >= 1, got {capacity!r}")
        require_non_negative_int(idle_rounds, "PeerTable idle_rounds")
        self._capacity = capacity
        self._idle_rounds = idle_rounds
        self._peers: OrderedDict[str, PeerIdentity] = OrderedDict()
        self._eviction_log: deque[tuple[str, int]] = deque(maxlen=MAX_PEER_EVICTION_LOG)
        self._evictions = 0
        self._refused = 0
        self._claim_conflicts = 0
        self._latest_round = 0

    def observe(
        self,
        peer_id: str,
        *,
        key_id: str,
        provenance_root: str,
        role_claim: RoleClass,
        round_index: int,
    ) -> PeerIdentity | None:
        """Record that ``peer_id`` was heard from; ``None`` means the newcomer was refused.

        A refusal is not an error: it is the table being full of peers that are still
        active, and it is counted in :meth:`refused`.
        """
        self._advance(round_index)
        known = self._peers.get(peer_id)
        if known is not None:
            return self._refresh(
                known,
                key_id=key_id,
                provenance_root=provenance_root,
                role_claim=role_claim,
                round_index=round_index,
            )
        candidate = PeerIdentity(
            peer_id=peer_id,
            key_id=key_id,
            provenance_root=provenance_root,
            role_claim=role_claim,
            first_seen_round=round_index,
            last_seen_round=round_index,
        )
        if len(self._peers) >= self._capacity and not self._evict_idle(round_index):
            self._refused += 1
            return None
        self._peers[peer_id] = candidate
        return candidate

    def _advance(self, round_index: int) -> None:
        require_non_negative_int(round_index, "round_index")
        if round_index < self._latest_round:
            raise ContractError(
                f"rounds may not run backwards: {round_index} < {self._latest_round}"
            )
        self._latest_round = round_index

    def _refresh(
        self,
        known: PeerIdentity,
        *,
        key_id: str,
        provenance_root: str,
        role_claim: RoleClass,
        round_index: int,
    ) -> PeerIdentity:
        # The first declaration binds; a changed claim is counted, never adopted.
        if provenance_root != known.provenance_root or role_claim != known.role_claim:
            self._claim_conflicts += 1
        updated = replace(known, key_id=key_id, last_seen_round=round_index)
        self._peers[known.peer_id] = updated
        self._peers.move_to_end(known.peer_id)
        return updated

    def _evict_idle(self, round_index: int) -> bool:
        """Evict the least-recently-seen peer if, and only if, it is idle past the bound."""
        oldest_id, oldest = next(iter(self._peers.items()))
        if round_index - oldest.last_seen_round <= self._idle_rounds:
            return False
        del self._peers[oldest_id]
        self._evictions += 1
        self._eviction_log.append((oldest_id, round_index))
        return True

    def get(self, peer_id: str) -> PeerIdentity | None:
        return self._peers.get(peer_id)

    def __len__(self) -> int:
        return len(self._peers)

    def __bool__(self) -> bool:
        # A store is not a flag: without this, an EMPTY PeerTable is falsy and
        # ``peers or PeerTable()`` silently swaps the caller's instance for a fresh one.
        return True

    def __contains__(self, peer_id: object) -> bool:
        return peer_id in self._peers

    @property
    def capacity(self) -> int:
        return self._capacity

    def refused(self) -> int:
        """Newcomers turned away because every slot held a peer active within the bound."""
        return self._refused

    def evictions(self) -> int:
        """Idle peers evicted to make room, over the table's lifetime (the log keeps 256)."""
        return self._evictions

    def eviction_log(self) -> tuple[tuple[str, int], ...]:
        """``(peer_id, round evicted)`` of the last :data:`MAX_PEER_EVICTION_LOG` evictions."""
        return tuple(self._eviction_log)

    def claim_conflicts(self) -> int:
        """Observations whose declared root or role disagreed with the peer's first declaration."""
        return self._claim_conflicts

    def memory_bytes(self) -> int:
        """An upper-bound estimate of what the table holds, in bytes."""
        entries = sum(
            sys.getsizeof(peer)
            + sys.getsizeof(peer.peer_id)
            + sys.getsizeof(peer.key_id)
            + sys.getsizeof(peer.provenance_root)
            + _ENTRY_OVERHEAD_BYTES
            for peer in self._peers.values()
        )
        log = sum(sys.getsizeof(peer_id) + 64 for peer_id, _ in self._eviction_log)
        return entries + log + sys.getsizeof(self._peers) + sys.getsizeof(self._eviction_log)
