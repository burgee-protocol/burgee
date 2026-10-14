"""Layer 2 state machine and the node runtime (spec sections 5, 6 and 9).

The machine is transport-agnostic: a :class:`Channel` carries opaque bytes in each
direction, a clock is injected, and the transport calls :meth:`Encounter.on_message` for
every inbound frame and :meth:`Encounter.tick` on a timer. The BLE transport and the
in-memory loopback both drive it the same way, so everything here is tested without a
radio.

Message flow (section 5 lifecycle, section 9 mutual authentication)::

    initiator                                   responder
    HAIL {eid, digest_i, profile, nonce_i}  --->
                                            <---  HAIL_ACK {digest_r, nonce_r, nonce_i}  (signed by R)
                                            <---  CARD_REQUEST {digest_i}   (only if R lacks I's card)
    CARD_REQUEST {digest_r} / PROPOSE ...   --->  first STREAM message carries n = nonce_i||nonce_r (signed by I)
    CARD {wire_i}                           --->  (on request)
                                            <---  CARD {wire_r}             (on request)
    ... PROPOSE / ACCEPT / COUNTER / DECLINE / STATUS / ABORT / SAFETY_STOP ...
    BYE                                     <-->

A frame that arrives before the peer's card is known is held and verified as soon as the
card is. Nothing is acted on before its signature has been checked against the key the
peer's card names, except HAIL and HAIL_ACK, which are read first and verified afterwards.
"""

from __future__ import annotations

import random
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from . import card as cardmod
from . import identity, messages, token
from .beacon import IdentityBeacon
from .messages import (
    Abort,
    Accept,
    Bye,
    Card,
    CardRequest,
    Counter,
    Decline,
    Hail,
    HailAck,
    Message,
    Propose,
    SafetyStop,
    Status,
)
from .registries import Capability, NodeClass, ReasonCode, SafetyCommand, StatusValue, profile_bits

# ---- constants from the spec ---------------------------------------------------------------

RSSI_THRESHOLD_DBM = -70
RSSI_CONSECUTIVE = 2
INITIATOR_WAIT_S = 0.5
TIMEOUT_HAILED_S = 2.0
TIMEOUT_VERIFIED_S = 3.0
TIMEOUT_PROPOSAL_S = 5.0
TIMEOUT_NEGOTIATION_S = 20.0
TIMEOUT_IDLE_S = 60.0
TIMEOUT_RANGE_LOST_S = 5.0
ROUND_TRIP_BOUND_S = 0.4
MAX_ENCOUNTERS_NODE = 4
MAX_ENCOUNTERS_MARK = 16
BACKOFF_RANGE_S = (1.0, 4.0)
HAIL_FLOOD_PER_MIN = 30
QUIET_PERIOD_S = 300.0
CARD_CACHE_S = 24 * 3600
STOP_RATE_LIMIT_S = 60.0


class State(Enum):
    OBSERVED = "observed"
    HAILED = "hailed"
    VERIFIED = "verified"
    NEGOTIATING = "negotiating"
    AGREED = "agreed"
    DECLINED = "declined"
    CLOSED = "closed"


class Role(Enum):
    INITIATOR = "initiator"
    RESPONDER = "responder"


class Channel(Protocol):
    """What a transport must provide: a way to send bytes to the peer and to hang up.
    Inbound bytes are pushed into :meth:`Encounter.on_message` by the transport."""

    def send(self, data: bytes) -> None: ...

    def close(self) -> None: ...


class EncounterError(Exception):
    """Raised when the machine is asked to do something its state does not allow."""


@dataclass
class Task:
    propose: Propose
    mine: bool  # True if this node proposed it
    state: str = "proposed"  # proposed | accepted | declined | countered | aborted | done | failed
    deadline: float = 0.0
    accept_params: dict[str, Any] = field(default_factory=dict)
    reason: ReasonCode | None = None


@dataclass
class Peer:
    ephemeral_id: bytes | None = None
    card_digest: bytes | None = None
    card: cardmod.AgentCard | None = None
    conformance_level: int = 1
    certified: bool = False
    nonce: bytes | None = None
    authenticated: bool = False
    retry_after_s: float | None = None  # set when the peer declined us with ``busy``

    @property
    def public_key(self) -> bytes | None:
        return self.card.burgee.public_key if self.card else None


class Handler(Protocol):
    """Application policy. The default implementation (:class:`Level1Handler`) declines every
    proposal with ``no_profile`` and reports its safe behavior, which is exactly what a
    Level 1 node does."""

    def on_propose(self, enc: Encounter, p: Propose) -> Accept | Decline | Counter: ...

    def on_agreed(self, enc: Encounter, task: Task) -> None: ...

    def on_declined(self, enc: Encounter, task: Task) -> None: ...

    def on_status(self, enc: Encounter, s: Status) -> None: ...

    def on_safety(self, enc: Encounter, command: SafetyCommand, zone: int, verified: bool) -> None: ...

    def on_closed(self, enc: Encounter, reason: str) -> None: ...


class Level1Handler:
    """Hailable but not negotiating: decline everything, say what you will do instead."""

    def __init__(self, safe_behavior: StatusValue = StatusValue.stopping) -> None:
        self.safe_behavior = safe_behavior

    def on_propose(self, enc: Encounter, p: Propose) -> Decline:
        enc.send(Status(task_id=p.task_id, status=self.safe_behavior))
        return Decline(task_id=p.task_id, reason=ReasonCode.no_profile)

    def on_agreed(self, enc: Encounter, task: Task) -> None:
        return None

    def on_declined(self, enc: Encounter, task: Task) -> None:
        return None

    def on_status(self, enc: Encounter, s: Status) -> None:
        return None

    def on_safety(self, enc: Encounter, command: SafetyCommand, zone: int, verified: bool) -> None:
        return None

    def on_closed(self, enc: Encounter, reason: str) -> None:
        return None


@dataclass
class LogEntry:
    t: float
    kind: str
    detail: str


class Encounter:
    """One authenticated session between two nodes, from hail to close."""

    def __init__(
        self,
        node: Node,
        role: Role,
        channel: Channel,
        now: float,
        *,
        profile: str = "rightofway/1",
        peer_ephemeral_id: bytes | None = None,
    ) -> None:
        self.node = node
        self.role = role
        self.channel = channel
        self.profile = profile
        self.state = State.OBSERVED
        self.peer = Peer(ephemeral_id=peer_ephemeral_id)
        self.opened_at = now
        self.last_activity = now
        self.deadline = now + TIMEOUT_HAILED_S
        self.negotiation_deadline: float | None = None
        self.tasks: dict[bytes, Task] = {}
        self.log: list[LogEntry] = []
        self.close_reason: str | None = None
        self._my_seq = 0
        self._their_seq = -1
        self._my_nonce = messages.new_nonce()
        self._first_stream_sent = False
        self._pending: deque[bytes] = deque()
        self._raw_hail: bytes | None = None
        self._raw_hail_ack: bytes | None = None
        self._raw_first_stream: bytes | None = None
        self._hail_sent_at: float | None = None
        self._peer_card_requested = False
        self._peer_needs_my_card = False

    # ---- helpers ---------------------------------------------------------------------------

    def _log(self, now: float, kind: str, detail: str = "") -> None:
        self.log.append(LogEntry(now, kind, detail))

    @property
    def nonces(self) -> bytes:
        """nonce_i || nonce_r, in that order, once both are known."""
        if self.peer.nonce is None:
            raise EncounterError("peer nonce not yet known")
        return (self._my_nonce + self.peer.nonce) if self.role is Role.INITIATOR else (self.peer.nonce + self._my_nonce)

    def _aad_out(self, message: Message) -> bytes:
        """External AAD binding a signature to this encounter: nothing for HAIL (no nonces yet),
        the initiator's nonce for HAIL_ACK, both nonces for everything after. A frame recorded
        in one encounter therefore fails verification in any other."""
        if isinstance(message, Hail):
            return b""
        if isinstance(message, HailAck):
            return self.peer.nonce or b""
        return self.nonces

    def _aad_in(self, message: Message) -> bytes:
        if isinstance(message, Hail):
            return b""
        if isinstance(message, HailAck):
            return self._my_nonce
        return self.nonces

    def send(self, message: Message) -> None:
        """Sign and send one message. The initiator's first STREAM message carries the nonces."""
        nonces = None
        if (
            self.role is Role.INITIATOR
            and not self._first_stream_sent
            and not isinstance(message, Hail)
            and self.peer.nonce is not None
        ):
            nonces = self.nonces
            self._first_stream_sent = True
        data = messages.encode(self.node.key, message, self._my_seq, nonces=nonces, aad=self._aad_out(message))
        self._my_seq += 1
        self.channel.send(data)

    def close(self, now: float, reason: str, *, send_bye: bool = True) -> None:
        if self.state is State.CLOSED:
            return
        if send_bye:
            try:
                self.send(Bye())
            except Exception:  # a dead channel must not stop the close
                pass
        self.state = State.CLOSED
        self.close_reason = reason
        self._log(now, "closed", reason)
        try:
            self.channel.close()
        finally:
            self.node._encounter_closed(self)
            self.node.handler.on_closed(self, reason)

    # ---- opening ---------------------------------------------------------------------------

    def start(self, now: float) -> None:
        """Initiator only: send HAIL."""
        if self.role is not Role.INITIATOR:
            raise EncounterError("only the initiator starts an encounter")
        self.state = State.HAILED
        self._hail_sent_at = now
        self.deadline = now + TIMEOUT_HAILED_S
        self.send(
            Hail(
                ephemeral_id=self.node.ephemeral_id,
                card_digest=self.node.card_digest,
                profile=self.profile,
                nonce=self._my_nonce,
                conformance_level=self.node.card.burgee.conformance_level,
            )
        )
        self._log(now, "hail", self.profile)

    # ---- inbound ---------------------------------------------------------------------------

    def on_message(self, data: bytes, now: float) -> None:
        """The transport delivers every inbound frame here. Nothing a peer sends can raise out
        of this method: a frame that is malformed in any way is logged and dropped."""
        if self.state is State.CLOSED:
            return
        self.last_activity = now
        try:
            self._on_message(data, now)
        except Exception as exc:  # defense in depth for a radio-facing callback
            self._log(now, "drop", f"{type(exc).__name__}: {exc}")

    def _on_message(self, data: bytes, now: float) -> None:
        try:
            env = messages.peek(data)
        except messages.MessageError as exc:
            self._log(now, "drop", f"unparseable frame: {exc}")
            return
        msg = env.message
        if isinstance(msg, Hail):
            self._on_hail(env, data, now)
            return
        if isinstance(msg, HailAck):
            self._on_hail_ack(env, data, now)
            return
        if isinstance(msg, Card):
            self._on_card(env, data, now)
            return
        if isinstance(msg, CardRequest):
            # A request for OUR card is served before the peer is verified: cards are public,
            # and the GATT CARD characteristic is readable by anyone in range anyway.
            self._on_card_request(env, data, now)
            return
        if (
            isinstance(msg, Decline)
            and msg.reason is ReasonCode.busy
            and msg.task_id == bytes(messages.TASK_ID_LEN)
            and self.role is Role.INITIATOR
            and self.state is State.HAILED
        ):
            # A busy responder declines before any card can be exchanged. Unverifiable, but all
            # it does is make us back off, which a jammer could force anyway.
            self.peer.retry_after_s = msg.retry_after_s
            self._log(now, "busy", f"retry after {msg.retry_after_s}s")
            self.close(now, "busy", send_bye=False)
            return
        # Everything else must be verified under the peer's key before it is acted on.
        if self.peer.public_key is None:
            self._pending.append(data)
            self._log(now, "hold", f"{msg.type.name} held until the peer's card arrives")
            return
        self._deliver_verified(data, now)

    def _verify(self, data: bytes) -> messages.Envelope:
        pub = self.peer.public_key
        if pub is None:
            raise messages.MessageError("peer key unknown")
        env = messages.decode(data, pub, aad=self.nonces)
        if env.seq <= self._their_seq:
            raise messages.MessageError(f"sequence {env.seq} not after {self._their_seq}")
        self._their_seq = env.seq
        return env

    def _deliver_verified(self, data: bytes, now: float) -> None:
        try:
            env = self._verify(data)
        except messages.MessageError as exc:
            self._log(now, "drop", f"verification failed: {exc}")
            return
        if self.role is Role.RESPONDER and not self.peer.authenticated:
            # The initiator's first STREAM message must carry the signed nonces.
            if env.nonces != self.nonces:
                self._log(now, "drop", "first STREAM message lacks the nonces")
                return
            self._authenticate_initiator(now)
        self._dispatch(env.message, now)

    def _authenticate_initiator(self, now: float) -> None:
        self.peer.authenticated = True
        self._log(now, "authenticated", "initiator proved its key")
        self._mark_verified(now)

    def _on_card_request(self, env: messages.Envelope, data: bytes, now: float) -> None:
        req: CardRequest = env.message  # type: ignore[assignment]
        if req.card_digest != self.node.card_digest:
            self._log(now, "drop", "CARD_REQUEST for a digest that is not ours")
            return
        if self.role is Role.RESPONDER and env.nonces is not None and not self.peer.authenticated:
            # This is the initiator's first STREAM message; keep it to verify once its card is here.
            self._raw_first_stream = data
            if self.peer.public_key is not None:
                self._verify_first_stream(now)
        self.send(Card(wire=self.node.card_wire))
        self._log(now, "card_sent")

    def _verify_first_stream(self, now: float) -> None:
        raw = self._raw_first_stream
        pub = self.peer.public_key
        if raw is None or pub is None or self.peer.authenticated:
            return
        try:
            env = messages.decode(raw, pub, aad=self.nonces)
        except messages.MessageError as exc:
            self._log(now, "drop", f"first STREAM signature: {exc}")
            return
        if env.nonces != self.nonces:
            self._log(now, "drop", "first STREAM message carries the wrong nonces")
            return
        self._their_seq = max(self._their_seq, env.seq)
        self._authenticate_initiator(now)

    def _flush_pending(self, now: float) -> None:
        while self._pending and self.peer.public_key is not None and self.state is not State.CLOSED:
            self._deliver_verified(self._pending.popleft(), now)

    # ---- handshake -------------------------------------------------------------------------

    def _on_hail(self, env: messages.Envelope, data: bytes, now: float) -> None:
        if self.role is not Role.RESPONDER or self.state not in (State.OBSERVED,):
            self._log(now, "drop", "unexpected HAIL")
            return
        h: Hail = env.message  # type: ignore[assignment]
        if not self.node.hail_allowed(h.ephemeral_id, now):
            self._log(now, "drop", "hail rate limit: quiet period")
            self.close(now, "quiet period", send_bye=False)
            return
        self._raw_hail = data
        self._their_seq = env.seq
        self.peer.ephemeral_id = h.ephemeral_id
        self.peer.card_digest = h.card_digest
        self.peer.nonce = h.nonce
        self.peer.conformance_level = h.conformance_level
        self.profile = h.profile
        self.state = State.HAILED
        self.deadline = now + TIMEOUT_VERIFIED_S
        self._log(now, "hailed", h.profile)
        if self.node.over_limit(self):
            # Spec section 5: beyond the limit, new hails are declined ``busy`` with a 1–4 s backoff.
            backoff = self.node.backoff_s()
            self.send(Decline(task_id=bytes(messages.TASK_ID_LEN), reason=ReasonCode.busy, retry_after_s=backoff))
            self.close(now, "busy", send_bye=False)
            return
        self.send(
            HailAck(
                card_digest=self.node.card_digest,
                nonce=self._my_nonce,
                peer_nonce=h.nonce,
                conformance_level=self.node.card.burgee.conformance_level,
            )
        )
        cached = self.node.card_cache.get(h.card_digest, now)
        if cached is not None:
            self._adopt_peer_card(cached, now)
        else:
            self.send(CardRequest(card_digest=h.card_digest))
            self._peer_card_requested = True

    def _on_hail_ack(self, env: messages.Envelope, data: bytes, now: float) -> None:
        if self.role is not Role.INITIATOR or self.state is not State.HAILED:
            self._log(now, "drop", "unexpected HAIL_ACK")
            return
        a: HailAck = env.message  # type: ignore[assignment]
        if a.peer_nonce != self._my_nonce:
            self._log(now, "drop", "HAIL_ACK echoes the wrong nonce")
            return
        if self._hail_sent_at is not None and now - self._hail_sent_at > ROUND_TRIP_BOUND_S:
            self._log(now, "drop", "HAIL round trip over the relay bound")
            self.close(now, "relay bound", send_bye=False)
            return
        self._raw_hail_ack = data
        self._their_seq = env.seq
        self.peer.card_digest = a.card_digest
        self.peer.nonce = a.nonce
        self.peer.conformance_level = a.conformance_level
        self.deadline = now + TIMEOUT_VERIFIED_S
        self._log(now, "hail_ack")
        cached = self.node.card_cache.get(a.card_digest, now)
        if cached is not None:
            self._adopt_peer_card(cached, now)
        else:
            self.send(CardRequest(card_digest=a.card_digest))
            self._peer_card_requested = True

    def _on_card(self, env: messages.Envelope, data: bytes, now: float) -> None:
        c: Card = env.message  # type: ignore[assignment]
        try:
            peer_card = cardmod.AgentCard.from_wire(c.wire)
        except cardmod.CardError as exc:
            self._log(now, "drop", f"bad card: {exc}")
            return
        if not peer_card.verify():
            self._log(now, "drop", "card self-signature does not verify")
            return
        if self.peer.card_digest is not None and peer_card.digest() != self.peer.card_digest:
            self._log(now, "drop", "card digest does not match the handshake")
            return
        if self.peer.nonce is None:
            self._log(now, "drop", "CARD before the handshake")
            return
        # The CARD envelope itself must be signed by the key the card names, bound to this encounter.
        try:
            verified = messages.decode(data, peer_card.burgee.public_key, aad=self.nonces)
        except messages.MessageError as exc:
            self._log(now, "drop", f"CARD envelope: {exc}")
            return
        self._their_seq = max(self._their_seq, verified.seq)
        self.node.card_cache.put(peer_card, now)
        self._adopt_peer_card(peer_card, now)
        # When the responder had the initiator's card to fetch, the initiator's CARD is its first
        # STREAM message and carries the nonces that complete mutual authentication.
        if (
            self.role is Role.RESPONDER
            and not self.peer.authenticated
            and verified.nonces is not None
            and verified.nonces == self.nonces
            and self.peer.card is peer_card
        ):
            self._authenticate_initiator(now)
            self._flush_pending(now)

    def _adopt_peer_card(self, peer_card: cardmod.AgentCard, now: float) -> None:
        self.peer.card = peer_card
        self.peer.certified = peer_card.is_certified(self.node.trusted_registry_keys, now=now)
        pub = peer_card.burgee.public_key
        # Retroactively verify the handshake message we could only read before.
        raw = self._raw_hail if self.role is Role.RESPONDER else self._raw_hail_ack
        if raw is None:
            self._log(now, "drop", "card arrived before the handshake")
            self.close(now, "protocol error", send_bye=False)
            return
        try:
            messages.decode(raw, pub, aad=b"" if self.role is Role.RESPONDER else self._my_nonce)
        except messages.MessageError as exc:
            self._log(now, "drop", f"handshake signature: {exc}")
            self.close(now, "handshake failed", send_bye=False)
            return
        self._log(now, "card", f"{peer_card.name} level {peer_card.burgee.conformance_level}")
        if self.role is Role.INITIATOR:
            # HAIL_ACK verified under the responder's key: the responder is authenticated.
            self.peer.authenticated = True
            self._mark_verified(now)
        else:
            self._verify_first_stream(now)
        self._flush_pending(now)

    def _mark_verified(self, now: float) -> None:
        if self.state is State.HAILED:
            self.state = State.VERIFIED
            self.deadline = now + TIMEOUT_IDLE_S
            self._log(now, "verified")

    # ---- negotiation -----------------------------------------------------------------------

    def _enter_negotiating(self, now: float) -> None:
        if self.state in (State.VERIFIED, State.AGREED, State.DECLINED):
            self.state = State.NEGOTIATING
            if self.negotiation_deadline is None:
                self.negotiation_deadline = now + TIMEOUT_NEGOTIATION_S
            self._log(now, "negotiating")

    def propose(
        self, action: str, params: dict[str, Any] | None = None, *, now: float, profile: str | None = None
    ) -> Task:
        """Send a PROPOSE under this encounter's profile. Allowed once the peer is verified."""
        if self.state not in (State.VERIFIED, State.NEGOTIATING, State.AGREED, State.DECLINED):
            raise EncounterError(f"cannot propose in state {self.state.value}")
        p = Propose(task_id=messages.new_task_id(), profile=profile or self.profile, action=action, params=params or {})
        task = Task(propose=p, mine=True, deadline=now + TIMEOUT_PROPOSAL_S)
        self.tasks[p.task_id] = task
        self._enter_negotiating(now)
        self.send(p)
        self._log(now, "propose", f"{p.skill_id} {p.params}")
        return task

    def status(self, task_id: bytes, status: StatusValue, *, now: float, reason: ReasonCode | None = None) -> None:
        self.send(Status(task_id=task_id, status=status, reason=reason))
        t = self.tasks.get(task_id)
        if t is not None:
            if status is StatusValue.done:
                t.state = "done"
            elif status is StatusValue.failed:
                t.state = "failed"
        self._log(now, "status", f"{task_id.hex()} {status.name}")

    def abort(self, task_id: bytes, reason: ReasonCode, *, now: float) -> None:
        self.send(Abort(task_id=task_id, reason=reason))
        t = self.tasks.get(task_id)
        if t is not None:
            t.state = "aborted"
            t.reason = reason
        self._log(now, "abort", f"{task_id.hex()} {reason.name}")

    def safety_stop(self, command: SafetyCommand, zone: int, token_bytes: bytes, *, now: float) -> None:
        """Marks and authority nodes only."""
        self.send(SafetyStop(command=command, zone=zone, token=token_bytes))
        self._log(now, "safety_stop", command.name)

    def _dispatch(self, msg: Message, now: float) -> None:
        if isinstance(msg, Bye):
            self.close(now, "peer said bye", send_bye=False)
        elif isinstance(msg, Propose):
            self._on_propose(msg, now)
        elif isinstance(msg, Counter):
            self._on_counter(msg, now)
        elif isinstance(msg, Accept):
            self._on_accept(msg, now)
        elif isinstance(msg, Decline):
            self._on_decline(msg, now)
        elif isinstance(msg, Status):
            self._on_status(msg, now)
        elif isinstance(msg, Abort):
            t = self.tasks.get(msg.task_id)
            if t is not None:
                t.state = "aborted"
                t.reason = msg.reason
            self._log(now, "aborted_by_peer", msg.reason.name)
        elif isinstance(msg, SafetyStop):
            self._on_safety_stop(msg, now)
        else:
            self._log(now, "drop", f"unexpected {msg.type.name}")

    def _on_propose(self, p: Propose, now: float) -> None:
        if self.state not in (State.VERIFIED, State.NEGOTIATING, State.AGREED, State.DECLINED):
            self._log(now, "drop", "PROPOSE before verification")
            return
        self.tasks[p.task_id] = Task(propose=p, mine=False, deadline=now + TIMEOUT_PROPOSAL_S)
        self._enter_negotiating(now)
        self._log(now, "proposed_by_peer", f"{p.skill_id} {p.params}")
        self._answer(p, now)

    def _on_counter(self, c: Counter, now: float) -> None:
        ref = self.tasks.get(c.ref_task_id)
        if ref is not None:
            ref.state = "countered"
        p = Propose(task_id=c.task_id, profile=c.profile, action=c.action, params=c.params)
        self.tasks[p.task_id] = Task(propose=p, mine=False, deadline=now + TIMEOUT_PROPOSAL_S)
        self._enter_negotiating(now)
        self._log(now, "countered_by_peer", f"{p.skill_id} {p.params}")
        self._answer(p, now)

    def _answer(self, p: Propose, now: float) -> None:
        if p.profile not in self.node.card.burgee.profiles or self.node.card.burgee.conformance_level < 2:
            self.send(Status(task_id=p.task_id, status=self.node.safe_behavior))
            reply: Accept | Decline | Counter = Decline(task_id=p.task_id, reason=ReasonCode.no_profile)
        else:
            reply = self.node.handler.on_propose(self, p)
        self.send(reply)
        t = self.tasks[p.task_id]
        if isinstance(reply, Accept):
            t.state = "accepted"
            t.accept_params = dict(reply.params)
            self.state = State.AGREED
            self._log(now, "accepted", p.skill_id)
            self.node.handler.on_agreed(self, t)
        elif isinstance(reply, Decline):
            t.state = "declined"
            t.reason = reply.reason
            self.state = State.DECLINED
            self._log(now, "declined", f"{p.skill_id} {reply.reason.name}")
            self.node.handler.on_declined(self, t)
        else:
            t.state = "countered"
            mine = Propose(task_id=reply.task_id, profile=reply.profile, action=reply.action, params=reply.params)
            self.tasks[mine.task_id] = Task(propose=mine, mine=True, deadline=now + TIMEOUT_PROPOSAL_S)
            self.state = State.NEGOTIATING
            self._log(now, "counter", mine.skill_id)

    def _on_accept(self, a: Accept, now: float) -> None:
        t = self.tasks.get(a.task_id)
        if t is None or not t.mine:
            self._log(now, "drop", "ACCEPT for an unknown task")
            return
        t.state = "accepted"
        t.accept_params = dict(a.params)
        self.state = State.AGREED
        self._log(now, "agreed", t.propose.skill_id)
        self.node.handler.on_agreed(self, t)

    def _on_decline(self, d: Decline, now: float) -> None:
        t = self.tasks.get(d.task_id)
        if t is None or not t.mine:
            self._log(now, "drop", "DECLINE for an unknown task")
            return
        t.state = "declined"
        t.reason = d.reason
        self.state = State.DECLINED
        self._log(now, "declined_by_peer", f"{t.propose.skill_id} {d.reason.name}")
        self.node.handler.on_declined(self, t)

    def _on_status(self, s: Status, now: float) -> None:
        t = self.tasks.get(s.task_id)
        if t is not None:
            if s.status is StatusValue.done:
                t.state = "done"
            elif s.status is StatusValue.failed:
                t.state = "failed"
                t.reason = s.reason
        self._log(now, "status_from_peer", s.status.name)
        self.node.handler.on_status(self, s)

    def _on_safety_stop(self, s: SafetyStop, now: float) -> None:
        verified = False
        try:
            tok = token.verify(s.token, self.node.trusted_roots, now=now)
            verified = tok.zone == s.zone and tok.allows(s.command)
        except (token.TokenError, ValueError) as exc:
            self._log(now, "safety_unverified", f"{s.command.name}: {exc}")
        if verified:
            self._log(now, "safety", f"{s.command.name} zone {s.zone}")
            self.node.handler.on_safety(self, s.command, s.zone, True)
        elif s.command is SafetyCommand.stop and self.node.stop_allowed_unverified(self.peer.ephemeral_id or b"", now):
            self.node.handler.on_safety(self, s.command, s.zone, False)

    # ---- time ------------------------------------------------------------------------------

    def tick(self, now: float) -> None:
        """Apply timeouts. The transport calls this on a timer."""
        if self.state is State.CLOSED:
            return
        if self.state in (State.HAILED,) and now > self.deadline:
            self.close(now, "handshake timeout", send_bye=False)
            return
        if self.state is State.NEGOTIATING:
            for t in list(self.tasks.values()):
                if t.state == "proposed" and now > t.deadline:
                    t.state = "declined"
                    t.reason = ReasonCode.timeout
                    self._log(now, "proposal_timeout", t.propose.skill_id)
            if self.negotiation_deadline is not None and now > self.negotiation_deadline:
                self.close(now, "negotiation timeout")
                return
        if now - self.last_activity > TIMEOUT_IDLE_S:
            self.close(now, "idle")

    def range_lost(self, now: float) -> None:
        """The transport reports the peer out of range for 5 s."""
        self.close(now, "range lost", send_bye=False)


# ---- node runtime --------------------------------------------------------------------------


class CardCache:
    """Cards by digest, 24 hours."""

    def __init__(self) -> None:
        self._items: dict[bytes, tuple[cardmod.AgentCard, float]] = {}

    def get(self, digest: bytes, now: float) -> cardmod.AgentCard | None:
        item = self._items.get(digest)
        if item is None:
            return None
        card_, stored = item
        if now - stored > CARD_CACHE_S:
            del self._items[digest]
            return None
        return card_

    def put(self, card_: cardmod.AgentCard, now: float) -> None:
        self._items[card_.digest()] = (card_, now)

    def __len__(self) -> int:
        return len(self._items)


@dataclass
class Sighting:
    ephemeral_id: bytes
    beacon: IdentityBeacon
    rssi: int
    consecutive: int
    last_seen: float
    qualified_at: float | None = None  # when the current run of qualifying beacons began


MARK_CLASSES = (NodeClass.mark_gate, NodeClass.charger, NodeClass.lift)


class Node:
    """A Burgee participant: its key, its card, its beacon, and its open encounters."""

    def __init__(
        self,
        key: identity.NodeKey,
        card_: cardmod.AgentCard,
        *,
        handler: Handler | None = None,
        clock: Callable[[], float] = time.time,
        trusted_registry_keys: dict[bytes, bytes] | None = None,
        trusted_roots: dict[bytes, bytes] | None = None,
        safe_behavior: StatusValue = StatusValue.stopping,
        rssi_threshold_dbm: int = RSSI_THRESHOLD_DBM,
        rng: random.Random | None = None,
    ) -> None:
        if key.public_key != card_.burgee.public_key:
            raise EncounterError("the card must name this node's key")
        if not card_.verify():
            raise EncounterError("the card must be signed")
        self.key = key
        self.card = card_
        self.card_digest = card_.digest()
        self.card_wire = card_.to_wire()
        self.handler: Handler = handler or Level1Handler(safe_behavior)
        self.clock = clock
        self.trusted_registry_keys = dict(trusted_registry_keys or {})
        self.trusted_roots = dict(trusted_roots or {})
        self.safe_behavior = safe_behavior
        self.rssi_threshold_dbm = rssi_threshold_dbm
        self.rng = rng or random.Random()
        self.eids = identity.EphemeralIdSource(key.public_key, clock=clock)
        self.card_cache = CardCache()
        self.encounters: list[Encounter] = []
        self.sightings: dict[bytes, Sighting] = {}
        self._hails: dict[bytes, deque[float]] = {}
        self._quiet_until: dict[bytes, float] = {}
        self._last_unverified_stop: dict[bytes, float] = {}
        self.is_mark = (
            bool(card_.burgee.capabilities & int(Capability.is_mark)) or card_.burgee.node_class in MARK_CLASSES
        )

    # ---- identity on the air ---------------------------------------------------------------

    @property
    def ephemeral_id(self) -> bytes:
        return self.eids.ephemeral_id

    @property
    def max_encounters(self) -> int:
        return MAX_ENCOUNTERS_MARK if self.is_mark else MAX_ENCOUNTERS_NODE

    def identity_beacon(
        self, *, state, heading_deg=None, speed_mps=None, timestamp_tenths: int | None = None
    ) -> IdentityBeacon:
        """The IDENTITY beacon for this node right now (encode it with ``beacon_session_key``)."""
        from .beacon import tenths_in_hour

        b = self.card.burgee
        return IdentityBeacon(
            node_class=b.node_class,
            ephemeral_id=self.ephemeral_id,
            capabilities=b.capabilities,
            state=state,
            priority_class=b.priority_class,
            profiles=profile_bits(b.profiles),
            timestamp_tenths=tenths_in_hour(self.clock()) if timestamp_tenths is None else timestamp_tenths,
            heading_deg=heading_deg,
            speed_mps=speed_mps,
            footprint_w_m=b.footprint_w_m,
            footprint_l_m=b.footprint_l_m,
        )

    @property
    def beacon_session_key(self) -> bytes:
        return self.eids.session_key

    # ---- observing and deciding to hail ----------------------------------------------------

    def observe(self, beacon: IdentityBeacon, rssi: int, now: float) -> bool:
        """Record a burgee seen on the air. Returns True when this node should open an encounter
        with that peer now: two consecutive beacons above the RSSI threshold, a profile in
        common, this node is the one that initiates, and there is room for another encounter."""
        from .beacon import tenths_in_hour, timestamp_is_fresh

        eid = beacon.ephemeral_id
        s = self.sightings.get(eid)
        fresh = timestamp_is_fresh(beacon.timestamp_tenths, tenths_in_hour(now))
        if rssi >= self.rssi_threshold_dbm and fresh:
            consecutive = (s.consecutive + 1) if s else 1
            qualified_at = s.qualified_at if (s and s.consecutive) else now
        else:
            consecutive = 0
            qualified_at = None
        self.sightings[eid] = Sighting(eid, beacon, rssi, consecutive, now, qualified_at)
        if consecutive < RSSI_CONSECUTIVE:
            return False
        if not (beacon.profiles & profile_bits(self.card.burgee.profiles)):
            return False
        if self.is_mark or self.card.burgee.conformance_level < 2:
            return False  # a mark never initiates; a Level 1 node is hailable, not hailing
        if any(e.peer.ephemeral_id == eid and e.state is not State.CLOSED for e in self.encounters):
            return False
        peer_is_mark = bool(beacon.capabilities & int(Capability.is_mark)) or beacon.node_class in MARK_CLASSES
        if not peer_is_mark and not identity.should_initiate(self.ephemeral_id, eid):
            # The higher ephemeral ID waits 500 ms for the lower one to hail before trying itself.
            if qualified_at is None or now - qualified_at < INITIATOR_WAIT_S:
                return False
        return len(self.open_encounters()) < self.max_encounters

    def open_encounters(self) -> list[Encounter]:
        return [e for e in self.encounters if e.state is not State.CLOSED]

    # ---- opening encounters ----------------------------------------------------------------

    def initiate(
        self, channel: Channel, peer_ephemeral_id: bytes, *, profile: str = "rightofway/1", now: float | None = None
    ) -> Encounter:
        """Open an encounter as the initiator over an already-connected channel."""
        now = self.clock() if now is None else now
        if len(self.open_encounters()) >= self.max_encounters:
            raise EncounterError("encounter limit reached")
        enc = Encounter(self, Role.INITIATOR, channel, now, profile=profile, peer_ephemeral_id=peer_ephemeral_id)
        self.encounters.append(enc)
        enc.start(now)
        return enc

    def accept(self, channel: Channel, *, now: float | None = None) -> Encounter:
        """Accept an inbound connection as the responder. Over the limit, the peer gets
        DECLINE ``busy`` with a randomized 1–4 s backoff hint and the channel closes."""
        now = self.clock() if now is None else now
        enc = Encounter(self, Role.RESPONDER, channel, now)
        self.encounters.append(enc)
        return enc

    def over_limit(self, enc: Encounter) -> bool:
        """True when ``enc`` is one encounter more than this node may hold."""
        return len(self.open_encounters()) > self.max_encounters

    def backoff_s(self) -> float:
        return round(self.rng.uniform(*BACKOFF_RANGE_S), 1)

    def _encounter_closed(self, enc: Encounter) -> None:
        return None

    def tick(self, now: float | None = None) -> None:
        now = self.clock() if now is None else now
        for e in list(self.encounters):
            e.tick(now)
        self.encounters = [e for e in self.encounters if e.state is not State.CLOSED or now - e.last_activity < 60]

    # ---- rate limits -----------------------------------------------------------------------

    def hail_allowed(self, peer_eid: bytes, now: float) -> bool:
        if self._quiet_until.get(peer_eid, 0.0) > now:
            return False
        q = self._hails.setdefault(peer_eid, deque())
        q.append(now)
        while q and now - q[0] > 60.0:
            q.popleft()
        if len(q) > HAIL_FLOOD_PER_MIN:
            self._quiet_until[peer_eid] = now + QUIET_PERIOD_S
            return False
        return True

    def stop_allowed_unverified(self, peer_eid: bytes, now: float) -> bool:
        """STOP from an unverified source is honored, logged, and rate-limited to one per 60 s
        per ephemeral ID."""
        last = self._last_unverified_stop.get(peer_eid)
        if last is not None and now - last < STOP_RATE_LIMIT_S:
            return False
        self._last_unverified_stop[peer_eid] = now
        return True

    # ---- log -------------------------------------------------------------------------------

    def encounter_records(self) -> list[dict[str, Any]]:
        """One record per encounter for the local log (section 9: kept 30 days, never sent)."""
        out = []
        for e in self.encounters:
            out.append(
                {
                    "role": e.role.value,
                    "peer_stable_id": e.peer.card.burgee.stable_id.hex() if e.peer.card else None,
                    "profile": e.profile,
                    "state": e.state.value,
                    "tasks": [
                        {
                            "skill": t.propose.skill_id,
                            "mine": t.mine,
                            "state": t.state,
                            "reason": t.reason.name if t.reason else None,
                        }
                        for t in e.tasks.values()
                    ],
                    "opened_at": e.opened_at,
                    "closed": e.close_reason,
                }
            )
        return out
