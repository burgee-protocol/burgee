"""Layer 3: the message set (spec section 6).

Every message is a COSE_Sign1 (EdDSA) over a CBOR map::

    {"t": <MessageType>, "s": <sequence>, "b": <body>, "n": <nonce_i || nonce_r>?}

``n`` appears only on the initiator's first STREAM message, where it completes mutual
authentication (section 9). The COSE external AAD binds every signature to its encounter:
empty for HAIL, the initiator's nonce for HAIL_ACK, both nonces for everything after, so a
frame recorded in one encounter does not verify in another.

Field names on the wire are short so a typical PROPOSE stays under one 247-byte MTU; the
Python attribute names are the spec's. Every decoder checks the type and length of what it
reads, because the bytes come from a stranger's radio.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, ClassVar

import cbor2

from . import cose, identity
from .registries import MessageType, ReasonCode, SafetyCommand, StatusValue

NONCE_LEN = 16
TASK_ID_LEN = 8
DIGEST_LEN = 32
EID_LEN = 8
MAX_PROFILE_LEN = 32
MAX_ACTION_LEN = 32
MAX_NOTE_LEN = 120
MAX_PARAMS = 16
MAX_CARD_WIRE = 1024
MAX_TOKEN = 512


class MessageError(ValueError):
    """Raised for a malformed or unverifiable Layer 3 message."""


def new_nonce() -> bytes:
    return os.urandom(NONCE_LEN)


def new_task_id() -> bytes:
    return os.urandom(TASK_ID_LEN)


# ---- field checks ------------------------------------------------------------------------


def _bytes(b: Mapping[str, Any], key: str, length: int | None = None, *, max_len: int | None = None) -> bytes:
    v = b.get(key)
    if not isinstance(v, bytes):
        raise MessageError(f"field {key!r} must be bytes")
    if length is not None and len(v) != length:
        raise MessageError(f"field {key!r} must be {length} bytes")
    if max_len is not None and len(v) > max_len:
        raise MessageError(f"field {key!r} longer than {max_len} bytes")
    return v


def _str(b: Mapping[str, Any], key: str, max_len: int, default: str | None = None) -> str:
    v = b.get(key, default)
    if not isinstance(v, str) or len(v) > max_len:
        raise MessageError(f"field {key!r} must be a string of at most {max_len} characters")
    return v


def _int(b: Mapping[str, Any], key: str, lo: int, hi: int, default: int | None = None) -> int:
    v = b.get(key, default)
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        raise MessageError(f"field {key!r} must be an integer in [{lo}, {hi}]")
    return v


def _params(b: Mapping[str, Any], key: str = "x") -> dict[str, Any]:
    v = b.get(key, {})
    if not isinstance(v, Mapping) or len(v) > MAX_PARAMS:
        raise MessageError(f"field {key!r} must be a small map")
    out: dict[str, Any] = {}
    for k, val in v.items():
        if not isinstance(k, str) or len(k) > 32:
            raise MessageError("parameter names must be short strings")
        if isinstance(val, Mapping) or (isinstance(val, (list, tuple)) and len(val) > 16):
            raise MessageError(f"parameter {k!r} has an unsupported value")
        out[k] = list(val) if isinstance(val, tuple) else val
    return out


def _reason(b: Mapping[str, Any], key: str = "r") -> ReasonCode:
    v = _int(b, key, 0, 255)
    try:
        return ReasonCode(v)
    except ValueError:
        return ReasonCode.other


# ---- bodies ------------------------------------------------------------------------------


@dataclass
class Hail:
    type: ClassVar[MessageType] = MessageType.HAIL
    ephemeral_id: bytes
    card_digest: bytes
    profile: str
    nonce: bytes
    conformance_level: int = 1

    def body(self) -> dict[str, Any]:
        return {
            "e": self.ephemeral_id,
            "d": self.card_digest,
            "p": self.profile,
            "n": self.nonce,
            "l": self.conformance_level,
        }

    @classmethod
    def from_body(cls, b: Mapping[str, Any]) -> Hail:
        return cls(
            _bytes(b, "e", EID_LEN),
            _bytes(b, "d", DIGEST_LEN),
            _str(b, "p", MAX_PROFILE_LEN),
            _bytes(b, "n", NONCE_LEN),
            _int(b, "l", 0, 3, 1),
        )


@dataclass
class HailAck:
    type: ClassVar[MessageType] = MessageType.HAIL_ACK
    card_digest: bytes
    nonce: bytes  # the responder's nonce
    peer_nonce: bytes  # the initiator's nonce, echoed; the signature over both is the proof
    conformance_level: int = 1

    def body(self) -> dict[str, Any]:
        return {"d": self.card_digest, "n": self.nonce, "pn": self.peer_nonce, "l": self.conformance_level}

    @classmethod
    def from_body(cls, b: Mapping[str, Any]) -> HailAck:
        return cls(
            _bytes(b, "d", DIGEST_LEN), _bytes(b, "n", NONCE_LEN), _bytes(b, "pn", NONCE_LEN), _int(b, "l", 0, 3, 1)
        )


@dataclass
class CardRequest:
    type: ClassVar[MessageType] = MessageType.CARD_REQUEST
    card_digest: bytes

    def body(self) -> dict[str, Any]:
        return {"d": self.card_digest}

    @classmethod
    def from_body(cls, b: Mapping[str, Any]) -> CardRequest:
        return cls(_bytes(b, "d", DIGEST_LEN))


@dataclass
class Card:
    type: ClassVar[MessageType] = MessageType.CARD
    wire: bytes  # AgentCard.to_wire()

    def body(self) -> dict[str, Any]:
        return {"c": self.wire}

    @classmethod
    def from_body(cls, b: Mapping[str, Any]) -> Card:
        return cls(_bytes(b, "c", max_len=MAX_CARD_WIRE))


@dataclass
class Propose:
    type: ClassVar[MessageType] = MessageType.PROPOSE
    task_id: bytes
    profile: str
    action: str
    params: dict[str, Any] = field(default_factory=dict)

    def body(self) -> dict[str, Any]:
        return {"t": self.task_id, "p": self.profile, "a": self.action, "x": dict(self.params)}

    @classmethod
    def from_body(cls, b: Mapping[str, Any]) -> Propose:
        return cls(_bytes(b, "t", TASK_ID_LEN), _str(b, "p", MAX_PROFILE_LEN), _str(b, "a", MAX_ACTION_LEN), _params(b))

    @property
    def skill_id(self) -> str:
        return f"{self.profile}:{self.action}"


@dataclass
class Accept:
    type: ClassVar[MessageType] = MessageType.ACCEPT
    task_id: bytes
    params: dict[str, Any] = field(default_factory=dict)

    def body(self) -> dict[str, Any]:
        return {"t": self.task_id, "x": dict(self.params)}

    @classmethod
    def from_body(cls, b: Mapping[str, Any]) -> Accept:
        return cls(_bytes(b, "t", TASK_ID_LEN), _params(b))


@dataclass
class Counter:
    type: ClassVar[MessageType] = MessageType.COUNTER
    task_id: bytes
    ref_task_id: bytes
    profile: str
    action: str
    params: dict[str, Any] = field(default_factory=dict)

    def body(self) -> dict[str, Any]:
        return {"t": self.task_id, "r": self.ref_task_id, "p": self.profile, "a": self.action, "x": dict(self.params)}

    @classmethod
    def from_body(cls, b: Mapping[str, Any]) -> Counter:
        return cls(
            _bytes(b, "t", TASK_ID_LEN),
            _bytes(b, "r", TASK_ID_LEN),
            _str(b, "p", MAX_PROFILE_LEN),
            _str(b, "a", MAX_ACTION_LEN),
            _params(b),
        )


@dataclass
class Decline:
    type: ClassVar[MessageType] = MessageType.DECLINE
    task_id: bytes
    reason: ReasonCode
    note: str = ""
    retry_after_s: float | None = None  # with ``busy``: the randomized 1–4 s backoff

    def body(self) -> dict[str, Any]:
        b: dict[str, Any] = {"t": self.task_id, "r": int(self.reason)}
        if self.note:
            b["m"] = self.note
        if self.retry_after_s is not None:
            b["w"] = float(self.retry_after_s)
        return b

    @classmethod
    def from_body(cls, b: Mapping[str, Any]) -> Decline:
        retry = b.get("w")
        if retry is not None and (
            isinstance(retry, bool) or not isinstance(retry, (int, float)) or not 0 <= retry <= 60
        ):
            raise MessageError("field 'w' must be a number of seconds in [0, 60]")
        return cls(
            _bytes(b, "t", TASK_ID_LEN),
            _reason(b),
            _str(b, "m", MAX_NOTE_LEN, ""),
            float(retry) if retry is not None else None,
        )


@dataclass
class Status:
    type: ClassVar[MessageType] = MessageType.STATUS
    task_id: bytes
    status: StatusValue
    reason: ReasonCode | None = None

    def body(self) -> dict[str, Any]:
        b: dict[str, Any] = {"t": self.task_id, "v": int(self.status)}
        if self.reason is not None:
            b["r"] = int(self.reason)
        return b

    @classmethod
    def from_body(cls, b: Mapping[str, Any]) -> Status:
        v = _int(b, "v", 0, 255)
        try:
            status = StatusValue(v)
        except ValueError as exc:
            raise MessageError(f"unknown status value {v}") from exc
        reason = _reason(b) if "r" in b else None
        return cls(_bytes(b, "t", TASK_ID_LEN), status, reason)


@dataclass
class Abort:
    type: ClassVar[MessageType] = MessageType.ABORT
    task_id: bytes
    reason: ReasonCode

    def body(self) -> dict[str, Any]:
        return {"t": self.task_id, "r": int(self.reason)}

    @classmethod
    def from_body(cls, b: Mapping[str, Any]) -> Abort:
        return cls(_bytes(b, "t", TASK_ID_LEN), _reason(b))


@dataclass
class SafetyStop:
    type: ClassVar[MessageType] = MessageType.SAFETY_STOP
    command: SafetyCommand
    zone: int
    token: bytes  # full authority token (COSE_Sign1 bytes)

    def body(self) -> dict[str, Any]:
        return {"c": int(self.command), "z": self.zone, "k": self.token}

    @classmethod
    def from_body(cls, b: Mapping[str, Any]) -> SafetyStop:
        c = _int(b, "c", 0, 255)
        try:
            command = SafetyCommand(c)
        except ValueError as exc:
            raise MessageError(f"unknown safety command {c}") from exc
        return cls(command, _int(b, "z", 0, 255), _bytes(b, "k", max_len=MAX_TOKEN))


@dataclass
class Bye:
    type: ClassVar[MessageType] = MessageType.BYE

    def body(self) -> dict[str, Any]:
        return {}

    @classmethod
    def from_body(cls, b: Mapping[str, Any]) -> Bye:
        return cls()


Message = Hail | HailAck | CardRequest | Card | Propose | Accept | Counter | Decline | Status | Abort | SafetyStop | Bye

_BY_TYPE: dict[int, type] = {
    int(c.type): c
    for c in (Hail, HailAck, CardRequest, Card, Propose, Accept, Counter, Decline, Status, Abort, SafetyStop, Bye)
}


# ---- envelope ----------------------------------------------------------------------------


@dataclass(frozen=True)
class Envelope:
    message: Message
    seq: int
    kid: bytes
    nonces: bytes | None = None  # nonce_i || nonce_r on the initiator's first STREAM message
    raw: bytes = b""


def encode(
    key: identity.NodeKey, message: Message, seq: int, *, nonces: bytes | None = None, aad: bytes = b""
) -> bytes:
    """Sign and serialize one message. ``aad`` is the encounter binding (see the module doc)."""
    payload: dict[str, Any] = {"t": int(message.type), "s": seq, "b": message.body()}
    if nonces is not None:
        if len(nonces) != 2 * NONCE_LEN:
            raise MessageError("nonces must be nonce_i || nonce_r, 32 bytes")
        payload["n"] = nonces
    return cose.sign(key, cbor2.dumps(payload, canonical=True), external_aad=aad)


def _decode_payload(payload: bytes, kid: bytes, raw: bytes) -> Envelope:
    try:
        d = cbor2.loads(payload)
    except Exception as exc:  # cbor2 raises several decoder error types
        raise MessageError(f"bad message payload: {exc}") from exc
    if not isinstance(d, Mapping):
        raise MessageError("message payload must be a map")
    mt = _int(d, "t", 0, 255)
    cls = _BY_TYPE.get(mt)
    if cls is None:
        raise MessageError(f"unknown message type {mt}")
    body = d.get("b", {})
    if not isinstance(body, Mapping):
        raise MessageError("message body must be a map")
    msg = cls.from_body(body)
    seq = _int(d, "s", 0, 2**32 - 1)
    nonces = d.get("n")
    if nonces is not None and (not isinstance(nonces, bytes) or len(nonces) != 2 * NONCE_LEN):
        raise MessageError("bad nonces field")
    return Envelope(message=msg, seq=seq, kid=kid, nonces=nonces, raw=raw)


def peek(data: bytes) -> Envelope:
    """Parse WITHOUT verifying the signature. Needed for HAIL, which arrives before the
    responder holds the initiator's card. Never act on a peeked message beyond fetching
    the card that will let it be verified, or backing off from a ``busy`` decline."""
    try:
        s = cose.parse(data)
    except cose.CoseError as exc:
        raise MessageError(str(exc)) from exc
    return _decode_payload(s.payload, s.kid, data)


def decode(data: bytes, public_key: bytes, *, aad: bytes = b"") -> Envelope:
    """Verify under ``public_key`` with the encounter binding ``aad`` and parse."""
    try:
        payload = cose.verify(data, public_key, external_aad=aad)
    except cose.CoseError as exc:
        raise MessageError(f"message signature: {exc}") from exc
    return _decode_payload(payload, identity.kid(public_key), data)


# ---- A2A view ----------------------------------------------------------------------------

A2A_STATE = {
    "proposed": "submitted",
    "accepted": "working",
    "declined": "rejected",
    "countered": "canceled",
    "aborted": "canceled",
    "done": "completed",
    "failed": "failed",
}


def to_a2a_task(propose: Propose, state: str, *, context_id: str | None = None) -> dict[str, Any]:
    """The A2A v1.0 Task object a PROPOSE creates, for logs, bridges and anyone mapping an
    encounter onto an A2A client. ``state`` is one of the keys of ``A2A_STATE``."""
    return {
        "id": propose.task_id.hex(),
        "contextId": context_id or propose.task_id.hex(),
        "status": {"state": A2A_STATE[state]},
        "metadata": {
            "skill": propose.skill_id,
            "profile": propose.profile,
            "action": propose.action,
            "params": dict(propose.params),
        },
    }
