"""Layer 1: the beacon.

Every beacon is a 24-byte payload carried in a legacy BLE 4.x advertisement
(31 bytes: 7 of framing, 24 of burgee). Spec section 4 is the source for every
offset here; the arithmetic for each type is checked in the tests.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from datetime import UTC, datetime

from . import identity
from .registries import (
    BeaconType,
    NodeClass,
    NodeState,
    PriorityClass,
    SafetyCommand,
)

PROTOCOL_VERSION = 1
PAYLOAD_LEN = 24
ADV_LEN = 31
COMPANY_ID_TEST = 0xFFFF  # Bluetooth SIG value reserved for testing; production uses the Steward's ID
TOKEN_HINT_LEN = 9
TAG_COVERED = 20  # bytes 0..19 are under the tag

HEADING_UNKNOWN = 255
HEADING_STEP_DEG = 2.0
HEADING_MAX_CODE = 179
SPEED_UNKNOWN = 255
SPEED_MAX_CMPS = 254
FOOTPRINT_STEP_M = 0.2
FOOTPRINT_MAX_CODE = 15
TENTHS_PER_HOUR = 36000
REPLAY_WINDOW_TENTHS = 20  # 2 s


class BeaconError(ValueError):
    """Raised for a malformed beacon or advertisement."""


def tenths_in_hour(now: float) -> int:
    """Tenths of a second since the top of the current UTC hour (the Remote ID convention)."""
    t = datetime.fromtimestamp(now, tz=UTC)
    return (t.minute * 60 + t.second) * 10 + t.microsecond // 100_000


def timestamp_is_fresh(sent_tenths: int, now_tenths: int, window: int = REPLAY_WINDOW_TENTHS) -> bool:
    """True when ``sent_tenths`` is within ``window`` tenths of ``now_tenths``, modulo the hour."""
    diff = (now_tenths - sent_tenths) % TENTHS_PER_HOUR
    return diff <= window or diff >= TENTHS_PER_HOUR - window


def _enum_or(enum, value, default):
    """A registry value this build does not know yet (added by a later BEP) decodes to a safe
    default instead of failing: an unknown class is ``other``, an unknown state is assumed to be
    moving, an unknown priority is standard. Forward compatibility without over-trust."""
    try:
        return enum(value)
    except ValueError:
        return default


def _header(kind: BeaconType) -> int:
    return (PROTOCOL_VERSION << 4) | int(kind)


def _check_eid(eid: bytes) -> None:
    if len(eid) != identity.EPHEMERAL_ID_LEN:
        raise BeaconError("ephemeral ID must be 8 bytes")


def _finish(body20: bytes, session_key: bytes) -> bytes:
    if len(body20) != TAG_COVERED:
        raise BeaconError(f"beacon body must be {TAG_COVERED} bytes before the tag")
    return body20 + identity.beacon_tag(session_key, body20)


def _split(payload: bytes, kind: BeaconType) -> tuple[bytes, bytes]:
    if len(payload) != PAYLOAD_LEN:
        raise BeaconError(f"beacon payload must be {PAYLOAD_LEN} bytes")
    version, mtype = payload[0] >> 4, payload[0] & 0x0F
    if version != PROTOCOL_VERSION:
        raise BeaconError(f"unsupported protocol version {version}")
    if mtype != int(kind):
        raise BeaconError(f"expected beacon type {kind.name}, got {mtype}")
    return payload[:TAG_COVERED], payload[TAG_COVERED:]


def encode_heading(deg: float | None) -> int:
    if deg is None:
        return HEADING_UNKNOWN
    code = round((deg % 360.0) / HEADING_STEP_DEG)
    return 0 if code > HEADING_MAX_CODE else code


def decode_heading(code: int) -> float | None:
    if code == HEADING_UNKNOWN or code > HEADING_MAX_CODE:
        return None
    return code * HEADING_STEP_DEG


def encode_speed(mps: float | None) -> int:
    if mps is None:
        return SPEED_UNKNOWN
    return max(0, min(SPEED_MAX_CMPS, round(mps * 100)))


def decode_speed(code: int) -> float | None:
    return None if code == SPEED_UNKNOWN else code / 100.0


def encode_footprint(width_m: float, length_m: float) -> int:
    """Width and length in 0.2 m steps, rounded UP: a node never understates its size."""
    w = max(0, min(FOOTPRINT_MAX_CODE, math.ceil(width_m / FOOTPRINT_STEP_M - 1e-9)))
    ln = max(0, min(FOOTPRINT_MAX_CODE, math.ceil(length_m / FOOTPRINT_STEP_M - 1e-9)))
    return (w << 4) | ln


def decode_footprint(code: int) -> tuple[float, float]:
    return (round((code >> 4) * FOOTPRINT_STEP_M, 1), round((code & 0x0F) * FOOTPRINT_STEP_M, 1))


@dataclass
class IdentityBeacon:
    """Message type 0. Who the node is and what it can do."""

    node_class: NodeClass
    ephemeral_id: bytes
    capabilities: int
    state: NodeState
    priority_class: PriorityClass
    profiles: int
    timestamp_tenths: int
    heading_deg: float | None = None
    speed_mps: float | None = None
    footprint_w_m: float = 0.0
    footprint_l_m: float = 0.0
    tag: bytes = field(default=b"", repr=False)

    kind = BeaconType.IDENTITY

    def encode(self, session_key: bytes) -> bytes:
        _check_eid(self.ephemeral_id)
        body = struct.pack(
            ">BB8sHBBBBHBB",
            _header(self.kind),
            int(self.node_class),
            self.ephemeral_id,
            self.capabilities & 0xFFFF,
            int(self.state),
            encode_heading(self.heading_deg),
            encode_speed(self.speed_mps),
            encode_footprint(self.footprint_w_m, self.footprint_l_m),
            self.timestamp_tenths % TENTHS_PER_HOUR,
            int(self.priority_class),
            self.profiles & 0xFF,
        )
        return _finish(body, session_key)

    @classmethod
    def decode(cls, payload: bytes) -> IdentityBeacon:
        body, tag = _split(payload, cls.kind)
        (_, ncls, eid, caps, state, heading, speed, fp, ts, prio, profiles) = struct.unpack(">BB8sHBBBBHBB", body)
        w, ln = decode_footprint(fp)
        return cls(
            node_class=_enum_or(NodeClass, ncls, NodeClass.other),
            ephemeral_id=eid,
            capabilities=caps,
            state=_enum_or(NodeState, state, NodeState.transiting),
            priority_class=_enum_or(PriorityClass, prio, PriorityClass.standard),
            profiles=profiles,
            timestamp_tenths=ts,
            heading_deg=decode_heading(heading),
            speed_mps=decode_speed(speed),
            footprint_w_m=w,
            footprint_l_m=ln,
            tag=tag,
        )


@dataclass
class LocationBeacon:
    """Message type 1. WGS84 or local-frame position. Optional."""

    ephemeral_id: bytes
    latitude: float
    longitude: float
    altitude_m: int = 0
    frame: int = 0  # 0 WGS84, 1 local map
    accuracy_class: int = 0  # 0 unknown, then finer classes per the registry process
    tag: bytes = field(default=b"", repr=False)

    kind = BeaconType.LOCATION

    def encode(self, session_key: bytes) -> bytes:
        _check_eid(self.ephemeral_id)
        body = struct.pack(
            ">B8siihB",
            _header(self.kind),
            self.ephemeral_id,
            round(self.latitude * 1e7),
            round(self.longitude * 1e7),
            int(self.altitude_m),
            ((self.frame & 0x0F) << 4) | (self.accuracy_class & 0x0F),
        )
        return _finish(body, session_key)

    @classmethod
    def decode(cls, payload: bytes) -> LocationBeacon:
        body, tag = _split(payload, cls.kind)
        _, eid, lat, lon, alt, fa = struct.unpack(">B8siihB", body)
        return cls(
            ephemeral_id=eid,
            latitude=lat / 1e7,
            longitude=lon / 1e7,
            altitude_m=alt,
            frame=fa >> 4,
            accuracy_class=fa & 0x0F,
            tag=tag,
        )


@dataclass
class SafetyBeacon:
    """Message type 2. Sent only by marks or authority nodes."""

    ephemeral_id: bytes
    command: SafetyCommand
    zone: int
    token_hint: bytes
    tag: bytes = field(default=b"", repr=False)

    kind = BeaconType.SAFETY

    def encode(self, session_key: bytes) -> bytes:
        _check_eid(self.ephemeral_id)
        if len(self.token_hint) != TOKEN_HINT_LEN:
            raise BeaconError(f"token hint must be {TOKEN_HINT_LEN} bytes")
        body = struct.pack(
            ">B8sBB9s",
            _header(self.kind),
            self.ephemeral_id,
            int(self.command),
            self.zone & 0xFF,
            self.token_hint,
        )
        return _finish(body, session_key)

    @classmethod
    def decode(cls, payload: bytes) -> SafetyBeacon:
        body, tag = _split(payload, cls.kind)
        _, eid, cmd, zone, hint = struct.unpack(">B8sBB9s", body)
        try:
            command = SafetyCommand(cmd)
        except ValueError as exc:
            raise BeaconError(f"unknown SAFETY command {cmd}") from exc
        return cls(ephemeral_id=eid, command=command, zone=zone, token_hint=hint, tag=tag)


@dataclass
class IntentBeacon:
    """Message type 3. Reserved for v0.2; v0.1 nodes ignore it on receipt."""

    ephemeral_id: bytes
    waypoints: list[tuple[float, float]]  # three (dx, dy) in m, relative to the node
    eta_s: int
    speed_mps: float | None = None
    side: int = 0  # 0 none, 1 keeping left, 2 keeping right
    tag: bytes = field(default=b"", repr=False)

    kind = BeaconType.INTENT
    WAYPOINT_STEP_M = 0.5

    def encode(self, session_key: bytes) -> bytes:
        _check_eid(self.ephemeral_id)
        if len(self.waypoints) != 3:
            raise BeaconError("INTENT carries exactly three waypoints")
        wp = []
        for dx, dy in self.waypoints:
            wp.append(max(-128, min(127, round(dx / self.WAYPOINT_STEP_M))))
            wp.append(max(-128, min(127, round(dy / self.WAYPOINT_STEP_M))))
        body = struct.pack(
            ">B8s6bBBBH",
            _header(self.kind),
            self.ephemeral_id,
            *wp,
            max(0, min(255, int(self.eta_s))),
            encode_speed(self.speed_mps),
            self.side & 0xFF,
            0,
        )
        return _finish(body, session_key)

    @classmethod
    def decode(cls, payload: bytes) -> IntentBeacon:
        body, tag = _split(payload, cls.kind)
        fields = struct.unpack(">B8s6bBBBH", body)
        eid = fields[1]
        raw = fields[2:8]
        wps = [(raw[i] * cls.WAYPOINT_STEP_M, raw[i + 1] * cls.WAYPOINT_STEP_M) for i in (0, 2, 4)]
        return cls(
            ephemeral_id=eid,
            waypoints=wps,
            eta_s=fields[8],
            speed_mps=decode_speed(fields[9]),
            side=fields[10],
            tag=tag,
        )


Beacon = IdentityBeacon | LocationBeacon | SafetyBeacon | IntentBeacon

_DECODERS = {
    BeaconType.IDENTITY: IdentityBeacon.decode,
    BeaconType.LOCATION: LocationBeacon.decode,
    BeaconType.SAFETY: SafetyBeacon.decode,
    BeaconType.INTENT: IntentBeacon.decode,
}


def beacon_type(payload: bytes) -> BeaconType:
    if not payload:
        raise BeaconError("empty payload")
    try:
        return BeaconType(payload[0] & 0x0F)
    except ValueError as exc:
        raise BeaconError(f"unknown beacon type {payload[0] & 0x0F}") from exc


def decode(payload: bytes) -> Beacon:
    """Decode any 24-byte beacon payload by its type nibble."""
    return _DECODERS[beacon_type(payload)](payload)


def verify_tag(payload: bytes, session_key: bytes) -> bool:
    """True when the tag matches under ``session_key``. Only the sender, or a peer it has
    revealed the key to inside an authenticated encounter, can check this."""
    if len(payload) != PAYLOAD_LEN:
        return False
    return identity.beacon_tag(session_key, payload[:TAG_COVERED]) == payload[TAG_COVERED:]


def frame_advertisement(payload: bytes, company_id: int = COMPANY_ID_TEST) -> bytes:
    """Wrap a 24-byte payload in the 31-byte legacy advertisement: Flags AD + Manufacturer
    Specific Data AD. The company ID is little-endian, as the Bluetooth core spec requires."""
    if len(payload) != PAYLOAD_LEN:
        raise BeaconError(f"beacon payload must be {PAYLOAD_LEN} bytes")
    flags = bytes([0x02, 0x01, 0x06])  # LE General Discoverable, BR/EDR not supported
    msd_value = struct.pack("<H", company_id) + payload
    msd = bytes([1 + len(msd_value), 0xFF]) + msd_value
    adv = flags + msd
    assert len(adv) == ADV_LEN
    return adv


def parse_advertisement(adv: bytes, company_id: int = COMPANY_ID_TEST) -> bytes:
    """Find the Burgee Manufacturer Specific Data block in an advertisement and return its
    24-byte payload. Tolerates other AD structures before or after it."""
    i = 0
    while i < len(adv):
        length = adv[i]
        if length == 0:
            break
        if i + 1 + length > len(adv):
            raise BeaconError("truncated AD structure")
        ad_type = adv[i + 1]
        value = adv[i + 2 : i + 1 + length]
        if ad_type == 0xFF and len(value) == 2 + PAYLOAD_LEN:
            cid = struct.unpack("<H", value[:2])[0]
            if cid == company_id:
                return value[2:]
        i += 1 + length
    raise BeaconError("no Burgee manufacturer data in advertisement")


def manufacturer_data(payload: bytes) -> bytes:
    """The value of the Manufacturer Specific Data field without the company ID, which is
    what BlueZ and bleak hand to applications keyed by company ID."""
    if len(payload) != PAYLOAD_LEN:
        raise BeaconError(f"beacon payload must be {PAYLOAD_LEN} bytes")
    return payload
