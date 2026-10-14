import os

import pytest

from burgee import beacon, identity
from burgee.registries import BeaconType, NodeClass, NodeState, PriorityClass, SafetyCommand

EID = bytes(range(8))
KEY = os.urandom(16)


def ident(**kw):
    base = dict(
        node_class=NodeClass.sidewalk_delivery,
        ephemeral_id=EID,
        capabilities=0b0000_1000_0000_0111,
        state=NodeState.transiting,
        priority_class=PriorityClass.standard,
        profiles=0b11,
        timestamp_tenths=12345,
        heading_deg=90.0,
        speed_mps=1.5,
        footprint_w_m=0.6,
        footprint_l_m=0.9,
    )
    base.update(kw)
    return beacon.IdentityBeacon(**base)


def test_identity_is_24_bytes_and_round_trips():
    b = ident()
    raw = b.encode(KEY)
    assert len(raw) == 24
    assert raw[0] == (1 << 4) | int(BeaconType.IDENTITY)
    d = beacon.IdentityBeacon.decode(raw)
    assert d.node_class is NodeClass.sidewalk_delivery
    assert d.ephemeral_id == EID
    assert d.capabilities == b.capabilities
    assert d.state is NodeState.transiting
    assert d.priority_class is PriorityClass.standard
    assert d.profiles == 0b11
    assert d.timestamp_tenths == 12345
    assert d.heading_deg == 90.0
    assert d.speed_mps == 1.5
    assert (d.footprint_w_m, d.footprint_l_m) == (0.6, 1.0)  # 0.9 rounds up to the next 0.2 m step
    assert beacon.verify_tag(raw, KEY)
    assert not beacon.verify_tag(raw, os.urandom(16))


def test_heading_and_speed_unknown_and_limits():
    d = beacon.IdentityBeacon.decode(ident(heading_deg=None, speed_mps=None).encode(KEY))
    assert d.heading_deg is None and d.speed_mps is None
    # 2-degree steps, 0..358; 359 wraps to 0 (code 180 > 179 is reserved).
    assert beacon.decode_heading(beacon.encode_heading(358.0)) == 358.0
    assert beacon.encode_heading(359.9) == 0
    assert beacon.encode_heading(361.0) == 0  # 361 mod 360 = 1 -> code 0 (rounds down)
    # speed caps at 2.54 m/s; 255 is reserved for unknown.
    assert beacon.encode_speed(9.0) == 254
    assert beacon.decode_speed(254) == 2.54
    assert beacon.decode_speed(255) is None


def test_footprint_steps():
    assert beacon.decode_footprint(beacon.encode_footprint(3.0, 0.2)) == (3.0, 0.2)
    assert beacon.decode_footprint(beacon.encode_footprint(0.41, 0.59)) == (0.6, 0.6)  # never understated
    assert beacon.encode_footprint(99.0, 99.0) == 0xFF
    assert beacon.decode_footprint(0xFF) == (3.0, 3.0)


def test_location_is_24_bytes_and_round_trips():
    b = beacon.LocationBeacon(EID, 41.7658, -72.6734, altitude_m=12, frame=0, accuracy_class=3)
    raw = b.encode(KEY)
    assert len(raw) == 24
    d = beacon.LocationBeacon.decode(raw)
    assert abs(d.latitude - 41.7658) < 1e-7 and abs(d.longitude + 72.6734) < 1e-7
    assert d.altitude_m == 12 and d.frame == 0 and d.accuracy_class == 3


def test_safety_is_24_bytes_and_round_trips():
    hint = os.urandom(9)
    raw = beacon.SafetyBeacon(EID, SafetyCommand.stop, 7, hint).encode(KEY)
    assert len(raw) == 24
    d = beacon.SafetyBeacon.decode(raw)
    assert d.command is SafetyCommand.stop and d.zone == 7 and d.token_hint == hint
    with pytest.raises(beacon.BeaconError):
        beacon.SafetyBeacon(EID, SafetyCommand.stop, 7, b"short").encode(KEY)


def test_intent_is_24_bytes_and_round_trips():
    b = beacon.IntentBeacon(EID, [(1.0, 0.5), (2.0, -1.0), (3.5, 0.0)], eta_s=12, speed_mps=1.2, side=2)
    raw = b.encode(KEY)
    assert len(raw) == 24
    d = beacon.IntentBeacon.decode(raw)
    assert d.waypoints == [(1.0, 0.5), (2.0, -1.0), (3.5, 0.0)]
    assert d.eta_s == 12 and d.speed_mps == 1.2 and d.side == 2


def test_decode_dispatches_on_type_nibble():
    for b in (
        ident(),
        beacon.LocationBeacon(EID, 1.0, 2.0),
        beacon.SafetyBeacon(EID, SafetyCommand.hold, 1, bytes(9)),
        beacon.IntentBeacon(EID, [(0, 0)] * 3, eta_s=1),
    ):
        raw = b.encode(KEY)
        assert type(beacon.decode(raw)) is type(b)


def test_wrong_version_and_wrong_type_rejected():
    raw = bytearray(ident().encode(KEY))
    raw[0] = (2 << 4) | 0
    with pytest.raises(beacon.BeaconError):
        beacon.IdentityBeacon.decode(bytes(raw))
    with pytest.raises(beacon.BeaconError):
        beacon.LocationBeacon.decode(ident().encode(KEY))
    with pytest.raises(beacon.BeaconError):
        beacon.decode(b"")


def test_advertisement_framing_is_31_bytes():
    payload = ident().encode(KEY)
    adv = beacon.frame_advertisement(payload)
    assert len(adv) == 31
    assert adv[:3] == bytes([0x02, 0x01, 0x06])
    assert adv[3] == 27 and adv[4] == 0xFF and adv[5:7] == b"\xff\xff"
    assert beacon.parse_advertisement(adv) == payload


def test_parse_advertisement_skips_other_structures():
    payload = ident().encode(KEY)
    adv = beacon.frame_advertisement(payload)
    name_ad = bytes([4, 0x09]) + b"abc"
    assert beacon.parse_advertisement(name_ad + adv) == payload
    with pytest.raises(beacon.BeaconError):
        beacon.parse_advertisement(name_ad)
    with pytest.raises(beacon.BeaconError):
        beacon.parse_advertisement(beacon.frame_advertisement(payload, company_id=0x1234))


def test_timestamp_freshness_wraps_the_hour():
    assert beacon.timestamp_is_fresh(100, 110)
    assert beacon.timestamp_is_fresh(100, 120)
    assert not beacon.timestamp_is_fresh(100, 121)
    assert beacon.timestamp_is_fresh(35995, 5)  # across the top of the hour
    assert 0 <= beacon.tenths_in_hour(1_700_000_000.0) < beacon.TENTHS_PER_HOUR


def test_tag_covers_first_twenty_bytes():
    raw = ident().encode(KEY)
    assert raw[20:] == identity.beacon_tag(KEY, raw[:20])


def test_unknown_registry_values_decode_to_safe_defaults():
    raw = bytearray(ident().encode(KEY))
    raw[1] = 200  # node class not in this build's registry
    raw[12] = 77  # state not in the registry
    raw[18] = 9  # priority class not in the registry
    d = beacon.IdentityBeacon.decode(bytes(raw))
    assert d.node_class is NodeClass.other
    assert d.state is NodeState.transiting
    assert d.priority_class is PriorityClass.standard
    bad_type = bytearray(ident().encode(KEY))
    bad_type[0] = (1 << 4) | 9
    with pytest.raises(beacon.BeaconError):
        beacon.decode(bytes(bad_type))
    bad_cmd = bytearray(beacon.SafetyBeacon(EID, SafetyCommand.stop, 1, bytes(9)).encode(KEY))
    bad_cmd[9] = 200
    with pytest.raises(beacon.BeaconError):
        beacon.decode(bytes(bad_cmd))
