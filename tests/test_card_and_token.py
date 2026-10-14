import os
import time

import pytest
from conftest import OPERATOR, make_card

from burgee import card as cardmod
from burgee import token
from burgee.card import AgentCard, RegistryKey
from burgee.identity import NodeKey
from burgee.registries import NodeClass, PriorityClass, SafetyCommand


def test_build_sign_verify_and_wire_round_trip(key_a):
    c = make_card(key_a, "rover-a")
    assert c.verify()
    wire = c.to_wire()
    assert len(wire) <= cardmod.MAX_WIRE_BYTES
    back = AgentCard.from_wire(wire)
    assert back.verify()
    assert back.digest() == c.digest()
    assert back.burgee.public_key == key_a.public_key
    d = back.to_dict()
    assert d["protocolVersion"] == "1.0"
    assert d["supportedInterfaces"][0]["protocolBinding"] == "burgee-ble"
    assert d["capabilities"]["extensions"][0]["uri"] == cardmod.EXTENSION_URI
    assert d["capabilities"]["extensions"][0]["params"]["certified"] is False
    assert {s["id"] for s in d["skills"]} >= {"rightofway/1:yield", "access/1:request_passage"}


def test_tampered_card_fails_verification(key_a):
    c = make_card(key_a, "rover-a")
    c.burgee.max_speed_mps = 9.0
    assert not c.verify()
    c.sign(key_a)
    assert c.verify()


def test_card_must_be_signed_by_named_key(key_a, key_b):
    c = make_card(key_a, "rover-a")
    with pytest.raises(cardmod.CardError):
        c.sign(key_b)


def test_card_rejects_unknown_profile_and_bad_region(key_a):
    with pytest.raises(cardmod.CardError):
        make_card(key_a, profiles=["teleport/9"])
    with pytest.raises(cardmod.CardError):
        cardmod.build_card(
            key=key_a,
            name="x",
            description="",
            version="1",
            node_class=NodeClass.ground_robot,
            operator=OPERATOR,
            footprint_m=(1, 1, 1),
            max_speed_mps=1,
            capabilities=0,
            profiles=["rightofway/1"],
            conformance_level=2,
            region="",
        )


def test_from_dict_requires_burgee_interface(key_a):
    d = make_card(key_a).to_dict()
    d["supportedInterfaces"] = [{"url": "https://x", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}]
    with pytest.raises(cardmod.CardError):
        AgentCard.from_dict(d)


def test_countersignature_makes_card_certified_only_for_trusted_registry(key_a):
    c = make_card(key_a, "rover-a", level=2)
    reg = RegistryKey(NodeKey.generate())
    other = RegistryKey(NodeKey.generate())
    now = time.time()
    digest_before = c.digest()
    c.burgee.countersignatures.append(reg.countersign(c, 2, expires_at=now + 3600))
    c.sign(key_a)  # the node re-signs after a countersignature is added
    assert c.digest() == digest_before  # digest excludes countersignatures
    assert c.verify()
    assert c.is_certified({reg.kid: reg.public_key}, now=now)
    assert not c.is_certified({other.kid: other.public_key}, now=now)
    assert not c.is_certified({}, now=now)
    assert not c.is_certified({reg.kid: reg.public_key}, now=now + 7200)  # expired
    # a countersignature below the declared level does not certify
    c2 = make_card(key_a, "rover-a", level=3)
    c2.burgee.countersignatures.append(reg.countersign(c2, 2, expires_at=now + 3600))
    assert not c2.is_certified({reg.kid: reg.public_key}, now=now)
    # certified is derived, so a stored value is ignored
    d = c.to_dict(trusted_registry_keys={reg.kid: reg.public_key}, now=now)
    assert d["capabilities"]["extensions"][0]["params"]["certified"] is True
    assert AgentCard.from_dict(d).verify()


def test_wire_size_limit(key_a):
    c = make_card(key_a, "rover-a")
    c.description = os.urandom(1500).hex()  # incompressible, 3,000 characters
    c.sign(key_a)
    with pytest.raises(cardmod.CardError):
        c.to_wire()
    assert len(c.to_wire(strict=False)) > cardmod.MAX_WIRE_BYTES


def test_priority_class_round_trips(key_a):
    c = make_card(key_a, priority=PriorityClass.emergency)
    assert AgentCard.from_wire(c.to_wire()).burgee.priority_class is PriorityClass.emergency


def test_authority_token_lifecycle():
    root = NodeKey.generate()
    now = 1_700_000_000
    tok = token.issue(root, zone=3, commands=[SafetyCommand.stop, SafetyCommand.hold], nbf=now, exp=now + 3600)
    assert len(token.hint(tok)) == 9
    t = token.verify(tok, {root.kid: root.public_key}, now=now + 10)
    assert t.zone == 3 and t.allows(SafetyCommand.stop) and t.allows(SafetyCommand.hold)
    assert not t.allows(SafetyCommand.evacuate_corridor)
    with pytest.raises(token.TokenError):
        token.verify(tok, {}, now=now + 10)  # unknown issuer
    with pytest.raises(token.TokenError):
        token.verify(tok, {root.kid: root.public_key}, now=now + 7200)  # expired
    with pytest.raises(token.TokenError):
        token.verify(tok, {root.kid: root.public_key}, now=now - 5)  # not yet valid
    with pytest.raises(token.TokenError):
        token.issue(root, zone=3, commands=[SafetyCommand.stop], nbf=now, exp=now + 25 * 3600)
    other = NodeKey.generate()
    with pytest.raises(token.TokenError):
        token.verify(tok, {root.kid: other.public_key}, now=now + 10)
