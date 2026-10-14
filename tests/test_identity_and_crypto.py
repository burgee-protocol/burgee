import cbor2
import pytest

from burgee import cose, identity, jws
from burgee.identity import NodeKey


def test_keys_stable_id_and_kid():
    k = NodeKey.generate()
    assert len(k.public_key) == 32
    assert k.stable_id == identity.stable_id(k.public_key)
    assert k.kid == k.stable_id[:8]
    k2 = NodeKey.from_seed(k.seed())
    assert k2.public_key == k.public_key
    sig = k.sign(b"x")
    assert identity.verify(k.public_key, sig, b"x")
    assert not identity.verify(k.public_key, sig, b"y")
    assert not identity.verify(NodeKey.generate().public_key, sig, b"x")
    with pytest.raises(ValueError):
        NodeKey.from_seed(b"short")


def test_ephemeral_id_rotates_on_schedule():
    t = [1000.0]
    k = NodeKey.generate()
    src = identity.EphemeralIdSource(k.public_key, rotation_s=600, clock=lambda: t[0])
    e1 = src.ephemeral_id
    assert len(e1) == 8
    t[0] += 599
    assert src.ephemeral_id == e1
    t[0] += 2
    e2 = src.ephemeral_id
    assert e2 != e1
    src.rotate_now()
    assert src.ephemeral_id != e2


def test_ephemeral_id_does_not_reveal_the_key():
    k = NodeKey.generate()
    a = identity.EphemeralIdSource(k.public_key)
    b = identity.EphemeralIdSource(k.public_key)
    assert a.ephemeral_id != b.ephemeral_id  # different session keys, same node


def test_lower_ephemeral_id_initiates():
    assert identity.should_initiate(b"\x00" * 8, b"\x01" * 8)
    assert not identity.should_initiate(b"\x01" * 8, b"\x00" * 8)


def test_cose_sign1_round_trip_and_tamper():
    k = NodeKey.generate()
    data = cose.sign(k, b"payload")
    assert cose.verify(data, k.public_key) == b"payload"
    parsed = cose.parse(data)
    assert parsed.kid == k.kid
    # tamper with the payload
    obj = cbor2.loads(data)
    protected, _, payload, sig = obj.value
    bad = cbor2.dumps(cbor2.CBORTag(18, [protected, {}, b"payloaX", sig]))
    with pytest.raises(cose.CoseError):
        cose.verify(bad, k.public_key)
    # wrong key
    with pytest.raises(cose.CoseError):
        cose.verify(data, NodeKey.generate().public_key)
    # external AAD must match
    aad = cose.sign(k, b"p", external_aad=b"ctx")
    with pytest.raises(cose.CoseError):
        cose.verify(aad, k.public_key)
    assert cose.verify(aad, k.public_key, external_aad=b"ctx") == b"p"


def test_cose_rejects_garbage():
    with pytest.raises(cose.CoseError):
        cose.parse(b"\x00\x01")
    with pytest.raises(cose.CoseError):
        cose.parse(cbor2.dumps([1, 2, 3]))
    with pytest.raises(cose.CoseError):
        cose.parse(cbor2.dumps(cbor2.CBORTag(18, [cbor2.dumps({1: -7}), {}, b"", b""])))


def test_jws_sign_verify_and_canonical():
    k = NodeKey.generate()
    payload = {"b": 1, "a": [1, 2.5, "x"], "nested": {"z": True, "y": None}}
    sig = jws.sign(k, payload)
    assert jws.verify(sig, payload, k.public_key)
    assert jws.verify(
        sig, {"nested": {"y": None, "z": True}, "a": [1, 2.5, "x"], "b": 1}, k.public_key
    )  # key order irrelevant
    assert not jws.verify(sig, {**payload, "b": 2}, k.public_key)
    assert not jws.verify(sig, payload, NodeKey.generate().public_key)
    hdr = jws.header(sig)
    assert hdr["alg"] == "EdDSA" and jws.b64url_decode(hdr["kid"]) == k.kid
    assert not jws.verify({"protected": "!!", "signature": "x"}, payload, k.public_key)
