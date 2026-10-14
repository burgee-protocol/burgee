import pytest

from burgee import messages as m
from burgee.identity import NodeKey
from burgee.registries import MessageType, ReasonCode, SafetyCommand, StatusValue


def all_messages():
    tid = m.new_task_id()
    return [
        m.Hail(b"\x01" * 8, b"\x02" * 32, "rightofway/1", m.new_nonce(), 2),
        m.HailAck(b"\x03" * 32, m.new_nonce(), m.new_nonce(), 3),
        m.CardRequest(b"\x04" * 32),
        m.Card(b"\x05" * 900),
        m.Propose(tid, "rightofway/1", "yield", {"hold_s": 10, "conflict_point": [1.5, -0.5]}),
        m.Accept(tid, {"granted_s": 30}),
        m.Counter(m.new_task_id(), tid, "rightofway/1", "wait_at", {"hold_s": 5}),
        m.Decline(tid, ReasonCode.policy, "no"),
        m.Status(tid, StatusValue.waiting),
        m.Status(tid, StatusValue.failed, ReasonCode.unsafe),
        m.Abort(tid, ReasonCode.timeout),
        m.SafetyStop(SafetyCommand.stop, 2, b"\x06" * 120),
        m.Bye(),
    ]


def test_every_message_round_trips():
    k = NodeKey.generate()
    for seq, msg in enumerate(all_messages()):
        data = m.encode(k, msg, seq)
        env = m.decode(data, k.public_key)
        assert env.seq == seq and env.kid == k.kid and env.nonces is None
        assert env.message == msg
        assert type(env.message) is type(msg)
        peeked = m.peek(data)
        assert peeked.message == msg


def test_message_numbers_match_registry():
    expected = {
        m.Hail: 1,
        m.HailAck: 2,
        m.CardRequest: 3,
        m.Card: 4,
        m.Propose: 5,
        m.Accept: 6,
        m.Counter: 7,
        m.Decline: 8,
        m.Status: 9,
        m.Abort: 10,
        m.SafetyStop: 11,
        m.Bye: 12,
    }
    for cls, n in expected.items():
        assert int(cls.type) == n
        assert MessageType(n).name == cls.type.name


def test_propose_fits_one_mtu():
    k = NodeKey.generate()
    p = m.Propose(
        m.new_task_id(), "rightofway/1", "wait_at", {"hold_s": 12, "conflict_point": [3.25, -1.5], "eta_s": 4}
    )
    data = m.encode(k, p, 7, nonces=m.new_nonce() + m.new_nonce())
    assert len(data) < 247


def test_tamper_and_wrong_key_rejected():
    k, other = NodeKey.generate(), NodeKey.generate()
    data = m.encode(k, m.Bye(), 1)
    with pytest.raises(m.MessageError):
        m.decode(data, other.public_key)
    bad = bytearray(data)
    bad[-1] ^= 0xFF
    with pytest.raises(m.MessageError):
        m.decode(bytes(bad), k.public_key)


def test_nonces_field_validated():
    k = NodeKey.generate()
    with pytest.raises(m.MessageError):
        m.encode(k, m.Bye(), 1, nonces=b"short")
    n = m.new_nonce() + m.new_nonce()
    assert m.decode(m.encode(k, m.Bye(), 1, nonces=n), k.public_key).nonces == n


def test_a2a_task_view():
    p = m.Propose(bytes(8), "access/1", "request_passage", {"service": "passage"})
    t = m.to_a2a_task(p, "accepted")
    assert t["status"]["state"] == "working" and t["metadata"]["skill"] == "access/1:request_passage"
