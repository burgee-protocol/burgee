import pytest
from conftest import OPERATOR, make_card

from burgee.card import Operator
from burgee.identity import NodeKey
from burgee.profiles import access
from burgee.profiles import rightofway as row
from burgee.registries import NodeState, PriorityClass, ReasonCode


def party(
    eid=b"\x05" * 8, prio=PriorityClass.standard, verified=False, state=NodeState.transiting, w=0.5, ln=0.5, human=False
):
    return row.Party(eid, prio, verified, state, w, ln, human)


def test_rule1_verified_priority_wins():
    a = party(prio=PriorityClass.authority, verified=True)
    b = party(eid=b"\x09" * 8, w=3, ln=3)
    assert row.precedence(a, b) == row.Precedence("a", 1)
    e = party(prio=PriorityClass.emergency, verified=True)
    s = party(eid=b"\x09" * 8, prio=PriorityClass.service)
    assert row.precedence(s, e) == row.Precedence("b", 1)


def test_rule1_unverified_priority_is_ignored():
    a = party(prio=PriorityClass.authority, verified=False)
    b = party(eid=b"\x09" * 8)
    p = row.precedence(a, b)
    assert p.rule != 1
    assert a.effective_priority == 0


def test_rule2_stationary_stays():
    moving = party(state=NodeState.transiting, w=3, ln=3)
    parked = party(eid=b"\x09" * 8, state=NodeState.waiting)
    assert row.precedence(moving, parked) == row.Precedence("b", 2)
    assert row.precedence(parked, moving) == row.Precedence("a", 2)


def test_rule3_larger_footprint_between_moving_nodes():
    big = party(w=1.0, ln=1.2)
    small = party(eid=b"\x09" * 8, w=0.4, ln=0.4)
    assert row.precedence(big, small) == row.Precedence("a", 3)
    assert row.precedence(small, big).yields() == "a"


def test_rule4_human_escort():
    a = party(human=True)
    b = party(eid=b"\x09" * 8)
    assert row.precedence(a, b) == row.Precedence("a", 4)


def test_rule5_lower_ephemeral_id_yields():
    a = party(eid=b"\x01" * 8)
    b = party(eid=b"\x02" * 8)
    p = row.precedence(a, b)
    assert p == row.Precedence("b", 5) and p.yields() == "a"
    assert row.default_action(a, b) == "yield" and row.default_action(b, a) == "proceed"


def test_rightofway_params_and_may_propose():
    assert row.validate_params("wait_at", {"hold_s": 10}) == {"hold_s": 10.0}
    assert row.validate_params("pass_left", {}) == {"side": "left"}
    out = row.validate_params("yield", {"conflict_point": [1, 2], "eta_s": 3})
    assert out == {"conflict_point": [1.0, 2.0], "eta_s": 3.0}
    with pytest.raises(row.RightOfWayError):
        row.validate_params("wait_at", {"hold_s": 31})
    with pytest.raises(row.RightOfWayError):
        row.validate_params("fly", {})
    with pytest.raises(row.RightOfWayError):
        row.validate_params("yield", {"side": "up"})
    a, b = party(eid=b"\x01" * 8), party(eid=b"\x02" * 8)
    assert row.may_propose("yield", a, b, False)
    assert not row.may_propose("proceed", a, b, False)
    assert row.may_propose("proceed", a, b, True)
    assert row.may_propose("proceed", b, a, False)


def test_access_decision_order_and_grant():
    key = NodeKey.generate()
    card = make_card(key, "rover", operator=Operator("Acme Robotics", "mailto:x@y", "acme"))
    now = 1_700_000_000.0  # 22:13 UTC
    pol = access.MarkPolicy(require_countersignature=True, allowed_operators={"acme"}, max_concurrent=1)
    r = access.decide(pol, card, certified=False, now=now, active=0, action="request_passage", params={})
    assert isinstance(r, access.Refused) and r.reason is ReasonCode.policy and "countersignature" in r.note
    r = access.decide(
        pol, card, certified=True, now=now, active=0, action="request_passage", params={"duration_s": 500}
    )
    assert isinstance(r, access.Refused) and r.reason is ReasonCode.no_profile  # bad params first
    g = access.decide(pol, card, certified=True, now=now, active=0, action="request_passage", params={"duration_s": 20})
    assert isinstance(g, access.Granted) and g.granted_s == 20 and g.service == "passage"
    assert g.params() == {"granted_s": 20, "service": "passage"}
    pol2 = access.MarkPolicy(require_countersignature=False, allowed_operators={"someone-else"})
    assert (
        access.decide(pol2, card, certified=False, now=now, active=0, action="request_hold", params={}).note
        == "operator not allowed"
    )
    pol3 = access.MarkPolicy(require_countersignature=False, min_priority=PriorityClass.emergency)
    assert (
        access.decide(pol3, card, certified=False, now=now, active=0, action="request_hold", params={}).reason
        is ReasonCode.priority_lower
    )
    # a self-declared emergency class counts only when the card is certified
    ambulance = make_card(NodeKey.generate(), "amb", priority=PriorityClass.emergency)
    assert (
        access.decide(pol3, ambulance, certified=False, now=now, active=0, action="request_hold", params={}).reason
        is ReasonCode.priority_lower
    )
    assert isinstance(
        access.decide(pol3, ambulance, certified=True, now=now, active=0, action="request_hold", params={}),
        access.Granted,
    )
    assert access.effective_priority(ambulance, False) == 0 and access.effective_priority(ambulance, True) == 2
    pol4 = access.MarkPolicy(require_countersignature=False, window_utc=(8, 18))
    assert (
        access.decide(pol4, card, certified=False, now=now, active=0, action="request_hold", params={}).note
        == "outside service window"
    )
    pol5 = access.MarkPolicy(require_countersignature=False, window_utc=(20, 6))
    assert isinstance(
        access.decide(pol5, card, certified=False, now=now, active=0, action="request_hold", params={}), access.Granted
    )
    assert (
        access.decide(pol5, card, certified=False, now=now, active=1, action="request_hold", params={}).reason
        is ReasonCode.busy
    )
    pol6 = access.MarkPolicy(require_countersignature=False, services={"passage"})
    assert (
        access.decide(
            pol6, card, certified=False, now=now, active=0, action="request_service", params={"service": "charge"}
        ).reason
        is ReasonCode.no_profile
    )
    with pytest.raises(access.AccessError):
        access.validate_params("request_service", {"service": "lift"})  # lift needs a floor
    assert access.validate_params("request_service", {"service": "lift", "floor": 4, "duration_s": 60})["floor"] == 4
    assert OPERATOR.registry_id == "acme"
