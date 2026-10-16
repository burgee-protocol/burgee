import random

import pytest
from conftest import AcceptAll, Clock, handshake, make_card

from burgee import encounter as E
from burgee import messages, token
from burgee.beacon import IdentityBeacon
from burgee.encounter import Node, State
from burgee.identity import NodeKey
from burgee.messages import Counter, Decline
from burgee.registries import Capability, NodeClass, NodeState, PriorityClass, ReasonCode, SafetyCommand, StatusValue
from burgee.transport import LoopbackLink


def test_full_handshake_authenticates_both_sides(pair, clock):
    a, b, link, ha, hb = pair
    ea, eb = handshake(a, b, link, clock())
    assert ea.state is State.VERIFIED and eb.state is State.VERIFIED
    assert ea.peer.authenticated and eb.peer.authenticated
    assert ea.peer.card.name == "rover-b" and eb.peer.card.name == "rover-a"
    assert ea.peer.card_digest == b.card_digest and eb.peer.card_digest == a.card_digest
    # six frames: HAIL, HAIL_ACK, CARD_REQUEST x2, CARD x2
    assert link.delivered == 6
    kinds = [e.kind for e in eb.log]
    assert kinds.index("authenticated") < kinds.index("verified")


def test_propose_accept_and_bye(pair, clock):
    a, b, link, ha, hb = pair
    ea, eb = handshake(a, b, link, clock())
    t = ea.propose("yield", {"hold_s": 10}, now=clock())
    while link.pump(clock()):
        pass
    assert t.state == "accepted" and t.accept_params == {"ack": True}
    assert ea.state is State.AGREED and eb.state is State.AGREED
    assert len(ha.agreed) == 1 and len(hb.agreed) == 1
    ea.status(t.propose.task_id, StatusValue.done, now=clock())
    while link.pump(clock()):
        pass
    assert hb.statuses[-1].status is StatusValue.done
    ea.close(clock(), "done")
    link.pump(clock())
    assert eb.state is State.CLOSED and eb.close_reason == "peer said bye"
    assert ha.closed == ["done"] and hb.closed == ["peer said bye"]


def test_level1_node_declines_with_safe_behavior(clock, key_a, card_a, key_b):
    a = Node(key_a, card_a, handler=AcceptAll(), clock=clock)
    hb = AcceptAll()
    b = Node(
        key_b,
        make_card(key_b, "tag", level=1, caps=int(Capability.can_stop)),
        handler=hb,
        clock=clock,
        safe_behavior=StatusValue.continuing_slow,
    )
    link = LoopbackLink()
    ea, eb = handshake(a, b, link, clock())
    t = ea.propose("yield", now=clock())
    while link.pump(clock()):
        pass
    assert t.state == "declined" and t.reason is ReasonCode.no_profile
    assert ea.state is State.DECLINED
    assert a.handler.statuses[-1].status is StatusValue.continuing_slow
    assert hb.agreed == []  # a Level 1 node's handler is never asked


def test_counter_proposal_flow(clock, key_a, card_a, key_b, card_b):
    class CounterOnce:
        def __init__(self):
            self.countered = False
            self.agreed = []

        def on_propose(self, enc, p):
            if p.action == "proceed" and not self.countered:
                self.countered = True
                return Counter(messages.new_task_id(), p.task_id, p.profile, "wait_at", {"hold_s": 5})
            return messages.Accept(task_id=p.task_id)

        def on_agreed(self, enc, t):
            self.agreed.append(t)

        def on_declined(self, enc, t): ...
        def on_status(self, enc, s): ...
        def on_safety(self, enc, c, z, v): ...
        def on_closed(self, enc, r): ...

    ha, hb = AcceptAll(), CounterOnce()
    a = Node(key_a, card_a, handler=ha, clock=clock)
    b = Node(key_b, card_b, handler=hb, clock=clock)
    link = LoopbackLink()
    ea, eb = handshake(a, b, link, clock())
    t = ea.propose("proceed", now=clock())
    while link.pump(clock()):
        pass
    assert t.state == "countered"
    counters = [x for x in ea.tasks.values() if x.propose.action == "wait_at"]
    assert len(counters) == 1 and counters[0].state == "accepted"
    assert ea.state is State.AGREED and eb.state is State.AGREED
    assert hb.agreed and hb.agreed[0].propose.action == "wait_at"


def test_cached_card_skips_card_exchange(pair, clock):
    a, b, link, ha, hb = pair
    handshake(a, b, link, clock())
    assert len(a.card_cache) == 1 and len(b.card_cache) == 1
    link2 = LoopbackLink()
    ea, eb = handshake(a, b, link2, clock())
    # second meeting: HAIL and HAIL_ACK only; the initiator is verified at once, the responder
    # when the initiator's first STREAM message (its first PROPOSE) carries the nonces.
    assert link2.delivered == 2
    assert ea.state is State.VERIFIED and ea.peer.authenticated
    assert eb.state is State.HAILED and not eb.peer.authenticated
    ea.propose("yield", now=clock())
    while link2.pump(clock()):
        pass
    assert eb.state is State.AGREED and eb.peer.authenticated and link2.delivered == 4


def test_responder_drops_silent_initiator_after_verified_timeout(pair, clock):
    a, b, link, ha, hb = pair
    handshake(a, b, link, clock())
    link2 = LoopbackLink()
    ea, eb = handshake(a, b, link2, clock())
    clock.advance(E.TIMEOUT_VERIFIED_S + 0.1)
    eb.tick(clock())
    assert eb.state is State.CLOSED and eb.close_reason == "handshake timeout"


def test_cached_card_expires_after_24h(pair, clock):
    a, b, link, ha, hb = pair
    handshake(a, b, link, clock())
    clock.advance(E.CARD_CACHE_S + 1)
    assert a.card_cache.get(b.card_digest, clock()) is None


def test_initiator_first_stream_message_is_propose_when_card_cached(pair, clock):
    a, b, link, ha, hb = pair
    handshake(a, b, link, clock())
    link2 = LoopbackLink()
    ea = a.initiate(link2.a, b.ephemeral_id, now=clock())
    link2.a.bind(ea)
    eb = b.accept(link2.b, now=clock())
    link2.b.bind(eb)
    link2.pump(clock(), max_frames=2)  # HAIL and HAIL_ACK
    assert ea.state is State.VERIFIED and eb.state is State.HAILED
    t = ea.propose("yield", now=clock())
    while link2.pump(clock()):
        pass
    assert eb.peer.authenticated and t.state == "accepted"


def test_busy_limit_declines_fifth_encounter(clock, key_a, card_a):
    a = Node(key_a, card_a, handler=AcceptAll(), clock=clock, rng=random.Random(1))
    links = []
    for i in range(E.MAX_ENCOUNTERS_NODE):
        k = NodeKey.generate()
        n = Node(k, make_card(k, f"peer{i}"), handler=AcceptAll(), clock=clock)
        link = LoopbackLink()
        e_init = n.initiate(link.a, a.ephemeral_id, now=clock())
        link.a.bind(e_init)
        e_resp = a.accept(link.b, now=clock())
        link.b.bind(e_resp)
        while link.pump(clock()):
            pass
        assert e_resp.state is State.VERIFIED
        links.append(link)
    k = NodeKey.generate()
    n = Node(k, make_card(k, "fifth"), handler=AcceptAll(), clock=clock)
    link = LoopbackLink()
    e_init = n.initiate(link.a, a.ephemeral_id, now=clock())
    link.a.bind(e_init)
    e_resp = a.accept(link.b, now=clock())
    link.b.bind(e_resp)
    while link.pump(clock()):
        pass
    assert e_resp.state is State.CLOSED and e_resp.close_reason == "busy"
    decline = messages.peek(link.b.sent[0]).message
    assert isinstance(decline, Decline) and decline.reason is ReasonCode.busy
    assert 1.0 <= decline.retry_after_s <= 4.0
    assert e_init.state is State.CLOSED and e_init.close_reason == "busy"
    assert e_init.peer.retry_after_s == decline.retry_after_s
    assert link.delivered == 2  # HAIL and the busy DECLINE, nothing else


def test_cross_encounter_replay_is_rejected(pair, clock):
    """A frame recorded in one encounter does not verify in a later one with the same peer."""
    a, b, link, ha, hb = pair
    ea, eb = handshake(a, b, link, clock())
    ea.propose("yield", now=clock())
    recorded = link.a.sent[-1]
    while link.pump(clock()):
        pass
    ea.close(clock(), "done")
    link.pump(clock())
    link2 = LoopbackLink()
    ea2, eb2 = handshake(a, b, link2, clock())
    before = len(eb2.tasks)
    eb2.on_message(recorded, clock())
    assert len(eb2.tasks) == before
    assert any(e.kind == "drop" and "signature" in e.detail for e in eb2.log)


def test_quadrant_initiator_cached_responder_not(clock, key_a, card_a, key_b, card_b):
    """The initiator already holds the responder's card; the responder has never seen the
    initiator. The initiator's CARD is its first STREAM message and must authenticate it."""
    a = Node(key_a, card_a, handler=AcceptAll(), clock=clock)
    b = Node(key_b, card_b, handler=AcceptAll(), clock=clock)
    a.card_cache.put(card_b, clock())
    link = LoopbackLink()
    ea, eb = handshake(a, b, link, clock())
    assert ea.state is State.VERIFIED and eb.state is State.VERIFIED
    assert ea.peer.authenticated and eb.peer.authenticated
    assert link.delivered == 4  # HAIL, HAIL_ACK, CARD_REQUEST (from b), CARD (from a)
    t = ea.propose("yield", now=clock())
    while link.pump(clock()):
        pass
    assert t.state == "accepted"


def test_quadrant_responder_cached_initiator_not(clock, key_a, card_a, key_b, card_b):
    a = Node(key_a, card_a, handler=AcceptAll(), clock=clock)
    b = Node(key_b, card_b, handler=AcceptAll(), clock=clock)
    b.card_cache.put(card_a, clock())
    link = LoopbackLink()
    ea, eb = handshake(a, b, link, clock())
    assert ea.state is State.VERIFIED and eb.state is State.VERIFIED
    assert link.delivered == 4  # HAIL, HAIL_ACK, CARD_REQUEST (from a, with nonces), CARD (from b)


def test_malformed_frames_never_raise(pair, clock):
    import cbor2

    from burgee import cose

    a, b, link, ha, hb = pair
    ea, eb = handshake(a, b, link, clock())
    bad_bodies = [
        {"t": 1, "s": 9, "b": {"e": [1, 2], "d": b"x" * 32, "p": "rightofway/1", "n": b"n" * 16}},
        {"t": 2, "s": 9, "b": {"d": b"x" * 32, "n": 7, "pn": b""}},
        {"t": 4, "s": 9, "b": {"c": 12345}},
        {"t": 4, "s": 9, "b": {"c": b"\x00" * 2000}},
        {"t": 5, "s": 9, "b": {"t": [1], "p": "rightofway/1", "a": "yield"}},
        {"t": 9, "s": 9, "b": {"t": b"x" * 8, "v": 99}},
        {"t": 11, "s": 9, "b": {"c": 2, "z": 1, "k": b"not a token"}},
        {"t": 11, "s": 9, "b": {"c": 2, "z": 1, "k": 5}},
        {"t": 99, "s": 9, "b": {}},
        {"t": 5, "s": "nine", "b": {}},
        "not a map",
    ]
    for body in bad_bodies:
        frame = cose.sign(b.key, cbor2.dumps(body), external_aad=eb.nonces)
        ea.on_message(frame, clock())  # must not raise
    ea.on_message(b"\xff\xff\xff", clock())
    ea.on_message(b"", clock())
    assert ea.state is State.VERIFIED
    # a token that is not COSE at all, properly signed as a SAFETY_STOP by the peer
    eb.send(messages.SafetyStop(SafetyCommand.stop, 1, b"garbage"))
    link.pump(clock())
    assert ea.state is State.VERIFIED


def test_handshake_timeout_closes(clock, key_a, card_a):
    a = Node(key_a, card_a, handler=AcceptAll(), clock=clock)
    link = LoopbackLink()
    ea = a.initiate(link.a, b"\x09" * 8, now=clock())
    link.a.bind(ea)
    clock.advance(E.TIMEOUT_HAILED_S + 0.1)
    ea.tick(clock())
    assert ea.state is State.CLOSED and ea.close_reason == "handshake timeout"


def test_proposal_and_negotiation_timeouts(pair, clock):
    a, b, link, ha, hb = pair
    ea, eb = handshake(a, b, link, clock())
    t = ea.propose("yield", now=clock())
    # the peer never answers (frames dropped)
    link._queue.clear()
    clock.advance(E.TIMEOUT_PROPOSAL_S + 0.1)
    ea.tick(clock())
    assert t.state == "declined" and t.reason is ReasonCode.timeout
    clock.advance(E.TIMEOUT_NEGOTIATION_S)
    ea.tick(clock())
    assert ea.state is State.CLOSED and ea.close_reason == "negotiation timeout"


def test_idle_timeout(pair, clock):
    a, b, link, ha, hb = pair
    ea, eb = handshake(a, b, link, clock())
    clock.advance(E.TIMEOUT_IDLE_S + 1)
    ea.tick(clock())
    assert ea.state is State.CLOSED and ea.close_reason == "idle"


def test_replayed_frame_is_dropped(pair, clock):
    a, b, link, ha, hb = pair
    ea, eb = handshake(a, b, link, clock())
    ea.propose("yield", now=clock())
    frame = link.a.sent[-1]
    while link.pump(clock()):
        pass
    before = len(eb.tasks)
    eb.on_message(frame, clock())  # replay
    assert len(eb.tasks) == before
    assert any(e.kind == "drop" and "sequence" in e.detail for e in eb.log)


def test_wrong_nonce_in_hail_ack_is_dropped(pair, clock):
    a, b, link, ha, hb = pair
    ea = a.initiate(link.a, b.ephemeral_id, now=clock())
    link.a.bind(ea)
    forged = messages.encode(b.key, messages.HailAck(b.card_digest, messages.new_nonce(), messages.new_nonce(), 2), 0)
    ea.on_message(forged, clock())
    assert ea.state is State.HAILED and ea.peer.nonce is None


def test_relay_bound_closes_slow_handshake(pair, clock):
    a, b, link, ha, hb = pair
    ea = a.initiate(link.a, b.ephemeral_id, now=clock())
    link.a.bind(ea)
    eb = b.accept(link.b, now=clock())
    link.b.bind(eb)
    link.pump(clock(), max_frames=1)  # HAIL delivered, HAIL_ACK queued
    clock.advance(E.ROUND_TRIP_BOUND_S + 0.1)
    link.pump(clock())
    assert ea.state is State.CLOSED and ea.close_reason == "relay bound"


def test_safety_stop_verified_and_unverified(pair, clock):
    a, b, link, ha, hb = pair
    root = NodeKey.generate()
    a.trusted_roots[root.kid] = root.public_key
    ea, eb = handshake(a, b, link, clock())
    now = int(clock())
    tok = token.issue(root, zone=2, commands=[SafetyCommand.hold], nbf=now - 10, exp=now + 600)
    eb.safety_stop(SafetyCommand.hold, 2, tok, now=clock())
    link.pump(clock())
    assert ha.safety[-1] == (SafetyCommand.hold, 2, True)
    # the token does not allow STOP in zone 2: unverified, but STOP alone is still honored once a minute
    eb.safety_stop(SafetyCommand.stop, 2, tok, now=clock())
    link.pump(clock())
    assert ha.safety[-1] == (SafetyCommand.stop, 2, False)
    eb.safety_stop(SafetyCommand.stop, 2, tok, now=clock())
    link.pump(clock())
    assert len(ha.safety) == 2  # rate-limited
    # HOLD without a valid token is ignored entirely
    eb.safety_stop(SafetyCommand.hold, 5, tok, now=clock())
    link.pump(clock())
    assert len(ha.safety) == 2


def test_observe_decides_when_to_hail(clock, key_a, card_a, key_b, card_b):
    a = Node(key_a, card_a, handler=AcceptAll(), clock=clock)
    b = Node(key_b, card_b, handler=AcceptAll(), clock=clock)
    initiator, other = (a, b) if a.ephemeral_id < b.ephemeral_id else (b, a)
    bea = other.identity_beacon(state=NodeState.transiting)
    assert initiator.observe(bea, -60, clock()) is False  # one beacon is not enough
    assert initiator.observe(bea, -60, clock()) is True  # two consecutive above threshold
    assert other.observe(initiator.identity_beacon(state=NodeState.transiting), -60, clock()) is False
    assert (
        other.observe(initiator.identity_beacon(state=NodeState.transiting), -60, clock()) is False
    )  # higher ID waits
    weak = initiator.observe(bea, -80, clock())
    assert weak is False and initiator.sightings[bea.ephemeral_id].consecutive == 0


def test_observe_ignores_nodes_without_common_profile(clock, key_a, card_a, key_b):
    a = Node(key_a, card_a, handler=AcceptAll(), clock=clock)
    b = Node(
        key_b,
        make_card(key_b, "charger", profiles=["access/1"], node_class=NodeClass.charger),
        handler=AcceptAll(),
        clock=clock,
    )
    other_card = make_card(key_b, "x", profiles=["access/1"])
    bea = b.identity_beacon(state=NodeState.idle)
    # rover-a lists access/1 too, so there is overlap; make one without overlap
    k = NodeKey.generate()
    c = Node(k, make_card(k, "row-only", profiles=["rightofway/1"]), handler=AcceptAll(), clock=clock)
    for _ in range(2):
        r = c.observe(bea, -50, clock())
    assert r is False
    assert b.observe(a.identity_beacon(state=NodeState.transiting), -50, clock()) is False  # a mark never initiates
    assert other_card.verify()


def test_level1_node_never_initiates(clock, key_a, key_b, card_b):
    tag = Node(key_a, make_card(key_a, "tag", level=1), handler=AcceptAll(), clock=clock)
    b = Node(key_b, card_b, handler=AcceptAll(), clock=clock)
    bea = b.identity_beacon(state=NodeState.transiting)
    assert tag.observe(bea, -50, clock()) is False
    assert tag.observe(bea, -50, clock()) is False


def test_mark_holds_sixteen_encounters(clock, key_b):
    mark = Node(
        key_b,
        make_card(key_b, "gate", node_class=NodeClass.mark_gate, profiles=["access/1"], level=3),
        handler=AcceptAll(),
        clock=clock,
    )
    assert mark.is_mark and mark.max_encounters == E.MAX_ENCOUNTERS_MARK


def test_encounter_records_and_node_rejects_unsigned_card(clock, key_a, card_a, key_b):
    a = Node(key_a, card_a, handler=AcceptAll(), clock=clock)
    assert a.encounter_records() == []
    unsigned = make_card(key_b, "u")
    unsigned.signatures = []
    with pytest.raises(E.EncounterError):
        Node(key_b, unsigned, clock=clock)
    with pytest.raises(E.EncounterError):
        Node(key_a, make_card(key_b, "wrong-key"), clock=clock)


def test_identity_beacon_reflects_card(pair, clock):
    a, b, link, ha, hb = pair
    bea = a.identity_beacon(state=NodeState.transiting, heading_deg=10, speed_mps=1.0)
    assert isinstance(bea, IdentityBeacon)
    assert bea.ephemeral_id == a.ephemeral_id
    assert bea.priority_class is PriorityClass.standard
    assert bea.profiles == 0b11
    raw = bea.encode(a.beacon_session_key)
    assert len(raw) == 24


def test_hail_flood_triggers_quiet_period(clock, key_a, card_a):
    a = Node(key_a, card_a, handler=AcceptAll(), clock=clock)
    eid = b"\x07" * 8
    for _ in range(E.HAIL_FLOOD_PER_MIN):
        assert a.hail_allowed(eid, clock())
    assert not a.hail_allowed(eid, clock())
    clock.advance(E.QUIET_PERIOD_S + 1)
    assert a.hail_allowed(eid, clock())


def test_clock_fixture():
    c = Clock(5.0)
    assert c() == 5.0 and c.advance(1) == 6.0


def test_mobile_node_hails_a_mark_regardless_of_ephemeral_id(clock, key_a, card_a, key_b):
    a = Node(key_a, card_a, handler=AcceptAll(), clock=clock)
    gate = Node(
        key_b, make_card(key_b, "gate", node_class=NodeClass.mark_gate, profiles=["access/1"], level=3), clock=clock
    )
    bea = gate.identity_beacon(state=NodeState.idle)
    assert a.observe(bea, -50, clock()) is False
    assert a.observe(bea, -50, clock()) is True  # even when the mark's ID is lower than ours


def test_higher_ephemeral_id_hails_after_the_wait(clock, key_a, card_a, key_b, card_b):
    a = Node(key_a, card_a, handler=AcceptAll(), clock=clock)
    b = Node(key_b, card_b, handler=AcceptAll(), clock=clock)
    higher, lower = (a, b) if a.ephemeral_id > b.ephemeral_id else (b, a)
    bea = lower.identity_beacon(state=NodeState.transiting)
    assert higher.observe(bea, -50, clock()) is False
    assert higher.observe(bea, -50, clock()) is False  # qualified, but the lower ID gets first go
    clock.advance(E.INITIATOR_WAIT_S + 0.05)
    assert higher.observe(lower.identity_beacon(state=NodeState.transiting), -50, clock()) is True


def test_stale_beacon_timestamp_does_not_count(clock, key_a, card_a, key_b, card_b):
    a = Node(key_a, card_a, handler=AcceptAll(), clock=clock)
    b = Node(key_b, card_b, handler=AcceptAll(), clock=clock)
    initiator, other = (a, b) if a.ephemeral_id < b.ephemeral_id else (b, a)
    from burgee.beacon import tenths_in_hour

    stale = other.identity_beacon(state=NodeState.transiting, timestamp_tenths=(tenths_in_hour(clock()) - 50) % 36000)
    assert initiator.observe(stale, -50, clock()) is False
    assert initiator.observe(stale, -50, clock()) is False
    assert initiator.sightings[stale.ephemeral_id].consecutive == 0


def test_handheld_always_initiates_and_is_never_hailed(clock, key_a, card_a, key_b):
    from burgee.card import Operator

    phone = Node(
        key_b,
        make_card(
            key_b,
            "reader-app",
            level=1,
            node_class=NodeClass.handheld,
            profiles=["rightofway/1"],
            footprint=(0.6, 0.6, 1.7),
            operator=Operator("Burgee Reader", "https://burgeeprotocol.org/reader", ""),
        ),
        handler=AcceptAll(),
        clock=clock,
    )
    rover = Node(key_a, card_a, handler=AcceptAll(), clock=clock)
    assert phone.is_handheld and not phone.is_mark
    bea = rover.identity_beacon(state=NodeState.transiting)
    assert phone.observe(bea, -50, clock()) is False
    assert phone.observe(bea, -50, clock()) is True  # Level 1 but handheld: hails, whatever the IDs
    # a robot never hails a handheld, even one that (against the spec) advertises
    phone_bea = phone.identity_beacon(state=NodeState.transiting)
    assert rover.observe(phone_bea, -50, clock()) is False
    assert rover.observe(phone_bea, -50, clock()) is False
    link = LoopbackLink()
    ep, er = handshake(phone, rover, link, clock())
    assert ep.state is State.VERIFIED and er.state is State.VERIFIED
    assert er.peer.card.burgee.node_class is NodeClass.handheld
