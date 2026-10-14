from __future__ import annotations

import pytest

from burgee import NodeKey, Operator, build_card
from burgee.encounter import Node
from burgee.messages import Accept
from burgee.registries import Capability, NodeClass, PriorityClass
from burgee.transport import LoopbackLink


class Clock:
    def __init__(self, t: float = 1_700_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> float:
        self.t += dt
        return self.t


class AcceptAll:
    """A Level 2 handler that accepts every proposal and records what happened."""

    def __init__(self) -> None:
        self.agreed: list = []
        self.declined: list = []
        self.statuses: list = []
        self.safety: list = []
        self.closed: list = []

    def on_propose(self, enc, p):
        return Accept(task_id=p.task_id, params={"ack": True})

    def on_agreed(self, enc, task):
        self.agreed.append(task)

    def on_declined(self, enc, task):
        self.declined.append(task)

    def on_status(self, enc, s):
        self.statuses.append(s)

    def on_safety(self, enc, command, zone, verified):
        self.safety.append((command, zone, verified))

    def on_closed(self, enc, reason):
        self.closed.append(reason)


OPERATOR = Operator(name="Acme Robotics", contact="mailto:ops@acme.example", registry_id="acme")


def make_card(
    key: NodeKey,
    name: str = "rover",
    *,
    level: int = 2,
    profiles=None,
    node_class=NodeClass.sidewalk_delivery,
    footprint=(0.6, 0.9, 0.7),
    caps: int | None = None,
    priority=PriorityClass.standard,
    operator=OPERATOR,
):
    caps = (
        int(Capability.can_yield | Capability.can_stop | Capability.can_wait | Capability.negotiates)
        if caps is None
        else caps
    )
    return build_card(
        key=key,
        name=name,
        description=f"{name} test card",
        version="1.0.0",
        node_class=node_class,
        operator=operator,
        footprint_m=footprint,
        max_speed_mps=1.8,
        capabilities=caps,
        profiles=profiles or ["rightofway/1", "access/1"],
        conformance_level=level,
        region="US-CT",
        priority_class=priority,
    )


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def key_a() -> NodeKey:
    return NodeKey.generate()


@pytest.fixture
def key_b() -> NodeKey:
    return NodeKey.generate()


@pytest.fixture
def card_a(key_a):
    return make_card(key_a, "rover-a")


@pytest.fixture
def card_b(key_b):
    return make_card(key_b, "rover-b", footprint=(0.4, 0.4, 0.3))


@pytest.fixture
def pair(clock, key_a, card_a, key_b, card_b):
    """Two Level 2 nodes with accept-all handlers and a loopback link between them."""
    ha, hb = AcceptAll(), AcceptAll()
    a = Node(key_a, card_a, handler=ha, clock=clock)
    b = Node(key_b, card_b, handler=hb, clock=clock)
    link = LoopbackLink()
    return a, b, link, ha, hb


def handshake(a: Node, b: Node, link: LoopbackLink, now: float, profile: str = "rightofway/1"):
    """Open an encounter from a to b and pump until quiet. Returns (ea, eb)."""
    ea = a.initiate(link.a, b.ephemeral_id, profile=profile, now=now)
    link.a.bind(ea)
    eb = b.accept(link.b, now=now)
    link.b.bind(eb)
    while link.pump(now):
        pass
    return ea, eb
