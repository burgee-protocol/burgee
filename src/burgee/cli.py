"""The ``burgee`` command line.

burgee keygen --out node.key
burgee card build --key node.key --name rover-a ... --out card.cbor
burgee card show card.cbor
burgee beacon encode --key node.key --class sidewalk_delivery ...
burgee beacon decode <hex>
burgee demo loopback          # a full encounter between two in-memory nodes
burgee run --key node.key --card card.cbor   # BLE, needs burgee[ble] and a Linux adapter
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from . import __version__, beacon
from .card import AgentCard, Operator, build_card
from .encounter import Node, State
from .identity import NodeKey
from .messages import Accept
from .registries import Capability, NodeClass, NodeState, PriorityClass, profile_ids


def _load_key(path: str) -> NodeKey:
    return NodeKey.from_seed(Path(path).read_bytes())


def cmd_keygen(a: argparse.Namespace) -> int:
    key = NodeKey.generate()
    out = Path(a.out)
    out.write_bytes(key.seed())
    os.chmod(out, 0o600)
    print(f"wrote {out} (stable id {key.stable_id.hex()})")
    return 0


def cmd_card_build(a: argparse.Namespace) -> int:
    key = _load_key(a.key)
    caps = 0
    for name in a.capability or []:
        caps |= int(Capability[name])
    card = build_card(
        key=key,
        name=a.name,
        description=a.description,
        version=a.version,
        node_class=NodeClass[a.node_class],
        operator=Operator(name=a.operator, contact=a.contact, registry_id=a.registry_id),
        footprint_m=(a.width, a.length, a.height),
        max_speed_mps=a.max_speed,
        capabilities=caps,
        profiles=a.profile,
        conformance_level=a.level,
        region=a.region,
        priority_class=PriorityClass[a.priority],
    )
    wire = card.to_wire()
    Path(a.out).write_bytes(wire)
    print(f"wrote {a.out}: {len(wire)} bytes on the wire, digest {card.digest().hex()}")
    return 0


def cmd_card_show(a: argparse.Namespace) -> int:
    card = AgentCard.from_wire(Path(a.card).read_bytes())
    print(json.dumps(card.to_dict(), indent=2))
    print(f"\nsignature valid: {card.verify()}  digest: {card.digest().hex()}", file=sys.stderr)
    return 0 if card.verify() else 1


def cmd_beacon_encode(a: argparse.Namespace) -> int:
    key = _load_key(a.key)
    from .identity import EphemeralIdSource

    src = EphemeralIdSource(key.public_key)
    b = beacon.IdentityBeacon(
        node_class=NodeClass[a.node_class],
        ephemeral_id=src.ephemeral_id,
        capabilities=sum(int(Capability[c]) for c in (a.capability or [])),
        state=NodeState[a.state],
        priority_class=PriorityClass[a.priority],
        profiles=beacon_profile_bits(a.profile),
        timestamp_tenths=beacon.tenths_in_hour(time.time()),
        heading_deg=a.heading,
        speed_mps=a.speed,
        footprint_w_m=a.width,
        footprint_l_m=a.length,
    )
    payload = b.encode(src.session_key)
    print("payload (24 bytes):      ", payload.hex())
    print("advertisement (31 bytes):", beacon.frame_advertisement(payload).hex())
    return 0


def beacon_profile_bits(profiles: list[str]) -> int:
    from .registries import profile_bits

    return profile_bits(profiles)


def cmd_beacon_decode(a: argparse.Namespace) -> int:
    raw = bytes.fromhex(a.hex)
    if len(raw) == beacon.ADV_LEN:
        raw = beacon.parse_advertisement(raw)
    b = beacon.decode(raw)
    for k, v in vars(b).items():
        if k == "tag":
            continue
        if isinstance(v, bytes):
            v = v.hex()
        print(f"{k:18} {v}")
    return 0


def cmd_demo_loopback(a: argparse.Namespace) -> int:
    from .transport import LoopbackLink

    class Yielding:
        def on_propose(self, enc, p):
            return Accept(task_id=p.task_id, params={"ok": True})

        def on_agreed(self, enc, t):
            print(f"    [{enc.node.card.name}] agreed: {t.propose.skill_id} {t.accept_params}")

        def on_declined(self, enc, t):
            print(f"    [{enc.node.card.name}] declined: {t.propose.skill_id} {t.reason}")

        def on_status(self, enc, s):
            print(f"    [{enc.node.card.name}] status from peer: {s.status.name}")

        def on_safety(self, enc, c, z, v):
            print(f"    [{enc.node.card.name}] safety {c.name} zone {z} verified={v}")

        def on_closed(self, enc, r):
            print(f"    [{enc.node.card.name}] closed: {r}")

    op = Operator(name="Demo Operator", contact="mailto:ops@example.org", registry_id="demo")
    ka, kb = NodeKey.generate(), NodeKey.generate()
    caps = int(Capability.can_yield | Capability.can_stop | Capability.can_wait | Capability.negotiates)
    ca = build_card(
        key=ka,
        name="rover-a",
        description="TurtleBot3 Burger",
        version="1.0.0",
        node_class=NodeClass.sidewalk_delivery,
        operator=op,
        footprint_m=(0.2, 0.2, 0.2),
        max_speed_mps=0.22,
        capabilities=caps,
        profiles=["rightofway/1"],
        conformance_level=2,
        region="US-CT",
    )
    cb = build_card(
        key=kb,
        name="rover-b",
        description="ROSMASTER X3",
        version="1.0.0",
        node_class=NodeClass.ground_robot,
        operator=op,
        footprint_m=(0.25, 0.3, 0.3),
        max_speed_mps=0.6,
        capabilities=caps,
        profiles=["rightofway/1"],
        conformance_level=2,
        region="US-CT",
    )
    now = time.time()
    A, B = Node(ka, ca, handler=Yielding()), Node(kb, cb, handler=Yielding())
    link = LoopbackLink()
    print(f"rover-a eid {A.ephemeral_id.hex()}  rover-b eid {B.ephemeral_id.hex()}")
    initiator, responder = (A, B) if A.ephemeral_id < B.ephemeral_id else (B, A)
    print(f"{initiator.card.name} has the lower ephemeral ID and initiates\n")
    ei = initiator.initiate(link.a, responder.ephemeral_id, now=now)
    link.a.bind(ei)
    er = responder.accept(link.b, now=now)
    link.b.bind(er)
    while link.pump(now):
        pass
    print(
        f"after handshake: {initiator.card.name}={ei.state.value} "
        f"{responder.card.name}={er.state.value}, {link.delivered} frames"
    )
    from .profiles import rightofway as row

    me = row.Party(
        initiator.ephemeral_id,
        PriorityClass.standard,
        False,
        NodeState.transiting,
        initiator.card.burgee.footprint_w_m,
        initiator.card.burgee.footprint_l_m,
    )
    other = row.Party(
        responder.ephemeral_id,
        PriorityClass.standard,
        False,
        NodeState.transiting,
        responder.card.burgee.footprint_w_m,
        responder.card.burgee.footprint_l_m,
    )
    prec = row.precedence(me, other)
    action = row.default_action(me, other)
    print(f"default precedence: rule {prec.rule}, {initiator.card.name} proposes '{action}'")
    t = ei.propose(action, {"hold_s": 10} if action == "yield" else {}, now=now)
    while link.pump(now):
        pass
    print(f"task {t.propose.skill_id}: {t.state}; states {ei.state.value}/{er.state.value}")
    ei.close(now, "demo done")
    link.pump(now)
    print("\ntranscript:")
    for who, e in ((initiator.card.name, ei), (responder.card.name, er)):
        for entry in e.log:
            print(f"  {who:8} {entry.kind:18} {entry.detail}")
    print(f"\nlargest frame on the wire: {max(len(f) for f in link.a.sent + link.b.sent)} bytes")
    return 0 if ei.state is State.CLOSED and t.state == "accepted" else 1


def cmd_run(a: argparse.Namespace) -> int:
    from .transport import ble

    key = _load_key(a.key)
    card = AgentCard.from_wire(Path(a.card).read_bytes())
    node = Node(key, card)
    print(f"running {card.name} (level {card.burgee.conformance_level}) on BLE; Ctrl-C to stop")
    ble.run(node, state_of=lambda: NodeState[a.state], profile=a.profile)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="burgee", description="Burgee — every robot flies a burgee.")
    p.add_argument("--version", action="version", version=f"burgee {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen", help="generate a node key")
    k.add_argument("--out", default="node.key")
    k.set_defaults(fn=cmd_keygen)

    card = sub.add_parser("card", help="build or show a card").add_subparsers(dest="sub", required=True)
    cb = card.add_parser("build")
    cb.add_argument("--key", required=True)
    cb.add_argument("--name", required=True)
    cb.add_argument("--description", default="")
    cb.add_argument("--version", dest="version", default="1.0.0")
    cb.add_argument("--node-class", dest="node_class", choices=[c.name for c in NodeClass], default="ground_robot")
    cb.add_argument("--operator", required=True)
    cb.add_argument("--contact", required=True, help="tel:, mailto: or https: URI")
    cb.add_argument("--registry-id", dest="registry_id", default="")
    cb.add_argument("--width", type=float, required=True)
    cb.add_argument("--length", type=float, required=True)
    cb.add_argument("--height", type=float, required=True)
    cb.add_argument("--max-speed", dest="max_speed", type=float, required=True)
    cb.add_argument("--capability", action="append", choices=[c.name for c in Capability])
    cb.add_argument("--profile", action="append", choices=profile_ids(), default=None)
    cb.add_argument("--level", type=int, default=1)
    cb.add_argument("--region", required=True)
    cb.add_argument("--priority", choices=[c.name for c in PriorityClass], default="standard")
    cb.add_argument("--out", default="card.cbor")
    cb.set_defaults(fn=cmd_card_build)
    cs = card.add_parser("show")
    cs.add_argument("card")
    cs.set_defaults(fn=cmd_card_show)

    bc = sub.add_parser("beacon", help="encode or decode a beacon").add_subparsers(dest="sub", required=True)
    be = bc.add_parser("encode")
    be.add_argument("--key", required=True)
    be.add_argument("--node-class", dest="node_class", choices=[c.name for c in NodeClass], default="ground_robot")
    be.add_argument("--capability", action="append", choices=[c.name for c in Capability])
    be.add_argument("--state", choices=[s.name for s in NodeState], default="transiting")
    be.add_argument("--priority", choices=[c.name for c in PriorityClass], default="standard")
    be.add_argument("--profile", action="append", choices=profile_ids(), default=None)
    be.add_argument("--heading", type=float, default=None)
    be.add_argument("--speed", type=float, default=None)
    be.add_argument("--width", type=float, default=0.5)
    be.add_argument("--length", type=float, default=0.5)
    be.set_defaults(fn=cmd_beacon_encode)
    bd = bc.add_parser("decode")
    bd.add_argument("hex", help="24-byte payload or 31-byte advertisement, hex")
    bd.set_defaults(fn=cmd_beacon_decode)

    demo = sub.add_parser("demo", help="demonstrations").add_subparsers(dest="sub", required=True)
    dl = demo.add_parser("loopback", help="a full encounter between two in-memory nodes")
    dl.set_defaults(fn=cmd_demo_loopback)

    r = sub.add_parser("run", help="advertise, scan and serve over BLE (Linux, burgee[ble])")
    r.add_argument("--key", required=True)
    r.add_argument("--card", required=True)
    r.add_argument("--state", choices=[s.name for s in NodeState], default="transiting")
    r.add_argument("--profile", choices=profile_ids(), default="rightofway/1")
    r.set_defaults(fn=cmd_run)

    a = p.parse_args(argv)
    if getattr(a, "profile", None) is None and a.cmd in ("card", "beacon") and a.sub in ("build", "encode"):
        a.profile = ["rightofway/1"]
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
