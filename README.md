# burgee

Reference implementation of **Burgee**, the Open Robot Proximity Protocol: a BLE identity
beacon plus an [A2A v1.0](https://a2a-protocol.org/latest/specification/) handshake between
robots that share no owner, no network and no prior relationship.

Every robot flies a burgee. The specification lives in
[burgee-protocol/spec](https://github.com/burgee-protocol/spec); this package implements it.

> Status: v0.1 alpha. The protocol core (beacons, cards, signatures, the encounter state
> machine, both v0.1 profiles) is complete and tested without hardware. The BLE transport is
> written against BlueZ and has not yet been run on a radio; that happens on the two prototype
> rovers.

## Install

```sh
pip install burgee            # protocol core, no hardware needed
pip install 'burgee[ble]'     # adds bleak + bluez-peripheral for Linux radios
```

Python 3.11+. Dependencies: `cryptography` (Ed25519), `cbor2`, `jcs` (RFC 8785).

## Try it in sixty seconds

```sh
burgee demo loopback
```

Two in-memory nodes meet, hail, exchange signed cards, authenticate each other, apply the
`rightofway/1` precedence table, agree, and close. The transcript prints every state change
and the largest frame that crossed the (virtual) wire.

```sh
burgee keygen --out node.key
burgee card build --key node.key --name rover-a --node-class sidewalk_delivery \
  --operator "Acme Robotics" --contact mailto:ops@acme.example \
  --width 0.6 --length 0.9 --height 0.7 --max-speed 1.8 \
  --capability can_yield --capability negotiates \
  --profile rightofway/1 --profile access/1 --level 2 --region US-CT --out card.cbor
burgee card show card.cbor
burgee beacon encode --key node.key --node-class sidewalk_delivery --heading 90 --speed 1.2
burgee beacon decode 0201061bffffff10...        # a 31-byte advertisement or 24-byte payload
```

## Use it from Python

```python
from burgee import NodeKey, Operator, build_card, Node
from burgee.registries import Capability, NodeClass, NodeState
from burgee.messages import Accept

key = NodeKey.generate()
card = build_card(
    key=key, name="rover-a", description="TurtleBot3", version="1.0.0",
    node_class=NodeClass.sidewalk_delivery,
    operator=Operator("Acme Robotics", "mailto:ops@acme.example", "acme"),
    footprint_m=(0.6, 0.9, 0.7), max_speed_mps=1.8,
    capabilities=int(Capability.can_yield | Capability.negotiates),
    profiles=["rightofway/1"], conformance_level=2, region="US-CT",
)

class Policy:                                   # your robot's decisions
    def on_propose(self, enc, p):               # p.profile, p.action, p.params
        return Accept(task_id=p.task_id)
    def on_agreed(self, enc, task): ...         # tell your planner to yield / hold / proceed
    def on_declined(self, enc, task): ...
    def on_status(self, enc, s): ...
    def on_safety(self, enc, command, zone, verified): ...   # stop the robot
    def on_closed(self, enc, reason): ...

node = Node(key, card, handler=Policy())
beacon = node.identity_beacon(state=NodeState.transiting, heading_deg=90, speed_mps=1.2)
payload = beacon.encode(node.beacon_session_key)      # 24 bytes, put it on the air
```

The `Node` is transport-agnostic. A transport hands it a `Channel` (anything with `send()` and
`close()`), calls `encounter.on_message(frame, now)` for inbound frames and `node.tick()` on a
timer. `burgee.transport.loopback` is the in-memory one; `burgee.transport.ble` is BlueZ.

On a Linux machine with a Bluetooth adapter and `burgee[ble]` installed:

```sh
burgee run --key node.key --card card.cbor --state transiting
```

## What is where

| Module | Spec section | Contents |
| --- | --- | --- |
| `burgee.registries` | 13 | The ten code registries, loaded from the vendored `registries.json` as enums |
| `burgee.identity` | 4, 9 | Ed25519 node key, stable ID, rotating ephemeral ID, beacon tag |
| `burgee.beacon` | 4 | IDENTITY, LOCATION, SAFETY and INTENT beacons, 24 bytes each; 31-byte advertisement framing |
| `burgee.cose` | 6, 9 | Minimal COSE_Sign1 with EdDSA (RFC 9052) |
| `burgee.jws` | 7 | JWS with EdDSA over JCS (RFC 8785) for A2A card signatures |
| `burgee.card` | 7 | The A2A Agent Card with the Burgee extension; digest, signing, countersignatures, wire form |
| `burgee.token` | 9 | The v0.1 authority token |
| `burgee.messages` | 6 | The 12-message Layer 3 set and its COSE envelope |
| `burgee.encounter` | 5, 6, 9 | The encounter state machine, the node runtime, rate limits, the card cache |
| `burgee.profiles.rightofway` | 8 | The default precedence table and proposal validation |
| `burgee.profiles.access` | 8 | The mark's decision policy |
| `burgee.transport.chunking` | 5 | 2-byte-header chunking for frames larger than one GATT write |
| `burgee.transport.loopback` | — | Deterministic in-memory link for tests and the demo |
| `burgee.transport.ble` | 5 | Advertising, scanning, the GATT service and client on BlueZ |

## Development

```sh
pip install -e '.[dev]'
pytest
ruff check src tests && ruff format --check src tests
python tools/sync_registries.py ../spec      # refresh the vendored registries from the spec repo
```

Contributions follow the [CLA and process](https://github.com/burgee-protocol/spec/blob/main/CONTRIBUTING.md)
in the spec repository. A change to the wire format is a BEP there first; code follows.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
