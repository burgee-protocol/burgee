"""BLE transport on Linux: BlueZ through ``bleak`` (scanning, GATT client) and
``bluez-peripheral`` (advertising, GATT server). Install with ``pip install burgee[ble]``.

Everything protocol-shaped (beacons, cards, encounters) lives in the transport-agnostic
core and is tested without a radio. This module only moves bytes:

* :class:`Advertiser` puts the node's 24-byte burgee on the air once a second (every 5 s
  when docked or idle) as Manufacturer Specific Data under the test company ID. The
  advertisement carries nothing else: Flags (3 bytes) + the 28-byte MSD block is the whole
  31-byte legacy packet, as spec section 4 lays it out.
* :class:`Scanner` turns received advertisements into ``IdentityBeacon`` objects and asks
  the node whether to hail.
* :class:`Peripheral` serves the Burgee GATT service (section 5). The initiator writes HAIL
  to the HAIL characteristic and every later frame to STREAM; the responder answers on REPLY
  (notify). Each connecting central gets its own responder :class:`Encounter`.
* :class:`Central` connects to a peer, subscribes to REPLY, writes HAIL and then STREAM, and
  carries the initiator :class:`Encounter`. Writes are serialized through one queue so chunks
  of two frames never interleave.
* :func:`run` ties them together on an asyncio loop.

Frames are chunked for GATT (``transport/chunking.py``). Because every frame is signed with
the encounter's nonces as external AAD, a frame that reaches the wrong central through
BlueZ's notify fan-out fails verification and is dropped; it cannot act on anyone else's
encounter.

Status: this module has not yet been run against hardware; the first run is on the two
prototype rovers.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from .. import beacon as beaconmod
from ..encounter import Encounter, Node
from ..registries import NodeState
from .chunking import Reassembler, chunk, max_chunk_for_mtu

log = logging.getLogger("burgee.ble")

SERVICE_UUID = "b0a7ee00-5e1f-4c5a-9b2d-7a6b0c3d1e02"
CARD_UUID = "b0a7ee01-5e1f-4c5a-9b2d-7a6b0c3d1e02"
HAIL_UUID = "b0a7ee02-5e1f-4c5a-9b2d-7a6b0c3d1e02"
REPLY_UUID = "b0a7ee03-5e1f-4c5a-9b2d-7a6b0c3d1e02"
STREAM_UUID = "b0a7ee04-5e1f-4c5a-9b2d-7a6b0c3d1e02"

BEACON_PERIOD_MOVING_S = 1.0
BEACON_PERIOD_IDLE_S = 5.0
TICK_S = 0.1


def _require(module: str) -> Any:
    try:
        return __import__(module, fromlist=["*"])
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise RuntimeError(f"{module} is not installed; run: pip install 'burgee[ble]'") from exc


# ---- advertising ---------------------------------------------------------------------------


class Advertiser:
    """Broadcasts the node's IDENTITY burgee. BlueZ reads an advertisement's properties when
    it is registered, so a changed payload means unregister and register again; at 1 Hz that
    is what this does. No local name and no service UUID go in the packet: the 31 bytes are
    spoken for."""

    def __init__(self, node: Node) -> None:
        self.node = node
        self._bus = None
        self._adapter = None
        self._advert = None

    async def start(self) -> None:
        util = _require("bluez_peripheral.util")
        self._bus = await util.get_message_bus()
        self._adapter = await util.Adapter.get_first(self._bus)

    async def publish(self, payload: bytes) -> None:
        advert_mod = _require("bluez_peripheral.advert")
        if self._advert is not None:
            try:
                await self._advert.unregister()
            except Exception as exc:  # pragma: no cover
                log.debug("unregister advertisement: %s", exc)
        self._advert = advert_mod.Advertisement(
            "",
            [],
            0,
            0,
            manufacturerData={beaconmod.COMPANY_ID_TEST: beaconmod.manufacturer_data(payload)},
        )
        await self._advert.register(self._bus, self._adapter)

    async def run(
        self,
        state_of: Callable[[], NodeState],
        heading_of: Callable[[], float | None] = lambda: None,
        speed_of: Callable[[], float | None] = lambda: None,
    ) -> None:
        await self.start()
        while True:
            state = state_of()
            b = self.node.identity_beacon(state=state, heading_deg=heading_of(), speed_mps=speed_of())
            await self.publish(b.encode(self.node.beacon_session_key))
            moving = state in (NodeState.transiting, NodeState.waiting)
            await asyncio.sleep(BEACON_PERIOD_MOVING_S if moving else BEACON_PERIOD_IDLE_S)


# ---- scanning ------------------------------------------------------------------------------


@dataclass
class Sighting:
    address: str
    beacon: beaconmod.IdentityBeacon
    rssi: int


class Scanner:
    """Listens for burgees and calls ``on_hail(sighting)`` when the node decides to open an
    encounter with that peer."""

    def __init__(self, node: Node, on_hail: Callable[[Sighting], Awaitable[None]]) -> None:
        self.node = node
        self.on_hail = on_hail
        self._scanner = None
        self._loop: asyncio.AbstractEventLoop | None = None

    def _detected(self, device: Any, adv: Any) -> None:
        try:
            md = adv.manufacturer_data.get(beaconmod.COMPANY_ID_TEST)
            if not md or len(md) != beaconmod.PAYLOAD_LEN:
                return
            b = beaconmod.decode(bytes(md))
            if not isinstance(b, beaconmod.IdentityBeacon):
                return  # LOCATION, SAFETY and INTENT are observed, not hailed on
            now = self.node.clock()
            if self.node.observe(b, int(adv.rssi), now) and self._loop is not None:
                self._loop.create_task(self.on_hail(Sighting(device.address, b, int(adv.rssi))))
        except Exception as exc:  # a bad packet must never kill the detection callback
            log.debug("ignored advertisement: %s", exc)

    async def run(self) -> None:
        bleak = _require("bleak")
        self._loop = asyncio.get_running_loop()
        self._scanner = bleak.BleakScanner(detection_callback=self._detected)
        await self._scanner.start()
        try:
            while True:
                await asyncio.sleep(3600)
        finally:
            await self._scanner.stop()


# ---- responder side (GATT server) ----------------------------------------------------------


@dataclass
class PeripheralChannel:
    """The responder side of one connection, inside the GATT server."""

    device: str
    service: Any
    encounter: Encounter | None = None
    closed: bool = False

    def send(self, data: bytes) -> None:
        if self.closed:
            return
        for piece in chunk(data, max_chunk_for_mtu()):
            self.service.notify_reply(piece)

    def close(self) -> None:
        self.closed = True


class Peripheral:
    """The Burgee GATT service. One responder encounter per connected central."""

    def __init__(self, node: Node) -> None:
        self.node = node
        self._channels: dict[str, PeripheralChannel] = {}
        self._reassemblers: dict[str, Reassembler] = {}
        self._card_pos: dict[str, int] = {}
        self._service = None
        self._bus = None

    def _channel_for(self, device: str) -> PeripheralChannel:
        ch = self._channels.get(device)
        if ch is None or ch.closed:
            ch = PeripheralChannel(device, self._service)
            enc = self.node.accept(ch, now=self.node.clock())
            ch.encounter = enc
            self._channels[device] = ch
            self._reassemblers[device] = Reassembler()
        return ch

    def _on_write(self, device: str, data: bytes) -> None:
        ch = self._channel_for(device)
        try:
            frame = self._reassemblers[device].feed(data)
        except Exception as exc:
            log.warning("chunk error from %s: %s", device, exc)
            return
        if frame is not None and ch.encounter is not None:
            ch.encounter.on_message(frame, self.node.clock())

    def _card_chunk(self, device: str) -> bytes:
        """Successive reads of CARD return successive chunks of the node's card; a read after
        the last chunk starts over. A GATT value is at most 512 bytes, so a 1 KB card cannot
        be one value."""
        pieces = list(chunk(self.node.card_wire, max_chunk_for_mtu()))
        pos = self._card_pos.get(device, 0)
        piece = pieces[pos]
        self._card_pos[device] = (pos + 1) % len(pieces)
        return piece

    async def run(self) -> None:
        gatt_service = _require("bluez_peripheral.gatt.service")
        gatt_char = _require("bluez_peripheral.gatt.characteristic")
        agent_mod = _require("bluez_peripheral.agent")
        util = _require("bluez_peripheral.util")
        peripheral = self
        CharFlags = gatt_char.CharacteristicFlags  # noqa: N806

        class BurgeeService(gatt_service.Service):
            def __init__(self) -> None:
                super().__init__(SERVICE_UUID, True)

            @gatt_char.characteristic(CARD_UUID, CharFlags.READ)
            def card(self, options: Any) -> bytes:
                return peripheral._card_chunk(getattr(options, "device", "?"))

            @gatt_char.characteristic(HAIL_UUID, CharFlags.WRITE)
            def hail(self, options: Any) -> bytes:
                return b""

            @hail.setter
            def hail(self, value: bytes, options: Any) -> None:
                peripheral._on_write(getattr(options, "device", "?"), bytes(value))

            @gatt_char.characteristic(REPLY_UUID, CharFlags.NOTIFY)
            def reply(self, options: Any) -> bytes:
                return b""

            @gatt_char.characteristic(STREAM_UUID, CharFlags.WRITE)
            def stream(self, options: Any) -> bytes:
                return b""

            @stream.setter
            def stream(self, value: bytes, options: Any) -> None:
                peripheral._on_write(getattr(options, "device", "?"), bytes(value))

            def notify_reply(self, piece: bytes) -> None:
                # bluez-peripheral notifies every subscriber of REPLY. Each frame is signed
                # under its own encounter's nonces, so a central that receives another
                # central's frame drops it at verification.
                self.reply.changed(piece)

        self._bus = await util.get_message_bus()
        self._service = BurgeeService()
        await self._service.register(self._bus)
        agent = agent_mod.NoIoAgent()
        await agent.register(self._bus)
        log.info("Burgee GATT service registered")
        while True:
            await asyncio.sleep(TICK_S)
            self.node.tick()


# ---- initiator side (GATT client) ----------------------------------------------------------


class CentralChannel:
    """The initiator side of one connection, over a bleak client. All writes go through one
    worker task in order; ``close`` runs after the last queued write."""

    def __init__(self, client: Any, loop: asyncio.AbstractEventLoop) -> None:
        self.client = client
        self.loop = loop
        self.closed = False
        self._first = True
        self.encounter: Encounter | None = None
        self._reassembler = Reassembler()
        self._queue: asyncio.Queue[tuple[str, bytes] | None] = asyncio.Queue()
        self._worker = loop.create_task(self._drain())

    async def _drain(self) -> None:
        while True:
            item = await self._queue.get()
            if item is None:
                try:
                    await self.client.disconnect()
                except Exception as exc:  # pragma: no cover
                    log.debug("disconnect: %s", exc)
                return
            uuid, piece = item
            try:
                await self.client.write_gatt_char(uuid, piece, response=True)
            except Exception as exc:
                log.warning("write failed: %s", exc)
                if self.encounter is not None:
                    self.encounter.range_lost(self.encounter.node.clock())
                return

    def send(self, data: bytes) -> None:
        if self.closed:
            return
        uuid = HAIL_UUID if self._first else STREAM_UUID
        self._first = False
        mtu = getattr(self.client, "mtu_size", 247)
        for piece in chunk(data, max_chunk_for_mtu(mtu)):
            self._queue.put_nowait((uuid, piece))

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self._queue.put_nowait(None)

    def _on_notify(self, _handle: Any, data: bytearray) -> None:
        try:
            frame = self._reassembler.feed(bytes(data))
        except Exception as exc:
            log.warning("chunk error: %s", exc)
            return
        if frame is not None and self.encounter is not None:
            self.encounter.on_message(frame, self.encounter.node.clock())


class Central:
    """Opens initiator encounters over BLE."""

    def __init__(self, node: Node) -> None:
        self.node = node

    async def hail(self, sighting: Sighting, *, profile: str = "rightofway/1") -> Encounter:
        bleak = _require("bleak")
        loop = asyncio.get_running_loop()
        client = bleak.BleakClient(sighting.address)
        await client.connect()
        ch = CentralChannel(client, loop)
        await client.start_notify(REPLY_UUID, ch._on_notify)
        enc = self.node.initiate(ch, sighting.beacon.ephemeral_id, profile=profile)
        ch.encounter = enc
        return enc


# ---- main loop -----------------------------------------------------------------------------


@dataclass
class Runner:
    node: Node
    state_of: Callable[[], NodeState] = lambda: NodeState.idle
    profile: str = "rightofway/1"
    on_encounter: Callable[[Encounter], None] | None = None
    tasks: list[asyncio.Task] = field(default_factory=list)

    async def _on_hail(self, sighting: Sighting) -> None:
        try:
            enc = await Central(self.node).hail(sighting, profile=self.profile)
        except Exception as exc:
            log.warning("hail to %s failed: %s", sighting.address, exc)
            return
        if self.on_encounter is not None:
            self.on_encounter(enc)

    async def run(self) -> None:
        adv = Advertiser(self.node)
        scan = Scanner(self.node, self._on_hail)
        per = Peripheral(self.node)
        self.tasks = [
            asyncio.create_task(adv.run(self.state_of)),
            asyncio.create_task(scan.run()),
            asyncio.create_task(per.run()),
        ]
        try:
            await asyncio.gather(*self.tasks)
        finally:
            for t in self.tasks:
                t.cancel()


def run(node: Node, **kw: Any) -> None:
    """Advertise, scan, serve and hail until interrupted."""
    asyncio.run(Runner(node, **kw).run())


__all__ = ["Advertiser", "Scanner", "Peripheral", "Central", "Runner", "run", "SERVICE_UUID"]
