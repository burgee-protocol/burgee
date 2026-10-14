"""An in-memory link between two encounters.

Frames are queued, not delivered synchronously, so a test (or the CLI demo) controls the
order and the clock: ``link.pump(now)`` delivers everything in flight. ``drop`` and
``delay`` hooks exist for fault injection.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field

from ..encounter import Encounter


@dataclass
class LoopbackChannel:
    name: str
    link: LoopbackLink
    encounter: Encounter | None = None
    closed: bool = False
    sent: list[bytes] = field(default_factory=list)

    def bind(self, encounter: Encounter) -> None:
        self.encounter = encounter

    def send(self, data: bytes) -> None:
        if self.closed:
            return
        self.sent.append(data)
        self.link.enqueue(self, data)

    def close(self) -> None:
        self.closed = True


class LoopbackLink:
    """Two channels, ``a`` and ``b``, joined back to back."""

    def __init__(self, *, drop: Callable[[str, bytes], bool] | None = None) -> None:
        self.a = LoopbackChannel("a", self)
        self.b = LoopbackChannel("b", self)
        self._queue: deque[tuple[LoopbackChannel, bytes]] = deque()
        self.drop = drop
        self.delivered = 0

    def peer_of(self, ch: LoopbackChannel) -> LoopbackChannel:
        return self.b if ch is self.a else self.a

    def enqueue(self, sender: LoopbackChannel, data: bytes) -> None:
        self._queue.append((sender, data))

    def pending(self) -> int:
        return len(self._queue)

    def pump(self, now: float, *, max_frames: int | None = None) -> int:
        """Deliver queued frames in order. Returns the number delivered."""
        n = 0
        while self._queue and (max_frames is None or n < max_frames):
            sender, data = self._queue.popleft()
            dest = self.peer_of(sender)
            if dest.closed or dest.encounter is None:
                continue
            if self.drop is not None and self.drop(sender.name, data):
                continue
            dest.encounter.on_message(data, now)
            n += 1
            self.delivered += 1
        return n
