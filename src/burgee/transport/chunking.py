"""Chunking for frames larger than one GATT write (spec section 5).

A frame is split into chunks of at most ``max_chunk`` bytes of payload, each prefixed by a
2-byte header: byte 0 is the chunk sequence number (wrapping at 256), byte 1 is flags, of
which bit 0 means "last chunk of this frame". At the default 247-byte MTU a GATT write
carries 244 bytes, so a 1 KB card arrives in five chunks.
"""

from __future__ import annotations

from collections.abc import Iterator

HEADER_LEN = 2
FLAG_LAST = 0x01
DEFAULT_MTU = 247
ATT_OVERHEAD = 3


class ChunkError(ValueError):
    """Raised when chunks arrive out of order or malformed."""


def max_chunk_for_mtu(mtu: int = DEFAULT_MTU) -> int:
    return mtu - ATT_OVERHEAD - HEADER_LEN


def chunk(frame: bytes, max_chunk: int | None = None) -> Iterator[bytes]:
    """Yield the chunks of ``frame``, each with its header. An empty frame yields one chunk."""
    size = max_chunk_for_mtu() if max_chunk is None else max_chunk
    if size < 1:
        raise ChunkError("max_chunk must be at least 1")
    pieces = [frame[i : i + size] for i in range(0, len(frame), size)] or [b""]
    for n, piece in enumerate(pieces):
        flags = FLAG_LAST if n == len(pieces) - 1 else 0
        yield bytes([n & 0xFF, flags]) + piece


MAX_FRAME = 4096  # the largest Layer 3 frame is a CARD (≤ 1,024 bytes of card plus its envelope)


class Reassembler:
    """Collects chunks in order and returns the frame when the last one arrives. A frame that
    grows past ``max_frame`` is discarded, so a peer cannot make a node buffer without bound."""

    def __init__(self, max_frame: int = MAX_FRAME) -> None:
        self.max_frame = max_frame
        self._parts: list[bytes] = []
        self._size = 0
        self._expect = 0

    def reset(self) -> None:
        self._parts = []
        self._size = 0
        self._expect = 0

    def feed(self, data: bytes) -> bytes | None:
        """Feed one chunk. Returns the complete frame on the last chunk, else None."""
        if len(data) < HEADER_LEN:
            self.reset()
            raise ChunkError("chunk shorter than its header")
        seq, flags = data[0], data[1]
        if seq != self._expect & 0xFF:
            self.reset()
            raise ChunkError(f"expected chunk {self._expect & 0xFF}, got {seq}")
        self._size += len(data) - HEADER_LEN
        if self._size > self.max_frame:
            self.reset()
            raise ChunkError(f"frame larger than {self.max_frame} bytes")
        self._parts.append(data[HEADER_LEN:])
        self._expect += 1
        if flags & FLAG_LAST:
            frame = b"".join(self._parts)
            self.reset()
            return frame
        return None
