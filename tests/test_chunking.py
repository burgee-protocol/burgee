import os

import pytest

from burgee.transport import chunking


def test_chunk_and_reassemble_round_trip():
    frame = os.urandom(1000)
    chunks = list(chunking.chunk(frame))
    assert len(chunks) == 5  # 244-byte payloads at a 247 MTU
    assert all(len(c) <= chunking.DEFAULT_MTU - chunking.ATT_OVERHEAD for c in chunks)
    r = chunking.Reassembler()
    out = None
    for c in chunks:
        out = r.feed(c)
    assert out == frame


def test_small_and_empty_frames():
    assert list(chunking.chunk(b"abc")) == [b"\x00\x01abc"]
    assert list(chunking.chunk(b"")) == [b"\x00\x01"]
    r = chunking.Reassembler()
    assert r.feed(b"\x00\x01") == b""


def test_out_of_order_chunk_resets():
    frame = os.urandom(600)
    c0, c1, c2 = list(chunking.chunk(frame))
    r = chunking.Reassembler()
    assert r.feed(c0) is None
    with pytest.raises(chunking.ChunkError):
        r.feed(c2)
    # after a reset the next frame starts cleanly
    assert r.feed(c0) is None and r.feed(c1) is None and r.feed(c2) == frame
    with pytest.raises(chunking.ChunkError):
        r.feed(b"\x00")


def test_oversized_frame_is_discarded():
    r = chunking.Reassembler(max_frame=100)
    chunks = list(chunking.chunk(bytes(150), max_chunk=60))
    assert r.feed(chunks[0]) is None
    with pytest.raises(chunking.ChunkError):
        r.feed(chunks[1])
    assert r.feed(b"\x00\x01ok") == b"ok"  # reset after the discard


def test_sequence_wraps_at_256():
    frame = bytes(300 * 10)
    chunks = list(chunking.chunk(frame, max_chunk=10))
    assert len(chunks) == 300 and chunks[256][0] == 0
    r = chunking.Reassembler(max_frame=10_000)
    out = None
    for c in chunks:
        out = r.feed(c)
    assert out == frame
