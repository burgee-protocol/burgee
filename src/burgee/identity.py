"""Node identity: one Ed25519 key per node, a stable ID derived from it, and
the rotating ephemeral ID that goes on the air.

Spec sections 4 (ephemeral ID, tag) and 9 (keys).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

STABLE_ID_LEN = 32
KID_LEN = 8
EPHEMERAL_ID_LEN = 8
TAG_LEN = 4
SESSION_KEY_LEN = 16
DEFAULT_ROTATION_S = 600


def stable_id(public_key: bytes) -> bytes:
    """SHA-256 of the 32-byte Ed25519 public key: the node's stable ID."""
    if len(public_key) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return hashlib.sha256(public_key).digest()


def kid(public_key: bytes) -> bytes:
    """The first 8 bytes of the stable ID, used as COSE ``kid`` and token ``iss``."""
    return stable_id(public_key)[:KID_LEN]


def verify(public_key: bytes, signature: bytes, data: bytes) -> bool:
    """True if ``signature`` is a valid Ed25519 signature of ``data`` under ``public_key``."""
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(signature, data)
    except (InvalidSignature, ValueError):
        return False
    return True


@dataclass
class NodeKey:
    """The node's Ed25519 keypair. Generate it on the device and never export the seed
    beyond that device's own storage."""

    _private: ed25519.Ed25519PrivateKey

    @classmethod
    def generate(cls) -> NodeKey:
        return cls(ed25519.Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> NodeKey:
        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be 32 bytes")
        return cls(ed25519.Ed25519PrivateKey.from_private_bytes(seed))

    def seed(self) -> bytes:
        """The 32-byte private seed, for storage on the device only."""
        return self._private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    @property
    def public_key(self) -> bytes:
        return self._private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    @property
    def stable_id(self) -> bytes:
        return stable_id(self.public_key)

    @property
    def kid(self) -> bytes:
        return kid(self.public_key)

    def sign(self, data: bytes) -> bytes:
        return self._private.sign(data)


@dataclass
class EphemeralIdSource:
    """Produces the ephemeral ID broadcast in the beacon.

    A fresh random session key is drawn every ``rotation_s`` seconds (default 10 minutes).
    The ephemeral ID is HMAC-SHA256(session_key, public_key)[:8]; the beacon tag is
    HMAC-SHA256(session_key, beacon bytes 0..19)[:4]. A passive listener sees a new ID
    every rotation and nothing that links two rotations together.
    """

    public_key: bytes
    rotation_s: float = DEFAULT_ROTATION_S
    clock: Callable[[], float] = time.time
    _session_key: bytes = field(default_factory=lambda: os.urandom(SESSION_KEY_LEN))
    _rotated_at: float = field(default=0.0)

    def __post_init__(self) -> None:
        if len(self.public_key) != 32:
            raise ValueError("Ed25519 public key must be 32 bytes")
        self._rotated_at = self.clock()

    def _maybe_rotate(self) -> None:
        now = self.clock()
        if now - self._rotated_at >= self.rotation_s:
            self._session_key = os.urandom(SESSION_KEY_LEN)
            self._rotated_at = now

    def rotate_now(self) -> None:
        """Force a rotation, e.g. when the node leaves a site."""
        self._session_key = os.urandom(SESSION_KEY_LEN)
        self._rotated_at = self.clock()

    @property
    def session_key(self) -> bytes:
        self._maybe_rotate()
        return self._session_key

    @property
    def ephemeral_id(self) -> bytes:
        return ephemeral_id(self.session_key, self.public_key)


def ephemeral_id(session_key: bytes, public_key: bytes) -> bytes:
    return hmac.new(session_key, public_key, hashlib.sha256).digest()[:EPHEMERAL_ID_LEN]


def beacon_tag(session_key: bytes, covered: bytes) -> bytes:
    """The 4-byte tag over beacon bytes 0..19."""
    return hmac.new(session_key, covered, hashlib.sha256).digest()[:TAG_LEN]


def should_initiate(my_ephemeral_id: bytes, their_ephemeral_id: bytes) -> bool:
    """Spec section 5: the node with the lower ephemeral ID opens the connection."""
    return my_ephemeral_id < their_ephemeral_id
