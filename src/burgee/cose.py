"""Minimal COSE_Sign1 (RFC 9052) with EdDSA over Ed25519.

Every Layer 3 message and every authority token is a COSE_Sign1 object:

    18([protected, unprotected, payload, signature])

with the protected header ``{1: -8}`` (alg EdDSA) and ``{4: kid}``, and the signature
computed over ``Sig_structure = ["Signature1", protected, external_aad, payload]``.
Only what Burgee uses is implemented; it is not a general COSE library.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

import cbor2

from . import identity

COSE_SIGN1_TAG = 18
HDR_ALG = 1
HDR_KID = 4
ALG_EDDSA = -8


class CoseError(ValueError):
    """Raised for a malformed or unverifiable COSE_Sign1 object."""


@dataclass(frozen=True)
class Sign1:
    protected: bytes
    payload: bytes
    signature: bytes
    kid: bytes

    def to_bytes(self) -> bytes:
        return cbor2.dumps(cbor2.CBORTag(COSE_SIGN1_TAG, [self.protected, {}, self.payload, self.signature]))


def _sig_structure(protected: bytes, payload: bytes, external_aad: bytes = b"") -> bytes:
    return cbor2.dumps(["Signature1", protected, external_aad, payload])


def sign(key: identity.NodeKey, payload: bytes, external_aad: bytes = b"") -> bytes:
    """Sign ``payload`` and return the tagged COSE_Sign1 bytes."""
    protected = cbor2.dumps({HDR_ALG: ALG_EDDSA, HDR_KID: key.kid})
    signature = key.sign(_sig_structure(protected, payload, external_aad))
    return Sign1(protected, payload, signature, key.kid).to_bytes()


def parse(data: bytes) -> Sign1:
    """Parse without verifying. Use :func:`verify` to check the signature."""
    try:
        obj = cbor2.loads(data)
    except Exception as exc:  # cbor2 raises several decoder error types
        raise CoseError(f"not CBOR: {exc}") from exc
    if isinstance(obj, cbor2.CBORTag):
        if obj.tag != COSE_SIGN1_TAG:
            raise CoseError(f"unexpected CBOR tag {obj.tag}")
        obj = obj.value
    # cbor2 hands back a tuple and a frozendict for an array and a map inside a tag.
    if not (isinstance(obj, (list, tuple)) and len(obj) == 4):
        raise CoseError("COSE_Sign1 must be a 4-element array")
    protected, unprotected, payload, signature = obj
    if not isinstance(protected, bytes) or not isinstance(payload, bytes) or not isinstance(signature, bytes):
        raise CoseError("COSE_Sign1 fields have the wrong types")
    if not isinstance(unprotected, Mapping):
        raise CoseError("unprotected header must be a map")
    try:
        hdr = cbor2.loads(protected)
    except Exception as exc:
        raise CoseError(f"protected header is not CBOR: {exc}") from exc
    if not isinstance(hdr, Mapping) or hdr.get(HDR_ALG) != ALG_EDDSA:
        raise CoseError("protected header must carry alg EdDSA")
    kid = hdr.get(HDR_KID)
    if not isinstance(kid, bytes) or len(kid) != identity.KID_LEN:
        raise CoseError("protected header must carry an 8-byte kid")
    return Sign1(protected, payload, signature, kid)


def verify(data: bytes, public_key: bytes, external_aad: bytes = b"") -> bytes:
    """Verify a COSE_Sign1 under ``public_key`` and return its payload. Checks that the kid in
    the protected header is the kid of ``public_key``, so a message cannot be re-signed by a
    different key while claiming the same identity."""
    s = parse(data)
    if s.kid != identity.kid(public_key):
        raise CoseError("kid does not match the public key")
    if not identity.verify(public_key, s.signature, _sig_structure(s.protected, s.payload, external_aad)):
        raise CoseError("signature does not verify")
    return s.payload
