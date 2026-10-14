"""JWS with EdDSA over JCS-canonicalized JSON, as A2A v1.0 Agent Card signatures use.

A2A signs the canonical form (RFC 8785) of the card with the ``signatures`` member removed,
and records each signature as ``{"protected": <b64url header>, "signature": <b64url sig>}``.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import jcs

from . import identity


class JwsError(ValueError):
    """Raised for a malformed or unverifiable signature."""


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + pad)
    except (ValueError, TypeError) as exc:
        raise JwsError(f"bad base64url: {exc}") from exc


def canonical(obj: Any) -> bytes:
    """RFC 8785 canonical JSON."""
    return jcs.canonicalize(obj)


def sign(key: identity.NodeKey, payload: dict[str, Any], extra_header: dict[str, Any] | None = None) -> dict[str, str]:
    """Produce an A2A-style signature object over the canonical form of ``payload``."""
    header: dict[str, Any] = {"alg": "EdDSA", "kid": b64url(key.kid)}
    if extra_header:
        header.update(extra_header)
    protected = b64url(canonical(header))
    signing_input = protected.encode("ascii") + b"." + b64url(canonical(payload)).encode("ascii")
    return {"protected": protected, "signature": b64url(key.sign(signing_input))}


def header(sig: dict[str, str]) -> dict[str, Any]:
    try:
        hdr = json.loads(b64url_decode(sig["protected"]))
    except (KeyError, ValueError) as exc:
        raise JwsError(f"bad protected header: {exc}") from exc
    if not isinstance(hdr, dict):
        raise JwsError("protected header must be a JSON object")
    return hdr


def verify(sig: dict[str, str], payload: dict[str, Any], public_key: bytes) -> bool:
    """True if ``sig`` is a valid EdDSA signature by ``public_key`` over ``payload``."""
    try:
        hdr = header(sig)
        if hdr.get("alg") != "EdDSA":
            return False
        if b64url_decode(hdr.get("kid", "")) != identity.kid(public_key):
            return False
        signing_input = sig["protected"].encode("ascii") + b"." + b64url(canonical(payload)).encode("ascii")
        return identity.verify(public_key, b64url_decode(sig["signature"]), signing_input)
    except (JwsError, KeyError, AttributeError):
        return False
