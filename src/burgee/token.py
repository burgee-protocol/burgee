"""The v0.1 authority token (spec section 9).

A COSE_Sign1 over a CBOR map ``{iss, zone, cmds, nbf, exp}`` signed by a root key that
the receiving node already trusts: a registry's published key, or a site operator's root
key provisioned into its marks and the nodes that work there. The SAFETY beacon carries
the first 9 bytes of the token's SHA-256 as a hint; the full token travels in SAFETY_STOP.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass

import cbor2

from . import cose, identity
from .beacon import TOKEN_HINT_LEN
from .registries import SafetyCommand

MAX_VALIDITY_S = 24 * 3600


class TokenError(ValueError):
    """Raised for a malformed, expired or untrusted token."""


def command_bits(commands: list[SafetyCommand]) -> int:
    bits = 0
    for c in commands:
        bits |= 1 << int(c)
    return bits


@dataclass(frozen=True)
class AuthorityToken:
    iss: bytes  # kid of the issuing root key
    zone: int
    cmds: int  # bitfield over SafetyCommand values
    nbf: int  # epoch seconds
    exp: int  # epoch seconds

    def __post_init__(self) -> None:
        if len(self.iss) != identity.KID_LEN:
            raise TokenError("iss must be an 8-byte kid")
        if not 0 <= self.zone <= 255:
            raise TokenError("zone must fit in a byte")
        if self.exp <= self.nbf:
            raise TokenError("exp must be after nbf")
        if self.exp - self.nbf > MAX_VALIDITY_S:
            raise TokenError("a token is valid for at most 24 hours")

    def allows(self, command: SafetyCommand) -> bool:
        return bool(self.cmds & (1 << int(command)))

    def is_current(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return self.nbf <= now <= self.exp

    def payload(self) -> bytes:
        return cbor2.dumps(
            {"iss": self.iss, "zone": self.zone, "cmds": self.cmds, "nbf": self.nbf, "exp": self.exp},
            canonical=True,
        )

    @classmethod
    def from_payload(cls, data: bytes) -> AuthorityToken:
        try:
            d = cbor2.loads(data)
            return cls(iss=d["iss"], zone=int(d["zone"]), cmds=int(d["cmds"]), nbf=int(d["nbf"]), exp=int(d["exp"]))
        except (KeyError, TypeError, ValueError, cbor2.CBORDecodeError) as exc:
            raise TokenError(f"bad token payload: {exc}") from exc


def issue(root: identity.NodeKey, *, zone: int, commands: list[SafetyCommand], nbf: int, exp: int) -> bytes:
    """Sign a token with a root key. Returns the COSE_Sign1 bytes that travel in SAFETY_STOP."""
    tok = AuthorityToken(iss=root.kid, zone=zone, cmds=command_bits(commands), nbf=nbf, exp=exp)
    return cose.sign(root, tok.payload())


def hint(token_bytes: bytes) -> bytes:
    """The 9-byte SHA-256 prefix the SAFETY beacon carries."""
    return hashlib.sha256(token_bytes).digest()[:TOKEN_HINT_LEN]


def verify(token_bytes: bytes, trusted_roots: dict[bytes, bytes], *, now: float | None = None) -> AuthorityToken:
    """Verify a token against ``trusted_roots`` (kid -> public key). Raises TokenError when the
    issuer is unknown, the signature fails, or the token is outside its validity window."""
    try:
        parsed = cose.parse(token_bytes)
    except cose.CoseError as exc:
        raise TokenError(f"token is not COSE_Sign1: {exc}") from exc
    pub = trusted_roots.get(parsed.kid)
    if pub is None:
        raise TokenError("unknown issuer")
    try:
        payload = cose.verify(token_bytes, pub)
    except cose.CoseError as exc:
        raise TokenError(f"token signature: {exc}") from exc
    tok = AuthorityToken.from_payload(payload)
    if tok.iss != parsed.kid:
        raise TokenError("iss does not match the signing key")
    if not tok.is_current(now):
        raise TokenError("token is outside its validity window")
    return tok
