"""The Card: an A2A v1.0 Agent Card carrying the Burgee robotics extension.

Spec section 7. The card is signed by the node's own Ed25519 key (JWS over the JCS form of
the card without ``signatures``). Its digest is the SHA-256 of the JCS form of the card
without ``signatures`` and without the extension's ``countersignatures`` and ``certified``
fields, so a registry can countersign a digest that does not change when it does.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import time
import zlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import cbor2

from . import identity, jws
from .registries import NodeClass, PriorityClass, profile_bits, profile_ids

A2A_PROTOCOL_VERSION = "1.0"
BURGEE_BINDING = "burgee-ble"
BURGEE_BINDING_VERSION = "1"
EXTENSION_URI = "https://burgeeprotocol.org/a2a/ext/burgee/1"
MAX_WIRE_BYTES = 1024
MAX_INFLATED_BYTES = 16 * 1024
COUNTERSIGNATURE_MAX_S = 365 * 86400


class CardError(ValueError):
    """Raised for a malformed, oversized or unverifiable card."""


@dataclass
class Operator:
    name: str
    contact: str  # tel:, mailto: or https: URI
    registry_id: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "registryId": self.registry_id, "contact": self.contact}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Operator:
        return cls(name=str(d["name"]), contact=str(d["contact"]), registry_id=str(d.get("registryId", "")))


@dataclass
class BurgeeExtension:
    """The ``burgee`` object: everything the beacon cannot say."""

    node_class: NodeClass
    public_key: bytes
    operator: Operator
    footprint_w_m: float
    footprint_l_m: float
    footprint_h_m: float
    max_speed_mps: float
    capabilities: int
    profiles: list[str]
    conformance_level: int
    region: str
    priority_class: PriorityClass = PriorityClass.standard
    countersignatures: list[dict[str, str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.public_key) != 32:
            raise CardError("identity.publicKey must be a 32-byte Ed25519 key")
        unknown = [p for p in self.profiles if p not in profile_ids()]
        if unknown:
            raise CardError(f"unknown profile ids {unknown}")
        if not 0 <= self.conformance_level <= 3:
            raise CardError("conformanceLevel must be 0..3")
        if not 1 <= len(self.region) <= 6:
            raise CardError("region must be an ISO 3166-2 code")

    @property
    def stable_id(self) -> bytes:
        return identity.stable_id(self.public_key)

    def to_dict(self, *, certified: bool = False) -> dict[str, Any]:
        return {
            "nodeClass": int(self.node_class),
            "identity": {"publicKey": base64.b64encode(self.public_key).decode("ascii")},
            "operator": self.operator.to_dict(),
            "footprint": {
                "width": round(self.footprint_w_m, 2),
                "length": round(self.footprint_l_m, 2),
                "height": round(self.footprint_h_m, 2),
            },
            "maxSpeed": round(self.max_speed_mps, 2),
            "priorityClass": int(self.priority_class),
            "capabilities": self.capabilities & 0xFFFF,
            "profiles": list(self.profiles),
            "conformanceLevel": self.conformance_level,
            "certified": certified,
            "region": self.region,
            "countersignatures": [dict(c) for c in self.countersignatures],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> BurgeeExtension:
        try:
            fp = d["footprint"]
            return cls(
                node_class=NodeClass(int(d["nodeClass"])),
                public_key=base64.b64decode(d["identity"]["publicKey"]),
                operator=Operator.from_dict(d["operator"]),
                footprint_w_m=float(fp["width"]),
                footprint_l_m=float(fp["length"]),
                footprint_h_m=float(fp["height"]),
                max_speed_mps=float(d["maxSpeed"]),
                capabilities=int(d["capabilities"]),
                profiles=[str(p) for p in d["profiles"]],
                conformance_level=int(d["conformanceLevel"]),
                region=str(d["region"]),
                priority_class=PriorityClass(int(d.get("priorityClass", 0))),
                countersignatures=[
                    {"protected": str(c["protected"]), "signature": str(c["signature"])}
                    for c in d.get("countersignatures", [])
                ],
            )
        except (KeyError, TypeError, ValueError, AttributeError, binascii.Error) as exc:
            raise CardError(f"bad burgee extension: {exc}") from exc


@dataclass
class AgentCard:
    """An A2A v1.0 Agent Card with the Burgee extension in ``capabilities.extensions``."""

    name: str
    description: str
    version: str
    burgee: BurgeeExtension
    skills: list[dict[str, Any]] = field(default_factory=list)
    extra_interfaces: list[dict[str, str]] = field(default_factory=list)
    signatures: list[dict[str, str]] = field(default_factory=list)

    # ---- serialization ---------------------------------------------------------------

    def interface_url(self) -> str:
        return f"{BURGEE_BINDING}://{self.burgee.stable_id.hex()}"

    def to_dict(
        self, *, trusted_registry_keys: dict[bytes, bytes] | None = None, now: float | None = None
    ) -> dict[str, Any]:
        """The A2A JSON form. ``certified`` is recomputed from the countersignatures against
        ``trusted_registry_keys`` (kid -> public key); it is never taken from stored data."""
        certified = self.is_certified(trusted_registry_keys or {}, now=now)
        skills = self.skills or default_skills(self.burgee.profiles)
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "protocolVersion": A2A_PROTOCOL_VERSION,
            "supportedInterfaces": [
                {
                    "url": self.interface_url(),
                    "protocolBinding": BURGEE_BINDING,
                    "protocolVersion": BURGEE_BINDING_VERSION,
                },
                *self.extra_interfaces,
            ],
            "capabilities": {
                "streaming": False,
                "pushNotifications": False,
                "extensions": [
                    {
                        "uri": EXTENSION_URI,
                        "required": True,
                        "description": "Burgee robot proximity profile",
                        "params": self.burgee.to_dict(certified=certified),
                    }
                ],
            },
            "defaultInputModes": ["application/cbor"],
            "defaultOutputModes": ["application/cbor"],
            "skills": skills,
            "signatures": [dict(s) for s in self.signatures],
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> AgentCard:
        try:
            if not isinstance(d, Mapping):
                raise CardError("card must be a map")
            exts = d["capabilities"]["extensions"]
            if not isinstance(exts, (list, tuple)):
                raise CardError("capabilities.extensions must be a list")
            params = next(e["params"] for e in exts if isinstance(e, Mapping) and e.get("uri") == EXTENSION_URI)
            if not isinstance(params, Mapping):
                raise CardError("burgee extension params must be a map")
            interfaces = d.get("supportedInterfaces", [])
            if not isinstance(interfaces, (list, tuple)) or not all(isinstance(i, Mapping) for i in interfaces):
                raise CardError("supportedInterfaces must be a list of maps")
            if not any(i.get("protocolBinding") == BURGEE_BINDING for i in interfaces):
                raise CardError("card does not list the burgee-ble interface")
            extra = [dict(i) for i in interfaces if i.get("protocolBinding") != BURGEE_BINDING]
            signatures = d.get("signatures", [])
            if not isinstance(signatures, (list, tuple)) or not all(
                isinstance(s, Mapping) and isinstance(s.get("protected"), str) and isinstance(s.get("signature"), str)
                for s in signatures
            ):
                raise CardError("signatures must be a list of {protected, signature} maps")
            skills = d.get("skills", [])
            if not isinstance(skills, (list, tuple)) or not all(isinstance(s, Mapping) for s in skills):
                raise CardError("skills must be a list of maps")
            return cls(
                name=str(d["name"]),
                description=str(d.get("description", "")),
                version=str(d["version"]),
                burgee=BurgeeExtension.from_dict(params),
                skills=[dict(s) for s in skills],
                extra_interfaces=extra,
                signatures=[{"protected": s["protected"], "signature": s["signature"]} for s in signatures],
            )
        except (KeyError, TypeError, ValueError, AttributeError, StopIteration) as exc:
            raise CardError(f"bad card: {exc}") from exc

    # ---- digest, signing, verification -------------------------------------------------

    def _digest_form(self) -> dict[str, Any]:
        d = self.to_dict()
        d.pop("signatures", None)
        params = d["capabilities"]["extensions"][0]["params"]
        params.pop("countersignatures", None)
        params.pop("certified", None)
        return d

    def digest(self) -> bytes:
        """SHA-256 over the canonical card without signatures, countersignatures and certified."""
        return hashlib.sha256(jws.canonical(self._digest_form())).digest()

    def _signing_form(self, trusted_registry_keys: dict[bytes, bytes] | None = None) -> dict[str, Any]:
        d = self.to_dict(trusted_registry_keys=trusted_registry_keys)
        d.pop("signatures", None)
        # ``certified`` is derived, so it is excluded from what the node signs.
        d["capabilities"]["extensions"][0]["params"].pop("certified", None)
        return d

    def sign(self, key: identity.NodeKey) -> AgentCard:
        """Sign with the node's key. Replaces any earlier self-signature."""
        if key.public_key != self.burgee.public_key:
            raise CardError("the signing key must be the key named in identity.publicKey")
        self.signatures = [jws.sign(key, self._signing_form())]
        return self

    def verify(self) -> bool:
        """True when the card carries a valid signature by the key it names."""
        pub = self.burgee.public_key
        return any(jws.verify(s, self._signing_form(), pub) for s in self.signatures)

    def is_certified(self, trusted_registry_keys: dict[bytes, bytes], *, now: float | None = None) -> bool:
        """True when a trusted registry has countersigned this card's digest at or above its
        declared conformance level and the countersignature has not expired."""
        if not trusted_registry_keys:
            return False
        now = time.time() if now is None else now
        digest_b64 = jws.b64url(self.digest())
        for c in self.burgee.countersignatures:
            try:
                hdr = jws.header(c)
                kid_bytes = jws.b64url_decode(hdr.get("kid", ""))
                payload = {
                    "digest": digest_b64,
                    "level": int(hdr.get("level", -1)),
                    "exp": int(hdr.get("exp", 0)),
                }
            except (jws.JwsError, ValueError, TypeError):
                continue
            pub = trusted_registry_keys.get(kid_bytes)
            if pub is None or payload["level"] < self.burgee.conformance_level or payload["exp"] < now:
                continue
            if jws.verify(c, payload, pub):
                return True
        return False

    # ---- wire form -------------------------------------------------------------------

    def to_wire(self, *, strict: bool = True) -> bytes:
        """deflate(CBOR(card)). Over 1,024 bytes is non-conformant; ``strict`` enforces it."""
        raw = zlib.compress(cbor2.dumps(self.to_dict(), canonical=True), 9)
        if strict and len(raw) > MAX_WIRE_BYTES:
            raise CardError(f"card is {len(raw)} bytes on the wire; the limit is {MAX_WIRE_BYTES}")
        return raw

    @classmethod
    def from_wire(cls, data: bytes) -> AgentCard:
        """Parse a wire-form card. The receive limit is the same 1,024 bytes as the send limit,
        and decompression is capped at ``MAX_INFLATED_BYTES`` so a compressed bomb is refused."""
        if not isinstance(data, bytes):
            raise CardError("card wire form must be bytes")
        if len(data) > MAX_WIRE_BYTES:
            raise CardError(f"card is {len(data)} bytes on the wire; the limit is {MAX_WIRE_BYTES}")
        try:
            inflater = zlib.decompressobj()
            raw = inflater.decompress(data, MAX_INFLATED_BYTES)
            if inflater.unconsumed_tail:
                raise CardError(f"card inflates past {MAX_INFLATED_BYTES} bytes")
            d = cbor2.loads(raw)
        except (zlib.error, cbor2.CBORDecodeError) as exc:
            raise CardError(f"bad card wire form: {exc}") from exc
        if not isinstance(d, Mapping):
            raise CardError("card wire form must decode to a map")
        return cls.from_dict(d)


def default_skills(profiles: list[str]) -> list[dict[str, Any]]:
    """One A2A skill per profile action a node supports."""
    actions = {
        "rightofway/1": ["yield", "proceed", "wait_at", "pass_left", "pass_right"],
        "access/1": ["request_passage", "request_hold", "request_service"],
    }
    out = []
    for pid in profiles:
        for a in actions.get(pid, []):
            out.append(
                {
                    "id": f"{pid}:{a}",
                    "name": f"{pid} {a}",
                    "description": f"Burgee {pid} proposal type {a}",
                    "tags": ["burgee", pid.split("/", 1)[0]],
                }
            )
    return out


@dataclass
class RegistryKey:
    """A registry's signing key, used to countersign cards. The registry's public key is
    distributed to nodes out of band (provisioned, or fetched from the registry's well-known
    URL) and kept in a trust store keyed by kid."""

    key: identity.NodeKey

    @property
    def kid(self) -> bytes:
        return self.key.kid

    @property
    def public_key(self) -> bytes:
        return self.key.public_key

    def countersign(self, card: AgentCard, level: int, *, expires_at: float) -> dict[str, str]:
        """Produce a countersignature over ``card``'s digest at ``level``. The caller appends it
        to ``card.burgee.countersignatures`` and the node re-signs the card."""
        if not 0 <= level <= 3:
            raise CardError("level must be 0..3")
        if expires_at - time.time() > COUNTERSIGNATURE_MAX_S:
            raise CardError("countersignatures are valid for at most one year")
        payload = {"digest": jws.b64url(card.digest()), "level": level, "exp": int(expires_at)}
        return jws.sign(self.key, payload, extra_header={"level": level, "exp": int(expires_at)})


def build_card(
    *,
    key: identity.NodeKey,
    name: str,
    description: str,
    version: str,
    node_class: NodeClass,
    operator: Operator,
    footprint_m: tuple[float, float, float],
    max_speed_mps: float,
    capabilities: int,
    profiles: list[str],
    conformance_level: int,
    region: str,
    priority_class: PriorityClass = PriorityClass.standard,
) -> AgentCard:
    """Build and sign a card in one call."""
    ext = BurgeeExtension(
        node_class=node_class,
        public_key=key.public_key,
        operator=operator,
        footprint_w_m=footprint_m[0],
        footprint_l_m=footprint_m[1],
        footprint_h_m=footprint_m[2],
        max_speed_mps=max_speed_mps,
        capabilities=capabilities,
        profiles=profiles,
        conformance_level=conformance_level,
        region=region,
        priority_class=priority_class,
    )
    return AgentCard(name=name, description=description, version=version, burgee=ext).sign(key)


def beacon_profile_bits(card: AgentCard) -> int:
    """Byte 19 of the IDENTITY beacon for this card's profiles."""
    return profile_bits(card.burgee.profiles)


def clone(card: AgentCard) -> AgentCard:
    return copy.deepcopy(card)
