"""Typed access to the Burgee code registries.

The source of truth is ``registries/registries.json`` in the ``spec``
repository. A copy is vendored at ``burgee/data/registries.json`` and the
enumerations below are built from it at import time, so a value added by BEP
appears here after the vendored file is refreshed (``tools/sync_registries.py``
in this repository). Nothing in the wire format is spelled out in code twice.
"""

from __future__ import annotations

import json
from enum import IntEnum, IntFlag
from importlib import resources

_DATA = json.loads(resources.files("burgee.data").joinpath("registries.json").read_text(encoding="utf-8"))

REGISTRIES_VERSION: str = _DATA["version"]


def _values(name: str) -> dict[str, int]:
    return {v["name"]: int(v["value"]) for v in _DATA[name]["values"]}


def _meanings(name: str) -> dict[int, str]:
    return {int(v["value"]): v["meaning"] for v in _DATA[name]["values"]}


BeaconType = IntEnum("BeaconType", _values("beacon_message_types"))
NodeClass = IntEnum("NodeClass", _values("node_classes"))
NodeState = IntEnum("NodeState", _values("node_states"))
PriorityClass = IntEnum("PriorityClass", _values("priority_classes"))
SafetyCommand = IntEnum("SafetyCommand", _values("safety_commands"))
ReasonCode = IntEnum("ReasonCode", _values("reason_codes"))
StatusValue = IntEnum("StatusValue", _values("status_values"))
MessageType = IntEnum("MessageType", _values("layer3_messages"))

# Bitfields: the registry stores bit indices; the flag value is 1 << index.
Capability = IntFlag("Capability", {k: 1 << v for k, v in _values("capability_bits").items()})
ProfileBit = IntFlag("ProfileBit", {k: 1 << v for k, v in _values("profiles").items()})

MEANING: dict[str, dict[int, str]] = {
    "beacon_message_types": _meanings("beacon_message_types"),
    "node_classes": _meanings("node_classes"),
    "node_states": _meanings("node_states"),
    "priority_classes": _meanings("priority_classes"),
    "safety_commands": _meanings("safety_commands"),
    "reason_codes": _meanings("reason_codes"),
    "status_values": _meanings("status_values"),
    "layer3_messages": _meanings("layer3_messages"),
}

PROFILE_VERSIONS: dict[str, list[int]] = {v["name"]: list(v["versions"]) for v in _DATA["profiles"]["values"]}


def profile_ids() -> list[str]:
    """Every profile identifier defined in this version, as ``name/version``."""
    return [f"{name}/{ver}" for name, vers in PROFILE_VERSIONS.items() for ver in vers]


def profile_bits(ids: list[str]) -> int:
    """The beacon byte-19 bitfield for a list of ``name/version`` profile ids."""
    bits = 0
    for pid in ids:
        name = pid.split("/", 1)[0]
        bits |= int(ProfileBit[name])
    return bits


__all__ = [
    "REGISTRIES_VERSION",
    "BeaconType",
    "NodeClass",
    "NodeState",
    "PriorityClass",
    "SafetyCommand",
    "ReasonCode",
    "StatusValue",
    "MessageType",
    "Capability",
    "ProfileBit",
    "MEANING",
    "PROFILE_VERSIONS",
    "profile_ids",
    "profile_bits",
]
