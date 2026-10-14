"""Burgee — reference implementation of the Open Robot Proximity Protocol.

Every robot flies a burgee. See https://github.com/burgee-protocol/spec for the specification
this package implements, and ``burgee --help`` for the command line.
"""

from . import beacon, card, cose, encounter, identity, jws, messages, registries, token
from .card import AgentCard, BurgeeExtension, Operator, RegistryKey, build_card
from .encounter import Encounter, Handler, Level1Handler, Node, Role, State
from .identity import NodeKey

__version__ = "0.1.0a1"

__all__ = [
    "__version__",
    "beacon",
    "card",
    "cose",
    "encounter",
    "identity",
    "jws",
    "messages",
    "registries",
    "token",
    "AgentCard",
    "BurgeeExtension",
    "Operator",
    "RegistryKey",
    "build_card",
    "Encounter",
    "Handler",
    "Level1Handler",
    "Node",
    "Role",
    "State",
    "NodeKey",
]
