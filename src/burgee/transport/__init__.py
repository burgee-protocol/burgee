"""Transports: something that carries frames between two Encounters.

``loopback`` is in-memory and deterministic; ``ble`` is BlueZ via bleak and bluez-peripheral
and is an optional extra (``pip install burgee[ble]``).
"""

from .loopback import LoopbackLink

__all__ = ["LoopbackLink"]
