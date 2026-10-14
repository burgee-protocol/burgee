"""rightofway/1 — who yields at a pinch point (spec section 8).

The default precedence table is fixed and every conformant node computes the same answer
from the same inputs, so two robots that have never met reach the same conclusion before
either sends a proposal.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..registries import NodeState, PriorityClass

PROFILE_ID = "rightofway/1"
ACTIONS = ("yield", "proceed", "wait_at", "pass_left", "pass_right")
MAX_HOLD_S = 30
CONFLICT_HORIZON_M = 10.0


class RightOfWayError(ValueError):
    """Raised for an invalid proposal under this profile."""


@dataclass(frozen=True)
class Party:
    """What one node knows about a participant from its beacon and verified card."""

    ephemeral_id: bytes
    priority_class: PriorityClass
    priority_verified: bool  # a registry countersignature backs classes 2 and 3
    state: NodeState
    footprint_w_m: float
    footprint_l_m: float
    human_escort: bool = False

    @property
    def effective_priority(self) -> int:
        p = int(self.priority_class)
        if p >= int(PriorityClass.emergency) and not self.priority_verified:
            return int(PriorityClass.standard)
        return p

    @property
    def moving(self) -> bool:
        return self.state == NodeState.transiting

    @property
    def footprint_area(self) -> float:
        return self.footprint_w_m * self.footprint_l_m


@dataclass(frozen=True)
class Precedence:
    winner: str  # "a" or "b": the party that has right of way
    rule: int  # which numbered rule of the default table decided it

    def yields(self) -> str:
        return "b" if self.winner == "a" else "a"


def precedence(a: Party, b: Party) -> Precedence:
    """Apply the default precedence table and say which party has right of way."""
    # 1. Verified authority over all; verified emergency over standard and service.
    pa, pb = a.effective_priority, b.effective_priority
    if pa != pb and max(pa, pb) >= int(PriorityClass.emergency):
        return Precedence("a" if pa > pb else "b", 1)
    # 2. A stationary node stays; the moving node yields.
    if a.moving != b.moving:
        return Precedence("b" if a.moving else "a", 2)
    # 3. A node carrying a human has right of way over one that is not.
    if a.human_escort != b.human_escort:
        return Precedence("a" if a.human_escort else "b", 3)
    # 4. Between two moving nodes, the larger footprint has right of way.
    if a.moving and b.moving and a.footprint_area != b.footprint_area:
        return Precedence("a" if a.footprint_area > b.footprint_area else "b", 4)
    # 5. Tie: the node with the lower ephemeral ID yields.
    return Precedence("a" if a.ephemeral_id > b.ephemeral_id else "b", 5)


def default_action(me: Party, other: Party) -> str:
    """The proposal a node makes when it has nothing better to say: ``yield`` when the table
    says it yields, ``proceed`` when it has right of way."""
    return "yield" if precedence(me, other).yields() == "a" else "proceed"


def validate_params(action: str, params: dict[str, Any]) -> dict[str, Any]:
    """Check and normalize proposal parameters; raise RightOfWayError on a bad proposal."""
    if action not in ACTIONS:
        raise RightOfWayError(f"unknown action {action!r}")
    out: dict[str, Any] = {}
    cp = params.get("conflict_point")
    if cp is not None:
        try:
            x, y = float(cp[0]), float(cp[1])
        except (TypeError, ValueError, IndexError) as exc:
            raise RightOfWayError("conflict_point must be [x, y] in metres") from exc
        out["conflict_point"] = [x, y]
    if "eta_s" in params:
        eta = float(params["eta_s"])
        if eta < 0:
            raise RightOfWayError("eta_s must be non-negative")
        out["eta_s"] = eta
    if action in ("pass_left", "pass_right"):
        out["side"] = "left" if action == "pass_left" else "right"
    elif "side" in params:
        side = str(params["side"])
        if side not in ("left", "right"):
            raise RightOfWayError("side must be left or right")
        out["side"] = side
    if action == "wait_at" or "hold_s" in params:
        hold = float(params.get("hold_s", MAX_HOLD_S))
        if not 0 < hold <= MAX_HOLD_S:
            raise RightOfWayError(f"hold_s must be in (0, {MAX_HOLD_S}]")
        out["hold_s"] = hold
    return out


def may_propose(action: str, me: Party, other: Party, reason_given: bool) -> bool:
    """A node may always propose to yield. It never proposes ``proceed`` against a higher
    precedence without a stated reason code."""
    if action != "proceed":
        return True
    if precedence(me, other).winner == "a":
        return True
    return reason_given
