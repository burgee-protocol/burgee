"""access/1 — a mobile node asks a mark for passage or service (spec section 8).

The mark checks the requester's card against its policy in a fixed order: registry
countersignature, operator allowlist, priority class, time window, concurrent-use limit.
It answers ACCEPT with ``granted_s`` or DECLINE with ``policy``. A mark never acts on an
unverified card; verification happens before this module is reached.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ..card import AgentCard
from ..registries import PriorityClass, ReasonCode

PROFILE_ID = "access/1"
ACTIONS = ("request_passage", "request_hold", "request_service")
SERVICES = ("passage", "hold", "charge", "lift", "locker")
MAX_DURATION_S = 120


class AccessError(ValueError):
    """Raised for an invalid proposal under this profile."""


@dataclass(frozen=True)
class Granted:
    granted_s: int
    service: str

    def params(self) -> dict[str, Any]:
        return {"granted_s": self.granted_s, "service": self.service}


@dataclass(frozen=True)
class Refused:
    reason: ReasonCode
    note: str


@dataclass
class MarkPolicy:
    require_countersignature: bool = True
    allowed_operators: set[str] | None = None  # registry IDs or names; None = any
    min_priority: PriorityClass = PriorityClass.standard
    window_utc: tuple[int, int] | None = None  # (start_hour, end_hour), end exclusive; wraps midnight
    max_concurrent: int = 1
    services: set[str] = field(default_factory=lambda: {"passage", "hold"})
    max_duration_s: int = MAX_DURATION_S

    def in_window(self, now: float) -> bool:
        if self.window_utc is None:
            return True
        start, end = self.window_utc
        hour = datetime.fromtimestamp(now, tz=UTC).hour
        return start <= hour < end if start <= end else (hour >= start or hour < end)


def validate_params(action: str, params: dict[str, Any]) -> dict[str, Any]:
    if action not in ACTIONS:
        raise AccessError(f"unknown action {action!r}")
    service = str(params.get("service", {"request_passage": "passage", "request_hold": "hold"}.get(action, "")))
    if service not in SERVICES:
        raise AccessError(f"service must be one of {SERVICES}")
    out: dict[str, Any] = {"service": service}
    dur = int(params.get("duration_s", 10))
    if not 0 < dur <= MAX_DURATION_S:
        raise AccessError(f"duration_s must be in (0, {MAX_DURATION_S}]")
    out["duration_s"] = dur
    if service == "lift":
        if "floor" not in params:
            raise AccessError("a lift request needs a floor")
        out["floor"] = int(params["floor"])
    if "payload_class" in params:
        out["payload_class"] = str(params["payload_class"])
    return out


def decide(
    policy: MarkPolicy,
    card: AgentCard,
    *,
    certified: bool,
    now: float,
    active: int,
    action: str,
    params: dict[str, Any],
) -> Granted | Refused:
    """The mark's decision, in the spec's order. ``certified`` is the receiver's own
    recomputation of the card's countersignatures; ``active`` is the number of grants in
    progress right now."""
    try:
        p = validate_params(action, params)
    except AccessError as exc:
        return Refused(ReasonCode.no_profile, str(exc))
    if p["service"] not in policy.services:
        return Refused(ReasonCode.no_profile, f"service {p['service']} not offered")
    if policy.require_countersignature and not certified:
        return Refused(ReasonCode.policy, "countersignature required")
    op = card.burgee.operator
    if policy.allowed_operators is not None and not ({op.registry_id, op.name} & policy.allowed_operators):
        return Refused(ReasonCode.policy, "operator not allowed")
    if effective_priority(card, certified) < int(policy.min_priority):
        return Refused(ReasonCode.priority_lower, "priority class too low")
    if not policy.in_window(now):
        return Refused(ReasonCode.policy, "outside service window")
    if active >= policy.max_concurrent:
        return Refused(ReasonCode.busy, "concurrent-use limit reached")
    return Granted(granted_s=min(p["duration_s"], policy.max_duration_s), service=p["service"])


def effective_priority(card: AgentCard, certified: bool) -> int:
    """Spec section 7: priority classes 2 and 3 count only with a registry countersignature;
    without one they are treated as 0."""
    p = int(card.burgee.priority_class)
    if p >= int(PriorityClass.emergency) and not certified:
        return int(PriorityClass.standard)
    return p
