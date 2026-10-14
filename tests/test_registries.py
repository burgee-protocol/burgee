import json
from pathlib import Path

import pytest

from burgee import registries as R


def test_registry_enums_are_populated():
    assert R.REGISTRIES_VERSION
    assert R.NodeClass.sidewalk_delivery == 1 and R.NodeClass.other == 255
    assert R.ReasonCode.no_profile == 2 and R.ReasonCode.other == 255
    assert int(R.Capability.can_yield) == 1 and int(R.Capability.is_mark) == 1 << 12
    assert int(R.ProfileBit.rightofway) == 1 and int(R.ProfileBit.safety) == 1 << 4
    assert R.profile_ids() == ["rightofway/1", "access/1"]
    assert R.profile_bits(["rightofway/1", "access/1"]) == 0b11
    assert R.MEANING["safety_commands"][2].startswith("Stop immediately")
    assert R.StatusValue.continuing_slow == 5


def test_vendored_registries_match_spec_repo_when_present():
    spec = Path(__file__).resolve().parents[2] / "spec" / "registries" / "registries.json"
    if not spec.exists():
        pytest.skip("spec repository not checked out next to this one")
    vendored = Path(__file__).resolve().parents[1] / "src" / "burgee" / "data" / "registries.json"
    assert json.loads(spec.read_text()) == json.loads(vendored.read_text())
