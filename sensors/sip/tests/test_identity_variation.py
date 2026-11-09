"""The advertised PBX version differs per install and stays stable for one install."""

from __future__ import annotations

import re

from sip_sensor.identity import VERSIONS, derive_profile


def _secret(i: int) -> str:
    return f"{i:04x}" * 16


def test_user_agent_is_stable_for_one_secret() -> None:
    assert derive_profile(_secret(3)).user_agent == derive_profile(_secret(3)).user_agent


def test_user_agent_varies_and_is_coherent() -> None:
    agents = [derive_profile(_secret(i)).user_agent for i in range(400)]
    assert len(set(agents)) > 20
    assert len(VERSIONS) >= 20
    fpbx = [a for a in agents if a.startswith("FPBX-")]
    plain = [a for a in agents if a.startswith("Asterisk PBX ")]
    assert fpbx and plain and len(fpbx) + len(plain) == len(agents)
    for a in plain:
        assert a.removeprefix("Asterisk PBX ") in VERSIONS
    for a in fpbx:
        m = re.fullmatch(r"FPBX-(15|16)\.0\.(\d+)\((\d+\.\d+\.\d+)\)", a)
        assert m and m.group(3) in VERSIONS
        # FreePBX 15 runs Asterisk 16, FreePBX 16 runs Asterisk 18.
        assert m.group(3).startswith("16." if m.group(1) == "15" else "18.")
