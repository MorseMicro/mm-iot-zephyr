# Copyright 2026 Morse Micro
# SPDX-License-Identifier: Apache-2.0

import re
import time

import pytest

from twister_harness import DeviceAdapter, Shell

# No region is compiled in (tests/prj.conf); each test gets a fresh
# `kernel reboot cold` (conftest.py), so from_region is always set explicitly.
# AU/JP share spectrum, so that pair also covers a direct real-to-real switch.
_REGION_TRANSITIONS = [
    ("00", "AU"),
    ("AU", "JP"),
    ("JP", "AU"),
    ("AU", "00"),
]


def _get_region(shell: Shell, iface: int) -> str:
    out = shell.exec_command(f"wifi reg_domain -i {iface}")
    m = re.search(r"Wi-Fi Regulatory domain is:\s*(\S+)", "\n".join(out))
    assert m, f"could not parse `wifi reg_domain` output: {out!r}"
    return m.group(1)


def _set_region(shell: Shell, iface: int, region: str, timeout: float = 15.0) -> list[str]:
    return shell.exec_command(f"wifi reg_domain -i {iface} {region}", timeout=timeout)


@pytest.mark.parametrize("from_region,to_region", _REGION_TRANSITIONS)
def test_reg_domain_switch(dut: DeviceAdapter, shell: Shell, wifi_iface: int,
                           from_region: str, to_region: str,
                           dut_supported_regions: tuple[str, ...] | None):

    if dut_supported_regions is not None and "JP" not in dut_supported_regions \
            and "JP" in (from_region, to_region):
        pytest.skip(f"JP is not supported by this DUT's module (BCF regions: "
                    f"{', '.join(dut_supported_regions)})")

    if from_region != "00":
        _set_region(shell, wifi_iface, from_region)
    assert _get_region(shell, wifi_iface) == from_region

    lines = _set_region(shell, wifi_iface, to_region)
    assert any(f"Wi-Fi Regulatory domain set to: {to_region}" in l for l in lines), \
        f"switching {from_region} -> {to_region} did not report success: {lines!r}"
    assert not any("failed" in l.lower() for l in lines), \
        f"unexpected failure switching {from_region} -> {to_region}: {lines!r}"
    assert _get_region(shell, wifi_iface) == to_region

    # scan can fail synchronously (no readlines_until() to wait for then) or async
    scan_lines = shell.exec_command(f"wifi scan -i {wifi_iface}")
    if not any("Scan request failed" in l for l in scan_lines):
        scan_lines += dut.readlines_until(
            regex=r"Scan request done|Scan request failed", timeout=15.0
        )
    result_rows = [l for l in scan_lines if re.match(r"^\d+\s*\|", l)]

    if to_region == "00":
        assert any("Scan request failed" in l for l in scan_lines), \
            f"scan against region 00 should fail outright: {scan_lines!r}"
        assert not result_rows, \
            f"scan against region 00 produced result rows: {scan_lines!r}"
        return

    assert not any("Scan request failed" in l for l in scan_lines), \
        f"scan failed after switching to {to_region}: {scan_lines!r}"


def test_reg_domain_switch_during_scan(dut: DeviceAdapter, shell: Shell, wifi_iface: int):
    _set_region(shell, wifi_iface, "AU")

    shell.exec_command(f"wifi scan -i {wifi_iface}")
    lines = _set_region(shell, wifi_iface, "00")
    assert not any("scan_callback failed" in l for l in lines), \
        f"stale scan result processed during region switch: {lines!r}"

    # let any late scan result surface before checking again
    time.sleep(2.0)
    extra = dut.readlines_until()
    assert not any("scan_callback failed" in l for l in extra), \
        f"stale scan result processed after region switch: {extra!r}"
