# Copyright 2026 Morse Micro
# SPDX-License-Identifier: Apache-2.0

import os
import re
import time
import warnings

import pytest

from twister_harness import DeviceAdapter, Shell


@pytest.fixture
def dut_supported_regions(dut: DeviceAdapter) -> tuple[str, ...] | None:
    reg_inc = dut.device_config.app_build_dir / "modules/morsemicro/components/morsemicro/firmware/morsemicro_bcf_regions.raw"
    if not reg_inc.is_file():
        return None
    packed = reg_inc.read_text().strip()
    regions = tuple(packed[i: i + 2] for i in range(0, len(packed), 2))

    if regions is None:
        warnings.warn(f"missing supported regions @ '{reg_inc}'")
    return regions


@pytest.fixture(autouse=True)
def reboot_before_test(dut: DeviceAdapter, shell: Shell) -> None:
    # dut/shell are session-scoped (pytest_dut_scope in testcase.yaml); reboot
    # instead of re-flashing to give each test a clean boot.
    dut.clear_buffer()
    dut.write(b"kernel reboot cold\n")
    if not shell.wait_for_prompt():
        pytest.fail("Prompt not found after reboot")
    time.sleep(0.5)  # more boot log can land after the first prompt
    dut.clear_buffer()


_IFACE_HEADER_RE = re.compile(r"^Interface\s+\S+\s+\(\S+\)\s+\(.*\)\s+\[(\d+)\]")
_DEVICE_RE = re.compile(r"^Device\s*:\s*(\S+)")


@pytest.fixture
def wifi_iface(shell: Shell) -> int:
    # Down interfaces don't display anything useful without explicitly targetting them
    indices = [int(m.group(1)) for line in shell.exec_command("net iface")
               if (m := _IFACE_HEADER_RE.match(line.strip()))]

    for idx in indices:
        out = shell.exec_command(f"net iface {idx}")
        device = next((m.group(1) for l in out if (m := _DEVICE_RE.match(l.strip()))), None)
        if device and "morse" in device.lower():
            return idx

    pytest.fail(f"no morse wifi interface found among `net iface` indices {indices}")


@pytest.fixture
def wifi_disconnect(shell: Shell, wifi_iface: int):
    yield
    shell.exec_command(f"wifi disconnect -i {wifi_iface}")


@pytest.fixture
def wifi_region_au(shell: Shell, wifi_iface: int) -> None:
    # no region is compiled in; test_reg_domain.py manages regions itself
    shell.exec_command(f"wifi reg_domain -i {wifi_iface} AU")


def _wait_for_dhcpv4(shell: Shell, timeout: float = 30.0) -> str:
    deadline = time.time() + timeout
    ip_re = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")
    while time.time() < deadline:
        out = shell.exec_command("net iface")
        for line in out:
            if "IPv4" not in line and "address" not in line.lower():
                continue
            m = ip_re.search(line)
            if m and m.group(1) != "0.0.0.0":
                return m.group(1)
        time.sleep(1.0)
    raise TimeoutError("no DHCPv4 lease within timeout")


@pytest.fixture
def wifi_connected(dut: DeviceAdapter, shell: Shell, wifi_disconnect, wifi_iface: int,
                   ap_ssid: str, ap_psk: str, ap_key_mgmt: str, ap_mfp: str) -> str:
    shell.exec_command(
        f"wifi connect -i {wifi_iface} -s {ap_ssid} -p {ap_psk} -k {ap_key_mgmt} -w {ap_mfp}"
    )
    lines = dut.readlines_until(regex=r"Connected|Connection request failed", timeout=30.0)
    if not any("Connected" in line for line in lines):
        pytest.fail("wifi did not connect")
    return _wait_for_dhcpv4(shell)


@pytest.fixture
def gateway_ip(shell: Shell, wifi_connected: str) -> str:
    out = shell.exec_command("net iface")
    gw_re = re.compile(r"IPv4 gateway\s*:\s*(\d+\.\d+\.\d+\.\d+)")
    for line in out:
        m = gw_re.search(line)
        if m and m.group(1) != "0.0.0.0":
            return m.group(1)
    pytest.fail("could not determine IPv4 gateway from `net iface`")


@pytest.fixture(scope="session")
def dns_query_name() -> str:
    return os.environ.get("HALOW_TEST_DNS_NAME") or "morsemicro.com"


@pytest.fixture(scope="session")
def ap_ssid() -> str:
    ssid = os.environ.get("HALOW_TEST_SSID")
    if not ssid:
        pytest.skip("HALOW_TEST_SSID not set")
    return ssid


@pytest.fixture(scope="session")
def ap_psk() -> str:
    psk = os.environ.get("HALOW_TEST_PSK")
    if not psk:
        pytest.skip("HALOW_TEST_PSK not set")
    return psk


@pytest.fixture(scope="session")
def ap_key_mgmt(ap_psk: str) -> str:
    # The morse drivers only accept WIFI_SECURITY_TYPE_SAE (3) or _NONE (0)
    # (see drivers/wifi/morse_sm/morse.c). HaLow is always SAE when secured,
    # so the value can be derived from whether a PSK is provided.
    return "3" if ap_psk else "0"


@pytest.fixture(scope="session")
def ap_mfp(ap_psk: str) -> str:
    # SAE (the only secured mode the morse driver supports) requires MFP
    # (802.11w). Open networks don't use it.
    return "2" if ap_psk else "0"
