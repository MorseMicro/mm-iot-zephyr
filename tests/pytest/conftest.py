# Copyright 2026 Morse Micro
# SPDX-License-Identifier: Apache-2.0

import os
import re
import time

import pytest

from twister_harness import DeviceAdapter, Shell


@pytest.fixture
def wifi_disconnect(shell: Shell):
    yield
    shell.exec_command("wifi disconnect")


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
def wifi_connected(dut: DeviceAdapter, shell: Shell, wifi_disconnect,
                   ap_ssid: str, ap_psk: str, ap_key_mgmt: str, ap_mfp: str) -> str:
    shell.exec_command(
        f"wifi connect -s {ap_ssid} -p {ap_psk} -k {ap_key_mgmt} -w {ap_mfp}"
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
