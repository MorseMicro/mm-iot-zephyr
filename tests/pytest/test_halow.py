# Copyright 2026 Morse Micro
# SPDX-License-Identifier: Apache-2.0

import os
import re
import subprocess
import time

import pytest

from twister_harness import DeviceAdapter, Shell


_ZPERF_PORT = 5001
_ZPERF_DURATION_S = 5

_DNS_RESULT_RE = re.compile(r"^dns:\s+(\d|[0-9a-f]+:)", re.IGNORECASE)

# no region is compiled in, so set one before the chip does anything
pytestmark = pytest.mark.usefixtures("wifi_region_au")


def test_iface_present(shell: Shell):
    out = shell.exec_command("net iface")
    assert any("interface wlan" in line.lower() for line in out), "no wifi interface found"


def test_get_version(shell: Shell):
    out = shell.exec_command("wifi version")
    drv_re = re.compile(r"Wi-Fi Driver Version:\s*(\S+)")
    fw_re = re.compile(r"Wi-Fi Firmware Version:\s*(\S+)")
    drv = next((m.group(1) for l in out if (m := drv_re.search(l))), None)
    fw = next((m.group(1) for l in out if (m := fw_re.search(l))), None)
    assert drv, f"no driver version reported: {out!r}"
    assert fw, f"no firmware version reported: {out!r}"


def test_connect_rejects_unsupported_security(dut: DeviceAdapter, shell: Shell):
    shell.exec_command("wifi connect -s unsupported-security-test -p 12345678 -k 1")
    lines = dut.readlines_until(regex=r"Connection request failed", timeout=10.0)
    assert any("Connection request failed" in line for line in lines), \
        f"expected a WPA2-PSK connect attempt to be rejected: {lines!r}"


def test_scan(dut: DeviceAdapter, shell: Shell):
    shell.exec_command("wifi scan")
    lines = dut.readlines_until(
        regex=r"Scan request done|Scan request failed", timeout=30.0
    )
    failures = [l for l in lines if "Scan request failed" in l]
    assert not failures, f"scan reported failure: {failures[0]!r}"
    assert any("Scan request done" in line for line in lines), "scan did not complete"

    ap_ssid = os.environ.get("HALOW_TEST_SSID")
    if ap_ssid:
        assert any(ap_ssid in line for line in lines), \
            f"AP '{ap_ssid}' not found in scan results"


def test_connect(dut: DeviceAdapter, shell: Shell, wifi_disconnect,
                 ap_ssid: str, ap_psk: str):
    shell.exec_command(f"wifi connect -s {ap_ssid} -p {ap_psk} -k 3 -w 2")
    lines = dut.readlines_until(regex=r"Connected|Connection request failed", timeout=30.0)
    assert any("Connected" in line for line in lines), "wifi did not connect"


def test_iface_status_fields(shell: Shell, wifi_connected: str, ap_ssid: str, ap_psk: str):
    out = shell.exec_command("wifi status")
    assert any(f"SSID: {ap_ssid}" in line for line in out), \
        f"unexpected SSID in status: {out!r}"

    expected_security = "WPA3-SAE-HNP" if ap_psk else "OPEN"
    assert any(line.strip().startswith("Security:") and expected_security in line
               for line in out), f"unexpected security in status: {out!r}"

    assert any(line.strip().startswith("MFP:") for line in out), \
        f"no MFP line in status: {out!r}"
    assert any(line.strip().startswith("RSSI:") for line in out), \
        f"no RSSI line in status: {out!r}"

    bssid_re = re.compile(r"BSSID:\s*([0-9a-f:]{17})", re.IGNORECASE)
    bssid = next((m.group(1) for l in out if (m := bssid_re.search(l))), None)
    assert bssid and bssid != "00:00:00:00:00:00", \
        f"no valid BSSID in status: {out!r}"


def _wait_for_disconnect(shell: Shell, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        out = shell.exec_command("wifi status")
        if any("State: INACTIVE" in line for line in out):
            return
        time.sleep(1.0)
    pytest.fail(f"wifi status did not report INACTIVE within {timeout}s of disconnect")


def test_disconnect_event(shell: Shell, wifi_connected: str):
    shell.exec_command("wifi disconnect")
    _wait_for_disconnect(shell)

