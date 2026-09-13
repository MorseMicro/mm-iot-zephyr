# HaLow Client

This sample provides an interactive shell for evaluating Morse Micro Wi-Fi HaLow.
It is a copy of Zephyr's [Wi-Fi shell sample](https://github.com/zephyrproject-rtos/zephyr/tree/main/samples/net/wifi/shell),
shipped here so users can exercise the Morse Micro driver and test HaLow from a single directory.

It exposes:
* The `wifi` shell module, for scan/connect/disconnect and other basic networking operations
* The `net` shell module, for inspecting `net_if` and other network stack state
* Optionally, the `zperf` shell module, for throughput/performance testing

## Kconfig

### Regulatory domain

The Morse Micro driver requires a country code to be set before Wi-Fi can be used. Set it via:

```
CONFIG_WIFI_MORSEMICRO_REGION="US"
```

This can also be set at runtime with:

```
wifi reg_domain US
```

### Zperf

Zperf is not compiled in by default, to keep the sample lighter weight by default. Enable it by building with the
`overlay-zperf.conf` overlay:

```
west build -b <board> . -- -DEXTRA_CONF_FILE=overlay-zperf.conf
```

The overlay also sizes the networking buffer pools (`NET_PKT_RX_COUNT`, `NET_PKT_TX_COUNT`,
`NET_BUF_RX_COUNT`, `NET_BUF_TX_COUNT`, `NET_BUF_DATA_SIZE`) up from `prj.conf`'s defaults, since
throughput testing needs more in-flight packets/buffers than basic shell use does.

*These values are selected to work on the MM8108 EKH05 platform. Adjust accordingly if using a
different SOC.*

## Building and Running

```
west build -b <board> . # This assumes you are already in the samples/halow_client directory
west flash
```

To also build in zperf, add `-- -DEXTRA_CONF_FILE=overlay-zperf.conf` to the `west build` command
above.

## Sample console interaction

```
uart:~$ wifi scan
Scan requested
Num  | SSID                             (len) | Chan (Band)   | RSSI | Security             | BSSID             | MFP
1    | my-halow-ssid                    13    | 37   (UNKNOWN) | -21  | WPA3-SAE-HNP         | 94:BB:43:DC:F9:84 | Required
Scan request done

uart:~$ wifi connect -s "my-halow-ssid" -p "my-halow-psk" -k 3 -w 2
Connection requested
Connected
```

With the `overlay-zperf.conf` overlay, throughput can also be tested, e.g.:

```
uart:~$ zperf udp download
uart:~$ zperf udp upload <ip> <port> <duration> <rate>
```
