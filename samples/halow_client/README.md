# HaLow Client

This sample provides an interactive shell for evaluating Morse Micro Wi-Fi HaLow.
It is largely a clone of Zephyr's [Wi-Fi shell sample](https://github.com/zephyrproject-rtos/zephyr/tree/main/samples/net/wifi/shell),
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

Zperf is not compiled in by default, to keep the sample lightweight. Enable it by building with the
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
shell> wifi scan
Scan requested
shell>
Num  | SSID                             (len) | Chan | RSSI | Sec
1    | my-halow-ap                      11    | 1    | -60  | WPA/WPA2
----------
Scan request done

shell> wifi connect -s "my-halow-ap" -p SecretStuff
Connection requested
shell>
Connected
```

With the `overlay-zperf.conf` overlay, throughput can also be tested, e.g.:

```
shell> zperf udp download
shell> zperf udp upload <ip> <port> <duration> <baud rate>
```
