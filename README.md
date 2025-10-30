Morse Micro IoT Zephyr Module (Alpha Port)
===================

# Overview

This alpha module includes drivers and sample applications to add Morse Micro HaLow Wi-Fi to LTS version 3.7 of the [Zephyr RTOS Project](https://www.zephyrproject.org/). The module is based on the 2.8.2 release of the [MM-IoT-SDK](https://www.github.com/MorseMicro/mm-iot-sdk)

## What is an Alpha Port
Morse Micro will provide Alpha ports of its software for some platforms. These ports are not part of the standard test and development cycle for a software release and may be incomplete in the set of supported features. They intend to provide a starting point for integrating Morse Micro software to projects based on these platforms.

# How to use this Zephyr Module

Create your workspace directory:
```
mkdir mm-iot-zephyr-workspace
cd mm-iot-zephyr-workspace
```

Create a virtual environment inside the Zephyr workspace
```
python3 -m venv .venv
```

Activate the virtual environment:
```
source .venv/bin/activate
```

Install west:
```
pip install west
```

Clone the Zephyr SDK:
```
west init -m https://github.com/MorseMicro/mm-iot-zephyr.git --mr main --mf west-zephyr.yaml ./
```

Install all of the python dependencies:
```
pip install -r zephyr/scripts/requirements.txt
```

Update west's modules:

```bash
west update
```

Fetch the required blobs:
```bash
west blobs fetch morsemicro
```

## Build and Run Porting Assistant Test Application

Build and execute `porting_assistant`

```
west build -p auto -b [board] [--shield morse_mmech08] modules/lib/morsemicro/samples/porting_assistant
west flash
```
If using a Morse Micro MMECH08 hat, add the shield parameter to the build command.
The porting assistant example application compilation will fail if a node with `compatible = "morse,spi"` is not found
in the compiled device tree.

## Build and Run HaLow Client Application

Build and execute `halow_client`

```
west build -p auto -b [board] [--shield morse_mmech08] modules/lib/morsemicro/samples/halow_client
west flash
```
This application will boot the MM6108 and enable device connectivity via the Zephyr command line.

To scan for a network, run
```
wifi scan
```
To connect to a network run
```
wifi connect -s "<ssid>" -p "<key>" -k 3
```
# Known Issues
## Throughput
Throughput measured on some boards is quite poor. For example, a `nucleo_u575zi_q` board may only see ~3.5 Mbps UDP upload.
## Device Power Management
Host device power management hooks are not implemented in the Morse Micro Wi-Fi driver for Zephyr.
## Incomplete Information in Status
The `band` information in the Zephyr Wi-Fi shell will show as `UNKNOWN` for Morse Micro HaLow interfaces.

## FAQ
## How do I improve performance?

The Morse Micro HaLow Wi-Fi embedded software stack carries out a mix of short and long transactions over SPI.
Unfortunately when paired with the SPI drivers for many platforms included in Zephyr, the overhead to prepare each transaction substantially reduces performance of the link.

Zephyr has recently released the RTIO subsystem which looks promising for improving this performance. Future development will focus on an RTIO compatible driver.

## Where do I go for support?
Feel free to join the Morse Micro developer community at https://community.morsemicro.com. While this is an Alpha port, we are happy to discuss issues and assist with further development.
