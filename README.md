Morse Micro IoT Zephyr Module (Alpha Port)
===================

# Overview

This alpha module includes drivers and sample applications to add Morse Micro HaLow Wi-Fi to LTS version 3.7 of the [Zephyr RTOS Project](https://www.zephyrproject.org/). The module is based on the 2.9.7 release of the [MM-IoT-SDK](https://www.github.com/MorseMicro/mm-iot-sdk)

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

Update west's modules:

```bash
west update
```

Install all of the python dependencies:
```
pip install -r zephyr/scripts/requirements.txt
```

Fetch the required blobs:
```bash
west blobs fetch morsemicro
```

### SDK

Download the appropriate SDK toolchain.
If your host architecture is 64-bit ARM (for example, M-series MacBooks), download the `macOS-aarch64` SDK.

|       |                                                                x86_64                                                                |                                                                 aarch64                                                                |
|-------|:------------------------------------------------------------------------------------------------------------------------------------:|:--------------------------------------------------------------------------------------------------------------------------------------:|
| Linux | [linux-x86_64](https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v0.16.9/zephyr-sdk-0.16.9_linux-x86_64_minimal.tar.xz) | [linux-aarch64](https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v0.16.9/zephyr-sdk-0.16.9_linux-aarch64_minimal.tar.xz) |
| macOS | [macOS-x86_64](https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v0.16.9/zephyr-sdk-0.16.9_macos-x86_64_minimal.tar.xz) | [macOS-aarch64](https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v0.16.9/zephyr-sdk-0.16.9_macos-aarch64_minimal.tar.xz) |

Install the toolchain:
```
tar xvf <YOUR SDK>.tar.xz -C $HOME/.local
cd $HOME/.local/<YOUR SDK>
./setup.sh
```

## Board Support

This repository supports multiple Morse Micro development boards and shields.

### Development Boards
We currently support the following Morse Micro development boards:

- `mm6108_ekh05_v3`
- `mm8108_ekh05`
- `m2m_u575`

### Shields
We also support the following Morse Micro shields:

- `morse_mmech08`
- `morse_mmech18`

The `m2m_u575` is a prototype **FS board** designed for Wi-Fi network stack offloading.
It uses the `morse_fs` driver, which is currently implemented only for **SPI**.
This board comprises of an STM32 Nucleo U575ZI-Q connected via SPI to an EKH08_U575
as defined by the `mmagic` applications in the MM-IoT-SDK.

The other supported shields use the `morse_sm` **SoftMAC** driver.

## Driver Architecture

The drivers and their components are organized in separate trees:

- `morse_sm`: SoftMAC driver
- `morse_fs`: FS driver (3-chip mockup)

This separation allows independent development and integration of SoftMAC and FS features.

## Build and Run Porting Assistant Test Application

Build and execute `porting_assistant`

```
west build -p auto -b [board] [--shield morse_mmech08] modules/lib/morsemicro/samples/porting_assistant
west flash
```
If using a Morse Micro MMECH08 hat, add the shield parameter to the build command.
The porting assistant example application compilation will fail if a node with `compatible = "morse,mm6108"` is not found
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
wifi connect -s "<ssid>" -p "<key>" -k 3 -w 2
```

## Twister
We also support a set of tests which can be run using Twister (note the `-W` flag)
```
west twister -T modules/lib/morsemicro/samples --build-only -W
```
If you have hardware and an appropriate hardware_map available, you can also run
```
west twister -T modules/lib/morsemicro/samples --device-testing -W --hardware-map hardware_map.yaml
```

# Known Issues
## Throughput
Throughput measured on some boards is quite poor. For example, a `nucleo_u575zi_q` board may only see ~3.5 Mbps UDP upload.
## Device Power Management
Host device power management hooks are not implemented in the Morse Micro Wi-Fi driver for Zephyr.
## Incomplete Information in Status
The `band` information in the Zephyr Wi-Fi shell will show as `UNKNOWN` for Morse Micro HaLow interfaces.
## Build Warnings
The twister tests require the `-W` flag to be passed in as there are warnings in our builds.

## FAQ
## How do I improve performance?

The Morse Micro HaLow Wi-Fi embedded software stack carries out a mix of short and long transactions over SPI.
Unfortunately when paired with the SPI drivers for many platforms included in Zephyr, the overhead to prepare each transaction substantially reduces performance of the link.

Zephyr has recently released the RTIO subsystem which looks promising for improving this performance. Future development will focus on an RTIO compatible driver.

## Where do I go for support?
Feel free to join the Morse Micro developer community at https://community.morsemicro.com. While this is an Alpha port, we are happy to discuss issues and assist with further development.
