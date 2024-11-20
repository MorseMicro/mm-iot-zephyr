Morse Micro IoT Zephyr Module
===================

## Overview

This module includes drivers and sample applications to add Morse Micro HaLow
Wi-Fi to the [Zephyr RTOS Project](https://www.zephyrproject.org/).

## How to use this Zephyr Module

### Modify your project's west manifest

Add the Morse Micro repository and module to your west.yml:
```
manifest:
  remotes:
    # <your other remotes>
    - name: morsemicro
      url-base: https://github.com/MorseMicro

  projects:
    # <your other projects>
    - name: morsemicro
      path: modules/lib/morsemicro
      revision: main
      remote: mm-iot-zephyr
```

Update west's modules:

```bash
west update
```

## Build and Run Porting Assistant Test Application

Build and execute `porting_assistant`

```
cd [zephyrproject]
west build -p auto -b [board] modules/lib/morsemicro/zephyr/samples/porting_assistant
west build -t run
```
