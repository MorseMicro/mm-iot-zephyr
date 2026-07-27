# Copyright 2024-2026 Morse Micro
# SPDX-License-Identifier: Apache-2.0
set(MMIOT_ROOT ${ZEPHYR_CURRENT_MODULE_DIR}/submodules/mm-iot-sdk)
set(MMFW_ROOT ${ZEPHYR_CURRENT_MODULE_DIR}/submodules/morse-firmware)

add_subdirectory_ifdef(CONFIG_SPI_STM32        drivers/spi)

add_subdirectory_ifdef(CONFIG_WIFI_MORSE_SM    components/morse_sm)
add_subdirectory_ifdef(CONFIG_WIFI_MORSE_SM    drivers/wifi/morse_sm)
