# Copyright 2024 Morse Micro
# SPDX-License-Identifier: Apache-2.0
set(BLOB_DIR ${ZEPHYR_MORSEMICRO_MODULE_DIR}/zephyr/blobs)

add_subdirectory_ifdef(CONFIG_SPI_STM32        drivers/spi)

add_subdirectory_ifdef(CONFIG_WIFI_MORSE_SM    components/morse_sm)
add_subdirectory_ifdef(CONFIG_WIFI_MORSE_SM    drivers/wifi/morse_sm)

add_subdirectory_ifdef(CONFIG_WIFI_MORSE_FS    components/morse_fs)
add_subdirectory_ifdef(CONFIG_WIFI_MORSE_FS    drivers/wifi/morse_fs)
