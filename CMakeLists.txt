# Copyright 2024 Morse Micro
# SPDX-License-Identifier: Apache-2.0
set(BLOB_DIR ${ZEPHYR_MORSEMICRO_MODULE_DIR}/zephyr/blobs)
add_subdirectory_ifdef(CONFIG_WIFI_MORSE    components)
add_subdirectory_ifdef(CONFIG_WIFI_MORSE    drivers)