# Copyright 2024 Morse Micro
# SPDX-License-Identifier: Apache-2.0

zephyr_library_named(mmutils)
zephyr_library_sources(${MMIOT_ROOT}/framework/src/mmutils/mmutils_wlan.c)
zephyr_include_directories(${MMIOT_ROOT}/framework/src/mmutils)
zephyr_library_add_dependencies(libmorse)
zephyr_library_link_libraries(libmorse)