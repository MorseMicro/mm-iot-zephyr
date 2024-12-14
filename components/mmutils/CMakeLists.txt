# Copyright 2024 Morse Micro
# SPDX-License-Identifier: Apache-2.0

zephyr_library_named(mmutils)
zephyr_library_sources(${CMAKE_CURRENT_SOURCE_DIR}/mmutils_wlan.c)
zephyr_library_add_dependencies(libmorse)
zephyr_library_link_libraries(libmorse)