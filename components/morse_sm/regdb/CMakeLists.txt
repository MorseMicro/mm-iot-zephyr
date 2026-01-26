# Copyright 2025 Morse Micro
# SPDX-License-Identifier: Apache-2.0

zephyr_library_named(regdb)
zephyr_library_sources(${MMIOT_ROOT}/framework/src/mmregdb/mmregdb.c)
zephyr_include_directories(${MMIOT_ROOT}/framework/src/mmregdb)
zephyr_library_add_dependencies(libmorse)
zephyr_library_link_libraries(libmorse)