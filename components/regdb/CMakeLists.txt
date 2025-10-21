# Copyright 2025 Morse Micro
# SPDX-License-Identifier: Apache-2.0

zephyr_library_named(regdb)
zephyr_library_sources(${CMAKE_CURRENT_SOURCE_DIR}/regdb.c)
zephyr_include_directories(.)
zephyr_library_add_dependencies(libmorse)
zephyr_library_link_libraries(libmorse)