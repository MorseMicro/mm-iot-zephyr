# Copyright 2025 Morse Micro
# SPDX-License-Identifier: Apache-2.0

zephyr_library_named(mmutils)
zephyr_library_sources(${CMAKE_CURRENT_SOURCE_DIR}/mmbuf.c)
zephyr_include_directories(.)