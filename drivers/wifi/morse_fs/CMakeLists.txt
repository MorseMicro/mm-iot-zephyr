# Copyright 2025 Morse Micro
# SPDX-License-Identifier: Apache-2.0

add_subdirectory(shims)

zephyr_library()
zephyr_library_sources(
	morse.c
)

zephyr_library_sources_ifdef(
	CONFIG_DT_HAS_MORSE_FS_ENABLED
	${CMAKE_CURRENT_SOURCE_DIR}/datalink_bus/spi.c
)

zephyr_library_include_directories(
	.
)

zephyr_library_link_libraries(
	subsys__net
	mmagic
	mmutils
	shims
)

# Optionally only build if CONFIG_WIFI_MORSE_FS is set
zephyr_library_compile_definitions_ifdef(CONFIG_WIFI_MORSE_FS MORSE_FS)