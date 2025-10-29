# Copyright 2025 Morse Micro
# SPDX-License-Identifier: Apache-2.0

zephyr_library_named(mmagic)
zephyr_library_sources(
	${CMAKE_CURRENT_SOURCE_DIR}/mmagic_controller.c
)

zephyr_library_add_dependencies(
	subsys__net
)
zephyr_library_link_libraries(
	subsys__net
	kernel
)

zephyr_include_directories(.)