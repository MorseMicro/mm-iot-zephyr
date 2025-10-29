# Copyright 2025 Morse Micro
# SPDX-License-Identifier: Apache-2.0

zephyr_library_named(shims)
zephyr_library_sources(
	${CMAKE_CURRENT_SOURCE_DIR}/mmhal.c
	${CMAKE_CURRENT_SOURCE_DIR}/mmosal_controller.c
)

zephyr_library_add_dependencies(
	subsys__net
)
zephyr_library_link_libraries(
	subsys__net
	kernel
)

zephyr_include_directories(.)
