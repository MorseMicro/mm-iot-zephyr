# Copyright 2024-2025 Morse Micro
# SPDX-License-Identifier: Apache-2.0

add_library(libmorse STATIC IMPORTED GLOBAL)
set_target_properties(libmorse PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/include)

zephyr_include_directories(./include)
zephyr_library_compile_definitions(libmorse INTERFACE
	MMOSAL_NOASSERT
	MMOSAL_NO_DEBUGLOG
)
