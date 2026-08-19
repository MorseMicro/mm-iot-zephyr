# Copyright 2024-2026 Morse Micro
# SPDX-License-Identifier: Apache-2.0

get_property(
  COMPILE_OPTIONS
  TARGET zephyr_interface
  PROPERTY INTERFACE_COMPILE_OPTIONS
)

add_subdirectory(mbedtls)
add_subdirectory(hostap)
add_subdirectory(firmware)
add_subdirectory(libmorse)
add_subdirectory(mmutils)
add_subdirectory(mmpktmem)
add_subdirectory(regdb)
