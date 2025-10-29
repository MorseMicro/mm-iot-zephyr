# Copyright 2024 Morse Micro
# SPDX-License-Identifier: Apache-2.0

zephyr_library_named(mmpktmem)
zephyr_library_sources(${CMAKE_CURRENT_SOURCE_DIR}/mmpktmem_static.c)
zephyr_library_compile_definitions(
  MMPKTMEM_TX_POOL_N_BLOCKS=CONFIG_MMPKTMEM_TX_POOL_N_BLOCKS
  MMPKTMEM_RX_POOL_N_BLOCKS=CONFIG_MMPKTMEM_RX_POOL_N_BLOCKS
)
zephyr_library_add_dependencies(libmorse mmutils)
zephyr_library_link_libraries(libmorse mmutils)