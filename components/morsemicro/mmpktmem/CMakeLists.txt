# Copyright 2024-2026 Morse Micro
# SPDX-License-Identifier: Apache-2.0

set(LIB_NAME mmpktmem)

set(SRC ${MMIOT_ROOT}/framework/src/mmpktmem/mmpktmem_static.c)

add_library(mmpktmem STATIC ${SRC})
target_compile_definitions(
  ${LIB_NAME} PRIVATE MMPKTMEM_TX_POOL_N_BLOCKS=CONFIG_MMPKTMEM_TX_POOL_N_BLOCKS
                      MMPKTMEM_RX_POOL_N_BLOCKS=CONFIG_MMPKTMEM_RX_POOL_N_BLOCKS
)
target_compile_options(${LIB_NAME} PRIVATE ${COMPILE_OPTIONS})

target_link_libraries(${LIB_NAME} PRIVATE libmorse mmutils)
