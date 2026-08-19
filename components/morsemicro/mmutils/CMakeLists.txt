# Copyright 2024-2026 Morse Micro
# SPDX-License-Identifier: Apache-2.0

set(LIB_NAME mmutils)

set(SRC ${MMIOT_ROOT}/framework/src/mmutils/mmutils_wlan.c)
set(INC ${MMIOT_ROOT}/framework/src/mmutils)

add_library(${LIB_NAME} STATIC ${SRC})
target_include_directories(${LIB_NAME} PUBLIC ${INC})
target_compile_options(${LIB_NAME} PRIVATE ${COMPILE_OPTIONS})
target_link_libraries(${LIB_NAME} PRIVATE libmorse)
