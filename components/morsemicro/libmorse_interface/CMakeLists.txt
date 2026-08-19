# Copyright 2026 Morse Micro
# SPDX-License-Identifier: Apache-2.0

set(LIB_NAME libmorse_interface)

add_library(${LIB_NAME} INTERFACE)

set(LIBMORSE_INCLUDES ${MMIOT_ROOT}/framework/morselib/include ${CMAKE_CURRENT_SOURCE_DIR}/include)

set(DEFS LOOKAROUND_FAIL_MAX=50 MMOSAL_ASSERT\(...\) MMOSAL_ASSERT_LOG_DATA\(...\) MMOSAL_NOASSERT
         MMOSAL_NO_DEBUGLOG
)

target_include_directories(${LIB_NAME} INTERFACE ${LIBMORSE_INCLUDES})
target_compile_definitions(${LIB_NAME} INTERFACE ${DEFS})
