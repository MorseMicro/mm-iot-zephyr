# Copyright 2024 Morse Micro
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_CPU_CORTEX_M33)
  set(MORSE_CPU_ARCH     arm-cortex-m33f)
elseif(CONFIG_CPU_CORTEX_M7)
  set(MORSE_CPU_ARCH     arm-cortex-m7f)
elseif(CONFIG_CPU_CORTEX_M4)
  set(MORSE_CPU_ARCH     arm-cortex-m4f)
endif()

find_library(LIBMORSE_FOUND "morse" HINTS "${MMIOT_ROOT}/framework/morselib/lib/${MORSE_CPU_ARCH}/")

if(NOT LIBMORSE_FOUND)
  message(FATAL_ERROR
  "Morse Micro driver library not found.\n"
  "Run the command below to download the necessary files:\n"
  "> west blobs fetch morsemicro")
  return()
endif()


list(APPEND LIBMORSE_INCLUDES "${MMIOT_ROOT}/framework/morselib/include" "${CMAKE_CURRENT_SOURCE_DIR}/include")
add_library(libmorse STATIC IMPORTED GLOBAL)
set_target_properties(libmorse PROPERTIES IMPORTED_LOCATION             ${MMIOT_ROOT}/framework/morselib/lib/${MORSE_CPU_ARCH}/libmorse.a)
set_target_properties(libmorse PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${LIBMORSE_INCLUDES}")

target_compile_definitions(libmorse INTERFACE
  MMOSAL_NOASSERT
  MMOSAL_NO_DEBUGLOG
)
