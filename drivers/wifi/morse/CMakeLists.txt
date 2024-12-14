# Copyright 2024 Morse Micro
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_WIFI_MORSE)

  list(APPEND REGIONS "AU" "EU" "IN" "JP" "KR" "NZ" "SG" "US")
  if(NOT CONFIG_WIFI_MORSE_REGION IN_LIST REGIONS)
    message(FATAL_ERROR
    "Invalid region specified for regulatory domain\n"
    "CONFIG_WIFI_MORSE_REGION must be one of:\n"
    "AU, EU, IN, JP, KR, NZ, SG, US")
    return()
  endif()

  zephyr_library_include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
  )

  zephyr_library_sources(
    ${CMAKE_CURRENT_SOURCE_DIR}/shims/mmhal_wlan_binaries.c
    ${CMAKE_CURRENT_SOURCE_DIR}/shims/wlan_hal.c
    ${CMAKE_CURRENT_SOURCE_DIR}/shims/mmosal_shim_zephyr.c
    ${CMAKE_CURRENT_SOURCE_DIR}/shims/mmhal.c
    ${CMAKE_CURRENT_SOURCE_DIR}/morse.c
  )

  zephyr_library_add_dependencies(
    subsys__net
    libmorse
    firmware
    mmutils
    mmpktmem
  )

  zephyr_library_link_libraries(
    subsys__net
    libmorse
    firmware
    mmutils
    mmpktmem
  )

endif()