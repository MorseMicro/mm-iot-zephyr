# Copyright 2024-2026 Morse Micro
# SPDX-License-Identifier: Apache-2.0

if(CONFIG_WIFI_MORSE_SM)

  list(APPEND REGIONS "AU" "EU" "IN" "JP" "KR" "NZ" "SG" "US")

  if(CONFIG_DT_HAS_MORSEMICRO_MM8108_ENABLED)
    list(APPEND REGIONS "GB")
  endif()

  if(NOT CONFIG_WIFI_MORSE_REGION IN_LIST REGIONS)
    message(FATAL_ERROR
    "Invalid region specified for regulatory domain\n"
    "CONFIG_WIFI_MORSE_REGION must be one of:\n"
    "AU, EU, GB (MM8108 ONLY), IN, JP, KR, NZ, SG, US")
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
    ${CMAKE_CURRENT_SOURCE_DIR}/morsemicro_spi.c
    ${CMAKE_CURRENT_SOURCE_DIR}/net_mgmt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/wifi_mgmt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mm6108.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mm8108.c
  )

function(dt_count_compats output_var compatible)
    dt_comp_path(nodes COMPATIBLE "${compatible}")

    set(count 0)

    foreach(node IN LISTS nodes)
        dt_node_has_status(
            node_is_okay
            PATH "${node}"
            STATUS "okay"
        )

        if(node_is_okay)
            math(EXPR count "${count} + 1")
        endif()
    endforeach()

    set(${output_var} "${count}" PARENT_SCOPE)
endfunction()

  dt_count_compats(MM6108 "morsemicro,mm6108")
  dt_count_compats(MM8108 "morsemicro,mm8108")

  if(MM6108 GREATER 1)
      message(FATAL_ERROR
          "morsemicro,mm6108: only one status-okay instance is supported; "
          "found ${MM6108}"
      )
  endif()

  if(MM8108 GREATER 1)
      message(FATAL_ERROR
          "morsemicro,mm8108: only one status-okay instance is supported; "
          "found ${MM8108}"
      )
  endif()

  if(MM6108 GREATER 0 AND MM8108 GREATER 0)
      message(FATAL_ERROR
          "morsemicro,mm6108 and morsemicro,mm8108 cannot both have status-okay instances"
      )
  endif()

  zephyr_library_add_dependencies(
    subsys__net
    libmorse
    firmware
    mmutils
    mmpktmem
    regdb
  )

  zephyr_library_link_libraries(
    subsys__net
    libmorse
    firmware
    mmutils
    mmpktmem
    regdb
  )

endif()
