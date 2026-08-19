# Copyright 2024-2026 Morse Micro
# SPDX-License-Identifier: Apache-2.0

zephyr_library_include_directories(${CMAKE_CURRENT_SOURCE_DIR})

if (CONFIG_WIFI_MORSEMICRO_UNPATCHED_WORKAROUNDS)
  zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR})
endif ()

zephyr_library_sources(
  ${CMAKE_CURRENT_SOURCE_DIR}/shims/mmhal_core.c
  ${CMAKE_CURRENT_SOURCE_DIR}/shims/mmhal_os.c
  ${CMAKE_CURRENT_SOURCE_DIR}/shims/mmhal_wlan.c
  ${CMAKE_CURRENT_SOURCE_DIR}/shims/mmhal_wlan_binaries.c
  ${CMAKE_CURRENT_SOURCE_DIR}/shims/mmosal.c
  ${CMAKE_CURRENT_SOURCE_DIR}/common.c
  ${CMAKE_CURRENT_SOURCE_DIR}/morsemicro_spi.c
  ${CMAKE_CURRENT_SOURCE_DIR}/net_mgmt.c
  ${CMAKE_CURRENT_SOURCE_DIR}/wifi_mgmt.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mm6108.c
  ${CMAKE_CURRENT_SOURCE_DIR}/mm8108.c
)

zephyr_library_sources_ifdef(
  CONFIG_WIFI_MORSEMICRO_SHELL ${CMAKE_CURRENT_SOURCE_DIR}/morsemicro_shell.c
)

function (dt_count_compats output_var compatible)
  dt_comp_path(nodes COMPATIBLE "${compatible}")

  set(count 0)

  foreach (node IN LISTS nodes)
    dt_node_has_status(node_is_okay PATH "${node}" STATUS "okay")

    if (node_is_okay)
      math(EXPR count "${count} + 1")
    endif ()
  endforeach ()

  set(${output_var}
      "${count}"
      PARENT_SCOPE
  )
endfunction ()

dt_count_compats(MM6108 "morsemicro,mm6108")
dt_count_compats(MM8108 "morsemicro,mm8108")

if (MM6108 GREATER 1)
  message(FATAL_ERROR "morsemicro,mm6108: only one status-okay instance is supported; "
                      "found ${MM6108}"
  )
endif ()

if (MM8108 GREATER 1)
  message(FATAL_ERROR "morsemicro,mm8108: only one status-okay instance is supported; "
                      "found ${MM8108}"
  )
endif ()

if (MM6108 GREATER 0 AND MM8108 GREATER 0)
  message(
    FATAL_ERROR "morsemicro,mm6108 and morsemicro,mm8108 cannot both have status-okay instances"
  )
endif ()

zephyr_library_add_dependencies(subsys__net libmorse firmware mmutils mmpktmem regdb)

zephyr_library_link_libraries(subsys__net libmorse firmware mmutils mmpktmem regdb)
