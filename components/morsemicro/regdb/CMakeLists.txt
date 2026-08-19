# Copyright 2025-2026 Morse Micro
# SPDX-License-Identifier: Apache-2.0

set(LIB_NAME regdb)

set(SRC ${MMIOT_ROOT}/framework/src/mmregdb/mmregdb.c)

set(INC ${MMIOT_ROOT}/framework/src/mmregdb)

add_library(${LIB_NAME} STATIC ${SRC})
target_include_directories(${LIB_NAME} PUBLIC ${INC})

if (CONFIG_WIFI_MORSEMICRO_AU_CHANNELISATION_2020)
  target_compile_definitions(
    ${LIB_NAME} PRIVATE MM_REGDB_DEFAULT_S1G_CHANNEL_LIST_AU=s1g_channel_list_au_80211_2020
  )
elseif (CONFIG_WIFI_MORSEMICRO_AU_CHANNELISATION_2024)
  target_compile_definitions(
    ${LIB_NAME} PRIVATE MM_REGDB_DEFAULT_S1G_CHANNEL_LIST_AU=s1g_channel_list_au_80211_2024
  )
else ()
  target_compile_definitions(
    ${LIB_NAME} PRIVATE MM_REGDB_DEFAULT_S1G_CHANNEL_LIST_AU=s1g_channel_list_au_80211_revmf
  )
endif ()

target_compile_options(${LIB_NAME} PRIVATE ${COMPILE_OPTIONS})

add_dependencies(${LIB_NAME} libmorse)
target_link_libraries(${LIB_NAME} PRIVATE libmorse)
