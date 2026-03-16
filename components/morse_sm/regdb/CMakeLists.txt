# Copyright 2025 Morse Micro
# SPDX-License-Identifier: Apache-2.0

zephyr_library_named(regdb)
zephyr_library_sources(${MMIOT_ROOT}/framework/src/mmregdb/mmregdb.c)
zephyr_include_directories(${MMIOT_ROOT}/framework/src/mmregdb)

if(CONFIG_WIFI_MORSE_AU_CHANNELISATION_2020)
  zephyr_library_compile_definitions(MM_REGDB_DEFAULT_S1G_CHANNEL_LIST_AU=s1g_channel_list_au_80211_2020)
elseif(CONFIG_WIFI_MORSE_AU_CHANNELISATION_2024)
  zephyr_library_compile_definitions(MM_REGDB_DEFAULT_S1G_CHANNEL_LIST_AU=s1g_channel_list_au_80211_2024)
else()
  zephyr_library_compile_definitions(MM_REGDB_DEFAULT_S1G_CHANNEL_LIST_AU=s1g_channel_list_au_80211_revmf)
endif()

zephyr_library_add_dependencies(libmorse)
zephyr_library_link_libraries(libmorse)