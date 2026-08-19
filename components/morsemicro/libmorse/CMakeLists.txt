# Copyright 2024-2026 Morse Micro
# SPDX-License-Identifier: Apache-2.0

set(LIB_NAME libmorse)
set(SRCS
    ${MMIOT_ROOT}/framework/morselib/mmrc/src/core/mmrc.c
    ${MMIOT_ROOT}/framework/morselib/src/common/common.c
    ${MMIOT_ROOT}/framework/morselib/src/common/consbuf.c
    ${MMIOT_ROOT}/framework/morselib/src/common/mac_address.c
    ${MMIOT_ROOT}/framework/morselib/src/common/mmpkt.c
    ${MMIOT_ROOT}/framework/morselib/src/common/mmpkt_list.c
    ${MMIOT_ROOT}/framework/morselib/src/dot11/dot11_utils.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/ap/umac_ap.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/ate/umac_ate.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/ba/umac_ba.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/connection/umac_connection.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/config/umac_config.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/core/umac_core.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/core/umac_evtloop.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/core/umac_evtq.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/core/umac_timeout.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/data/umac_data.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/data/umac_sta_data.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/datapath/datapath_defrag.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/datapath/umac_datapath.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/datapath/umac_datapath_ap.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/datapath/umac_datapath_sta.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/frames/action.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/frames/s1g_action.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/frames/association.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/frames/authentication.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/frames/deauthentication.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/frames/disassociation.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/frames/frame_constructor.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/frames/probe_request.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/frames/probe_response.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/frames/utils.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/health_check/umac_health_check.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/ies/aid_request.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/ies/reachable_address.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/ies/twt_ie.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/ies/s1g_capabilities.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/ies/s1g_operation.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/ies/s1g_tim.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/ies/ies_common.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/ies/wmm.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/ies/morse_ie.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/interface/umac_interface.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/keys/connection_keys.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/keys/umac_keys.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/ps/umac_ps.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/rc/mmrc_osal/mmrc_osal.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/rc/umac_rc.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/regdb/umac_regdb.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/scan/umac_scan.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/scan/hw_scan.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/stats/umac_stats.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/supplicant_shim/bip.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/supplicant_shim/ccmp.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/supplicant_shim/config.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/supplicant_shim/driver.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/supplicant_shim/driver_ap.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/supplicant_shim/eloop.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/supplicant_shim/morse_dpp_event.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/supplicant_shim/random.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/supplicant_shim/supplicant_core.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/supplicant_shim/supplicant_core_ap.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/twt/umac_twt.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/umac.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/umac_mmdrv_shim.c
    ${MMIOT_ROOT}/framework/morselib/src/umac/wnm_sleep/umac_wnm_sleep.c
    ${MMIOT_ROOT}/framework/morselib/src/driver/morse_driver/mm6108/mm6108.c
    ${MMIOT_ROOT}/framework/morselib/src/driver/morse_driver/mm6108/pager_if_hw.c
    ${MMIOT_ROOT}/framework/morselib/src/driver/morse_driver/mm6108/pager_if.c
    ${MMIOT_ROOT}/framework/morselib/src/driver/morse_driver/mm6108/pageset.c
    ${MMIOT_ROOT}/framework/morselib/src/driver/morse_driver/mm8108/mm8108.c
    ${MMIOT_ROOT}/framework/morselib/src/driver/morse_driver/mm8108/yaps-hw.c
    ${MMIOT_ROOT}/framework/morselib/src/driver/morse_driver/mm8108/yaps.c
    ${MMIOT_ROOT}/framework/morselib/src/driver/beacon/beacon.c
    ${MMIOT_ROOT}/framework/morselib/src/driver/driver.c
    ${MMIOT_ROOT}/framework/morselib/src/driver/driver_task.c
    ${MMIOT_ROOT}/framework/morselib/src/driver/puff/puff.c
    ${MMIOT_ROOT}/framework/morselib/src/driver/morse_crc/morse_crc.c
    ${MMIOT_ROOT}/framework/morselib/src/driver/morse_driver/command.c
    ${MMIOT_ROOT}/framework/morselib/src/driver/morse_driver/coredump.c
    ${MMIOT_ROOT}/framework/morselib/src/driver/morse_driver/event.c
    ${MMIOT_ROOT}/framework/morselib/src/driver/morse_driver/ext_host_table.c
    ${MMIOT_ROOT}/framework/morselib/src/driver/morse_driver/firmware.c
    ${MMIOT_ROOT}/framework/morselib/src/driver/morse_driver/firmware_mbin.c
    ${MMIOT_ROOT}/framework/morselib/src/driver/morse_driver/hw.c
    ${MMIOT_ROOT}/framework/morselib/src/driver/morse_driver/ps.c
    ${MMIOT_ROOT}/framework/morselib/src/driver/morse_driver/skbq.c
    ${MMIOT_ROOT}/framework/morselib/src/driver/transport/sdio.c
    ${MMIOT_ROOT}/framework/morselib/src/driver/transport/sdio_spi.c
    ${MMIOT_ROOT}/framework/morselib/src/emmet/emmet_stubs.c
)

if (CONFIG_WIFI_MORSEMICRO_AP_MODE)
  list(APPEND SRCS ${MMIOT_ROOT}/framework/morselib/src/umac/supplicant_shim/driver_ap.c
       ${MMIOT_ROOT}/framework/morselib/src/umac/supplicant_shim/supplicant_core_ap.c
  )
else ()
  list(APPEND BUILD_DEFINES MMWLAN_AP_DISABLED=1)
endif ()

set(INC
    ${MMIOT_ROOT}/framework/morselib/src/
    ${MMIOT_ROOT}/framework/morselib/src/internal
    ${MMIOT_ROOT}/framework/morselib/src/emmet
    ${MMIOT_ROOT}/framework/morselib/src/umac/rc/mmrc_osal
    ${MMIOT_ROOT}/framework/morselib/mmrc/src/core
)

add_library(${LIB_NAME} STATIC ${SRCS})
target_include_directories(${LIB_NAME} PRIVATE ${INC})

target_compile_definitions(${LIB_NAME} PUBLIC ${BUILD_DEFINES})

if (CONFIG_PICOLIBC)
  target_compile_options(${LIB_NAME} PRIVATE -include ${CMAKE_CURRENT_SOURCE_DIR}/ffs_compat.h)
endif ()

target_compile_options(${LIB_NAME} PRIVATE -w)

add_dependencies(${LIB_NAME} mmutils mmpktmem mmhostap)
target_link_libraries(${LIB_NAME} PUBLIC libmorse_interface)
target_link_libraries(${LIB_NAME} PRIVATE mmutils mmhostap mmpktmem zephyr_interface)
