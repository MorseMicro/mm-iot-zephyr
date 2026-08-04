# Copyright 2026 Morse Micro
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(ap_channel_regdb)

set(MORSEMICRO_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)
set(MORSEMICRO_DRV_DIR ${MORSEMICRO_ROOT}/drivers/wifi/morsemicro)
set(MMIOT_ROOT ${MORSEMICRO_ROOT}/submodules/mm-iot-sdk)

target_compile_definitions(app PRIVATE
  CONFIG_WIFI_MORSEMICRO_AP_MODE=1
  CONFIG_WIFI_LOG_LEVEL=0
)

target_include_directories(app PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/stubs
  ${MORSEMICRO_DRV_DIR}
  ${MMIOT_ROOT}/framework/morselib/include
  ${MMIOT_ROOT}/framework/src/mmutils
  ${MMIOT_ROOT}/framework/src/mmregdb
)

target_sources(app PRIVATE
  src/main.c
  ${MMIOT_ROOT}/framework/src/mmregdb/mmregdb.c
)
