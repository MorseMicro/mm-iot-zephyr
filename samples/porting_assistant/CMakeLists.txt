# Copyright 2024 Morse Micro
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(porting_assistant)

FILE(GLOB app_sources src/*.c)
target_include_directories(app PRIVATE ${ZEPHYR_MORSEMICRO_MODULE_DIR}/drivers/wifi/morse/include)
target_sources(app PRIVATE ${app_sources})