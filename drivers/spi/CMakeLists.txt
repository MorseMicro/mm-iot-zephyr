# Copyright 2025 Morse Micro
# SPDX-License-Identifier: Apache-2.0

# Based on the pattern seen here: https://github.com/Atmosic/openair/blob/5d3fda75ab412d686b55c9b44675e8741b5eae12/drivers/spi/CMakeLists.txt
# and here https://github.com/spacecubics/scsat1-fsw/blob/c637159c188f7c3f47fefac6ae6f965791070b5d/drivers/spi/CMakeLists.txt

if(CONFIG_SPI)
  zephyr_library_amend()
  zephyr_library_include_directories(${ZEPHYR_BASE}/drivers/spi)
  zephyr_library_sources_ifdef(CONFIG_SPI_STM32_OPTIM spi_ll_stm32_optim.c)
endif()
