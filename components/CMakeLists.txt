# Copyright 2024-2026 Morse Micro
# SPDX-License-Identifier: Apache-2.0

include(cmake/extensions.cmake)
add_subdirectory_ifdef(CONFIG_WIFI_MORSEMICRO morsemicro)
