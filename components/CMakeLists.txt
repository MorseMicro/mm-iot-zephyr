# Copyright 2024-2025 Morse Micro
# SPDX-License-Identifier: Apache-2.0

add_subdirectory_ifdef(CONFIG_WIFI_MORSE_SM    morse_sm)
add_subdirectory_ifdef(CONFIG_WIFI_MORSE_FS    morse_fs)