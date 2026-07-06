# Copyright (c) 2024 STMicroelectronics
# SPDX-License-Identifier: Apache-2.0

board_runner_args(openocd "--tcl-port=6666")
board_runner_args(openocd --cmd-pre-init "gdb_report_data_abort enable")
board_runner_args(openocd "--no-halt")

include(${ZEPHYR_BASE}/boards/common/openocd.board.cmake)
