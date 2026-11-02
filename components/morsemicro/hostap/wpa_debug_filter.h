/*
 * Copyright 2026 Morse Micro
 * SPDX-License-Identifier: Apache-2.0
 *
 * Compile out wpa_supplicant output below the runtime log level.
 *
 * umac_supp_start_supp() fixes wpa_debug_level from MMLOG_LEVEL and nothing
 * changes it afterwards, so lower priority messages can never be output.
 * Wrapping the output functions in a constant level check lets the compiler
 * discard those calls and their strings.
 */

#ifndef WPA_DEBUG_FILTER_H
#define WPA_DEBUG_FILTER_H

#if !defined(CONFIG_NO_STDOUT_DEBUG) && !defined(WPA_DEBUG_FILTER_SKIP)

#include "includes.h"
#include "common.h"
#include "mmlog.h"

/* Must match WPA_LOG_LEVEL in morselib supplicant_core.c */
#if MMLOG_LEVEL < MMLOG_LEVEL_ERR
#define WPA_DEBUG_FILTER_LEVEL (MSG_ERROR + 1)
#elif MMLOG_LEVEL == MMLOG_LEVEL_ERR
#define WPA_DEBUG_FILTER_LEVEL (MSG_ERROR)
#elif MMLOG_LEVEL == MMLOG_LEVEL_WRN
#define WPA_DEBUG_FILTER_LEVEL (MSG_WARNING)
#elif MMLOG_LEVEL == MMLOG_LEVEL_INF
#define WPA_DEBUG_FILTER_LEVEL (MSG_INFO)
#elif MMLOG_LEVEL == MMLOG_LEVEL_DBG
#define WPA_DEBUG_FILTER_LEVEL (MSG_DEBUG)
#else
#define WPA_DEBUG_FILTER_LEVEL (MSG_EXCESSIVE)
#endif

#define WPA_DEBUG_FILTER(level, call)                                                          \
	do {                                                                                       \
		if ((level) >= WPA_DEBUG_FILTER_LEVEL) {                                           \
			call;                                                                      \
		}                                                                                  \
	} while (0)

/* Function-like macros are not expanded recursively, so these call the real functions */
#define wpa_printf(level, ...) WPA_DEBUG_FILTER(level, wpa_printf(level, __VA_ARGS__))
#define wpa_hexdump(level, ...) WPA_DEBUG_FILTER(level, wpa_hexdump(level, __VA_ARGS__))
#define wpa_hexdump_key(level, ...) WPA_DEBUG_FILTER(level, wpa_hexdump_key(level, __VA_ARGS__))
#define wpa_hexdump_ascii(level, ...) WPA_DEBUG_FILTER(level, wpa_hexdump_ascii(level, __VA_ARGS__))
#define wpa_hexdump_ascii_key(level, ...)                                                          \
	WPA_DEBUG_FILTER(level, wpa_hexdump_ascii_key(level, __VA_ARGS__))
/* No wpa_msg_cb is registered, so wpa_msg() (and wpa_dbg()) only outputs through wpa_printf() */
#define wpa_msg(ctx, level, ...) WPA_DEBUG_FILTER(level, wpa_msg(ctx, level, __VA_ARGS__))

#endif /* !CONFIG_NO_STDOUT_DEBUG && !WPA_DEBUG_FILTER_SKIP */

#endif /* WPA_DEBUG_FILTER_H */
