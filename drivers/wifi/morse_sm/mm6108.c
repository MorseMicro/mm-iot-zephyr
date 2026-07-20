/*
 * Copyright 2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define DT_DRV_COMPAT morsemicro_mm6108

#include "morse.h"
#include "mmhal.h"

#if defined(CONFIG_WIFI_MORSE_EXT_XTAL_INIT) && CONFIG_WIFI_MORSE_EXT_XTAL_INIT
bool mmhal_wlan_ext_xtal_init_is_required(void)
{
	return true;
}
#endif

DT_INST_FOREACH_STATUS_OKAY_VARGS(MORSEMICRO_NET_DEVICE, mm6108)
