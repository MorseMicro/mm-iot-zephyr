/*
 * Copyright 2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#define AP_SSID CONFIG_AP_SSID

#define AP_STATIC_IP      CONFIG_AP_STATIC_IP
#define AP_STATIC_NETMASK CONFIG_AP_STATIC_NETMASK

#define UDP_ECHO_PORT CONFIG_UDP_ECHO_PORT

#define AP_CHANNEL CONFIG_AP_CHANNEL

#define AP_BANDWIDTH_MHZ                                                                           \
	(IS_ENABLED(CONFIG_AP_BANDWIDTH_1MHZ)   ? 1                                                \
	 : IS_ENABLED(CONFIG_AP_BANDWIDTH_2MHZ) ? 2                                                \
	 : IS_ENABLED(CONFIG_AP_BANDWIDTH_4MHZ) ? 4                                                \
						: 8)
