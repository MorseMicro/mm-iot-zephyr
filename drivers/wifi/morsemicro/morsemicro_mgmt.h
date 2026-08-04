/*
 * Copyright 2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <zephyr/net/net_if.h>
#include <zephyr/net/net_mgmt.h>

#define NET_MORSEMICRO_LAYER NET_MGMT_LAYER_L2
#define NET_MORSEMICRO_CODE  NET_MGMT_LAYER_CODE_USER1
#define NET_MORSEMICRO_BASE                                                                        \
	(NET_MGMT_IFACE_BIT | NET_MGMT_LAYER(NET_MORSEMICRO_LAYER) |                               \
	 NET_MGMT_LAYER_CODE(NET_MORSEMICRO_CODE))

/** Morse Micro Wi-Fi HaLow specific management commands. */
enum net_request_morsemicro_cmd {
	/** Configure the AP's S1G operating channel bandwidth. */
	NET_REQUEST_MORSEMICRO_CMD_S1G_BANDWIDTH = 1,
};

/**
 * Request to configure the AP's S1G operating channel bandwidth, in MHz (1/2/4/8).
 *
 * The data passed to net_mgmt() must be a pointer to a single uint8_t bandwidth value, with
 * len set to sizeof(uint8_t). Must be set before enabling the AP - see
 * @ref CONFIG_WIFI_MORSEMICRO_UNPATCHED_WORKAROUNDS.
 */
#define NET_REQUEST_MORSEMICRO_S1G_BANDWIDTH                                                       \
	(NET_MORSEMICRO_BASE | NET_REQUEST_MORSEMICRO_CMD_S1G_BANDWIDTH)

NET_MGMT_DEFINE_REQUEST_HANDLER(NET_REQUEST_MORSEMICRO_S1G_BANDWIDTH);
