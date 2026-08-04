/*
 * Copyright 2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <errno.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/wifi_mgmt.h>

#include "ap.h"
#include "config.h"
#ifndef WIFI_MORSEMICRO_PATCHED
#include "morsemicro_mgmt.h"
#endif /* WIFI_MORSEMICRO_PATCHED */

LOG_MODULE_REGISTER(ap_mode_ap, LOG_LEVEL_INF);

static int set_static_ip(struct net_if *iface)
{
	struct in_addr addr;
	struct in_addr netmask;

	if (net_addr_pton(AF_INET, AP_STATIC_IP, &addr) < 0) {
		LOG_ERR("Invalid static IP %s", AP_STATIC_IP);
		return -EINVAL;
	}

	if (net_addr_pton(AF_INET, AP_STATIC_NETMASK, &netmask) < 0) {
		LOG_ERR("Invalid netmask %s", AP_STATIC_NETMASK);
		return -EINVAL;
	}

	if (!net_if_ipv4_addr_add(iface, &addr, NET_ADDR_MANUAL, 0)) {
		LOG_ERR("Failed to add static IPv4 address");
		return -EIO;
	}

	net_if_ipv4_set_netmask_by_addr(iface, &addr, &netmask);

	LOG_INF("AP static IPv4 address: %s/%s", AP_STATIC_IP, AP_STATIC_NETMASK);
	return 0;
}

#ifndef WIFI_MORSEMICRO_PATCHED
static int set_s1g_bandwidth(struct net_if *iface)
{
	uint8_t bw_mhz = AP_BANDWIDTH_MHZ;

	return net_mgmt(NET_REQUEST_MORSEMICRO_S1G_BANDWIDTH, iface, &bw_mhz, sizeof(bw_mhz));
}
#endif /* WIFI_MORSEMICRO_PATCHED */

int ap_start(struct net_if *iface)
{
	struct wifi_connect_req_params params = {0};

	int rc = set_static_ip(iface);
	if (rc) {
		return rc;
	}

#ifndef WIFI_MORSEMICRO_PATCHED
	rc = set_s1g_bandwidth(iface);
	if (rc) {
		LOG_ERR("S1G bandwidth request failed: %d", rc);
		return rc;
	}
#else
	switch (AP_BANDWIDTH_MHZ) {
	case 1:
		params.bandwidth = WIFI_FREQ_BANDWIDTH_1MHZ;
		break;
	case 2:
		params.bandwidth = WIFI_FREQ_BANDWIDTH_2MHZ;
		break;
	case 4:
		params.bandwidth = WIFI_FREQ_BANDWIDTH_4MHZ;
		break;
	case 8:
		params.bandwidth = WIFI_FREQ_BANDWIDTH_8MHZ;
		break;
	}
#endif /* WIFI_MORSEMICRO_PATCHED */

	params.ssid = AP_SSID;
	params.channel = AP_CHANNEL;
	params.ssid_length = strlen(AP_SSID);
	params.security = WIFI_SECURITY_TYPE_NONE;
	params.mfp = WIFI_MFP_DISABLE;

	LOG_INF("Starting open AP: %s", AP_SSID);
	rc = net_mgmt(NET_REQUEST_WIFI_AP_ENABLE, iface, &params, sizeof(params));
	if (rc) {
		LOG_ERR("AP enable request failed: %d", rc);
		return rc;
	}

	LOG_INF("AP started");
	return 0;
}
