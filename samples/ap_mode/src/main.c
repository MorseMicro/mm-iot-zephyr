/*
 * Copyright 2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>

#include "ap.h"
#include "config.h"
#include "udp_echo.h"

LOG_MODULE_REGISTER(ap_mode_main, LOG_LEVEL_INF);

int main(void)
{
	struct net_if *ap_iface = net_if_get_wifi_sap();
	int rc;

	if (!ap_iface) {
		LOG_ERR("No AP interface found - is CONFIG_WIFI_MORSEMICRO_AP_MODE enabled?");
		return -ENODEV;
	}

	rc = ap_start(ap_iface);
	if (rc) {
		return rc;
	}

	udp_echo_run(UDP_ECHO_PORT);

	return 0;
}
