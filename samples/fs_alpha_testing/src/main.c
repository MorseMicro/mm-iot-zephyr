/*
 * Copyright (c) 2016 Intel Corporation.
 * Copyright 2025 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/mqtt.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/net_event.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/drivers/sensor.h>
#include <zephyr/random/random.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/net_if.h>

#include "wifi.h"

LOG_MODULE_REGISTER(fs_alpha_testing, LOG_LEVEL_INF);

int main(void)
{
	init_net_mgmt();
	printf("Test count: %d\n", TEST_REPEAT_COUNT);

	for (size_t i = 0; i < TEST_REPEAT_COUNT; i++) {
		LOG_INF("Running test %d", i);
		int rc = wifi_scan_blocking();
		if (rc) {
			LOG_ERR("wifi_connect blocking: %d", rc);
			return rc;
		}

		rc = wifi_connect_blocking();
		if (rc) {
			LOG_ERR("wifi_connect_blocking: %d", rc);
			return rc;
		}

		rc = wait_for_network();
		if (rc) {
			LOG_ERR("Network not ready: %d", rc);
			return rc;
		}

		rc = wifi_disconnect_blocking();
		if (rc) {
			LOG_ERR("Could not disconnect");
			return rc;
		}
		LOG_INF("Test %d completed.", i);
	}
	LOG_INF("%d tests completed.", TEST_REPEAT_COUNT);
	return 0;
}
