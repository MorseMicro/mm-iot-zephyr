/*
 * Copyright (c) 2016 Intel Corporation.
 * Copyright (c) 2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/net_event.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/drivers/sensor.h>
#include <zephyr/random/random.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/net_if.h>
#include <errno.h>
#include <string.h>

#include "wifi.h"

LOG_MODULE_REGISTER(long_runnning, LOG_LEVEL_INF);

BUILD_ASSERT(strcmp(CONFIG_WIFI_MORSEMICRO_REGION, "00") != 0,
	     "Non interactive samples need CONFIG_WIFI_MORSEMICRO_REGION set to function");

#define PAYLOAD_SIZE CONFIG_PAYLOAD_SIZE

static inline void fill_buffer_with_pattern(uint8_t *buffer, size_t buffer_size,
					    const uint8_t *pattern, size_t pattern_size)
{
	size_t offset = 0;

	/* Copy pattern repeatedly until we reach the buffer end */
	while (offset < buffer_size) {
		size_t remaining = buffer_size - offset;
		size_t copy_size = (remaining < pattern_size) ? remaining : pattern_size;

		memcpy(buffer + offset, pattern, copy_size);
		offset += copy_size;
	}
}

int main(void)
{
	int sock = 0;
	int rc = 0;

	init_net_mgmt();

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

	sock = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		LOG_ERR("Failed to create socket (%d)", errno);
		return sock;
	}

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(TCP_SERVER_PORT),
	};

	rc = zsock_inet_pton(AF_INET, TCP_SERVER_IP, &addr.sin_addr);
	if (rc != 1) {
		printk("server: inet_pton failed\n");
		return rc;
	}

	rc = zsock_connect(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (rc) {
		LOG_ERR("Failed to connect: %d, errno: %d (%s)", rc, errno, strerror(errno));
		return rc;
	}
	LOG_INF("Connected to TCP Server");

	uint8_t data[PAYLOAD_SIZE];
	const char *pattern = "MORSE: hello world!\n";
	fill_buffer_with_pattern(data, PAYLOAD_SIZE, pattern, strlen(pattern));

	const int64_t finished = k_uptime_get() + CONFIG_TEST_DURATION;

	while (k_uptime_get() < finished) {
		LOG_DBG("Sending payload of size %d...", PAYLOAD_SIZE);
		rc = zsock_send(sock, data, PAYLOAD_SIZE, 0);
		if (rc < 0) {
			LOG_ERR("Unable to send data, errno: %d (%s)", errno, strerror(errno));
			break;
		}
		k_sleep(K_MSEC(1000));
	}

	rc = zsock_close(sock);
	if (rc) {
		LOG_ERR("Failed to close socket: %d, errno: %d (%s)", rc, errno, strerror(errno));
	}

	rc = wifi_disconnect_blocking();
	if (rc) {
		LOG_ERR("Failed to disconnect from AP");
		return rc;
	}
	return rc;
}
