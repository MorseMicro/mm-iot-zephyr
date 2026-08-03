/*
 * Copyright 2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/posix/arpa/inet.h>
#include <zephyr/posix/sys/socket.h>
#include <zephyr/posix/unistd.h>

#include "udp_echo.h"

LOG_MODULE_REGISTER(ap_mode_echo, LOG_LEVEL_INF);

void udp_echo_run(uint16_t port)
{
	int sock;
	struct sockaddr_in addr = {0};
	uint8_t buf[256];

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		LOG_ERR("Failed to create socket (%d)", errno);
		return;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		LOG_ERR("Failed to bind socket (%d)", errno);
		close(sock);
		return;
	}

	LOG_INF("UDP echo server listening on port %u", port);

	while (1) {
		struct sockaddr_in src;
		socklen_t src_len = sizeof(src);
		int len = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&src, &src_len);

		if (len < 0) {
			LOG_ERR("recvfrom failed (%d)", errno);
			continue;
		}

		if (sendto(sock, buf, len, 0, (struct sockaddr *)&src, src_len) < 0) {
			LOG_ERR("sendto failed (%d)", errno);
		}
	}
}
