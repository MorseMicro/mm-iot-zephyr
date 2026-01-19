/*
 * Copyright 2025-2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __WIFI_H__
#define __WIFI_H__

#include <zephyr/posix/sys/socket.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/net_event.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/posix/arpa/inet.h>
#include "config.h"

int wifi_connect_blocking(void);
int wait_for_network(void);
int wifi_scan_blocking(void);
void init_net_mgmt(void);
int wifi_disconnect_blocking(void);

#endif // __WIFI_H__
