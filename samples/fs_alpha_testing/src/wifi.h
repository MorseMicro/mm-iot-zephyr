/*
 * Copyright (c) 2016 Intel Corporation.
 * Copyright 2025 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __WIFI_H__
#define __WIFI_H__

#include <zephyr/net/socket.h>
#include <zephyr/net/mqtt.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/net_event.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/random/random.h>
#include <zephyr/net/wifi_mgmt.h>

#define TEST_REPEAT_COUNT CONFIG_TEST_REPEAT_COUNT

/* WiFi definitions */
#ifndef WIFI_SSID
#define WIFI_SSID "MorseMicro"
#endif

#ifndef WIFI_PSK
#define WIFI_PSK "12345678"
#endif

#define WIFI_SECURITY   WIFI_SECURITY_TYPE_SAE
#define WIFI_TIMEOUT_MS 15000

int wifi_connect_blocking(void);
int wait_for_network(void);
int wifi_scan_blocking(void);
void init_net_mgmt(void);
int wifi_disconnect_blocking(void);

#endif // __WIFI_H__
