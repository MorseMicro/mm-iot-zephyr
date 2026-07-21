/*
 * Copyright 2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

/* Wi-Fi definitions */
#define WIFI_SSID CONFIG_WIFI_SSID
#define WIFI_PSK  CONFIG_WIFI_PSK

#define WIFI_SECURITY   WIFI_SECURITY_TYPE_SAE
#define WIFI_TIMEOUT_MS 15000

/* TCP Server definitions */
#define TCP_SERVER_IP   CONFIG_TCP_SERVER_IP
#define TCP_SERVER_PORT CONFIG_TCP_SERVER_PORT
