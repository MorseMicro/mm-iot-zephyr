/*
 * Copyright 2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

/* WiFi definitions */
#ifndef CONFIG_WIFI_SSID
#define WIFI_SSID "MorseMicro"
#else
#define WIFI_SSID CONFIG_WIFI_SSID
#endif

#ifndef CONFIG_WIFI_PSK
#define WIFI_PSK "12345678"
#else
#define WIFI_PSK CONFIG_WIFI_PSK
#endif

#define WIFI_SECURITY   WIFI_SECURITY_TYPE_SAE
#define WIFI_TIMEOUT_MS 15000

#ifndef CONFIG_SERVER_PORT_1
#define SERVER_PORT_1 4242
#else
#define SERVER_PORT_1 CONFIG_SERVER_PORT_1
#endif

#ifndef CONFIG_SERVER_PORT_2
#define SERVER_PORT_2 4243
#else
#define SERVER_PORT_2 CONFIG_SERVER_PORT_2
#endif

#define N_SERVERS   2
#define SERVER_ADDR CONFIG_NET_CONFIG_PEER_IPV4_ADDR
