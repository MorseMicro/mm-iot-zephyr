/*
 * Copyright 2025 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __MQTT_H__
#define __MQTT_H__
#include <zephyr/net/socket.h>
#include <zephyr/net/mqtt.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/net_event.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/random/random.h>
#include <zephyr/net/wifi_mgmt.h>
#include <inttypes.h>

/* MQTT definitions */
#define BROKER_ADDR    "192.168.12.1"
#define BROKER_PORT    1883
#define MQTT_CLIENTID  CONFIG_BOARD "_client"
#define MQTT_TOPIC     "twister/input"
#define MQTT_SUB_TOPIC "twister/output"

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
int init_mqtt();
int wifi_disconnect_blocking(void);

#endif // __MQTT_H__
