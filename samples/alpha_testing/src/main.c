/*
 * Copyright (c) 2016 Intel Corporation.
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

#include "mqtt.h"

LOG_MODULE_REGISTER(alpha_testing, LOG_LEVEL_INF);

extern struct mqtt_client client;

bool done = false;

int main(void)
{
	int rc = wifi_connect_blocking();
	if (rc) {
		LOG_ERR("wifi_connect_blocking: %d", rc);
		return rc;
	}

	rc = wait_for_network();
	if (rc) {
		LOG_ERR("Network not ready: %d", rc);
		return rc;
	}

	rc = init_mqtt();
	if (rc) {
		LOG_ERR("Could not set up MQTT broker");
		return rc;
	}
	char payload[256];
	snprintf(payload, sizeof(payload), "board=%s", CONFIG_BOARD);
	while (!done) {
		struct mqtt_publish_param param = {0};
		param.message.topic.topic.utf8 = (uint8_t *)MQTT_TOPIC;
		param.message.topic.topic.size = strlen(MQTT_TOPIC);
		param.message.topic.qos = MQTT_QOS_0_AT_MOST_ONCE;
		param.message.payload.data = payload;
		param.message.payload.len = strlen(payload);
		param.message_id = 0;
		param.dup_flag = 0;
		param.retain_flag = 0;
		int rc = mqtt_publish(&client, &param);
		if (rc < 0) {
			LOG_ERR("MQTT_PUBLISH FAILED %d", rc);
			return rc;
		}
		(void)mqtt_input(&client);
		(void)mqtt_live(&client);
		k_sleep(K_MSEC(1000));
	}
	rc = wifi_disconnect_blocking();
	if (rc) {
		LOG_ERR("Could not disconnect");
		return rc;
	}
	return rc;
}
