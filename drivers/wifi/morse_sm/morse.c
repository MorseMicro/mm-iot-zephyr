/*
 * Copyright 2024-2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "morse_log.h"
LOG_MODULE_REGISTER(LOG_MODULE_NAME, CONFIG_WIFI_LOG_LEVEL);

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <string.h>
#include <errno.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/net/conn_mgr/connectivity_wifi_mgmt.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/pm/device.h>

#include "morse.h"
#include "mmosal.h"
#include "mmwlan.h"
#include "mmregdb.h"
#include "mmutils.h"
#include "mmhal.h"

struct morse_data morse_data0;
const struct device *morse_dev;

extern void morse_busy_cb(const struct device *dev, struct gpio_callback *cb, uint32_t pins);
extern uint32_t mmhal_get_deep_sleep_veto(void);
extern volatile uint32_t mmhal_spi_irq_poll_interval;

int morse_pm_action(const struct device *dev, enum pm_device_action action)
{
	ARG_UNUSED(dev);
	switch (action) {
	case PM_DEVICE_ACTION_SUSPEND:
		if (mmhal_get_deep_sleep_veto() != 0) {
			return -EBUSY;
		}
		break;
	case PM_DEVICE_ACTION_RESUME:
	case PM_DEVICE_ACTION_TURN_OFF:
	case PM_DEVICE_ACTION_TURN_ON:
		break;
	}
	return 0;
}

int morse_init(const struct device *dev)
{
	struct morse_data *morse = dev->data;
	const struct morse_config *cfg = dev->config;

	morse_dev = dev;

	morse->status = WIFI_STATE_DISCONNECTED;
	LOG_DBG("");

	if (!gpio_is_ready_dt(&cfg->resetn)) {
		LOG_ERR("%s: device %s is not ready", dev->name, cfg->resetn.port->name);
		return -ENODEV;
	}
	gpio_pin_configure_dt(&cfg->resetn, GPIO_OUTPUT_INACTIVE);

	if (!gpio_is_ready_dt(&cfg->wakeup)) {
		LOG_ERR("%s: device %s is not ready", dev->name, cfg->wakeup.port->name);
		return -ENODEV;
	}
	gpio_pin_configure_dt(&cfg->wakeup, GPIO_OUTPUT_ACTIVE);

	if (!gpio_is_ready_dt(&cfg->busy)) {
		LOG_ERR("%s: device %s is not ready", dev->name, cfg->busy.port->name);
		return -ENODEV;
	}
	gpio_pin_configure_dt(&cfg->busy, GPIO_INPUT);

	gpio_pin_interrupt_configure_dt(&cfg->busy, GPIO_INT_DISABLE);

	gpio_init_callback(&morse->busy_cb, morse_busy_cb, BIT(cfg->busy.pin));
	gpio_add_callback(cfg->busy.port, &morse->busy_cb);

	if (!cfg->bus_ops || !cfg->bus_ops->init) {
		LOG_ERR("%s: no bus_init callback configured", dev->name);
		return -ENOTSUP;
	}

	return cfg->bus_ops->init(dev);
}
