/*
 * Copyright 2024-2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "morsemicro_log.h"
LOG_MODULE_REGISTER(LOG_MODULE_NAME, CONFIG_WIFI_LOG_LEVEL);

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <string.h>
#include <errno.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/net/conn_mgr/connectivity_wifi_mgmt.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/pm/device.h>

#include "common.h"
#include "mmosal.h"
#include "mmwlan.h"
#include "mmregdb.h"
#include "mmutils.h"
#include "mmhal.h"

struct morsemicro_data morsemicro_data0;
const struct device *morsemicro_dev;

extern void morsemicro_busy_cb(const struct device *dev, struct gpio_callback *cb, uint32_t pins);
extern uint32_t mmhal_get_deep_sleep_veto(void);
extern volatile uint32_t mmhal_spi_irq_poll_interval;

int morsemicro_pm_action(const struct device *dev, enum pm_device_action action)
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

int morsemicro_init(const struct device *dev)
{
	struct morsemicro_data *morsemicro = dev->data;
	const struct morsemicro_config *cfg = dev->config;

	morsemicro_dev = dev;

	morsemicro->status = WIFI_STATE_DISCONNECTED;
	LOG_DBG("");

	if (!gpio_is_ready_dt(&cfg->resetn)) {
		LOG_ERR("%s: device %s is not ready", dev->name, cfg->resetn.port->name);
		return -ENODEV;
	}
	gpio_pin_configure_dt(&cfg->resetn, GPIO_OUTPUT_INACTIVE);

#if defined(CONFIG_WIFI_MORSEMICRO_POWERSAVE)

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

	gpio_init_callback(&morsemicro->busy_cb, morsemicro_busy_cb, BIT(cfg->busy.pin));
	gpio_add_callback(cfg->busy.port, &morsemicro->busy_cb);

	if (!cfg->bus_ops || !cfg->bus_ops->init) {
		LOG_ERR("%s: no bus_init callback configured", dev->name);
		return -ENOTSUP;
	}
#endif /* defined(MORSEMICRO_POWERSAVE) */

	return cfg->bus_ops->init(dev);
}
