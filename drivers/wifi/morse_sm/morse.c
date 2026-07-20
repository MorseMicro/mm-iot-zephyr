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

#if CONFIG_DT_HAS_MORSEMICRO_MM8108_ENABLED
#define DT_DRV_COMPAT morsemicro_mm8108
#else
#define DT_DRV_COMPAT morsemicro_mm6108
#endif

#define SPI_FRAME_BITS 8

struct morse_data morse_data0;
const struct device *morse_dev;

extern void morse_busy_cb(const struct device *dev, struct gpio_callback *cb, uint32_t pins);
extern uint32_t mmhal_get_deep_sleep_veto(void);
extern volatile uint32_t mmhal_spi_irq_poll_interval;

#ifdef CONFIG_PM

static int morse_pm_action(const struct device *dev, enum pm_device_action action)
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

#endif

static int morse_init(const struct device *dev)
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

	return morsemicro_bus_ops_spi.init(dev);
}

struct morse_config conf = {
	.spi = SPI_DT_SPEC_INST_GET(0,
				    (SPI_LOCK_ON | SPI_OP_MODE_MASTER | SPI_TRANSFER_MSB |
				     SPI_WORD_SET(SPI_FRAME_BITS)),
				    0),
	.resetn = GPIO_DT_SPEC_INST_GET(0, resetn_gpios),
	.wakeup = GPIO_DT_SPEC_INST_GET(0, wakeup_gpios),
	.busy = GPIO_DT_SPEC_INST_GET(0, busy_gpios),
	.spi_irq = GPIO_DT_SPEC_INST_GET(0, spi_irq_gpios),
};

#ifndef CONFIG_WIFI_MORSE_TEST

#ifdef CONFIG_PM_DEVICE
PM_DEVICE_DT_INST_DEFINE(0, morse_pm_action);
#endif

NET_DEVICE_DT_INST_DEFINE(0, morse_init, PM_DEVICE_DT_INST_GET(0), &morse_data0, &conf,
			  CONFIG_WIFI_INIT_PRIORITY, &morsemicro_net_mgmt_ops, ETHERNET_L2,
			  NET_L2_GET_CTX_TYPE(ETHERNET_L2), NET_ETH_MTU);

CONNECTIVITY_WIFI_MGMT_BIND(Z_DEVICE_DT_DEV_ID(DT_DRV_INST(0)));

#else

DEVICE_DT_INST_DEFINE(0, morse_init, NULL, &morse_data0, &conf, POST_KERNEL,
		      CONFIG_WIFI_INIT_PRIORITY, NULL);

#endif /* CONFIG_WIFI_MORSE_TEST */

struct morse_config *morse_config0 = &conf;
