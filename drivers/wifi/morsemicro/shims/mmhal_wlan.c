/*
 * Copyright 2024-2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/hwinfo.h>
#include <zephyr/net/ethernet.h>
#include <zephyr/random/random.h>
#include <zephyr/sys/crc.h>

#include "mmhal.h"
#include "mmhal_wlan.h"
#include "mmosal.h"

#include "morsemicro_common.h"

#include "morsemicro_log.h"
LOG_MODULE_DECLARE(LOG_MODULE_NAME);

extern const struct device *morsemicro_dev;

#if defined(CONFIG_WIFI_MORSEMICRO_POWERSAVE)
static mmhal_irq_handler_t busy_irq_handler = NULL;
#endif /* defined(CONFIG_WIFI_MORSEMICRO_POWERSAVE) */

static uint32_t mmhal_read_device_uid(void)
{
	uint8_t eui64[8];
	static uint32_t uid = 0;
	int ret;

	if (uid != 0) {
		return uid;
	}

	ret = hwinfo_get_device_eui64(eui64);
	if (ret == 0) {
		uid = crc32_ieee((uint8_t *)eui64, 8);
		return uid;
	}

	ret = hwinfo_get_device_id(eui64, 8);
	if (ret > 0) {
		uid = crc32_ieee((uint8_t *)eui64, 8);
		return uid;
	}

	uid = sys_rand32_get();

	return uid;
}

void mmhal_read_mac_addr(uint8_t *mac_addr)
{
	uint32_t uid = mmhal_read_device_uid();

	if (net_eth_is_addr_valid((struct net_eth_addr *)mac_addr)) {
		return;
	}

	mac_addr[0] = 0x02;
	mac_addr[1] = 0x00;

	memcpy(&mac_addr[2], &uid, sizeof(uint32_t));
}

void mmhal_wlan_hard_reset(void)
{
	const struct morsemicro_config *cfg = morsemicro_config0;
	const struct gpio_dt_spec *gpio_dt = &cfg->resetn;
	int ret = 0;

	if ((ret = gpio_pin_set_dt(gpio_dt, 1)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
	}
	mmosal_task_sleep(5);
	if ((ret = gpio_pin_set_dt(gpio_dt, 0)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
	}
	mmosal_task_sleep(20);
}

void mmhal_wlan_init(void)
{
	const struct morsemicro_config *cfg = morsemicro_config0;
	const struct gpio_dt_spec *gpio_dt = &cfg->resetn;
	int ret = 0;
	if ((ret = gpio_pin_set_dt(gpio_dt, 1)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
	}
}

void mmhal_wlan_deinit(void)
{
	const struct morsemicro_config *cfg = morsemicro_config0;
	const struct gpio_dt_spec *gpio_dt = &cfg->resetn;
	int ret = 0;

	if (cfg->bus_ops->release != NULL) {
		cfg->bus_ops->release();
	}

	if ((ret = gpio_pin_set_dt(gpio_dt, 0)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
	}
}

#if defined(CONFIG_WIFI_MORSEMICRO_POWERSAVE)

void mmhal_wlan_wake_assert(void)
{
	const struct morsemicro_config *cfg = morsemicro_config0;
	const struct gpio_dt_spec *gpio_dt = &cfg->wakeup;
	int ret = 0;
	if ((ret = gpio_pin_set_dt(gpio_dt, 1)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
	}
}

void mmhal_wlan_wake_deassert(void)
{
	const struct morsemicro_config *cfg = morsemicro_config0;
	const struct gpio_dt_spec *gpio_dt = &cfg->wakeup;
	int ret = 0;
	if ((ret = gpio_pin_set_dt(gpio_dt, 0)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
	}
}

bool mmhal_wlan_busy_is_asserted(void)
{
	const struct morsemicro_config *cfg = morsemicro_config0;
	const struct gpio_dt_spec *gpio_dt = &cfg->busy;
	int ret = 0;
	if ((ret = gpio_pin_get_dt(gpio_dt)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
		return false;
	}
	return !!ret;
}

void mmhal_wlan_register_busy_irq_handler(mmhal_irq_handler_t handler)
{
	busy_irq_handler = handler;
}

void mmhal_wlan_set_busy_irq_enabled(bool enabled)
{
	const struct morsemicro_config *cfg = morsemicro_config0;

	if (enabled) {
		gpio_pin_interrupt_configure_dt(&cfg->busy, GPIO_INT_EDGE_TO_ACTIVE);
	} else {
		gpio_pin_interrupt_configure_dt(&cfg->busy, GPIO_INT_DISABLE);
	}
}

/**
 * @brief This function handles BUSY interrupt.
 */
void morsemicro_busy_cb(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	if (busy_irq_handler != NULL) {
		busy_irq_handler();
	}
}

#else
void mmhal_wlan_wake_assert(void)
{
}

void mmhal_wlan_wake_deassert(void)
{
}

bool mmhal_wlan_busy_is_asserted(void)
{
	return false;
}

void mmhal_wlan_register_busy_irq_handler(mmhal_irq_handler_t handler)
{
	ARG_UNUSED(handler);
}

void mmhal_wlan_set_busy_irq_enabled(bool enabled)
{
	ARG_UNUSED(enabled);
}

void morsemicro_busy_cb(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(cb);
	ARG_UNUSED(pins);
}

#endif /* CONFIG_WIFI_MORSEMICRO_POWERSAVE */
