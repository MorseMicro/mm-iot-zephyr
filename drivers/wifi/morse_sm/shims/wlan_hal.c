/*
 * Copyright 2024 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "mmhal.h"
#include "mmosal.h"

#include "morse.h"

#include "morse_log.h"
LOG_MODULE_DECLARE(LOG_MODULE_NAME);

static mmhal_irq_handler_t busy_irq_handler = NULL;

void mmhal_wlan_hard_reset(void)
{
	const struct morse_config *cfg = morse_config0;
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
	const struct morse_config *cfg = morse_config0;
	const struct gpio_dt_spec *gpio_dt = &cfg->resetn;
	int ret = 0;
	if ((ret = gpio_pin_set_dt(gpio_dt, 1)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
	}
}

void mmhal_wlan_deinit(void)
{
	const struct morse_config *cfg = morse_config0;
	const struct gpio_dt_spec *gpio_dt = &cfg->resetn;
	int ret = 0;

	if (cfg->bus_ops->release != NULL) {
		cfg->bus_ops->release();
	}

	if ((ret = gpio_pin_set_dt(gpio_dt, 0)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
	}
}

void mmhal_wlan_wake_assert(void)
{
	const struct morse_config *cfg = morse_config0;
	const struct gpio_dt_spec *gpio_dt = &cfg->wakeup;
	int ret = 0;
	if ((ret = gpio_pin_set_dt(gpio_dt, 1)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
	}
}

void mmhal_wlan_wake_deassert(void)
{
	const struct morse_config *cfg = morse_config0;
	const struct gpio_dt_spec *gpio_dt = &cfg->wakeup;
	int ret = 0;
	if ((ret = gpio_pin_set_dt(gpio_dt, 0)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
	}
}

bool mmhal_wlan_busy_is_asserted(void)
{
	const struct morse_config *cfg = morse_config0;
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
	const struct morse_config *cfg = morse_config0;

	if (enabled) {
		gpio_pin_interrupt_configure_dt(&cfg->busy, GPIO_INT_EDGE_TO_ACTIVE);
	} else {
		gpio_pin_interrupt_configure_dt(&cfg->busy, GPIO_INT_DISABLE);
	}
}

/**
 * @brief This function handles BUSY interrupt.
 */
void morse_busy_cb(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	if (busy_irq_handler != NULL) {
		busy_irq_handler();
	}
}
