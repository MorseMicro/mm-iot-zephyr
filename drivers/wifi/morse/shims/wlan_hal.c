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

/** 10x8bit training seq */
#define BYTE_TRAIN 16

static mmhal_irq_handler_t spi_irq_handler = NULL;
static mmhal_irq_handler_t busy_irq_handler = NULL;

static const uint8_t spi_ones[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

void mmhal_wlan_hard_reset(void)
{
	const struct morse_config *cfg = &morse_config0;
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

void mmhal_wlan_spi_cs_assert(void)
{
}

void mmhal_wlan_spi_cs_deassert(void)
{
}

uint8_t mmhal_wlan_spi_rw(uint8_t data)
{
	const struct morse_config *cfg = &morse_config0;
	const struct device *spi = cfg->spi.bus;
	const struct spi_config *spi_cfg = &cfg->spi.config;
	int ret = 0;
	uint8_t read_val = 0;

	struct spi_buf tx_bufs[] = {{.buf = &data, .len = 1}};

	const struct spi_buf_set tx = {
	        .buffers = tx_bufs,
	        .count = 1,
	};

	struct spi_buf rx_bufs[] = {{.buf = &read_val, .len = 1}};

	const struct spi_buf_set rx = {
	        .buffers = rx_bufs,
	        .count = 1,
	};

	if ((ret = spi_transceive(spi, spi_cfg, &tx, &rx)) < 0) {
		LOG_ERR("Unhandled error %d in spi_tranceive\n", ret);
	}

	return read_val;
}

void mmhal_wlan_spi_read_buf(uint8_t *buf, unsigned len)
{
	const struct morse_config *cfg = &morse_config0;
	const struct device *spi = cfg->spi.bus;
	const struct spi_config *spi_cfg = &cfg->spi.config;
	int ret = 0;

	struct spi_buf rx_bufs[] = {{.buf = buf, .len = len}};

	const struct spi_buf_set rx = {
	        .buffers = rx_bufs,
	        .count = 1,
	};

	if ((ret = spi_read(spi, spi_cfg, &rx)) < 0) {
		LOG_ERR("Unhandled error %d in spi_read()\n", ret);
	}
}

void mmhal_wlan_spi_write_buf(const uint8_t *buf, unsigned len)
{
	const struct morse_config *cfg = &morse_config0;
	const struct device *spi = cfg->spi.bus;
	const struct spi_config *spi_cfg = &cfg->spi.config;
	int ret = 0;

	struct spi_buf tx_bufs[] = {{.buf = buf, .len = len}};

	const struct spi_buf_set tx = {
	        .buffers = tx_bufs,
	        .count = 1,
	};

	if ((ret = spi_write(spi, spi_cfg, &tx)) < 0) {
		LOG_ERR("Unhandled error %d in spi_write()\n", ret);
	}
}

void mmhal_wlan_send_training_seq(void)
{
	const struct morse_config *cfg = &morse_config0;
	const struct device *spi = cfg->spi.bus;
	struct gpio_dt_spec *cs_gpio = &cfg->spi.config.cs.gpio;
	struct spi_config spi_cfg = cfg->spi.config;
	gpio_flags_t flags = GPIO_OUTPUT_INACTIVE;
	int ret = 0;

	struct spi_buf tx_bufs = {.buf = (uint8_t *)spi_ones, .len = sizeof(spi_ones)};

	const struct spi_buf_set tx = {
	        .buffers = &tx_bufs,
	        .count = 1,
	};

	ret = gpio_pin_get_config_dt(cs_gpio, &flags);
	if (ret == -ENOSYS) {
		LOG_DBG("Platform does not implement gpio_pin_get_config(), using default flags\n");
	} else if (ret < 0) {
		LOG_ERR("Unhandled error %d in gpio_pin_get_config_dt()\n", ret);
		return;
	}

	ret = gpio_pin_configure(cs_gpio->port, cs_gpio->pin, flags & ~(GPIO_ACTIVE_LOW));
	if (ret != 0) {
		LOG_ERR("Unhandled error %d in gpio_pin_configure()\n", ret);
		return;
	}

	ret = spi_transceive(spi, &spi_cfg, &tx, NULL);
	if (ret != 0) {
		LOG_ERR("Unhandled error %d in spi_transceive()\n", ret);
		return;
	}
	/* Release lock on SPI bus */
	ret = spi_release(spi, &spi_cfg);

	ret = gpio_pin_configure(cs_gpio->port, cs_gpio->pin, flags | GPIO_ACTIVE_LOW);
	if (ret != 0) {
		LOG_ERR("Unhandled error %d in gpio_pin_configure()\n", ret);
		return;
	}
}

void mmhal_wlan_register_spi_irq_handler(mmhal_irq_handler_t handler)
{
	spi_irq_handler = handler;
}

bool mmhal_wlan_spi_irq_is_asserted(void)
{
	const struct morse_config *cfg = &morse_config0;
	const struct gpio_dt_spec *gpio_dt = &cfg->spi_irq;
	int ret = 0;
	if ((ret = gpio_pin_get_dt(gpio_dt)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
		return false;
	}
	return !!ret;
}

void mmhal_wlan_set_spi_irq_enabled(bool enabled)
{
	const struct morse_config *cfg = &morse_config0;

	if (enabled) {
		/* The transiver will hold the IRQ line low if there is additional information
		 * to be retrived. Ideally the interrupt pin would be configured as a low level
		 * interrupt.
		 */
		if (mmhal_wlan_spi_irq_is_asserted()) {
			if (spi_irq_handler != NULL) {
				spi_irq_handler();
			}
		}
		gpio_pin_interrupt_configure_dt(&cfg->spi_irq, GPIO_INT_EDGE_TO_ACTIVE);
	} else {
		gpio_pin_interrupt_configure_dt(&cfg->spi_irq, GPIO_INT_DISABLE);
	}
}

void mmhal_wlan_init(void)
{
	const struct morse_config *cfg = &morse_config0;
	const struct gpio_dt_spec *gpio_dt = &cfg->resetn;
	int ret = 0;
	if ((ret = gpio_pin_set_dt(gpio_dt, 1)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
	}
}

void mmhal_wlan_deinit(void)
{
	const struct morse_config *cfg = &morse_config0;
	const struct gpio_dt_spec *gpio_dt = &cfg->resetn;
	int ret = 0;
	if ((ret = gpio_pin_set_dt(gpio_dt, 0)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
	}
}

void mmhal_wlan_wake_assert(void)
{
	const struct morse_config *cfg = &morse_config0;
	const struct gpio_dt_spec *gpio_dt = &cfg->wakeup;
	int ret = 0;
	if ((ret = gpio_pin_set_dt(gpio_dt, 1)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
	}
}

void mmhal_wlan_wake_deassert(void)
{
	const struct morse_config *cfg = &morse_config0;
	const struct gpio_dt_spec *gpio_dt = &cfg->wakeup;
	int ret = 0;
	if ((ret = gpio_pin_set_dt(gpio_dt, 0)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
	}
}

bool mmhal_wlan_busy_is_asserted(void)
{
	const struct morse_config *cfg = &morse_config0;
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
	const struct morse_config *cfg = &morse_config0;

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

/**
 * @brief This function handles SPI IRQ interrupts.
 */
void morse_spi_irq_cb(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	if (spi_irq_handler != NULL) {
		spi_irq_handler();
	}
}
