/*
 * Copyright 2024-2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "morsemicro_log.h"
LOG_MODULE_DECLARE(LOG_MODULE_NAME);

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/spi.h>
#include <errno.h>

#include "mmhal.h"

#include "morsemicro_common.h"

static struct gpio_callback spi_irq_gpio_cb;
static mmhal_irq_handler_t spi_irq_handler = NULL;

static union morsemicro_bus_config bus_config;

static const uint8_t training_sequence[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
					    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/**
 * @brief This function handles SPI IRQ interrupts.
 */
static void morsemicro_spi_irq_cb(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	if (spi_irq_handler != NULL) {
		spi_irq_handler();
	}
}

void mmhal_wlan_spi_cs_assert(void)
{
}

void mmhal_wlan_spi_cs_deassert(void)
{
}

uint8_t mmhal_wlan_spi_rw(uint8_t data)
{
	const struct device *spi = bus_config.spi.bus;
	const struct spi_config *spi_cfg = &bus_config.spi.config;
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
	const struct device *spi = bus_config.spi.bus;
	const struct spi_config *spi_cfg = &bus_config.spi.config;
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
	const struct device *spi = bus_config.spi.bus;
	const struct spi_config *spi_cfg = &bus_config.spi.config;
	int ret = 0;

	struct spi_buf tx_bufs[] = {{.buf = (void *)buf, .len = len}};

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
	const struct device *spi = bus_config.spi.bus;
	struct gpio_dt_spec *cs_gpio = &bus_config.spi.config.cs.gpio;
	struct spi_config spi_cfg = bus_config.spi.config;
	gpio_flags_t flags = GPIO_OUTPUT_INACTIVE;
	int ret = 0;

	struct spi_buf tx_bufs = {.buf = (uint8_t *)training_sequence,
				  .len = sizeof(training_sequence)};

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
	int ret = 0;
	if ((ret = gpio_pin_get_dt(&bus_config.spi_irq)) < 0) {
		LOG_ERR("Unhandled exception %d in %s\n", ret, __func__);
		return false;
	}
	return !!ret;
}

void mmhal_wlan_set_spi_irq_enabled(bool enabled)
{
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
		gpio_pin_interrupt_configure_dt(&bus_config.spi_irq, GPIO_INT_EDGE_TO_ACTIVE);
	} else {
		gpio_pin_interrupt_configure_dt(&bus_config.spi_irq, GPIO_INT_DISABLE);
	}
}

static int morsemicro_bus_init(const struct device *dev)
{
	bus_config = ((const struct morsemicro_config *)dev->config)->bus_config;

	if (!spi_is_ready_dt(&bus_config.spi)) {
		LOG_ERR("SPI bus %s not ready", bus_config.spi.bus->name);
		return -ENODEV;
	}

	if (!gpio_is_ready_dt(&bus_config.spi_irq)) {
		LOG_ERR("%s: device %s is not ready", dev->name, bus_config.spi_irq.port->name);
		return -ENODEV;
	}
	gpio_pin_configure_dt(&bus_config.spi_irq, GPIO_INPUT | GPIO_PULL_UP);
	gpio_pin_interrupt_configure_dt(&bus_config.spi_irq, GPIO_INT_DISABLE);

	gpio_init_callback(&spi_irq_gpio_cb, morsemicro_spi_irq_cb, BIT(bus_config.spi_irq.pin));
	gpio_add_callback(bus_config.spi_irq.port, &spi_irq_gpio_cb);

	return 0;
}

static int morsemicro_bus_release()
{
	int ret = spi_release(bus_config.spi.bus, &bus_config.spi.config);

	if (ret != 0) {
		LOG_ERR("Failed to release SPI bus: %d", ret);
	}

	return ret;
}

const struct morsemicro_bus_ops morsemicro_bus_ops_spi = {
	.init = morsemicro_bus_init,
	.release = morsemicro_bus_release,
};
