/*
 * Copyright 2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "morsemicro_log.h"
LOG_MODULE_DECLARE(LOG_MODULE_NAME);

#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/sdhc.h>
#include <zephyr/sd/sd.h>
#include <zephyr/sd/sd_spec.h>

#include "mmhal.h"

#include "morsemicro_common.h"

static mmhal_irq_handler_t spi_irq_handler = NULL;
static struct sd_card morsemicro_sdio_card;

/*
 * Falls back to this poll period (ms) when the SDHC controller can't notify us of SDIO_INT
 * (sdhc_enable_interrupt() returns -ENOSYS), instead of morselib's default 5000ms.
 */
#define MORSEMICRO_SDIO_IRQ_POLL_FALLBACK_MS 5
extern volatile uint32_t mmhal_spi_irq_poll_interval;

#define MORSEMICRO_SDIO_CMD_TIMEOUT_MS  1000
#define MORSEMICRO_SDIO_DATA_TIMEOUT_MS 1000

static int morsemicro_sdio_cmd_response_type(uint8_t cmd_idx)
{
	switch (cmd_idx) {
	case SD_GO_IDLE_STATE:
		return SD_RSP_TYPE_NONE;
	case SD_SEND_RELATIVE_ADDR:
		return SD_RSP_TYPE_R6;
	case SDIO_SEND_OP_COND:
		return SD_RSP_TYPE_R4;
	case SD_SEND_IF_COND:
		return SD_RSP_TYPE_R7;
	case SDIO_RW_DIRECT:
	case SDIO_RW_EXTENDED:
		return SD_RSP_TYPE_R5;
	case SD_SELECT_CARD:
		return SD_RSP_TYPE_R1b;
	default:
		return SD_RSP_TYPE_R1;
	}
}

static int morsemicro_sdio_map_cmd_error(int ret)
{
	switch (ret) {
	case 0:
		return 0;
	case -ETIMEDOUT:
		return MMHAL_SDIO_CMD_TIMEOUT;
	default:
		return MMHAL_SDIO_OTHER_ERROR;
	}
}

static int morsemicro_sdio_map_data_error(int ret)
{
	switch (ret) {
	case 0:
		return 0;
	case -ETIMEDOUT:
		return MMHAL_SDIO_DATA_TIMEOUT;
	default:
		return MMHAL_SDIO_OTHER_ERROR;
	}
}

static int morsemicro_sdio_cmd53_raw(uint32_t sdio_arg, void *data, uint16_t block_size,
				     uint32_t transfer_length)
{
	const struct morsemicro_config *cfg = morsemicro_config0;
	struct sdhc_command cmd = {
		.opcode = SDIO_RW_EXTENDED,
		.arg = sdio_arg,
		.response_type = SD_RSP_TYPE_R5,
		.timeout_ms = MORSEMICRO_SDIO_CMD_TIMEOUT_MS,
	};
	struct sdhc_data sdhc_data = {0};
	int ret;

	if (block_size != 0) {
		sdhc_data.block_size = block_size;
		sdhc_data.blocks = transfer_length;
	} else {
		sdhc_data.block_size = transfer_length;
		sdhc_data.blocks = 1;
	}
	sdhc_data.data = data;
	sdhc_data.timeout_ms = MORSEMICRO_SDIO_DATA_TIMEOUT_MS;

	ret = sdhc_request(cfg->bus_config.sdio, &cmd, &sdhc_data);
	return morsemicro_sdio_map_data_error(ret);
}

static void morsemicro_sdio_irq_handler(const struct device *dev, int reason, const void *user_data)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(user_data);

	if ((reason & SDHC_INT_SDIO) != 0 && (spi_irq_handler != NULL)) {
		spi_irq_handler();
	}
}

static int morsemicro_bus_init(const struct device *dev)
{
	const struct morsemicro_config *cfg = dev->config;

	if (!device_is_ready(cfg->bus_config.sdio)) {
		LOG_ERR("SDIO bus not ready");
		return -ENODEV;
	}

	memset(&morsemicro_sdio_card, 0, sizeof(morsemicro_sdio_card));

	return 0;
}

int mmhal_wlan_sdio_startup(void)
{
	int ret;

	ret = sd_init(morsemicro_config0->bus_config.sdio, &morsemicro_sdio_card);
	if (ret != 0) {
		return morsemicro_sdio_map_cmd_error(ret);
	}

	ret = mmhal_wlan_sdio_cmd(SDIO_RW_DIRECT,
				  mmhal_make_cmd52_arg(MMHAL_SDIO_WRITE, MMHAL_SDIO_FUNCTION_0,
						       SDIO_CCCR_IO_EN, 0x06),
				  NULL);
	if (ret != 0) {
		return ret;
	}

	ret = mmhal_wlan_sdio_cmd(SDIO_RW_DIRECT,
				  mmhal_make_cmd52_arg(MMHAL_SDIO_WRITE, MMHAL_SDIO_FUNCTION_0,
						       SDIO_CCCR_INT_EN, 0x07),
				  NULL);
	if (ret != 0) {
		return ret;
	}

	ret = mmhal_wlan_sdio_cmd(
		SDIO_RW_DIRECT,
		mmhal_make_cmd52_arg(MMHAL_SDIO_WRITE, MMHAL_SDIO_FUNCTION_1, 0x10000, 0x05), NULL);
	if (ret != 0) {
		return ret;
	}

	ret = mmhal_wlan_sdio_cmd(
		SDIO_RW_DIRECT,
		mmhal_make_cmd52_arg(MMHAL_SDIO_WRITE, MMHAL_SDIO_FUNCTION_1, 0x10001, 0x10), NULL);
	if (ret != 0) {
		return ret;
	}

	ret = mmhal_wlan_sdio_cmd(
		SDIO_RW_DIRECT,
		mmhal_make_cmd52_arg(MMHAL_SDIO_WRITE, MMHAL_SDIO_FUNCTION_1, 0x10002, 0x02), NULL);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

int mmhal_wlan_sdio_cmd(uint8_t cmd_idx, uint32_t arg, uint32_t *rsp)
{
	const struct morsemicro_config *cfg = morsemicro_config0;
	struct sdhc_command cmd = {
		.opcode = cmd_idx,
		.arg = arg,
		.response_type = morsemicro_sdio_cmd_response_type(cmd_idx),
		.timeout_ms = MORSEMICRO_SDIO_CMD_TIMEOUT_MS,
	};
	int ret;

	ret = sdhc_request(cfg->bus_config.sdio, &cmd, NULL);
	if (ret != 0) {
		return morsemicro_sdio_map_cmd_error(ret);
	}

	if (rsp != NULL) {
		*rsp = cmd.response[0];
	}

	return 0;
}

int mmhal_wlan_sdio_cmd53_write(const struct mmhal_wlan_sdio_cmd53_write_args *args)
{
	return morsemicro_sdio_cmd53_raw(args->sdio_arg, (void *)args->data, args->block_size,
					 args->transfer_length);
}

int mmhal_wlan_sdio_cmd53_read(const struct mmhal_wlan_sdio_cmd53_read_args *args)
{
	return morsemicro_sdio_cmd53_raw(args->sdio_arg, args->data, args->block_size,
					 args->transfer_length);
}

void mmhal_wlan_register_spi_irq_handler(mmhal_irq_handler_t handler)
{
	spi_irq_handler = handler;
}

bool mmhal_wlan_spi_irq_is_asserted(void)
{
	uint32_t rsp = 0;
	int error = mmhal_wlan_sdio_cmd(
		SDIO_RW_DIRECT,
		mmhal_make_cmd52_arg(MMHAL_SDIO_READ, MMHAL_SDIO_FUNCTION_0, SDIO_CCCR_INT_P, 0),
		&rsp);
	if (error != 0) {
		return false;
	}

	return ((rsp & 0xFFu) != 0u);
}

void mmhal_wlan_set_spi_irq_enabled(bool enabled)
{
	const struct morsemicro_config *cfg = morsemicro_config0;
	int ret;

	if (enabled) {
		ret = sdhc_enable_interrupt(cfg->bus_config.sdio, morsemicro_sdio_irq_handler,
					    SDHC_INT_SDIO, NULL);
		if (ret == -ENOSYS) {
			mmhal_spi_irq_poll_interval = MORSEMICRO_SDIO_IRQ_POLL_FALLBACK_MS;
		} else if (ret != 0) {
			LOG_ERR("Failed to enable SDIO interrupt: %d", ret);
		}
		if (mmhal_wlan_spi_irq_is_asserted() && (spi_irq_handler != NULL)) {
			spi_irq_handler();
		}
	} else {
		ret = sdhc_disable_interrupt(cfg->bus_config.sdio, SDHC_INT_SDIO);
		if ((ret != 0) && (ret != -ENOSYS)) {
			LOG_ERR("Failed to disable SDIO interrupt: %d", ret);
		}
	}

	return;
}

static int morsemicro_bus_release(void)
{
	return 0;
}

const struct morsemicro_bus_ops morsemicro_bus_ops_sdio = {
	.init = morsemicro_bus_init,
	.release = morsemicro_bus_release,
};
