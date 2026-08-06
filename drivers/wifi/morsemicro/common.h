/*
 * Copyright 2024-2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <string.h>
#include <errno.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/spi.h>
#include <zephyr/net/conn_mgr/connectivity_wifi_mgmt.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/pm/device.h>

#include "mmwlan.h"
#include "mmutils.h"

union morsemicro_bus_config {
	struct {
		struct spi_dt_spec spi;
		struct gpio_dt_spec spi_irq;
	};
};

struct morsemicro_bus_ops {
	int (*init)(const struct device *dev);
	int (*release)(void);
};

struct morsemicro_config {
	struct gpio_dt_spec resetn;
	struct gpio_dt_spec wakeup;
	struct gpio_dt_spec busy;
	const struct morsemicro_bus_ops *bus_ops;
	union morsemicro_bus_config bus_config;
};

struct morsemicro_data {
	struct net_if *iface;
	enum wifi_iface_state status;
	enum wifi_iface_state scan_prev_state;

	const char *country_code;
	const struct mmwlan_s1g_channel_list *channel_list;

	scan_result_cb_t scan_cb;
	struct gpio_callback busy_cb;

	uint8_t mac_addr[6];
	struct mmwlan_version version;
	struct mmwlan_sta_args sta_args;
	uint8_t frame_buf[NET_ETH_MAX_FRAME_SIZE];
};

#define RSN_MFPR 1 << 6
#define RSN_MFPC 1 << 7

extern struct morsemicro_config *morsemicro_config0;
extern struct morsemicro_data morsemicro_data0;
extern const struct morsemicro_bus_ops morsemicro_bus_ops_spi;

extern const struct wifi_mgmt_ops morsemicro_mgmt_api;
extern const struct net_wifi_mgmt_offload morsemicro_api;

/**
 * @brief net_if callback for the netif init.
 *
 * @param[in] iface: interface being initialised.
 */
void morsemicro_iface_init(struct net_if *iface);

/**
 * @brief Starts mmlwan with the provided domain
 *
 * @param[in] iface: net_if being brought up.
 * @param[in] data: driver data for iface.
 * @param[in] country_code: alpha2 reg domain to boot into.
 *
 * @return 0 on success, negative errno otherwise.
 */
int morsemicro_wlan_start(struct net_if *iface, struct morsemicro_data *data,
			  const char *country_code);

/**
 * @brief Device init function, shared by all chip-specific device definitions.
 *
 * @param[in] dev: compatible device.
 *
 * @return 0 on success, negative errno otherwise.
 */
int morsemicro_init(const struct device *dev);

/**
 * @brief Device PM action callback, shared by all chip-specific device definitions.
 *
 * @param[in] dev: compatible device.
 * @param[in] action: PM action being requested.
 *
 * @return 0 on success, negative errno otherwise.
 */
int morsemicro_pm_action(const struct device *dev, enum pm_device_action action);

/**
 * @brief net_if callback for packet sending
 *
 * @param[in] dev: compatible device.
 * @param[in] pkt: packet to transmit.
 *
 * @return 0 on success, negative errno otherwise.
 */
int mmnetif_tx(const struct device *dev, struct net_pkt *pkt);

/**
 * @brief This function handles BUSY interrupt.
 */
void morsemicro_busy_cb(const struct device *dev, struct gpio_callback *cb, uint32_t pins);

/**
 * @brief Query whether deep sleep should be vetoed.
 *
 * @return 0 if deep sleep is permitted, non-zero to veto.
 */
uint32_t mmhal_get_deep_sleep_veto(void);

extern const struct wifi_mgmt_ops morsemicro_wifi_mgmt_ops;
extern const struct net_wifi_mgmt_offload morsemicro_net_mgmt_ops;

/**
 * @brief Create a mapping between mmwlan_status to generic error codes.
 *
 * @param[in] status: mmwlan_status we want to map.
 *
 * @return 0 on success, mapped error code otherwise.
 */
static inline int mmwlan_err_to_errno(enum mmwlan_status status)
{
	switch (status) {
	case MMWLAN_SUCCESS:
		return 0;
	case MMWLAN_INVALID_ARGUMENT:
		return -EINVAL;
	case MMWLAN_UNAVAILABLE:
		return -EAGAIN;
	case MMWLAN_CHANNEL_LIST_NOT_SET:
	case MMWLAN_CHANNEL_INVALID:
		return -ECHRNG;
	case MMWLAN_NO_MEM:
		return -ENOMEM;
	case MMWLAN_TIMED_OUT:
		return -ETIMEDOUT;
	case MMWLAN_NOT_FOUND:
	case MMWLAN_NOT_RUNNING:
		return -ENODEV;
	case MMWLAN_ERROR:
	case MMWLAN_SHUTDOWN_BLOCKED:
	default:
		return -EIO;
	}
}

#define SPI_FRAME_BITS 8

#define MORSEMICRO_SPI_BUS_CONFIG(inst)                                                            \
	.spi = SPI_DT_SPEC_INST_GET(inst, (SPI_LOCK_ON | SPI_OP_MODE_MASTER | SPI_TRANSFER_MSB |   \
					   SPI_WORD_SET(SPI_FRAME_BITS))),                         \
	.spi_irq = GPIO_DT_SPEC_INST_GET(inst, spi_irq_gpios),

#define MORSEMICRO_NETIF(inst, chip)                                                               \
	NET_DEVICE_DT_INST_DEFINE(inst, morsemicro_init, PM_DEVICE_DT_INST_GET(inst),              \
				  &chip##_data##inst, &chip##_config##inst,                        \
				  CONFIG_WIFI_INIT_PRIORITY, &morsemicro_net_mgmt_ops,             \
				  ETHERNET_L2, NET_L2_GET_CTX_TYPE(ETHERNET_L2), NET_ETH_MTU);

#define MORSEMICRO_TEST(inst, chip)                                                                \
	DEVICE_DT_INST_DEFINE(inst, morsemicro_init, NULL, &chip##_data##inst,                     \
			      &chip##_config##inst, POST_KERNEL, CONFIG_WIFI_INIT_PRIORITY, NULL);

#define MORSEMICRO_NET_DEVICE(inst, chip)                                                          \
	static struct morsemicro_data chip##_data##inst;                                           \
	static struct morsemicro_config chip##_config##inst = {                                    \
		.resetn = GPIO_DT_SPEC_INST_GET(inst, resetn_gpios),                               \
		.wakeup = GPIO_DT_SPEC_INST_GET(inst, wakeup_gpios),                               \
		.busy = GPIO_DT_SPEC_INST_GET(inst, busy_gpios),                                   \
		.bus_ops =                                                                         \
			COND_CODE_1(DT_INST_ON_BUS(inst, spi), (&morsemicro_bus_ops_spi), (NULL)), \
		.bus_config = {COND_CODE_1(DT_INST_ON_BUS(inst, spi),                              \
					   (MORSEMICRO_SPI_BUS_CONFIG(inst)), ({}))},              \
	};                                                                                         \
	struct morsemicro_config *morsemicro_config0 = &chip##_config##inst;                       \
	PM_DEVICE_DT_INST_DEFINE(inst, morsemicro_pm_action);                                      \
	COND_CODE_1(CONFIG_WIFI_MORSEMICRO_TEST, (MORSEMICRO_TEST(inst, chip)),                    \
		    (MORSEMICRO_NETIF(inst, chip)))                                                \
	CONNECTIVITY_WIFI_MGMT_BIND(Z_DEVICE_DT_DEV_ID(DT_DRV_INST(inst)));                        \
	const struct mmhal_chip *mmhal_get_chip(void)                                              \
	{                                                                                          \
		return &mmhal_##chip;                                                              \
	}
