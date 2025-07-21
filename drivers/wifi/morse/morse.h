/*
 * Copyright 2024 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_DRIVERS_WIFI_MORSE_MORSE_H_
#define ZEPHYR_DRIVERS_WIFI_MORSE_MORSE_H_

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <string.h>
#include <errno.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/spi.h>
#include <zephyr/net/wifi_mgmt.h>

#include "mmwlan.h"
#include "mmutils.h"

struct morse_config {
	struct spi_dt_spec spi;
	struct spi_cs_control cs_control;
	struct gpio_dt_spec resetn;
	struct gpio_dt_spec wakeup;
	struct gpio_dt_spec busy;
	struct gpio_dt_spec spi_irq;
	struct gpio_dt_spec test;
};

struct morse_data {
	struct net_if *iface;
	uint8_t frame_buf[NET_ETH_MAX_FRAME_SIZE];
	uint8_t mac_addr[6];
	struct gpio_callback busy_cb;
	struct gpio_callback spi_irq_cb;
	scan_result_cb_t scan_cb;
	const struct mmwlan_s1g_channel_list *channel_list;
	const char *country_code;
	struct mmwlan_sta_args sta_args;
	struct mmosal_semb *status_sem;
	enum wifi_iface_state status;
	bool scanning;
};

#define RSN_MFPR 1 << 6
#define RSN_MFPC 1 << 7

extern const struct morse_config morse_config0;
extern struct morse_data morse_data0;

#endif /* ZEPHYR_DRIVERS_WIFI_MORSE_MORSE_H_ */
