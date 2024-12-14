/*
 * Copyright 2024 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/random/random.h>
#include <zephyr/drivers/hwinfo.h>
#include <zephyr/sys/crc.h>
#include <stdatomic.h>
#include <zephyr/sys/reboot.h>
#include "mmhal.h"
#include "mmosal.h"
#include "mmwlan.h"

void mmhal_reset(void)
{
	sys_reboot(SYS_REBOOT_WARM);
}

enum mmhal_isr_state mmhal_get_isr_state(void)
{
	if (k_is_in_isr()) {
		return MMHAL_IN_ISR;
	}

	return MMHAL_NOT_IN_ISR;
}

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

	mac_addr[0] = 0x02;
	mac_addr[1] = 0x00;

	memcpy(&mac_addr[2], &uid, sizeof(uint32_t));
}

uint32_t mmhal_random_u32(uint32_t min, uint32_t max)
{
	uint32_t rndm = sys_rand32_get();
	if (min == 0 && max == UINT32_MAX) {
		return rndm;
	} else {
		return rndm % (max - min + 1) + min;
	}
}

void mmhal_set_deep_sleep_veto(uint8_t veto_id)
{
	(void)veto_id;
}

void mmhal_clear_deep_sleep_veto(uint8_t veto_id)
{
	(void)veto_id;
}