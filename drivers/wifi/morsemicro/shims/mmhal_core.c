/*
 * Copyright 2024-2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdatomic.h>

#include <zephyr/pm/device.h>
#include <zephyr/random/random.h>

#include "mmhal.h"
#include "mmosal.h"

#include "morsemicro_log.h"
LOG_MODULE_DECLARE(LOG_MODULE_NAME);

extern const struct device *morse_dev;

static volatile atomic_uint_fast32_t deep_sleep_vetos = 0;

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
	MMOSAL_ASSERT(veto_id < 32);
	atomic_fetch_or(&deep_sleep_vetos, 1ul << veto_id);
	pm_device_busy_set(morse_dev);
}

void mmhal_clear_deep_sleep_veto(uint8_t veto_id)
{
	MMOSAL_ASSERT(veto_id < 32);
	atomic_fetch_and(&deep_sleep_vetos, ~(1ul << veto_id));
	if (deep_sleep_vetos == 0) {
		pm_device_busy_clear(morse_dev);
	}
}

uint32_t mmhal_get_deep_sleep_veto(void)
{
	return deep_sleep_vetos;
}
