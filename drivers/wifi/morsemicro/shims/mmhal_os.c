/*
 * Copyright 2024-2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/sys/reboot.h>

#include "mmhal.h"

#include "morsemicro_log.h"
LOG_MODULE_DECLARE(LOG_MODULE_NAME);

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
