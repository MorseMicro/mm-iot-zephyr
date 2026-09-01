/*
 * Copyright 2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* Provides libatomic entry points missing on cores without hardware atomic support. */

#include <stdint.h>
#include <zephyr/sys/atomic.h>

uint32_t __atomic_fetch_or_4(volatile void *mem, uint32_t val, int memorder)
{
	ARG_UNUSED(memorder);
	return (uint32_t)atomic_or((atomic_t *)mem, (atomic_val_t)val);
}

uint32_t __atomic_fetch_and_4(volatile void *mem, uint32_t val, int memorder)
{
	ARG_UNUSED(memorder);
	return (uint32_t)atomic_and((atomic_t *)mem, (atomic_val_t)val);
}
