#pragma once
#include <zephyr/arch/common/ffs.h>

static inline int ffs(int x)
{
	return (int)find_lsb_set((uint32_t)x);
}
