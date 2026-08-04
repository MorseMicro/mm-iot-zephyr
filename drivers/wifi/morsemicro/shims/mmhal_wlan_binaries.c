/*
 * Copyright 2024-2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "mmhal_wlan.h"
#include "mmosal.h"
#include <stddef.h>
#include <stdint.h>

static const uint8_t morsemicro_bcf[] = {
#include "morsemicro_bcf.inc"
};

static const size_t bcf_len = sizeof(morsemicro_bcf);

static const uint8_t morsemicro_firmware[] = {
#include "morsemicro_firmware.inc"
};

static const size_t firmware_len = sizeof(morsemicro_firmware);

void mmhal_wlan_read_bcf_file(uint32_t offset, uint32_t requested_len, struct mmhal_robuf *robuf)
{

	robuf->buf = NULL;
	robuf->len = 0;
	robuf->free_arg = NULL;
	robuf->free_cb = NULL;

	if (bcf_len < offset) {
		printf("Detected an attempt to start reading off the end of the bcf file.\n");
		return;
	}

	robuf->buf = &morsemicro_bcf[offset];
	robuf->len = bcf_len - offset;
	robuf->len = (robuf->len < requested_len) ? robuf->len : requested_len;
}

void mmhal_wlan_read_fw_file(uint32_t offset, uint32_t requested_len, struct mmhal_robuf *robuf)
{
	const size_t read_len = firmware_len - offset;

	if (offset > firmware_len) {
		printf("Detected an attempt to start read off the end of the firmware file.\n");
		robuf->buf = NULL;
		return;
	}

	robuf->buf = &morsemicro_firmware[offset];

	robuf->len = (read_len < requested_len) ? read_len : requested_len;
}
