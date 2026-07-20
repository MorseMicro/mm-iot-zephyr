/*
 * Copyright 2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define DT_DRV_COMPAT morsemicro_mm8108

#include "morse.h"
#include "mmhal.h"

DT_INST_FOREACH_STATUS_OKAY_VARGS(MORSEMICRO_NET_DEVICE, mm8108)
