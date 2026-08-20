/*
 * Copyright 2023 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#define MMPORT_BREAKPOINT()
#define MMPORT_GET_LR()     0
#define MMPORT_GET_PC(_a)   0
#define MMPORT_MEM_SYNC()   __sync_synchronize()
