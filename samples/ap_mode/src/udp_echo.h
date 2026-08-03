/*
 * Copyright 2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdint.h>

/**
 * @brief Run a UDP echo server on the given port. Blocks forever.
 *
 * @param[in] port: UDP port to listen on.
 */
void udp_echo_run(uint16_t port);
