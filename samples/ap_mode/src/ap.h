/*
 * Copyright 2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <zephyr/net/net_if.h>

/**
 * @brief Find the net_if running in AP mode (the second Wi-Fi interface).
 *
 * @return the AP net_if, or NULL if none is registered.
 */
struct net_if *get_ap_iface(void);

/**
 * @brief Assign a static IPv4 address and bring up an open AP on the interface.
 *
 * @param[in] iface: AP net_if, as returned by get_ap_iface().
 *
 * @return 0 on success, negative errno otherwise.
 */
int ap_start(struct net_if *iface);
