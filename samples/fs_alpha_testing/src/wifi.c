/*
 * Copyright 2025 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "wifi.h"

LOG_MODULE_REGISTER(fs_alpha_testing_NETWORKING);

static K_SEM_DEFINE(wifi_conn_sem, 0, 1);
static K_SEM_DEFINE(wifi_disconn_sem, 0, 1);
static K_SEM_DEFINE(wifi_scan_sem, 0, 1);
static K_SEM_DEFINE(net_ready, 0, 1);

static struct net_mgmt_event_callback wifi_cb;
static struct net_mgmt_event_callback ipv4_cb;

static void ipv4_event_handler(struct net_mgmt_event_callback *cb, uint32_t mgmt_event,
                               struct net_if *iface)
{
	ARG_UNUSED(cb);
	ARG_UNUSED(iface);

	if (mgmt_event == NET_EVENT_IPV4_ADDR_ADD) {
		k_sem_give(&net_ready);
	}
}

static void wifi_mgmt_event(struct net_mgmt_event_callback *cb, uint32_t mgmt_event,
                            struct net_if *iface)
{
	if (mgmt_event == NET_EVENT_WIFI_CONNECT_RESULT) {
		const struct wifi_status *status = (const struct wifi_status *)cb->info;
		if (status && status->status == WIFI_STATUS_CONN_SUCCESS) {
			LOG_INF("Wi-Fi connected");
			k_sem_give(&wifi_conn_sem);
		} else {
			LOG_ERR("Wi-Fi connect failed: %d", status ? status->status : -1);
		}
	} else if (mgmt_event == NET_EVENT_WIFI_DISCONNECT_RESULT) {
		const struct wifi_status *status = (const struct wifi_status *)cb->info;
		LOG_INF("Wi-Fi disconnected (%d)", status ? status->status : -1);
		k_sem_give(&wifi_disconn_sem);
	} else if (mgmt_event == NET_EVENT_WIFI_SCAN_DONE) {
		LOG_INF("Wi-Fi scan completed");
		k_sem_give(&wifi_scan_sem);
	}
}

void init_net_mgmt(void)
{
	net_mgmt_init_event_callback(&wifi_cb, wifi_mgmt_event,
	                             NET_EVENT_WIFI_CONNECT_RESULT |
	                                     NET_EVENT_WIFI_DISCONNECT_RESULT |
	                                     NET_EVENT_WIFI_SCAN_RESULT);
	net_mgmt_add_event_callback(&wifi_cb);

	net_mgmt_init_event_callback(&ipv4_cb, ipv4_event_handler, NET_EVENT_IPV4_ADDR_ADD);
	net_mgmt_add_event_callback(&ipv4_cb);
}

int wifi_connect_blocking(void)
{
	int rc = 0;

	struct net_if *iface = net_if_get_first_wifi();
	if (!iface) {
		LOG_ERR("No Wi-Fi interface");
		rc = -ENODEV;
		goto finish;
	}

	struct wifi_connect_req_params cp = {0};
	cp.ssid = WIFI_SSID;
	cp.ssid_length = strlen(WIFI_SSID);
	cp.psk = WIFI_PSK;
	cp.psk_length = strlen(WIFI_PSK);
	cp.channel = WIFI_CHANNEL_ANY;
	cp.security = WIFI_SECURITY;
	cp.mfp = WIFI_MFP_OPTIONAL;

	LOG_INF("Joining SSID: %s ...", WIFI_SSID);
	rc = net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &cp, sizeof(cp));
	if (rc) {
		LOG_ERR("Wi-Fi connect request failed: %d", rc);
		goto finish;
	}

	if (k_sem_take(&wifi_conn_sem, K_MSEC(WIFI_TIMEOUT_MS)) != 0) {
		LOG_ERR("Wi-Fi connect timeout");
		rc = -ETIMEDOUT;
		goto finish;
	}

finish:
	return rc;
}

int wait_for_network(void)
{
	int rc = 0;

	/* If the interface is already up with an IPv4 address, skip wait. */
	struct net_if *iface = net_if_get_default();
	if (iface && net_if_flag_is_set(iface, NET_IF_UP) &&
	    net_if_ipv4_get_global_addr(iface, NET_ADDR_PREFERRED)) {
		goto finish;
	}

	LOG_INF("Waiting for IPv4 address via DHCP…");
	if (k_sem_take(&net_ready, K_SECONDS(30)) != 0) {
		LOG_ERR("No IPv4 address within timeout");
		rc = -ETIMEDOUT;	
	}

finish:
	return rc;
}

int wifi_disconnect_blocking(void)
{
	int rc = 0;

	struct net_if *iface = net_if_get_first_wifi();
	if (!iface) {
		LOG_ERR("No Wi-Fi interface");
		rc = -ENODEV;
		goto finish;
	}

	rc = net_mgmt(NET_REQUEST_WIFI_DISCONNECT, iface, NULL, 0);
	if (rc) {
		LOG_ERR("Wi-Fi disconnect request failed: %d", rc);
		goto finish;
	}

	if (k_sem_take(&wifi_disconn_sem, K_MSEC(WIFI_TIMEOUT_MS)) != 0) {
		LOG_ERR("Wi-Fi disconnect timeout");
		rc = -ETIMEDOUT;
		goto finish;
	}

finish:
	return rc;
}

int wifi_scan_blocking(void)
{
	int rc = 0;

	struct net_if *iface = net_if_get_first_wifi();
	if (!iface) {
		LOG_ERR("No Wi-Fi interface");
		rc = -ENODEV;
		goto finish;
	}

	rc = net_mgmt(NET_REQUEST_WIFI_SCAN, iface, NULL, 0);
	if (rc) {
		LOG_ERR("Wi-Fi scan request failed: %d", rc);
		goto finish;
	}

	if (k_sem_take(&wifi_scan_sem, K_MSEC(WIFI_TIMEOUT_MS)) != 0) {
		LOG_ERR("Wi-Fi scan timeout");
		rc = -ETIMEDOUT;
		goto finish;
	}

finish:
	return rc;
}