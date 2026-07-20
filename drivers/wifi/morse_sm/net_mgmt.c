/* Copyright 2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "morse_log.h"
LOG_MODULE_DECLARE(LOG_MODULE_NAME, CONFIG_WIFI_LOG_LEVEL);

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <string.h>
#include <errno.h>
#include <zephyr/net/wifi_mgmt.h>

#include "morse.h"
#include "mmwlan.h"
#include "mmregdb.h"

int mmnetif_tx(const struct device *dev, struct net_pkt *pkt)
{
	struct morse_data *morse = dev->data;
	const int pkt_len = net_pkt_get_len(pkt);

	if (pkt_len > NET_ETH_MAX_FRAME_SIZE) {
		return -ENOMEM;
	}

	int ret = net_pkt_read(pkt, morse->frame_buf, pkt_len);
	if (ret < 0) {
		LOG_ERR("Failed to read packet buffer");
		return ret;
	}

	enum mmwlan_status status = mmwlan_tx(morse->frame_buf, pkt_len);
	if (status != MMWLAN_SUCCESS) {
		LOG_ERR("Failed to send packet - %d", status);
		return mmwlan_err_to_errno(status);
	}

	LOG_DBG("Packet sent");

	return 0;
};

static void mmnetif_rx(uint8_t *header, unsigned header_len, uint8_t *payload, unsigned payload_len,
		       void *arg)
{
	struct morse_data *morse = (struct morse_data *)arg;
	struct net_pkt *pkt;

	NET_ASSERT(morse != NULL);
	if (morse->iface == NULL) {
		LOG_ERR("Unhandled packet, network interface unavailable");
		return;
	}

	pkt = net_pkt_rx_alloc_with_buffer(morse->iface, header_len + payload_len, AF_UNSPEC, 0,
					   K_MSEC(200));
	if (!pkt) {
		LOG_ERR("Failed to allocate packet buffer");
		return;
	}

	if (net_pkt_write(pkt, header, header_len) < 0) {
		LOG_ERR("Failed to write packet header");
		goto pkt_unref;
	}

	if (net_pkt_write(pkt, payload, payload_len) < 0) {
		LOG_ERR("Failed to write packet data");
		goto pkt_unref;
	}

	if (net_recv_data(morse->iface, pkt) < 0) {
		LOG_ERR("Failed to propagate packet");
		goto pkt_unref;
	}

	return;

pkt_unref:
	net_pkt_unref(pkt);
	return;
}

static void mmnetif_link_state(enum mmwlan_link_state link_state, void *arg)
{
	struct morse_data *morse = (struct morse_data *)arg;
	NET_ASSERT(morse != NULL);

	if (link_state == MMWLAN_LINK_DOWN) {
		net_if_dormant_on(morse->iface);
		if (morse->status == WIFI_STATE_INACTIVE) {
			wifi_mgmt_raise_disconnect_result_event(morse->iface,
								WIFI_REASON_DISCONN_UNSPECIFIED);
		}
		morse->status = WIFI_STATE_INACTIVE;
	} else {
		net_if_dormant_off(morse->iface);
#if defined(CONFIG_NET_DHCPV4)
		net_dhcpv4_restart(morse->iface);
#endif /* defined(CONFIG_NET_DHCPV4) */
		wifi_mgmt_raise_connect_result_event(morse->iface, WIFI_STATUS_CONN_SUCCESS);
		morse->status = WIFI_STATE_COMPLETED;
	}
}

void morse_iface_init(struct net_if *iface)
{
	enum mmwlan_status status;
	const struct mmwlan_s1g_channel_list *channel_list;

	struct mmwlan_boot_args boot_args = MMWLAN_BOOT_ARGS_INIT;
	const struct device *dev = net_if_get_device(iface);
	struct morse_data *morse = dev->data;
	struct ethernet_context *eth_ctx = net_if_l2_data(iface);

	if (morse->iface) {
		return;
	}

	eth_ctx->eth_if_type = L2_ETH_IF_TYPE_WIFI;
	morse->iface = iface;

	morse->status = WIFI_STATE_INTERFACE_DISABLED;

	LOG_DBG("%s: initialising morse interface\n", __func__);

	channel_list =
		mmwlan_lookup_regulatory_domain(get_regulatory_db(), CONFIG_WIFI_MORSE_REGION);

	if (channel_list == NULL) {
		LOG_ERR("Could not find specified regulatory domain matching country code %s\n",
			CONFIG_WIFI_MORSE_REGION);
		return;
	}

	mmwlan_init();
	mmwlan_set_channel_list(channel_list);
	morse->channel_list = channel_list;
	morse->country_code = CONFIG_WIFI_MORSE_REGION;

	status = mmwlan_boot(&boot_args);
	if (status != MMWLAN_SUCCESS) {
		LOG_DBG("mmwlan_boot failed with code %d", status);
		return;
	}

	/* Set MAC hardware address */
	status = mmwlan_get_mac_addr(morse->mac_addr);
	if (status != MMWLAN_SUCCESS) {
		LOG_DBG("mmwlan_get_mac_addr failed with code %d", status);
		return;
	}

	if (net_if_set_link_addr(iface, morse->mac_addr, MMWLAN_MAC_ADDR_LEN, NET_LINK_ETHERNET)) {
		LOG_ERR("Failed to set link address");
	}

	status = mmwlan_register_rx_cb(mmnetif_rx, morse);
	if (status != MMWLAN_SUCCESS) {
		LOG_DBG("mmwlan_register_rx_cb failed with code %d", status);
		return;
	}

	status = mmwlan_register_link_state_cb(mmnetif_link_state, morse);
	if (status != MMWLAN_SUCCESS) {
		LOG_DBG("mmwlan_register_link_state_cb failed with code %d", status);
		return;
	}

	LOG_DBG("Morse Micro Wi-Fi HaLow interface initialised.\n"
		"MAC address %02x:%02x:%02x:%02x:%02x:%02x",
		morse->mac_addr[0], morse->mac_addr[1], morse->mac_addr[2], morse->mac_addr[3],
		morse->mac_addr[4], morse->mac_addr[5]);

	status = mmwlan_get_version(&morse->version);
	if (status != MMWLAN_SUCCESS) {
		LOG_DBG("mmwlan_get_version failed with code %d", status);
		return;
	}

	LOG_DBG("Morse firmware version %s, morselib version %s, Morse chip ID 0x%04x\n",
		morse->version.morse_fw_version, morse->version.morselib_version,
		morse->version.morse_chip_id);

	/* Initialize Ethernet L2 stack */
	ethernet_init(morse->iface);

	/* Not currently connected to a network */
	net_if_dormant_on(morse->iface);

	/* L1 network layer (physical layer) is up */
	net_if_carrier_on(morse->iface);

	morse->status = WIFI_STATE_INACTIVE;
	struct mmwlan_sta_args init_args = MMWLAN_STA_ARGS_INIT;
	memcpy(&morse->sta_args, &init_args, sizeof(struct mmwlan_sta_args));
}

const struct net_wifi_mgmt_offload morsemicro_net_mgmt_ops = {
	.wifi_iface.iface_api.init = morse_iface_init,
	.wifi_iface.send = mmnetif_tx,
	.wifi_mgmt_api = &morsemicro_wifi_mgmt_ops,
};
