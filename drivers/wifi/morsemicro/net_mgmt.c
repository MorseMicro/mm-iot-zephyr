/* Copyright 2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "morsemicro_log.h"
LOG_MODULE_DECLARE(LOG_MODULE_NAME, CONFIG_WIFI_LOG_LEVEL);

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <string.h>
#include <errno.h>
#include <zephyr/net/wifi_mgmt.h>

#include "common.h"
#include "mmwlan.h"
#include "mmregdb.h"

static const uint8_t morsemicro_bcf_regions[] = {
#include "morsemicro_bcf_regions.inc"
};

static const size_t bcf_regions_len = sizeof(morsemicro_bcf_regions);

int mmnetif_tx(const struct device *dev, struct net_pkt *pkt)
{
	struct morsemicro_data *morsemicro = dev->data;
	const int pkt_len = net_pkt_get_len(pkt);

	if (pkt_len > NET_ETH_MAX_FRAME_SIZE) {
		return -ENOMEM;
	}

	int ret = net_pkt_read(pkt, morsemicro->frame_buf, pkt_len);
	if (ret < 0) {
		LOG_ERR("Failed to read packet buffer");
		return ret;
	}

	enum mmwlan_status status = mmwlan_tx(morsemicro->frame_buf, pkt_len);
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
	struct morsemicro_data *morsemicro = (struct morsemicro_data *)arg;
	struct net_pkt *pkt;

	NET_ASSERT(morsemicro != NULL);
	if (morsemicro->iface == NULL) {
		LOG_ERR("Unhandled packet, network interface unavailable");
		return;
	}

	pkt = net_pkt_rx_alloc_with_buffer(morsemicro->iface, header_len + payload_len, AF_UNSPEC,
					   0, K_MSEC(200));
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

	if (net_recv_data(morsemicro->iface, pkt) < 0) {
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
	struct morsemicro_data *dev_data = (struct morsemicro_data *)arg;
	NET_ASSERT(dev_data != NULL);

	if (link_state == MMWLAN_LINK_DOWN) {
		net_if_dormant_on(dev_data->iface);
		if (dev_data->status == WIFI_STATE_INACTIVE) {
			wifi_mgmt_raise_disconnect_result_event(dev_data->iface,
								WIFI_REASON_DISCONN_UNSPECIFIED);
		}
		dev_data->status = WIFI_STATE_INACTIVE;
	} else {
		net_if_dormant_off(dev_data->iface);
#if defined(CONFIG_NET_DHCPV4)
		net_dhcpv4_restart(dev_data->iface);
#endif /* defined(CONFIG_NET_DHCPV4) */
		wifi_mgmt_raise_connect_result_event(dev_data->iface, WIFI_STATUS_CONN_SUCCESS);
		dev_data->status = WIFI_STATE_COMPLETED;
	}
}

static int bcf_reg_dne(const char *country_code)
{
	for (size_t i = 0; i < bcf_regions_len; i += 2) {
		if (country_code[0] == morsemicro_bcf_regions[i] &&
		    country_code[1] == morsemicro_bcf_regions[i + 1]) {
			return 0;
		}
	}
	return -EINVAL;
}

int morsemicro_wlan_start(struct net_if *iface, struct morsemicro_data *dev_data,
			  const char *country_code)
{
	enum mmwlan_status status;
	const struct mmwlan_s1g_channel_list *channel_list;
	struct mmwlan_boot_args boot_args = MMWLAN_BOOT_ARGS_INIT;
	struct mmwlan_sta_args init_args = MMWLAN_STA_ARGS_INIT;

	if (bcf_reg_dne(country_code)) {
		LOG_ERR("Region %s missing radio configuration parameterss in BCF", country_code);
		dev_data->channel_list = NULL;
		return -EINVAL;
	}

	channel_list = mmwlan_lookup_regulatory_domain(get_regulatory_db(), country_code);
	if (channel_list == NULL) {
		LOG_ERR("Region %s missing Wi-Fi channel definitions in mmregdb", country_code);
		return -ENOENT;
	}

	mmwlan_init();
	mmwlan_set_channel_list(channel_list);
	dev_data->channel_list = channel_list;
	dev_data->country_code = country_code;

	status = mmwlan_boot(&boot_args);
	if (status != MMWLAN_SUCCESS) {
		LOG_DBG("mmwlan_boot failed with code %d", status);
		return mmwlan_err_to_errno(status);
	}

	/* Set MAC hardware address */
	status = mmwlan_get_mac_addr(dev_data->mac_addr);
	if (status != MMWLAN_SUCCESS) {
		LOG_DBG("mmwlan_get_mac_addr failed with code %d", status);
		return mmwlan_err_to_errno(status);
	}

	if (net_if_set_link_addr(iface, dev_data->mac_addr, MMWLAN_MAC_ADDR_LEN,
				 NET_LINK_ETHERNET)) {
		LOG_ERR("Failed to set link address");
	}

	status = mmwlan_register_rx_cb(mmnetif_rx, dev_data);
	if (status != MMWLAN_SUCCESS) {
		LOG_DBG("mmwlan_register_rx_cb failed with code %d", status);
		return mmwlan_err_to_errno(status);
	}

	status = mmwlan_register_link_state_cb(mmnetif_link_state, dev_data);
	if (status != MMWLAN_SUCCESS) {
		LOG_DBG("mmwlan_register_link_state_cb failed with code %d", status);
		return mmwlan_err_to_errno(status);
	}

	LOG_DBG("Morse Micro Wi-Fi HaLow interface initialised.\n"
		"MAC address %02x:%02x:%02x:%02x:%02x:%02x",
		dev_data->mac_addr[0], dev_data->mac_addr[1], dev_data->mac_addr[2],
		dev_data->mac_addr[3], dev_data->mac_addr[4], dev_data->mac_addr[5]);

	status = mmwlan_get_version(&dev_data->version);
	if (status != MMWLAN_SUCCESS) {
		LOG_DBG("mmwlan_get_version failed with code %d", status);
		return mmwlan_err_to_errno(status);
	}

	LOG_DBG("Morse Micro firmware version %s, morselib version %s, Morse Micro chip ID "
		"0x%04x\n",
		dev_data->version.morse_fw_version, dev_data->version.morselib_version,
		dev_data->version.morse_chip_id);

	/* Not currently connected to a network */
	net_if_dormant_on(iface);

	/* L1 network layer (physical layer) is up */
	net_if_carrier_on(iface);

	dev_data->status = WIFI_STATE_INACTIVE;
	memcpy(&dev_data->sta_args, &init_args, sizeof(struct mmwlan_sta_args));

	return 0;
}

static int morsemicro_iface_start(const struct device *dev)
{
	struct morsemicro_data *dev_data = dev->data;

	if (dev_data->channel_list == NULL) {
		LOG_ERR("Cannot bring interface up without a valid regulatory domain");
		return -ENODEV;
	}

	return 0;
}

void morsemicro_iface_init(struct net_if *iface)
{
	const struct device *dev = net_if_get_device(iface);
	struct morsemicro_data *dev_data = dev->data;
	struct ethernet_context *eth_ctx = net_if_l2_data(iface);

	eth_ctx->eth_if_type = L2_ETH_IF_TYPE_WIFI;
	dev_data->iface = iface;
	dev_data->status = WIFI_STATE_INTERFACE_DISABLED;

	LOG_DBG("%s: initialising Morse Micro interface\n", __func__);

	/* Initialize Ethernet L2 stack, done once regardless of mmwlan start outcome */
	ethernet_init(dev_data->iface);

	net_if_dormant_on(iface);

	/* L1 network layer (physical layer) down unti valid reg is set */
	net_if_carrier_off(iface);

	if (morsemicro_wlan_start(iface, dev_data, CONFIG_WIFI_MORSEMICRO_REGION) != 0) {
		LOG_DBG("%s: mmwlan start failed, interface left down", __func__);
	}
}

const struct net_wifi_mgmt_offload morsemicro_net_mgmt_ops = {
	.wifi_iface.iface_api.init = morsemicro_iface_init,
	.wifi_iface.start = morsemicro_iface_start,
	.wifi_iface.send = mmnetif_tx,
	.wifi_mgmt_api = &morsemicro_wifi_mgmt_ops,
};
