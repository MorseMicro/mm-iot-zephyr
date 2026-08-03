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
#include "mmpkt.h"
#include "mmregdb.h"

static const uint8_t morsemicro_bcf_regions[] = {
#include "morsemicro_bcf_regions.inc"
};

static const size_t bcf_regions_len = sizeof(morsemicro_bcf_regions);

static int mmnetif_vif_tx(struct morsemicro_vif_data *vif_data, struct net_pkt *pkt)
{
	const int pkt_len = net_pkt_get_len(pkt);
	struct mmwlan_tx_metadata metadata = MMWLAN_TX_METADATA_INIT;
	struct mmpkt *tx_pkt;
	struct mmpktview *pkt_view;
	uint8_t *pkt_data;
	int ret;
	enum mmwlan_status status;

	status = mmwlan_tx_wait_until_ready(MMWLAN_TX_DEFAULT_TIMEOUT_MS);
	if (status != MMWLAN_SUCCESS) {
		return mmwlan_err_to_errno(status);
	}

	tx_pkt = mmwlan_alloc_mmpkt_for_tx(pkt_len, MMWLAN_TX_DEFAULT_QOS_TID);
	if (tx_pkt == NULL) {
		return -ENOMEM;
	}

	pkt_view = mmpkt_open(tx_pkt);
	pkt_data = mmpkt_append(pkt_view, pkt_len);
	ret = net_pkt_read(pkt, pkt_data, pkt_len);
	mmpkt_close(&pkt_view);

	if (ret < 0) {
		LOG_ERR("Failed to read packet buffer");
		mmpkt_release(tx_pkt);
		return ret;
	}

	metadata.vif = vif_data->vif;

	status = mmwlan_tx_pkt(tx_pkt, &metadata);
	if (status != MMWLAN_SUCCESS) {
		LOG_ERR("Failed to send packet - %d", status);
		return mmwlan_err_to_errno(status);
	}

	LOG_DBG("Packet sent");

	return 0;
}

int mmnetif_tx(const struct device *dev, struct net_pkt *pkt)
{
	struct morsemicro_data *dev_data = dev->data;
	const int pkt_len = net_pkt_get_len(pkt);

	if (pkt_len > NET_ETH_MAX_FRAME_SIZE) {
		return -ENOMEM;
	}

	return mmnetif_vif_tx(&dev_data->sta, pkt);
};

static void mmnetif_rx(struct mmpkt *mmpkt, const struct mmwlan_rx_metadata *metadata, void *arg)
{
	struct morsemicro_vif_data *vif_data = (struct morsemicro_vif_data *)arg;
	struct mmpktview *pkt_view;
	struct net_pkt *pkt;
	uint8_t *pkt_data;
	uint32_t pkt_len;

	ARG_UNUSED(metadata);

	NET_ASSERT(vif_data != NULL);
	if (vif_data->iface == NULL) {
		LOG_ERR("Unhandled packet, network interface unavailable");
		mmpkt_release(mmpkt);
		return;
	}

	pkt_view = mmpkt_open(mmpkt);
	pkt_data = mmpkt_get_data_start(pkt_view);
	pkt_len = mmpkt_get_data_length(pkt_view);

	pkt = net_pkt_rx_alloc_with_buffer(vif_data->iface, pkt_len, AF_UNSPEC, 0, K_MSEC(200));
	if (!pkt) {
		LOG_ERR("Failed to allocate packet buffer");
		goto done;
	}

	if (net_pkt_write(pkt, pkt_data, pkt_len) < 0) {
		LOG_ERR("Failed to write packet data");
		net_pkt_unref(pkt);
		goto done;
	}

	if (net_recv_data(vif_data->iface, pkt) < 0) {
		LOG_ERR("Failed to propagate packet");
		net_pkt_unref(pkt);
		goto done;
	}

done:
	mmpkt_close(&pkt_view);
	mmpkt_release(mmpkt);
}

static void mmnetif_vif_state(const struct mmwlan_vif_state *state, void *arg)
{
	struct morsemicro_vif_data *vif_data = (struct morsemicro_vif_data *)arg;
	NET_ASSERT(vif_data != NULL);

	if (state->link_state == MMWLAN_LINK_DOWN) {
		net_if_dormant_on(vif_data->iface);
		if (vif_data->vif == MMWLAN_VIF_STA && vif_data->status == WIFI_STATE_INACTIVE) {
			wifi_mgmt_raise_disconnect_result_event(vif_data->iface,
								WIFI_REASON_DISCONN_UNSPECIFIED);
		}
		vif_data->status = WIFI_STATE_INACTIVE;
	} else {
		net_if_dormant_off(vif_data->iface);
		if (vif_data->vif == MMWLAN_VIF_STA) {
#if defined(CONFIG_NET_DHCPV4)
			net_dhcpv4_restart(vif_data->iface);
#endif /* defined(CONFIG_NET_DHCPV4) */
			wifi_mgmt_raise_connect_result_event(vif_data->iface,
							     WIFI_STATUS_CONN_SUCCESS);
		}
		vif_data->status = WIFI_STATE_COMPLETED;
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
	status = mmwlan_get_vif_mac_addr(dev_data->sta.vif, dev_data->sta.mac_addr);
	if (status != MMWLAN_SUCCESS) {
		LOG_DBG("mmwlan_get_vif_mac_addr failed with code %d", status);
		return mmwlan_err_to_errno(status);
	}

	if (net_if_set_link_addr(iface, dev_data->sta.mac_addr, MMWLAN_MAC_ADDR_LEN,
				 NET_LINK_ETHERNET)) {
		LOG_ERR("Failed to set link address");
	}

	status = mmwlan_register_rx_pkt_ext_cb(dev_data->sta.vif, mmnetif_rx, &dev_data->sta);
	if (status != MMWLAN_SUCCESS) {
		LOG_DBG("mmwlan_register_rx_pkt_ext_cb failed with code %d", status);
		return mmwlan_err_to_errno(status);
	}

	status = mmwlan_register_vif_state_cb(dev_data->sta.vif, mmnetif_vif_state, &dev_data->sta);
	if (status != MMWLAN_SUCCESS) {
		LOG_DBG("mmwlan_register_vif_state_cb failed with code %d", status);
		return mmwlan_err_to_errno(status);
	}

#if defined(CONFIG_WIFI_MORSEMICRO_AP_MODE)
	dev_data->ap.vif = MMWLAN_VIF_AP;

	status = mmwlan_register_rx_pkt_ext_cb(dev_data->ap.vif, mmnetif_rx, &dev_data->ap);
	if (status != MMWLAN_SUCCESS) {
		LOG_DBG("mmwlan_register_rx_pkt_ext_cb (AP) failed with code %d", status);
		return mmwlan_err_to_errno(status);
	}

	status = mmwlan_register_vif_state_cb(dev_data->ap.vif, mmnetif_vif_state, &dev_data->ap);
	if (status != MMWLAN_SUCCESS) {
		LOG_DBG("mmwlan_register_vif_state_cb (AP) failed with code %d", status);
		return mmwlan_err_to_errno(status);
	}
#endif /* defined(CONFIG_WIFI_MORSEMICRO_AP_MODE) */

	LOG_DBG("Morse Micro Wi-Fi HaLow interface initialised.\n"
		"MAC address %02x:%02x:%02x:%02x:%02x:%02x",
		dev_data->sta.mac_addr[0], dev_data->sta.mac_addr[1], dev_data->sta.mac_addr[2],
		dev_data->sta.mac_addr[3], dev_data->sta.mac_addr[4], dev_data->sta.mac_addr[5]);

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

	dev_data->sta.status = WIFI_STATE_INACTIVE;
	memcpy(&dev_data->sta.sta_args, &init_args, sizeof(struct mmwlan_sta_args));

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
	dev_data->sta.iface = iface;
	dev_data->sta.vif = MMWLAN_VIF_STA;
	dev_data->sta.status = WIFI_STATE_INTERFACE_DISABLED;

	LOG_DBG("%s: initialising Morse Micro interface\n", __func__);

	/* Initialize Ethernet L2 stack, done once regardless of mmwlan start outcome */
	ethernet_init(dev_data->sta.iface);

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

#if defined(CONFIG_WIFI_MORSEMICRO_AP_MODE)
int mmnetif_tx_ap(const struct device *dev, struct net_pkt *pkt)
{
	struct morsemicro_data *morsemicro = dev->data;
	const int pkt_len = net_pkt_get_len(pkt);

	if (pkt_len > NET_ETH_MAX_FRAME_SIZE) {
		return -ENOMEM;
	}

	return mmnetif_vif_tx(&morsemicro->ap, pkt);
}

void morsemicro_ap_iface_init(struct net_if *iface)
{
	const struct device *dev = net_if_get_device(iface);
	struct morsemicro_data *dev_data = dev->data;
	struct ethernet_context *eth_ctx = net_if_l2_data(iface);

	eth_ctx->eth_if_type = L2_ETH_IF_TYPE_WIFI;
	dev_data->ap.iface = iface;
	dev_data->ap.status = WIFI_STATE_INTERFACE_DISABLED;

	LOG_DBG("%s: initialising Morse Micro AP interface\n", __func__);

	ethernet_init(iface);
}

const struct net_wifi_mgmt_offload morsemicro_net_mgmt_ap_ops = {
	.wifi_iface.iface_api.init = morsemicro_ap_iface_init,
	.wifi_iface.send = mmnetif_tx_ap,
	.wifi_mgmt_api = &morsemicro_wifi_mgmt_ops,
};
#endif /* defined(CONFIG_WIFI_MORSEMICRO_AP_MODE) */
