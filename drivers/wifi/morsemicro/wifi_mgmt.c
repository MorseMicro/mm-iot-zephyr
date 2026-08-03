/*
 * Copyright 2026 Morse Micro
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
#include <zephyr/net/net_if.h>

#include "common.h"
#include "mmwlan.h"
#include "mmutils.h"

#define RSN_PARSE_ERR -2
#define RSN_NOT_FOUND -1

static void scan_callback(const struct mmwlan_scan_result *result, void *arg)
{
	struct morsemicro_data *dev_data = arg;
	struct wifi_scan_result scan;
	struct mm_rsn_information rsn_info;
	struct mm_s1g_operation s1g_operation;

	memset(&scan, 0, sizeof(scan));

	if (dev_data->channel_list == NULL) {
		LOG_DBG("channel list hasn't been set...");
		LOG_ERR("%s failed %d", __func__, MMWLAN_ERROR);
		return;
	}

	scan.ssid_length = result->ssid_len < (WIFI_SSID_MAX_LEN - 1) ? result->ssid_len
								      : WIFI_SSID_MAX_LEN - 1;
	memcpy(scan.ssid, result->ssid, scan.ssid_length);
	scan.ssid[WIFI_SSID_MAX_LEN - 1] = '\0';

	memcpy(scan.mac, result->bssid, WIFI_MAC_ADDR_LEN);
	scan.mac_length = WIFI_MAC_ADDR_LEN;
	scan.band = WIFI_FREQ_BAND_UNKNOWN;
	scan.channel = 0;
	scan.rssi = (int8_t)result->rssi;

	int ret = mm_parse_s1g_operation(result->ies, result->ies_len, &s1g_operation);
	if (ret != 0) {
		LOG_ERR("Failed to parse S1G Operation Element");
		return;
	}
	scan.channel = s1g_operation.primary_channel_number;

	ret = mm_parse_rsn_information(result->ies, result->ies_len, &rsn_info);
	if (ret == RSN_PARSE_ERR) {
		LOG_ERR("Failed to parse RSN IE for ssid: %s", scan.ssid);
		return;
	}

	/* Parse the RSN Information to get the MFP requirements */
	if (rsn_info.rsn_capabilities & RSN_MFPC) {
		scan.mfp = WIFI_MFP_OPTIONAL;
		if (rsn_info.rsn_capabilities & RSN_MFPR) {
			scan.mfp = WIFI_MFP_REQUIRED;
		}
	}

	scan.security = WIFI_SECURITY_TYPE_NONE;
	if (ret == RSN_NOT_FOUND || rsn_info.num_akm_suites == 0) {
		goto scan_cb_end;
	}

	/* working with the API at the moment. Technically to be HaLow, a device SHALL
	 * be using WPA3. However, it can be handy for debugging, to use something other than WPA3
	 * There also isn't an OWE definition in Zephyr yet - fake being SAE.
	 */
	for (int i = 0; i < rsn_info.num_akm_suites; i++) {
		switch (rsn_info.akm_suites[i]) {
		case MM_AKM_SUITE_NONE:
			LOG_DBG("ssid: %s has cipher suite NONE", scan.ssid);
			scan.security = MAX(scan.security, WIFI_SECURITY_TYPE_NONE);
			break;

		case MM_AKM_SUITE_PSK:
			LOG_DBG("ssid: %s has cipher suite WPA2-PSK", scan.ssid);
			scan.security = MAX(scan.security, WIFI_SECURITY_TYPE_PSK);
			break;

		case MM_AKM_SUITE_SAE:
			LOG_DBG("ssid: %s has cipher suite WPA3-SAE", scan.ssid);
			scan.security = MAX(scan.security, WIFI_SECURITY_TYPE_SAE);
			break;

		case MM_AKM_SUITE_OWE:
			LOG_DBG("ssid: %s has cipher suite WPA3-OWE -"
				" currently unsupported by Zephyr",
				scan.ssid);
			scan.security = MAX(scan.security, WIFI_SECURITY_TYPE_SAE);
			break;

		case MM_AKM_SUITE_OTHER:
		default:
			LOG_DBG("ssid: %s has an unknown cipher suite - assuming WPA3", scan.ssid);
			scan.security = MAX(scan.security, WIFI_SECURITY_TYPE_SAE);
			break;
		}
	}

scan_cb_end:
	dev_data->sta.scan_cb(dev_data->sta.iface, 0, &scan);
	k_yield();
	return;
}

static void scan_complete_callback(enum mmwlan_scan_state state, void *arg)
{
	struct morsemicro_data *dev_data = arg;
	dev_data->sta.status = dev_data->sta.scan_prev_state;
	LOG_DBG("Scanning completed.");
	dev_data->sta.scan_cb(dev_data->sta.iface, 0, NULL);
}

static int morsemicro_mgmt_scan(const struct device *dev, struct wifi_scan_params *params,
				scan_result_cb_t cb)
{
	struct morsemicro_data *dev_data = dev->data;

	enum mmwlan_status status;
	struct mmwlan_scan_req scan_req = MMWLAN_SCAN_REQ_INIT;

	dev_data->sta.scan_cb = cb;
	scan_req.scan_rx_cb = scan_callback;
	scan_req.scan_complete_cb = scan_complete_callback;
	scan_req.scan_cb_arg = dev_data;
	status = mmwlan_scan_request(&scan_req);
	if (status != MMWLAN_SUCCESS) {
		LOG_ERR("Failed to start scanning");
		return mmwlan_err_to_errno(status);
	}

	dev_data->sta.scan_prev_state = dev_data->sta.status;
	dev_data->sta.status = WIFI_STATE_SCANNING;
	LOG_DBG("Scan started, waiting for results...");
	return 0;
}

static int morsemicro_mgmt_connect(const struct device *dev, struct wifi_connect_req_params *params)
{
	struct morsemicro_data *dev_data = dev->data;
	struct mmwlan_sta_args *sta_args = &dev_data->sta.sta_args;
	enum mmwlan_status status;

	size_t ssid_len = MIN(sizeof(sta_args->ssid), params->ssid_length);
	memcpy((char *)sta_args->ssid, params->ssid, ssid_len);
	sta_args->ssid_len = ssid_len;

	if (params->security == WIFI_SECURITY_TYPE_SAE) {
		const uint8_t *psk = params->sae_password ? params->sae_password : params->psk;
		uint8_t psk_len = psk == params->sae_password ? params->sae_password_length
							      : params->psk_length;
		if (psk == params->psk) {
			LOG_WRN("WPA2 PSK is not supported. Upgrading to WPA3 SAE.");
		}
		psk_len = MIN(sizeof(sta_args->passphrase), psk_len);
		memcpy(sta_args->passphrase, psk, psk_len);
		sta_args->passphrase_len = psk_len;
		sta_args->security_type = MMWLAN_SAE;
	} else if (params->security == WIFI_SECURITY_TYPE_NONE) {
		sta_args->security_type = MMWLAN_OPEN;
	} else {
		LOG_ERR("Authentication method not supported");
		return -EINVAL;
	}

	switch (params->mfp) {
	case WIFI_MFP_DISABLE: {
		sta_args->pmf_mode = MMWLAN_PMF_DISABLED;
		break;
	}
	case WIFI_MFP_OPTIONAL:
	case WIFI_MFP_REQUIRED: {
		sta_args->pmf_mode = MMWLAN_PMF_REQUIRED;
		break;
	}
	default: {
		LOG_WRN("Invalid MFP option");
	}
	}

	LOG_DBG("Attempting to connect to %s with passphrase %s", sta_args->ssid,
		sta_args->passphrase);
	LOG_DBG("This may take some time (~30 seconds)");

	status = mmwlan_sta_enable(sta_args, NULL);
	if (status != MMWLAN_SUCCESS) {
		LOG_ERR("%s: mmwlan_sta_enable returned %d", __func__, status);
		return mmwlan_err_to_errno(status);
	}

	return 0;
}

static int morsemicro_mgmt_disconnect(const struct device *dev)
{
	struct morsemicro_data *dev_data = dev->data;
	enum mmwlan_status status = mmwlan_sta_disable();

	if (status != MMWLAN_SUCCESS && status != MMWLAN_SHUTDOWN_BLOCKED) {
		LOG_ERR("Failed to disconnect from AP");
		return mmwlan_err_to_errno(status);
	}

	wifi_mgmt_raise_disconnect_result_event(dev_data->sta.iface,
						WIFI_REASON_DISCONN_USER_REQUEST);
	return 0;
}

static int morsemicro_mgmt_iface_status(const struct device *dev, struct wifi_iface_status *status)
{
	struct morsemicro_data *dev_data = dev->data;

#if defined(CONFIG_WIFI_MORSEMICRO_AP_MODE)
	if (dev_data->ap.iface && net_if_get_device(dev_data->ap.iface) == dev) {
		struct mmwlan_ap_args *ap_args = &dev_data->ap.ap_args;

		status->state = dev_data->ap.status;

		strncpy(status->ssid, ap_args->ssid, WIFI_SSID_MAX_LEN);
		status->ssid_len = ap_args->ssid_len;
		status->iface_mode = WIFI_MODE_AP;
		status->band = WIFI_FREQ_BAND_UNKNOWN;
		status->link_mode = WIFI_LINK_MODE_UNKNOWN;
		status->mfp = ap_args->pmf_mode == MMWLAN_PMF_DISABLED ? WIFI_MFP_DISABLE
									: WIFI_MFP_REQUIRED;

		switch (ap_args->security_type) {
		case MMWLAN_OPEN:
			status->security = WIFI_SECURITY_TYPE_NONE;
			break;
		case MMWLAN_SAE:
			status->security = WIFI_SECURITY_TYPE_SAE;
			break;
		default:
			status->security = WIFI_SECURITY_TYPE_UNKNOWN;
		}

		if (dev_data->ap.status == WIFI_STATE_COMPLETED) {
			if (mmwlan_get_vif_mac_addr(MMWLAN_VIF_AP, status->bssid) != MMWLAN_SUCCESS) {
				LOG_ERR("Could not get AP BSSID");
			}

			/* Currently no simple way to get this information from the mmwlan APIs. */
			status->channel = 0;
			status->beacon_interval = 0;
		}

		return 0;
	}
#endif /* defined(CONFIG_WIFI_MORSEMICRO_AP_MODE) */

	status->state = dev_data->sta.status;

	strncpy(status->ssid, dev_data->sta.sta_args.ssid, WIFI_SSID_MAX_LEN);
	status->ssid_len = dev_data->sta.sta_args.ssid_len;
	status->iface_mode = WIFI_MODE_INFRA;
	status->band = WIFI_FREQ_BAND_UNKNOWN;
	status->link_mode = WIFI_LINK_MODE_UNKNOWN;
	status->mfp = dev_data->sta.sta_args.pmf_mode == MMWLAN_PMF_DISABLED ? WIFI_MFP_DISABLE
									     : WIFI_MFP_REQUIRED;

	switch (dev_data->sta.sta_args.security_type) {
	case MMWLAN_OPEN:
		status->security = WIFI_SECURITY_TYPE_NONE;
		break;
	case MMWLAN_SAE:
		status->security = WIFI_SECURITY_TYPE_SAE;
		break;
	default:
		status->security = WIFI_SECURITY_TYPE_UNKNOWN;
	}

	if (dev_data->sta.status == WIFI_STATE_COMPLETED) {
		status->rssi = mmwlan_get_rssi();
		if (mmwlan_get_bssid(status->bssid) != MMWLAN_SUCCESS) {
			LOG_ERR("Could not get AP BSSID");
		}
		status->link_mode = WIFI_LINK_MODE_UNKNOWN;

		/* Currently no simple way to get this information from the mmwlan APIs. */
		status->channel = 0;
		status->beacon_interval = 0;
	}

	return 0;
}

static int morsemicro_mgmt_get_version(const struct device *dev, struct wifi_version *params)
{
	struct morsemicro_data *dev_data = dev->data;

	if (dev_data->sta.status == WIFI_STATE_INTERFACE_DISABLED) {
		return -ENODEV;
	}

	params->drv_version = dev_data->version.morselib_version;
	params->fw_version = dev_data->version.morse_fw_version;
	return 0;
}

static int morsemicro_mgmt_reg_domain(const struct device *dev, struct wifi_reg_domain *domain)
{
	struct morsemicro_data *dev_data = dev->data;

	switch (domain->oper) {
	case WIFI_MGMT_SET: {
		static char country_code[WIFI_COUNTRY_CODE_LEN + 1];
		enum mmwlan_status status = mmwlan_shutdown();
		int ret;

		if (status != MMWLAN_SUCCESS) {
			LOG_ERR("Failed cycling interface during region switch\n"
				"mmwlan_shutdown: err %d",
				status);
			return mmwlan_err_to_errno(status);
		}

		memcpy(country_code, domain->country_code, WIFI_COUNTRY_CODE_LEN);
		country_code[WIFI_COUNTRY_CODE_LEN] = '\0';

		/* Gets set in wlan_start with valid reg  */
		dev_data->channel_list = NULL;

		/* 00 check to avoid printing error messages from mmregdb lookup */
		if (country_code[0] == '0' && country_code[1] == '0') {
			ret = 0;
		} else {
			ret = morsemicro_wlan_start(dev_data->sta.iface, dev_data, country_code);
		}

		/* netif down when no valid channels (invalid reg) */
		if (dev_data->channel_list == NULL && net_if_is_up(dev_data->sta.iface)) {
			net_if_down(dev_data->sta.iface);
		}

		return ret;
	}

	case WIFI_MGMT_GET: {

		if (dev_data->channel_list == NULL) {
			domain->country_code[0] = '0';
			domain->country_code[1] = '0';
			domain->num_channels = 0;
			return 0;
		}

		memcpy(domain->country_code, dev_data->channel_list->country_code,
		       WIFI_COUNTRY_CODE_LEN);
		domain->num_channels = 0;

		if (domain->chan_info == NULL) {
			return 0;
		}

		domain->num_channels = MIN(dev_data->channel_list->num_channels, MAX_REG_CHAN_NUM);
		for (unsigned int i = 0; i < domain->num_channels; i++) {
			const struct mmwlan_s1g_channel *channel =
				&dev_data->channel_list->channels[i];

			domain->chan_info[i].center_frequency = channel->centre_freq_hz / 1000000;
			domain->chan_info[i].max_power = channel->max_tx_eirp_dbm;
			domain->chan_info[i].supported = 1;
			domain->chan_info[i].passive_only = 0;
			domain->chan_info[i].dfs = 0;
		}

		return 0;
	}
	default:
		return -EINVAL;
	}
}

#if defined(CONFIG_WIFI_MORSEMICRO_AP_MODE)
static int morsemicro_mgmt_ap_enable(const struct device *dev,
				     struct wifi_connect_req_params *params)
{
	struct morsemicro_data *dev_data = dev->data;
	struct mmwlan_ap_args *ap_args = &dev_data->ap.ap_args;
	enum mmwlan_status status;

	size_t ssid_len = MIN(sizeof(ap_args->ssid), params->ssid_length);

	memcpy((char *)ap_args->ssid, params->ssid, ssid_len);
	ap_args->ssid_len = ssid_len;

	if (params->security == WIFI_SECURITY_TYPE_SAE) {
		const uint8_t *psk = params->sae_password ? params->sae_password : params->psk;
		uint8_t psk_len = psk == params->sae_password ? params->sae_password_length
							      : params->psk_length;

		psk_len = MIN(sizeof(ap_args->passphrase), psk_len);
		memcpy(ap_args->passphrase, psk, psk_len);
		ap_args->passphrase_len = psk_len;
		ap_args->security_type = MMWLAN_SAE;
	} else if (params->security == WIFI_SECURITY_TYPE_NONE) {
		ap_args->security_type = MMWLAN_OPEN;
	} else {
		LOG_ERR("Authentication method not supported");
		return -EINVAL;
	}

	switch (params->mfp) {
	case WIFI_MFP_DISABLE: {
		ap_args->pmf_mode = MMWLAN_PMF_DISABLED;
		break;
	}
	case WIFI_MFP_OPTIONAL:
	case WIFI_MFP_REQUIRED: {
		ap_args->pmf_mode = MMWLAN_PMF_REQUIRED;
		break;
	}
	default: {
		LOG_WRN("Invalid MFP option");
	}
	}

	ap_args->op_class = CONFIG_WIFI_MORSEMICRO_AP_OP_CLASS;
	ap_args->s1g_chan_num = CONFIG_WIFI_MORSEMICRO_AP_S1G_CHAN_NUM;

	status = mmwlan_ap_enable(ap_args);
	if (status != MMWLAN_SUCCESS) {
		LOG_ERR("%s: mmwlan_ap_enable returned %d", __func__, status);
		wifi_mgmt_raise_ap_enable_result_event(dev_data->ap.iface, WIFI_STATUS_AP_FAIL);
		return mmwlan_err_to_errno(status);
	}

	status = mmwlan_get_vif_mac_addr(MMWLAN_VIF_AP, dev_data->ap.mac_addr);
	if (status == MMWLAN_SUCCESS) {
		/* net_if_set_link_addr() refuses to run while the iface is administratively
		 * up, which it already is (auto-started at boot). Bracket it with down/up. */
		bool was_up = net_if_is_up(dev_data->ap.iface);

		if (was_up) {
			net_if_down(dev_data->ap.iface);
		}

		if (net_if_set_link_addr(dev_data->ap.iface, dev_data->ap.mac_addr,
					 MMWLAN_MAC_ADDR_LEN, NET_LINK_ETHERNET)) {
			LOG_ERR("Failed to set link address");
		}

		if (was_up) {
			net_if_up(dev_data->ap.iface);
		}
	}

	wifi_mgmt_raise_ap_enable_result_event(dev_data->ap.iface, WIFI_STATUS_AP_SUCCESS);
	return 0;
}

static int morsemicro_mgmt_ap_disable(const struct device *dev)
{
	struct morsemicro_data *dev_data = dev->data;
	enum mmwlan_status status = mmwlan_ap_disable();

	if (status != MMWLAN_SUCCESS && status != MMWLAN_SHUTDOWN_BLOCKED) {
		LOG_ERR("Failed to disable AP");
		wifi_mgmt_raise_ap_disable_result_event(dev_data->ap.iface, WIFI_STATUS_AP_FAIL);
		return mmwlan_err_to_errno(status);
	}

	wifi_mgmt_raise_ap_disable_result_event(dev_data->ap.iface, WIFI_STATUS_AP_SUCCESS);
	return 0;
}
#endif /* defined(CONFIG_WIFI_MORSEMICRO_AP_MODE) */

const struct wifi_mgmt_ops morsemicro_wifi_mgmt_ops = {
	.scan = morsemicro_mgmt_scan,
	.connect = morsemicro_mgmt_connect,
	.disconnect = morsemicro_mgmt_disconnect,
	.iface_status = morsemicro_mgmt_iface_status,
	.get_version = morsemicro_mgmt_get_version,
	.reg_domain = morsemicro_mgmt_reg_domain,
#if defined(CONFIG_WIFI_MORSEMICRO_AP_MODE)
	.ap_enable = morsemicro_mgmt_ap_enable,
	.ap_disable = morsemicro_mgmt_ap_disable,
#endif /* defined(CONFIG_WIFI_MORSEMICRO_AP_MODE) */
};
