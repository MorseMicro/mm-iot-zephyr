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

#if defined(CONFIG_WIFI_MORSEMICRO_UNPATCHED_WORKAROUNDS)
#include "morsemicro_mgmt.h"
#endif /* defined(CONFIG_WIFI_MORSEMICRO_UNPATCHED_WORKAROUNDS) */
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
		const uint8_t *psk;
		uint8_t psk_len;

		if (params->sae_password) {
			psk = params->sae_password;
			psk_len = params->sae_password_length;
		} else {
			psk = params->psk;
			psk_len = params->psk_length;
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
#ifdef WIFI_MORSEMICRO_PATCHED
		status->band = WIFI_FREQ_BAND_SUB_1_GHZ;
#else
		status->band = WIFI_FREQ_BAND_UNKNOWN;
#endif /* WIFI_MORSEMICRO_PATCHED */
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
			if (mmwlan_get_vif_mac_addr(MMWLAN_VIF_AP, status->bssid) !=
			    MMWLAN_SUCCESS) {
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
#ifdef WIFI_MORSEMICRO_PATCHED
	status->band = WIFI_FREQ_BAND_SUB_1_GHZ;
#else
	status->band = WIFI_FREQ_BAND_UNKNOWN;
#endif /* WIFI_MORSEMICRO_PATCHED */
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
/**
 * @brief Validate a candidate AP channel against the active regulatory domain.
 *
 * @param[in] channel_list: active regulatory domain's channel list.
 * @param[in] op_class: candidate global or S1G operating class.
 * @param[in] chan_num: candidate S1G channel number.
 * @param[in] bw_mhz: candidate operating bandwidth, in MHz.
 * @param[in] pri_1mhz_chan_idx: candidate primary 1 MHz channel index.
 *
 * @return true if the combination has a matching entry in channel_list.
 */
static bool morsemicro_ap_channel_is_valid(const struct mmwlan_s1g_channel_list *channel_list,
					   uint16_t op_class, uint16_t chan_num, uint8_t bw_mhz,
					   uint8_t pri_1mhz_chan_idx)
{
	if (channel_list == NULL || bw_mhz == 0 || pri_1mhz_chan_idx >= bw_mhz) {
		return false;
	}

	for (unsigned int i = 0; i < channel_list->num_channels; i++) {
		const struct mmwlan_s1g_channel *chan = &channel_list->channels[i];

		if (chan->s1g_chan_num != chan_num || chan->bw_mhz != bw_mhz) {
			continue;
		}

		if (chan->global_operating_class == MMWLAN_SKIP_OP_CLASS_CHECK ||
		    chan->s1g_operating_class == MMWLAN_SKIP_OP_CLASS_CHECK ||
		    chan->global_operating_class == (int16_t)op_class ||
		    chan->s1g_operating_class == (int16_t)op_class) {
			return true;
		}
	}

	return false;
}

/**
 * @brief Compute the index of a primary channel (1 or 2 MHz) within an S1G operating channel.
 *
 * @param[in] channel_list: active regulatory domain's channel list.
 * @param[in] op_class: operating channel's global or S1G operating class.
 * @param[in] chan_num: operating channel's S1G channel number.
 * @param[in] s1g_primary_channel: S1G channel number of the primary channel.
 *
 * @return the primary channel's index (pri_1mhz_chan_idx) within the operating channel,
 *         or -1 if either channel could not be resolved, or the primary channel's bandwidth
 *         is invalid (must be 1 or 2 MHz, and no wider than the operating channel).
 */
static int calc_primary_chan_idx(const struct mmwlan_s1g_channel_list *channel_list,
				 uint16_t op_class, uint16_t chan_num, uint8_t s1g_primary_channel)
{
	const struct mmwlan_s1g_channel *op_chan = NULL;
	const struct mmwlan_s1g_channel *primary_chan = NULL;
	int32_t freq_delta_hz;
	int32_t bw_margin_hz;
	int idx;

	if (channel_list == NULL) {
		return -ENOENT;
	}

	for (unsigned int i = 0; i < channel_list->num_channels; i++) {
		const struct mmwlan_s1g_channel *chan = &channel_list->channels[i];

		if (op_chan == NULL && chan->s1g_chan_num == chan_num &&
		    (chan->global_operating_class == MMWLAN_SKIP_OP_CLASS_CHECK ||
		     chan->s1g_operating_class == MMWLAN_SKIP_OP_CLASS_CHECK ||
		     chan->global_operating_class == (int16_t)op_class ||
		     chan->s1g_operating_class == (int16_t)op_class)) {
			op_chan = chan;
		}

		if (primary_chan == NULL && chan->s1g_chan_num == s1g_primary_channel) {
			primary_chan = chan;
		}
	}

	if (op_chan == NULL || primary_chan == NULL || primary_chan->bw_mhz > 2 ||
	    primary_chan->bw_mhz > op_chan->bw_mhz) {
		return -1;
	}

	freq_delta_hz = (int32_t)primary_chan->centre_freq_hz - (int32_t)op_chan->centre_freq_hz;
	bw_margin_hz = ((int32_t)op_chan->bw_mhz - (int32_t)primary_chan->bw_mhz) * 500000;
	idx = (freq_delta_hz + bw_margin_hz) / 1000000;

	if (idx < 0 || idx >= op_chan->bw_mhz) {
		return -1;
	}

	return idx;
}

/**
 * @brief Find the S1G operating channel that contains a primary channel at a given bandwidth.
 *
 * @param[in] channel_list: active regulatory domain's channel list.
 * @param[in] pri_chan: the primary channel's regdb entry.
 * @param[in] bw_mhz: desired operating channel bandwidth, in MHz.
 *
 * @return the matching operating channel entry, or NULL if no channel_list entry of that
 *         bandwidth spans pri_chan's centre frequency.
 */
static const struct mmwlan_s1g_channel *
find_operating_channel(const struct mmwlan_s1g_channel_list *channel_list,
		       const struct mmwlan_s1g_channel *primary_chan, uint8_t bw_mhz)
{
	for (unsigned int i = 0; i < channel_list->num_channels; i++) {
		const struct mmwlan_s1g_channel *chan = &channel_list->channels[i];
		int32_t half_span_hz = ((int32_t)bw_mhz * 1000000) / 2;
		int32_t freq_delta_hz =
			(int32_t)primary_chan->centre_freq_hz - (int32_t)chan->centre_freq_hz;

		if (chan->bw_mhz == bw_mhz && freq_delta_hz > -half_span_hz &&
		    freq_delta_hz < half_span_hz) {
			return chan;
		}
	}

	return NULL;
}

/**
 * @brief Derive the S1G operating channel using the primary channel and operating bandwidth in
 * conjunciton with the region
 *
 * @param[in] channel_list: active regulatory domain's channel list.
 * @param[in] s1g_primary_channel: S1G channel number of the primary channel.
 * @param[in] bw_mhz: operating channel bandwidth, in MHz.
 * @param[out] op_class: set to the operating channel's operating class on success.
 * @param[out] s1g_chan_num: set to the operating channel's S1G channel number on success.
 * @param[out] pri_1mhz_chan_idx: set to the primary channel's index within the operating
 *             channel on success.
 * @param[out] pri_bw_mhz: set to the primary channel's own bandwidth (1 or 2 MHz) on success.
 *
 * @return 0 on success, -ENOENT if the primary channel, or a matching operating channel for
 *         it at bw_mhz, could not be found in channel_list.
 */
static int derive_operating_channel(const struct mmwlan_s1g_channel_list *channel_list,
				    uint8_t s1g_primary_channel, uint8_t bw_mhz, uint16_t *op_class,
				    uint16_t *s1g_chan_num, uint8_t *pri_1mhz_chan_idx,
				    uint8_t *pri_bw_mhz)
{
	const struct mmwlan_s1g_channel *pri_chan = NULL;
	const struct mmwlan_s1g_channel *op_chan;
	int idx;

	if (channel_list == NULL) {
		return -ENOENT;
	}

	for (unsigned int i = 0; i < channel_list->num_channels; i++) {
		if (channel_list->channels[i].s1g_chan_num == s1g_primary_channel) {
			pri_chan = &channel_list->channels[i];
			break;
		}
	}

	if (pri_chan == NULL || pri_chan->bw_mhz > 2 || pri_chan->bw_mhz > bw_mhz) {
		return -ENOENT;
	}

	op_chan = find_operating_channel(channel_list, pri_chan, bw_mhz);
	if (op_chan == NULL) {
		return -ENOENT;
	}

	if (op_chan->s1g_operating_class != MMWLAN_SKIP_OP_CLASS_CHECK) {
		*op_class = (uint16_t)op_chan->s1g_operating_class;
	} else {
		*op_class = (uint16_t)op_chan->global_operating_class;
	}

	idx = calc_primary_chan_idx(channel_list, *op_class, op_chan->s1g_chan_num,
				    s1g_primary_channel);
	if (idx < 0) {
		return -ENOENT;
	}

	*s1g_chan_num = op_chan->s1g_chan_num;
	*pri_1mhz_chan_idx = (uint8_t)idx;
	*pri_bw_mhz = pri_chan->bw_mhz;

	return 0;
}

static void morsemicro_ap_sta_status_cb(const struct mmwlan_ap_sta_status *sta_status, void *arg)
{
	struct morsemicro_vif_data *vif_data = (struct morsemicro_vif_data *)arg;
	struct wifi_ap_sta_info sta_info = {0};

	memcpy(sta_info.mac, sta_status->mac_addr, WIFI_MAC_ADDR_LEN);
	sta_info.mac_length = WIFI_MAC_ADDR_LEN;
	sta_info.link_mode = WIFI_LINK_MODE_UNKNOWN;

	if (sta_status->state == MMWLAN_AP_STA_AUTHORIZED) {
		wifi_mgmt_raise_ap_sta_connected_event(vif_data->iface, &sta_info);
	} else if (sta_status->state == MMWLAN_AP_STA_UNKNOWN) {
		wifi_mgmt_raise_ap_sta_disconnected_event(vif_data->iface, &sta_info);
	}
}

static int morsemicro_mgmt_ap_enable(const struct device *dev,
				     struct wifi_connect_req_params *params)
{
	struct morsemicro_data *dev_data = dev->data;

	struct mmwlan_ap_args *ap_args = &dev_data->ap.ap_args;
	enum mmwlan_status status;

	uint8_t bw_mhz;
	uint8_t primary_chan;
	uint16_t op_class;
	uint16_t s1g_chan_num;
	uint8_t pri_1mhz_chan_idx;
	uint8_t pri_bw_mhz;

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

	primary_chan = params->channel;

#if defined(WIFI_MORSEMICRO_PATCHED)
	switch (params->bandwidth) {
	case WIFI_FREQ_BANDWIDTH_1MHZ:
		bw_mhz = 1;
		break;
	case WIFI_FREQ_BANDWIDTH_2MHZ:
		bw_mhz = 2;
		break;
	case WIFI_FREQ_BANDWIDTH_4MHZ:
		bw_mhz = 4;
		break;
	case WIFI_FREQ_BANDWIDTH_8MHZ:
		bw_mhz = 8;
		break;
	default:
		LOG_ERR("Unsupported S1G bandwidth %d", params->bandwidth);
		return -EINVAL;
	}
#elif defined(CONFIG_WIFI_MORSEMICRO_UNPATCHED_WORKAROUNDS)

	if (dev_data->ap.s1g_bw_mhz == 0) {
		LOG_ERR("S1G bandwidth not set - run the s1g_bandwidth shell command "
			"before enabling the AP");
		return -EINVAL;
	}

	bw_mhz = dev_data->ap.s1g_bw_mhz;

#endif /* defined(WIFI_MORSEMICRO_PATCHED) */

	if (derive_operating_channel(dev_data->channel_list, params->channel, bw_mhz, &op_class,
				     &s1g_chan_num, &pri_1mhz_chan_idx, &pri_bw_mhz)) {
		LOG_ERR("Invalid AP channel");
		return -EINVAL;
	}

	if (!morsemicro_ap_channel_is_valid(dev_data->channel_list, op_class, s1g_chan_num, bw_mhz,
					    pri_1mhz_chan_idx)) {
		LOG_ERR("Invalid AP channel");
		return -EINVAL;
	}

	ap_args->op_class = op_class;
	ap_args->s1g_chan_num = s1g_chan_num;
	ap_args->pri_bw_mhz = pri_bw_mhz;
	ap_args->pri_1mhz_chan_idx = pri_1mhz_chan_idx;
	ap_args->sta_status_cb = morsemicro_ap_sta_status_cb;
	ap_args->sta_status_cb_arg = &dev_data->ap;

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

static int morsemicro_mgmt_ap_config_params(const struct device *dev,
					    struct wifi_ap_config_params *params)
{
	struct morsemicro_data *dev_data = dev->data;

	/* Takes effect on the next ap_enable */
	if (params->type & WIFI_AP_CONFIG_PARAM_MAX_NUM_STA) {
		dev_data->ap.ap_args.max_stas = params->max_num_sta;
	}

	if (params->type & ~(uint32_t)WIFI_AP_CONFIG_PARAM_MAX_NUM_STA) {
		LOG_WRN("Only max_num_sta is supported for AP config params");
	}

	return 0;
}

#if defined(CONFIG_WIFI_MORSEMICRO_UNPATCHED_WORKAROUNDS)
static int morsemicro_mgmt_s1g_bandwidth(uint64_t mgmt_request, struct net_if *iface, void *data,
					 size_t len)
{
	struct morsemicro_data *dev_data;
	uint8_t bw_mhz;

	ARG_UNUSED(mgmt_request);

	if (!iface || !data || len != sizeof(bw_mhz)) {
		return -EINVAL;
	}

	bw_mhz = *(uint8_t *)data;

	if (bw_mhz != 1 && bw_mhz != 2 && bw_mhz != 4 && bw_mhz != 8) {
		LOG_ERR("Unsupported S1G bandwidth %u", bw_mhz);
		return -EINVAL;
	}

	dev_data = net_if_get_device(iface)->data;
	dev_data->ap.s1g_bw_mhz = bw_mhz;

	return 0;
}

NET_MGMT_REGISTER_REQUEST_HANDLER(NET_REQUEST_MORSEMICRO_S1G_BANDWIDTH,
				  morsemicro_mgmt_s1g_bandwidth);
#endif /* defined(CONFIG_WIFI_MORSEMICRO_UNPATCHED_WORKAROUNDS) */
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
	.ap_config_params = morsemicro_mgmt_ap_config_params,
#endif /* defined(CONFIG_WIFI_MORSEMICRO_AP_MODE) */
};
