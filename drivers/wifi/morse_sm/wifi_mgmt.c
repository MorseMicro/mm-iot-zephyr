/*
 * Copyright 2026 Morse Micro
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
#include "mmutils.h"

#define RSN_PARSE_ERR -2
#define RSN_NOT_FOUND -1

static void scan_callback(const struct mmwlan_scan_result *result, void *arg)
{
	struct morse_data *morse = arg;
	struct wifi_scan_result scan;
	struct mm_rsn_information rsn_info;
	struct mm_s1g_operation s1g_operation;

	memset(&scan, 0, sizeof(scan));

	if (morse->channel_list == NULL) {
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
	morse->scan_cb(morse->iface, 0, &scan);
	k_yield();
	return;
}

static void scan_complete_callback(enum mmwlan_scan_state state, void *arg)
{
	struct morse_data *morse = arg;
	morse->status = morse->scan_prev_state;
	LOG_DBG("Scanning completed.");
	morse->scan_cb(morse->iface, 0, NULL);
}

static int morse_mgmt_scan(const struct device *dev, struct wifi_scan_params *params,
			   scan_result_cb_t cb)
{
	struct morse_data *morse = dev->data;

	enum mmwlan_status status;
	struct mmwlan_scan_req scan_req = MMWLAN_SCAN_REQ_INIT;

	morse->scan_cb = cb;
	scan_req.scan_rx_cb = scan_callback;
	scan_req.scan_complete_cb = scan_complete_callback;
	scan_req.scan_cb_arg = morse;
	status = mmwlan_scan_request(&scan_req);
	if (status != MMWLAN_SUCCESS) {
		LOG_ERR("Failed to start scanning");
		return mmwlan_err_to_errno(status);
	}

	morse->scan_prev_state = morse->status;
	morse->status = WIFI_STATE_SCANNING;
	LOG_DBG("Scan started, waiting for results...");
	return 0;
}

static int morse_mgmt_connect(const struct device *dev, struct wifi_connect_req_params *params)
{
	struct morse_data *morse = dev->data;
	struct mmwlan_sta_args *sta_args = &morse->sta_args;
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

static int morse_mgmt_disconnect(const struct device *dev)
{
	struct morse_data *morse = dev->data;
	enum mmwlan_status status = mmwlan_sta_disable();

	if (status != MMWLAN_SUCCESS && status != MMWLAN_SHUTDOWN_BLOCKED) {
		LOG_ERR("Failed to disconnect from AP");
		return mmwlan_err_to_errno(status);
	}

	wifi_mgmt_raise_disconnect_result_event(morse->iface, WIFI_REASON_DISCONN_USER_REQUEST);
	return 0;
}

static int morse_mgmt_iface_status(const struct device *dev, struct wifi_iface_status *status)
{
	struct morse_data *morse = dev->data;

	status->state = morse->status;

	strncpy(status->ssid, morse->sta_args.ssid, WIFI_SSID_MAX_LEN);
	status->ssid_len = morse->sta_args.ssid_len;
	status->iface_mode = WIFI_MODE_INFRA;
	status->band = WIFI_FREQ_BAND_UNKNOWN;
	status->link_mode = WIFI_LINK_MODE_UNKNOWN;
	status->mfp = morse->sta_args.pmf_mode == MMWLAN_PMF_DISABLED ? WIFI_MFP_DISABLE
								      : WIFI_MFP_REQUIRED;

	switch (morse->sta_args.security_type) {
	case MMWLAN_OPEN:
		status->security = WIFI_SECURITY_TYPE_NONE;
		break;
	case MMWLAN_SAE:
		status->security = WIFI_SECURITY_TYPE_SAE;
		break;
	default:
		status->security = WIFI_SECURITY_TYPE_UNKNOWN;
	}

	if (morse->status == WIFI_STATE_COMPLETED) {
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

static int morse_mgmt_get_version(const struct device *dev, struct wifi_version *params)
{
	struct morse_data *morse = dev->data;

	if (morse->status == WIFI_STATE_INTERFACE_DISABLED) {
		return -ENODEV;
	}

	params->drv_version = morse->version.morselib_version;
	params->fw_version = morse->version.morse_fw_version;
	return 0;
}

const struct wifi_mgmt_ops morsemicro_wifi_mgmt_ops = {
	.scan = morse_mgmt_scan,
	.connect = morse_mgmt_connect,
	.disconnect = morse_mgmt_disconnect,
	.iface_status = morse_mgmt_iface_status,
	.get_version = morse_mgmt_get_version,
};
