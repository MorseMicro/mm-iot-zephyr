#include <zephyr/kernel.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/net_offload.h>
#include <zephyr/logging/log.h>
#include "morse.h"
#include "mmagic_controller.h"

#include <stdlib.h>
#include <limits.h>
#include <zephyr/posix/fcntl.h>

#include <zephyr/kernel.h>
#include <zephyr/net/socket_offload.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/conn_mgr/connectivity_wifi_mgmt.h>

#define DT_DRV_COMPAT morse_fs

#define LINK_STATE_TIMEOUT_MS 1500

LOG_MODULE_REGISTER(mmagic_offload, CONFIG_NET_OFFLOAD_LOG_LEVEL);

static struct net_if *morse_iface;

/* Your controller instance */
struct mmagic_controller *mmagic_ctrl;

K_KERNEL_STACK_DEFINE(morse_workq_stack, MM_K_STACK_SIZE);

struct morse_config {
} morse_config0;
struct morse_data morse_data0;

static struct mmosal_semb *agent_started_semb = NULL;

static void morse_apply_dhcp_lease(struct net_if *iface, struct in_addr *ip,
                                   const struct in_addr *netmask, const struct in_addr *gw)
{
	/* Add IP + netmask */
	net_if_ipv4_addr_add(iface, ip, NET_ADDR_DHCP, 0);

	/* Add default gateway */
	net_if_ipv4_set_gw(iface, gw);

	/* Add netmask */
	net_if_ipv4_set_netmask_by_addr(iface, ip, netmask);
}

static void morse_wifi_connect_work(struct k_work *work)
{
	struct mmagic_core_wlan_connect_cmd_args connect_args = {
		.timeout = MM_WLAN_CONNECT_TIMEOUT,
	};
	enum mmagic_status status = mmagic_controller_wlan_connect(mmagic_ctrl, &connect_args);
	if (status != MMAGIC_STATUS_OK) {
		LOG_ERR("mmagic_controller_wlan_connect: %d", status);
		goto finish;
	}

	struct mmagic_core_ip_status_rsp_args ip_status_rsp_args = {};
	uint32_t timeout = mmosal_get_time_ms() + LINK_STATE_TIMEOUT_MS;
	while (mmosal_time_lt(mmosal_get_time_ms(), timeout)) {
		status = mmagic_controller_ip_status(mmagic_ctrl, &ip_status_rsp_args);
		if ((status == MMAGIC_STATUS_OK) &&
		    (ip_status_rsp_args.status.link_state == MMAGIC_IP_LINK_STATE_UP)) {
			LOG_INF("Link Up");
			LOG_INF("Link is up %s. Time: %u ms, ",
			        ip_status_rsp_args.status.dhcp_enabled ? "(DHCP)" : "(Static)",
			        mmosal_get_time_ms());
			LOG_INF("IP: %s, ", ip_status_rsp_args.status.ip_addr.addr);
			LOG_INF("Netmask: %s, ", ip_status_rsp_args.status.netmask.addr);
			LOG_INF("Gateway: %s", ip_status_rsp_args.status.gateway.addr);

			net_if_dormant_off(morse_iface);
			net_if_up(morse_iface);
#if defined(CONFIG_NET_DHCPV4)
			struct in_addr ip, gw, mask;
			net_addr_pton(AF_INET, ip_status_rsp_args.status.ip_addr.addr, &ip);
			net_addr_pton(AF_INET, ip_status_rsp_args.status.netmask.addr, &mask);
			net_addr_pton(AF_INET, ip_status_rsp_args.status.gateway.addr, &gw);
			morse_apply_dhcp_lease(morse_iface, &ip, &mask, &gw);
#endif /* defined(CONFIG_NET_DHCPV4) */
			wifi_mgmt_raise_connect_result_event(morse_iface, WIFI_STATUS_CONN_SUCCESS);
			goto finish;
		}
		mmosal_task_sleep(500);
	}
finish:
	morse_data0.connect_in_progress = false;
	return;
}

static int morse_mgmt_connect(const struct device *dev, struct wifi_connect_req_params *params)
{
	if (!net_if_is_carrier_ok(morse_iface) || !net_if_is_admin_up(morse_iface)) {
		return -EIO;
	}
	if (morse_data0.connect_in_progress) {
		return -EINPROGRESS;
	}
	morse_data0.connect_in_progress = true;

	enum mmagic_status status;
	status = mmagic_controller_set_wlan_ssid(mmagic_ctrl, params->ssid);
	if (status != MMAGIC_STATUS_OK) {
		LOG_ERR("mmagic_controller_set_wlan_ssid: %d", status);
		return status;
	}
	status = mmagic_controller_set_wlan_password(mmagic_ctrl, params->psk);
	if (status != MMAGIC_STATUS_OK) {
		LOG_ERR("mmagic_controller_set_wlan_password: %d", status);
		return status;
	}

	k_work_submit_to_queue(&morse_data0.workq, &morse_data0.connect_work);

	return 0;
}

static int morse_mgmt_disconnect(const struct device *dev)
{
	enum mmagic_status status = mmagic_controller_wlan_disconnect(mmagic_ctrl);
	if (status != MMAGIC_STATUS_OK) {
		LOG_ERR("mmagic_controller_wlan_disconnect returned - %d", status);
	}
	return status;
}

void morse_agent_start_handler(struct mmagic_controller *controller, void *arg)
{
	MM_UNUSED(controller);
	struct mmosal_semb *started = (struct mmosal_semb *)arg;
	LOG_INF("Agent start notification received");
	mmosal_semb_give(started);
}

static int morse_mgmt_scan(const struct device *dev, struct wifi_scan_params *params,
                           scan_result_cb_t cb)
{
	struct morse_data *data = dev->data;
	ARG_UNUSED(params);

	if (data->scan_cb != NULL) {
		return -EINPROGRESS;
	}

	if (!net_if_is_carrier_ok(morse_iface)) {
		LOG_ERR("carrier not ok");
		return -EIO;
	}

	data->scan_cb = cb;
	k_work_submit_to_queue(&morse_data0.workq, &morse_data0.scan_work);

	return 0;
}

static void morse_scan_work(struct k_work *work)
{
	struct mmagic_core_wlan_scan_cmd_args cmd_args = {
		.timeout = MM_SCAN_TIMEOUT,
	};
	static struct mmagic_core_wlan_scan_rsp_args rsp = {0};
	enum mmagic_status status = mmagic_controller_wlan_scan(mmagic_ctrl, &cmd_args, &rsp);

	struct wifi_scan_result scan = {0};

	if (status != MMAGIC_STATUS_OK) {
		LOG_ERR("mmagic_controller_wlan_scan: %d", status);
	}

	// TODO: Scan results are incorrectly formated and need fixing
	for (int i = 0; i < rsp.results.num; i++) {
		struct struct_scan_result scan_result = rsp.results.results[i];
		memcpy(scan.ssid, scan_result.ssid.data, scan_result.ssid.len + 1);
		scan.ssid_length = scan_result.ssid.len;
		memcpy(scan.mac, scan_result.bssid.addr, sizeof(scan_result.bssid.addr));
		scan.mac_length = sizeof(scan_result.bssid.addr);
		scan.band = scan_result.op_bw_mhz;
		scan.channel = scan_result.channel_freq_hz;
		scan.rssi = scan_result.rssi;
		morse_data0.scan_cb(morse_iface, 0, &scan);
	}

	morse_data0.scan_cb(morse_iface, 0, NULL);
	morse_data0.scan_cb = NULL;
}

static enum offloaded_net_if_types morse_offload_get_type(void)
{
	return L2_OFFLOADED_NET_IF_TYPE_WIFI;
}

static void morse_wifi_iface_init(struct net_if *iface)
{
	const struct device *dev = net_if_get_device(iface);
	struct morse_data *morse = dev->data;
	struct ethernet_context *eth_ctx = net_if_l2_data(iface);

	eth_ctx->eth_if_type = L2_ETH_IF_TYPE_WIFI;
	morse_iface = iface;

	net_if_up(iface);
	net_if_dormant_on(iface);
	net_if_carrier_on(iface);
}

static const struct wifi_mgmt_ops morse_mgmt_api = {
	.scan = morse_mgmt_scan,
	.connect = morse_mgmt_connect,
	.disconnect = morse_mgmt_disconnect,
};

static const struct net_wifi_mgmt_offload morse_api = {
	.wifi_iface.iface_api.init = morse_wifi_iface_init,
	.wifi_iface.get_type = morse_offload_get_type,
	.wifi_mgmt_api = &morse_mgmt_api,
};

static int morse_fs_init(const struct device *dev);

NET_DEVICE_DT_INST_DEFINE(0, morse_fs_init, NULL, &morse_data0, &morse_config0,
                          CONFIG_WIFI_INIT_PRIORITY, &morse_api, ETHERNET_L2,
                          NET_L2_GET_CTX_TYPE(ETHERNET_L2), NET_ETH_MTU);

CONNECTIVITY_WIFI_MGMT_BIND(Z_DEVICE_DT_DEV_ID(DT_DRV_INST(0)));

static int morse_fs_init(const struct device *dev)
{
	agent_started_semb = mmosal_semb_create("agent_started");
	struct mmagic_controller_init_args init_args = MMAGIC_CONTROLLER_ARGS_INIT;
	init_args.agent_start_cb = morse_agent_start_handler;
	init_args.agent_start_arg = (void *)agent_started_semb;
	mmagic_ctrl = mmagic_controller_init(&init_args);

	bool agent_already_running = false;
	enum mmagic_status status;

	LOG_INF("M2M Controller enabled. Awaiting Agent start");
	if (mmosal_semb_wait(agent_started_semb, MM_AGENT_ACTION_TIMEOUT_MS)) {
		goto register_work_items;
	}
	LOG_INF("No agent start notification, agent may already be running.");
	LOG_INF("Attempting sync to recover connection.");
	status = mmagic_controller_agent_sync(mmagic_ctrl, MM_AGENT_ACTION_TIMEOUT_MS);
	if (status == MMAGIC_STATUS_OK) {
		agent_already_running = true;
		goto register_work_items;
	}

	LOG_INF("Sync failed with status %d, attempting LLC agent reset.", status);
	mmagic_controller_request_agent_reset(mmagic_ctrl);
	if (mmosal_semb_wait(agent_started_semb, MM_AGENT_ACTION_TIMEOUT_MS)) {
		goto register_work_items;
	}

	LOG_ERR("LLC reset failed. Please hard reset the agent.");
	mmosal_semb_wait(agent_started_semb, UINT32_MAX);

register_work_items:
	k_work_init(&morse_data0.scan_work, morse_scan_work);
	k_work_init(&morse_data0.connect_work, morse_wifi_connect_work);
	k_work_queue_start(&morse_data0.workq, morse_workq_stack,
	                   K_KERNEL_STACK_SIZEOF(morse_workq_stack), K_PRIO_COOP(7), NULL);

	k_thread_name_set(&morse_data0.workq.thread, "morse_workq");
	LOG_INF("Morse fs driver initialized");
	return 0;
}
