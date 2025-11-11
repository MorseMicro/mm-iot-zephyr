#include <zephyr/kernel.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/net_offload.h>
#include <zephyr/logging/log.h>
#include "morse.h"
#include "mmagic_controller.h"

#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <stdatomic.h>
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
	ARG_UNUSED(dev);

	enum mmagic_status status = mmagic_controller_wlan_disconnect(mmagic_ctrl);
	if (status != MMAGIC_STATUS_OK) {
		LOG_ERR("mmagic_controller_wlan_disconnect returned - %d", status);
		wifi_mgmt_raise_disconnect_result_event(morse_iface, WIFI_REASON_DISCONN_UNSPECIFIED);
		return status;
	}
	wifi_mgmt_raise_disconnect_result_event(morse_iface, WIFI_REASON_DISCONN_SUCCESS);
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

static void morse_tcp_offload_recv_work(struct k_work *work);
static void morse_tcp_offload_send_work(struct k_work *work);

/**
 * Initialises a Morse socket descriptor pointer.
 */
void init_morse_socket_descriptor(morse_sd *socket, uint8_t id, uint16_t port,
                                  struct net_context *context)
{
	MMOSAL_ASSERT(socket);

	socket->id = id;
	socket->port = port;
	socket->context = context;
	socket->state = ATOMIC_INIT(0);

	k_work_init(&socket->recv_work, morse_tcp_offload_recv_work);
	k_work_init(&socket->send_work, morse_tcp_offload_send_work);
	return;
}

/**
 * Converts Zephyr sockaddr_in to morse_tcp_sockaddr_in and populates m_addr accordingly.
 *
 * @param addr Pointer to sockaddr_in to be converted.
 * @param m_addr Pointer to morse_tcp_sockaddr_in that stores the result.
 *
 * @returns 0 on success, -EINVAL otherwise.
 */
static int convert_host_socket_address_to_mm(const struct sockaddr_in *addr,
                                             struct morse_tcp_sockaddr_in *m_addr)
{
	MMOSAL_ASSERT(addr);
	MMOSAL_ASSERT(m_addr);

	char *res =
		net_addr_ntop(AF_INET, &addr->sin_addr, m_addr->url.data, sizeof(m_addr->url.data));

	if (res == NULL) {
		return -EINVAL;
	}

	m_addr->url.len = (uint8_t)strnlen(m_addr->url.data, sizeof(m_addr->url.data));
	m_addr->port = ntohs(addr->sin_port);

	return 0;
}

/**
 * Converts Zephyr pkt to Morse buffer1536 and populates buffer accordingly.
 *
 * @param pkt Pointer to net_pkt to be converted.
 * @param buffer Pointer to raw1536 that stores the result.
 *
 * @returns 0 on success, negative errno code otherwise.
 */
static int convert_host_pkt_to_mm(struct net_pkt *pkt, struct raw1536 *buffer)
{
	MMOSAL_ASSERT(pkt);
	MMOSAL_ASSERT(buffer);

	net_pkt_cursor_init(pkt);

	size_t pkt_len = net_pkt_get_len(pkt);

	int pkt_read_status = net_pkt_read(pkt, buffer->data, pkt_len);

	buffer->len = (uint16_t)pkt_len;
	return pkt_read_status;
}

/**
 * Converts Morse raw1536 to Zephyr pkt and populates pkt accordingly.
 *
 * @param buffer Pointer to raw1536 to be converted.
 * @param pkt Pointer to net_pkt that stores the result.
 *
 * @returns 0 on success, negative errno code otherwise.
 */
static int convert_mm_pkt_to_host(struct raw1536 *buffer, struct net_pkt *pkt)
{
	MMOSAL_ASSERT(buffer);
	MMOSAL_ASSERT(pkt);

	net_pkt_cursor_init(pkt);
	int pkt_write_status = net_pkt_write(pkt, buffer->data, buffer->len);

	return pkt_write_status;
}

/**
 * Clean up socket recv states.
 */
void morse_tcp_offload_socket_cleanup_recv(morse_sd *socket)
{
	MMOSAL_ASSERT(socket);

	atomic_clear_bit(&socket->state, MM_TCP_SOCKET_IS_RECV);
	socket->recv_cb = NULL;
	socket->recv_user_data = NULL;
	return;
}

/**
 * Clean up socket send states.
 */
void morse_tcp_offload_socket_cleanup_send(morse_sd *socket)
{
	MMOSAL_ASSERT(socket);

	socket->send_cb = NULL;
	socket->send_user_data = NULL;
	return;
}

static void morse_tcp_offload_send_work(struct k_work *work)
{
	MMOSAL_ASSERT(work);

	morse_sd *socket = CONTAINER_OF(work, morse_sd, send_work);
	MMOSAL_ASSERT(socket);

	if (atomic_test_bit(&socket->state, MM_TCP_SOCKET_IS_CLOSING)) {
		goto cleanup;
	}

	struct mmagic_core_tcp_write_poll_cmd_args write_poll_cmd_args = {
		.stream_id = socket->id,
		.timeout = MM_TCP_SOCKET_ASYNC_OP_TIMEOUT,
	};

	enum mmagic_status write_poll_status =
		mmagic_controller_tcp_write_poll(mmagic_ctrl, &write_poll_cmd_args);

	if (atomic_test_bit(&socket->state, MM_TCP_SOCKET_IS_CLOSING)) {
		goto cleanup;
	} else if (write_poll_status == MMAGIC_STATUS_TIMEOUT) {
		/* If write_poll timeouts, requeue the work to wait until mmagic is ready. */
		k_work_submit_to_queue(&morse_data0.workq, &socket->send_work);
		return;
	} else if (write_poll_status != MMAGIC_STATUS_OK) {
		LOG_ERR("TCP Send: mmagic_controller_tcp_write_poll raised %d.", write_poll_status);
		goto cleanup;
	}

	struct mmagic_core_tcp_send_cmd_args cmd_args = {0};

	int convert_status = convert_host_pkt_to_mm(socket->send_pkt, &cmd_args.buffer);
	if (convert_status != 0) {
		LOG_ERR("TCP Send: Failed to read pkt: %d.", convert_status);
		goto cleanup;
	}

	cmd_args.stream_id = socket->id;

	enum mmagic_status send_status = mmagic_controller_tcp_send(mmagic_ctrl, &cmd_args);

	if (atomic_test_bit(&socket->state, MM_TCP_SOCKET_IS_CLOSING)) {
		goto cleanup;
	} else if (send_status != MMAGIC_STATUS_OK) {
		LOG_ERR("TCP Send: mmagic_controller_tcp_write_poll raised %d.", send_status);
		goto cleanup;
	}

	socket->send_cb(socket->context, net_pkt_get_len(socket->send_pkt), socket->send_user_data);
	return;

cleanup:
	morse_tcp_offload_socket_cleanup_send(socket);
	return;
}

static void morse_tcp_offload_recv_work(struct k_work *work)
{
	MMOSAL_ASSERT(work);

	morse_sd *socket = CONTAINER_OF(work, morse_sd, recv_work);
	MMOSAL_ASSERT(socket);

	if (!atomic_test_bit(&socket->state, MM_TCP_SOCKET_IS_RECV) ||
	    atomic_test_bit(&socket->state, MM_TCP_SOCKET_IS_CLOSING)) {
		goto cleanup;
	}

	struct mmagic_core_tcp_read_poll_cmd_args read_poll_cmd_args = {
		.stream_id = socket->id,
		.timeout = MM_TCP_SOCKET_ASYNC_OP_TIMEOUT,
	};

	enum mmagic_status read_poll_status =
		mmagic_controller_tcp_read_poll(mmagic_ctrl, &read_poll_cmd_args);

	if (!atomic_test_bit(&socket->state, MM_TCP_SOCKET_IS_RECV) ||
	    atomic_test_bit(&socket->state, MM_TCP_SOCKET_IS_CLOSING)) {
		goto cleanup;
	} else if (read_poll_status == MMAGIC_STATUS_TIMEOUT) {
		/* If read_poll timeouts, requeue the work to wait until mmagic is ready. */
		k_work_submit_to_queue(&morse_data0.workq, &socket->recv_work);
		return;
	} else if (read_poll_status != MMAGIC_STATUS_OK) {
		LOG_ERR("TCP Recv: Stopping recv - mmagic_controller_tcp_read_poll raised %d.",
		        read_poll_status);
		goto cleanup;
	}

	struct mmagic_core_tcp_recv_cmd_args recv_cmd_args = {
		.stream_id = socket->id,
		.len = MM_TCP_SOCKET_BUFFER_SIZE,
		.timeout = UINT32_MAX,
	};
	struct mmagic_core_tcp_recv_rsp_args recv_rsp = {0};

	enum mmagic_status recv_status =
		mmagic_controller_tcp_recv(mmagic_ctrl, &recv_cmd_args, &recv_rsp);

	if (!atomic_test_bit(&socket->state, MM_TCP_SOCKET_IS_RECV) ||
	    atomic_test_bit(&socket->state, MM_TCP_SOCKET_IS_CLOSING)) {
		goto cleanup;
	} else if (recv_status != MMAGIC_STATUS_OK) {
		LOG_ERR("TCP Recv: Stopping recv - mmagic_controller_tcp_recv raised %d.",
		        recv_status);
		goto cleanup;
	}

	struct net_pkt *pkt = net_pkt_rx_alloc_with_buffer(morse_iface, recv_rsp.buffer.len,
	                                                   AF_INET, IPPROTO_TCP, K_FOREVER);
	if (pkt == NULL) {
		LOG_ERR("TCP Recv: Stopping recv - failed to alloc pkt.");
		goto cleanup;
	}

	int convert_status = convert_mm_pkt_to_host(&recv_rsp.buffer, pkt);

	if (convert_status != 0) {
		LOG_ERR("TCP Recv: Stopping recv - failed to write pkt: %d.", convert_status);
		goto cleanup;
	}

	socket->recv_cb(socket->context, pkt, NULL, NULL, 0, socket->recv_user_data);

	if (!atomic_test_bit(&socket->state, MM_TCP_SOCKET_IS_RECV) ||
	    atomic_test_bit(&socket->state, MM_TCP_SOCKET_IS_CLOSING)) {
		goto cleanup;
	}

	int k_work_submit_status = k_work_submit_to_queue(&morse_data0.workq, &socket->recv_work);

	if (k_work_submit_status == -EBUSY) {
		LOG_ERR("TCP Recv: Failed to requeue: -EBUSY");
		goto cleanup;
	} else if (k_work_submit_status == -EINVAL) {
		LOG_ERR("TCP Recv: Failed to requeue: -EINVAL");
		goto cleanup;
	} else if (k_work_submit_status == -ENODEV) {
		LOG_ERR("TCP Recv: Failed to requeue: -ENODEV");
		goto cleanup;
	}

	return;

cleanup:
	morse_tcp_offload_socket_cleanup_recv(socket);
	return;
}

static int morse_tcp_offload_recv(struct net_context *context, net_context_recv_cb_t cb,
                                  int32_t timeout, void *user_data)
{
	MMOSAL_ASSERT(context);

	morse_sd *socket = (morse_sd *)context->offload_context;
	MMOSAL_ASSERT(socket);

	if (atomic_test_bit(&socket->state, MM_TCP_SOCKET_IS_RECV)) {
		LOG_ERR("TCP Recv: Already receiving.");
		return -EALREADY;
	}

	atomic_set_bit(&socket->state, MM_TCP_SOCKET_IS_RECV);
	socket->recv_cb = cb;
	socket->recv_user_data = user_data;

	k_work_submit_to_queue(&morse_data0.workq, &socket->recv_work);
	return 0;
}

static int morse_tcp_offload_connect(struct net_context *context, const struct sockaddr *addr,
                                     socklen_t addrlen, net_context_connect_cb_t cb,
                                     int32_t timeout, void *user_data)
{
	MMOSAL_ASSERT(context);
	MMOSAL_ASSERT(addr);

	ARG_UNUSED(timeout);

	struct morse_tcp_sockaddr_in m_addr = {0};
	int m_addr_status =
		convert_host_socket_address_to_mm((const struct sockaddr_in *)addr, &m_addr);
	if (m_addr_status != 0) {
		LOG_ERR("TCP Connect: Failed to parse address.");
		cb(context, -1, user_data);
		return -EINVAL;
	}

	morse_sd *socket = k_malloc(sizeof(morse_sd));

	if (socket == NULL) {
		LOG_ERR("TCP Connect: Failed to k_malloc socket.");
		cb(context, -1, user_data);
		return -ENOMEM;
	}

	struct mmagic_core_tcp_connect_cmd_args cmd_args = {
		.url = m_addr.url,
		.port = m_addr.port,
		.enable_tls = MM_TCP_SOCKET_TLS_DISABLED,
	};

	LOG_INF("TCP connecting to %s:%d", cmd_args.url.data, cmd_args.port);

	struct mmagic_core_tcp_connect_rsp_args rsp = {0};

	enum mmagic_status status = mmagic_controller_tcp_connect(mmagic_ctrl, &cmd_args, &rsp);

	if (status != MMAGIC_STATUS_OK) {
		k_free(socket);
		LOG_ERR("TCP Connect: Connection failed: %d", status);
		cb(context, -1, user_data);
		return -ECONNREFUSED;
	}
	LOG_INF("TCP Connect: Connection established with stream id: %d", rsp.stream_id);

	init_morse_socket_descriptor(socket, rsp.stream_id, m_addr.port, context);
	atomic_set_bit(&socket->state, MM_TCP_SOCKET_IS_CONNECTED);
	context->offload_context = socket;

	cb(context, 0, user_data);
	return 0;
}

static int morse_tcp_offload_send(struct net_pkt *pkt, net_context_send_cb_t cb, int32_t timeout,
                                  void *user_data)
{
	MMOSAL_ASSERT(pkt);
	ARG_UNUSED(timeout);

	struct net_context *context = net_pkt_context(pkt);
	MMOSAL_ASSERT(context);
	morse_sd *socket = (morse_sd *)context->offload_context;
	MMOSAL_ASSERT(socket);

	socket->send_cb = cb;
	socket->send_user_data = user_data;
	socket->send_pkt = net_pkt_ref(pkt);

	k_work_submit_to_queue(&morse_data0.workq, &socket->send_work);

	return 0;
}

static int morse_tcp_offload_put(struct net_context *context)
{
	MMOSAL_ASSERT(context);
	morse_sd *socket = (morse_sd *)context->offload_context;

	if (socket == NULL || !atomic_test_bit(&socket->state, MM_TCP_SOCKET_IS_CONNECTED)) {
		LOG_ERR("TCP Close: Not connected.");
		return -ENOTCONN;
	}

	atomic_set_bit(&socket->state, MM_TCP_SOCKET_IS_CLOSING);
	morse_tcp_offload_socket_cleanup_recv(socket);

	struct mmagic_core_tcp_close_cmd_args cmd_args = {
		.stream_id = socket->id,
	};

	enum mmagic_status status = mmagic_controller_tcp_close(mmagic_ctrl, &cmd_args);

	if (status == MMAGIC_STATUS_OK) {
		atomic_clear_bit(&socket->state, MM_TCP_SOCKET_IS_CONNECTED);
		LOG_INF("TCP connection to stream id closed: %d.", cmd_args.stream_id);
	} else {
		LOG_ERR("TCP Close: Failed: %d.", status);
		return status;
	}

	struct k_work_sync sync;
	k_work_cancel_sync(&socket->recv_work, &sync);

	k_free(socket);
	return 0;
}

/* Unimplemented but required by offload vtable. */
static int morse_tcp_offload_get(sa_family_t family, enum net_sock_type type,
                                 enum net_ip_protocol ip_proto, struct net_context **context)
{
	ARG_UNUSED(context);
	ARG_UNUSED(family);
	ARG_UNUSED(type);
	ARG_UNUSED(ip_proto);
	return 0;
}

/* Unimplemented but required by offload vtable. */
static int morse_tcp_offload_bind(struct net_context *context, const struct sockaddr *addr,
                                  socklen_t addrlen)
{
	ARG_UNUSED(context);
	ARG_UNUSED(addr);
	ARG_UNUSED(addrlen);
	return 0;
}

static struct net_offload morse_tcp_offload_vtable = {
	.get = morse_tcp_offload_get,
	.bind = morse_tcp_offload_bind,
	.connect = morse_tcp_offload_connect,
	.send = morse_tcp_offload_send,
	.recv = morse_tcp_offload_recv,
	.put = morse_tcp_offload_put,
};

static void morse_wifi_iface_init(struct net_if *iface)
{
	morse_iface = iface;

	iface->if_dev->offload = &morse_tcp_offload_vtable;

	net_if_up(iface);
	net_if_dormant_on(iface);
	net_if_carrier_on(iface);
	return;
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

NET_DEVICE_DT_INST_OFFLOAD_DEFINE(0, morse_fs_init, NULL, &morse_data0, &morse_config0,
                                  CONFIG_WIFI_INIT_PRIORITY, &morse_api, NET_ETH_MTU);

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