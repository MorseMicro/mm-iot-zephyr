#ifndef ZEPHYR_DRIVERS_NET_MMAGIC_OFFLOAD_H_
#define ZEPHYR_DRIVERS_NET_MMAGIC_OFFLOAD_H_

#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/spi.h>

#include <zephyr/kernel.h>
#include <zephyr/kernel_includes.h>
#include <zephyr/kernel/thread.h>
#include <zephyr/kernel/thread_stack.h>

#include <zephyr/net/net_context.h>
#include <zephyr/net/net_offload.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/wifi_mgmt.h>

#include "mmosal_controller.h"
#include "mmbuf.h"
#include "mmutils.h"
#include "mmagic_controller.h"
#include "mmagic_datalink_controller.h"
#include "mmhal.h"

/** Maximum number of streams possible. */
#define MMAGIC_LLC_MAX_STREAMS (8)

#define LINK_STATE_TIMEOUT_MS 1500
#define MM_K_STACK_SIZE       2048

/*  TODO - decide if we want to leave this hardcoded or allow user
 *  config. Other drivers hard-code
 */
#define MM_WLAN_CONNECT_TIMEOUT    12000
#define MM_SCAN_TIMEOUT            3000
#define MM_AGENT_ACTION_TIMEOUT_MS 1000

struct morse_data {
	struct k_work_q workq;
	struct k_work scan_work;
	struct k_work connect_work;

	scan_result_cb_t scan_cb;
	bool connect_in_progress;
};

/* Directly copied from MM-IoT-SDK */
struct mmagic_controller {
	struct {
		/** The HAL transport handle */
		struct mmagic_datalink_controller *controller_dl;
		/* The last sequence number we received, used to detect lost/repeat packets */
		uint8_t last_seen_seq;
		/* The sequence number we sent, we increment this by 1 for every new packet sent */
		uint8_t last_sent_seq;
		/* Token for outstanding sync request. Cleared on successful response. */
		volatile uint32_t sync_token;
		/* Status of last sync request. Final status must be set before clearing the sync
		 * token. */
		volatile enum mmagic_status sync_status;
	} controller_llc;

	struct {
		mmagic_wlan_beacon_rx_event_handler_t wlan_beacon_rx;
		void *wlan_beacon_rx_arg;
		mmagic_wlan_standby_exit_event_handler_t wlan_standby_exit;
		void *wlan_standby_exit_arg;
		mmagic_wlan_sta_event_event_handler_t wlan_sta_event;
		void *wlan_sta_event_arg;
		mmagic_ip_link_status_event_handler_t ip_link_status;
		void *ip_link_status_arg;
		mmagic_mqtt_message_received_event_handler_t mqtt_message_received;
		void *mqtt_message_received_arg;
		mmagic_mqtt_broker_connection_event_handler_t mqtt_broker_connection;
		void *mqtt_broker_connection_arg;
	} event_handlers;

	/** Callback function to executed any time a event that the agent has started is
	 * received. */
	mmagic_controller_agent_start_cb_t agent_start_cb;
	/** User argument that will be passed when the agent_start_cb is executed. */
	void *agent_start_arg;
};

#endif /* ZEPHYR_DRIVERS_NET_MMAGIC_OFFLOAD_H_ */
