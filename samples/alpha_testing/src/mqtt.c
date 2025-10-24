#include "mqtt.h"

LOG_MODULE_REGISTER(alpha_testing_NETWORKING);

static K_SEM_DEFINE(wifi_conn_sem, 0, 1);
static K_SEM_DEFINE(wifi_disconn_sem, 0, 1);
static K_SEM_DEFINE(net_ready, 0, 1);
static K_SEM_DEFINE(mqtt_conn_sem, 0, 1);

static struct net_mgmt_event_callback wifi_cb;
static struct net_mgmt_event_callback ipv4_cb;
static atomic_t mqtt_is_connected;

extern bool done;

#define BUFFER_SIZE 256
static uint8_t rx_payload_buf[BUFFER_SIZE];
static uint8_t rx_buffer[BUFFER_SIZE];
static uint8_t tx_buffer[BUFFER_SIZE];

/* Global structs */
struct mqtt_client client;
static struct sockaddr_storage broker;
static struct mqtt_topic subscribe_topic = {
	.topic =
		{
			.utf8 = MQTT_SUB_TOPIC,
			.size = sizeof(MQTT_SUB_TOPIC) - 1,
		},
	.qos = MQTT_QOS_1_AT_LEAST_ONCE,
};

static struct mqtt_subscription_list sub_list = {
	.list = &subscribe_topic,
	.list_count = 1,
	.message_id = 1,
};

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
	}
}

int wifi_connect_blocking(void)
{
	struct net_if *iface = net_if_get_first_wifi();
	if (!iface) {
		LOG_ERR("No Wi-Fi interface");
		return -ENODEV;
	}

	net_mgmt_init_event_callback(&wifi_cb, wifi_mgmt_event,
	                             NET_EVENT_WIFI_CONNECT_RESULT |
	                                     NET_EVENT_WIFI_DISCONNECT_RESULT);
	net_mgmt_add_event_callback(&wifi_cb);

	struct wifi_connect_req_params cp = {0};
	cp.ssid = WIFI_SSID;
	cp.ssid_length = strlen(WIFI_SSID);
	cp.psk = WIFI_PSK;
	cp.psk_length = strlen(WIFI_PSK);
	cp.channel = WIFI_CHANNEL_ANY;
	cp.security = WIFI_SECURITY;
	cp.mfp = WIFI_MFP_OPTIONAL;

	LOG_INF("Joining SSID: %s ...", WIFI_SSID);
	int rc = net_mgmt(NET_REQUEST_WIFI_CONNECT, iface, &cp, sizeof(cp));
	if (rc) {
		LOG_ERR("Wi-Fi connect request failed: %d", rc);
		return rc;
	}

	if (k_sem_take(&wifi_conn_sem, K_MSEC(WIFI_TIMEOUT_MS)) != 0) {
		LOG_ERR("Wi-Fi connect timeout");
		return -ETIMEDOUT;
	}
	return 0;
}

int wifi_disconnect_blocking(void)
{
	struct net_if *iface = net_if_get_first_wifi();
	if (!iface) {
		LOG_ERR("No Wi-Fi interface");
		return -ENODEV;
	}

	int rc = net_mgmt(NET_REQUEST_WIFI_DISCONNECT, iface, NULL, 0);

	if (k_sem_take(&wifi_disconn_sem, K_MSEC(WIFI_TIMEOUT_MS)) != 0) {
		LOG_ERR("Wi-Fi disconnect timeout");
		return -ETIMEDOUT;
	}
	return rc;
}

static void ipv4_event_handler(struct net_mgmt_event_callback *cb, uint32_t mgmt_event,
                               struct net_if *iface)
{
	ARG_UNUSED(cb);
	ARG_UNUSED(iface);

	if (mgmt_event == NET_EVENT_IPV4_ADDR_ADD) {
		k_sem_give(&net_ready);
	}
}

int wait_for_network(void)
{
	/* Fire once if already configured, otherwise wait for DHCP. */
	net_mgmt_init_event_callback(&ipv4_cb, ipv4_event_handler, NET_EVENT_IPV4_ADDR_ADD);
	net_mgmt_add_event_callback(&ipv4_cb);

	/* If the interface is already up with an IPv4 address, skip wait. */
	struct net_if *iface = net_if_get_default();
	if (iface && net_if_flag_is_set(iface, NET_IF_UP) &&
	    net_if_ipv4_get_global_addr(iface, NET_ADDR_PREFERRED)) {
		return 0;
	}

	LOG_INF("Waiting for IPv4 address via DHCP…");
	if (k_sem_take(&net_ready, K_SECONDS(30)) == 0) {
		return 0;
	}
	LOG_ERR("No IPv4 address within timeout");
	return -ETIMEDOUT;
}

static void process_resp(struct mqtt_client *const c, const struct mqtt_evt *evt)
{
	const struct mqtt_publish_param *p = &evt->param.publish;
	LOG_INF("Received message on topic %.*s", evt->param.publish.message.topic.topic.size,
	        evt->param.publish.message.topic.topic.utf8);
	if (p->message.payload.len > BUFFER_SIZE) {
		LOG_WRN("Payload too big, truncating");
	}
	uint32_t read_len = MIN(p->message.payload.len, BUFFER_SIZE);

	(void)mqtt_input(c);
	int rc = mqtt_read_publish_payload(c, rx_payload_buf, read_len);
	if (rc < 0) {
		LOG_ERR("mqtt_read_publish_payload failed: %d", rc);
		return;
	}

	/* Null terminate so we can log as string */
	rx_payload_buf[rc] = '\0';
	LOG_INF("Payload: %s", rx_payload_buf);
	done = true;
}

static void mqtt_evt_handler(struct mqtt_client *const c, const struct mqtt_evt *evt)
{
	switch (evt->type) {
	case MQTT_EVT_CONNACK:
		if (evt->result == 0) {
			mqtt_subscribe(&client, &sub_list);
			atomic_set(&mqtt_is_connected, 1);
			k_sem_give(&mqtt_conn_sem);
			LOG_INF("MQTT connected");
		} else {
			LOG_ERR("CONNACK error: %d", evt->result);
		}
		break;
	case MQTT_EVT_DISCONNECT:
		atomic_clear(&mqtt_is_connected);
		LOG_INF("MQTT disconnected (%d)", evt->result);
		break;
	case MQTT_EVT_SUBACK:
		LOG_INF("Subscribed to topic");
		break;
	case MQTT_EVT_PUBLISH:
		process_resp(c, evt);
		break;

	default:
		break;
	}
}

static int resolve_broker(struct sockaddr_storage *broker)
{
	struct sockaddr_in *broker4 = (struct sockaddr_in *)broker;

	memset(broker, 0, sizeof(*broker));
	broker4->sin_family = AF_INET;
	broker4->sin_port = htons(BROKER_PORT);

	int rc = net_addr_pton(AF_INET, BROKER_ADDR, &broker4->sin_addr);
	return rc;
}

int init_mqtt()
{

	int rc = resolve_broker(&broker);
	if (rc) {
		LOG_ERR("Invalid broker address (rc=%d): %s", rc, BROKER_ADDR);
		return rc;
	}

	mqtt_client_init(&client);

	client.broker = (struct sockaddr *)&broker;
	client.evt_cb = mqtt_evt_handler;
	client.client_id.utf8 = (uint8_t *)MQTT_CLIENTID;
	client.client_id.size = strlen(MQTT_CLIENTID);
	client.password = NULL;
	client.user_name = NULL;
	client.protocol_version = MQTT_VERSION_3_1_1;

	client.rx_buf = rx_buffer;
	client.rx_buf_size = sizeof(rx_buffer);
	client.tx_buf = tx_buffer;
	client.tx_buf_size = sizeof(tx_buffer);

	client.transport.type = MQTT_TRANSPORT_NON_SECURE;

	LOG_INF("broker: %p", client.broker);
	LOG_INF("client_id size: %d", client.client_id.size);
	LOG_INF("evt_cb: %p", client.evt_cb);

	LOG_INF("Connecting to %s:%d …", BROKER_ADDR, BROKER_PORT);
	rc = mqtt_connect(&client);
	if (rc) {
		LOG_ERR("mqtt_connect failed: %d", rc);
		return rc;
	}

	int64_t deadline = k_uptime_get() + 8000; /* 8s */
	k_sem_take(&mqtt_conn_sem, K_SECONDS(5));
	while (!atomic_get(&mqtt_is_connected) && k_uptime_get() < deadline) {
		int irc = mqtt_input(&client); /* non-blocking */
		if (irc && irc != -EAGAIN) {
			LOG_WRN("mqtt_input: %d", irc);
		}
		(void)mqtt_live(&client);
		k_sleep(K_MSEC(5)); /* small yield */
	}

	if (!atomic_get(&mqtt_is_connected)) {
		LOG_ERR("MQTT connect timeout");
		(void)mqtt_disconnect(&client);
		return rc;
	}
	return 0;
}
