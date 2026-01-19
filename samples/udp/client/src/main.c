#include <zephyr/kernel.h>

#include "wifi.h"
#include "config.h"

LOG_MODULE_REGISTER(udp_client, LOG_LEVEL_DBG);

int main(void)
{
	int sock = 0;
	struct sockaddr_in servers[N_SERVERS];
	uint16_t ports[N_SERVERS] = {SERVER_PORT_1, SERVER_PORT_2};
	int attempts = 0;
	int rc = 0;

	init_net_mgmt();
	rc = wifi_connect_blocking();
	if (rc) {
		LOG_ERR("wifi_connect_blocking: %d", rc);
		return rc;
	}

	rc = wait_for_network();
	if (rc) {
		LOG_ERR("Network not ready: %d", rc);
		return rc;
	}

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		LOG_ERR("Failed to create socket (%d)", errno);
		return sock;
	}

	for (int i = 0; i < N_SERVERS; i++) {
		servers[i].sin_family = AF_INET;
		servers[i].sin_port = htons(ports[i]);
		inet_pton(AF_INET, SERVER_ADDR, &servers[i].sin_addr);
	}

	while (attempts++ < 10) {
		const char *msg = "Hello from Zephyr\n";
		int ret = sendto(sock, msg, strlen(msg), 0,
				 (struct sockaddr *)&servers[attempts % N_SERVERS],
				 sizeof(servers[attempts % N_SERVERS]));

		if (ret < 0) {
			LOG_ERR("sendto failed (%d)", errno);
		} else {
			LOG_INF("Sent UDP packet");
		}

		k_sleep(K_SECONDS(1));
	}
	return 0;
}
