/*
 * Copyright 2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <zephyr/shell/shell.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_mgmt.h>

#include "morsemicro_mgmt.h"

#if defined(CONFIG_WIFI_MORSEMICRO_AP_MODE)
static int cmd_s1g_bandwidth(const struct shell *sh, size_t argc, char *argv[])
{
	struct net_if *iface = net_if_get_wifi_sap();
	uint8_t bw_mhz;
	int rc;

	ARG_UNUSED(argc);

	if (!iface) {
		shell_error(sh, "No AP interface");
		return -ENODEV;
	}

	bw_mhz = (uint8_t)strtoul(argv[1], NULL, 0);

	rc = net_mgmt(NET_REQUEST_MORSEMICRO_S1G_BANDWIDTH, iface, &bw_mhz, sizeof(bw_mhz));
	if (rc) {
		shell_error(sh, "Failed: %d", rc);
		return rc;
	}

	shell_print(sh, "S1G bandwidth set to %u MHz", bw_mhz);
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(
	morsemicro_ap_cmds,
	SHELL_CMD_ARG(s1g_bandwidth, NULL,
		      "<bw_mhz> - set the S1G operating channel bandwidth before enabling the AP",
		      cmd_s1g_bandwidth, 2, 0),
	SHELL_SUBCMD_SET_END);

SHELL_STATIC_SUBCMD_SET_CREATE(morsemicro_cmds,
			       SHELL_CMD(ap, &morsemicro_ap_cmds, "AP mode commands", NULL),
			       SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(morsemicro, &morsemicro_cmds, "Morse Micro driver commands", NULL);
#endif /* defined(CONFIG_WIFI_MORSEMICRO_AP_MODE) */
