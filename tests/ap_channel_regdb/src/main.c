/*
 * Copyright 2026 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <zephyr/ztest.h>

#include "wifi_mgmt.c"

#include "mmregdb.h"

/*
 * Sanity sweep of the mmregdb
 *
 * Checks that the required channel parameters can be derived from the primary channel + operating
 * bandwidth
 */

/* Operating bandwidths a primary channel can be paired with. */
static const uint8_t operating_bws_mhz[] = {1, 2, 4, 8};

static const struct mmwlan_s1g_channel *
expected_operating_channel(const struct mmwlan_s1g_channel_list *channel_list,
			   const struct mmwlan_s1g_channel *primary_chan, uint8_t bw_mhz)
{
	for (unsigned int i = 0; i < channel_list->num_channels; i++) {
		const struct mmwlan_s1g_channel *cand = &channel_list->channels[i];
		int32_t half_span_hz = ((int32_t)bw_mhz * 1000000) / 2;
		int32_t freq_delta_hz =
			(int32_t)primary_chan->centre_freq_hz - (int32_t)cand->centre_freq_hz;

		if (cand->bw_mhz == bw_mhz && freq_delta_hz > -half_span_hz &&
		    freq_delta_hz < half_span_hz) {
			return cand;
		}
	}

	return NULL;
}

static void check_primary_channel(const struct mmwlan_s1g_channel_list *channel_list,
				  const struct mmwlan_s1g_channel *primary_chan, uint8_t bw_mhz)
{
	const struct mmwlan_s1g_channel *expected_op;
	uint16_t op_class = 0;
	uint16_t s1g_chan_num = 0;
	uint8_t pri_1mhz_chan_idx = 0;
	uint8_t pri_bw_mhz = 0;
	int ret;

	ret = derive_operating_channel(channel_list, primary_chan->s1g_chan_num, bw_mhz, &op_class,
				       &s1g_chan_num, &pri_1mhz_chan_idx, &pri_bw_mhz);

	/* A primary channel can never be paired with a narrower operating bandwidth. */
	if (bw_mhz < primary_chan->bw_mhz) {
		zassert_equal(
			ret, -ENOENT,
			"%s: primary chan %u (%u MHz) @ operating bw %u MHz: expected to error"
			"got %d",
			channel_list->country_code, primary_chan->s1g_chan_num,
			primary_chan->bw_mhz, bw_mhz, ret);
		return;
	}

	expected_op = expected_operating_channel(channel_list, primary_chan, bw_mhz);

	if (expected_op == NULL) {
		zassert_equal(ret, -ENOENT,
			     "%s: primary chan %u @ operating bw %u MHz: regdb has no matching "
			     "operating channel, but derive_operating_channel returned %d",
			     channel_list->country_code, primary_chan->s1g_chan_num, bw_mhz, ret);
		return;
	}

	zassert_ok(ret,
		  "%s: primary chan %u @ operating bw %u MHz: derive_operating_channel failed "
		  "(%d) despite regdb chan %u being a valid match",
		  channel_list->country_code, primary_chan->s1g_chan_num, bw_mhz, ret,
		  expected_op->s1g_chan_num);

	uint16_t expected_op_class = expected_op->s1g_operating_class != MMWLAN_SKIP_OP_CLASS_CHECK
					     ? (uint16_t)expected_op->s1g_operating_class
					     : (uint16_t)expected_op->global_operating_class;

	zassert_equal(s1g_chan_num, expected_op->s1g_chan_num,
		     "%s: primary chan %u @ operating bw %u MHz: got operating chan %u, regdb "
		     "says %u",
		     channel_list->country_code, primary_chan->s1g_chan_num, bw_mhz,
		     s1g_chan_num, expected_op->s1g_chan_num);

	zassert_equal(op_class, expected_op_class,
		     "%s: primary chan %u @ operating bw %u MHz: got op class %u, regdb says %u",
		     channel_list->country_code, primary_chan->s1g_chan_num, bw_mhz, op_class,
		     expected_op_class);

	zassert_equal(pri_bw_mhz, primary_chan->bw_mhz,
		     "%s: primary chan %u @ operating bw %u MHz: got primary bandwidth %u MHz, "
		     "regdb says %u MHz",
		     channel_list->country_code, primary_chan->s1g_chan_num, bw_mhz, pri_bw_mhz,
		     primary_chan->bw_mhz);

	zassert_true(morsemicro_ap_channel_is_valid(channel_list, op_class, s1g_chan_num, bw_mhz,
						    pri_1mhz_chan_idx),
		    "%s: primary chan %u @ operating bw %u MHz: derived combination (op_class=%u,"
		    " chan=%u, bw=%u, pri_idx=%u) doesn't independently validate against the "
		    "regdb",
		    channel_list->country_code, primary_chan->s1g_chan_num, bw_mhz, op_class,
		    s1g_chan_num, bw_mhz, pri_1mhz_chan_idx);
}

static void check_domain(const struct mmwlan_s1g_channel_list *channel_list)
{
	for (unsigned int i = 0; i < channel_list->num_channels; i++) {
		const struct mmwlan_s1g_channel *primary_chan = &channel_list->channels[i];

		/* Primaries are 1 & 2 MHz */
		if (primary_chan->bw_mhz > 2) {
			continue;
		}

		for (size_t b = 0; b < ARRAY_SIZE(operating_bws_mhz); b++) {
			check_primary_channel(channel_list, primary_chan, operating_bws_mhz[b]);
		}
	}
}

ZTEST(ap_channel_regdb, test_all_regions_all_bandwidths)
{
	const struct mmwlan_regulatory_db *db = get_regulatory_db();

	zassert_not_null(db, "regulatory database not available");
	zassert_true(db->num_domains > 0, "regulatory database has no domains");

	for (unsigned int d = 0; d < db->num_domains; d++) {
		check_domain(db->domains[d]);
	}
}

ZTEST_SUITE(ap_channel_regdb, NULL, NULL, NULL, NULL, NULL);
