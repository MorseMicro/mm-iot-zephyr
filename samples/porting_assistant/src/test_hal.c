
/*
 * Copyright 2023 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "porting_assistant.h"
#include "mmhal.h"
#include "mmutils.h"

TEST_STEP(test_step_enable_leds, "Enable LEDs")
{
    // mmhal_set_led(LED_RED, LED_ON);
    // mmhal_set_led(LED_GREEN, LED_ON);
    // mmhal_set_led(LED_BLUE, LED_ON);

    // TEST_LOG_APPEND("Inspect LEDs (if present/implemented), all should be illuminated.\n\n");

    /* There is no way for us to validate that the LEDs turned on so the USER needs to check */
    return TEST_NO_RESULT;
}
