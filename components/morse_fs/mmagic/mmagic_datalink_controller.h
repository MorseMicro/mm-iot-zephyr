/*
 * Copyright 2024 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @ingroup MMAGIC
 * @defgroup MMAGIC_DATALINK_CONTROLLER Morse M2M Interface Controller Data Link API
 *
 * This API provides the interface between the Controller library and the underlying data
 * link implementation, which is platform and transport specific.
 *
 * @{
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "mmbuf.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup MMAGIC_DATALINK_CONTROLLER_SPI Definitions for SPI data link
 *
 * This must be kept in sync with Agent.
 *
 * @{
 */

/** Size of the payload type field. */
#define MMAGIC_DATALINK_PAYLOAD_TYPE_SIZE (1)
/** Size of the payload length field. */
#define MMAGIC_DATALINK_PAYLOAD_LEN_SIZE (2)
/** Total size of the transfer header. */
#define MMAGIC_DATALINK_PAYLOAD_HEADER_SIZE (MMAGIC_DATALINK_PAYLOAD_TYPE_SIZE + \
                                             MMAGIC_DATALINK_PAYLOAD_LEN_SIZE)

/** Enumeration of data link payload types. */
enum mmagic_datalink_payload_type
{
    MMAGIC_DATALINK_NACK,
    MMAGIC_DATALINK_ACK,
    MMAGIC_DATALINK_WRITE,
    MMAGIC_DATALINK_READ,
    MMAGIC_DATALINK_REREAD,
};

/** @} */

/**
 * Controller struct used internally by the data-link. This will be specific to each
 * type of interface. i.e SPI and UART may have different elements in the struct.
 */
struct mmagic_datalink_controller;

/**
 * Prototype for callback function invoked when the mmagic_datalink_controller receives a data
 * payload.
 *
 * @note The callback function will executed in a thread context.
 *
 * @param controller_dl The datalink handle.
 * @param arg           User argument that was given when the callback was registered.
 * @param buf           mmbuf containing the received data. The callback takes ownership of the
 *                      buffer and is responsible for releasing it.
 */
typedef void (*mmagic_datalink_controller_rx_buffer_cb_t)(
    struct mmagic_datalink_controller *controller_dl,
    void *arg, struct mmbuf *buf);

/**
 * Initialization structure for mmagic_datalink_controller.
 */
struct mmagic_datalink_controller_init_args
{
    /** Callback function to execute when a packet has been received. */
    mmagic_datalink_controller_rx_buffer_cb_t rx_callback;
    /** User argument that will be passed when the rx callback is executed. */
    void *rx_arg;
};

/**
 * Initializer for @ref mmagic_datalink_controller_init_args.
 */
#define MMAGIC_DATALINK_CONTROLLER_ARGS_INIT { 0 }

/**
 * Initialize the mmagic_datalink_controller.
 *
 * @param  args Reference to the initialization arguments for the mmagic_datalink_controller.
 *
 * @return      Reference to the create controller_dl handle on success. @c Null on error.
 */
struct mmagic_datalink_controller *mmagic_datalink_controller_init(
    const struct mmagic_datalink_controller_init_args *args);

/**
 * Deinitialize the mmagic_datalink_controller. Any resources used will be freed.
 *
 * @param controller_dl Reference to the datalink handle.
 */
void mmagic_datalink_controller_deinit(struct mmagic_datalink_controller *controller_dl);

/**
 * Allocates a buffer that can subsequently used with @ref mmagic_datalink_controller_tx_buffer().
 *
 * The allocated buffer may also include additional space at the end of the payload to allow for
 * things like CRC bits.
 *
 * @param  controller_dl Reference to the datalink handle.
 * @param  header_size   The size of any headers that may be required.
 * @param  payload_size  The size of the payload.
 *
 * @return               An @c mmbuf with the required space pre allocated. NULL on error.
 */
struct mmbuf *mmagic_datalink_controller_alloc_buffer_for_tx(
    struct mmagic_datalink_controller *controller_dl,
    size_t header_size,
    size_t payload_size);

/**
 * Transmits the given buffer as a packet to the agent. This function will block until the whole
 * packet has been transmitted or an error occurs. @ref
 * mmagic_datalink_controller_alloc_buffer_for_tx()
 * should be used to allocated the buffer.
 *
 * @param  controller_dl Reference to the datalink handle.
 * @param  buf           The buffer containing the data to be framed and sent to the agent. This
 *                       function takes ownership of the buffer and is responsible for releasing it.
 *
 * @return               The number of bytes transmitted on success. Negative value on error.
 */
int mmagic_datalink_controller_tx_buffer(struct mmagic_datalink_controller *controller_dl,
                                         struct mmbuf *buf);

#ifdef __cplusplus
}
#endif

/** @} */
