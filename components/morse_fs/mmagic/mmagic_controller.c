/*
 * Copyright 2025 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "mmosal_controller.h"
#include "mmbuf.h"
#include "mmutils.h"
#include "mmagic_controller.h"
#include "mmagic_datalink_controller.h"

/*
 * ---------------------------------------------------------------------------------------------
 *
 * Agent/Controller shared LLC definitions
 *
 * This must be kept in sync with Agent.
 */

#define MMAGIC_LLC_PROTOCOL_VERSION    1U
MM_STATIC_ASSERT(MMAGIC_LLC_PROTOCOL_VERSION < UINT8_MAX, "Protocol version must be uint8");

/** The maximum size of packets we support */
#define MMAGIC_LLC_MAX_PACKET_SIZE    2048

/** Extracts the packet type from the TSEQ field */
#define MMAGIC_LLC_GET_PTYPE(x)       ((x) >> 4)

/** Extracts the sequence number from the TSEQ field */
#define MMAGIC_LLC_GET_SEQ(x)         ((x) & 0x0F)

/** Gets the next SEQ number */
#define MMAGIC_LLC_GET_NEXT_SEQ(x)    ((x + 1) & 0x0F)

/** Sets the packet type and seq in the the TSEQ field */
#define MMAGIC_LLC_SET_TSEQ(t, s)   (((t) << 4) | (s & 0x0F))

/* An invalid sequence ID that can never be encountered normally */
#define MMAGIC_LLC_INVALID_SEQUENCE   0xFF

/**
 * The LLC uses these packet types to sequence communications between the
 * controller and the agent. This is encoded into 4 bits of the PTYPE/SEQ byte and
 * so is limited to 16 packet type entries at most.
 */
enum mmagic_llc_packet_type
{
    /** This is a command from the controller to the agent */
    MMAGIC_LLC_PTYPE_COMMAND                  = 0,

    /** This is a response from the agent to the controller. */
    MMAGIC_LLC_PTYPE_RESPONSE                 = 1,

    /** This is an unsolicited event from Agent to Controller. */
    MMAGIC_LLC_PTYPE_EVENT                    = 2,

    /** An unspecified error condition has occured */
    MMAGIC_LLC_PTYPE_ERROR                    = 3,

    /** Instructs the agent to reset itself */
    MMAGIC_LLC_PTYPE_AGENT_RESET              = 4,

    /** Notifies the controller that the agent was just reset or started */
    MMAGIC_LLC_PTYPE_AGENT_START_NOTIFICATION = 5,

    /** Notifies the other party that the referenced stream is invalid or not opened yet */
    MMAGIC_LLC_PTYPE_INVALID_STREAM           = 8,

    /** Notifies the other party that a packet was missed due to a gap in the sequence numbers */
    MMAGIC_LLC_PTYPE_PACKET_LOSS_DETECTED     = 9,

    /** Sent by the Controller to request the Agent to send a SYNC_RESP. Does not increment
     *  the sequence number counter. Sequence number counter is ignored by the Agent. */
    MMAGIC_LLC_PTYPE_SYNC_REQ                 = 10,

    /** Sent by the Agent in response to the Controller. Does not increment the sequence number
     *  counter. */
    MMAGIC_LLC_PTYPE_SYNC_RESP                = 11,
};

struct MM_PACKED mmagic_llc_header
{
    /** Packet type and sequence number, cmd is upper nibble, seq is lower nibble */
    uint8_t tseq;
    /** Stream ID */
    uint8_t sid;
    /** Length of the llc packet not including the header. */
    uint16_t length;
};

struct MM_PACKED mmagic_llc_sync_req
{
    /** Token to match respones to requests. */
    uint8_t token[4];
};

struct MM_PACKED mmagic_llc_sync_rsp
{
    /** Token to match respones to requests. */
    uint8_t token[4];
    /** The last seen sequence number for Controller to Agent transmissions. */
    uint8_t last_seen_seq;
    /** LLC protocol version. */
    uint8_t protocol_version;
};

MM_STATIC_ASSERT(MM_MEMBER_SIZE(struct mmagic_llc_sync_req, token) ==
                 MM_MEMBER_SIZE(struct mmagic_llc_sync_rsp, token),
                 "REQ and RESP tokens must match");

MM_STATIC_ASSERT(MM_MEMBER_SIZE(struct mmagic_llc_sync_req, token) == sizeof(uint32_t),
                 "Token must match generated token type");

/** Invalid token value in sync req/resp */
#define INVALID_TOKEN_U32 0U

/*
 * ---------------------------------------------------------------------------------------------
 *
 * Agent/Controller shared M2M API definitions
 *
 * This must be kept in sync with Agent.
 */

/**
 * M2M command header.
 *
 * This is prefixed to M2M command packets.
 */
struct MM_PACKED mmagic_m2m_command_header
{
    /** The subsystem this commend is directed at */
    uint8_t subsystem;
    /** The command to execute */
    uint8_t command;
    /** The subcommand or setting if applicable */
    uint8_t subcommand;
    /** Reserved */
    uint8_t reserved;
};

/**
 * M2M response header.
 *
 * This is prefixed to M2M response packets.
 */
struct MM_PACKED mmagic_m2m_response_header
{
    /** The subsystem this response is from */
    uint8_t subsystem;
    /** The command this response is for */
    uint8_t command;
    /** The subcommand or setting if applicable */
    uint8_t subcommand;
    /** The result code, the response packet is only valid if the result is a success */
    uint8_t result;
};

/**
 * M2M event header.
 *
 * This is prefixed to M2M event packets.
 */
struct MM_PACKED mmagic_m2m_event_header
{
    /** The subsystem this commend is directed at */
    uint8_t subsystem;
    /** The event identifier */
    uint8_t event;
    /** Reserved */
    uint8_t reserved1;
    /** Reserved */
    uint8_t reserved2;
};

/** Enumeration of event identifiers. These are unique within a given subsystem. */
enum mmagic_m2m_event_id
{
    MMAGIC_WLAN_EVT_BEACON_RX         = 1,
    MMAGIC_WLAN_EVT_STANDBY_EXIT      = 2,
    MMAGIC_WLAN_EVT_STA_EVENT         = 3,
    MMAGIC_IP_EVT_LINK_STATUS         = 4,
    MMAGIC_MQTT_EVT_MESSAGE_RECEIVED  = 5,
    MMAGIC_MQTT_EVT_BROKER_CONNECTION = 6,
};

/*
 * ---------------------------------------------------------------------------------------------
 */

/** Maximum number of streams possible. */
#define MMAGIC_LLC_MAX_STREAMS  (8)

struct mmagic_controller
{
    struct
    {
        /** The HAL transport handle */
        struct mmagic_datalink_controller *controller_dl;
        /* The last sequence number we received, used to detect lost/repeat packets */
        uint8_t last_seen_seq;
        /* The sequence number we sent, we increment this by 1 for every new packet sent */
        uint8_t last_sent_seq;
        /* Token for outstanding sync request. Cleared on successful response. */
        volatile uint32_t sync_token;
        /* Status of last sync request. Final status must be set before clearing the sync token. */
        volatile enum mmagic_status sync_status;
    } controller_llc;

    struct
    {
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

    struct mmosal_queue *stream_queue[MMAGIC_LLC_MAX_STREAMS];
    /** The mutex to protect access to the streams @c mmbuf_list and TX path */
    struct mmosal_mutex *tx_mutex;
    /** Callback function to executed any time a event that the agent has started is
     * received. */
    mmagic_controller_agent_start_cb_t agent_start_cb;
    /** User argument that will be passed when the agent_start_cb is executed. */
    void *agent_start_arg;
};

static void mmagic_m2m_controller_rx_callback(struct mmagic_controller *controller, uint8_t sid,
                                              struct mmbuf *rx_buffer);

static void mmagic_m2m_controller_event_rx_callback(struct mmagic_controller *controller,
                                                    uint8_t sid, struct mmbuf *rx_buffer);

/* -------------------------------------------------------------------------------------------- */

void mmagic_controller_register_wlan_beacon_rx_handler(
    struct mmagic_controller *controller,
    mmagic_wlan_beacon_rx_event_handler_t handler,
    void *arg)
{
    controller->event_handlers.wlan_beacon_rx = handler;
    controller->event_handlers.wlan_beacon_rx_arg = arg;
}

void mmagic_controller_register_wlan_standby_exit_handler(
    struct mmagic_controller *controller,
    mmagic_wlan_standby_exit_event_handler_t handler,
    void *arg)
{
    controller->event_handlers.wlan_standby_exit = handler;
    controller->event_handlers.wlan_standby_exit_arg = arg;
}

void mmagic_controller_register_wlan_sta_event_handler(
    struct mmagic_controller *controller,
    mmagic_wlan_sta_event_event_handler_t handler,
    void *arg)
{
    controller->event_handlers.wlan_sta_event = handler;
    controller->event_handlers.wlan_sta_event_arg = arg;
}

void mmagic_controller_register_ip_link_status_handler(
    struct mmagic_controller *controller,
    mmagic_ip_link_status_event_handler_t handler,
    void *arg)
{
    controller->event_handlers.ip_link_status = handler;
    controller->event_handlers.ip_link_status_arg = arg;
}

void mmagic_controller_register_mqtt_message_received_handler(
    struct mmagic_controller *controller,
    mmagic_mqtt_message_received_event_handler_t handler,
    void *arg)
{
    controller->event_handlers.mqtt_message_received = handler;
    controller->event_handlers.mqtt_message_received_arg = arg;
}

void mmagic_controller_register_mqtt_broker_connection_handler(
    struct mmagic_controller *controller,
    mmagic_mqtt_broker_connection_event_handler_t handler,
    void *arg)
{
    controller->event_handlers.mqtt_broker_connection = handler;
    controller->event_handlers.mqtt_broker_connection_arg = arg;
}

/* -------------------------------------------------------------------------------------------- */

struct mmbuf *mmagic_llc_controller_alloc_buffer_for_tx(struct mmagic_controller *controller,
                                                        uint8_t *payload, size_t payload_size)
{
    struct mmbuf *mmbuffer =
        mmagic_datalink_controller_alloc_buffer_for_tx(controller->controller_llc.controller_dl,
                                                       sizeof(struct mmagic_llc_header),
                                                       payload_size);
    if (mmbuffer && payload)
    {
        mmbuf_append_data(mmbuffer, payload, payload_size);
    }

    return mmbuffer;
}

static void mmagic_llc_handle_sync_resp(struct mmagic_controller *controller,
                                        struct mmbuf *rx_buffer)
{
    if (controller->controller_llc.sync_token == INVALID_TOKEN_U32)
    {
        mmosal_printf("MMAGIC_LLC: Unexpected sync response from agent\n");
        return;
    }

    struct mmagic_llc_sync_rsp *sync_resp =
        (struct mmagic_llc_sync_rsp *)mmbuf_remove_from_start(rx_buffer, sizeof(*sync_resp));
    if (sync_resp == NULL)
    {
        mmosal_printf("MMAGIC_LLC: Agent sync response has insufficient length %lu\n",
                      mmbuf_get_data_length(rx_buffer));
        controller->controller_llc.sync_status = MMAGIC_STATUS_ERROR;
        return;
    }

    uint32_t recieved_token = INVALID_TOKEN_U32;
    memcpy(&recieved_token, sync_resp->token, sizeof(sync_resp->token));

    if (recieved_token == INVALID_TOKEN_U32 ||
        recieved_token != controller->controller_llc.sync_token)
    {
        mmosal_printf("MMAGIC_LLC: Agent sync response has bad token %lx, expected %lx\n",
                      recieved_token, controller->controller_llc.sync_token);
        return;
    }

    /* Token was valid. Update status to OK, unless another error is observed */
    enum mmagic_status sync_status = MMAGIC_STATUS_OK;
    if (sync_resp->protocol_version != MMAGIC_LLC_PROTOCOL_VERSION)
    {
        mmosal_printf("MMAGIC_LLC: Agent has wrong protocol version %lu, expected %lu\n",
                      sync_resp->protocol_version, MMAGIC_LLC_PROTOCOL_VERSION);
        sync_status = MMAGIC_STATUS_BAD_VERSION;
    }

    if (sync_resp->last_seen_seq != controller->controller_llc.last_sent_seq)
    {
        mmosal_printf("MMAGIC_LLC: Agent was out of sync %lu, expected %lu\n",
                      sync_resp->last_seen_seq, controller->controller_llc.last_sent_seq);
    }

    /* Clear prev sync token */
    controller->controller_llc.sync_status = sync_status;
    controller->controller_llc.sync_token = INVALID_TOKEN_U32;
}

static void mmagic_llc_controller_rx_callback(struct mmagic_datalink_controller *controller_dl,
                                              void *arg, struct mmbuf *rx_buffer)
{
    MM_UNUSED(controller_dl);
    if (rx_buffer == NULL)
    {
        /* Invalid packet received, ignore */
        mmosal_printf("MMAGIC_LLC: Received NULL packet!\n");
        return;
    }

    struct mmagic_controller *controller = (struct mmagic_controller *)arg;
    uint8_t seq;

    /* Extract received header */
    struct mmagic_llc_header *rxheader =
        (struct mmagic_llc_header *)mmbuf_remove_from_start(rx_buffer, sizeof(*rxheader));

    if (rxheader == NULL)
    {
        /* Invalid packet received, ignore */
        mmosal_printf("MMAGIC_LLC: Packet size too small %lu!\n", mmbuf_get_data_length(rx_buffer));
        /* We haven't seen a new seq number as the packet was invalid. Use the last_seen_seq
         * so the update on exit is a no-op */
        seq = controller->controller_llc.last_seen_seq;
        goto exit;
    }

    uint8_t sid = rxheader->sid;
    seq = MMAGIC_LLC_GET_SEQ(rxheader->tseq);
    enum mmagic_llc_packet_type ptype =
        (enum mmagic_llc_packet_type)MMAGIC_LLC_GET_PTYPE(rxheader->tseq);
    uint16_t length = rxheader->length;

    if (sid >= MMAGIC_LLC_MAX_STREAMS)
    {
        /* Invalid stream received, ignore */
        mmosal_printf("MMAGIC_LLC: Invalid stream ID %u!\n", sid);
        goto exit;
    }

    if (mmbuf_get_data_length(rx_buffer) < length)
    {
        mmosal_printf("MMAGIC_LLC: Buffer smaller than length specified (%u < %u)!\n",
                      mmbuf_get_data_length(rx_buffer), length);
        goto exit;
    }

    /* Ignore if packet is a retransmission of a packet we have already seen, unless it is a
     * recovery packet. */
    if ((seq == controller->controller_llc.last_seen_seq) &&
        (ptype != MMAGIC_LLC_PTYPE_SYNC_RESP) &&
        (ptype != MMAGIC_LLC_PTYPE_AGENT_START_NOTIFICATION))
    {
        mmosal_printf("MMAGIC_LLC: Repeated packet dropped!\n");
        goto exit;
    }

    switch (ptype)
    {
    case MMAGIC_LLC_PTYPE_RESPONSE:
        /* Response from agent, pass to appropriate stream queue */
        mmagic_m2m_controller_rx_callback(controller, sid, rx_buffer);

        /* mmagic_m2m_controller_rx_callback() takes ownership of rx_buffer, so we set the
         * reference to NULL here since we do not want it to be freed when this function
         * returns. */
        rx_buffer = NULL;
        break;

    case MMAGIC_LLC_PTYPE_EVENT:
        mmagic_m2m_controller_event_rx_callback(controller, sid, rx_buffer);

        /* mmagic_m2m_controller_event_rx_callback() takes ownership of rx_buffer, so we set
         * the reference to NULL here since we do not want it to be freed when this function
         * returns. */
        rx_buffer = NULL;
        break;

    case MMAGIC_LLC_PTYPE_ERROR:
        /* Log error and continue for now - we have to handle this explicitly or else we
         * could end up in an 'error loop' with both sides bouncing the error back and
         * forth. */
        mmosal_printf("MMAGIC_LLC: Received error event from agent!\n");
        break;

    case MMAGIC_LLC_PTYPE_AGENT_START_NOTIFICATION:
        mmosal_printf("MMAGIC_LLC: Received agent START event!\n");
        if (controller->agent_start_cb)
        {
            controller->agent_start_cb(controller, controller->agent_start_arg);
        }
        break;

    case MMAGIC_LLC_PTYPE_INVALID_STREAM:
        mmosal_printf("MMAGIC_LLC: Agent reports invalid stream!\n");
        break;

    case MMAGIC_LLC_PTYPE_PACKET_LOSS_DETECTED:
        mmosal_printf("MMAGIC_LLC: Agent reports packet loss!\n");
        break;

    case MMAGIC_LLC_PTYPE_SYNC_RESP:
        mmagic_llc_handle_sync_resp(controller, rx_buffer);
        break;

    case MMAGIC_LLC_PTYPE_COMMAND:
    case MMAGIC_LLC_PTYPE_AGENT_RESET:
    case MMAGIC_LLC_PTYPE_SYNC_REQ:
    default:
        /* We have encountered an unexpected command or error. */
        mmosal_printf("MMAGIC_LLC: Received invalid packet of ptype: %u\n", ptype);
        break;
    }

    /* Check if we missed a packet */
    if ((seq != MMAGIC_LLC_GET_NEXT_SEQ(controller->controller_llc.last_seen_seq)) &&
        (controller->controller_llc.last_seen_seq != MMAGIC_LLC_INVALID_SEQUENCE) &&
        (ptype != MMAGIC_LLC_PTYPE_AGENT_START_NOTIFICATION))
    {
        /* We have encountered an out of order sequence */
        mmosal_printf("MMAGIC_LLC: Observed packet loss - seq num observed: %u expected: %u\n",
                      seq, MMAGIC_LLC_GET_NEXT_SEQ(controller->controller_llc.last_seen_seq));
    }

exit:
    mmbuf_release(rx_buffer);

    /* We always update the last seen sequence number even if we dropped the packet above */
    controller->controller_llc.last_seen_seq = seq;
}

static enum mmagic_status mmagic_llc_controller_tx(struct mmagic_controller *controller,
                                                   enum mmagic_llc_packet_type ptype,
                                                   uint8_t sid, struct mmbuf *tx_buffer)
{
    struct mmagic_llc_header *txheader;
    if (tx_buffer == NULL)
    {
        return MMAGIC_STATUS_INVALID_ARG;
    }

    uint32_t payload_len = mmbuf_get_data_length(tx_buffer);
    if (payload_len > UINT16_MAX)
    {
        mmbuf_release(tx_buffer);
        return MMAGIC_STATUS_INVALID_ARG;
    }

    if (mmbuf_available_space_at_start(tx_buffer) < sizeof(*txheader))
    {
        mmbuf_release(tx_buffer);
        return MMAGIC_STATUS_NO_MEM;
    }

    txheader = (struct mmagic_llc_header *)mmbuf_prepend(tx_buffer, sizeof(*txheader));
    txheader->sid = sid;
    txheader->length = payload_len;

    /* We take the mutex here to make tx_seq transmission thread safe */
    mmosal_mutex_get(controller->tx_mutex, UINT32_MAX);
    uint8_t sent_seq = MMAGIC_LLC_GET_NEXT_SEQ(controller->controller_llc.last_sent_seq);
    txheader->tseq = MMAGIC_LLC_SET_TSEQ(ptype, sent_seq);

    /* Send the buffer - tx_buffer will be freed by mmhal_datalink */
    enum mmagic_status status = MMAGIC_STATUS_TX_ERROR;
    if (mmagic_datalink_controller_tx_buffer(controller->controller_llc.controller_dl,
                                             tx_buffer) > 0)
    {
        /* Update last_sent_seq if datalink indicates data sent */
        status = MMAGIC_STATUS_OK;
        controller->controller_llc.last_sent_seq = sent_seq;
    }
    mmosal_mutex_release(controller->tx_mutex);
    return status;
}

/* -------------------------------------------------------------------------------------------- */

/**
 * Safely convert from an unsigned 8-bit integer value to @ref mmagic_status code.
 *
 * @note While this may look inefficient, the compiler should be smart in optimizing it.
 *
 * @param status The input status code (integer type).
 *
 * @returns The status code (as @c mmagic_status). Unrecognized input values will result in a
 *          return value of @c MMAGIC_STATUS_ERROR.
 */
static enum mmagic_status mmagic_status_from_u8(uint8_t status)
{
    switch (status)
    {
    case MMAGIC_STATUS_OK:
        return MMAGIC_STATUS_OK;

    case MMAGIC_STATUS_ERROR:
        return MMAGIC_STATUS_ERROR;

    case MMAGIC_STATUS_INVALID_ARG:
        return MMAGIC_STATUS_INVALID_ARG;

    case MMAGIC_STATUS_UNAVAILABLE:
        return MMAGIC_STATUS_UNAVAILABLE;

    case MMAGIC_STATUS_TIMEOUT:
        return MMAGIC_STATUS_TIMEOUT;

    case MMAGIC_STATUS_INVALID_STREAM:
        return MMAGIC_STATUS_INVALID_STREAM;

    case MMAGIC_STATUS_NOT_FOUND:
        return MMAGIC_STATUS_NOT_FOUND;

    case MMAGIC_STATUS_NOT_SUPPORTED:
        return MMAGIC_STATUS_NOT_SUPPORTED;

    case MMAGIC_STATUS_TX_ERROR:
        return MMAGIC_STATUS_TX_ERROR;

    case MMAGIC_STATUS_NO_MEM:
        return MMAGIC_STATUS_NO_MEM;

    case MMAGIC_STATUS_CLOSED:
        return MMAGIC_STATUS_CLOSED;

    case MMAGIC_STATUS_CHANNEL_LIST_NOT_SET:
        return MMAGIC_STATUS_CHANNEL_LIST_NOT_SET;

    case MMAGIC_STATUS_SHUTDOWN_BLOCKED:
        return MMAGIC_STATUS_SHUTDOWN_BLOCKED;

    case MMAGIC_STATUS_CHANNEL_INVALID:
        return MMAGIC_STATUS_CHANNEL_INVALID;

    case MMAGIC_STATUS_NOT_RUNNING:
        return MMAGIC_STATUS_NOT_RUNNING;

    case MMAGIC_STATUS_NO_LINK:
        return MMAGIC_STATUS_NO_LINK;

    case MMAGIC_STATUS_UNKNOWN_HOST:
        return MMAGIC_STATUS_UNKNOWN_HOST;

    case MMAGIC_STATUS_SOCKET_FAILED:
        return MMAGIC_STATUS_SOCKET_FAILED;

    case MMAGIC_STATUS_SOCKET_CONNECT_FAILED:
        return MMAGIC_STATUS_SOCKET_CONNECT_FAILED;

    case MMAGIC_STATUS_SOCKET_BIND_FAILED:
        return MMAGIC_STATUS_SOCKET_BIND_FAILED;

    case MMAGIC_STATUS_SOCKET_LISTEN_FAILED:
        return MMAGIC_STATUS_SOCKET_LISTEN_FAILED;

    case MMAGIC_STATUS_NTP_KOD_RECEIVED:
        return MMAGIC_STATUS_NTP_KOD_RECEIVED;

    case MMAGIC_STATUS_NTP_KOD_BACKOFF_RECEIVED:
        return MMAGIC_STATUS_NTP_KOD_BACKOFF_RECEIVED;

    case MMAGIC_STATUS_SOCKET_SEND_FAILED:
        return MMAGIC_STATUS_SOCKET_SEND_FAILED;

    case MMAGIC_STATUS_INVALID_CREDENTIALS:
        return MMAGIC_STATUS_INVALID_CREDENTIALS;

    case MMAGIC_STATUS_HANDSHAKE_FAILED:
        return MMAGIC_STATUS_HANDSHAKE_FAILED;

    case MMAGIC_STATUS_AUTHENTICATION_FAILED:
        return MMAGIC_STATUS_AUTHENTICATION_FAILED;

    case MMAGIC_STATUS_MISSING_CREDENTIALS:
        return MMAGIC_STATUS_MISSING_CREDENTIALS;

    case MMAGIC_STATUS_TIME_NOT_SYNCHRONIZED:
        return MMAGIC_STATUS_TIME_NOT_SYNCHRONIZED;

    case MMAGIC_STATUS_MQTT_REFUSED:
        return MMAGIC_STATUS_MQTT_REFUSED;

    case MMAGIC_STATUS_MQTT_KEEPALIVE_TIMEOUT:
        return MMAGIC_STATUS_MQTT_KEEPALIVE_TIMEOUT;

    case MMAGIC_STATUS_BAD_VERSION:
        return MMAGIC_STATUS_BAD_VERSION;

    default:
        return MMAGIC_STATUS_ERROR;
    }
}

enum mmagic_status mmagic_controller_rx(struct mmagic_controller *controller, uint8_t stream_id,
                                        uint8_t submodule_id, uint8_t command_id,
                                        uint8_t subcommand_id, uint8_t *buffer,
                                        size_t buffer_length, uint32_t timeout_ms)
{
    struct mmbuf *rx_buffer = NULL;
    struct mmagic_m2m_response_header *rx_header;

    if (!mmosal_queue_pop(controller->stream_queue[stream_id], &rx_buffer, timeout_ms))
    {
        return MMAGIC_STATUS_ERROR;
    }

    if (rx_buffer == NULL)
    {
        return MMAGIC_STATUS_ERROR;
    }

    if (stream_id >= MMAGIC_LLC_MAX_STREAMS)
    {
        mmbuf_release(rx_buffer);
        return MMAGIC_STATUS_INVALID_STREAM;
    }

    rx_header = (struct mmagic_m2m_response_header *)mmbuf_remove_from_start(rx_buffer,
                                                                             sizeof(*rx_header));
    if (rx_header == NULL)
    {
        /* Packet too small */
        mmbuf_release(rx_buffer);
        return MMAGIC_STATUS_ERROR;
    }

    size_t payload_len = mmbuf_get_data_length(rx_buffer);
    if (payload_len > buffer_length)
    {
        /* Packet too big */
        mmbuf_release(rx_buffer);
        return MMAGIC_STATUS_ERROR;
    }

    if (rx_header->result != 0)
    {
        /* Error condition indicated by the agent. */
        mmbuf_release(rx_buffer);
        return mmagic_status_from_u8(rx_header->result);
    }

    if (payload_len && buffer == NULL)
    {
        /* No buffer to copy payload into. */
        mmbuf_release(rx_buffer);
        return MMAGIC_STATUS_INVALID_ARG;
    }

    if ((rx_header->command == command_id) && (rx_header->subsystem == submodule_id) &&
        (rx_header->subcommand == subcommand_id))
    {
        if (payload_len)
        {
            /* buffer may be NULL if payload_len is 0 and calling memcpy would be UB. */
            memcpy(buffer, mmbuf_get_data_start(rx_buffer), payload_len);
        }
        mmbuf_release(rx_buffer);
        return MMAGIC_STATUS_OK;
    }

    /* Packet header did not match */
    mmbuf_release(rx_buffer);
    return MMAGIC_STATUS_NOT_FOUND;
}

static void mmagic_m2m_controller_rx_callback(struct mmagic_controller *controller,
                                              uint8_t sid, struct mmbuf *rx_buffer)
{
    if (rx_buffer == NULL)
    {
        return;
    }

    if (sid >= MMAGIC_LLC_MAX_STREAMS)
    {
        /* Invalid stream */
        mmbuf_release(rx_buffer);
        return;
    }

    mmosal_queue_push(controller->stream_queue[sid], &rx_buffer, UINT32_MAX);
}

static void mmagic_m2m_controller_event_rx_callback(struct mmagic_controller *controller,
                                                    uint8_t sid, struct mmbuf *rx_buffer)
{
    struct mmagic_m2m_event_header *rx_header;

    if (rx_buffer == NULL)
    {
        return;
    }

    if (sid != CONTROL_STREAM)
    {
        /* Invalid stream */
        goto cleanup;
    }

    rx_header = (struct mmagic_m2m_event_header *)mmbuf_remove_from_start(
        rx_buffer, sizeof(*rx_header));
    if (rx_header == NULL)
    {
        /* Packet too small */
        goto cleanup;
    }

    switch (rx_header->subsystem)
    {
    case MMAGIC_WLAN:
        switch (rx_header->event)
        {
        case MMAGIC_WLAN_EVT_BEACON_RX:
            if (controller->event_handlers.wlan_beacon_rx != NULL)
            {
                /** Event arguments structure for wlan_beacon_rx */
                struct mmagic_wlan_beacon_rx_event_args *args =
                    (struct mmagic_wlan_beacon_rx_event_args *)
                    mmbuf_remove_from_start(rx_buffer, sizeof(*args));
                if (args == NULL)
                {
                    goto cleanup;
                }

                controller->event_handlers.wlan_beacon_rx(
                    args, controller->event_handlers.wlan_beacon_rx_arg);
            }
            break;

        case MMAGIC_WLAN_EVT_STANDBY_EXIT:
            if (controller->event_handlers.wlan_standby_exit != NULL)
            {
                /** Event arguments structure for wlan_standby_exit */
                struct mmagic_wlan_standby_exit_event_args *args =
                    (struct mmagic_wlan_standby_exit_event_args *)
                    mmbuf_remove_from_start(rx_buffer, sizeof(*args));
                if (args == NULL)
                {
                    goto cleanup;
                }

                controller->event_handlers.wlan_standby_exit(
                    args, controller->event_handlers.wlan_standby_exit_arg);
            }
            break;

        case MMAGIC_WLAN_EVT_STA_EVENT:
            if (controller->event_handlers.wlan_sta_event != NULL)
            {
                /** Event arguments structure for wlan_sta_event */
                struct mmagic_wlan_sta_event_event_args *args =
                    (struct mmagic_wlan_sta_event_event_args *)
                    mmbuf_remove_from_start(rx_buffer, sizeof(*args));
                if (args == NULL)
                {
                    goto cleanup;
                }

                controller->event_handlers.wlan_sta_event(
                    args, controller->event_handlers.wlan_sta_event_arg);
            }
            break;

        default:
            break;
        }
        break;

    case MMAGIC_IP:
        switch (rx_header->event)
        {
        case MMAGIC_IP_EVT_LINK_STATUS:
            if (controller->event_handlers.ip_link_status != NULL)
            {
                /** Event arguments structure for ip_link_status */
                struct mmagic_ip_link_status_event_args *args =
                    (struct mmagic_ip_link_status_event_args *)
                    mmbuf_remove_from_start(rx_buffer, sizeof(*args));
                if (args == NULL)
                {
                    goto cleanup;
                }

                controller->event_handlers.ip_link_status(
                    args, controller->event_handlers.ip_link_status_arg);
            }
            break;

        default:
            break;
        }
        break;

    case MMAGIC_MQTT:
        switch (rx_header->event)
        {
        case MMAGIC_MQTT_EVT_MESSAGE_RECEIVED:
            if (controller->event_handlers.mqtt_message_received != NULL)
            {
                /** Event arguments structure for mqtt_message_received */
                struct mmagic_mqtt_message_received_event_args *args =
                    (struct mmagic_mqtt_message_received_event_args *)
                    mmbuf_remove_from_start(rx_buffer, sizeof(*args));
                if (args == NULL)
                {
                    goto cleanup;
                }

                controller->event_handlers.mqtt_message_received(
                    args, controller->event_handlers.mqtt_message_received_arg);
            }
            break;

        case MMAGIC_MQTT_EVT_BROKER_CONNECTION:
            if (controller->event_handlers.mqtt_broker_connection != NULL)
            {
                /** Event arguments structure for mqtt_broker_connection */
                struct mmagic_mqtt_broker_connection_event_args *args =
                    (struct mmagic_mqtt_broker_connection_event_args *)
                    mmbuf_remove_from_start(rx_buffer, sizeof(*args));
                if (args == NULL)
                {
                    goto cleanup;
                }

                controller->event_handlers.mqtt_broker_connection(
                    args, controller->event_handlers.mqtt_broker_connection_arg);
            }
            break;

        default:
            break;
        }
        break;

    default:
        break;
    }

cleanup:
    mmbuf_release(rx_buffer);
}

enum mmagic_status mmagic_controller_tx(struct mmagic_controller *controller, uint8_t stream_id,
                                        uint8_t submodule_id, uint8_t command_id,
                                        uint8_t subcommand_id,
                                        const uint8_t *buffer, size_t buffer_length)
{
    if (buffer_length && buffer == NULL)
    {
        return MMAGIC_STATUS_INVALID_ARG;
    }

    struct mmagic_m2m_command_header tx_header;
    struct mmbuf *tx_buffer =
        mmagic_llc_controller_alloc_buffer_for_tx(controller, NULL,
                                                  sizeof(struct mmagic_m2m_command_header) +
                                                  buffer_length);
    if (!tx_buffer)
    {
        return MMAGIC_STATUS_NO_MEM;
    }

    tx_header.subsystem = submodule_id;
    tx_header.command = command_id;
    tx_header.subcommand = subcommand_id;
    tx_header.reserved = 0;

    mmbuf_append_data(tx_buffer, (uint8_t *)&tx_header, sizeof(tx_header));
    if (buffer_length)
    {
        /* buffer may be NULL if buffer_length is 0 and calling memcpy would be UB. */
        mmbuf_append_data(tx_buffer, buffer, buffer_length);
    }

    return mmagic_llc_controller_tx(controller, MMAGIC_LLC_PTYPE_COMMAND, stream_id, tx_buffer);
}

enum mmagic_status mmagic_controller_agent_sync(struct mmagic_controller *controller,
                                                uint32_t timeout_ms)
{
    if (controller->controller_llc.sync_token != INVALID_TOKEN_U32)
    {
        mmosal_printf("MMAGIC LLC: No response on previous SYNC\n");
    }

    uint32_t new_token = mmosal_random_u32(INVALID_TOKEN_U32 + 1, UINT32_MAX);
    MMOSAL_DEV_ASSERT(new_token != INVALID_TOKEN_U32);
    struct mmbuf *tx_buffer = mmagic_llc_controller_alloc_buffer_for_tx(controller,
                                                                        (uint8_t *)&new_token,
                                                                        sizeof(new_token));
    if (!tx_buffer)
    {
        return MMAGIC_STATUS_NO_MEM;
    }

    enum mmagic_status status = mmagic_llc_controller_tx(controller, MMAGIC_LLC_PTYPE_SYNC_REQ,
                                                         CONTROL_STREAM,
                                                         tx_buffer);
    if (status != MMAGIC_STATUS_OK)
    {
        return status;
    }
    controller->controller_llc.sync_token = new_token;
    /* We default the status to TIMEOUT. If a sync response is recieved, the status will be updated
     * to reflect the appropriate status. */
    controller->controller_llc.sync_status = MMAGIC_STATUS_TIMEOUT;

    const uint32_t wait_until_ms = mmosal_get_time_ms() + timeout_ms;
    enum { SYNC_POLL_PERIOD_MS = 1, };

    while (controller->controller_llc.sync_token != INVALID_TOKEN_U32)
    {
        if ((timeout_ms != UINT32_MAX) && mmosal_time_has_passed(wait_until_ms))
        {
            break;
        }
        mmosal_task_sleep(SYNC_POLL_PERIOD_MS);
    }
    return controller->controller_llc.sync_status;
}

enum mmagic_status mmagic_controller_request_agent_reset(struct mmagic_controller *controller)
{
    struct mmbuf *tx_buffer = mmagic_llc_controller_alloc_buffer_for_tx(controller, NULL, 0);
    if (!tx_buffer)
    {
        return MMAGIC_STATUS_NO_MEM;
    }

    return mmagic_llc_controller_tx(controller, MMAGIC_LLC_PTYPE_AGENT_RESET, CONTROL_STREAM,
                                    tx_buffer);
}

static struct mmagic_controller m2m_controller;

static struct mmagic_controller *mmagic_controller_get(void)
{
    return &m2m_controller;
}

struct mmagic_controller *mmagic_controller_init(const struct mmagic_controller_init_args *args)
{
    struct mmagic_controller *controller = mmagic_controller_get();
    struct mmagic_datalink_controller_init_args init_args = MMAGIC_DATALINK_CONTROLLER_ARGS_INIT;

    memset(controller, 0, sizeof(*controller));

    controller->agent_start_cb = args->agent_start_cb;
    controller->agent_start_arg = args->agent_start_arg;
    controller->tx_mutex = mmosal_mutex_create("mmagic_llc_agent_datalink");
    if (controller->tx_mutex == NULL)
    {
        return NULL;
    }

    /* Create queues */
    for (int ii = 0; ii < MMAGIC_LLC_MAX_STREAMS; ii++)
    {
        controller->stream_queue[ii] = mmosal_queue_create(1, sizeof(struct mmbuf *), NULL);
        if (controller->stream_queue[ii] == NULL)
        {
            goto error;
        }
    }

    /* Set this to an invalid number so we know we never saw a packet before */
    controller->controller_llc.last_seen_seq = MMAGIC_LLC_INVALID_SEQUENCE;
    /* Set this to an invalid number so we know we never sent a packet before */
    controller->controller_llc.last_sent_seq = MMAGIC_LLC_INVALID_SEQUENCE;

    init_args.rx_callback = mmagic_llc_controller_rx_callback;
    init_args.rx_arg = (void *)controller;
    controller->controller_llc.controller_dl = mmagic_datalink_controller_init(&init_args);
    if (!controller->controller_llc.controller_dl)
    {
        goto error;
    }

    return controller;

error:
    for (int ii = 0; ii < MMAGIC_LLC_MAX_STREAMS; ii++)
    {
        mmosal_queue_delete(controller->stream_queue[ii]);
    }
    return NULL;
}

void mmagic_controller_deinit(struct mmagic_controller *controller)
{
    /* Delete queues */
    for (int ii = 0; ii < MMAGIC_LLC_MAX_STREAMS; ii++)
    {
        mmosal_queue_delete(controller->stream_queue[ii]);
    }

    mmagic_datalink_controller_deinit(controller->controller_llc.controller_dl);
}
