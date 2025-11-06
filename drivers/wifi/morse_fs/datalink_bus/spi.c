#include <mmagic_datalink_controller.h>
#include <zephyr/drivers/spi.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/sys/crc.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/wifi_mgmt.h>

LOG_MODULE_REGISTER(datalink_spi, CONFIG_NET_OFFLOAD_LOG_LEVEL);

#define DT_DRV_COMPAT  morse_fs
#define SPI_DEV        DT_COMPAT_GET_ANY_STATUS_OKAY(DT_DRV_COMPAT)
#define SPI_FRAME_BITS 8

#define MMOSAL_TASK_STACK_SIZE 512

#define MMAGIC_DATALINK_RETRY_ATTEMPTS 3

#define MM_CRC_POLY 0x11021

struct mmagic_datalink_controller {
	/** Mutex to protect accessing the bus during transactions. */
	struct mmosal_mutex *spi_mutex;
	/** Callback to execute when an RX packet has been received. */
	mmagic_datalink_controller_rx_buffer_cb_t rx_buffer_callback;
	/** Argument to pass to the callback function. */
	void *rx_buffer_cb_arg;
	/** Flag to indicate that the background rx task should terminate. */
	bool shutdown;

	/** Flag to indicate when the rx_task has finished running. */
	bool rx_task_has_finished;
	/** Task handle for the background rx task. */
	struct mmosal_task *rx_task_handle;

	/** Binary semaphore to signal the receive task when there is data available. */
	struct mmosal_semb *rx_task_semb;

	struct spi_dt_spec spi;

	struct gpio_dt_spec wake;
	struct gpio_dt_spec irq;
	struct gpio_callback irq_cb;
};

struct mmagic_datalink_controller controller = {
	.spi = SPI_DT_SPEC_GET(SPI_DEV,
                               (SPI_LOCK_ON | SPI_OP_MODE_MASTER | SPI_TRANSFER_MSB |
                                SPI_WORD_SET(SPI_FRAME_BITS)),
                               0),
	.wake = GPIO_DT_SPEC_GET(SPI_DEV, wake_gpios),
	.irq = GPIO_DT_SPEC_GET(SPI_DEV, irq_gpios),
};

static bool morse_spi_wait_for_ready_high()
{
	int val = gpio_pin_get_dt(&controller.irq);
	while (val != 1) {
		val = gpio_pin_get_dt(&controller.irq);
	}
	return true;
}

static bool morse_spi_wait_for_ready_low()
{
	int val = gpio_pin_get_dt(&controller.irq);
	while (val != 0) {
		val = gpio_pin_get_dt(&controller.irq);
	}
	return true;
}

void morse_spi_irq_cb(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
	if (!gpio_pin_get_dt(&controller.wake)) {
		mmosal_semb_give_from_isr(controller.rx_task_semb);
	}
}

static int morse_spi_read(struct mmagic_datalink_controller *controller_dl,
                          const struct spi_buf *data, const struct spi_buf *crc_buf)
{
	struct spi_buf_set buffers = {data, 1};
	int ret = spi_read_dt(&controller_dl->spi, &buffers);
	buffers.buffers = crc_buf;
	ret = spi_read_dt(&controller_dl->spi, &buffers);
	return ret;
}

static int morse_spi_write(struct mmagic_datalink_controller *controller_dl,
                           const struct spi_buf *data, const struct spi_buf *crc_buf)
{
	struct spi_buf_set buffers = {data, 1};
	int ret = spi_write_dt(&controller_dl->spi, &buffers);

	buffers.buffers = crc_buf;
	ret = spi_write_dt(&controller_dl->spi, &buffers);
	return ret;
}

static struct mmbuf *controller_rx_buffer(struct mmagic_datalink_controller *controller_dl,
                                          enum mmagic_datalink_payload_type read_type)
{
	uint8_t *data = NULL;
	uint16_t payload_len = 0;
	uint8_t payload_header[MMAGIC_DATALINK_PAYLOAD_HEADER_SIZE] = {read_type};

	mmosal_mutex_get(controller_dl->spi_mutex, UINT32_MAX);
	gpio_pin_set_dt(&controller_dl->wake, 1);
	morse_spi_wait_for_ready_high();
	
	struct mmbuf *rx_buffer = NULL;
	const struct spi_buf header_buffer = {payload_header, MMAGIC_DATALINK_PAYLOAD_HEADER_SIZE};
	uint16_t crc = htons(crc16((uint16_t)MM_CRC_POLY, 0, payload_header,
	                           MMAGIC_DATALINK_PAYLOAD_HEADER_SIZE));
	struct spi_buf crc_buf = {&crc, sizeof(crc)};

	int ret = morse_spi_write(controller_dl, &header_buffer, &crc_buf);
	if (ret != 0) {
		LOG_ERR("Error sending data - %d", ret);
		goto exit;
	}

	morse_spi_wait_for_ready_low();

	struct spi_buf rx_size = {&payload_header[1], 2};
	ret = morse_spi_read(controller_dl, &rx_size, &crc_buf);

	if (ret != 0) {
		LOG_ERR("Error receiving data - %d", ret);
		goto exit;
	}

	payload_len = payload_header[1] << 8 | payload_header[2];

	rx_buffer = mmbuf_alloc_on_heap(0, payload_len);
	if (rx_buffer == NULL) {
		LOG_ERR("Not enough mem to allocate rx_buffer");
		goto exit;
	}

	data = mmbuf_append(rx_buffer, payload_len);

	morse_spi_wait_for_ready_high();

	const struct spi_buf buffer = {data, payload_len};
	ret = morse_spi_read(controller_dl, &buffer, &crc_buf);
	if (ret != 0) {
		LOG_ERR("Error receiving data - %d", ret);
		goto exit;
	}

	morse_spi_wait_for_ready_low();

exit:
	gpio_pin_set_dt(&controller_dl->wake, 0);
	mmosal_mutex_release(controller_dl->spi_mutex);

	return rx_buffer;
}

static struct mmbuf *
mmagic_datalink_controller_rx_buffer(struct mmagic_datalink_controller *controller_dl)
{
	uint8_t attempts = 1;
	struct mmbuf *rx_buf = NULL;
	rx_buf = controller_rx_buffer(controller_dl, MMAGIC_DATALINK_READ);
	while ((attempts < MMAGIC_DATALINK_RETRY_ATTEMPTS) && (!rx_buf)) {
		rx_buf = controller_rx_buffer(controller_dl, MMAGIC_DATALINK_REREAD);
		attempts++;
	}

	return rx_buf;
}

static void mmagic_datalink_controller_rx_task(void *arg)
{
	struct mmagic_datalink_controller *controller_dl = (struct mmagic_datalink_controller *)arg;

	while (!controller_dl->shutdown) {
		mmosal_semb_wait(controller_dl->rx_task_semb, UINT32_MAX);
		struct mmbuf *rx_buf = mmagic_datalink_controller_rx_buffer(controller_dl);
		if (rx_buf != NULL) {
			controller_dl->rx_buffer_callback(controller_dl,
			                                  controller_dl->rx_buffer_cb_arg, rx_buf);
		} else {
			LOG_ERR("Error with controller rx buffer");
		}
	}
	controller_dl->rx_task_has_finished = true;
}

struct mmagic_datalink_controller *
mmagic_datalink_controller_init(const struct mmagic_datalink_controller_init_args *args)
{
	if (!gpio_is_ready_dt(&controller.wake)) {
		LOG_ERR("Wake %s is not ready", controller.wake.port->name);
		return NULL;
	}
	if (!gpio_is_ready_dt(&controller.irq)) {
		LOG_ERR("IRQ %s is not ready", controller.wake.port->name);
		return NULL;
	}
	gpio_pin_configure_dt(&controller.wake, GPIO_OUTPUT_INACTIVE);

	controller.rx_buffer_callback = args->rx_callback;
	controller.rx_buffer_cb_arg = args->rx_arg;
	if (controller.rx_buffer_callback == NULL) {
		/* These are required fields, do not proceed if not present. */
		return NULL;
	}

	controller.spi_mutex = mmosal_mutex_create("mmagic_datalink_spi");
	if (!controller.spi_mutex) {
		return NULL;
	}

	controller.rx_task_semb = mmosal_semb_create("mmagic_datalink_rx");
	if (!controller.rx_task_semb) {
		return NULL;
	}

	controller.rx_task_handle = mmosal_task_create(
		mmagic_datalink_controller_rx_task, &controller, MMOSAL_TASK_PRI_LOW,
		MMOSAL_TASK_STACK_SIZE, "mmagic_datalink_rx");
	if (!controller.rx_task_handle) {
		mmosal_mutex_delete(controller.spi_mutex);
		return NULL;
	}

	gpio_pin_configure_dt(&controller.irq, GPIO_INPUT);
	gpio_pin_interrupt_configure_dt(&controller.irq, GPIO_INT_EDGE_TO_ACTIVE);

	gpio_init_callback(&controller.irq_cb, morse_spi_irq_cb, BIT(controller.irq.pin));
	gpio_add_callback(controller.irq.port, &controller.irq_cb);
	LOG_INF("Set up IRQ Handler at %s pin %d", controller.irq.port->name, controller.irq.pin);

	return &controller;
}

void mmagic_datalink_controller_deinit(struct mmagic_datalink_controller *controller_dl)
{
	return;
}

struct mmbuf *
mmagic_datalink_controller_alloc_buffer_for_tx(struct mmagic_datalink_controller *controller_dl,
                                               size_t header_size, size_t payload_size)
{
	return mmbuf_alloc_on_heap(header_size + MMAGIC_DATALINK_PAYLOAD_HEADER_SIZE, payload_size);
}

int mmagic_datalink_controller_tx_buffer(struct mmagic_datalink_controller *controller_dl,
                                         struct mmbuf *buf)
{
	mmosal_mutex_get(controller_dl->spi_mutex, UINT32_MAX);
	gpio_pin_set_dt(&controller.wake, 1);

	uint8_t payload_header[MMAGIC_DATALINK_PAYLOAD_HEADER_SIZE] = {MMAGIC_DATALINK_WRITE};
	uint16_t payload_len = (uint16_t)mmbuf_get_data_length(buf);
	payload_header[1] = (uint8_t)(payload_len >> 8);
	payload_header[2] = (uint8_t)payload_len;

	uint16_t crc = htons(crc16((uint16_t)MM_CRC_POLY, 0, payload_header,
	                           MMAGIC_DATALINK_PAYLOAD_HEADER_SIZE));

	uint8_t ack = MMAGIC_DATALINK_NACK;

	struct spi_buf crc_buf = {&crc, sizeof(crc)};

	morse_spi_wait_for_ready_high();

	const struct spi_buf header_buffer = {payload_header, MMAGIC_DATALINK_PAYLOAD_HEADER_SIZE};
	int ret = morse_spi_write(controller_dl, &header_buffer, &crc_buf);
	if (ret != 0) {
		LOG_ERR("Error sending data - %d", ret);
		goto exit;
	}

	morse_spi_wait_for_ready_low();

	const struct spi_buf buffer = {mmbuf_get_data_start(buf), payload_len};
	crc = htons(crc16((uint16_t)MM_CRC_POLY, 0, mmbuf_get_data_start(buf), payload_len));
	ret = morse_spi_write(controller_dl, &buffer, &crc_buf);
	if (ret != 0) {
		LOG_ERR("Error sending data - %d", ret);
		goto exit;
	}

	morse_spi_wait_for_ready_high();

	const struct spi_buf tx_buf = {&ack, 1};
	ret = morse_spi_read(controller_dl, &tx_buf, &crc_buf);
	if (ret != 0) {
		LOG_ERR("Error receiving data - %d", ret);
		goto exit;
	}

	morse_spi_wait_for_ready_low();

exit:
	mmbuf_release(buf);
	gpio_pin_set_dt(&controller_dl->wake, 0);
	mmosal_mutex_release(controller_dl->spi_mutex);

	return ack == MMAGIC_DATALINK_ACK ? buf->buf_len : -1;
}
