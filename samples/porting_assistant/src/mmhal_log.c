#include <zephyr/kernel.h>
#include "mmhal.h"

void mmhal_log_write(const uint8_t *data, size_t length) {
	printf(data);
}

void mmhal_log_flush(void){

}