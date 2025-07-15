/*
 * Copyright 2024 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <sys/types.h>
#include "mmosal.h"
#include "mmhal.h"
#include "errno.h"

#include "morse_log.h"
LOG_MODULE_DECLARE(LOG_MODULE_NAME);

/*
 * For now, assume all critical sections complete without yielding or nesting.
 * This assumption allows us to maintain a single lock key for all mmosal tasks.
 * This could be inserted into thread metadata to support yielding within critical
 * sections, but this is not required now, and requires consideration as the functions
 * using this key would then need to create metadata for calls from non-mmosal threads.
 */
static int irq_lock_key = -1;

/*
 * If an external thread has custom data, we want to reject it. Use a magic
 * identifier.
 */
static const uint32_t mmosal_data_id = 0x4d4f5253;

static void *k_thread_other_custom_data_get(k_tid_t tid)
{
	return tid->custom_data;
}

/** Duration to delay before resetting the device on assert. */
#define DELAY_BEFORE_RESET_MS 1000

void mmosal_log_failure_info(const struct mmosal_failure_info *info)
{
	// stubbed for now
	(void)info;
}

void mmosal_impl_assert(void)
{
	mmosal_task_sleep(DELAY_BEFORE_RESET_MS);
	mmhal_reset();
	while (1) {
	}
}

void *mmosal_malloc(size_t size)
{
	return k_malloc(size);
}

void *mmosal_malloc_dbg(size_t size, const char *name, unsigned line_number)
{
	(void)name;
	(void)line_number;
	return k_malloc(size);
}

void mmosal_free(void *p)
{
	k_free(p);
}

void *mmosal_realloc(void *ptr, size_t size)
{
	return k_realloc(ptr, size);
}

void *mmosal_calloc(size_t nitems, size_t size)
{
	return k_calloc(nitems, size);
}

int mmosal_task_priorities[MMOSAL_TASK_PRI_HIGH + 1] = {
	12, /* MMOSAL_TASK_PRI_IDLE */
	9,  /* MMOSAL_TASK_PRI_MIN */
	6,  /* MMOSAL_TASK_PRI_LOW */
	3,  /* MMOSAL_TASK_PRI_NORM */
	0   /* MMOSAL_TASK_PRI_HIGH */
};

/*
 * For implementation of the mmosal_task functions in Zephyr, we need some storage.
 * We could provide an implementation of mmosal_task, however, doing so introduces
 * difficulty retrieving the active task if the active task was not created with
 * mmosal_task_create, as the pointer does not exist.
 * Instead, construct storage across mmosal created tasks to be carried through thread
 * custom_data. This assumes functions such as mmosal_task_*_critical and
 * mmosal_task_wait_for_notification are only called from mmosal tasks.
 * The mmosal_task pointer can then be an opaque pointer to Zephyrs tid_t and remain
 * compatible with other tasks running in the system.
 */
struct mmosal_task_data {
	struct k_thread tid;
	uint32_t magic;
	k_thread_stack_t *stack;
	struct k_sem sem;
};

/*
 * This thread wrapper just provides a valid Zephyr k_thread_entry_t for the
 * task create function. We will use the thread_abort_hook to tidy up after ourselves
 */
void mmosal_task_fn(void *p1, void *p2, void *p3)
{
	mmosal_task_fn_t task_fn = p1;
	void *argument = p2;
	ARG_UNUSED(p3);

	task_fn(argument);
};

struct mmosal_task_data *mmosal_task_metadata_create(void)
{
	struct mmosal_task_data *data = k_malloc(sizeof(struct mmosal_task_data));
	if (data == NULL) {
		goto exit;
	}
	data->magic = mmosal_data_id;
	data->stack = NULL;
	k_sem_init(&data->sem, 0, 1);
	return data;
exit:
	return NULL;
}

void mmosal_task_metadata_delete(struct mmosal_task_data *data)
{
	k_free(data);
}

void thread_abort_hook(struct k_thread *thread)
{
	struct mmosal_task_data *data = k_thread_other_custom_data_get(thread);

	if (data == NULL) {
		return;
	}

	if (data->magic != mmosal_data_id) {
		return;
	}

	k_thread_stack_free(data->stack);
	data->stack = NULL;
	mmosal_task_metadata_delete(data);
}

struct mmosal_task *mmosal_task_create(mmosal_task_fn_t task_fn, void *argument,
                                       enum mmosal_task_priority priority, unsigned stack_size_u32,
                                       const char *name)
{
	k_tid_t tid;
	struct mmosal_task_data *data = mmosal_task_metadata_create();
	if (data == NULL) {
		goto exit;
	}

	data->stack = k_thread_stack_alloc(sizeof(uint32_t) * stack_size_u32, 0);
	if (data->stack == NULL) {
		goto free_task;
	}

	tid = k_thread_create(&data->tid, data->stack, sizeof(uint32_t) * stack_size_u32,
	                      mmosal_task_fn, task_fn, argument, data,
	                      mmosal_task_priorities[priority], 0, K_FOREVER);

	/* This needs to be set before the thread starts otherwise we could notify too early */
	tid->custom_data = data;
	k_thread_name_set(tid, name);

	k_thread_start(tid);
	return (struct mmosal_task *)tid;

free_task:
	mmosal_task_metadata_delete(data);
exit:
	return NULL;
}

void mmosal_task_delete(struct mmosal_task *task)
{
	k_tid_t tid = (k_tid_t)task;
	if (tid == NULL) {
		tid = k_current_get();
	}

	k_thread_abort(tid);
}

void mmosal_task_join(struct mmosal_task *task)
{
	k_tid_t tid = (k_tid_t)task;
	if (tid == NULL) {
		return;
	}

	if (k_thread_join(tid, K_FOREVER) < 0) {
		LOG_ERR("Unhandled failure in k_thread_join()\n");
	}
}

struct mmosal_task *mmosal_task_get_active(void)
{
	return (struct mmosal_task *)k_current_get();
}

void mmosal_task_yield(void)
{
	k_yield();
}

void mmosal_task_sleep(uint32_t duration_ms)
{
	if (duration_ms > INT32_MAX) {
		k_msleep(INT32_MAX);
		duration_ms -= INT32_MAX;
	}
	k_msleep(duration_ms);
}

void mmosal_task_enter_critical(void)
{
	irq_lock_key = irq_lock();
}

void mmosal_task_exit_critical(void)
{
	irq_unlock(irq_lock_key);
}

void mmosal_disable_interrupts(void)
{
	mmosal_task_enter_critical();
}

void mmosal_enable_interrupts(void)
{
	mmosal_task_exit_critical();
}

const char *mmosal_task_name(void)
{
	return k_thread_name_get(k_current_get());
}

/*
 * We are sometimes called from contexts where a thread was created without using the mmosal
 * functions. In most cases, we should be able to create and inject custom data. However, there
 * is a distinct incompatibility if custom data already exists. Fail spectacularly.
 * The thread_abort_hook will clean up this data.
 */
bool mmosal_task_wait_for_notification(uint32_t timeout_ms)
{
	struct mmosal_task_data *data = k_thread_custom_data_get();
	int ret;

	if (data == NULL) {
		data = mmosal_task_metadata_create();
		k_thread_custom_data_set(data);
	}

	__ASSERT(data->magic == mmosal_data_id, "%s called from incompatible thread: %p", __func__,
	         k_current_get());

	ret = k_sem_take(&data->sem, K_MSEC(timeout_ms));

	return !(ret < 0);
}

/*
 * mmosal_task_notify is only used after being told which task to notify. That task
 * will have had metadata created.
 */
void mmosal_task_notify(struct mmosal_task *task)
{
	struct mmosal_task_data *data = k_thread_other_custom_data_get((k_tid_t)task);

	if (data == NULL) {
		data = mmosal_task_metadata_create();
		k_thread_custom_data_set(data);
	}

	__ASSERT(data->magic, "%s called against incompatible thread: %p", __func__, tid);

	k_sem_give(&data->sem);
}

void mmosal_task_notify_from_isr(struct mmosal_task *task)
{
	mmosal_task_notify(task);
}

struct mmosal_mutex {
	struct k_mutex mutex;
	k_tid_t owner;
	const char *name;
};

// Mutex management functions
struct mmosal_mutex *mmosal_mutex_create(const char *name)
{
	struct mmosal_mutex *mutex = k_malloc(sizeof(struct mmosal_mutex));
	if (mutex == NULL) {
		goto exit;
	}
	mutex->owner = NULL;
	mutex->name = name;
	if (k_mutex_init(&mutex->mutex) != 0) {
		goto free_mutex;
	}

	return mutex;
free_mutex:
	k_free(mutex);
exit:
	return NULL;
}

void mmosal_mutex_delete(struct mmosal_mutex *mutex)
{
	if (mutex == NULL) {
		return;
	}

	mmosal_mutex_release(mutex);
	k_free(mutex);
}

bool mmosal_mutex_get(struct mmosal_mutex *mutex, uint32_t timeout_ms)
{
	if (mutex == NULL) {
		return false;
	}
	if (k_mutex_lock(&mutex->mutex, K_MSEC(timeout_ms)) < 0) {
		return false;
	}

	mutex->owner = k_current_get();

	return true;
}

bool mmosal_mutex_release(struct mmosal_mutex *mutex)
{
	if (mutex == NULL) {
		return false;
	}

	if (k_mutex_unlock(&mutex->mutex) < 0) {
		return false;
	}

	mutex->owner = NULL;

	return true;
}

bool mmosal_mutex_is_held_by_active_task(struct mmosal_mutex *mutex)
{
	if (mutex == NULL) {
		return false;
	}

	volatile k_tid_t task = k_current_get();
	LOG_DBG("%p", task);
	if (mutex->owner == k_current_get()) {
		return true;
	}

	return false;
}

struct mmosal_sem {
	struct k_sem sem;
	int maximum;
};

struct mmosal_sem *mmosal_sem_create(unsigned max_count, unsigned initial_count, const char *name)
{
	(void)name;

	struct mmosal_sem *sem = k_malloc(sizeof(struct mmosal_sem));
	if (sem == NULL) {
		goto exit;
	}

	sem->maximum = max_count;
	if (k_sem_init(&sem->sem, initial_count, max_count) != 0) {
		goto free_sem;
	}

	return sem;
free_sem:
	k_free(sem);
exit:
	return NULL;
}

void mmosal_sem_delete(struct mmosal_sem *sem)
{
	if (sem == NULL) {
		return;
	}
	k_sem_reset(&sem->sem);
	k_free(sem);
}

bool mmosal_sem_give(struct mmosal_sem *sem)
{
	if (k_sem_count_get(&sem->sem) == sem->maximum) {
		return false;
	}
	k_sem_give(&sem->sem);
	return true;
}

bool mmosal_sem_give_from_isr(struct mmosal_sem *sem)
{
	return mmosal_sem_give(sem);
}

bool mmosal_sem_wait(struct mmosal_sem *sem, uint32_t timeout_ms)
{
	if (sem == NULL) {
		return false;
	}

	if (k_sem_take(&sem->sem, K_MSEC(timeout_ms)) < 0) {
		return false;
	}

	return true;
}

uint32_t mmosal_sem_get_count(struct mmosal_sem *sem)
{
	if (sem == NULL) {
		return 0;
	}

	return k_sem_count_get(&sem->sem);
}

struct mmosal_semb *mmosal_semb_create(const char *name)
{
	(void)name;

	struct k_sem *sem = k_malloc(sizeof(struct k_sem));
	if (sem == NULL) {
		goto exit;
	}

	if (k_sem_init(sem, 0, 1) != 0) {
		goto free_sem;
	}

	return (struct mmosal_semb *)sem;
free_sem:
	k_free(sem);
exit:
	return NULL;
}

void mmosal_semb_delete(struct mmosal_semb *sem)
{
	if (sem == NULL) {
		return;
	}
	k_sem_reset((struct k_sem *)sem);
	k_free(sem);
}

bool mmosal_semb_give(struct mmosal_semb *sem)
{
	if (k_sem_count_get((struct k_sem *)sem) == 1) {
		return false;
	}
	k_sem_give((struct k_sem *)sem);
	return true;
}

bool mmosal_semb_give_from_isr(struct mmosal_semb *sem)
{
	return mmosal_semb_give(sem);
}

bool mmosal_semb_wait(struct mmosal_semb *sem, uint32_t timeout_ms)
{
	if (k_sem_take((struct k_sem *)sem, K_MSEC(timeout_ms)) < 0) {
		return false;
	}
	return true;
}

struct mmosal_queue {
	struct k_msgq queue;
	char *buffer;
};

struct mmosal_queue *mmosal_queue_create(size_t num_items, size_t item_size, const char *name)
{
	(void)name;

	struct mmosal_queue *queue = k_malloc(sizeof(struct mmosal_queue));
	if (queue == NULL) {
		goto exit;
	}

	queue->buffer = k_malloc(num_items * item_size);
	if (queue->buffer == NULL) {
		goto free_q;
	}

	k_msgq_init(&queue->queue, queue->buffer, item_size, num_items);

	return queue;
free_q:
	k_free(queue);
exit:
	return NULL;
}

void mmosal_queue_delete(struct mmosal_queue *queue)
{
	k_free(queue->buffer);
	queue->buffer = NULL;
	k_free(queue);
}

static bool mmosal_queue_pop_impl(struct mmosal_queue *queue, void *item, k_timeout_t timeout)
{
	if (queue == NULL) {
		return false;
	}

	if (k_msgq_get(&queue->queue, item, timeout) < 0) {
		return false;
	}

	return true;
}

static bool mmosal_queue_push_impl(struct mmosal_queue *queue, const void *item,
                                   k_timeout_t timeout)
{
	if (queue == NULL) {
		return false;
	}

	if (k_msgq_put(&queue->queue, item, timeout) < 0) {
		return false;
	}
	return true;
}

bool mmosal_queue_pop(struct mmosal_queue *queue, void *item, uint32_t timeout_ms)
{
	return mmosal_queue_pop_impl(queue, item, K_MSEC(timeout_ms));
}

bool mmosal_queue_push(struct mmosal_queue *queue, const void *item, uint32_t timeout_ms)
{
	return mmosal_queue_push_impl(queue, item, K_MSEC(timeout_ms));
}

bool mmosal_queue_pop_from_isr(struct mmosal_queue *queue, void *item)
{
	return mmosal_queue_pop_impl(queue, item, K_NO_WAIT);
}

bool mmosal_queue_push_from_isr(struct mmosal_queue *queue, const void *item)
{
	return mmosal_queue_push_impl(queue, item, K_NO_WAIT);
}

uint32_t mmosal_get_time_ms(void)
{
	return k_uptime_get_32();
}

uint32_t mmosal_get_time_ticks(void)
{
	return (uint32_t)k_uptime_ticks();
}

uint32_t mmosal_ticks_per_second(void)
{
	return k_sec_to_ticks_ceil32(1);
}

struct mmosal_timer {
	struct k_timer timer;
	uint32_t period;
	bool reload;
	timer_callback_t expiry;
	void *arg;
};

static void mmosal_timer_expiry_fn(struct k_timer *timer_id)
{
	struct mmosal_timer *data = (struct mmosal_timer *)k_timer_user_data_get(timer_id);
	if (data == NULL) {
		return;
	}

	data->expiry(data);
}

struct mmosal_timer *mmosal_timer_create(const char *name, uint32_t timer_period_ms,
                                         bool auto_reload, void *arg, timer_callback_t callback)
{
	struct mmosal_timer *timer = k_malloc(sizeof(struct mmosal_timer));
	if (timer == NULL) {
		goto exit;
	}

	timer->period = timer_period_ms;
	timer->reload = auto_reload;
	timer->arg = arg;
	timer->expiry = callback;
	k_timer_init(&timer->timer, mmosal_timer_expiry_fn, NULL);
	k_timer_user_data_set(&timer->timer, timer);
	return timer;
exit:
	return NULL;
}

void mmosal_timer_delete(struct mmosal_timer *timer)
{
	if (timer == NULL) {
		return;
	}

	k_timer_stop(&timer->timer);
	k_free(timer);
}

bool mmosal_timer_start(struct mmosal_timer *timer)
{
	if (timer == NULL) {
		return false;
	}

	k_timer_start(&timer->timer, K_MSEC(timer->period),
	              timer->reload ? K_MSEC(timer->period) : K_FOREVER);

	return true;
}

bool mmosal_timer_stop(struct mmosal_timer *timer)
{
	if (timer == NULL) {
		return false;
	}

	k_timer_stop(&timer->timer);

	return true;
}

bool mmosal_timer_change_period(struct mmosal_timer *timer, uint32_t new_period)
{
	if (timer == NULL) {
		return false;
	}

	timer->period = new_period;
	mmosal_timer_start(timer);

	return true;
}

void *mmosal_timer_get_arg(struct mmosal_timer *timer)
{
	if (timer == NULL) {
		return NULL;
	}

	return timer->arg;
}

bool mmosal_is_timer_active(struct mmosal_timer *timer)
{
	if (timer == NULL) {
		return false;
	}

	return !!k_timer_remaining_get(&timer->timer);
}
