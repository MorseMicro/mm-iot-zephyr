/*
 * Copyright 2024 Morse Micro
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @defgroup MMOSAL_CONTROLLER Morse Micro Operating System Abstraction Layer (mmosal) API
 * Controller subset
 *
 * This API provides a layer of abstraction from the underlying operation system. Functionality
 * is provided for RTOS features needed by the Controller.
 *
 * @{
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ---------------------------------------------------------------------------------------------
 */

/**
 * @defgroup MMOSAL_MUTEX Mutex
 *
 * Provides mutex support for mutual exclusion.
 *
 * @{
 */

/**
 * Create a new mutex.
 *
 * @param name The name for the mutex.
 *
 * @returns an opaque handle to the mutex, or @c NULL on failure.
 */
struct mmosal_mutex *mmosal_mutex_create(const char *name);

/**
 * Delete a mutex.
 *
 * @param mutex Handle of mutex to delete
 */
void mmosal_mutex_delete(struct mmosal_mutex *mutex);

/**
 * Acquire a mutex.
 *
 * @param mutex      Handle of mutex to acquire.
 * @param timeout_ms Timeout after which to give up. To wait infinitely use @c UINT32_MAX.
 *
 * @returns @c true if the mutex was acquired successfully otherwise @c false.
 */
bool mmosal_mutex_get(struct mmosal_mutex *mutex, uint32_t timeout_ms);

/**
 * Release a mutex.
 *
 * @param mutex Handle of mutex to release.
 *
 * @returns @c true if the mutex was released successfully otherwise @c false.
 */
bool mmosal_mutex_release(struct mmosal_mutex *mutex);

/**
 * @}
 */

/*
 * ---------------------------------------------------------------------------------------------
 */

/**
 * @defgroup MMOSAL_QUEUE Queues (aka pipes)
 *
 * Provides queue support for inter-task communication.
 *
 * @{
 */

/**
 * Create a new queue.
 *
 * @param num_items The maximum number of items that may be in the queue at a time.
 * @param item_size The size of each item in the queue.
 * @param name      The name of the queue.
 *
 * @returns an opaque handle to the queue, or @c NULL on failure.
 */
struct mmosal_queue *mmosal_queue_create(size_t num_items, size_t item_size, const char *name);

/**
 * Delete a queue.
 *
 * @param queue handle of the queue to delete.
 */
void mmosal_queue_delete(struct mmosal_queue *queue);

/**
 * Pop an item from the queue.
 *
 * @warning May not be invoked from an ISR.
 *
 * @param queue      The queue to pop from.
 * @param item       Pointer to memory to receive the popped item. The item will be copied into
 *                      this memory. The memory size must match the @c item_size given at creation.
 * @param timeout_ms Timeout after which to give up waiting for an item if the queue is empty
 *                      (in milliseconds).
 *
 * @returns @c true if an item was successfully popped, else @c false.
 */
bool mmosal_queue_pop(struct mmosal_queue *queue, void *item, uint32_t timeout_ms);

/**
 * Push an item into the queue.
 *
 * @warning May not be invoked from an ISR.
 *
 * @param queue      The queue to push to.
 * @param item       Pointer to the item to push. This item will be copied into the queue.
 *                      The size of the item must match the @c item_size given at creation.
 * @param timeout_ms Timeout after which to give up waiting for space if the queue is full
 *                      (in milliseconds).
 *
 * @returns @c true if an item was successfully pushed, else @c false.
 */
bool mmosal_queue_push(struct mmosal_queue *queue, const void *item, uint32_t timeout_ms);

/**
 * @}
 */

/**
 * @defgroup MMOSAL_MISC Miscellaneous functions
 *
 * @{
 */

/**
 * Generate a random 32 bit integer within the given range.
 *
 * @param min Minimum value (inclusive).
 * @param max Maximum value (inclusive).
 *
 * @returns a randomly generated integer (min <= i <= max).
 */
uint32_t mmosal_random_u32(uint32_t min, uint32_t max);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

/** @} */
