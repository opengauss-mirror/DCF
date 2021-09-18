/*
 * Copyright (c) 2021 Huawei Technologies Co.,Ltd.
 *
 * openGauss is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * cm_chan.c
 *
 *
 * IDENTIFICATION
 *    src/common/cm_struct/cm_chan.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_chan.h"
#include "cm_error.h"
#include "cm_log.h"

// create an new chan
chan_t *cm_chan_new(uint32 capacity)
{
    errno_t rc_memzero;
    uint32 real_size;

    if (capacity == 0) {
        LOG_DEBUG_ERR("cm_chan_new invalid capacity 0");
        return NULL;
    }

    chan_t *chan = (chan_t *)malloc(sizeof(chan_t));
    if (chan == NULL) {
        LOG_DEBUG_ERR("cm_chan_new malloc %lu failed", sizeof(chan_t));
        return NULL;
    }
    rc_memzero = memset_sp(chan, sizeof(chan_t), 0, sizeof(chan_t));
    if (rc_memzero != EOK) {
        CM_FREE_PTR(chan);
        LOG_DEBUG_ERR("cm_chan_new memset_sp failed");
        return NULL;
    }
    chan->capacity = capacity;
    chan->count = 0;
    real_size = sizeof(pointer_t) * capacity;
    if (real_size / capacity != sizeof(pointer_t)) {
        CM_FREE_PTR(chan);
        LOG_DEBUG_ERR("cm_chan_new failed");
        return NULL;
    }
    chan->buf = (pointer_t *)malloc(real_size);
    if (chan->buf == NULL) {
        CM_FREE_PTR(chan);
        LOG_DEBUG_ERR("cm_chan_new malloc %u failed", real_size);
        return NULL;
    }
    rc_memzero = memset_sp(chan->buf, (size_t)real_size, 0, (size_t)real_size);
    if (rc_memzero != EOK) {
        CM_FREE_PTR(chan->buf);
        CM_FREE_PTR(chan);
        LOG_DEBUG_ERR("cm_chan_new memset_sp failed");
        return NULL;
    }
    chan->buf_end = chan->buf + capacity;
    chan->begin = chan->buf;
    chan->end = chan->buf;

    chan->lock = 0;
    (void)cm_event_init(&chan->event_send);
    (void)cm_event_init(&chan->event_recv);
    chan->waittime_ms = 100;

    chan->is_closed = CM_FALSE;
    chan->ref_count = 0;

    return chan;
}

status_t cm_chan_send_timeout(chan_t *chan, const pointer_t elem, uint32 timeout_ms)
{
    if (chan == NULL || elem == NULL) {
        return CM_ERROR;
    }

    cm_spin_lock(&chan->lock, NULL);
    {
        if (chan->buf == NULL || chan->is_closed) {
            cm_spin_unlock(&chan->lock);
            return CM_ERROR;
        }

        // chan is full
        while (chan->count == chan->capacity) {
            cm_spin_unlock(&chan->lock);

            // wait for the recv signal
            if (CM_TIMEDOUT == cm_event_timedwait(&chan->event_recv, timeout_ms)) {
                return CM_TIMEDOUT;
            }

            cm_spin_lock(&chan->lock, NULL);

            if (chan->count < chan->capacity) {
                break;
            }
        }

        // ring
        if (chan->end >= chan->buf_end) {
            chan->end = chan->buf;
        }
        *chan->end = elem;
        chan->end++;
        chan->count++;
    }
    cm_spin_unlock(&chan->lock);

    cm_event_notify(&chan->event_send);

    return CM_SUCCESS;
}

// send an element, will block until there are space to store
status_t cm_chan_send(chan_t *chan, const pointer_t elem)
{
    return cm_chan_send_timeout(chan, elem, 0xFFFFFFFF);
}

// recv an element, will block until there are elems in the chan
status_t cm_chan_recv_timeout(chan_t *chan, pointer_t *elem, uint32 timeout_ms)
{
    if (chan == NULL || elem == NULL) {
        return CM_ERROR;
    }

    cm_spin_lock(&chan->lock, NULL);
    {
        if (chan->buf == NULL) {
            cm_spin_unlock(&chan->lock);
            return CM_ERROR;
        }

        // chan is empty
        while (chan->count == 0) {
            if (chan->is_closed) {
                cm_spin_unlock(&chan->lock);
                return CM_ERROR;
            }

            cm_spin_unlock(&chan->lock);
            if (CM_TIMEDOUT == cm_event_timedwait(&chan->event_send, timeout_ms)) {
                return CM_TIMEDOUT;
            }
            cm_spin_lock(&chan->lock, NULL);

            if (chan->count > 0) {
                break;
            }
        }

        // ring
        if (chan->begin >= chan->buf_end) {
            chan->begin = chan->buf;
        }

        *elem = *chan->begin;
        chan->begin++;
        chan->count--;
    }
    cm_spin_unlock(&chan->lock);

    cm_event_notify(&chan->event_recv);

    return CM_SUCCESS;
}

// send an element, will block until there are space to store
status_t cm_chan_recv(chan_t *chan, pointer_t *elem)
{
    return cm_chan_recv_timeout(chan, elem, 0xFFFFFFFF);
}

// recv an element, will block until there are elems in the chan
status_t cm_chan_batch_recv_timeout(chan_t *chan, pointer_t *elems, uint32 size, uint32 *total, uint32 timeout_ms)
{
    cm_spin_lock(&chan->lock, NULL);
    // chan is empty
    while (chan->count == 0) {
        if (chan->is_closed) {
            cm_spin_unlock(&chan->lock);
            return CM_ERROR;
        }

        cm_spin_unlock(&chan->lock);

        // wait for the send signal
        if (CM_TIMEDOUT == cm_event_timedwait(&chan->event_send, timeout_ms)) {
            return CM_TIMEDOUT;
        }

        cm_spin_lock(&chan->lock, NULL);

        if (chan->count > 0) {
            break;
        }
    }

    *total = MIN(chan->count, size);
    errno_t errcode;
    if (chan->begin + (*total) <= chan->buf_end) {
        errcode = memcpy_sp(elems, size * sizeof(pointer_t), chan->begin, (*total) * sizeof(pointer_t));
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            cm_spin_unlock(&chan->lock);
            return CM_ERROR;
        }
        chan->begin += *total;
    } else {
        uint32 count = (uint32)(chan->buf_end - chan->begin);
        if (count > 0) {
            errcode = memcpy_sp(elems, size * sizeof(pointer_t), chan->begin, count * sizeof(pointer_t));
            if (SECUREC_UNLIKELY(errcode != EOK)) {
                cm_spin_unlock(&chan->lock);
                return CM_ERROR;
            }
        }
        chan->begin   = chan->buf;
        uint32 remain = *total - count;
        errcode = memcpy_sp(elems + count, (size - count) * sizeof(pointer_t), chan->begin, remain * sizeof(pointer_t));
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            cm_spin_unlock(&chan->lock);
            return CM_ERROR;
        }
        chan->begin += remain;
    }
    chan->count -= *total;

    cm_spin_unlock(&chan->lock);

    cm_event_notify(&chan->event_recv);

    return CM_SUCCESS;
}

// send an element, will block until there are space to store
status_t cm_chan_batch_recv(chan_t *chan, pointer_t *elems, uint32 size, uint32 *total)
{
    return cm_chan_batch_recv_timeout(chan, elems, size, total, 0xFFFFFFFF);
}

// is the chan empty
bool32 cm_chan_empty(chan_t *chan)
{
    cm_spin_lock(&chan->lock, NULL);
    if (chan->count == 0) {
        cm_spin_unlock(&chan->lock);
        return CM_TRUE;
    }

    cm_spin_unlock(&chan->lock);
    return CM_FALSE;
}

// close the chan, notify all block sender and receiver to exit
void cm_chan_close(chan_t *chan)
{
    if (chan == NULL) {
        return;
    }

    cm_spin_lock(&chan->lock, NULL);
    if (chan->is_closed) {
        cm_spin_unlock(&chan->lock);
        return;
    }

    chan->is_closed = CM_TRUE;

    for (uint32 i = 0; i < chan->ref_count; i++) {
        cm_event_notify(&chan->event_recv);
        cm_event_notify(&chan->event_send);
    }

    cm_spin_unlock(&chan->lock);
}

// free memory
void cm_chan_free(chan_t *chan)
{
    if (chan == NULL) {
        return;
    }

    cm_event_destory(&chan->event_recv);
    cm_event_destory(&chan->event_send);

    CM_FREE_PTR(chan->buf);
    chan->begin = NULL;
    chan->end = NULL;
    chan->buf_end = NULL;

    chan->capacity = 0;
    chan->count = 0;

    chan->is_closed = CM_TRUE;
    chan->ref_count = 0;

    CM_FREE_PTR(chan);
}
