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
 * cm_chan.h
 *
 *
 * IDENTIFICATION
 *    src/common/cm_struct/cm_chan.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_CHAN_H__
#define __CM_CHAN_H__

#include "cm_spinlock.h"
#include "cm_sync.h"
#include "cm_error.h"
#include "cm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

                        Thread Safe Data Channel

         sender        >==================>        receiver

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
typedef struct st_chan_t {
    uint32 capacity;

    uint32 count;

    uint8 is_closed;
    uint32 ref_count;

    pointer_t *buf;
    pointer_t *buf_end;
    pointer_t *begin;
    pointer_t *end;

    spinlock_t lock;
    cm_event_t event_send;
    cm_event_t event_recv;
    uint32 waittime_ms;
} chan_t;

chan_t *cm_chan_new(uint32 capacity);
status_t cm_chan_send(chan_t *chan, const pointer_t elem);
status_t cm_chan_send_timeout(chan_t *chan, const pointer_t elem, uint32 timeout_ms);
status_t cm_chan_recv(chan_t *chan, pointer_t *elem);
status_t cm_chan_batch_recv(chan_t *chan, pointer_t *elems, uint32 size, uint32 *total);
status_t cm_chan_recv_timeout(chan_t *chan, pointer_t *elem, uint32 timeout_ms);
status_t cm_chan_batch_recv_timeout(chan_t *chan, pointer_t *elems, uint32 size, uint32 *total, uint32 timeout_ms);
bool32 cm_chan_empty(chan_t *chan);
void cm_chan_close(chan_t *chan);
void cm_chan_free(chan_t *q);

#ifdef __cplusplus
}
#endif

#endif

