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
 * mec_queue.h
 *    mec process
 *
 * IDENTIFICATION
 *    src/network/mec/mec_queue.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __MEC_QUEUE_H__
#define __MEC_QUEUE_H__

// MQ = Message Queue
#include "cm_defs.h"
#include "mec.h"
#include "mec_profile.h"
#include "cm_spinlock.h"
#include "cm_thread.h"
#include "compress.h"
#include "cm_sync.h"
#ifdef __cplusplus
extern "C" {
#endif


typedef struct st_dtc_msgitem {
    void *msg;
    struct st_dtc_msgitem *prev;
    struct st_dtc_msgitem *next;
} dtc_msgitem_t;

#ifdef WIN32
typedef struct st_dtc_msgqueue
#else
typedef struct __attribute__((aligned(128))) st_dtc_msgqueue
#endif
{
    spinlock_t       lock;
    volatile uint32  count;
    dtc_msgitem_t *first;
    dtc_msgitem_t *last;
} dtc_msgqueue_t;

void init_msgqueue(dtc_msgqueue_t *queue);

#define MSG_ITEM_BATCH_SIZE         128
#define INIT_MSGITEM_BUFFER_SIZE    8192
#define MAX_POOL_BUFFER_COUNT       8192

typedef struct st_dtc_msgitem_pool {
    spinlock_t       lock;
    dtc_msgitem_t   *buffer[MAX_POOL_BUFFER_COUNT];
    uint16           buf_idx;
    uint16           hwm;
    dtc_msgqueue_t  free_list;
} dtc_msgitem_pool_t;

void init_msgitem_pool(dtc_msgitem_pool_t *pool);
void free_msgitem_pool(dtc_msgitem_pool_t *pool);


#define DTC_MSG_QUEUE_NUM  16

typedef struct st_task_arg {
    spinlock_t lock;
    struct {
        bool32 is_start : 1;
        bool32 is_send : 1;
        bool32 reserved : 30;
    };
    void   *mq_ctx;
    uint32 index;
    compress_t ctx;
    cm_event_t event;
} task_arg_t;

#define MSG_POOL_MAX_EXTENTS      (8)
#define HIGH_MSG_POOL_EXTENT      (8)

typedef struct st_message_pool {
    spinlock_t        lock;
    uint32            msg_len;
    char             *extents[MSG_POOL_MAX_EXTENTS];
    volatile uint32   capacity;
    uint32            count;
    uint32            ext_cnt;
    uint32            free_first;
    volatile uint32   free_count;
    volatile bool32   extending;
    uint32            msg_pool_extent;
    cm_event_t        event;
} message_pool_t;

typedef struct st_msg_item {
    message_pool_t *pool;
    uint32          id;
    uint32          next;
    char            buffer[0];
} msg_item_t;

#define MSG_ITEM_SIZE(pool)                \
    ((pool)->msg_len + sizeof(msg_item_t)) \

#define MSG_GET_ITEMS(pool, id) \
    ((msg_item_t *)((pool)->extents[(id) / (pool)->msg_pool_extent] + \
                 MSG_ITEM_SIZE(pool) * ((id) % (pool)->msg_pool_extent)))

typedef union un_pool_loc {
    uint32 val;
    struct {
        bool32 is_send : 1;
        bool32 priv : 1;
        bool32 reserved : 30;
    };
} pool_loc_t;

typedef struct st_mq_context_t {
    thread_t tasks[MEC_DEFALT_THREAD_NUM + 1];
    task_arg_t  work_thread_idx[MEC_DEFALT_THREAD_NUM + 1];
    // msg queue for session background task, multiple queue to reduce contention
    dtc_msgqueue_t   queue[DTC_MSG_QUEUE_NUM + 1];
    dtc_msgitem_pool_t  pool;
    dtc_msgqueue_t  **channel_private_queue;
    mec_profile_t    *profile;
    void *mec_ctx;
    void *fragment_ctx;
    spinlock_t      private_pool_init_lock;
    uint32          private_msg_pool_extent[PRIV_CEIL];
    message_pool_t *private_pool[CM_MAX_NODE_COUNT][PRIV_CEIL];
    message_pool_t msg_pool[PRIV_CEIL];
} mq_context_t;

dtc_msgitem_t *mec_alloc_msgitem(mq_context_t *mq_ctx, dtc_msgqueue_t *queue);
void put_msgitem(dtc_msgqueue_t *queue, dtc_msgitem_t *msgitem);

void dtc_task_proc(thread_t *thread);
status_t init_dtc_mq_instance(mq_context_t *mq_ctx, bool32 is_send);
status_t mec_alloc_channel_msg_queue(mq_context_t *mq_ctx);
void mec_free_channel_msg_queue(mq_context_t *mq_ctx);
void free_dtc_mq_instance(mq_context_t *mq_ctx);

typedef struct st_mec_perf_stat_t {
    uint64 send_count;
    uint64 send_wait;
    uint64 send_delay;
    uint64 recv_count;
    uint64 recv_delay;
    uint64 compress;
    uint64 origin_size;
    uint64 compress_size;
    uint64 decompress;
} mec_perf_stat_t;

void mec_get_perf_stat(mec_perf_stat_t* perf_stat);
void sync_tasks_closed(mq_context_t *mq_ctx);
status_t dtc_compress(compress_t *compress_ctx, mec_message_head_t *head);
status_t dtc_init_compress(const mec_profile_t *profile, compress_t *compress, bool32 is_compress);

uint32 mec_get_que_count(const mq_context_t *mq_ctx, msg_priv_t priv);
int64 mec_get_mem_capacity(mq_context_t *mq_ctx, msg_priv_t priv);
status_t mec_alloc_msg_item_from_private_pool(message_pool_t **private_pool, msg_item_t **item, uint32 buf_size,
    uint32 private_msg_pool_extent, spinlock_t *private_initlock);
void mec_destory_private_msg_pool(mq_context_t *mq_ctx);


#ifdef __cplusplus
}
#endif


#endif
