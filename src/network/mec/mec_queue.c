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
 * mec_queue.c
 *    mec process
 *
 * IDENTIFICATION
 *    src/network/mec/mec_queue.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_hash.h"
#include "cm_memory.h"
#include "mec_func.h"
#include "compress.h"
#include "cm_utils.h"
#include "cm_timer.h"
#include "util_profile_stat.h"
#include "cb_func.h"

#ifdef __cplusplus
    extern "C" {
#endif

void dtc_recv_proc(mec_context_t *mec_ctx, fragment_ctx_t *fragment_ctx, mec_message_head_t *head);

void put_msgitem_nolock(dtc_msgqueue_t *queue, dtc_msgitem_t *msgitem)
{
    if (queue->count == 0) {
        queue->first = msgitem;
        queue->last = msgitem;
        msgitem->next = NULL;
        msgitem->prev = NULL;
    } else {
        queue->last->next = msgitem;
        msgitem->prev = queue->last;
        queue->last = msgitem;
    }
    msgitem->next = NULL;
    queue->count++;
}


void put_msgitem(dtc_msgqueue_t *queue, dtc_msgitem_t *msgitem)
{
    cm_spin_lock(&queue->lock, NULL);
    put_msgitem_nolock(queue, msgitem);
    cm_spin_unlock(&queue->lock);
}

void get_batch_msgitems(dtc_msgqueue_t *queue, dtc_msgqueue_t *batch, uint32 batch_size)
{
    if (queue->count == 0) {
        return;
    }

    cm_spin_lock(&queue->lock, NULL);
    if (queue->count == 0) {
        cm_spin_unlock(&queue->lock);
        return;
    }
    uint32 size = MIN(batch_size, queue->count);
    batch->first = queue->first;
    for (uint32 loop = 0; loop < size - 1; loop++) {
        CM_ASSERT(queue->first->msg != NULL);
        queue->first = queue->first->next;
    }

    batch->last = queue->first;
    queue->first = queue->first->next;
    if (queue->first != NULL) {
        queue->first->prev = NULL;
    }
    batch->last->next = NULL;
    batch->count = size;

    queue->count -= size;
    if (queue->count == 0) {
        queue->last = NULL;
        queue->first = NULL;
    }

    cm_spin_unlock(&queue->lock);
    return;
}

void put_batch_msgitems_nolock(dtc_msgqueue_t *queue, dtc_msgqueue_t *batch_queue)
{
    if (batch_queue->count == 0) {
        return;
    }

    if (queue->count == 0) {
        *queue = *batch_queue;
    } else {
        queue->last->next = batch_queue->first;
        batch_queue->first->prev = queue->last;
        queue->last = batch_queue->last;
        queue->count += batch_queue->count;
    }
    init_msgqueue(batch_queue);
    return;
}

static inline void get_items_from_free_lst(dtc_msgqueue_t *msgitems, dtc_msgitem_pool_t *pool)
{
    uint32 size = MIN(pool->free_list.count, MSG_ITEM_BATCH_SIZE);
    msgitems->first = pool->free_list.first;
    for (uint32 loop = 0; loop < size - 1; loop++) {
        pool->free_list.first = pool->free_list.first->next;
    }
    msgitems->last = pool->free_list.first;
    pool->free_list.first = pool->free_list.first->next;
    msgitems->last->next = NULL;
    msgitems->count = size;
    if (pool->free_list.first != NULL) {
        pool->free_list.first->prev = NULL;
    }

    pool->free_list.count -= size;
    if (pool->free_list.count == 0) {
        pool->free_list.last = NULL;
        pool->free_list.first = NULL;
    }
}


status_t alloc_msgitems(dtc_msgitem_pool_t *pool, dtc_msgqueue_t *msgitems)
{
    if (pool->free_list.count > 0) {
        cm_spin_lock(&pool->free_list.lock, NULL);
        if (pool->free_list.count > 0) {
            get_items_from_free_lst(msgitems, pool);
            cm_spin_unlock(&pool->free_list.lock);
            return CM_SUCCESS;
        }
        cm_spin_unlock(&pool->free_list.lock);
    }

    dtc_msgitem_t *item = NULL;
    cm_spin_lock(&pool->lock, NULL);
    if (pool->buf_idx == CM_INVALID_ID16 || pool->hwm == MAX_POOL_BUFFER_COUNT) {
        pool->buf_idx++;
        if (pool->buf_idx >= MAX_POOL_BUFFER_COUNT) {
            cm_spin_unlock(&pool->lock);
            return CM_ERROR;
        }
        pool->hwm = 0;
        uint32 size = INIT_MSGITEM_BUFFER_SIZE * sizeof(dtc_msgitem_t);
        pool->buffer[pool->buf_idx] = (dtc_msgitem_t *)malloc(size);
        if (pool->buffer[pool->buf_idx] == NULL) {
            cm_spin_unlock(&pool->lock);
            return CM_ERROR;
        }
        if (memset_sp(pool->buffer[pool->buf_idx], size, 0, size) != EOK) {
            cm_spin_unlock(&pool->lock);
            return CM_ERROR;
        }
    }
    item = (dtc_msgitem_t *)(pool->buffer[pool->buf_idx] + pool->hwm);
    pool->hwm += MSG_ITEM_BATCH_SIZE;
    cm_spin_unlock(&pool->lock);

    msgitems->first = item;
    item->prev = NULL;
    for (uint32 loop = 0; loop < MSG_ITEM_BATCH_SIZE - 1; loop++) {
        item->next = item + 1;
        item = item->next;
        item->prev = item - 1;
    }
    item->next = NULL;
    msgitems->last = item;
    msgitems->count = MSG_ITEM_BATCH_SIZE;
    return CM_SUCCESS;
}


void free_msgitems(dtc_msgitem_pool_t *pool, dtc_msgqueue_t *msgitems)
{
    cm_spin_lock(&pool->free_list.lock, NULL);
    if (pool->free_list.count > 0) {
        pool->free_list.last->next = msgitems->first;
        msgitems->first->prev = pool->free_list.last;
        pool->free_list.last = msgitems->last;
        pool->free_list.count += msgitems->count;
    } else {
        pool->free_list.first = msgitems->first;
        pool->free_list.last = msgitems->last;
        pool->free_list.count = msgitems->count;
    }
    cm_spin_unlock(&pool->free_list.lock);
    init_msgqueue(msgitems);
}

dtc_msgitem_t *mec_alloc_msgitem(mq_context_t *mq_ctx, dtc_msgqueue_t *queue)
{
    dtc_msgitem_t *item = NULL;

    cm_spin_lock(&queue->lock, NULL);
    if (queue->count == 0) {
        if (alloc_msgitems(&mq_ctx->pool, queue) != CM_SUCCESS) {
            cm_spin_unlock(&queue->lock);
            CM_THROW_ERROR_EX(ERR_MEC_CREATE_AREA, "alloc msg item failed");
            return NULL;
        }
    }

    item = queue->first;
    queue->first = item->next;
    if (queue->first != NULL) {
        queue->first->prev = NULL;
    }
    queue->count--;
    if (queue->count == 0) {
        queue->first = NULL;
        queue->last = NULL;
    }
    cm_spin_unlock(&queue->lock);
    CM_ASSERT(item->prev == NULL);
    item->next = NULL;
    item->msg = NULL;
    return item;
}

void init_msgqueue(dtc_msgqueue_t *queue)
{
    queue->lock = 0;
    queue->first = NULL;
    queue->last = NULL;
    queue->count = 0;
}

void init_msgitem_pool(dtc_msgitem_pool_t *pool)
{
    pool->lock = 0;
    pool->buf_idx = CM_INVALID_ID16;
    pool->hwm = 0;
    init_msgqueue(&pool->free_list);
}

void free_msgitem_pool(dtc_msgitem_pool_t *pool)
{
    if (pool->buf_idx == CM_INVALID_ID16) {
        return;
    }

    for (uint16 i = 0; i <= pool->buf_idx; i++) {
        CM_FREE_PTR(pool->buffer[i]);
    }
    pool->buf_idx = CM_INVALID_ID16;
}

#define PROC_DIFF_ENDIAN(head)                                    \
do {                                                              \
    (head)->batch_size = cs_reverse_int16((head)->batch_size);    \
    (head)->src_inst = cs_reverse_uint32((head)->src_inst);       \
    (head)->dst_inst = cs_reverse_uint32((head)->dst_inst);       \
    (head)->stream_id = cs_reverse_uint32((head)->stream_id);     \
    (head)->size = cs_reverse_uint32((head)->size);               \
    (head)->serial_no = cs_reverse_uint32((head)->serial_no);     \
    (head)->frag_no = cs_reverse_uint32((head)->frag_no);         \
    (head)->version = cs_reverse_uint32((head)->version);         \
} while (0)

static mec_perf_stat_t g_mec_perf_stat;

void mec_get_perf_stat(mec_perf_stat_t* perf_stat)
{
    (void)memcpy_s(perf_stat, sizeof(mec_perf_stat_t), &g_mec_perf_stat, sizeof(mec_perf_stat_t));
    (void)memset_s(&g_mec_perf_stat, sizeof(mec_perf_stat_t), 0, sizeof(mec_perf_stat_t));
}

status_t dtc_compress_core(compress_t *compress_ctx, char *write_buf, size_t *write_buf_len)
{
    size_t buf_size = *write_buf_len;
    *write_buf_len = 0;
    // write frame header
    if (compress_begin(compress_ctx) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[MEC]compress frame header failed");
        return CM_ERROR;
    }
    errno_t ret;
    if (compress_ctx->write_len > 0) {
        ret = memcpy_sp(write_buf, buf_size, compress_ctx->out_buf, compress_ctx->write_len);
        MEMS_RETURN_IFERR(ret);
    }

    /* stream data */
    if (compress_stream(compress_ctx, write_buf, buf_size) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[MEC]compress stream failed");
        return CM_ERROR;
    }

    size_t write_len = compress_ctx->write_len;
    /* flush whatever remains within internal buffers */
    if (compress_flush(compress_ctx) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[MEC]compress flush remain data failed");
        return CM_ERROR;
    }
    if (compress_ctx->write_len - write_len > 0) {
        ret = memcpy_sp(write_buf + write_len, buf_size - write_len,
            compress_ctx->out_buf, compress_ctx->write_len - write_len);
        MEMS_RETURN_IFERR(ret);
    }

    *write_buf_len = compress_ctx->write_len;
    return CM_SUCCESS;
}

status_t dtc_compress(compress_t *compress_ctx, mec_message_head_t *head)
{
    if (!CS_COMPRESS(head->flags) || head->size <= sizeof(mec_message_head_t)) {
        CM_BIT_RESET(head->flags, CS_FLAG_COMPRESS);
        return CM_SUCCESS;
    }

    if (compress_init(compress_ctx) != CM_SUCCESS) {
        return CM_ERROR;
    }

    size_t len = head->size - sizeof(mec_message_head_t);
    CM_ASSERT(compress_ctx->in_buf_capcity >= len);
    errno_t ret = memcpy_sp(compress_ctx->in_buf, compress_ctx->in_buf_capcity, (void *)(head + 1), len);
    if (ret != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CM_ERROR;
    }
    compress_ctx->in_chunk_size = len;
    char *write_buf = (char *)(head + 1);
    size_t buf_len = compress_ctx->frag_size;

    if (dtc_compress_core(compress_ctx, write_buf, &buf_len) != CM_SUCCESS) {
        return CM_ERROR;
    }
    head->size = (uint32)(sizeof(mec_message_head_t) + buf_len);
    return CM_SUCCESS;
}


static inline void set_time3(dtc_msgqueue_t *queue, date_t time2)
{
    date_t time3 = g_timer()->now;

    dtc_msgitem_t *msg_item = queue->first;
    mec_message_head_t *head = NULL;
    while (msg_item != NULL) {
        head = (mec_message_head_t *)msg_item->msg;
        g_mec_perf_stat.send_wait += time2 - head->time1;
        g_mec_perf_stat.send_delay += (time3 - time2);
        g_mec_perf_stat.send_count++;
        stat_record(SEND_DELAY, time3 - time2);
        stat_record(SEND_WAIT, time2 - head->time1);
        msg_item = msg_item->next;
    }
}

static status_t dtc_send_proc_core(mec_context_t *mec_ctx, dtc_msgqueue_t *temp_queue,
                                   mec_message_head_t *first_head, cs_pipe_t *pipe)
{
    uint32 batch_size = first_head->batch_size;

    if (batch_size > 1) {
        if (CS_DIFFERENT_ENDIAN(pipe->options)) {
            PROC_DIFF_ENDIAN(first_head);
        }

        if (cs_send_fixed_size(pipe, (char *)first_head, sizeof(mec_message_head_t)) != CM_SUCCESS) {
            return CM_ERROR;
        }
    }

    uint32 size = 0;
    dtc_msgitem_t *msg_item = temp_queue->first;
    mec_message_head_t *head = NULL;
    while (msg_item != NULL) {
        head = (mec_message_head_t *)msg_item->msg;
        size = head->size;
#ifdef DB_MEC_DUMP
        cm_dump_mem(head, head->size);
#endif
        if (CS_DIFFERENT_ENDIAN(pipe->options)) {
            PROC_DIFF_ENDIAN(head);
        }
        if (cs_send_fixed_size(pipe, (char *)head, size) != CM_SUCCESS) {
            return CM_ERROR;
        }
        msg_item = msg_item->next;
        batch_size--;
    }

    CM_ASSERT(batch_size == 0);
    return CM_SUCCESS;
}

void dtc_send_proc(mec_context_t *mec_ctx, const mec_profile_t *profile, dtc_msgqueue_t *temp_queue,
    mec_message_head_t *head)
{
    uint8 channel_id = MEC_STREAM_TO_CHANNEL_ID(head->stream_id, profile->channel_num);
    mec_channel_t *channel = &mec_ctx->channels[head->dst_inst][channel_id];
    msg_priv_t priv = CS_PRIV_LOW(head->flags) ? PRIV_LOW : PRIV_HIGH;
    mec_pipe_t *pipe = &channel->pipe[priv];
    if (cm_atomic32_cas(&pipe->send_need_close, CM_TRUE, CM_FALSE) == CM_TRUE) {
        mec_close_send_pipe(pipe);
        LOG_DEBUG_WAR("[MEC]send pipe to dst_inst[%u] priv[%u] need closed.", head->dst_inst, priv);
        return;
    }

    if (!pipe->send_pipe_active) {
        LOG_DEBUG_ERR("[MEC]send pipe to dst_inst[%u] priv[%u] is not ready.", head->dst_inst, priv);
        return;
    }

    cm_thread_lock(&pipe->send_lock);
    if (!pipe->send_pipe_active) {
        cm_thread_unlock(&pipe->send_lock);
        LOG_DEBUG_ERR("[MEC]send_pipe to dst_inst[%u] priv[%u] is not ready.", head->dst_inst, priv);
        return;
    }

    date_t time2 = g_timer()->now;
    if (dtc_send_proc_core(mec_ctx, temp_queue, head, &pipe->send_pipe) != CM_SUCCESS) {
        cm_thread_unlock(&pipe->send_lock);
        mec_close_send_pipe(pipe);
        int32 code = 0;
        const char *message = NULL;
        cm_get_error(&code, &message);
        LOG_DEBUG_ERR("[MEC]dtc_send_proc_core failed, msg len[%u], src inst[%d], dst inst[%d], "
                      "cmd[%u], flag[%u], stream id[%u], serial no[%u], batch size[%u], "
                      "frag no[%u], err code %d, err msg %s",
                      head->size, head->src_inst, head->dst_inst, head->cmd,
                      head->flags, head->stream_id, head->serial_no, head->batch_size,
                      head->frag_no, code, code == 0 ? "N/A" : message);
        LOG_DEBUG_ERR("[MEC]dtc_send_proc_core failed. disconnect send channel %d, priv %d",
            pipe->channel->id, pipe->priv);
        return;
    }

    cm_thread_unlock(&pipe->send_lock);
    set_time3(temp_queue, time2);
    stat_record(SEND_PACK_SIZE, head->size);
    LOG_DEBUG_INF("[MEC]send message msg finish, len[%u], src inst[%d], dst inst[%d], "
        "cmd[%u], flag[%u], stream id[%u], serial no[%u], batch size[%u], frag no[%u]",
        head->size, head->src_inst, head->dst_inst, head->cmd,
        head->flags, head->stream_id, head->serial_no, head->batch_size, head->frag_no);
    return;
}

static inline void release_temp_msgqueue(dtc_msgqueue_t *temp_queue, dtc_msgqueue_t *finished_msgitem_queue)
{
    dtc_msgitem_t *msg_item = temp_queue->first;
    while (msg_item != NULL) {
        if (msg_item->msg != NULL) {
            mec_release_message_buf(msg_item->msg);
            msg_item->msg = NULL;
        }
        msg_item = msg_item->next;
    }

    put_batch_msgitems_nolock(finished_msgitem_queue, temp_queue);
}

static inline void remove_head_item(dtc_msgitem_t *first_item, dtc_msgqueue_t *batch_queue,
                                    dtc_msgqueue_t *temp_queue)
{
    batch_queue->first = first_item->next;
    if (batch_queue->first != NULL) {
        batch_queue->first->prev = NULL;
    }
    CM_ASSERT(first_item->prev == NULL);
    first_item->next = NULL;
    batch_queue->count--;
    put_msgitem_nolock(temp_queue, first_item);
}

void dtc_put_item(mec_message_head_t *head, dtc_msgitem_t **curr_item,
    dtc_msgqueue_t *batch_queue, dtc_msgqueue_t *temp_queue)
{
    dtc_msgitem_t *next_item;
    mec_message_head_t *head1 = (mec_message_head_t *)(*curr_item)->msg;
    if (!CS_BATCH(head->flags)) {
        head->flags |= CS_FLAG_BATCH;
        head->size += sizeof(mec_message_head_t);
    }
    head->batch_size++;
    head->size += head1->size;
    // remove from batch queue
    if ((*curr_item)->prev != NULL) {
        (*curr_item)->prev->next = (*curr_item)->next;
    }
    if ((*curr_item)->next != NULL) {
        (*curr_item)->next->prev = (*curr_item)->prev;
    }
    if (batch_queue->first == (*curr_item)) {
        batch_queue->first = batch_queue->first->next;
    }
    batch_queue->count--;
    next_item = (*curr_item)->next;
    (*curr_item)->next = NULL;
    put_msgitem_nolock(temp_queue, (*curr_item));
    (*curr_item) = next_item;
}

void dtc_send_batch_proc(mec_context_t *mec_ctx, mec_profile_t *profile, dtc_msgqueue_t *batch_queue,
                         dtc_msgqueue_t *finished_msgitem_queue)
{
    dtc_msgitem_t *curr_item, *first_item;
    mec_message_head_t *head1, head;
    dtc_msgqueue_t temp_queue;
    init_msgqueue(&temp_queue);
    uint32 buf_size = 0;
    while (batch_queue->count > 0) {
        first_item = batch_queue->first;
        head = *((mec_message_head_t *)first_item->msg);
        buf_size = CS_PRIV_LOW(head.flags) ? MEC_ACTL_MSG_BUFFER_SIZE(profile) : MEC_PRIV_MESSAGE_BUFFER_SIZE;
        remove_head_item(first_item, batch_queue, &temp_queue);

        curr_item = batch_queue->first;
        while (curr_item != NULL) {
            head1 = (mec_message_head_t *)curr_item->msg;
            if (head.dst_inst != head1->dst_inst) {
                curr_item = curr_item->next;
                continue;
            }

            if ((head.size + head1->size) >= (buf_size - sizeof(mec_message_head_t))) {
                break;
            }
            dtc_put_item(&head, &curr_item, batch_queue, &temp_queue);
        }

        dtc_send_proc(mec_ctx, profile, &temp_queue, &head);
        release_temp_msgqueue(&temp_queue, finished_msgitem_queue);
    }
}

status_t dtc_decompress_core(compress_t *compress_ctx, mec_message_head_t *head)
{
    if (!CS_COMPRESS(head->flags) || head->size == sizeof(mec_message_head_t)) {
        return CM_SUCCESS;
    }
    if (CS_COMPRESS(head->flags) && compress_ctx->algorithm == COMPRESS_NONE) {
        return CM_ERROR;
    }
    if (compress_init(compress_ctx) != CM_SUCCESS) {
        return CM_ERROR;
    }
    compress_ctx->in_chunk_size = head->size - sizeof(mec_message_head_t);
    CM_ASSERT(compress_ctx->in_buf_capcity >= compress_ctx->in_chunk_size);
    errno_t ret = memcpy_sp(compress_ctx->in_buf, compress_ctx->in_buf_capcity, (char *)(head + 1),
        compress_ctx->in_chunk_size);
    if (ret != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CM_ERROR;
    }
    size_t buf_len = compress_ctx->frag_size;
    if (decompress_stream(compress_ctx, (char *)(head + 1), &buf_len) != CM_SUCCESS) {
        return CM_ERROR;
    }
    head->size = (uint32)(buf_len + sizeof(mec_message_head_t));
    return CM_SUCCESS;
}

status_t dtc_decompress_batch_core(compress_t *compress_ctx, mec_message_head_t *frag_head, mec_message_head_t *head)
{
    if (!CS_COMPRESS(frag_head->flags) || frag_head->size == sizeof(mec_message_head_t)) {
        return CM_SUCCESS;
    }

    if (CS_COMPRESS(frag_head->flags) && compress_ctx->algorithm == COMPRESS_NONE) {
        return CM_ERROR;
    }
    if (compress_init(compress_ctx) != CM_SUCCESS) {
        return CM_ERROR;
    }
    compress_ctx->in_chunk_size = frag_head->size - sizeof(mec_message_head_t);
    compress_ctx->in_buf = (char *)(frag_head + 1);

    size_t buf_len = compress_ctx->frag_size;
    if (decompress_stream(compress_ctx, (char *)(head + 1), &buf_len) != CM_SUCCESS) {
        return CM_ERROR;
    }
    head->size = (uint32)(buf_len + sizeof(mec_message_head_t));
    return CM_SUCCESS;
}

status_t dtc_proc_batch_core(mec_context_t *mec_ctx, fragment_ctx_t *fragment_ctx, mec_message_head_t *head)
{
    int32 batch_size = head->batch_size;
    uint32 remain_size = (uint32)(head->size - sizeof(mec_message_head_t));
    CM_ASSERT(batch_size > 1);

    msg_priv_t head_priv = CS_PRIV_LOW(head->flags) ? PRIV_LOW : PRIV_HIGH;
    mec_message_head_t *temp_head = head + 1;
    while (batch_size > 0) {
        CM_ASSERT(!CS_COMPRESS(temp_head->flags));
        msg_priv_t cur_priv = CS_PRIV_LOW(temp_head->flags) ? PRIV_LOW : PRIV_HIGH;
        if (cur_priv != head_priv || remain_size < temp_head->size
            || remain_size < (uint32)sizeof(mec_message_head_t)) {
            LOG_DEBUG_ERR("[MEC]batchc err: cur_priv %u, head_priv %u, cur_size %u, remain_size %u, src %u",
                cur_priv, head_priv, temp_head->size, remain_size, head->src_inst);
            return CM_ERROR;
        }
        dtc_recv_proc(mec_ctx, fragment_ctx, temp_head);
        temp_head = (mec_message_head_t *)((char *)temp_head + temp_head->size);
        batch_size--;
        remain_size -= temp_head->size;
    }
    return CM_SUCCESS;
}
status_t dtc_decompress_batch(compress_t *compress_ctx, mec_context_t *mec_ctx,
                              fragment_ctx_t *fragment_ctx, mec_message_head_t *head)
{
    int32 batch_size = head->batch_size;
    msg_priv_t head_priv = CS_PRIV_LOW(head->flags) ? PRIV_LOW : PRIV_HIGH;
    CM_ASSERT(batch_size > 1);
    char *inbuf = compress_ctx->in_buf;
    size_t inbuf_capcity = compress_ctx->in_buf_capcity;
    CM_ASSERT(compress_ctx->in_buf_capcity >= head->size - sizeof(mec_message_head_t));
    errno_t ret = memcpy_sp(inbuf, inbuf_capcity, (char *)(head + 1), head->size - sizeof(mec_message_head_t));
    if (ret != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CM_ERROR;
    }
    mec_message_head_t *temp_head = (mec_message_head_t *)inbuf;
    while (batch_size > 0) {
        *head = *temp_head;
        date_t time2 = g_timer()->now;
        if (dtc_decompress_batch_core(compress_ctx, (mec_message_head_t *)temp_head, head) != CM_SUCCESS) {
            compress_ctx->in_buf = inbuf;
            compress_ctx->in_buf_capcity = inbuf_capcity;
            return CM_ERROR;
        }
        g_mec_perf_stat.decompress += g_timer()->now - time2;
        msg_priv_t cur_priv = CS_PRIV_LOW(head->flags) ? PRIV_LOW : PRIV_HIGH;
        if (cur_priv != head_priv) {
            LOG_DEBUG_ERR("[MEC]dec err:cur_priv %u not equal with head_priv %u, src %u",
                cur_priv, head_priv, head->src_inst);
            return CM_ERROR;
        }
        dtc_recv_proc(mec_ctx, fragment_ctx, head);

        temp_head = (mec_message_head_t *)((char *)temp_head + temp_head->size);
        batch_size--;
    }

    compress_ctx->in_buf = inbuf;
    compress_ctx->in_buf_capcity = inbuf_capcity;
    return CM_SUCCESS;
}

status_t dtc_proc_batch(task_arg_t *arg, mec_message_head_t *head)
{
    compress_t *compress_ctx = &arg->ctx;
    mq_context_t *mq_ctx = (mq_context_t *)arg->mq_ctx;
    mec_context_t *mec_ctx = (mec_context_t *)mq_ctx->mec_ctx;
    fragment_ctx_t *fragment_ctx = (fragment_ctx_t *)mq_ctx->fragment_ctx;

    if (CS_BATCH(head->flags)) {
        if (compress_ctx->algorithm == COMPRESS_NONE) {
            return dtc_proc_batch_core(mec_ctx, fragment_ctx, head);
        } else {
            return dtc_decompress_batch(compress_ctx, mec_ctx, fragment_ctx, head);
        }
    }

    date_t time2 = g_timer()->now;
    CM_RETURN_IFERR(dtc_decompress_core(compress_ctx, head));
    g_mec_perf_stat.decompress += g_timer()->now - time2;
    dtc_recv_proc(mec_ctx, fragment_ctx, head);
    return CM_SUCCESS;
}


static void dtc_proc_more_data(fragment_ctx_t *fragment_ctx, mec_message_head_t *head)
{
    fragment_key_t key;
    FILL_FRAGMENT_KEY(head, key);
    uint32 hash_key = cm_hash_bytes((const uint8 *)&key, sizeof(fragment_key_t), FRAGMENT_BUCKETS);
    fragment_bucket_t *bucket = &fragment_ctx->buckets[hash_key];
    fragment_ctrl_t *ctrl = NULL;
    uint32 del_sn;

    ctrl = find_fragment_ctrl(bucket, &key);
    if (head->frag_no == 0) {
        if (ctrl != NULL) {
            LOG_DEBUG_WAR("[MEC]first_frag ctrl not null. src inst[%d], frag_no[%u], serial no[%u], batch size[%u], "
                          "err code %d, err msg %s",
                          head->src_inst, head->frag_no, head->serial_no, head->batch_size,
                          cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
            goto error;
        }

        if (insert_fragment_pack(head, bucket) != CM_SUCCESS) {
            LOG_DEBUG_WAR("[MEC]first_frag insert fail. src inst[%d], frag_no[%u], serial no[%u], batch size[%u], "
                          "err code %d, err msg %s",
                          head->src_inst, head->frag_no, head->serial_no, head->batch_size,
                          cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
            return;
        }
    } else {
        if (ctrl == NULL) {
            LOG_DEBUG_WAR("[MEC]non_first_frag ctrl null. src inst[%d], frag_no[%u], serial no[%u], batch size[%u], "
                          "err code %d, err msg %s",
                          head->src_inst, head->frag_no, head->serial_no, head->batch_size,
                          cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
            return;
        }

        if (concat_fragment_pack(ctrl, head) != CM_SUCCESS) {
            LOG_DEBUG_WAR("[MEC]non_first_frag concat fail. src inst[%d], frag_no[%u], serial no[%u], batch size[%u], "
                          "err code %d, err msg %s",
                          head->src_inst, head->frag_no, head->serial_no, head->batch_size,
                          cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
            goto error;
        }
        cm_spin_unlock(&ctrl->lock);
    }

    return;
error:
    if (ctrl != NULL) {
        del_sn = ctrl->sn;
        cm_spin_unlock(&ctrl->lock);
        release_fragment_ctrl(ctrl, del_sn);
    }
}

static void dtc_proc_end_data(mec_context_t *mec_ctx, msg_proc_t proc, fragment_ctx_t *fragment_ctx,
    mec_message_head_t *head)
{
    mec_message_t pack;
    fragment_key_t key;
    FILL_FRAGMENT_KEY(head, key);
    uint32 hash_key = cm_hash_bytes((const uint8 *)&key, sizeof(fragment_key_t), FRAGMENT_BUCKETS);
    fragment_bucket_t *bucket = &fragment_ctx->buckets[hash_key];
    fragment_ctrl_t *ctrl = NULL;
    uint32 del_sn;
    ctrl = find_fragment_ctrl(bucket, &key);
    if (ctrl == NULL) {
        LOG_DEBUG_WAR("[MEC]end_data find_fragment_ctrl fail. src inst[%d], dst inst[%d], cmd[%u], "
                      "stream id[%u], serial no[%u], batch size[%u], err code %d, err msg %s",
                      head->src_inst, head->dst_inst, head->cmd,
                      head->stream_id, head->serial_no, head->batch_size,
                      cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
        return;
    }

    if (concat_fragment_pack(ctrl, head) != CM_SUCCESS) {
        del_sn = ctrl->sn;
        cm_spin_unlock(&ctrl->lock);
        release_fragment_ctrl(ctrl, del_sn);
        LOG_DEBUG_WAR("[MEC]end_data concat_fragment_pack fail. inst[%d], dst inst[%d], cmd[%u], "
                      "stream id[%u], serial no[%u], batch size[%u], err code %d, err msg %s",
                      head->src_inst, head->dst_inst, head->cmd,
                      head->stream_id, head->serial_no, head->batch_size,
                      cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
        return;
    }
    MEC_MESSAGE_ATTACH2(&pack, (char *)ctrl->buffer);
    mec_init_get(&pack);

    if (proc(&pack) != CM_SUCCESS) {
        int32 code = 0;
        const char *message = NULL;
        cm_get_error(&code, &message);

        LOG_DEBUG_WAR("[MEC]proc_end_data src inst[%d], dst inst[%d], cmd[%u], "
                      "stream id[%u], serial no[%u], batch size[%u] failed, err code %d, err msg %s",
                      pack.head->src_inst,
                      pack.head->dst_inst,
                      pack.head->cmd,
                      pack.head->stream_id,
                      pack.head->serial_no,
                      pack.head->batch_size,
                      code,
                      code == 0 ? "N/A" : message);
    }

    del_sn = ctrl->sn;
    cm_spin_unlock(&ctrl->lock);
    release_fragment_ctrl(ctrl, del_sn);
}

void dtc_recv_proc(mec_context_t *mec_ctx, fragment_ctx_t *fragment_ctx, mec_message_head_t *head)
{
    mec_message_t pack;

    if (md_check_stream_node_exist(head->stream_id, head->src_inst) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[MEC]eachhead: invalid stream_id %u or src_inst %u", head->stream_id, head->src_inst);
        return;
    }

    if (SECUREC_UNLIKELY(head->dst_inst != md_get_cur_node())) {
        LOG_DEBUG_ERR("[MEC]eachhead: dst_inst %u is not me.", head->dst_inst);
        return;
    }

    if (SECUREC_UNLIKELY(head->cmd >= MEC_CMD_CEIL)) {
        LOG_DEBUG_ERR("[MEC]invalid mec command %u", head->cmd);
        return;
    }

    msg_proc_t proc = mec_ctx->cb_processer[head->cmd].proc;
    if (SECUREC_UNLIKELY(proc == NULL)) {
        LOG_DEBUG_ERR("[MEC]no message handling function is registered for message type %u", head->cmd);
        return;
    }

    LOG_DEBUG_INF("[MEC]recv message msg len[%u], src inst[%d], dst inst[%d], "
                  "cmd[%u], flag[%u], stream id[%u], serial no[%u], batch size[%u], frag no[%u]",
                  head->size, head->src_inst, head->dst_inst, head->cmd,
                  head->flags, head->stream_id, head->serial_no, head->batch_size, head->frag_no);

    head->time2 = g_timer()->now;
    g_mec_perf_stat.recv_count++;
    g_mec_perf_stat.recv_delay += head->time2 - head->time1;
    stat_record(RECV_DELAY, head->time2 - head->time1);

    if (CS_MORE_DATA(head->flags)) {
        dtc_proc_more_data(fragment_ctx, head);
    } else if (CS_END_DATA(head->flags)) {
        dtc_proc_end_data(mec_ctx, proc, fragment_ctx, head);
    } else {
        MEC_MESSAGE_ATTACH2(&pack, (char *)head);
        mec_init_get(&pack);

        if (proc(&pack) != CM_SUCCESS) {
            int32 code = 0;
            const char *message = NULL;
            cm_get_error(&code, &message);
            LOG_DEBUG_WAR("[MEC]proc message failed,src[%d],dst[%d],cmd[%u],stream id[%u],err code %d, err msg %s",
                head->src_inst, head->dst_inst, head->cmd, head->stream_id, code, code == 0 ? "N/A" : message);
        }
    }
}


void dtc_proc_batch_recv(dtc_msgqueue_t *batch_queue, task_arg_t *arg)
{
    dtc_msgitem_t *msg_item = batch_queue->first;
    mec_message_head_t *head = NULL;
    while (msg_item != NULL) {
        head = (mec_message_head_t *)msg_item->msg;
        if (dtc_proc_batch(arg, head) != CM_SUCCESS) {
            LOG_DEBUG_ERR("[MEC]dtc decompress failed, msg len[%u], src inst[%d], dst inst[%d], "
                          "cmd[%u], flag[%u], stream id[%u], serial no[%u], batch size[%u], frag no [%u]",
                          head->size,
                          head->src_inst,
                          head->dst_inst,
                          head->cmd,
                          head->flags,
                          head->stream_id,
                          head->serial_no,
                          head->batch_size,
                          head->frag_no);
            return;
        }
        mec_release_message_buf(msg_item->msg);
        msg_item->msg = NULL;
        msg_item = msg_item->next;
    }
}


void release_batch_msgitems(dtc_msgqueue_t *batch_queue, dtc_msgqueue_t *finished_msgitem_queue,
                            mq_context_t *mq_ctx)
{
    dtc_msgitem_t *msg_item = batch_queue->first;
    while (msg_item != NULL) {
        if (msg_item->msg != NULL) {
            mec_release_message_buf(msg_item->msg);
            msg_item->msg = NULL;
        }
        msg_item = msg_item->next;
    }

    put_batch_msgitems_nolock(finished_msgitem_queue, batch_queue);
    if (finished_msgitem_queue->count >= MSG_ITEM_BATCH_SIZE) {
        free_msgitems(&mq_ctx->pool, finished_msgitem_queue);
    }
}

void dtc_task_proc(thread_t *thread)
{
    task_arg_t *arg = (task_arg_t *)thread->argument;
    uint32 queue_idx = arg->index % (DTC_MSG_QUEUE_NUM + 1);
    mq_context_t *mq_ctx = arg->mq_ctx;
    mec_context_t *mec_ctx = (mec_context_t *)mq_ctx->mec_ctx;
    bool32 is_send = arg->is_send;
    dtc_msgqueue_t  finished_msgitem_queue;
    dtc_msgqueue_t  batch_queue;
    init_msgqueue(&finished_msgitem_queue);
    init_msgqueue(&batch_queue);
    dtc_msgqueue_t *queue = &mq_ctx->queue[queue_idx];
    char *thread_name = NULL;
    thread_name = is_send ? "send_mq_task" : "recv_mq_task";
    (void)cm_set_thread_name(thread_name);

    usr_cb_thread_memctx_init_t cb_memctx_init = get_dcf_worker_memctx_init_cb();
    if (!is_send && cb_memctx_init != NULL) {
        cb_memctx_init();
        LOG_DEBUG_INF("[MEC]dtc_task_proc recv thread's memctx init callback: cb_memctx_init done");
    }

    LOG_RUN_INF("[MEC]work thread started, tid:%lu, close:%u", thread->id, thread->closed);
    while (!thread->closed) {
        for (;;) {
            // event will be set after put queue
            if (queue->count > 0 || cm_event_timedwait(&arg->event, CM_SLEEP_50_FIXED) == CM_SUCCESS) {
                break;
            }

            if (thread->closed || mec_ctx->phase != SHUTDOWN_PHASE_NOT_BEGIN) {
                LOG_RUN_INF("[MEC]work thread thread closed, tid:%lu, close:%u", thread->id, thread->closed);
                return;
            }
        }

        get_batch_msgitems(queue, &batch_queue, mq_ctx->profile->batch_size);
        if (batch_queue.count == 0) {
            continue;
        }

        if (is_send) {
            dtc_send_batch_proc(mec_ctx, mq_ctx->profile, &batch_queue, &finished_msgitem_queue);
        } else {
            dtc_proc_batch_recv(&batch_queue, arg);
        }

        release_batch_msgitems(&batch_queue, &finished_msgitem_queue, mq_ctx);
    }

    LOG_RUN_INF("[MEC]work thread closed, tid:%lu, close:%u", thread->id, thread->closed);
}

status_t dtc_init_compress(const mec_profile_t *profile, compress_t *compress, bool32 is_compress)
{
    if (profile->algorithm == COMPRESS_NONE) {
        return CM_SUCCESS;
    }
    compress->algorithm = profile->algorithm;
    compress->level = profile->level;
    compress->frag_size = profile->frag_size + MEC_BUFFER_RESV_SIZE;
    compress->is_compress = is_compress;
    if (compress_alloc(compress) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (compress_alloc_buff(compress) != CM_SUCCESS) {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

#define INIT_MSG_POOL(pool)                   \
    do {                                      \
        (pool)->capacity = 0;                 \
        (pool)->count = 0;                    \
        (pool)->lock = 0;                     \
        (pool)->ext_cnt = 0;                  \
        (pool)->free_first = CM_INVALID_ID32; \
        (pool)->free_count = 0;               \
        (pool)->extending = CM_FALSE;         \
    } while (0)

static status_t mec_init_message_pool(message_pool_t *pool, size_t msg_len)
{
    if (cm_event_init(&pool->event) != CM_SUCCESS) {
        CM_THROW_ERROR(ERR_CREATE_EVENT, cm_get_os_error());
        return CM_ERROR;
    }

    pool->msg_len = msg_len;
    GS_INIT_SPIN_LOCK(pool->lock);
    INIT_MSG_POOL(pool);
    return CM_SUCCESS;
}

void mec_destory_message_pool(message_pool_t *pool)
{
    for (uint32 i = 0; i < pool->ext_cnt; i++) {
        CM_FREE_PTR(pool->extents[i]);
    }
    cm_event_destory(&pool->event);
    INIT_MSG_POOL(pool);

    return;
}

void free_dtc_mq_resource(task_arg_t *task_arg, uint32 loop)
{
    for (uint32 i = 1; i < loop; i++) {
        free_compress_ctx(&task_arg[i].ctx);
    }
}

status_t init_dtc_mq_instance(mq_context_t *mq_ctx, bool32 is_send)
{
    for (uint32 loop = 0; loop < DTC_MSG_QUEUE_NUM + 1; loop++) {
        init_msgqueue(&mq_ctx->queue[loop]);
    }

    init_msgitem_pool(&mq_ctx->pool);

    GS_INIT_SPIN_LOCK(mq_ctx->private_pool_init_lock);

    mq_ctx->msg_pool[PRIV_HIGH].msg_pool_extent = HIGH_MSG_POOL_EXTENT;
    mq_ctx->private_msg_pool_extent[PRIV_HIGH] = HIGH_MSG_POOL_EXTENT;
    uint32 max_items = (mq_ctx->profile->msg_pool_size / mq_ctx->profile->inst_count) / (sizeof(msg_item_t) +
        MEC_ACTL_MSG_BUFFER_SIZE(mq_ctx->profile));
    mq_ctx->msg_pool[PRIV_LOW].msg_pool_extent = MAX((max_items / MSG_POOL_MAX_EXTENTS), 1);
    mq_ctx->private_msg_pool_extent[PRIV_LOW] = mq_ctx->msg_pool[PRIV_LOW].msg_pool_extent;
    LOG_RUN_INF("[MEC]high msg_pool_extent=%u, low msg_pool_extent=%u",
        mq_ctx->private_msg_pool_extent[PRIV_HIGH], mq_ctx->private_msg_pool_extent[PRIV_LOW]);

    if (mec_init_message_pool(&mq_ctx->msg_pool[PRIV_HIGH], MEC_PRIV_MESSAGE_BUFFER_SIZE) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (mec_init_message_pool(&mq_ctx->msg_pool[PRIV_LOW],
        MEC_ACTL_MSG_BUFFER_SIZE(mq_ctx->profile)) != CM_SUCCESS) {
        mec_destory_message_pool(&mq_ctx->msg_pool[PRIV_HIGH]);
        return CM_ERROR;
    }

    for (uint32 loop = 0; loop < MEC_DEFALT_THREAD_NUM + 1; loop++) {
        mq_ctx->work_thread_idx[loop].index = loop;
        mq_ctx->work_thread_idx[loop].mq_ctx = mq_ctx;
        mq_ctx->work_thread_idx[loop].is_send = is_send;
        GS_INIT_SPIN_LOCK(mq_ctx->work_thread_idx[loop].lock);
        mq_ctx->work_thread_idx[loop].is_start = CM_FALSE;
        if (loop > 0 && !is_send) {
            if (dtc_init_compress(mq_ctx->profile, &mq_ctx->work_thread_idx[loop].ctx, CM_FALSE) != CM_SUCCESS) {
                mec_destory_message_pool(&mq_ctx->msg_pool[PRIV_LOW]);
                mec_destory_message_pool(&mq_ctx->msg_pool[PRIV_HIGH]);
                free_dtc_mq_resource(mq_ctx->work_thread_idx, loop);
                return CM_ERROR;
            }
        }
    }

    return CM_SUCCESS;
}

void sync_tasks_closed(mq_context_t *mq_ctx)
{
    for (uint32 loop = 0; loop < MEC_DEFALT_THREAD_NUM + 1; loop++) {
        if (mq_ctx->work_thread_idx[loop].is_start) {
            cm_close_thread(&mq_ctx->tasks[loop]);
            cm_event_destory(&mq_ctx->work_thread_idx[loop].event);
            mq_ctx->work_thread_idx[loop].is_start = CM_FALSE;
        }
    }
}

void free_dtc_mq_instance(mq_context_t *mq_ctx)
{
    free_msgitem_pool(&mq_ctx->pool);
    mec_destory_message_pool(&mq_ctx->msg_pool[PRIV_HIGH]);
    mec_destory_message_pool(&mq_ctx->msg_pool[PRIV_LOW]);
    mec_destory_private_msg_pool(mq_ctx);
    free_dtc_mq_resource(mq_ctx->work_thread_idx, MEC_DEFALT_THREAD_NUM + 1);
}


status_t mec_alloc_channel_msg_queue(mq_context_t *mq_ctx)
{
    uint32 alloc_size;
    char *temp_buf = NULL;
    uint32 i, j;
    mec_profile_t *profile = mq_ctx->profile;
    // alloc msgqueue
    alloc_size = sizeof(dtc_msgqueue_t *) * CM_MAX_NODE_COUNT + sizeof(dtc_msgqueue_t) * CM_MAX_NODE_COUNT *
        profile->channel_num;
    temp_buf = malloc(alloc_size);
    if (temp_buf == NULL) {
        CM_THROW_ERROR_EX(ERR_MEC_CREATE_AREA, "allocate dtc_msgqueue_t failed, channel_num %u alloc size %u",
            profile->channel_num, alloc_size);
        return CM_ERROR;
    }

    errno_t ret = memset_sp(temp_buf, alloc_size, 0, alloc_size);
    if (ret != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        CM_FREE_PTR(temp_buf);
        return CM_ERROR;
    }

    mq_ctx->channel_private_queue = (dtc_msgqueue_t **)temp_buf;
    temp_buf += (sizeof(dtc_msgqueue_t *) * CM_MAX_NODE_COUNT);
    for (i = 0; i < CM_MAX_NODE_COUNT; i++) {
        mq_ctx->channel_private_queue[i] = (dtc_msgqueue_t *)temp_buf;
        temp_buf += sizeof(dtc_msgqueue_t) * profile->channel_num;
    }

    // init channel
    for (i = 0; i < CM_MAX_NODE_COUNT; i++) {
        for (j = 0; j < profile->channel_num; j++) {
            init_msgqueue(&mq_ctx->channel_private_queue[i][j]);
        }
    }

    return CM_SUCCESS;
}

void mec_free_channel_msg_queue(mq_context_t *mq_ctx)
{
    if (mq_ctx->channel_private_queue != NULL) {
        CM_FREE_PTR(mq_ctx->channel_private_queue);
    }
}

uint32 mec_get_que_count(const mq_context_t *mq_ctx, msg_priv_t priv)
{
    if (mq_ctx == NULL) {
        return 0;
    }
    uint32 total = 0;
    if (priv == PRIV_HIGH) {
        total = mq_ctx->queue[0].count;
        return total;
    }

    for (uint32 i = 1; i < sizeof(mq_ctx->queue) / sizeof(mq_ctx->queue[0]); i++) {
        total += mq_ctx->queue[i].count;
    }
    return total;
}

int64 mec_get_mem_capacity(mq_context_t *mq_ctx, msg_priv_t priv)
{
    if (mq_ctx == NULL) {
        return 0;
    }

    int64 mem_capacity = 0;
    for (uint32 dstidx = 0; dstidx < CM_MAX_NODE_COUNT; dstidx++) {
        message_pool_t *private_pool = mq_ctx->private_pool[dstidx][priv];
        if (private_pool != NULL) {
            mem_capacity += private_pool->capacity;
        }
    }
    message_pool_t *pool = &mq_ctx->msg_pool[priv];
    mem_capacity += pool->capacity;
    mem_capacity *= MSG_ITEM_SIZE(pool);
    return mem_capacity;
}

status_t mec_private_pool_init(message_pool_t **private_pool, uint32 buf_size, uint32 private_msg_pool_extent)
{
    size_t ctrl_size = sizeof(message_pool_t);
    message_pool_t *cur_pool = (message_pool_t *)malloc(ctrl_size);
    if (cur_pool == NULL) {
        LOG_RUN_ERR("[MEC]malloc private_pool ctrl failed.");
        return CM_ERROR;
    }
    errno_t err = memset_s(cur_pool, ctrl_size, 0, ctrl_size);
    if (err != EOK) {
        CM_FREE_PTR(cur_pool);
        LOG_RUN_ERR("[MEC]memset private_pool ctrl failed.");
        return CM_ERROR;
    }
    if (mec_init_message_pool(cur_pool, buf_size) != CM_SUCCESS) {
        CM_FREE_PTR(cur_pool);
        LOG_RUN_ERR("[MEC]init private_pool ctrl failed.");
        return CM_ERROR;
    }

    (cur_pool)->msg_pool_extent = private_msg_pool_extent;
    *private_pool = cur_pool;
    return CM_SUCCESS;
}


status_t mec_alloc_msg_item_from_private_pool(message_pool_t **private_pool, msg_item_t **item, uint32 buf_size,
    uint32 private_msg_pool_extent, spinlock_t *private_initlock)
{
    *item = NULL;
    if (*private_pool == NULL) {
        cm_spin_lock(private_initlock, NULL);
        if (*private_pool == NULL) {
            if (mec_private_pool_init(private_pool, buf_size, private_msg_pool_extent) != CM_SUCCESS) {
                LOG_RUN_ERR("[MEC]init private_pool failed.");
                cm_spin_unlock(private_initlock);
                return CM_ERROR;
            }
        }
        cm_spin_unlock(private_initlock);
    }

    return mec_alloc_msg_item(*private_pool, item);
}

void mec_destory_private_msg_pool(mq_context_t *mq_ctx)
{
    for (uint32 dstidx = 0; dstidx < CM_MAX_NODE_COUNT; dstidx++) {
        for (uint32 priidx = 0; priidx < PRIV_CEIL; priidx++) {
            message_pool_t *private_pool = mq_ctx->private_pool[dstidx][priidx];
            if (private_pool != NULL) {
                for (uint32 i = 0; i < private_pool->ext_cnt; i++) {
                    CM_FREE_PTR(private_pool->extents[i]);
                }
                cm_event_destory(&private_pool->event);
                INIT_MSG_POOL(private_pool);
                CM_FREE_PTR(mq_ctx->private_pool[dstidx][priidx]);
            }
        }
    }
}

#ifdef __cplusplus
}
#endif

