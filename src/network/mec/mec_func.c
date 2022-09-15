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
 * mec_func.c
 *    mec process
 *
 * IDENTIFICATION
 *    src/network/mec/mec_func.c
 *
 * -------------------------------------------------------------------------
 */

// MEC = Message Exchange Component
#include "cm_ip.h"
#include "cm_timer.h"
#include "cm_spinlock.h"
#include "cm_sync.h"
#include "cs_tcp.h"
#include "mec_reactor.h"
#include "metadata.h"
#include "cm_hash.h"
#include "cm_thread.h"
#include "mec_instance.h"

#ifdef __cplusplus
extern "C" {
#endif

static mem_pool_t g_buddy_pool;
mem_pool_t* get_mem_pool()
{
    return &g_buddy_pool;
}

#ifndef WIN32
static pthread_key_t g_thread_key;
pthread_key_t* addr_of_thread_key()
{
    return &g_thread_key;
}

void delete_thread_key()
{
    (void)pthread_key_delete(g_thread_key);
}
#endif

static bool32 g_ssl_enable = CM_FALSE;
static usr_cb_decrypt_pwd_t usr_cb_decrypt_pwd = NULL;

void mec_release_message_buf(const char *msg_buf)
{
    msg_item_t *item = (msg_item_t *)(msg_buf - sizeof(msg_item_t));
    message_pool_t *pool = item->pool;

    cm_spin_lock(&pool->lock, NULL);
    CM_ASSERT(item->next == CM_INVALID_ID32);
    item->next = pool->free_first;
    pool->free_first = item->id;
    pool->free_count++;
    cm_spin_unlock(&pool->lock);
    cm_event_notify(&pool->event);
    return;
}

void mec_release_pack(mec_message_t *pack)
{
    if (get_mec_ctx()->phase != SHUTDOWN_PHASE_NOT_BEGIN) {
        return;
    }
    if (!CM_BIT_TEST(pack->options, CSO_BUFF_IN_QUEUE)) {
        mec_release_message_buf((const char *)pack->buffer);
        CM_BIT_SET(pack->options, CSO_BUFF_IN_QUEUE);
    }
}

status_t mec_alloc_msg_item(message_pool_t *pool, msg_item_t **item)
{
    *item = NULL;
    for (;;) {
        cm_spin_lock(&pool->lock, NULL);
        if (pool->free_first != CM_INVALID_ID32) {
            GET_FROM_FREE_LST(pool, *item);
            cm_spin_unlock(&pool->lock);
            return CM_SUCCESS;
        }
        if (pool->count < pool->capacity) {
            ALLOC_FROM_POOL(pool, *item);
            cm_spin_unlock(&pool->lock);
            return CM_SUCCESS;
        }
        if (pool->extending) {
            cm_spin_unlock(&pool->lock);
            cm_sleep(CM_SLEEP_1_FIXED);
            continue;
        }
        pool->extending = CM_TRUE;
        cm_spin_unlock(&pool->lock);
        if (pool->capacity >= MSG_POOL_MAX_EXTENTS * pool->msg_pool_extent) {
            pool->extending = CM_FALSE;
            return CM_SUCCESS;
        }
        size_t alloc_size = MSG_ITEM_SIZE(pool) * pool->msg_pool_extent;
        pool->extents[pool->ext_cnt] = malloc(alloc_size);
        if (pool->extents[pool->ext_cnt] == NULL) {
            pool->extending = CM_FALSE;
            CM_THROW_ERROR(ERR_ALLOC_MEMORY, alloc_size, "message items");
            return CM_ERROR;
        }
        pool->capacity += pool->msg_pool_extent;
        ++pool->ext_cnt;
        CM_MFENCE;
        pool->extending = CM_FALSE;
        LOG_DEBUG_INF("[MEC]alloc message item with pool extend, alloc_size:%zu ext_cnt:%u msg_pool_extent:%u "
            "capacity:%u", alloc_size, pool->ext_cnt, pool->msg_pool_extent, pool->capacity);
    }
    return CM_SUCCESS;
}

status_t mec_get_message_buf(mec_message_t *pack, uint32 dst_inst, msg_priv_t priv)
{
    mq_context_t *mq_ctx = get_send_mq_ctx();
    msg_item_t *item = NULL;
    uint32 buf_size = (priv == PRIV_LOW) ? MEC_ACTL_MSG_BUFFER_SIZE(get_mec_profile()) : MEC_PRIV_MESSAGE_BUFFER_SIZE;
    message_pool_t *pool = &mq_ctx->msg_pool[priv];
    timespec_t begin = cm_clock_now();
    timespec_t last = begin;
    cm_event_t *wait_event = &pool->event;

    while (1) {
        if (dst_inst != CM_INVALID_NODE_ID) {
            CM_RETURN_IFERR(mec_alloc_msg_item_from_private_pool(&mq_ctx->private_pool[dst_inst][priv], &item,
                buf_size, mq_ctx->private_msg_pool_extent[priv], &mq_ctx->private_pool_init_lock));
            if (item != NULL) {
                MEC_MESSAGE_ATTACH(pack, get_mec_profile(), priv, item->buffer);
                return CM_SUCCESS;
            }
        }
        if (mec_alloc_msg_item(pool, &item) != CM_SUCCESS) {
            LOG_DEBUG_ERR("[MEC]mec_get_message_buf fail. priv[%u], err code %d, err msg %s",
                priv, cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
            return CM_ERROR;
        }
        if (item != NULL) {
            MEC_MESSAGE_ATTACH(pack, get_mec_profile(), priv, item->buffer);
            return CM_SUCCESS;
        }
        if (get_mec_ctx()->phase != SHUTDOWN_PHASE_NOT_BEGIN) {
            LOG_DEBUG_ERR("[MEC]mec_get_message_buf fail,not begin now. priv[%u], err code %d, err msg %s",
                          priv, cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
            return CM_ERROR;
        }
        timespec_t now = cm_clock_now();
        if ((now - last) > MICROSECS_PER_SECOND) {
            LOG_DEBUG_ERR("[MEC]wait for free buffer more than %llu seconds, dst_inst[%u], priv[%u].",
                (now - begin) / MICROSECS_PER_SECOND, dst_inst, priv);
            last = now;
            if ((now - begin) > MICROSECS_PER_SECOND * CM_3X_FIXED) {
                return CM_ERROR;
            }
        }
        if (dst_inst != CM_INVALID_NODE_ID && mq_ctx->private_pool[dst_inst][priv]) {
            wait_event = &mq_ctx->private_pool[dst_inst][priv]->event;
        }
        (void)cm_event_timedwait(wait_event, CM_SLEEP_1_FIXED);
    }

    return CM_SUCCESS;
}

static inline status_t set_time1(mec_message_head_t *head)
{
    uint32 temp_size = 0;
    mec_message_head_t *temp = head;
    date_t time1 = g_timer()->now;
    if (CS_BATCH(head->flags)) {
        temp++;
        uint32 remain_size = (uint32)(head->size - sizeof(mec_message_head_t));
        while (remain_size > 0) {
            temp_size = temp->size;
            if (remain_size < temp_size || remain_size < (uint32)sizeof(mec_message_head_t)) {
                LOG_DEBUG_ERR("[MEC]batch_err: head_size %u, remain %u, cur_size %u.",
                    head->size, remain_size, temp_size);
                return CM_ERROR;
            }
            temp->time1 = time1;
            remain_size -= temp_size;
            temp = (mec_message_head_t *)((char *)temp + temp_size);
        }
    } else {
        temp->time1 = time1;
    }

    return CM_SUCCESS;
}

static status_t check_recv_head_info(const mec_message_t *msg, msg_priv_t pipe_priv)
{
    mec_context_t *mec_ctx = get_mec_ctx();
    uint32 cur_node = md_get_cur_node();
    mec_message_head_t *head = msg->head;

    if (md_check_stream_node_exist(head->stream_id, head->src_inst) != CM_SUCCESS
        || head->src_inst == cur_node || head->dst_inst != cur_node) {
        LOG_DEBUG_ERR("[MEC]rcvhead: invalid stream_id %u or src_inst %u or dst_inst %u, cur=%u",
            head->stream_id, head->src_inst, head->dst_inst, cur_node);
        return CM_ERROR;
    }

    if (SECUREC_UNLIKELY(head->cmd >= MEC_CMD_CEIL)) {
        LOG_DEBUG_ERR("[MEC]rcvhead:invalid msg command %u", head->cmd);
        return CM_ERROR;
    }
    if (SECUREC_UNLIKELY(mec_ctx->cb_processer[head->cmd].proc == NULL)) {
        LOG_DEBUG_ERR("[MEC]rcvhead:no message handling function registered for message type %u", head->cmd);
        return CM_ERROR;
    }

    msg_priv_t flag_priv = CS_PRIV_LOW(head->flags) ? PRIV_LOW : PRIV_HIGH;
    msg_priv_t cmd_priv = mec_ctx->cb_processer[head->cmd].priv;
    if (flag_priv != pipe_priv || cmd_priv != pipe_priv) {
        LOG_DEBUG_ERR("[MEC]rcvhead:flag_priv %u or cmd_priv %u not equal with pipe_priv %u, cmd %u",
            flag_priv, cmd_priv, pipe_priv, head->cmd);
        return CM_ERROR;
    }

    if (get_mec_profile()->algorithm == COMPRESS_NONE && CS_COMPRESS(head->flags)) {
        LOG_DEBUG_ERR("[MEC]rcvhead:compress is not enable, but recv compress pkt. head_flags=%u", head->flags);
        return CM_ERROR;
    }

    if (CS_MORE_DATA(head->flags) && CS_END_DATA(head->flags)) {
        LOG_DEBUG_ERR("[MEC]rcvhead:more or end flag error. head_flags=%u", head->flags);
        return CM_ERROR;
    }

    if ((CS_BATCH(head->flags) && head->batch_size <= 1) || (head->batch_size == 0)
        || (head->batch_size > get_mec_profile()->batch_size)) {
        LOG_DEBUG_ERR("[MEC]rcvhead:batch_flag 0x%x or batch_size %u exceed error, prof_batch %u.",
            head->flags, head->batch_size, get_mec_profile()->batch_size);
        return CM_ERROR;
    }

    if (head->size < sizeof(mec_message_head_t) || head->size > msg->aclt_size) {
        LOG_DEBUG_ERR("[MEC]rcvhead:recv message length %u exceed min or max %u", head->size, msg->aclt_size);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t mec_read_message(cs_pipe_t *pipe, mec_message_t *msg, msg_priv_t pipe_priv)
{
    char *buf = NULL;

    if (cs_read_fixed_size(pipe, msg->buffer, sizeof(mec_message_head_t)) != CM_SUCCESS) {
        return CM_ERROR;
    }
    CM_RETURN_IFERR(check_recv_head_info(msg, pipe_priv));

    buf = msg->buffer + sizeof(mec_message_head_t);
    if (cs_read_fixed_size(pipe, buf, msg->head->size - sizeof(mec_message_head_t)) != CM_SUCCESS) {
        return CM_ERROR;
    }

    return set_time1(msg->head);
}

status_t mec_process_message(const mec_pipe_t *pipe, mec_message_t *msg)
{
    dtc_msgqueue_t *my_queue = NULL;
    mq_context_t *mq_ctx = get_recv_mq_ctx();

    uint32 channel_id = MEC_STREAM_TO_CHANNEL_ID(msg->head->stream_id, get_mec_profile()->channel_num);
    my_queue = &mq_ctx->channel_private_queue[msg->head->src_inst][channel_id];
    dtc_msgitem_t *msgitem = mec_alloc_msgitem(mq_ctx, my_queue);
    if (msgitem == NULL) {
        LOG_DEBUG_ERR("[MEC]alloc message item failed, error code %d.", cm_get_os_error());
        return CM_ERROR;
    }
    msgitem->msg = msg->buffer;
    uint32 index = 0;
    if (pipe->priv == PRIV_LOW) {
        index = 1; // avoid concurrent attacks without affecting performance.
    }
    CM_MFENCE;
    put_msgitem(&mq_ctx->queue[index], msgitem);

    if (!mq_ctx->work_thread_idx[index].is_start) {
        cm_spin_lock(&mq_ctx->work_thread_idx[index].lock, NULL);
        if (!mq_ctx->work_thread_idx[index].is_start) {
            if (cm_event_init(&mq_ctx->work_thread_idx[index].event) != CM_SUCCESS) {
                LOG_RUN_ERR("[MEC]create thread %u event failed, error code %d.", index, cm_get_os_error());
                cm_spin_unlock(&mq_ctx->work_thread_idx[index].lock);
                return CM_ERROR;
            }
            if (cm_create_thread(dtc_task_proc, 0, (void *)&mq_ctx->work_thread_idx[index],
                                 &mq_ctx->tasks[index]) != CM_SUCCESS) {
                LOG_RUN_ERR("[MEC]create work thread %u failed.", index);
                cm_spin_unlock(&mq_ctx->work_thread_idx[index].lock);
                return CM_ERROR;
            }
            mq_ctx->work_thread_idx[index].is_start = CM_TRUE;
        }
        cm_spin_unlock(&mq_ctx->work_thread_idx[index].lock);
    }
    cm_event_notify(&mq_ctx->work_thread_idx[index].event);
    return CM_SUCCESS;
}

status_t mec_discard_recv_msg(mec_pipe_t *pipe)
{
    uint32 buf_size = (pipe->priv == PRIV_LOW) ? MEC_ACTL_MSG_BUFFER_SIZE(get_mec_profile())
        : MEC_PRIV_MESSAGE_BUFFER_SIZE;
    mec_message_t pack;
    char *msg_buf = galloc(buf_size, &g_buddy_pool);
    if (msg_buf == NULL) {
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, buf_size, "mec message");
        return CM_ERROR;
    }
    MEC_MESSAGE_ATTACH(&pack, get_mec_profile(), pipe->priv, msg_buf);
    if (mec_read_message(&pipe->recv_pipe, &pack, pipe->priv) != CM_SUCCESS) {
        gfree(msg_buf);
        return CM_ERROR;
    }

    LOG_DEBUG_WAR("[MEC]discard the message, msg len[%u], src inst[%d], dst inst[%d], "
                  "cmd[%u], flag[%u], stream id[%u], serial no[%u], batch size[%u], frag no[%u].",
                  pack.head->size, pack.head->src_inst, pack.head->dst_inst, pack.head->cmd,
                  pack.head->flags, pack.head->stream_id, pack.head->serial_no, pack.head->batch_size,
                  pack.head->frag_no);
    gfree(msg_buf);
    return CM_SUCCESS;
}

status_t mec_proc_recv_msg(mec_pipe_t *pipe)
{
    bool32 ready = CM_FALSE;
    if (cs_wait(&pipe->recv_pipe, CS_WAIT_FOR_READ, MEC_CHANNEL_TIMEOUT, &ready) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[MEC]cs_wait failed, channel %d, priv %d", pipe->channel->id, pipe->priv);
        return CM_ERROR;
    }

    if (!ready) {
        return CM_SUCCESS;
    }

    mec_message_t pack;
    mq_context_t *mq_ctx = get_recv_mq_ctx();
    message_pool_t *pool = &mq_ctx->msg_pool[pipe->priv];
    msg_item_t *item = NULL;

    uint32 buf_size = (pipe->priv == PRIV_LOW) ? MEC_ACTL_MSG_BUFFER_SIZE(get_mec_profile())
        : MEC_PRIV_MESSAGE_BUFFER_SIZE;
    CM_RETURN_IFERR(mec_alloc_msg_item_from_private_pool(
        &mq_ctx->private_pool[MEC_INSTANCE_ID(pipe->channel->id)][pipe->priv],
        &item, buf_size, mq_ctx->private_msg_pool_extent[pipe->priv], &mq_ctx->private_pool_init_lock));
    if (item == NULL) {
        if (mec_alloc_msg_item(pool, &item) != CM_SUCCESS) {
            LOG_DEBUG_ERR("[MEC]mec_alloc_msg_item failed, channel %d, priv %d", pipe->channel->id, pipe->priv);
            return CM_ERROR;
        }
        if (item == NULL) {
            return mec_discard_recv_msg(pipe);
        }
    }
    MEC_MESSAGE_ATTACH(&pack, get_mec_profile(), pipe->priv, item->buffer);
    cm_reset_error();
    if (mec_read_message(&pipe->recv_pipe, &pack, pipe->priv) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[MEC]mec_read_message failed. channel %d, priv %d", pipe->channel->id, pipe->priv);
        mec_release_pack(&pack);
        return CM_ERROR;
    }

    if (mec_process_message(pipe, &pack) != CM_SUCCESS) {
        mec_release_pack(&pack);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

void mec_close_recv_pipe(mec_pipe_t *pipe)
{
    cm_thread_lock(&pipe->recv_lock);
    if (!pipe->recv_pipe_active) {
        cm_thread_unlock(&pipe->recv_lock);
        return;
    }
    cs_disconnect(&pipe->recv_pipe);
    pipe->recv_pipe_active = CM_FALSE;
    cm_thread_unlock(&pipe->recv_lock);

    return;
}

void mec_proc_recv_pipe(struct st_mec_pipe *pipe, bool32 *is_continue)
{
    reactor_t *reactor = pipe->reactor;
    *is_continue = CM_FALSE;

    if (cm_atomic32_cas(&pipe->recv_need_close, CM_TRUE, CM_FALSE) == CM_TRUE
        || get_mec_ctx()->phase != SHUTDOWN_PHASE_NOT_BEGIN) {
        LOG_DEBUG_ERR("[MEC]mec recv need close or phase(%d) not begin, "
                      "disconnect recv channel %d, priv %d",
                      get_mec_ctx()->phase, pipe->channel->id, pipe->priv);
        reactor_unregister_pipe(pipe);
        mec_close_recv_pipe(pipe);
        detach_agent(pipe, RECV_MODE);
        return;
    }

    if (mec_proc_recv_msg(pipe) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[MEC]mec process receive pipe failed, err code %d, err msg %s. "
                      "disconnect recv channel %d, priv %d",
                      cm_get_error_code(), cm_get_errormsg(cm_get_error_code()), pipe->channel->id, pipe->priv);
        reactor_unregister_pipe(pipe);
        mec_close_recv_pipe(pipe);
        detach_agent(pipe, RECV_MODE);
        return;
    }

    if (reactor_in_dedicated_mode(reactor)) {
        *is_continue = CM_TRUE;
    } else {
        agent_detach_and_set_oneshot(pipe);
    }

    return;
}

#define FILL_CONNECT_HEAD(head, profile, channel, pipe)                     \
    do {                                                                    \
        (head).cmd = MEC_CMD_CONNECT;                                       \
        (head).src_inst = (profile)->inst_id;                               \
        (head).stream_id = MEC_CHANNEL_ID((channel)->id);                   \
        (head).size = sizeof(mec_message_head_t);                           \
        (head).flags = ((pipe)->priv == PRIV_HIGH ? 0 : CS_FLAG_PRIV_LOW);  \
        (head).serial_no = cm_atomic32_inc(&(channel)->serial_no);          \
        if (CS_DIFFERENT_ENDIAN((pipe)->send_pipe.options)) {               \
            (head).src_inst = cs_reverse_uint32((head).src_inst);           \
            (head).stream_id = cs_reverse_uint32((head).stream_id);         \
            (head).size = cs_reverse_uint32((head).size);                   \
            (head).serial_no = cs_reverse_uint32((head).serial_no);         \
        }                                                                   \
    } while (0)

static void mec_show_connect_error_info(const char *url)
{
    static timespec_t last = 0;
    if ((cm_clock_now() - last) > MICROSECS_PER_SECOND) {
        LOG_DEBUG_ERR("[MEC]cs_connect fail,peer_url=%s, err code %d, err msg %s.", url, cm_get_error_code(),
            cm_get_errormsg(cm_get_error_code()));
        last = cm_clock_now();
    }
}

void mec_try_connect(mec_pipe_t *pipe)
{
    char peer_url[MEC_URL_BUFFER_SIZE];
    char *remote_host = NULL;
    mec_message_head_t head = { 0 };
    mec_profile_t *profile = get_mec_profile();
    mec_channel_t *channel = (mec_channel_t *)pipe->channel;

    if (profile->pipe_type != CS_TYPE_TCP) {
        LOG_DEBUG_ERR("[MEC]pipe_type %u not support now.", profile->pipe_type);
        return;
    }

    cm_reset_error();
    remote_host = MEC_HOST_NAME(MEC_INSTANCE_ID(channel->id), profile);
    PRTS_RETVOID_IFERR(snprintf_s(peer_url, MEC_URL_BUFFER_SIZE, MEC_URL_BUFFER_SIZE - 1, "%s:%d", remote_host,
        MEC_HOST_PORT(MEC_INSTANCE_ID(channel->id), profile)));

    cm_thread_lock(&pipe->send_lock);
    if (pipe->send_pipe_active) {
        cm_thread_unlock(&pipe->send_lock);
        return;
    }
    if (cs_connect(peer_url, &pipe->send_pipe, NULL) != CM_SUCCESS) {
        cm_thread_unlock(&pipe->send_lock);
        mec_show_connect_error_info(peer_url);
        return;
    }

    if (g_ssl_enable) {
        if (cs_ssl_connect(get_mec_ptr()->ssl_connector_fd, &pipe->send_pipe) != CM_SUCCESS) {
            cs_disconnect(&pipe->send_pipe);
            cm_thread_unlock(&pipe->send_lock);
            mec_show_connect_error_info(peer_url);
            return;
        }
    }
    LOG_RUN_INF("[MEC]after cs_connect to instance %u channel id %u, priv %d.", MEC_INSTANCE_ID(pipe->channel->id),
        MEC_CHANNEL_ID(pipe->channel->id), pipe->priv);

    FILL_CONNECT_HEAD(head, profile, channel, pipe);
    if (cs_send_bytes(&pipe->send_pipe, (const char *)&head, sizeof(mec_message_head_t)) != CM_SUCCESS) {
        cs_disconnect(&pipe->send_pipe);
        cm_thread_unlock(&pipe->send_lock);
        LOG_DEBUG_WAR("[MEC]cs_send_bytes fail, instance %u channel id %u, priv %d.",
            MEC_INSTANCE_ID(pipe->channel->id), MEC_CHANNEL_ID(pipe->channel->id), pipe->priv);
        return;
    }
    pipe->send_pipe_active = CM_TRUE;
    cm_thread_unlock(&pipe->send_lock);
}

/* if can't connect for 10s, give up. other pipe can get agent again. */
#define PIPE_MAX_TRY_CONNECT_TIME_MS 10000

void mec_proc_send_pipe(struct st_mec_pipe *pipe, bool32 *is_continue)
{
    *is_continue = CM_TRUE;
    if (!pipe->send_pipe_active) {
        mec_try_connect(pipe);
    }

    do {
        if (get_mec_ctx()->phase != SHUTDOWN_PHASE_NOT_BEGIN) {
            break;
        }
        if (!pipe->send_pipe_active) {
            cm_sleep(MEC_CHANNEL_TIMEOUT);
            pipe->try_connet_count++;
            if (pipe->try_connet_count >= (PIPE_MAX_TRY_CONNECT_TIME_MS / MEC_CHANNEL_TIMEOUT)) {
                LOG_DEBUG_ERR("[MEC]can't connect to instance %u channel id %u, priv %d for %u ms, give up this time.",
                    MEC_INSTANCE_ID(pipe->channel->id),
                    MEC_CHANNEL_ID(pipe->channel->id), pipe->priv, pipe->try_connet_count * MEC_CHANNEL_TIMEOUT);
                break;
            }
            return;
        }

        LOG_RUN_INF("[MEC]connect to instance %u channel id %u, priv %d success.",
                    MEC_INSTANCE_ID(pipe->channel->id),
                    MEC_CHANNEL_ID(pipe->channel->id),
                    pipe->priv);
    } while (0);

    *is_continue = CM_FALSE;
    pipe->try_connet_count = 0;
    detach_agent(pipe, SEND_MODE);
    return;
}

void mec_close_send_pipe(mec_pipe_t *pipe)
{
    cm_thread_lock(&pipe->send_lock);
    if (!pipe->send_pipe_active) {
        cm_thread_unlock(&pipe->send_lock);
        return;
    }
    cs_disconnect(&pipe->send_pipe);
    pipe->send_pipe_active = CM_FALSE;
    cm_thread_unlock(&pipe->send_lock);
}

void mec_clear_addr(uint32 inst_id, mec_profile_t *profile)
{
    if (inst_id >= CM_MAX_NODE_COUNT) {
        return;
    }

    MEMS_RETVOID_IFERR(memset_sp(&profile->inst_arr[inst_id], sizeof(mec_addr_t), 0, sizeof(mec_addr_t)));
    return;
}

static status_t mec_conn_pipe(mec_pipe_t *pipe)
{
    agent_t *agent = NULL;

    if (pipe->send_pipe_active || pipe->attach[SEND_MODE].agent != NULL) {
        return CM_SUCCESS;
    }
    cm_thread_lock(&pipe->send_lock);
    if (pipe->send_pipe_active || pipe->attach[SEND_MODE].agent != NULL) {
        cm_thread_unlock(&pipe->send_lock);
        return CM_SUCCESS;
    }
    LOG_DEBUG_INF("[MEC]start to connect pipe, inst [%u], channel id [%u], priv [%d]",
                  MEC_INSTANCE_ID(pipe->channel->id), MEC_CHANNEL_ID(pipe->channel->id), pipe->priv);
    if (attach_agent(pipe, get_mec_agent(pipe->priv), SEND_MODE, &agent) != CM_SUCCESS) {
        LOG_RUN_ERR("[MEC]attached agent failed inst [%u], channel id [%u], priv [%d]",
                    MEC_INSTANCE_ID(pipe->channel->id), MEC_CHANNEL_ID(pipe->channel->id), pipe->priv);
        cm_thread_unlock(&pipe->send_lock);
        return CM_ERROR;
    }
    cm_thread_unlock(&pipe->send_lock);
    if (agent != NULL) {
        LOG_DEBUG_INF("[MEC]trigger agent %lu to run, inst [%u], channel id [%u], priv [%d]",
                      agent->thread.id, MEC_INSTANCE_ID(pipe->channel->id),
                      MEC_CHANNEL_ID(pipe->channel->id), pipe->priv);
        cm_event_notify(&agent->event);
    }
    return CM_SUCCESS;
}

status_t mec_connect_channel(mec_channel_t *channel)
{
    mec_context_t *mec_ctx = get_mec_ctx();
    uint32 inst_id = MEC_INSTANCE_ID(channel->id);
    uint32 chann_id = MEC_CHANNEL_ID(channel->id);

    for (uint32 i = 0; i < PRIV_CEIL; i++) {
        mec_pipe_t *pipe = &channel->pipe[i];

        if (mec_conn_pipe(pipe) != CM_SUCCESS) {
            return CM_ERROR;
        }
    }
    mec_ctx->is_connect[inst_id][chann_id] = CM_TRUE;
    LOG_RUN_INF("[MEC]connect to instance %u channel id %u.", inst_id, chann_id);
    return CM_SUCCESS;
}

status_t mec_connect(uint32 inst_id)
{
    mec_channel_t *channel = NULL;
    mec_profile_t *profile = get_mec_profile();
    mec_context_t *mec_ctx = get_mec_ctx();

    if ((inst_id >= CM_MAX_NODE_COUNT)) {
        CM_THROW_ERROR_EX(ERR_MEC_PARAMETER, "inst_id %u .", inst_id);
        return CM_ERROR;
    }
    for (uint32 i = 0; i < profile->channel_num; i++) {
        channel = &mec_ctx->channels[inst_id][i];
        if (mec_ctx->is_connect[inst_id][i]) {
            continue;
        }
        if (mec_connect_channel(channel) != CM_SUCCESS) {
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}


static void mec_close_pipe(mec_pipe_t *pipe)
{
    mec_close_send_pipe(pipe);
    mec_close_recv_pipe(pipe);
}

void mec_disconnect(uint32 inst_id)
{
    mec_channel_t *channel = NULL;
    mec_context_t *mec_ctx = get_mec_ctx();
    mec_profile_t *profile = get_mec_profile();
    if (inst_id == profile->inst_id || mec_ctx->channels == NULL) {
        return;
    }

    for (uint32 i = 0; i < profile->channel_num; i++) {
        channel = &mec_ctx->channels[inst_id][i];
        if (!mec_ctx->is_connect[inst_id][i]) {
            continue;
        }
        for (uint32 j = 0; j < PRIV_CEIL; j++) {
            mec_close_pipe(&channel->pipe[j]);
        }
        mec_ctx->is_connect[inst_id][i] = CM_FALSE;
    }

    mec_clear_addr(inst_id, profile);
    LOG_RUN_INF("[MEC]disconnect node %u.", inst_id);

    return;
}

void mec_init_channels_param(mec_channel_t *channel, const mec_profile_t *profile)
{
    for (uint32 k = 0; k < PRIV_CEIL; k++) {
        mec_pipe_t *pipe = &channel->pipe[k];
        cm_init_thread_lock(&pipe->send_lock);
        cm_init_thread_lock(&pipe->recv_lock);
        cm_init_thread_lock(&pipe->recv_epoll_lock);
        pipe->priv = k;
        pipe->channel = channel;
        pipe->attach[SEND_MODE].job = mec_proc_send_pipe;
        pipe->attach[RECV_MODE].job = mec_proc_recv_pipe;
        pipe->send_pipe.connect_timeout = profile->connect_timeout;
        pipe->send_pipe.socket_timeout = profile->socket_timeout;
        pipe->recv_pipe.connect_timeout = profile->connect_timeout;
        pipe->recv_pipe.socket_timeout = profile->socket_timeout;
        pipe->send_pipe.l_onoff = 1;
        pipe->send_pipe.l_linger = 1;
        pipe->try_connet_count = 0;
        pipe->send_need_close = CM_FALSE;
        pipe->recv_need_close = CM_FALSE;
    }
}

static void mec_init_inst_param(mec_profile_t *profile, mec_context_t *mec_ctx, uint32 inst_id)
{
    uint32 j;
    mec_channel_t *channel = NULL;
    // init channel
    for (j = 0; j < profile->channel_num; j++) {
        channel = &mec_ctx->channels[inst_id][j];
        channel->id = (inst_id << 8) | j;
        mec_init_channels_param(channel, profile);
    }
    return;
}

static status_t mec_alloc_channel(uint32 inst_id)
{
    mec_profile_t *profile = get_mec_profile();
    mec_context_t *mec_ctx = get_mec_ctx();

    uint32 alloc_size = sizeof(mec_channel_t) * profile->channel_num;
    char *temp_buf = (char *)malloc(alloc_size);
    if (temp_buf == NULL) {
        CM_THROW_ERROR_EX(ERR_MEC_CREATE_AREA, "allocate mec channel failed, inst_id=%u channel_num=%u alloc_size=%d",
            inst_id, profile->channel_num, alloc_size);
        return CM_ERROR;
    }
    errno_t err = memset_s(temp_buf, alloc_size, 0, alloc_size);
    if (err != EOK) {
        CM_FREE_PTR(temp_buf);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CM_ERROR;
    }
    mec_ctx->channels[inst_id] = (mec_channel_t *)temp_buf;

    mec_init_inst_param(profile, mec_ctx, inst_id);

    return CM_SUCCESS;
}

static status_t mec_alloc_channels()
{
    uint32 i, inst_id;
    uint32 alloc_size;
    char *temp_buf = NULL;
    mec_profile_t *profile = get_mec_profile();
    mec_context_t *mec_ctx = get_mec_ctx();

    // alloc channel
    if (profile->channel_num == 0) {
        CM_THROW_ERROR_EX(ERR_MEC_CREATE_AREA, "channel num %u is invalid", profile->channel_num);
        return CM_ERROR;
    }

    alloc_size = sizeof(mec_channel_t *) * CM_MAX_NODE_COUNT;
    temp_buf = (char *)malloc(alloc_size);
    if (temp_buf == NULL) {
        CM_THROW_ERROR_EX(ERR_MEC_CREATE_AREA, "allocate mec channel failed, channel_num %u alloc size %u",
            profile->channel_num, alloc_size);
        return CM_ERROR;
    }
    errno_t ret = memset_sp(temp_buf, alloc_size, 0, alloc_size);
    if (ret != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        CM_FREE_PTR(temp_buf);
        return CM_ERROR;
    }
    mec_ctx->channels = (mec_channel_t **)temp_buf;

    for (i = 0; i < profile->inst_count; i++) {
        inst_id = GET_INST_INDEX(i, profile);
        CM_RETURN_IFERR(mec_alloc_channel(inst_id));
    }

    return CM_SUCCESS;
}

static void mec_free_channels()
{
    mec_context_t *mec_ctx = get_mec_ctx();
    for (int32 i = 0; i < CM_MAX_NODE_COUNT; i++) {
        CM_FREE_PTR(mec_ctx->channels[i]);
    }
    CM_FREE_PTR(mec_ctx->channels);
}

status_t mec_connect_by_profile()
{
    uint32 i, inst_id;
    mec_profile_t *profile = get_mec_profile();
    // channel connect
    for (i = 0; i < profile->inst_count; i++) {
        inst_id = GET_INST_INDEX(i, profile);
        if (inst_id == profile->inst_id) {
            continue;
        }
        if (mec_connect(inst_id) != CM_SUCCESS) {
            LOG_RUN_ERR("[MEC]conncect to instance %d failed.", inst_id);
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

static status_t mec_init_channels()
{
    // alloc channel
    if (mec_alloc_channels() != CM_SUCCESS) {
        LOG_RUN_ERR("[MEC]alloc channels failed.");
        return CM_ERROR;
    }

    // alloc msgqueue
    if (mec_alloc_channel_msg_queue(get_send_mq_ctx()) != CM_SUCCESS) {
        mec_free_channels();
        LOG_RUN_ERR("[MEC]alloc mesqueue failed.");
        return CM_ERROR;
    }

    // alloc msgqueue
    if (mec_alloc_channel_msg_queue(get_recv_mq_ctx()) != CM_SUCCESS) {
        mec_free_channel_msg_queue(get_send_mq_ctx());
        mec_free_channels();
        LOG_RUN_ERR("[MEC]alloc mesqueue failed.");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

void mec_destory_channels()
{
    uint32 i, inst_id;
    mec_profile_t *profile = get_mec_profile();
    for (i = 0; i < profile->inst_count; i++) {
        inst_id = GET_INST_INDEX(i, profile);
        if (inst_id != profile->inst_id) {
            mec_disconnect(inst_id);
        }
    }
    mec_free_channel_msg_queue(get_send_mq_ctx());
    mec_free_channel_msg_queue(get_recv_mq_ctx());
    mec_free_channels();
    cs_tcp_deinit();
}

static status_t mec_init_pipe(cs_pipe_t *pipe)
{
    link_ready_ack_t ack;
    uint32 proto_code = 0;
    int32 size;
    pipe->connect_timeout = get_mec_profile()->connect_timeout;
    pipe->socket_timeout = get_mec_profile()->socket_timeout;
    if (cs_read_bytes(pipe, (char *)&proto_code, sizeof(proto_code), &size) != CM_SUCCESS) {
        cs_disconnect(pipe);
        LOG_RUN_ERR("[MEC]cs_read_bytes failed.");
        return CM_ERROR;
    }

    if (sizeof(proto_code) != size || proto_code != CM_PROTO_CODE) {
        CM_THROW_ERROR(ERR_INVALID_PROTOCOL, "invalid proto code");
        return CM_ERROR;
    }

    ack.endian = (IS_BIG_ENDIAN ? (uint8)1 : (uint8)0);
    ack.version = CS_LOCAL_VERSION;
    ack.flags = 0;

    if (cs_send_bytes(pipe, (const char *)&ack, sizeof(link_ready_ack_t)) != CM_SUCCESS) {
        cs_disconnect(pipe);
        LOG_RUN_ERR("[MEC]cs_read_bytes failed.");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t check_connect_head_info(const mec_message_head_t *head)
{
    mec_context_t *mec_ctx = get_mec_ctx();
    uint32 cur_node = md_get_cur_node();

    if (head->cmd != (uint8)MEC_CMD_CONNECT) {
        LOG_RUN_ERR("[MEC]cmd %u invalid when building connection.", head->cmd);
        return CM_ERROR;
    }
    if (head->stream_id >= get_mec_profile()->channel_num || head->src_inst >= CM_MAX_NODE_COUNT
        || head->src_inst == CM_INVALID_NODE_ID || head->src_inst == cur_node) {
        LOG_DEBUG_ERR("[MEC]invalid channel %u or src_inst %u, cur=%u", head->stream_id, head->src_inst, cur_node);
        return CM_ERROR;
    }
    if (mec_ctx->channels[head->src_inst] == NULL) {
        LOG_RUN_WAR("[MEC]channel for inst[%u] not already malloc, can't accept now.", head->src_inst);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t mec_accept(cs_pipe_t *pipe)
{
    bool32          ready;
    mec_channel_t  *channel = NULL;
    mec_message_head_t head;
    mec_context_t *mec_ctx = get_mec_ctx();

    LOG_RUN_INF("[MEC]mec_accept: received req, start accept...");

    if (mec_init_pipe(pipe) != CM_SUCCESS) {
        LOG_RUN_ERR("[MEC]init pipe failed.");
        return CM_ERROR;
    }

    if (g_ssl_enable) {
        LOG_RUN_INF("[MEC]mec_accept: start cs_ssl_accept...");
        CM_RETURN_IFERR(cs_ssl_accept(get_mec_ptr()->ssl_acceptor_fd, pipe));
    }

    if (cs_wait(pipe, CS_WAIT_FOR_READ, CM_CONNECT_TIMEOUT, &ready) != CM_SUCCESS) {
        LOG_RUN_ERR("[MEC]wait failed.");
        return CM_ERROR;
    }

    if (cs_read_fixed_size(pipe, (char *)&head, sizeof(mec_message_head_t)) != CM_SUCCESS) {
        LOG_RUN_ERR("[MEC]read message failed.");
        return CM_ERROR;
    }

    CM_RETURN_IFERR(check_connect_head_info(&head));

    channel = &mec_ctx->channels[head.src_inst][head.stream_id];
    msg_priv_t priv = CS_PRIV_LOW(head.flags) ? PRIV_LOW : PRIV_HIGH;
    mec_pipe_t *mec_pipe = &channel->pipe[priv];
    uint32 count = 0;
    while (mec_pipe->is_reg || mec_pipe->attach[RECV_MODE].agent != NULL) {
        cm_sleep(CM_SLEEP_10_FIXED);
        count++;
        if (count > CM_100X_FIXED) {
            (void)cm_atomic32_cas(&mec_pipe->recv_need_close, CM_FALSE, CM_TRUE);
            LOG_RUN_ERR("[MEC]wait old pipe clean failed,force clean.stream %u,src %u,priv %u,reg %u",
                head.stream_id, head.src_inst, priv, mec_pipe->is_reg);
            return CM_ERROR;
        }
    }
    mec_close_recv_pipe(mec_pipe);
    cm_thread_lock(&mec_pipe->recv_lock);
    mec_pipe->recv_pipe = *pipe;
    mec_pipe->recv_pipe_active = CM_TRUE;
    cm_thread_unlock(&mec_pipe->recv_lock);
    CM_MFENCE;

    if (reactor_register_pipe(mec_pipe, get_mec_reactor(priv)) != CM_SUCCESS) {
        LOG_RUN_ERR("[MEC]register channel %u priv %u to reactor failed.", channel->id, priv);
        return CM_ERROR;
    }

    LOG_RUN_INF("[MEC]mec_accept: channel id %u priv %u receive ok.", channel->id, priv);
    return CM_SUCCESS;
}

status_t mec_tcp_accept(tcp_lsnr_t *lsnr, cs_pipe_t *pipe)
{
    return mec_accept(pipe);
}

status_t mec_start_lsnr()
{
    mec_profile_t  *profile = get_mec_profile();
    mec_context_t  *mec_ctx = get_mec_ctx();
    if (profile->pipe_type != CS_TYPE_TCP) {
        LOG_RUN_ERR("[MEC]start lsnr failed, lsnr type %u", profile->pipe_type);
        return CM_ERROR;
    }

    mec_ctx->lsnr.type = (cs_pipe_type_t)profile->pipe_type;
    char *lsnr_host = MEC_HOST_NAME(profile->inst_id, profile);
    uint16 port = MEC_HOST_PORT(profile->inst_id, profile);

    MEMS_RETURN_IFERR(strncpy_s(mec_ctx->lsnr.tcp.host[0], CM_MAX_IP_LEN, lsnr_host, strlen(lsnr_host)));
    mec_ctx->lsnr.tcp.port = port;
    mec_ctx->lsnr.tcp.type = LSNR_TYPE_MES;
    if (cs_start_tcp_lsnr(&mec_ctx->lsnr.tcp, mec_tcp_accept) != CM_SUCCESS) {
        LOG_RUN_ERR("[MEC]start tcp lsnr failed.");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

void mec_stop_lsnr()
{
    mec_profile_t  *profile = get_mec_profile();
    mec_context_t  *mec_ctx = get_mec_ctx();
    if (profile->pipe_type == CS_TYPE_TCP) {
        mec_ctx->lsnr.tcp.host[0][0] = '\0';
        cs_stop_tcp_lsnr(&(mec_ctx->lsnr.tcp));
    } else {
        return;
    }
}

void fragment_ctx_deinit()
{
    fragment_ctx_t *fragment_ctx = get_fragment_ctx();
    fragment_ctrl_pool_t  *ctrl_pool = &fragment_ctx->ctrl_pool;
    for (uint32 i = 0; i < ctrl_pool->ext_cnt; i++) {
        CM_FREE_PTR(ctrl_pool->extents[i]);
    }
    RESET_POOL(ctrl_pool);
    return;
}

status_t mec_init_reactor()
{
    if (agent_create_pool(get_mec_agent(PRIV_HIGH), get_mec_profile()->agent_num) != CM_SUCCESS) {
        LOG_RUN_ERR("[MEC]init priv[%u] agent pool failed.", PRIV_HIGH);
        return CM_ERROR;
    }

    if (reactor_create_pool(get_mec_reactor(PRIV_HIGH), get_mec_agent(PRIV_HIGH), get_mec_profile()) != CM_SUCCESS) {
        LOG_RUN_ERR("[MEC]init priv[%u] reactor pool failed.", PRIV_HIGH);
        goto high_reactor_error;
    }

    if (agent_create_pool(get_mec_agent(PRIV_LOW), get_mec_profile()->agent_num) != CM_SUCCESS) {
        LOG_RUN_ERR("[MEC]init priv[%u] agent pool failed.", PRIV_LOW);
        goto low_agent_error;
    }

    if (reactor_create_pool(get_mec_reactor(PRIV_LOW), get_mec_agent(PRIV_LOW), get_mec_profile()) != CM_SUCCESS) {
        LOG_RUN_ERR("[MEC]init priv[%u] reactor pool failed.", PRIV_LOW);
        goto low_reactor_error;
    }

    return CM_SUCCESS;

low_reactor_error:
    agent_destroy_pool(get_mec_agent(PRIV_LOW));
low_agent_error:
    reactor_destroy_pool(get_mec_reactor(PRIV_HIGH));
high_reactor_error:
    agent_destroy_pool(get_mec_agent(PRIV_HIGH));
    return CM_ERROR;
}

void mec_deinit_reactor()
{
    reactor_destroy_pool(get_mec_reactor(PRIV_LOW));
    reactor_destroy_pool(get_mec_reactor(PRIV_HIGH));
    agent_destroy_pool(get_mec_agent(PRIV_LOW));
    agent_destroy_pool(get_mec_agent(PRIV_HIGH));
    return;
}

status_t mec_init_mq()
{
    mq_context_t *send_mq = get_send_mq_ctx();
    mq_context_t *recv_mq = get_recv_mq_ctx();
    send_mq->profile = get_mec_profile();
    send_mq->mec_ctx = get_mec_ctx();
    recv_mq->profile = get_mec_profile();
    recv_mq->mec_ctx = get_mec_ctx();
    recv_mq->fragment_ctx = get_fragment_ctx();
    if (init_dtc_mq_instance(send_mq, CM_TRUE) != CM_SUCCESS) {
        LOG_RUN_ERR("[MEC]init dtc send message queue failed.");
        return CM_ERROR;
    }

    if (init_dtc_mq_instance(recv_mq, CM_FALSE) != CM_SUCCESS) {
        free_dtc_mq_instance(send_mq);
        LOG_RUN_ERR("[MEC]init dtc received message queue failed.");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}


void mec_deinit_mq()
{
    free_dtc_mq_instance(get_send_mq_ctx());
    free_dtc_mq_instance(get_recv_mq_ctx());
}

void mec_pause_lsnr(lsnr_type_t type)
{
    switch (type) {
        case LSNR_TYPE_MES:
            cs_pause_tcp_lsnr(&get_mec_ctx()->lsnr.tcp);
            break;
        default:
            return;
    }

    return;
}

void mec_deinit_ssl()
{
    if (get_mec_ptr()->ssl_acceptor_fd != NULL) {
        cs_ssl_free_context(get_mec_ptr()->ssl_acceptor_fd);
        get_mec_ptr()->ssl_acceptor_fd = NULL;
    }

    if (get_mec_ptr()->ssl_connector_fd != NULL) {
        cs_ssl_free_context(get_mec_ptr()->ssl_connector_fd);
        get_mec_ptr()->ssl_connector_fd = NULL;
    }

    g_ssl_enable = CM_FALSE;
    usr_cb_decrypt_pwd = NULL;
}

status_t init_mec_profile_inst(mec_profile_t *profile)
{
    cm_spin_lock(&profile->lock, NULL);
    profile->inst_count = 0;
    for (uint32 i = 0; i < CM_MAX_NODE_COUNT; i++) {
        profile->maps[i] = -1;
    }

    uint32 list[CM_MAX_NODE_COUNT];
    uint32 count;
    if (md_get_node_list(list, &count) != CM_SUCCESS) {
        cm_spin_unlock(&profile->lock);
        return CM_ERROR;
    }

    dcf_node_t node_item;
    for (uint32 i = 0; i < count; i++) {
        if (md_get_node(list[i], &node_item) != CM_SUCCESS) {
            cm_spin_unlock(&profile->lock);
            return CM_ERROR;
        }

        if (strncpy_sp(profile->inst_arr[node_item.node_id].t_addr.ip, CM_MAX_IP_LEN, node_item.ip,
            strlen(node_item.ip)) != EOK) {
            cm_spin_unlock(&profile->lock);
            return CM_ERROR;
        }
        profile->inst_arr[node_item.node_id].t_addr.port = node_item.port;
        profile->maps[i] = node_item.node_id;
    }
    profile->inst_count = count;
    cm_spin_unlock(&profile->lock);
    return CM_SUCCESS;
}

status_t init_mec_profile(mec_profile_t *profile)
{
    profile->inst_id = md_get_cur_node();
    param_value_t param_value;
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_MEC_CHANNEL_NUM, &param_value));
    profile->channel_num = param_value.channel_num;
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_MEC_POOL_MAX_SIZE, &param_value));
    profile->msg_pool_size = param_value.mec_pool_max_size;
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_MEC_FRAGMENT_SIZE, &param_value));
    profile->frag_size = param_value.frag_size;
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_MEC_BATCH_SIZE, &param_value));
    profile->batch_size = MAX(param_value.batch_size, 1);
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_COMPRESS_ALGORITHM, &param_value));
    profile->algorithm = param_value.compress;
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_COMPRESS_LEVEL, &param_value));
    profile->level = param_value.level;
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_SOCKET_TIMEOUT, &param_value));
    profile->socket_timeout = param_value.socket_timeout;
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_CONNECT_TIMEOUT, &param_value));
    profile->connect_timeout = param_value.connect_timeout;
    CM_RETURN_IFERR (md_get_param(DCF_PARAM_MEC_REACTOR_THREAD_NUM, &param_value));
    profile->reactor_num = param_value.reactor_num;
    CM_RETURN_IFERR (md_get_param(DCF_PARAM_MEC_AGENT_THREAD_NUM, &param_value));
    profile->agent_num = param_value.agent_num;
    profile->pipe_type = (uint8)CS_TYPE_TCP;
    GS_INIT_SPIN_LOCK(profile->lock);
    return init_mec_profile_inst(profile);
}

void fragment_bucket_delete(fragment_bucket_t *bucket, fragment_ctrl_t *ctrl)
{
    fragment_ctrl_pool_t  *ctrl_pool = &get_fragment_ctx()->ctrl_pool;
    if (ctrl->id == bucket->first) {
        bucket->first = ctrl->next;
    }
    if (ctrl->prev != CM_INVALID_ID32) {
        FRAGMENT_CTRL_PTR(ctrl_pool, ctrl->prev)->next = ctrl->next;
    }
    if (ctrl->next != CM_INVALID_ID32) {
        FRAGMENT_CTRL_PTR(ctrl_pool, ctrl->next)->prev = ctrl->prev;
    }
}

void fragment_bucket_insert(fragment_bucket_t *bucket, fragment_ctrl_t *ctrl)
{
    fragment_ctrl_pool_t  *ctrl_pool = &get_fragment_ctx()->ctrl_pool;
    ctrl->next = bucket->first;
    if (bucket->first != CM_INVALID_ID32) {
        FRAGMENT_CTRL_PTR(ctrl_pool, bucket->first)->prev = ctrl->id;
    }
    ctrl->prev = CM_INVALID_ID32;
    bucket->first = ctrl->id;
    ctrl->bucket = bucket->id;
}

static void proc_fragment_timeout()
{
    fragment_ctrl_pool_t  *pool = &get_fragment_ctx()->ctrl_pool;
    for (uint32 i = 0; i < FRAGMENT_BUCKETS; i++) {
        fragment_bucket_t *bucket = &get_fragment_ctx()->buckets[i];
        cm_latch_x(&bucket->latch, 0, NULL);
        uint32 ctrl_id = bucket->first;
        uint32 next_id;
        fragment_ctrl_t *ctrl = NULL;
        while (ctrl_id != CM_INVALID_ID32) {
            ctrl = FRAGMENT_CTRL_PTR(pool, ctrl_id);
            next_id = ctrl->next;
            if (g_timer()->now - ctrl->now < MICROSECS_PER_SECOND) {
                ctrl_id = next_id;
                continue;
            }
            cm_spin_lock(&ctrl->lock, NULL);
            if (g_timer()->now - ctrl->now < MICROSECS_PER_SECOND) {
                cm_spin_unlock(&ctrl->lock);
                ctrl_id = next_id;
                continue;
            }
            char date[CM_MAX_TIME_STRLEN] = {0};
            mec_message_head_t *head = (mec_message_head_t *)ctrl->buffer;
            (void)cm_date2str(ctrl->now, "yyyy-mm-dd hh24:mi:ss.ff3", date, CM_MAX_TIME_STRLEN);
            LOG_RUN_WAR("[MEC]receive fragment over time, message src inst[%d], "
                        "dst inst[%d], cmd[%u], stream id[%u], serial no[%u], batch size[%u], last hit %s.",
                        head->src_inst,
                        head->dst_inst,
                        head->cmd,
                        head->stream_id,
                        head->serial_no,
                        head->batch_size,
                        date);
            ctrl->sn++;
            if (ctrl->buffer != NULL) {
                gfree(ctrl->buffer);
                ctrl->buffer = NULL;
            }
            cm_spin_unlock(&ctrl->lock);
            fragment_bucket_delete(bucket, ctrl);
            fragment_free_ctrl(ctrl);
            ctrl_id = next_id;
        }
        cm_unlatch(&bucket->latch, NULL);
    }
}

static inline bool32 is_inst_exist(uint32 inst_id)
{
    uint32 list[CM_MAX_NODE_COUNT];
    uint32 count;
    if (md_get_node_list(list, &count) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[MEC]md_get_node_list failed.inst_id=%u", inst_id);
        return CM_FALSE;
    }

    for (uint32 i = 0; i < count; i++) {
        if (inst_id == list[i]) {
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

static void proc_connect_channels()
{
    uint32 inst_id;
    mec_profile_t *profile = get_mec_profile();
    mec_context_t *mec_ctx = get_mec_ctx();
    // channel connect

    for (uint32 i = 0; i < profile->inst_count; i++) {
        inst_id = GET_INST_INDEX(i, profile);
        if (inst_id == profile->inst_id) {
            continue;
        }

        if (is_inst_exist(inst_id) == CM_FALSE) {
            LOG_DEBUG_INF("[MEC]inst_id=%u not exist, no need to connet.", inst_id);
            continue;
        }

        for (uint32 j = 0; j < profile->channel_num; j++) {
            mec_channel_t *channel = &mec_ctx->channels[inst_id][j];
            if (!mec_ctx->is_connect[inst_id][j]) {
                continue;
            }
            for (uint32 k = 0; k < PRIV_CEIL; k++) {
                mec_pipe_t *pipe = &channel->pipe[k];
                if (mec_conn_pipe(pipe) != CM_SUCCESS) {
                    LOG_DEBUG_ERR("[MEC]mec_conn_pipe failed, inst_id=%u", inst_id);
                }
            }
        }
    }
    return;
}

static inline status_t mec_chk_ssl_cert_expire()
{
    param_value_t cert_notify;
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_SSL_CERT_NOTIFY_TIME, &cert_notify));
    if (cert_notify.ssl_cert_notify_time < CM_MIN_SSL_EXPIRE_THRESHOLD ||
        cert_notify.ssl_cert_notify_time > CM_MAX_SSL_EXPIRE_THRESHOLD) {
        LOG_RUN_ERR("[MEC]invalid ssl expire day %d, must between %u and %u", cert_notify.ssl_cert_notify_time,
            CM_MIN_SSL_EXPIRE_THRESHOLD, CM_MAX_SSL_EXPIRE_THRESHOLD);
        return CM_ERROR;
    }
    ssl_ca_cert_expire(get_mec_ptr()->ssl_acceptor_fd, cert_notify.ssl_cert_notify_time);
    return CM_SUCCESS;
}

static void mec_health_chk(uint32 stream_id, mec_command_t cmd)
{
    uint32 nodes[CM_MAX_NODE_COUNT];
    uint32 count;
    uint32 src_node = md_get_cur_node();
    mec_message_t pack;

    if (md_get_stream_nodes(stream_id, nodes, &count) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[MEC]health_chk, md_get_stream_nodes failed.stream_id=%u,cmd=%u,src_node=%u",
            stream_id, cmd, src_node);
        return;
    }

    for (uint32 i = 0; i < count; i++) {
        uint32 node_id = nodes[i];
        if (node_id == src_node) {
            continue;
        }
        if (mec_alloc_pack(&pack, cmd, src_node, node_id, stream_id) != CM_SUCCESS) {
            LOG_DEBUG_ERR("[MEC]health_chk,mec_alloc_pack failed.stream_id=%u,cmd=%u,src_node=%u,dest_node=%u",
                stream_id, cmd, src_node, node_id);
            continue;
        }
        /* only send head, no need to encode */
        if (mec_send_data(&pack) != CM_SUCCESS) {
            LOG_DEBUG_ERR("[MEC]health_chk,mec_send_data failed.stream_id=%u,cmd=%u,src_node=%u,dest_node=%u",
                stream_id, cmd, src_node, node_id);
        }
        mec_release_pack(&pack);
    }

    return;
}

static inline void proc_health_check()
{
    uint32 streams[CM_MAX_STREAM_COUNT];
    uint32 stream_count;

    if (md_get_stream_list(streams, &stream_count) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[MEC]health_check, md_get_stream_list failed");
        return;
    }

    for (uint32 i = 0; i < stream_count; i++) {
        uint32 stream_id = streams[i];
        mec_health_chk(stream_id, MEC_CMD_HEALTH_CHECK_HIGH);
        mec_health_chk(stream_id, MEC_CMD_HEALTH_CHECK_LOW);
        LOG_DEBUG_INF("[MEC]stream_id=%u mec_health_chk finished.", stream_id);
    }

    return;
}

static void mec_daemon_proc(thread_t *thread)
{
    (void)cm_set_thread_name("daemon_proc");

    int64 periods = 0;

    while (!thread->closed) {
        proc_connect_channels();
        proc_fragment_timeout();

        if (periods == SECONDS_PER_DAY && g_ssl_enable) {
            periods = 0;
            (void)mec_chk_ssl_cert_expire();
        }
        periods++;

        proc_health_check();
        show_agent_count(get_mec_agent(PRIV_HIGH), PRIV_HIGH);
        show_agent_count(get_mec_agent(PRIV_LOW), PRIV_LOW);

        cm_sleep(CM_SLEEP_1000_FIXED);
    }
}

static status_t fragment_ctx_init()
{
    fragment_ctx_t *fragment_ctx = get_fragment_ctx();
    fragment_bucket_t *buckets = fragment_ctx->buckets;
    for (uint32 i = 0; i < FRAGMENT_BUCKETS; i++) {
        buckets[i].first = CM_INVALID_ID32;
        buckets[i].id = i;
        cm_latch_init(&buckets[i].latch);
    }
    INIT_POOL(&fragment_ctx->ctrl_pool);
    return CM_SUCCESS;
}

status_t fragment_alloc_ctrl(fragment_ctrl_t **ctrl)
{
    fragment_ctrl_pool_t *pool = &get_fragment_ctx()->ctrl_pool;
    for (;;) {
        cm_spin_lock(&pool->lock, NULL);
        if (pool->free_first != CM_INVALID_ID32) {
            GET_FROM_FREE_LIST(*ctrl, pool);
            cm_spin_unlock(&pool->lock);
            return CM_SUCCESS;
        }
        if (pool->count < pool->capacity) {
            *ctrl = FRAGMENT_CTRL_PTR(pool, pool->count);
            (*ctrl)->id = pool->count;
            ++pool->count;
            cm_spin_unlock(&pool->lock);
            return CM_SUCCESS;
        }
        if (pool->extending) {
            cm_spin_unlock(&pool->lock);
            cm_sleep(1);
            continue;
        }
        pool->extending = CM_TRUE;
        cm_spin_unlock(&pool->lock);
        if (pool->capacity == FRAGMENT_MAX_ITEMS) {
            pool->extending = CM_FALSE;
            CM_THROW_ERROR(ERR_MEC_FRAGMENT_THRESHOLD, FRAGMENT_MAX_ITEMS);
            return CM_ERROR;
        }
        uint32 alloc_size = sizeof(fragment_ctrl_t) * FRAGMENT_EXTENT;
        pool->extents[pool->ext_cnt] = malloc(alloc_size);
        if (pool->extents[pool->ext_cnt] == NULL) {
            pool->extending = CM_FALSE;
            CM_THROW_ERROR(ERR_ALLOC_MEMORY, alloc_size, "fragment ctrl");
            return CM_ERROR;
        }
        errno_t ret = memset_sp(pool->extents[pool->ext_cnt], alloc_size, 0, alloc_size);
        if (ret != EOK) {
            pool->extending = CM_FALSE;
            CM_FREE_PTR(pool->extents[pool->ext_cnt]);
            CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
            return CM_ERROR;
        }
        pool->capacity += FRAGMENT_EXTENT;
        ++pool->ext_cnt;
        CM_MFENCE;
        pool->extending = CM_FALSE;
    }
    return CM_SUCCESS;
}

void fragment_free_ctrl(fragment_ctrl_t *ctrl)
{
    fragment_ctrl_pool_t *pool = &get_fragment_ctx()->ctrl_pool;
    cm_spin_lock(&pool->lock, NULL);
    ctrl->next = pool->free_first;
    pool->free_first = ctrl->id;
    pool->free_count++;
    cm_spin_unlock(&pool->lock);
}

fragment_ctrl_t *find_fragment_ctrl(fragment_bucket_t *bucket, const fragment_key_t *key)
{
    fragment_ctrl_pool_t *pool = &get_fragment_ctx()->ctrl_pool;
    fragment_ctrl_t *ctrl = NULL;
    cm_latch_s(&bucket->latch, 0, CM_FALSE, NULL);
    uint32 ctrl_id = bucket->first;
    while (ctrl_id != CM_INVALID_ID32) {
        ctrl = FRAGMENT_CTRL_PTR(pool, ctrl_id);
        if (FRAGMENT_EQUAL(key, (mec_message_head_t *)ctrl->buffer)) {
            cm_spin_lock(&ctrl->lock, NULL);
            cm_unlatch(&bucket->latch, NULL);
            return ctrl;
        }
        ctrl_id = ctrl->next;
    }
    cm_unlatch(&bucket->latch, NULL);
    return NULL;
}

static status_t check_fragment_buffer_space(fragment_ctrl_t *ctrl, const mec_message_head_t *head)
{
    uint32 new_size = ctrl->size;
    uint32 old_size = ((mec_message_head_t *)ctrl->buffer)->size;
    uint32 bytes_needed = old_size + head->size - sizeof(mec_message_head_t);
    char *buffer = NULL;
    if (new_size >= bytes_needed) {
        return CM_SUCCESS;
    }

    do  {
        new_size = new_size * CM_2X_FIXED;
    } while (new_size > 0 && bytes_needed > new_size);

    if (new_size > 0 && new_size >= bytes_needed) {
        buffer = (char *)grealloc((void *)ctrl->buffer, new_size, &g_buddy_pool);
        if (buffer == NULL) {
            CM_THROW_ERROR(ERR_ALLOC_MEMORY, (size_t)new_size, "1fragment buffer");
            return CM_ERROR;
        }
        ctrl->buffer = buffer;
        ctrl->size = new_size;
        return CM_SUCCESS;
    }
    new_size = ctrl->size;
    do {
        new_size += SIZE_K(8);
    } while (new_size > 0 && bytes_needed > (uint32) new_size);

    if (new_size > 0 && new_size >= bytes_needed) {
        buffer = (char *)grealloc((void *)ctrl->buffer, new_size, &g_buddy_pool);
        if (buffer == NULL) {
            CM_THROW_ERROR(ERR_ALLOC_MEMORY, (size_t)new_size, "2fragment buffer");
            return CM_ERROR;
        }
        ctrl->buffer = buffer;
        ctrl->size = new_size;
        return CM_SUCCESS;
    }
    CM_THROW_ERROR(ERR_ALLOC_MEMORY, (size_t)new_size, "3fragment buffer");
    return CM_ERROR;
}

status_t concat_fragment_pack(fragment_ctrl_t *ctrl, mec_message_head_t *head)
{
    if (((mec_message_head_t *)ctrl->buffer)->frag_no + 1 != head->frag_no) {
        CM_THROW_ERROR(ERR_MEC_INCONSISTENT_FRAG_NO, ((mec_message_head_t *)ctrl->buffer)->frag_no,
                       head->frag_no);
        LOG_DEBUG_WAR("[MEC]last fragment number[%d] is not consistent with new[%d]",
            ((mec_message_head_t *)ctrl->buffer)->frag_no, head->frag_no);
        return CM_ERROR;
    }
    uint32 old_size = ((mec_message_head_t *)ctrl->buffer)->size;
    if (check_fragment_buffer_space(ctrl, head) != CM_SUCCESS) {
        LOG_DEBUG_WAR("[MEC]check_fragment_buffer_space fail.cmd[%u] stream id[%u]", head->cmd, head->stream_id);
        return CM_ERROR;
    }
    MEMS_RETURN_IFERR(memcpy_sp(ctrl->buffer + old_size, ctrl->size - old_size, head + 1,
        head->size - sizeof(mec_message_head_t)));
    ((mec_message_head_t *)ctrl->buffer)->size += (head->size - sizeof(mec_message_head_t));
    ((mec_message_head_t *)ctrl->buffer)->frag_no = head->frag_no;
    ctrl->now = g_timer()->now;
    return CM_SUCCESS;
}

void release_fragment_ctrl(fragment_ctrl_t *ctrl, uint32 del_sn)
{
    fragment_bucket_t *bucket = &get_fragment_ctx()->buckets[ctrl->bucket];
    cm_latch_x(&bucket->latch, 0, NULL);
    cm_spin_lock(&ctrl->lock, NULL);
    if (del_sn != ctrl->sn) {
        cm_spin_unlock(&ctrl->lock);
        cm_unlatch(&bucket->latch, NULL);
        return;
    }
    ctrl->sn++;
    if (ctrl->buffer != NULL) {
        gfree(ctrl->buffer);
        ctrl->buffer = NULL;
    }
    fragment_bucket_delete(bucket, ctrl);
    cm_spin_unlock(&ctrl->lock);
    cm_unlatch(&bucket->latch, NULL);
    fragment_free_ctrl(ctrl);
}

status_t insert_fragment_pack(mec_message_head_t *head, fragment_bucket_t *bucket)
{
    fragment_ctrl_t *ctrl = NULL;
    if (fragment_alloc_ctrl(&ctrl) != CM_SUCCESS) {
        return CM_ERROR;
    }

    ctrl->bucket = bucket->id;
    ctrl->buffer = (char *)galloc(head->size, &g_buddy_pool);
    if (ctrl->buffer == NULL) {
        fragment_free_ctrl(ctrl);
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, sizeof(fragment_ctrl_t), "fragment message");
        return CM_ERROR;
    }
    ctrl->size = head->size;
    errno_t ret = memcpy_sp(ctrl->buffer, head->size, head, head->size);
    if (ret != EOK) {
        gfree(ctrl->buffer);
        fragment_free_ctrl(ctrl);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CM_ERROR;
    }

    ctrl->now = g_timer()->now;
    cm_latch_x(&bucket->latch, 0, NULL);
    fragment_bucket_insert(bucket, ctrl);
    cm_unlatch(&bucket->latch, NULL);
    return CM_SUCCESS;
}

status_t mec_register_decrypt_pwd(usr_cb_decrypt_pwd_t cb_func)
{
    usr_cb_decrypt_pwd = cb_func;
    return CM_SUCCESS;
}

static status_t mec_verify_ssl_key_pwd(ssl_config_t *ssl_cfg, char *plain, uint32 size)
{
    param_value_t keypwd;

    // check password which encrypted by DCF
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_SSL_PWD_PLAINTEXT, &keypwd));
    if (keypwd.inter_pwd.cipher_len > 0) {
        CM_RETURN_IFERR(cm_decrypt_pwd(&keypwd.inter_pwd, (uchar*)plain, &size));
        ssl_cfg->key_password = plain;
        return CM_SUCCESS;
    }

    // check password which encrypted by RSM
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_SSL_PWD_CIPHERTEXT, &keypwd));
    if (!CM_IS_EMPTY_STR(keypwd.ext_pwd)) {
        if (usr_cb_decrypt_pwd == NULL) {
            LOG_RUN_ERR("[MEC]user decrypt function has not registered");
            return CM_ERROR;
        }
        CM_RETURN_IFERR(usr_cb_decrypt_pwd(keypwd.ext_pwd, strlen(keypwd.ext_pwd), plain, size));
        ssl_cfg->key_password = plain;
    }
    return CM_SUCCESS;
}

static status_t mec_init_ssl()
{
    ssl_config_t ssl_cfg = { 0 };
    char plain[CM_PASSWD_MAX_LEN + 1] = { 0 };
    param_value_t ca, key, crl, cert, cipher;

    // Required parameters
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_SSL_CA, &ca));
    ssl_cfg.ca_file = ca.ssl_ca;
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_SSL_KEY, &key));
    ssl_cfg.key_file = key.ssl_key;
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_SSL_CERT, &cert));
    ssl_cfg.cert_file = cert.ssl_cert;

    if (CM_IS_EMPTY_STR(ssl_cfg.cert_file) ||
        CM_IS_EMPTY_STR(ssl_cfg.key_file) || CM_IS_EMPTY_STR(ssl_cfg.ca_file)) {
        LOG_RUN_INF("[MEC]mec_init_ssl: ssl is disabled.");
        return CM_SUCCESS;
    }

    // Optional parameters
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_SSL_CRL, &crl));
    ssl_cfg.crl_file = crl.ssl_crl;
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_SSL_CIPHER, &cipher));
    ssl_cfg.cipher = cipher.ssl_cipher;

    /* Require no public access to key file */
    CM_RETURN_IFERR(cs_ssl_verify_file_stat(ssl_cfg.ca_file));
    CM_RETURN_IFERR(cs_ssl_verify_file_stat(ssl_cfg.key_file));
    CM_RETURN_IFERR(cs_ssl_verify_file_stat(ssl_cfg.cert_file));

    // verify ssl key password and KMC module
    CM_RETURN_IFERR(mec_verify_ssl_key_pwd(&ssl_cfg, plain, sizeof(plain) - 1));

    // create acceptor fd
    get_mec_ptr()->ssl_acceptor_fd = cs_ssl_create_acceptor_fd(&ssl_cfg);
    if (get_mec_ptr()->ssl_acceptor_fd == NULL) {
        LOG_RUN_ERR("[MEC]create ssl acceptor context failed");
        MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0, sizeof(plain)));
        return CM_ERROR;
    }

    // create connector fd
    get_mec_ptr()->ssl_connector_fd = cs_ssl_create_connector_fd(&ssl_cfg);
    MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0, sizeof(plain)));
    if (get_mec_ptr()->ssl_connector_fd == NULL) {
        LOG_RUN_ERR("[MEC]create ssl connector context failed");
        return CM_ERROR;
    }

    CM_RETURN_IFERR(mec_chk_ssl_cert_expire());
    g_ssl_enable = CM_TRUE;
    LOG_RUN_INF("[MEC]mec_init_ssl: ssl is enabled.");
    return CM_SUCCESS;
}

status_t health_check_req_proc(mec_message_t *pack)
{
    uint32 stream_id = pack->head->stream_id;
    uint32 src_node_id = pack->head->src_inst;
    uint32 size = pack->head->size;
    msg_priv_t priv = CS_PRIV_LOW(pack->head->flags) ? PRIV_LOW : PRIV_HIGH;
    LOG_DEBUG_INF("recv health_check_req: stream_id=%u,src_node=%u,priv=%u,size=%u",
        stream_id, src_node_id, priv, size);
    return CM_SUCCESS;
}

status_t mec_init_core()
{
    if (mec_init_ssl() != CM_SUCCESS) {
        LOG_RUN_ERR("[MEC]init ssl failed.");
        goto mq_fail;
    }

    if (mec_init_mq() != CM_SUCCESS) {
        LOG_RUN_ERR("[MEC]init mec mq failed.");
        goto mq_fail;
    }
    if (mec_init_channels() != CM_SUCCESS) {
        LOG_RUN_ERR("[MEC]init channels failed.");
        goto channels_fail;
    }
    if (fragment_ctx_init() != CM_SUCCESS) {
        LOG_RUN_ERR("[MEC]init fragment context failed.");
        goto fragment_fail;
    }
    if (mec_start_lsnr() != CM_SUCCESS) {
        LOG_RUN_ERR("[MEC]start lsnr failed.");
        goto lsnr_fail;
    }
    // channel connect
    if (mec_connect_by_profile() != CM_SUCCESS) {
        LOG_RUN_ERR("[MEC]mec_connect_by_profile failed.");
        goto connet_fail;
    }
    register_msg_process(MEC_CMD_HEALTH_CHECK_HIGH, health_check_req_proc, PRIV_HIGH);
    register_msg_process(MEC_CMD_HEALTH_CHECK_LOW, health_check_req_proc, PRIV_LOW);

    if (cm_create_thread(mec_daemon_proc, 0, NULL, get_daemon_thread()) != CM_SUCCESS) {
        LOG_RUN_ERR("[MEC]failed to create mec daemon thread");
        goto connet_fail;
    }

    return CM_SUCCESS;

connet_fail:
    mec_stop_lsnr();
lsnr_fail:
    fragment_ctx_deinit();
fragment_fail:
    mec_destory_channels();
channels_fail:
    mec_deinit_mq();
mq_fail:
    mec_deinit_ssl();
    return CM_ERROR;
}

void compress_ctx_destructor(void *data)
{
    compress_t *compress_ctx = (compress_t *)data;
    if (compress_ctx == NULL) {
        return;
    }
    free_compress_ctx(compress_ctx);
    CM_FREE_PTR(compress_ctx);
}

uint32 mec_get_send_que_count(msg_priv_t priv)
{
    return mec_get_que_count(get_send_mq_ctx(), priv);
}

uint32 mec_get_recv_que_count(msg_priv_t priv)
{
    return mec_get_que_count(get_recv_mq_ctx(), priv);
}

int64 mec_get_send_mem_capacity(msg_priv_t priv)
{
    return mec_get_mem_capacity(get_send_mq_ctx(), priv);
}

int64 mec_get_recv_mem_capacity(msg_priv_t priv)
{
    return mec_get_mem_capacity(get_recv_mq_ctx(), priv);
}


static status_t mec_create_compress_ctx(compress_t **compress_ctx)
{
    compress_t *temp = NULL;
    temp = (compress_t *)malloc(sizeof(compress_t));
    if (temp == NULL) {
        return CM_ERROR;
    }
    errno_t ret = memset_sp(temp, sizeof(compress_t), 0, sizeof(compress_t));
    if (ret != EOK) {
        CM_FREE_PTR(temp);
        return CM_ERROR;
    }
    if (dtc_init_compress(get_mec_profile(), temp, CM_TRUE) != CM_SUCCESS) {
        free_compress_ctx(temp);
        CM_FREE_PTR(temp);
        return CM_ERROR;
    }
    *compress_ctx = temp;
    return CM_SUCCESS;
}

static status_t mec_snd_compress(mec_message_head_t *head)
{
    compress_t *compress_ctx = NULL;
#ifndef WIN32
    compress_ctx = (compress_t *)pthread_getspecific(g_thread_key);
    if (compress_ctx == NULL) {
        if (mec_create_compress_ctx(&compress_ctx) != CM_SUCCESS) {
            return CM_ERROR;
        }
        (void)pthread_setspecific(g_thread_key, compress_ctx);
    }
#else
    if (mec_create_compress_ctx(&compress_ctx) != CM_SUCCESS) {
        return CM_ERROR;
    }
#endif
    status_t status = dtc_compress(compress_ctx, head);
#ifdef WIN32
    free_compress_ctx(compress_ctx);
    CM_FREE_PTR(compress_ctx);
#endif
    return status;
}
status_t mec_put_msg_queue(const void *msg, bool32 is_send)
{
    mq_context_t *mq_ctx = is_send ? get_send_mq_ctx() : get_recv_mq_ctx();
    dtc_msgqueue_t *my_queue = NULL;
    mec_message_head_t *head = (mec_message_head_t *)msg;
    uint32 channel_id = MEC_STREAM_TO_CHANNEL_ID(head->stream_id, get_mec_profile()->channel_num);
    my_queue = &mq_ctx->channel_private_queue[head->dst_inst][channel_id];
    dtc_msgitem_t *msgitem = mec_alloc_msgitem(mq_ctx, my_queue);
    if (msgitem == NULL) {
        LOG_DEBUG_ERR("[MEC]mec alloc message item failed, error code %d.", cm_get_os_error());
        return CM_ERROR;
    }
    msgitem->msg = (void *)msg;
    uint32 index = 0;
    if (CS_PRIV_LOW(head->flags)) {
        index = cm_hash_uint32((head->dst_inst & 0xFFFFFF) | (channel_id << 24), DTC_MSG_QUEUE_NUM) + 1;
    }
    if (mec_snd_compress(head) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[MEC]dtc compress failed. msg len[%u], src inst[%d], dst inst[%d], "
            "cmd[%u], flag[%u], stream id[%u], serial no[%u], batch size[%u], frag no [%u]",
            head->size, head->src_inst, head->dst_inst, head->cmd,
            head->flags, head->stream_id, head->serial_no, head->batch_size, head->frag_no);
        return CM_ERROR;
    }

    CM_MFENCE;
    put_msgitem(&mq_ctx->queue[index], msgitem);
    if (!mq_ctx->work_thread_idx[index].is_start) {
        cm_spin_lock(&mq_ctx->work_thread_idx[index].lock, NULL);
        if (!mq_ctx->work_thread_idx[index].is_start) {
            if (cm_event_init(&mq_ctx->work_thread_idx[index].event) != CM_SUCCESS) {
                LOG_RUN_ERR("[MEC]init thread %u event failed, error code %d.", index, cm_get_os_error());
                cm_spin_unlock(&mq_ctx->work_thread_idx[index].lock);
                return CM_ERROR;
            }
            if (cm_create_thread(dtc_task_proc, 0, (void *)&mq_ctx->work_thread_idx[index],
                                 &mq_ctx->tasks[index]) != CM_SUCCESS) {
                LOG_RUN_ERR("[MEC]create work thread %u failed.", index);
                cm_spin_unlock(&mq_ctx->work_thread_idx[index].lock);
                return CM_ERROR;
            }
            mq_ctx->work_thread_idx[index].is_start = CM_TRUE;
        }
        cm_spin_unlock(&mq_ctx->work_thread_idx[index].lock);
    }
    cm_event_notify(&mq_ctx->work_thread_idx[index].event);
    return CM_SUCCESS;
}

status_t mec_scale_out(uint32 inst_id, uint32 channel_id)
{
    mec_profile_t *profile = get_mec_profile();
    mec_context_t *mec_ctx = get_mec_ctx();
    mec_channel_t *channel = NULL;
    dcf_node_t node_item;
    uint16 i;
    status_t status;
    if (md_get_node(inst_id, &node_item) != CM_SUCCESS) {
        return CM_ERROR;
    }
    cm_spin_lock(&profile->lock, NULL);
    if (mec_ctx->is_connect[inst_id][channel_id]) {
        cm_spin_unlock(&profile->lock);
        return CM_SUCCESS;
    }
    for (i = 0; i < profile->inst_count; i++) {
        if (profile->maps[i] == inst_id) {
            break;
        }
    }
    if (i == profile->inst_count) {
        profile->maps[profile->inst_count] = inst_id;
        MEMS_RETURN_IFERR(strncpy_sp(profile->inst_arr[inst_id].t_addr.ip, CM_MAX_IP_LEN,
                                     node_item.ip, strlen(node_item.ip)));
        profile->inst_arr[inst_id].t_addr.port = node_item.port;
        CM_MFENCE;
        profile->inst_count++;
    }
    if (mec_ctx->channels[inst_id] == NULL) {
        CM_RETURN_IFERR_EX(mec_alloc_channel(inst_id), cm_spin_unlock(&profile->lock));
    }
    channel = &mec_ctx->channels[inst_id][channel_id];
    status = mec_connect_channel(channel);
    cm_spin_unlock(&profile->lock);
    return status;
}


bool32 mec_check_last(const uint64 inst_bits[INSTS_BIT_SZ], uint32 inst_id)
{
    for (uint32 i = inst_id + 1; i < CM_MAX_NODE_COUNT; i++) {
        if (MEC_IS_INST_SEND(inst_bits, i)) {
            return CM_FALSE;
        }
    }
    return CM_TRUE;
}

void get_broadcast_insts(const uint64 inst_bits[INSTS_BIT_SZ], char *buffer, uint32 buff_size)
{
    text_t text = {.str = buffer,
                   .len = 0};
    for (uint32 inst_id = 0; inst_id < CM_MAX_NODE_COUNT; inst_id++) {
        if (MEC_IS_INST_SEND(inst_bits, inst_id)) {
            cm_concat_fmt(&text, buff_size - text.len, "%d,", inst_id);
        }
    }
}

static status_t mec_write_fragment(mec_message_t *pack, const char *data,
                                   uint32 total_size, uint32 *curr_size,
                                   bool32 *fill_len)
{
    int32 remain_size;
    remain_size = MEC_REMAIN_SIZE(pack) - sizeof(uint32);
    if (remain_size < 0) {
        CM_BIT_RESET(pack->head->flags, CS_FLAG_END_DATA);
        pack->head->flags |= CS_FLAG_MORE_DATA;
        return CM_SUCCESS;
    }

    uint32 copy_size;
    if (*curr_size > (uint32)remain_size) {
        CM_BIT_RESET(pack->head->flags, CS_FLAG_END_DATA);
        pack->head->flags |= CS_FLAG_MORE_DATA;
        copy_size = remain_size;
    } else {
        CM_BIT_RESET(pack->head->flags, CS_FLAG_MORE_DATA);
        pack->head->flags |= CS_FLAG_END_DATA;
        copy_size = *curr_size;
    }

    if (*curr_size == total_size && !*fill_len) {
        (void)mec_put_int32(pack, total_size);
        *fill_len = CM_TRUE;
    }

    if (copy_size != 0) {
        MEMS_RETURN_IFERR(memcpy_sp(MEC_WRITE_ADDR(pack), MEC_REMAIN_SIZE(pack), data, copy_size));
    }

    GET_MSG_HEAD(pack)->size += copy_size;
    *curr_size -= copy_size;

    return CM_SUCCESS;
}

status_t mec_send_fragment(mec_message_t *pack, const char *data, uint32 size)
{
    mec_message_t fragment;
    mec_message_head_t head = *(pack->head);
    uint32 curr_size = size;
    uint32 align_size = CM_ALIGN4(size);
    bool32 fill_len = CM_FALSE;
    msg_priv_t priv = CS_PRIV_LOW(head.flags) ? PRIV_LOW : PRIV_HIGH;
    do {
        if (mec_write_fragment(pack, data + size - curr_size, size, &curr_size, &fill_len) != CM_SUCCESS) {
            mec_release_pack(pack);
            return CM_ERROR;
        }
        if (curr_size == 0) {
            GET_MSG_HEAD(pack)->size += (align_size - size);
            break;
        }
        if (get_mec_ctx()->phase != SHUTDOWN_PHASE_NOT_BEGIN) {
            mec_release_pack(pack);
            return CM_ERROR;
        }
        if (mec_send_data(pack) != CM_SUCCESS) {
            mec_release_pack(pack);
            return CM_ERROR;
        }
        CM_RETURN_IFERR(mec_get_message_buf(&fragment, head.dst_inst, priv));
        head.frag_no++;
        *fragment.head = head;
        fragment.head->size = sizeof(mec_message_head_t);
        fragment.options = pack->options;
        CM_BIT_RESET(fragment.options, CSO_BUFF_IN_QUEUE);
        *pack = fragment;
    } while (1);

    return CM_SUCCESS;
}

status_t mec_extend_pack(mec_message_t *pack)
{
    mec_message_t fragment;
    mec_message_head_t head = *pack->head;
    msg_priv_t priv = CS_PRIV_LOW(head.flags) ? PRIV_LOW : PRIV_HIGH;
    CM_BIT_RESET(pack->head->flags, CS_FLAG_END_DATA);
    pack->head->flags |= CS_FLAG_MORE_DATA;
    if (mec_send_data(pack) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[MEC]mec_extend_pack failed. msg len[%u], src inst[%d], dst inst[%d], "
            "cmd[%u], flag[%u], stream id[%u], serial no[%u], batch size[%u], frag no [%u]",
            head.size, head.src_inst, head.dst_inst, head.cmd,
            head.flags, head.stream_id, head.serial_no, head.batch_size, head.frag_no);
        mec_release_pack(pack);
        return CM_ERROR;
    }
    CM_RETURN_IFERR(mec_get_message_buf(&fragment, head.dst_inst, priv));
    *fragment.head = head;
    fragment.head->frag_no = head.frag_no + 1;
    fragment.options = pack->options;
    CM_BIT_RESET(fragment.options, CSO_BUFF_IN_QUEUE);
    fragment.head->size = sizeof(mec_message_head_t);
    CM_BIT_RESET(fragment.head->flags, CS_FLAG_MORE_DATA);
    fragment.head->flags |= CS_FLAG_END_DATA;
    *pack = fragment;
    return CM_SUCCESS;
}


status_t mec_get_data(mec_message_t *pack, uint32 size, void **buf)
{
    int64 len;
    char *temp_buf = NULL;
    len = CM_ALIGN4((int64)size);
    TO_UINT32_OVERFLOW_CHECK(len, int64);
    MEC_CHECK_RECV_PACK_FREE(pack, (uint32)len);
    temp_buf = MEC_READ_ADDR(pack);
    pack->offset += CM_ALIGN4(size);
    if (buf != NULL) {
        *buf = (void *)temp_buf;
    }
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif

