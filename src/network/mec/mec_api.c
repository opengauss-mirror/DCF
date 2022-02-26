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
 * mec_api.c
 *    mec process
 *
 * IDENTIFICATION
 *    src/network/mec/mec_api.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_timer.h"
#include "mec_reactor.h"
#include "mec_instance.h"
#include "mec_func.h"


#ifdef __cplusplus
extern "C" {
#endif

static mec_instance_t *g_mec = NULL;
mec_instance_t* get_mec_ptr()
{
    return g_mec;
}

thread_t* get_daemon_thread()
{
    return &g_mec->daemon_thread;
}

mq_context_t* get_send_mq_ctx()
{
    return &g_mec->send_mq;
}

mq_context_t* get_recv_mq_ctx()
{
    return &g_mec->recv_mq;
}

mec_context_t* get_mec_ctx()
{
    return &g_mec->mec_ctx;
}

mec_profile_t* get_mec_profile()
{
    return &g_mec->profile;
}

fragment_ctx_t* get_fragment_ctx()
{
    return &g_mec->fragment_ctx;
}

reactor_pool_t* get_mec_reactor(msg_priv_t priv)
{
    return &g_mec->reactor_pool[priv];
}

agent_pool_t* get_mec_agent(msg_priv_t priv)
{
    return &g_mec->agent_pool[priv];
}

static inline status_t init_buddy_pool()
{
    param_value_t init_size, max_size;
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_MEM_POOL_INIT_SIZE, &init_size));
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_MEM_POOL_MAX_SIZE, &max_size));
    // buffer memory  init
    mem_pool_t* buddy_pool = get_mem_pool();
    CM_RETURN_IFERR(buddy_pool_init("buddy pool", init_size.buddy_init_size, max_size.buddy_max_size, buddy_pool));
    return CM_SUCCESS;
}

status_t mec_init()
{
    if (init_buddy_pool() != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (g_mec != NULL) {
        return CM_SUCCESS;
    }
#ifndef WIN32
    if (pthread_key_create(addr_of_thread_key(), compress_ctx_destructor) != 0) {
        return CM_ERROR;
    }
#endif
    g_mec = (mec_instance_t *)malloc(sizeof(mec_instance_t));
    if (g_mec == NULL) {
        goto malloc_fail;
    }
    if (memset_sp(g_mec, sizeof(mec_instance_t), 0, sizeof(mec_instance_t)) != EOK) {
        goto memset_fail;
    }
#ifdef WIN32
    if (epoll_init() != CM_SUCCESS) {
        goto memset_fail;
    }
#endif
    if (init_mec_profile(get_mec_profile()) != CM_SUCCESS) {
        LOG_RUN_ERR("[MEC]init mec profile failed.");
        goto memset_fail;
    }
    if (mec_init_reactor() != CM_SUCCESS) {
        LOG_RUN_ERR("[MEC]init mec reactor failed.");
        goto memset_fail;
    }
    if (mec_init_core() != CM_SUCCESS) {
        goto init_core_fail;
    }

    LOG_RUN_INF("[MEC]Mec init succeed");
    return CM_SUCCESS;

init_core_fail:
    mec_deinit_reactor();
memset_fail:
    CM_FREE_PTR(g_mec);
malloc_fail:
#ifndef WIN32
    delete_thread_key();
#endif
    return CM_ERROR;
}

void mec_deinit()
{
    if (g_mec == NULL) {
        return;
    }

    get_mec_ctx()->phase = SHUTDOWN_PHASE_INPROGRESS;
    // pause external input
    mec_pause_lsnr(LSNR_TYPE_MES);
    reactor_pause_pool(get_mec_reactor(PRIV_HIGH));
    reactor_pause_pool(get_mec_reactor(PRIV_LOW));

    // close threads
    cm_close_thread(get_daemon_thread());
    sync_agents_closed(get_mec_agent(PRIV_HIGH));
    sync_agents_closed(get_mec_agent(PRIV_LOW));
    sync_tasks_closed(get_send_mq_ctx());
    sync_tasks_closed(get_recv_mq_ctx());

    // free resource
    mec_deinit_mq();
    fragment_ctx_deinit();
    mec_stop_lsnr();
    mec_deinit_reactor();
    mec_destory_channels();
    mec_deinit_ssl();

    get_mec_ctx()->phase = SHUTDOWN_PHASE_DONE;
    CM_FREE_PTR(g_mec);
#ifndef WIN32
    delete_thread_key();
#endif

    mem_pool_t* buddy_pool = get_mem_pool();
    buddy_pool_deinit(buddy_pool);
    return;
}

void register_msg_process(mec_command_t cmd, msg_proc_t proc, msg_priv_t priv)
{
    mec_context_t *mec_ctx = get_mec_ctx();
    if (cmd >= MEC_CMD_CEIL) {
        return;
    }
    mec_ctx->cb_processer[cmd].priv = priv;
    mec_ctx->cb_processer[cmd].proc = proc;
}

void unregister_msg_process(mec_command_t cmd)
{
    mec_context_t *mec_ctx = get_mec_ctx();
    mec_ctx->cb_processer[cmd].proc = NULL;
    mec_ctx->cb_processer[cmd].priv = PRIV_CEIL;
}

status_t mec_alloc_pack(mec_message_t *pack, mec_command_t cmd, uint32 src_inst, uint32 dst_inst, uint32 stream_id)
{
    mec_context_t *mec_ctx = get_mec_ctx();
    // get invalid
    if (cmd >= MEC_CMD_CEIL || mec_ctx->phase != SHUTDOWN_PHASE_NOT_BEGIN) {
        return CM_ERROR;
    }

    msg_priv_t priv = mec_ctx->cb_processer[cmd].priv;
    CM_RETURN_IFERR(mec_get_message_buf(pack, dst_inst, priv));
    mec_message_head_t *head = GET_MSG_HEAD(pack);
    head->cmd       = (uint8)cmd;
    head->src_inst  = src_inst;
    head->dst_inst  = dst_inst;
    head->stream_id = stream_id;
    head->size = sizeof(mec_message_head_t);
    head->flags = (priv == PRIV_HIGH ? 0 : CS_FLAG_PRIV_LOW);
    head->serial_no = 0;
    head->batch_size = 1;
    head->frag_no = 0;
    head->version = CS_LOCAL_VERSION;
    if (get_mec_profile()->algorithm != COMPRESS_NONE && priv) {
        head->flags |= CS_FLAG_COMPRESS;
    }

    if (dst_inst != CM_INVALID_NODE_ID) {
        uint8 channel_id = MEC_STREAM_TO_CHANNEL_ID(stream_id, get_mec_profile()->channel_num);
        if (dst_inst != src_inst) {
            if (SECUREC_UNLIKELY(!mec_ctx->is_connect[dst_inst][channel_id])) {
                if (mec_scale_out(dst_inst, channel_id) != CM_SUCCESS) {
                    LOG_RUN_ERR("[MEC]scale out failed src_inst[%u] to dest_inst[%u] when alloc pack.",
                        head->src_inst, head->dst_inst);
                    return CM_ERROR;
                }
                LOG_RUN_INF("[MEC]scale out src_inst[%u] to dest_inst[%u] when alloc pack.",
                    head->src_inst, head->dst_inst);
            }
        }
        mec_channel_t *channel = &mec_ctx->channels[dst_inst][channel_id];
        mec_pipe_t *pipe = &channel->pipe[priv];
        pack->options = pipe->send_pipe.options;
        head->serial_no = cm_atomic32_inc(&channel->serial_no);
    }
    return CM_SUCCESS;
}


status_t mec_send_data(mec_message_t *pack)
{
    mec_message_head_t *head = pack->head;
    mec_profile_t *profile = get_mec_profile();
    mec_context_t *mec_ctx = get_mec_ctx();
    uint32 channel_id = MEC_STREAM_TO_CHANNEL_ID(head->stream_id, profile->channel_num);
    msg_priv_t priv = CS_PRIV_LOW(head->flags) ? PRIV_LOW : PRIV_HIGH;
    head->time1 = g_timer()->now;
    LOG_DEBUG_INF("[MEC]begin send pack to dest[%u],priv[%u],serial_no[%u],flag[%u],frag no [%u]",
                  head->dst_inst, priv, head->serial_no, head->flags, head->frag_no);
    if (SECUREC_UNLIKELY(head->size > MEC_MESSAGE_BUFFER_SIZE(get_mec_profile()))) {
        LOG_DEBUG_ERR("[MEC]send data length %u excced max %llu", head->size,
                      MEC_MESSAGE_BUFFER_SIZE(get_mec_profile()));
        return CM_ERROR;
    }

    CM_ASSERT(CM_BIT_TEST(pack->options, CSO_BUFF_IN_QUEUE) == 0);
    if (mec_ctx->phase != SHUTDOWN_PHASE_NOT_BEGIN) {
        LOG_DEBUG_ERR("[MEC]mec_send_data fail, not begin now.dest[%u],priv[%u]", head->dst_inst, priv);
        return CM_ERROR;
    }

    bool32 is_send = CM_TRUE;
    // send direct to recevied queue
    if (head->dst_inst == profile->inst_id) {
        // send to self no need to compress
        CM_BIT_RESET(head->flags, CS_FLAG_COMPRESS);
        is_send = CM_FALSE;
    } else {
        if (SECUREC_UNLIKELY(!mec_ctx->is_connect[head->dst_inst][channel_id])) {
            if (mec_scale_out(head->dst_inst, channel_id) != CM_SUCCESS) {
                LOG_RUN_ERR("[MEC]scale out failed src_inst[%u] to dest_inst[%u] when send data.",
                    head->src_inst, head->dst_inst);
                return CM_ERROR;
            }
            LOG_RUN_INF("[MEC]scale out src_inst[%u] to dest_inst[%u] when send data.", head->src_inst, head->dst_inst);
        }

        mec_channel_t *channel = &mec_ctx->channels[head->dst_inst][channel_id];
        if (!channel->pipe[priv].send_pipe_active) {
            LOG_DEBUG_ERR("[MEC]data send_pipe to dst_inst[%u] priv[%u] is not ready.", head->dst_inst, priv);
            return CM_ERROR;
        }
    }

    if (mec_put_msg_queue((const void *)head, is_send) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[MEC]mec_send_data put_msg_queue fail.dest[%u],priv[%u]", head->dst_inst, priv);
        return CM_ERROR;
    }

    CM_BIT_SET(pack->options, CSO_BUFF_IN_QUEUE);

    LOG_DEBUG_INF("[MEC]end send pack to dest[%u],priv[%u],serial_no[%u],flag[%u],frag no [%u]",
                  head->dst_inst, priv, head->serial_no, head->flags, head->frag_no);
    return CM_SUCCESS;
}

void mec_broadcast(uint32 stream_id, uint64 inst_bits[INSTS_BIT_SZ], mec_message_t *pack,
    uint64 success_bits[INSTS_BIT_SZ])
{
    mec_message_head_t *head = pack->head;
    mec_message_t  copy_pack;
    mec_message_t *brd_pack;
    char all_insts[MAX_INST_STR_LEN] = { 0 };
    char success_insts[MAX_INST_STR_LEN] = { 0 };
    msg_priv_t priv = CS_PRIV_LOW(head->flags) ? PRIV_LOW : PRIV_HIGH;
    if (SECUREC_UNLIKELY(head->size > MEC_MESSAGE_BUFFER_SIZE(get_mec_profile())) ||
        get_mec_ctx()->phase != SHUTDOWN_PHASE_NOT_BEGIN) {
        mec_release_pack(pack);
        return;
    }
    for (uint32 inst_id = 0; inst_id < CM_MAX_NODE_COUNT; inst_id++) {
        MEC_RESET_BRD_INST(success_bits, inst_id);
        if (inst_id == get_mec_profile()->inst_id) {
            continue;
        }
        if (MEC_IS_INST_SEND(inst_bits, inst_id)) {
            head->dst_inst = inst_id;
            brd_pack = pack;
            if (!mec_check_last(inst_bits, inst_id)) {
                if (mec_get_message_buf(&copy_pack, inst_id, priv) != CM_SUCCESS) {
                    break;
                }
                errno_t ret = memcpy_sp(copy_pack.head, copy_pack.aclt_size, head, head->size);
                if (ret != EOK) {
                    mec_release_pack(&copy_pack);
                    break;
                }
                brd_pack = &copy_pack;
            }
            if (mec_send_data(brd_pack) != CM_SUCCESS) {
                mec_release_pack(brd_pack);
                continue;
            }
            MEC_INST_SENT_SUCCESS(success_bits, inst_id);
        }
    }
    if (memcmp(inst_bits, success_bits, INSTS_BIT_SZ * sizeof(uint64)) != 0) {
        get_broadcast_insts(inst_bits, all_insts, MAX_INST_STR_LEN);
        get_broadcast_insts(success_bits, success_insts, MAX_INST_STR_LEN);
        LOG_DEBUG_ERR("[MEC]broad cast failed, broad cast insts %s success insts %s",
            CM_IS_EMPTY_STR(all_insts) ? "NA" : all_insts, CM_IS_EMPTY_STR(success_insts) ? "NA" : success_insts);
    }
    return;
}

status_t mec_put_int64(mec_message_t *pack, uint64 value)
{
    if (!MEC_HAS_REMAIN(pack, sizeof(uint64))) {
        if (GET_MSG_HEAD(pack)->dst_inst == CM_INVALID_NODE_ID) {
            CM_THROW_ERROR(ERR_PACKET_SEND, pack->buf_size, GET_MSG_HEAD(pack)->size, sizeof(uint64));
            LOG_DEBUG_ERR("[MEC]mec_put dst_inst error,buff size: %u,head size: %u,put size: %u.",
                          pack->buf_size, GET_MSG_HEAD(pack)->size, (uint32)sizeof(uint64));
            return CM_ERROR;
        }
        if (mec_extend_pack(pack) != CM_SUCCESS) {
            return CM_ERROR;
        }
    }

    *(uint64 *)MEC_WRITE_ADDR(pack) = CS_DIFFERENT_ENDIAN(pack->options) ? cs_reverse_int64(value) : value;
    GET_MSG_HEAD(pack)->size += sizeof(uint64);
    return CM_SUCCESS;
}

status_t mec_put_int32(mec_message_t *pack, uint32 value)
{
    if (!MEC_HAS_REMAIN(pack, sizeof(uint32))) {
        if (GET_MSG_HEAD(pack)->dst_inst == CM_INVALID_NODE_ID) {
            CM_THROW_ERROR(ERR_PACKET_SEND, pack->buf_size, GET_MSG_HEAD(pack)->size, sizeof(uint32));
            LOG_DEBUG_ERR("[MEC]mec_put dst_inst error,buff size: %u,head size: %u,put size: %u.",
                          pack->buf_size, GET_MSG_HEAD(pack)->size, (uint32)sizeof(uint32));
            return CM_ERROR;
        }
        if (mec_extend_pack(pack) != CM_SUCCESS) {
            return CM_ERROR;
        }
    }

    *(uint32 *)MEC_WRITE_ADDR(pack) = CS_DIFFERENT_ENDIAN(pack->options) ? cs_reverse_int32(value) : value;
    GET_MSG_HEAD(pack)->size += sizeof(uint32);
    return CM_SUCCESS;
}

status_t mec_put_int16(mec_message_t *pack, uint16 value)
{
    if (!MEC_HAS_REMAIN(pack, (uint32)CS_ALIGN_SIZE)) {
        if (GET_MSG_HEAD(pack)->dst_inst == CM_INVALID_NODE_ID) {
            CM_THROW_ERROR(ERR_PACKET_SEND, pack->buf_size, GET_MSG_HEAD(pack)->size, (uint32)CS_ALIGN_SIZE);
            LOG_DEBUG_ERR("[MEC]mec_put dst_inst error,buff size: %u,head size: %u,put size: %u.",
                          pack->buf_size, GET_MSG_HEAD(pack)->size, (uint32)CS_ALIGN_SIZE);
            return CM_ERROR;
        }
        if (mec_extend_pack(pack) != CM_SUCCESS) {
            return CM_ERROR;
        }
    }

    *(uint16 *)MEC_WRITE_ADDR(pack) = CS_DIFFERENT_ENDIAN(pack->options) ? cs_reverse_int16(value) : value;
    GET_MSG_HEAD(pack)->size += CS_ALIGN_SIZE;
    return CM_SUCCESS;
}

status_t mec_put_double(mec_message_t *pack, double value)
{
    if (!MEC_HAS_REMAIN(pack, sizeof(double))) {
        if (GET_MSG_HEAD(pack)->dst_inst == CM_INVALID_NODE_ID) {
            CM_THROW_ERROR(ERR_PACKET_SEND, pack->buf_size, GET_MSG_HEAD(pack)->size, sizeof(double));
            LOG_DEBUG_ERR("[MEC]mec_put dst_inst error,buff size: %u,head size: %u,put size: %u.",
                          pack->buf_size, GET_MSG_HEAD(pack)->size, (uint32)sizeof(double));
            return CM_ERROR;
        }
        if (mec_extend_pack(pack) != CM_SUCCESS) {
            return CM_ERROR;
        }
    }
    *(double *)MEC_WRITE_ADDR(pack) = CS_DIFFERENT_ENDIAN(pack->options) ? cs_reverse_real(value) : value;
    GET_MSG_HEAD(pack)->size += sizeof(double);
    return CM_SUCCESS;
}

status_t mec_put_bin(mec_message_t *pack, uint32 size, const void *buffer)
{
    uint32 align_size = sizeof(uint32) + CM_ALIGN4(size);
    if (!MEC_HAS_REMAIN(pack, align_size)) {
        if (GET_MSG_HEAD(pack)->dst_inst == CM_INVALID_NODE_ID) {
            CM_THROW_ERROR(ERR_PACKET_SEND, (pack)->buf_size, GET_MSG_HEAD(pack)->size, (uint32)align_size);
            LOG_DEBUG_ERR("[MEC]mec_put dst_inst error,buff size: %u,head size: %u,put size: %u.",
                          (pack)->buf_size, GET_MSG_HEAD(pack)->size, (uint32)align_size);
            return CM_ERROR;
        }
        return mec_send_fragment(pack, buffer, size);
    }
    /* put the length of text */
    CM_RETURN_IFERR(mec_put_int32(pack, size));
    if (size == 0) {
        return CM_SUCCESS;
    }
    /* put the string of text, and append the terminated sign */
    MEMS_RETURN_IFERR(memcpy_sp(MEC_WRITE_ADDR(pack), MEC_REMAIN_SIZE(pack), buffer, size));
    GET_MSG_HEAD(pack)->size += CM_ALIGN4(size);
    return CM_SUCCESS;
}

status_t mec_get_int64(mec_message_t *pack, int64 *value)
{
    int64 temp_value;
    MEC_CHECK_RECV_PACK_FREE(pack, sizeof(int64));
    temp_value = *(int64 *)MEC_READ_ADDR(pack);
    temp_value = CS_DIFFERENT_ENDIAN(pack->options) ? cs_reverse_int64(temp_value) : temp_value;
    pack->offset += sizeof(int64);
    if (value != NULL) {
        *value = temp_value;
    }
    return CM_SUCCESS;
}

status_t mec_get_int32(mec_message_t *pack, int32 *value)
{
    int32 temp_value;
    MEC_CHECK_RECV_PACK_FREE(pack, sizeof(int32));
    temp_value = *(int32 *)MEC_READ_ADDR(pack);
    pack->offset += sizeof(int32);
    temp_value = CS_DIFFERENT_ENDIAN(pack->options) ? cs_reverse_int32(temp_value) : temp_value;
    if (value != NULL) {
        *value = temp_value;
    }
    return CM_SUCCESS;
}

/* need keep 4-byte align by the caller */
status_t mec_get_int16(mec_message_t *pack, int16 *value)
{
    int16 temp_value;
    MEC_CHECK_RECV_PACK_FREE(pack, CS_ALIGN_SIZE);

    temp_value = *(int16 *)MEC_READ_ADDR(pack);
    pack->offset += CS_ALIGN_SIZE;
    temp_value = CS_DIFFERENT_ENDIAN(pack->options) ? cs_reverse_int16(temp_value) : temp_value;
    if (value != NULL) {
        *value = temp_value;
    }
    return CM_SUCCESS;
}

status_t mec_get_double(mec_message_t *pack, double *value)
{
    double temp_value;
    MEC_CHECK_RECV_PACK_FREE(pack, sizeof(double));
    temp_value = *(double *)MEC_READ_ADDR(pack);
    pack->offset += sizeof(double);
    temp_value = CS_DIFFERENT_ENDIAN(pack->options) ? cs_reverse_real(temp_value) : temp_value;
    if (value != NULL) {
        *value = temp_value;
    }
    return CM_SUCCESS;
}

status_t mec_get_bin(mec_message_t *pack, uint32 *size, void **buffer)
{
    CM_RETURN_IFERR(mec_get_int32(pack, (int32 *)size));
    return mec_get_data(pack, *size, buffer);
}

uint32 mec_get_write_pos(const mec_message_t *pack)
{
    return pack->head->size;
}

void mec_modify_int64(mec_message_t *pack, uint32 pos, uint64 value)
{
    *(uint64 *)(GET_MSG_BUFF(pack) + pos) = CS_DIFFERENT_ENDIAN(pack->options) ? cs_reverse_int64(value) : value;
}

bool32 mec_check_one_connect(uint32 inst_id)
{
    mec_profile_t *profile = get_mec_profile();
    mec_context_t *mec_ctx = get_mec_ctx();
    mec_channel_t *channel = NULL;
    mec_pipe_t *pipe;
    bool32 ready = CM_TRUE;

    for (uint32 j = 0; j < profile->channel_num; j++) {
        channel = &mec_ctx->channels[inst_id][j];
        for (uint32 k = 0; k < PRIV_CEIL; k++) {
            pipe = &channel->pipe[k];
            if (!pipe->send_pipe_active || !pipe->recv_pipe_active) {
                LOG_RUN_INF("[MEC]dest_inst=%d, channel=%d pipe=%d is not ready, waiting...", inst_id, j, k);
                ready = CM_FALSE;
            }
        }
    }

    return ready;
}

bool32 mec_check_all_connect()
{
    uint32 inst_id;
    mec_profile_t *profile = get_mec_profile();

    for (uint32 i = 0; i < profile->inst_count; i++) {
        inst_id = GET_INST_INDEX(i, profile);
        if (inst_id == profile->inst_id) {
            continue;
        }

        if (mec_check_one_connect(inst_id) == CM_FALSE) {
            return CM_FALSE;
        }
    }

    return CM_TRUE;
}

static inline bool32 is_node_in_new_profile(uint32 node_id)
{
    mec_profile_t *profile = get_mec_profile();
    for (uint32 i = 0; i < profile->inst_count; i++) {
        if (node_id == GET_INST_INDEX(i, profile)) {
            return CM_TRUE;
        }
    }
    return CM_FALSE;
}

void mec_close_node_pipe(uint32 inst_id)
{
    mec_channel_t *channel = NULL;
    mec_pipe_t *pipe;
    mec_context_t *mec_ctx = get_mec_ctx();
    mec_profile_t *profile = get_mec_profile();
    if (inst_id == profile->inst_id || mec_ctx->channels == NULL) {
        return;
    }

    for (uint32 i = 0; i < profile->channel_num; i++) {
        channel = &mec_ctx->channels[inst_id][i];
        for (uint32 j = 0; j < PRIV_CEIL; j++) {
            pipe = &channel->pipe[j];
            (void)cm_atomic32_cas(&pipe->send_need_close, CM_FALSE, CM_TRUE);
            (void)cm_atomic32_cas(&pipe->recv_need_close, CM_FALSE, CM_TRUE);
        }
    }

    LOG_RUN_INF("[MEC]set pipe need close of node %u.", inst_id);

    return;
}

status_t mec_update_profile_inst()
{
    uint32 i;
    mec_profile_t *profile = get_mec_profile();
    uint32 old_nodes[CM_MAX_NODE_COUNT];
    uint32 old_node_count = profile->inst_count;
    for (i = 0; i < old_node_count; i++) {
        old_nodes[i] = GET_INST_INDEX(i, profile);
    }

    if (init_mec_profile_inst(profile) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[MEC]get node info from metadata fail.");
        return CM_ERROR;
    }
    LOG_RUN_INF("[MEC]update profile inst ok. old_node_count=%u, inst_count=%u.", old_node_count, profile->inst_count);

    /* close removed node's pipe */
    if (old_node_count > profile->inst_count) {
        for (i = 0; i < old_node_count; i++) {
            if (is_node_in_new_profile(old_nodes[i]) == CM_FALSE) {
                mec_close_node_pipe(old_nodes[i]);
            }
        }
    }

    return CM_SUCCESS;
}

bool32 mec_is_ready(uint32 stream_id, uint32 dst_inst, msg_priv_t priv)
{
    mec_context_t *mec_ctx = get_mec_ctx();
    mec_profile_t *profile = get_mec_profile();
    uint32 channel_id = MEC_STREAM_TO_CHANNEL_ID(stream_id, profile->channel_num);
    mec_channel_t *channel = &mec_ctx->channels[dst_inst][channel_id];
    if (channel == NULL) {
        return CM_FALSE;
    }

    return channel->pipe[priv].send_pipe_active;
}

status_t mec_get_peer_version(uint32 stream_id, uint32 dst_inst, uint32 *peer_version)
{
    mec_context_t *mec_ctx = get_mec_ctx();
    mec_profile_t *profile = get_mec_profile();
    uint32 channel_id = MEC_STREAM_TO_CHANNEL_ID(stream_id, profile->channel_num);
    mec_channel_t *channel = &mec_ctx->channels[dst_inst][channel_id];
    if (channel == NULL) {
        LOG_DEBUG_ERR("[MEC]null channel or peer_version, stream_id %u, dst_inst %u", stream_id, dst_inst);
        return CM_ERROR;
    }
    *peer_version = channel->pipe[PRIV_HIGH].send_pipe.version;
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif

