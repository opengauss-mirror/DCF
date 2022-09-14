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
 * rep_follower.c
 *    follower  process
 *
 * IDENTIFICATION
 *    src/replication/rep_follower.c
 *
 * -------------------------------------------------------------------------
 */

#include "rep_common.h"
#include "rep_msg_pack.h"
#include "dcf_interface.h"
#include "util_perf_stat.h"

typedef struct st_rep_follower_state_t {
    volatile log_id_t   leader_commit_log;
    volatile log_id_t   last_append_log;
    log_id_t            last_ack_log_id;
    uint64              last_ack_time;
    uint64              leader_term;
    uint64              leader_last_index;
}rep_follower_state_t;

// follower state
rep_follower_state_t  g_follower_state[CM_MAX_STREAM_COUNT];

#define LEADER_COMMIT_IDX (g_follower_state[stream_id].leader_commit_log)
#define LEADER_LAST_IDX (g_follower_state[stream_id].leader_last_index)
#define LEADER_TERM (g_follower_state[stream_id].leader_term)
#define LAST_APPEND_IDX (g_follower_state[stream_id].last_append_log)
#define LAST_ACK_IDX (g_follower_state[stream_id].last_ack_log_id)
#define LAST_ACK_TIME (g_follower_state[stream_id].last_ack_time)
#define SEND_ACK_RETRY_INTERVAL (1*MICROSECS_PER_SECOND)    // ms

static status_t rep_appendlog_req_proc(mec_message_t *pack);

void rep_follower_reset(uint32 stream_id)
{
    log_id_t* invalid_log_id = get_invalid_log_id();
    LEADER_COMMIT_IDX = *invalid_log_id;
    LAST_APPEND_IDX = *invalid_log_id;
    LAST_ACK_IDX = *invalid_log_id;
    LAST_ACK_TIME = 0;
    LEADER_TERM = CM_INVALID_TERM_ID;
    LEADER_LAST_IDX = CM_INVALID_INDEX_ID;

    LOG_DEBUG_INF("[REP]rep_follower_reset,stream_id=%u.", stream_id);
}

status_t rep_follower_init()
{
    uint32 streams[CM_MAX_STREAM_COUNT];
    uint32 stream_count;
    uint32 stream_id;

    register_msg_process(MEC_CMD_APPEND_LOG_RPC_REQ, rep_appendlog_req_proc, PRIV_LOW);

    CM_RETURN_IFERR(md_get_stream_list(streams, &stream_count));
    for (uint32 i = 0; i < stream_count; i++) {
        stream_id = streams[i];
        rep_follower_reset(stream_id);
    }

    return CM_SUCCESS;
}

static status_t rep_follower_appendlog(uint32 stream_id, const rep_apendlog_req_t* appendlog_req, mec_message_t *pack,
    rep_log_t* log0, errno_t* error_no)
{
    if (appendlog_req->log_count == 0) {
        return CM_SUCCESS;
    }

    ps_start(log0->log_id.index, g_timer()->now);
    if (stg_append_entry(stream_id, log0->log_id.term, log0->log_id.index, log0->buf, log0->size,
        log0->key, log0->type, NULL) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[REP]stg_append_entry failed, log0 index=%llu", log0->log_id.index);
        *error_no = ERR_APPEND_ENTRY_FAILED;
        return CM_ERROR;
    }
    LAST_APPEND_IDX = log0->log_id;

    for (uint64 i = 1; i < appendlog_req->log_count; i++) {
        rep_log_t log;
        if (rep_decode_one_log(pack, &log) != CM_SUCCESS) {
            LOG_DEBUG_ERR("[REP]rep_decode_one_log failed");
            *error_no = ERR_APPEND_ENTRY_FAILED;
            return CM_ERROR;
        }

        ps_start(log.log_id.index, g_timer()->now);
        if (stg_append_entry(stream_id, log.log_id.term, log.log_id.index, log.buf, log.size,
            log.key, log.type, NULL) != CM_SUCCESS) {
            LOG_DEBUG_ERR("[REP]stg_append_entry failed, log index=%llu", log.log_id.index);
            *error_no = ERR_APPEND_ENTRY_FAILED;
            return CM_ERROR;
        }
        LAST_APPEND_IDX = log.log_id;
    }

    return CM_SUCCESS;
}

static status_t rep_check_exception(uint32 stream_id, const rep_apendlog_req_t* appendlog_req, const errno_t* error_no)
{
    if (*error_no != ERR_TERM_IS_NOT_MATCH) {
        return CM_SUCCESS;
    }

    uint64 last_index = stg_last_index(stream_id);
    uint64 applied_idx = stg_get_applied_index(stream_id);
    if (applied_idx + 1 < appendlog_req->leader_first_log.index && last_index < appendlog_req->leader_first_log.index) {
        LOG_DEBUG_ERR("[REP]first index term not match. last index %llu, leader first log index %llu",
            stg_last_index(stream_id), appendlog_req->leader_first_log.index);
        dcf_set_exception(stream_id, DCF_EXCEPTION_MISSING_LOG);
        return CM_ERROR;
    }

    uint64 term = stg_get_term(stream_id, appendlog_req->leader_first_log.index);
    if (term != CM_INVALID_TERM_ID && term != appendlog_req->leader_first_log.term) {
        LOG_DEBUG_ERR("[REP]first index term not match. leader first log index %llu, term [%llu != %llu]",
            appendlog_req->leader_first_log.index, appendlog_req->leader_first_log.term, term);
        dcf_set_exception(stream_id, DCF_EXCEPTION_MISSING_LOG);
        return CM_ERROR;
    }

    return CM_ERROR;
}

static status_t rep_follower_check_log_count(uint32 stream_id, const rep_apendlog_req_t* appendlog_req,
    errno_t* error_no)
{
    if (appendlog_req->log_count == 0) {
        // the pre log is matched
        if (LAST_APPEND_IDX.index == CM_INVALID_INDEX_ID) {
            LAST_APPEND_IDX.index = appendlog_req->pre_log.index;
            LAST_APPEND_IDX.term = stg_get_term(stream_id, appendlog_req->pre_log.index);
        }
        log_id_t last_log = stg_last_log_id(stream_id);
        if (appendlog_req->leader_last_index > last_log.index) {
            LOG_DEBUG_WAR("[REP]append_log request may be lost. leader last log = %llu, my last log %llu",
                appendlog_req->leader_last_index, last_log.index);
            *error_no = ERR_APPEN_LOG_REQ_LOST;
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

static void rep_follower_check_log_match(uint32 stream_id, const rep_apendlog_req_t* appendlog_req,
    const rep_log_t* log0, errno_t* error_no)
{
    if (appendlog_req->pre_log.index == CM_INVALID_INDEX_ID) {
        return;
    }
    if (appendlog_req->pre_log.index <= stg_get_applied_index(stream_id)) {
        return;
    }
    uint64 last_index = stg_last_index(stream_id);
    if (last_index != CM_INVALID_INDEX_ID && last_index < appendlog_req->leader_first_log.index) {
        LOG_DEBUG_ERR("[REP]log is not continue, last log's idx = %llu, first idx %llu",
            last_index, appendlog_req->leader_first_log.index);
        *error_no = ERR_TERM_IS_NOT_MATCH;
        return;
    }

    uint64 pre_log_term = stg_get_term(stream_id, appendlog_req->pre_log.index);
    if (appendlog_req->pre_log.term == pre_log_term) {
        return;
    }

    if (appendlog_req->pre_log.term != CM_INVALID_TERM_ID) {
        LOG_DEBUG_ERR("[REP]pre log term is not match.index = %llu, term[%llu != %llu]",
            appendlog_req->pre_log.index, appendlog_req->pre_log.term, pre_log_term);
        *error_no = ERR_TERM_IS_NOT_MATCH;
    } else {
        if (appendlog_req->log_count != 0) {
            uint64 cur_log_term = stg_get_term(stream_id, appendlog_req->pre_log.index + 1);
            if (cur_log_term != log0->log_id.term) {
                LOG_DEBUG_ERR("[REP]pre log term is not match. leader's pre log is invalid. match.index = %llu,"
                    " term[%llu != %llu]",
                    log0->log_id.index, log0->log_id.term, cur_log_term);
                *error_no = ERR_TERM_IS_NOT_MATCH;
            }
        }
    }
}

static status_t rep_follower_process(uint32 stream_id, rep_apendlog_req_t* appendlog_req, mec_message_t *pack,
    rep_log_t* log0, errno_t* error_no)
{
    uint64 cur_term = elc_get_current_term(stream_id);
    *error_no = 0;

    if (appendlog_req->leader_term < cur_term) {
        LOG_DEBUG_ERR("[REP]leader's term is less than mine.");
        *error_no = ERR_TERM_IS_EXPIRED;
        return CM_ERROR;
    } else if (appendlog_req->leader_term > cur_term) {
        if (I_AM_LEADER(stream_id)) {
            (void)elc_judge_term(stream_id, appendlog_req->leader_term);
            LOG_DEBUG_INF("[REP]another leader's term is greater than mine.[%llu > %llu]",
                appendlog_req->leader_term, cur_term);
        } else {
            LOG_DEBUG_INF("[REP]leader's term is greater than mine.[%llu > %llu]",
                appendlog_req->leader_term, cur_term);
        }

        return CM_SUCCESS;
    } else {
        if (I_AM_LEADER(stream_id)) {
            LOG_DEBUG_INF("[REP] I'm leader,can not receive log now.");
            return CM_SUCCESS;
        }
    }

    if (LEADER_TERM != appendlog_req->leader_term) {
        rep_follower_reset(stream_id);
        LEADER_TERM = appendlog_req->leader_term;
    }

    LEADER_LAST_IDX = appendlog_req->leader_last_index;
    LEADER_COMMIT_IDX = appendlog_req->leader_commit_log;
    rep_set_accept_flag(stream_id);
    rep_set_cluster_min_apply_idx(stream_id, appendlog_req->cluster_min_apply_id);

    rep_follower_check_log_match(stream_id, appendlog_req, log0, error_no);

    CM_RETURN_IFERR(rep_check_exception(stream_id, appendlog_req, error_no));

    CM_RETURN_IFERR(rep_follower_check_log_count(stream_id, appendlog_req, error_no));

    CM_RETURN_IFERR(rep_follower_appendlog(stream_id, appendlog_req, pack, log0, error_no));

    return CM_SUCCESS;
}

static status_t rep_follower_send_ack1(uint32 stream_id, uint32 leader, const rep_apendlog_req_t* appendlog_req,
    errno_t error_no)
{
    rep_apendlog_ack_t appendlog_ack;
    mec_message_t ack_pack;
    CM_RETURN_IFERR(mec_alloc_pack(&ack_pack, MEC_CMD_APPEND_LOG_RPC_ACK, md_get_cur_node(),
        leader, stream_id));

    appendlog_ack.head.req_seq = appendlog_req->head.req_seq;
    appendlog_ack.head.ack_seq = g_timer()->now;
    appendlog_ack.head.msg_ver = REP_MSG_VER;
    appendlog_ack.follower_term = elc_get_current_term(stream_id);
    appendlog_ack.ret_code = error_no;
    appendlog_ack.pre_log = appendlog_req->pre_log;
    appendlog_ack.mismatch_log.term = CM_INVALID_TERM_ID;
    appendlog_ack.mismatch_log.index = CM_INVALID_INDEX_ID;
    appendlog_ack.follower_accept_log.term = CM_INVALID_TERM_ID;
    appendlog_ack.follower_accept_log.index = CM_INVALID_INDEX_ID;
    appendlog_ack.apply_id = stg_get_applied_index(stream_id);

    if (error_no == ERR_TERM_IS_NOT_MATCH) {
        log_id_t last_log = stg_last_log_id(stream_id);
        appendlog_ack.mismatch_log = appendlog_req->pre_log;
        if (last_log.index < appendlog_req->pre_log.index) {
            appendlog_ack.mismatch_log = last_log;
            LOG_DEBUG_INF("[REP]set mismatch_log1 (%llu,%llu).", last_log.term, last_log.index);
        } else {
            appendlog_ack.mismatch_log = rep_get_pre_term_log(stream_id, appendlog_req->pre_log.index);
            LOG_DEBUG_INF("[REP]set mismatch_log2 (%llu,%llu).",
                appendlog_ack.mismatch_log.term, appendlog_ack.mismatch_log.index);
        }
    }

    if (rep_encode_appendlog_ack(&ack_pack, &appendlog_ack) != CM_SUCCESS) {
        mec_release_pack(&ack_pack);
        LOG_DEBUG_ERR("[REP]rep_encode_appendlog_ack failed.");
        return CM_ERROR;
    }

    LOG_TRACE(rep_get_tracekey(), "send ack" REP_APPEND_ACK_FMT, REP_APPEND_ACK_VAL(&ack_pack, &appendlog_ack));
    if (mec_send_data(&ack_pack) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[REP]send ack failed." REP_APPEND_ACK_FMT,
            REP_APPEND_ACK_VAL(&ack_pack, &appendlog_ack));
    } else {
        LOG_DEBUG_INF("[REP]send ack succeed." REP_APPEND_ACK_FMT,
            REP_APPEND_ACK_VAL(&ack_pack, &appendlog_ack));
        LOG_TRACE(rep_get_tracekey(), "send ack success");
    }

    mec_release_pack(&ack_pack);

    return CM_SUCCESS;
}

// follower process append log message
static status_t rep_appendlog_req_proc(mec_message_t *pack)
{
    rep_apendlog_req_t appendlog_req;
    uint32 stream_id = pack->head->stream_id;
    errno_t error_no;

    if (rep_decode_appendlog_head(pack, &appendlog_req) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[REP]rep_decode_appendlog_req failed.");
        return CM_ERROR;
    }

    rep_log_t log0;
    if (appendlog_req.log_count > 0) {
        if (rep_decode_one_log(pack, &log0) != CM_SUCCESS) {
            LOG_DEBUG_ERR("[REP]rep_decode_log0 failed, log_count=%llu", appendlog_req.log_count);
            return CM_ERROR;
        }
        if (appendlog_req.head.trace_key >= log0.log_id.index &&
            appendlog_req.head.trace_key < log0.log_id.index + appendlog_req.log_count) {
            rep_save_tracekey(appendlog_req.head.trace_key);
            set_trace_key(appendlog_req.head.trace_key);
        }
    }

    LOG_DEBUG_INF("[REP]recv append_req:" REP_APPEND_REQ_FMT,
        REP_APPEND_REQ_VAL(pack, &appendlog_req, log0.log_id.index));

    status_t ret = rep_follower_process(stream_id, &appendlog_req, pack, &log0, &error_no);
    if (ret != CM_SUCCESS) {
        return rep_follower_send_ack1(stream_id, pack->head->src_inst, &appendlog_req, error_no);
    }
    (void)elc_set_hb_timeout(stream_id, cm_clock_now());
    return CM_SUCCESS;
}

status_t rep_follower_send_ack(uint32 stream_id, uint32 leader, const log_id_t* last_accept_log)
{
    mec_message_t pack;
    rep_apendlog_ack_t appendlog_ack;

    CM_RETURN_IFERR(mec_alloc_pack(&pack, MEC_CMD_APPEND_LOG_RPC_ACK, md_get_cur_node(),
        leader, stream_id));

    appendlog_ack.head.req_seq = 0;
    appendlog_ack.head.ack_seq = g_timer()->now;
    appendlog_ack.head.msg_ver = REP_MSG_VER;
    appendlog_ack.follower_term = elc_get_current_term(stream_id);
    appendlog_ack.pre_log.term = CM_INVALID_TERM_ID;
    appendlog_ack.pre_log.index = CM_INVALID_INDEX_ID;
    appendlog_ack.ret_code = 0;
    appendlog_ack.mismatch_log.term = CM_INVALID_TERM_ID;
    appendlog_ack.mismatch_log.index = CM_INVALID_INDEX_ID;
    // when rematch is success, the log is less than last accept log
    if (LAST_APPEND_IDX.index >= (*last_accept_log).index) {
        appendlog_ack.follower_accept_log = *last_accept_log;
    } else {
        appendlog_ack.follower_accept_log = LAST_APPEND_IDX;
    }

    appendlog_ack.apply_id = stg_get_applied_index(stream_id);

    if (rep_encode_appendlog_ack(&pack, &appendlog_ack) !=  CM_SUCCESS) {
        mec_release_pack(&pack);
        return CM_ERROR;
    }

    LOG_TRACE(rep_get_tracekey(), "send ack " REP_APPEND_ACK_FMT, REP_APPEND_ACK_VAL(&pack, &appendlog_ack));

    if (mec_send_data(&pack) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[REP]send ack failed." REP_APPEND_ACK_FMT,
            REP_APPEND_ACK_VAL(&pack, &appendlog_ack));
    } else {
        LOG_DEBUG_INF("[REP]send ack succeed." REP_APPEND_ACK_FMT,
            REP_APPEND_ACK_VAL(&pack, &appendlog_ack));
        LOG_TRACE(rep_get_tracekey(), "follower send ack success");
    }

    mec_release_pack(&pack);

    return CM_SUCCESS;
}

// called by accept thread
status_t rep_follower_acceptlog_proc(uint32 stream_id)
{
    LOG_TRACE(rep_get_tracekey(), "rep_follwer: rep_follower_acceptlog_proc begin, stream_id=%u", stream_id);
    log_id_t commit_log = rep_get_commit_log(stream_id);
    log_id_t last_accept_log = stg_last_disk_log_id(stream_id);

    log_id_t try_commit_id = last_accept_log;
    if (try_commit_id.index > LAST_APPEND_IDX.index) {
        try_commit_id = LAST_APPEND_IDX;
    }

    if (try_commit_id.index > LEADER_COMMIT_IDX.index) {
        uint64 my_term = stg_get_term(stream_id, LEADER_COMMIT_IDX.index);
        if (my_term == LEADER_COMMIT_IDX.term) {
            try_commit_id = LEADER_COMMIT_IDX;
        }
    }

    LOG_DEBUG_INF("[REP]commit:(%llu,%llu),last_accept:(%llu,%llu),last_append:(%llu,%llu),leader_commit:(%llu,%llu)",
        commit_log.term, commit_log.index, last_accept_log.term, last_accept_log.index,
        LAST_APPEND_IDX.term, LAST_APPEND_IDX.index, LEADER_COMMIT_IDX.term, LEADER_COMMIT_IDX.index);

    if (try_commit_id.index > commit_log.index) {
        rep_set_commit_log1(stream_id, try_commit_id);
        LOG_DEBUG_INF("[REP]follower set commit index to (%llu,%llu)",
            try_commit_id.term, try_commit_id.index);
        rep_apply_trigger();
    }

    uint32 leader = elc_get_votefor(stream_id);
    if (leader == CM_INVALID_NODE_ID) {
        LOG_DEBUG_WAR("[REP]invalid votefor:%u,no leader now", leader);
        return CM_ERROR;
    }

    if (leader == md_get_cur_node()) {
        return CM_SUCCESS;
    }

    uint64 now = g_timer()->now;
    if (LAST_ACK_IDX.index != last_accept_log.index ||
        now - LAST_ACK_TIME > SEND_ACK_RETRY_INTERVAL) {
        if (rep_follower_send_ack(stream_id, leader, &last_accept_log) != CM_SUCCESS) {
            LOG_DEBUG_WAR("[REP]send ack failed");
            return CM_ERROR;
        }
        LAST_ACK_IDX = last_accept_log;
        LAST_ACK_TIME = now;
    }

    return CM_SUCCESS;
}

// called by storage trigger when log is accepted
void rep_follower_acceptlog(uint32 stream_id, uint64 term, uint64 index, status_t status)
{
    if (status != CM_SUCCESS) {
        return;
    }
}

uint64 rep_follower_get_leader_last_idx(uint32 stream_id)
{
    return LEADER_LAST_IDX;
}

log_id_t rep_get_last_append_log(uint32 stream_id)
{
    return LAST_APPEND_IDX;
}