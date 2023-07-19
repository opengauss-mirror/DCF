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
 * replication.c
 *    replication for raft
 *
 * IDENTIFICATION
 *    src/replication/replication.c
 *
 * -------------------------------------------------------------------------
 */

#include "replication.h"
#include "rep_common.h"
#include "rep_leader.h"
#include "rep_follower.h"
#include "mec.h"

static latch_t    g_rep_latch = {0};
static bool32     g_rep_inited = CM_FALSE;

static status_t rep_init_impl()
{
    if (rep_common_init() != CM_SUCCESS) {
        LOG_DEBUG_ERR("[REP]rep_common_init failed");
        return CM_ERROR;
    }

    if (stg_register_cb(ENTRY_TYPE_LOG, rep_accepted_trigger) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[REP]rep register stg callback failed");
        return CM_ERROR;
    }

    if (rep_follower_init() != CM_SUCCESS) {
        LOG_DEBUG_ERR("[REP]rep_follower_init failed");
        return CM_ERROR;
    }

    if (rep_leader_init() != CM_SUCCESS) {
        LOG_DEBUG_ERR("[REP]rep_leader_init failed");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static inline void rep_stop_impl()
{
    rep_leader_deinit();
    rep_common_deinit();
    unregister_msg_process(MEC_CMD_APPEND_LOG_RPC_REQ);
    unregister_msg_process(MEC_CMD_APPEND_LOG_RPC_ACK);
}

status_t rep_init()
{
    cm_latch_x(&g_rep_latch, 0, NULL);
    if (g_rep_inited) {
        cm_unlatch(&g_rep_latch, NULL);
        return CM_SUCCESS;
    }

    if (rep_init_impl() != CM_SUCCESS) {
        rep_stop_impl();
        cm_unlatch(&g_rep_latch, NULL);
        return CM_ERROR;
    }

    LOG_RUN_INF("[REP]rep_init succeed");
    g_rep_inited = CM_TRUE;
    cm_unlatch(&g_rep_latch, NULL);
    return CM_SUCCESS;
}

void rep_stop()
{
    cm_latch_x(&g_rep_latch, 0, NULL);
    if (!g_rep_inited) {
        cm_unlatch(&g_rep_latch, NULL);
        return;
    }
    rep_stop_impl();
    g_rep_inited = CM_FALSE;
    cm_unlatch(&g_rep_latch, NULL);
}

status_t rep_wait_all_logs_applied(uint32 stream_id);
status_t rep_wait_node_log_catchup(uint32 stream_id, uint32 node_id);

#define MAX_TRY_PROMOTE_LEADER_TIMES    3
#define MAX_SLEEP_CNT                   100

void rep_try_promote_prio_leader(uint32 stream_id, uint32 prio_leader)
{
    if (!I_AM_LEADER(stream_id)) {
        return;
    }

    (void)md_set_status(META_NORMAL);
    clear_node_block_status(stream_id);
    (void)rep_leader_reset(stream_id);

    if (rep_wait_node_log_catchup(stream_id, prio_leader) == CM_SUCCESS) {
        uint32 try_times = 0;
        uint32 sleep_cnt = 0;
        while (I_AM_LEADER(stream_id)) {
            if (sleep_cnt % MAX_SLEEP_CNT == 0) {
                try_times++;
                if (try_times > MAX_TRY_PROMOTE_LEADER_TIMES) {
                    return;
                }
                if (elc_promote_leader(stream_id, prio_leader) != CM_SUCCESS) {
                    LOG_DEBUG_ERR("[REP]try_promote_prio_leader failed, prio_leader=%u.", prio_leader);
                    return;
                }
                LOG_DEBUG_INF("[REP]try_promote_prio_leader %u times, prio_leader=%u.", try_times, prio_leader);
            }
            sleep_cnt++;
            cm_sleep(CM_SLEEP_1_FIXED);
        }
    }
}

status_t rep_role_notify(uint32 stream_id, dcf_role_t old_role, dcf_role_t new_role)
{
    (void)md_set_status(META_NORMAL);
    clear_node_block_status(stream_id);

    if (new_role == DCF_ROLE_LEADER) {
        (void)rep_leader_reset(stream_id);
        if (I_AM_LEADER(stream_id)) {
            /* new leader must wait all logs applied and then set can_write flag */
            if (rep_wait_all_logs_applied(stream_id) == CM_SUCCESS) {
                rep_set_can_write_flag(stream_id, CM_TRUE);
            }
        }
    } else {
        rep_follower_reset(stream_id);
    }

    return CM_SUCCESS;
}

status_t rep_write(uint32 stream_id, const char* buffer, uint32 length, uint64 key,
    entry_type_t type, uint64* out_index)
{
    uint64 index;
    if (!I_AM_LEADER(stream_id)) {
        LOG_DEBUG_ERR("[REP]current node is not leader.");
        return CM_ERROR;
    }

    //  write to storage buffer
    LOG_DEBUG_INF("stg_append_entry begin");
    if (stg_append_entry(stream_id,
        elc_get_current_term(stream_id),
        CM_INVALID_INDEX_ID, (char*)buffer, length, key, type, &index) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[REP]stg_append_entry failed");
        return CM_ERROR;
    }
    LOG_DEBUG_INF("stg_append_entry end,index=%llu", index);

    LOG_TRACE(index, "rep_write:stg_append_entry finish.");
    if (is_trace_key(index)) {
        rep_save_tracekey(index);
    }
    // notify replication thread to replicate the log to other nodes
    rep_appendlog_trigger(stream_id);

    if (out_index != NULL) {
        *out_index = index;
    }

    return CM_SUCCESS;
}

uint64 rep_get_commit_index(uint32 stream_id)
{
    return rep_get_commit_log(stream_id).index;
}

uint64 rep_get_data_commit_index(uint32 stream_id)
{
    uint64 commit_idx = rep_get_commit_log(stream_id).index;
    do {
        log_entry_t *entry = stg_get_entry(stream_id, commit_idx);
        if (entry == NULL) {
            LOG_DEBUG_WAR("rep get data commit index %llu not found", commit_idx);
            break;
        }
        if (ENTRY_TYPE(entry) == ENTRY_TYPE_LOG) {
            stg_entry_dec_ref(entry);
            break;
        }
        stg_entry_dec_ref(entry);
        commit_idx--;
    } while (commit_idx);

    return commit_idx;
}

uint64 rep_get_last_index(uint32 stream_id)
{
    return stg_last_log_id(stream_id).index;
}

uint64 rep_get_leader_last_index(uint32 stream_id)
{
    if (I_AM_LEADER(stream_id)) {
        return stg_last_log_id(stream_id).index;
    } else {
        return rep_follower_get_leader_last_idx(stream_id);
    }
}
