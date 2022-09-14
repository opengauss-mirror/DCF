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
 * rep_common.c
 *    common  process
 *
 * IDENTIFICATION
 *    src/replication/rep_common.c
 *
 * -------------------------------------------------------------------------
 */

#include "rep_common.h"
#include "dcf_interface.h"
#include "rep_leader.h"
#include "rep_follower.h"
#include "util_perf_stat.h"
#include "util_profile_stat.h"

#define REP_REMATCH_STEP 1000
#define REP_REMATCH_COUNT 100

typedef struct st_rep_common_state_t {
    volatile log_id_t   commit_index;
    uint64              cluster_min_apply_idx;
    volatile date_t     last_accept_time;
    volatile uint32     can_write;
    volatile uint8      accept_log;
}rep_common_state_t;

// for all role
rep_common_state_t g_common_state[CM_MAX_STREAM_COUNT];

cm_event_t g_accept_cond;
cm_event_t g_apply_cond;
thread_t g_stat_thread;
thread_t g_accept_thread;
thread_t g_apply_thread;
uint64  g_rep_tracekey = (uint64)-1;

usr_cb_after_writer_t g_cb_after_writer[ENTRY_TYPE_CELL] = {NULL};
usr_cb_after_commit_t g_cb_after_commit[ENTRY_TYPE_CELL] = {NULL};
usr_cb_consensus_notify_t   g_cb_consensus_notify[ENTRY_TYPE_CELL] = {NULL};

static void rep_accept_thread_entry(thread_t *thread);
static void rep_apply_thread_entry(thread_t *thread);
static void rep_stat_thread_entry(thread_t *thread);

void print_state();

uint64 rep_get_tracekey()
{
    return g_rep_tracekey;
}

void rep_save_tracekey(uint64 tracekey)
{
    g_rep_tracekey = tracekey;
}

status_t rep_common_init()
{
    uint32 streams[CM_MAX_STREAM_COUNT];
    uint32 stream_count;

    if (cm_event_init(&g_accept_cond) != CM_SUCCESS) {
        CM_THROW_ERROR(ERR_CREATE_EVENT, cm_get_os_error());
        return CM_ERROR;
    }
    if (cm_event_init(&g_apply_cond) != CM_SUCCESS) {
        CM_THROW_ERROR(ERR_CREATE_EVENT, cm_get_os_error());
        return CM_ERROR;
    }

    if (md_get_stream_list(streams, &stream_count) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[REP]md_get_stream_list failed");
        return CM_ERROR;
    }

    for (uint32 i = 0; i < stream_count; i++) {
        uint32 stream_id = streams[i];
        log_id_t* invalid_log_id = get_invalid_log_id();
        g_common_state[stream_id].commit_index = *invalid_log_id;
        g_common_state[stream_id].cluster_min_apply_idx = CM_INVALID_INDEX_ID;
        g_common_state[stream_id].accept_log = CM_FALSE;
        g_common_state[stream_id].last_accept_time = 0;
        g_common_state[stream_id].can_write = CM_FALSE;
    }

    if (cm_create_thread(rep_accept_thread_entry, 0, NULL, &g_accept_thread) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[REP]cm_create_thread failed");
        return CM_ERROR;
    }

    if (cm_create_thread(rep_apply_thread_entry, 0, NULL, &g_apply_thread) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[REP]cm_create_thread failed");
        return CM_ERROR;
    }

    if (cm_create_thread(rep_stat_thread_entry, 0, NULL, &g_stat_thread) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[REP]cm_create_thread failed");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

void rep_common_deinit()
{
    cm_close_thread(&g_accept_thread);
    cm_close_thread(&g_apply_thread);
    cm_close_thread(&g_stat_thread);
    cm_event_destory(&g_accept_cond);
    cm_event_destory(&g_apply_cond);
}

static status_t rep_acceptlog_proc(uint32 stream_id)
{
    LOG_DEBUG_INF("rep_acceptlog_proc.");
    LOG_TIME_BEGIN(rep_acceptlog_proc);
    if (I_AM_LEADER(stream_id)) {
        LOG_TIME_BEGIN(rep_leader_acceptlog_proc);
        CM_RETURN_IFERR(rep_leader_acceptlog_proc(stream_id));
        LOG_TIME_END(rep_leader_acceptlog_proc);
    } else {
        LOG_TIME_BEGIN(rep_follower_acceptlog_proc);
        CM_RETURN_IFERR(rep_follower_acceptlog_proc(stream_id));
        LOG_TIME_END(rep_follower_acceptlog_proc);
    }
    LOG_TIME_END(rep_acceptlog_proc);

    return CM_SUCCESS;
}

static void rep_accept_thread_entry(thread_t *thread)
{
    uint32 streams[CM_MAX_STREAM_COUNT];
    uint32 stream_count;
    bool8  exists_log = CM_TRUE;

    if (cm_set_thread_name("rep_accept") != CM_SUCCESS) {
        LOG_DEBUG_ERR("[REP]set accept thread name failed");
    }
    if (md_get_stream_list(streams, &stream_count) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[REP]md_get_stream_list failed");
        return;
    }

    while (!thread->closed) {
        if (!exists_log) {
            LOG_TRACE(g_rep_tracekey, "accept_thread wait.");
            (void)cm_event_timedwait(&g_accept_cond, CM_SLEEP_500_FIXED);
        }
        LOG_TRACE(g_rep_tracekey, "accept_thread work.");

        exists_log = CM_FALSE;
        for (uint32 i = 0; i < stream_count; i++) {
            uint32 stream_id = streams[i];
            date_t now = g_timer()->now;
            exists_log = (exists_log || g_common_state[stream_id].accept_log);
            if (g_common_state[stream_id].accept_log ||
                now - g_common_state[stream_id].last_accept_time > CM_DEFAULT_HB_INTERVAL*MICROSECS_PER_MILLISEC) {
                LOG_TRACE(g_rep_tracekey, "accept_thread do work.");
                g_common_state[stream_id].accept_log = CM_FALSE;
                g_common_state[stream_id].last_accept_time = now;
                if (rep_acceptlog_proc(stream_id) != CM_SUCCESS) {
                    LOG_DEBUG_ERR("[REP]rep_acceptlog_proc failed.");
                }
            } else {
                LOG_TRACE(g_rep_tracekey, "accept_thread no work.");
            }
        }
    }
}

static void rep_reset_commit_idx(uint32 stream_id, bool8 is_leader, log_id_t *commit_log)
{
    log_id_t disk_log = stg_last_disk_log_id(stream_id);
    if (is_leader && disk_log.index < commit_log->index) {
        commit_log->index = disk_log.index;
        commit_log->term = disk_log.term;
    }
}

static status_t rep_apply_proc(uint32 stream_id, bool8* stream_exists_log)
{
    bool8 is_leader = I_AM_LEADER(stream_id);
    // apply the committed log
    uint64 applied_index = stg_get_applied_index(stream_id);
    log_id_t commit_log = rep_get_commit_log(stream_id);
    // LOGGER only set apply index.
    CHECK_IF_LOGGER_PROC(stream_id, applied_index, commit_log.index);
    *stream_exists_log = commit_log.index > applied_index;
    uint64 cur_term = elc_get_current_term(stream_id);
    // to ensure leader's log is flushed
    rep_reset_commit_idx(stream_id, is_leader, &commit_log);
    for (uint64 index = applied_index + 1; index <= commit_log.index; index++) {
        ps_record1(PS_BEING_APPLY, index);
        log_entry_t* entry = stg_get_entry(stream_id, index);
        if (entry == NULL) {
            LOG_RUN_ERR("[REP]stg_get_entry failed,stream_id=%u,index = %llu.", stream_id, index);
            return CM_ERROR;
        }

        if (is_leader && ENTRY_TERM(entry) == cur_term) {
            usr_cb_after_writer_t cb_after_writer = g_cb_after_writer[ENTRY_TYPE(entry)];
            if (cb_after_writer != NULL) {
                if (cb_after_writer(stream_id, index, ENTRY_BUF(entry), ENTRY_SIZE(entry), ENTRY_KEY(entry), 0) != 0) {
                    LOG_DEBUG_ERR("[REP]g_cb_after_writer failed, index=%llu.", index);
                    stg_entry_dec_ref(entry);
                    return CM_ERROR;
                }
            }
        } else {
            usr_cb_consensus_notify_t cb_consensus_notify = g_cb_consensus_notify[ENTRY_TYPE(entry)];
            if (cb_consensus_notify != NULL) {
                if (cb_consensus_notify(stream_id, index, ENTRY_BUF(entry), ENTRY_SIZE(entry), ENTRY_KEY(entry)) != 0) {
                    LOG_DEBUG_ERR_EX("[REP]cb_consensus_notify failed, index=%llu.", index);
                    stg_entry_dec_ref(entry);
                    return CM_ERROR;
                }
            }
        }
        LOG_DEBUG_INF("[REP]apply index=%llu, key=%llu, size=%u, is_leader=%u, entry_term=%llu, cur_term=%llu, "
            "entry_type=%u", index, ENTRY_KEY(entry), ENTRY_SIZE(entry), is_leader, ENTRY_TERM(entry), cur_term,
            ENTRY_TYPE(entry));
        stg_entry_dec_ref(entry);
        CM_RETURN_IFERR(stg_set_applied_index(stream_id, index));
        LOG_TRACE(index, "am I is leader %d, apply index=%llu", is_leader, index);
        if (g_rep_tracekey < index || g_rep_tracekey == (uint64)-1) {
            g_rep_tracekey = (uint64)-1;
        }
        LOG_TRACE(index, "index=%llu trace end!", index);
        ps_record1(PS_END_APPLY, index);
    }

    return CM_SUCCESS;
}

static void rep_apply_thread_entry(thread_t *thread)
{
    uint32 streams[CM_MAX_STREAM_COUNT];
    uint32 stream_count;
    bool8  exists_log = CM_TRUE;

    if (cm_set_thread_name("rep_apply") != CM_SUCCESS) {
        LOG_DEBUG_ERR("[REP]set apply thread name failed");
    }
    if (md_get_stream_list(streams, &stream_count) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[REP]md_get_stream_list failed");
        return;
    }

    while (!thread->closed) {
        if (!exists_log) {
            (void)cm_event_timedwait(&g_apply_cond, CM_SLEEP_500_FIXED);
        }

        LOG_TRACE(g_rep_tracekey, "apply_thread work");
        exists_log = CM_FALSE;
        for (uint32 i = 0; i < stream_count; i++) {
            uint32 stream_id = streams[i];
            bool8 stream_exists_log = CM_FALSE;
            LOG_TIME_BEGIN(rep_apply_proc);
            if (rep_apply_proc(stream_id, &stream_exists_log) != CM_SUCCESS) {
                LOG_DEBUG_ERR_EX("[REP]rep_apply_proc failed.");
            }
            LOG_TIME_END(rep_apply_proc);

            exists_log = (exists_log || stream_exists_log);
        }
    }
}

void rep_set_accept_flag(uint32 stream_id)
{
    LOG_DEBUG_INF("rep_set_accept_flag.");
    g_common_state[stream_id].accept_log = CM_TRUE;
    cm_event_notify(&g_accept_cond);
}

void rep_set_can_write_flag(uint32 stream_id, uint32 flag)
{
    LOG_DEBUG_INF("[REP]rep_set_can_write_flag=%u.", flag);
    g_common_state[stream_id].can_write = flag;
}

uint32 rep_get_can_write_flag(uint32 stream_id)
{
    return g_common_state[stream_id].can_write;
}

void rep_apply_trigger()
{
    LOG_DEBUG_INF("[REP]rep_apply_trigger");
    LOG_TRACE(g_rep_tracekey, "common:rep_apply_trigger.");
    cm_event_notify(&g_apply_cond);
}

void rep_accepted_trigger(uint32 stream_id, uint64 term, uint64 index, int err_code, entry_type_t type)
{
    LOG_DEBUG_INF("[REP]rep_accepted_trigger,log=(%llu,%llu)", term, index);

    LOG_TRACE(index, "log is accepted,trigger.");

    if (I_AM_LEADER(stream_id)) {
        rep_leader_acceptlog(stream_id, term, index, err_code);
    } else {
        rep_follower_acceptlog(stream_id, term, index, err_code);
    }

    rep_set_accept_flag(stream_id);
}

log_id_t rep_get_commit_log(uint32 stream_id)
{
    return g_common_state[stream_id].commit_index;
}

void rep_set_commit_log(uint32 stream_id, uint64 term, uint64 index)
{
    ps_record1(PS_COMMIT, index);
    g_common_state[stream_id].commit_index.term = term;
    g_common_state[stream_id].commit_index.index = index;
}

void rep_set_commit_log1(uint32 stream_id, log_id_t log_id)
{
    ps_record1(PS_COMMIT, log_id.index);
    g_common_state[stream_id].commit_index = log_id;
}

void rep_set_cluster_min_apply_idx(uint32 stream_id, uint64 cluster_min_apply_id)
{
    g_common_state[stream_id].cluster_min_apply_idx = cluster_min_apply_id;
}

uint64 rep_get_cluster_min_apply_idx(uint32 stream_id)
{
    return g_common_state[stream_id].cluster_min_apply_idx;
}

log_id_t rep_get_pre_term_log(uint32 stream_id, uint64 index)
{
    int rematch_count = 0;
    log_id_t log_id;
    log_id.index = index;
    log_id.term = stg_get_term(stream_id, index);

    if (log_id.term == CM_INVALID_TERM_ID ||
        log_id.index == CM_INVALID_INDEX_ID) {
        return log_id;
    }

    log_id_t pre_term_log = log_id;

    while (CM_TRUE) {
        if (pre_term_log.term != log_id.term) {
            break;
        }

        if (pre_term_log.term == CM_INVALID_TERM_ID ||
            pre_term_log.index == CM_INVALID_INDEX_ID) {
            break;
        }

        if (pre_term_log.index <= 1) {
            break;
        }

        if (pre_term_log.index <= REP_REMATCH_STEP) {
            pre_term_log.index = 1;
            pre_term_log.term = stg_get_term(stream_id, pre_term_log.index);
            break;
        } else {
            pre_term_log.index -= REP_REMATCH_STEP;
            pre_term_log.term = stg_get_term(stream_id, pre_term_log.index);
        }

        if (rematch_count > REP_REMATCH_COUNT) {
            break;
        }
        rematch_count++;
    }

    return pre_term_log;
}

int rep_register_after_writer(entry_type_t type, usr_cb_after_writer_t cb_func)
{
    g_cb_after_writer[type] = cb_func;
    return CM_SUCCESS;
}

int rep_register_consensus_notify(entry_type_t type, usr_cb_consensus_notify_t cb_func)
{
    g_cb_consensus_notify[type] = cb_func;
    return CM_SUCCESS;
}

int rep_register_after_commit(entry_type_t type, usr_cb_after_commit_t cb_func)
{
    g_cb_after_commit[type] = cb_func;
    return CM_SUCCESS;
}

uint32 rep_get_pause_time(uint32 stream_id, uint32 node_id);

void print_stream_state_leader(uint32 stream_id)
{
    uint32 nodes[CM_MAX_NODE_COUNT];
    uint32 node_count;
    char   commit_index_str[64], match_index_str[64];

    uint32 leader_id = md_get_cur_node();

    if (md_get_stream_nodes(stream_id, nodes, &node_count) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[REP]md_get_stream_nodes failed.");
        return;
    }

    if (snprintf_s(commit_index_str, sizeof(commit_index_str), sizeof(commit_index_str) - 1, "(%llu,%lld)",
        g_common_state[stream_id].commit_index.term,
        g_common_state[stream_id].commit_index.index) == -1) {
        return;
    }

    for (uint32 i = 0; i < node_count; i++) {
        uint32 node_id = nodes[i];
        log_id_t match_index = rep_leader_get_match_index(stream_id, node_id);
        if (snprintf_s(match_index_str, sizeof(match_index_str), sizeof(match_index_str) - 1, "(%llu,%lld)",
            match_index.term, match_index.index) == -1) {
            return;
        }

        uint64 next_index = rep_leader_get_next_index(stream_id, node_id);
        if (leader_id == node_id) {
            dcf_role_t role = elc_get_node_role(stream_id);
            LOG_PROFILE("[REP]%10u %8u %8s %8u %8u %8llu %-16s %-16s %20llu", stream_id, node_id,
                "-", role, elc_get_votefor(stream_id),
                elc_get_current_term(stream_id), commit_index_str, match_index_str,
                next_index);
        } else {
            LOG_PROFILE("[REP]%10u %8u %8u %8s %8s %8s %-16s %-16s %20llu", stream_id, node_id,
                rep_get_pause_time(stream_id, node_id), "-", "-", "-", "-", match_index_str,
                next_index);
        }
    }
}

void print_stream_state_follower(uint32 stream_id)
{
    char   accept_index_str[64], commit_index_str[64];

    uint32 node_id = md_get_cur_node();
    dcf_role_t role = elc_get_node_role(stream_id);
    log_id_t accept_index = stg_last_disk_log_id(stream_id);
    PRTS_RETVOID_IFERR(snprintf_s(accept_index_str, sizeof(accept_index_str), sizeof(accept_index_str) - 1,
        "(%llu,%llu)",
        accept_index.term, accept_index.index));
    PRTS_RETVOID_IFERR(snprintf_s(commit_index_str, sizeof(commit_index_str), sizeof(commit_index_str) - 1,
        "(%llu,%llu)",
        g_common_state[stream_id].commit_index.term, g_common_state[stream_id].commit_index.index));

    LOG_PROFILE("[REP]%10u %8u %8u %8u %8llu %-16s %-16s", stream_id, node_id,
        role, elc_get_votefor(stream_id),
        elc_get_current_term(stream_id), commit_index_str, accept_index_str);
}

static void rep_stat_thread_entry(thread_t *thread)
{
    if (cm_set_thread_name("rep_stat") != CM_SUCCESS) {
        LOG_DEBUG_ERR("[REP]set stat thread name failed!");
    }

    while (!thread->closed) {
        print_state();
        cm_sleep(CM_SLEEP_1000_FIXED);
    }
}

void print_state()
{
    uint32 streams[CM_MAX_STREAM_COUNT];
    uint32 stream_count;
    static uint64 last = 0;
    uint64 now = g_timer()->now;
    if (now - last < DEFAULT_STAT_INTERVAL * MICROSECS_PER_SECOND) {
        return;
    }
    last = now;

    if (md_get_stream_list(streams, &stream_count) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[REP]md_get_stream_list failed");
        return;
    }

    for (uint32 i = 0; i < stream_count; i++) {
        uint32 stream_id = streams[i];
        if (I_AM_LEADER(stream_id)) {
            LOG_PROFILE("[REP]%10s %8s %8s %8s %8s %8s %-16s %-16s %20s",
                "stream_id", "node_id", "pause", "role", "leader", "term", "commit_index", "match_index", "next_index");
            print_stream_state_leader(stream_id);
        } else {
            LOG_PROFILE("[REP]%10s %8s %8s %8s %8s %-16s %-16s",
                "stream_id", "node_id", "role", "leader", "term", "commit_index", "accept_index");
            print_stream_state_follower(stream_id);
        }
    }
}

