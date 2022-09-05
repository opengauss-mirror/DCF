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
 * rep_leader.c
 *    leader  process
 *
 * IDENTIFICATION
 *    src/replication/rep_leader.c
 *
 * -------------------------------------------------------------------------
 */

#include "rep_leader.h"
#include "cm_date.h"
#include "cm_thread.h"
#include "metadata.h"
#include "election.h"
#include "rep_msg_pack.h"
#include "rep_common.h"
#include "replication.h"
#include "cm_timer.h"
#include "util_perf_stat.h"
#include "rep_monitor.h"
#include "cm_num.h"
#include "cm_text.h"

#define APPEND_NORMAL_MODE 0
#define APPEND_REMATCH_MODE 1
#define APPEND_INTERVAL 1000    // ms

#define FLAG_EXISTS_ACTIVE_NODE 0x1
#define FLAG_EXISTS_LOG         0x2
#define FLAG_CONTROL_FLOW       0x4

typedef struct st_rep_leader_state_t {
    volatile uint64     next_index[CM_MAX_NODE_COUNT];
    volatile log_id_t   match_index[CM_MAX_NODE_COUNT];
    volatile uint8      append_mode[CM_MAX_NODE_COUNT];
    volatile uint32     pause_time[CM_MAX_NODE_COUNT];
    atomic32_t          try_rematch[CM_MAX_NODE_COUNT];
    uint64              apply_index[CM_MAX_NODE_COUNT];
    uint64              pre_app_time[CM_MAX_NODE_COUNT];
    uint32              disk_error;
}rep_leader_state_t;

#define NEXT_INDEX  (g_leader_state[stream_id].next_index[node_id])
#define MATCH_INDEX (g_leader_state[stream_id].match_index[node_id])
#define APPEND_MODE (g_leader_state[stream_id].append_mode[node_id])
#define PAUSE_TIME  (g_leader_state[stream_id].pause_time[node_id])
#define TRY_REMATCH (g_leader_state[stream_id].try_rematch[node_id])
#define APPLY_INDEX (g_leader_state[stream_id].apply_index[node_id])
#define PRE_APPTIME (g_leader_state[stream_id].pre_app_time[node_id])
#define DISK_ERROR  (g_leader_state[stream_id].disk_error)
#define DISK_ERROR_THRESHOLD 10
// leader state
rep_leader_state_t    g_leader_state[CM_MAX_STREAM_COUNT];

static cm_thread_cond_t g_appendlog_cond;
static thread_t g_appendlog_thread[REP_MAX_APPEND_THREAS_NUM];
static uint64 g_append_thread_id[CM_MAX_NODE_COUNT];
static uint32 g_append_thread_num;
static uint32 g_cur_node_id;

// for monitor
thread_t g_leader_monitor_thread;
rep_monitor_statistics_t g_leader_monitor_statistics;
#define LOAD_LEVEL          (g_leader_monitor_statistics.load_level)
#define ADJUST_STEP         (g_leader_monitor_statistics.adjust_step)
#define HIGH_LEVEL_TIMES    (g_leader_monitor_statistics.high_level_times)

#define REP_FC_TIME_UNIT       100  // 100us unit
#define REP_FC_INIT_VAL        10
#define REP_FC_SAMP_PERIOD     1
#define REP_FC_CTRL_PERIOD     5
#define REP_FC_MAX_VAL         100
#define FC_MIN_MAX             2
#define REP_FC_CTRL_THD        4000 // reduce fc_val if commit_delay less than this threshold
static volatile uint32 g_rep_flow_ctrl_val = REP_FC_INIT_VAL;
static uint32 g_flow_ctrl_type = FC_NONE;


static void rep_appendlog_thread_entry(thread_t *thread);
static status_t rep_appendlog_ack_proc(mec_message_t *pack);
static void rep_follower_accepted_trigger(uint32 stream_id, uint32 node_id, log_id_t log_id);
static void rep_leader_monitor_entry(thread_t *thread);
static void rep_init_thread_id();
status_t rep_leader_reset(uint32 stream_id);
status_t rep_wait_all_logs_applied(uint32 stream_id);

// called when module is started
status_t rep_leader_init()
{
    uint32 streams[CM_MAX_STREAM_COUNT];
    uint32 stream_count;
    param_value_t param_value;
    g_cur_node_id = md_get_cur_node();

    cm_init_cond(&g_appendlog_cond);

    register_msg_process(MEC_CMD_APPEND_LOG_RPC_ACK, rep_appendlog_ack_proc, PRIV_LOW);

    if (md_get_param(DCF_PARAM_MEC_BATCH_SIZE, &param_value) != CM_SUCCESS) {
        LOG_RUN_ERR("rep_leader_init: get batchsize failed.");
        return CM_ERROR;
    }
    if (param_value.batch_size == 0) {
        g_flow_ctrl_type = FC_COMMIT_DELAY;
    }
    LOG_RUN_INF("rep_leader_init: flow_ctrl_type=%u.", g_flow_ctrl_type);

    if (md_get_param(DCF_REP_APPEND_THREAD_NUM, &param_value) != CM_SUCCESS) {
        return CM_ERROR;
    }

    g_append_thread_num = param_value.rep_append_thread_num;
    if (g_append_thread_num <= 0 || g_append_thread_num > REP_MAX_APPEND_THREAS_NUM) {
        LOG_RUN_ERR("rep_leader_init failed: invalid param value :REP_APPEND_THREAD_NUM = %u.",
            g_append_thread_num);
        return CM_ERROR;
    }
    rep_init_thread_id();

    CM_RETURN_IFERR(md_get_stream_list(streams, &stream_count));
    for (uint32 i = 0; i < stream_count; i++) {
        uint32 stream_id = streams[i];
        uint32 node_num = 0;
        CM_RETURN_IFERR(md_get_stream_nodes_count(stream_id, &node_num));
        if (node_num == 1) { // 1 node mode
            CM_RETURN_IFERR(rep_leader_reset(stream_id));
        }
    }

    CM_RETURN_IFERR(rep_monitor_init());
    CM_RETURN_IFERR(cm_create_thread(rep_leader_monitor_entry, 0, NULL, &g_leader_monitor_thread));

    for (uint64 i = 0; i < g_append_thread_num; i++) {
        CM_RETURN_IFERR(cm_create_thread(rep_appendlog_thread_entry, 0,
            (void*)i, &g_appendlog_thread[i]));
    }

    for (uint32 i = 0; i < stream_count; i++) {
        uint32 stream_id = streams[i];
        if (I_AM_LEADER(stream_id)) {
            /* new leader must wait all logs applied and then set can_write flag */
            CM_RETURN_IFERR(rep_wait_all_logs_applied(stream_id));
            rep_set_can_write_flag(stream_id, CM_TRUE);
        }
    }

    LOG_RUN_INF("rep_leader_init finished");

    return CM_SUCCESS;
}

void rep_leader_deinit()
{
    for (uint64 i = 0; i < g_append_thread_num; i++) {
        cm_close_thread(&g_appendlog_thread[i]);
    }
    cm_close_thread(&g_leader_monitor_thread);
    LOG_RUN_INF("rep_leader_deinit finished");
}

status_t rep_wait_node_log_catchup(uint32 stream_id, uint32 node_id)
{
    uint64 leader_last_index = rep_get_last_index(stream_id);
    uint64 node_last_index = rep_leader_get_match_index(stream_id, node_id).index;
    uint64 node_old_last_index = 0;
    timespec_t begin = cm_clock_now();
    timespec_t last = cm_clock_now();
    while (node_last_index != leader_last_index) {
        if ((cm_clock_now() - last) > MICROSECS_PER_SECOND * CM_10X_FIXED) {
            LOG_RUN_INF("[REP]already wait for %lld seconds,leader_last_index=%llu,node_last_index=%llu",
                        (cm_clock_now() - begin) / MICROSECS_PER_SECOND, leader_last_index, node_last_index);
            last = cm_clock_now();

            if (node_last_index == node_old_last_index) {
                LOG_RUN_WAR("[REP]wait_node_log_catchup failed, node=%u,leader_last_index=%llu,"
                    "node_last_index=%llu,node_old_last_index=%llu",
                    node_id, leader_last_index, node_last_index, node_old_last_index);
                return CM_ERROR;
            }
            node_old_last_index = node_last_index;
        }
        cm_sleep(CM_SLEEP_1_FIXED);
        if (!I_AM_LEADER(stream_id)) {
            LOG_RUN_INF("[REP]wait_node_log_catchup:I'm not leader now.");
            return CM_ERROR;
        }
        if (elc_is_notify_thread_closed() == CM_TRUE) {
            LOG_RUN_INF("[REP]wait_node_log_catchup:status_notify_thread closed, stop now.");
            return CM_ERROR;
        }
        leader_last_index = rep_get_last_index(stream_id);
        node_last_index = rep_leader_get_match_index(stream_id, node_id).index;
    }

    LOG_DEBUG_INF("[REP]wait_node_log_catchup OK. leader_last_index=%llu, node_last_index=%llu",
        leader_last_index, node_last_index);
    return CM_SUCCESS;
}

status_t rep_wait_all_logs_applied(uint32 stream_id)
{
    uint64 last_index = rep_get_last_index(stream_id);
    uint64 applied_index = stg_get_applied_index(stream_id);
    timespec_t begin = cm_clock_now();
    timespec_t last = cm_clock_now();
    while (last_index != applied_index) {
        if ((cm_clock_now() - last) > MICROSECS_PER_SECOND) {
            LOG_RUN_INF("[REP]already wait for %lld seconds,last_index=%llu,applied_index=%llu",
                        (cm_clock_now() - begin) / MICROSECS_PER_SECOND, last_index, applied_index);
            last = cm_clock_now();
        }
        cm_sleep(CM_SLEEP_1_FIXED);
        if (!I_AM_LEADER(stream_id)) {
            LOG_RUN_INF("[REP]wait_all_logs_applied:I'm not leader now.");
            return CM_ERROR;
        }
        if (elc_is_notify_thread_closed() == CM_TRUE) {
            LOG_RUN_INF("[REP]wait_all_logs_applied:status_notify_thread closed, stop now.");
            return CM_ERROR;
        }
        last_index = rep_get_last_index(stream_id);
        applied_index = stg_get_applied_index(stream_id);
    }

    LOG_DEBUG_INF("[REP]wait_all_logs_applied OK. last_index=%llu, applied_index=%llu", last_index, applied_index);
    return CM_SUCCESS;
}

// called by election when this node becomes leader
status_t rep_leader_reset(uint32 stream_id)
{
    uint32 nodes[CM_MAX_NODE_COUNT];
    uint32 count;

    CM_RETURN_IFERR(md_get_stream_nodes(stream_id, nodes, &count));

    log_id_t last_log = stg_last_log_id(stream_id);
    for (uint32 i = 0; i < count; i++) {
        uint32 node_id = nodes[i];
        NEXT_INDEX = last_log.index;
        if (node_id == g_cur_node_id) {
            MATCH_INDEX = stg_last_disk_log_id(stream_id);
        } else {
            log_id_t* invalid_log_id = get_invalid_log_id();
            MATCH_INDEX = *invalid_log_id;
        }
        APPEND_MODE = APPEND_NORMAL_MODE;
        TRY_REMATCH = CM_FALSE;
        PRE_APPTIME = 0;
        PAUSE_TIME  = 0;
        LOG_DEBUG_INF("[REP]rep_leader_reset:node_id=%u,next_index=%llu", node_id,
            NEXT_INDEX);
    }

    if (I_AM_LEADER(stream_id)) {
        /* Write matadata when leader reset for:
        1. try commit previous term's log
        2. ensure configurations on all nodes are consistent */
        CM_RETURN_IFERR(md_set_status(META_CATCH_UP));
        uint32 size;
        char *md_buf = (char *)malloc(CM_METADATA_DEF_MAX_LEN);
        if (md_buf == NULL) {
            LOG_DEBUG_ERR("rep_leader_reset malloc failed");
            CM_RETURN_IFERR(md_set_status(META_NORMAL));
            return CM_ERROR;
        }
        if (md_to_string(md_buf, CM_METADATA_DEF_MAX_LEN, &size) != CM_SUCCESS) {
            CM_FREE_PTR(md_buf);
            CM_RETURN_IFERR(md_set_status(META_NORMAL));
            return CM_ERROR;
        }
        if (rep_write(stream_id, md_buf, size, CFG_LOG_KEY(CM_INVALID_NODE_ID, OP_FLAG_NONE),
            ENTRY_TYPE_CONF, NULL) != CM_SUCCESS) {
            CM_FREE_PTR(md_buf);
            CM_RETURN_IFERR(md_set_status(META_NORMAL));
            return CM_ERROR;
        }
        CM_FREE_PTR(md_buf);
        CM_RETURN_IFERR(md_set_status(META_NORMAL));
    } else {
        LOG_RUN_WAR("rep_leader_reset:I'm not a leader now!");
    }

    LOG_RUN_INF("rep_leader_reset finished");

    return CM_SUCCESS;
}

static inline void rep_init_appendlog_head(uint32 stream_id, rep_apendlog_req_t* appendlog_req,
    uint64 pre_log_index, uint64 last_log_index)
{
    appendlog_req->head.req_seq = g_timer()->now;
    appendlog_req->head.ack_seq = 0;
    appendlog_req->head.trace_key = get_trace_key();
    appendlog_req->head.msg_ver = REP_MSG_VER;
    appendlog_req->leader_node_id = g_cur_node_id;
    appendlog_req->leader_term = elc_get_current_term(stream_id);
    appendlog_req->leader_commit_log = rep_get_commit_log(stream_id);
    appendlog_req->leader_first_log.index = stg_first_index(stream_id);
    appendlog_req->leader_first_log.term = stg_get_term(stream_id, appendlog_req->leader_first_log.index);
    appendlog_req->pre_log.index = pre_log_index;
    appendlog_req->pre_log.term = stg_get_term(stream_id, pre_log_index);
    appendlog_req->leader_last_index = last_log_index;
    appendlog_req->cluster_min_apply_id = rep_get_cluster_min_apply_idx(stream_id);
    appendlog_req->log_count = 0;
}

static uint64 rep_calu_log_count_by_control(dcf_role_t default_role, uint64 log_count)
{
    if (default_role != DCF_ROLE_PASSIVE) {
        return log_count;
    }
    LOG_DEBUG_INF("[REP]before control count: %llu", log_count);
    if (log_count == 0) {
        return log_count;
    }
    log_count = (uint64)(log_count * ADJUST_STEP);
    LOG_DEBUG_INF("[REP]flow control count: %llu, load level: %d, step: %f, high times: %u", log_count, LOAD_LEVEL,
                  ADJUST_STEP, HIGH_LEVEL_TIMES);
    if (log_count == 0) {
        return 1;
    }

    return log_count;
}

static uint64 rep_calu_log_count(uint32 stream_id, uint32 node_id, dcf_role_t default_role, uint64 log_begin,
    uint64 log_end)
{
    uint64 log_count;

    if (log_end == CM_INVALID_INDEX_ID) {
        return 0;
    }

    if (log_end < log_begin) {
        return 0;
    }

    if (log_begin == CM_INVALID_INDEX_ID) {
        log_count = log_end;
    } else {
        log_count = (log_end - log_begin) + 1;
    }

    if (APPEND_MODE != APPEND_NORMAL_MODE) {
        log_count = MIN(log_count, 1);
    }

    return rep_calu_log_count_by_control(default_role, log_count);
}

#define MEC_AND_REP_HEAD_SIZE (sizeof(mec_message_head_t) + sizeof(rep_apendlog_req_t))
// Check if value illegal at compile time
CM_STATIC_ASSERT(MEC_BUFFER_RESV_SIZE >= (PADDING_BUFFER_SIZE + MEC_AND_REP_HEAD_SIZE));
CM_STATIC_ASSERT(MEC_BUFFER_RESV_SIZE < (PADDING_BUFFER_SIZE + MEC_AND_REP_HEAD_SIZE + SIZE_K(1)));

static status_t rep_appendlog_node(uint32 stream_id, uint32 node_id, dcf_role_t default_role, uint64 last_log_index,
    bool8* node_exists_log)
{
    uint64 old_next_index = (uint64)cm_atomic_get((atomic_t*)&NEXT_INDEX);
    uint64 log_begin = old_next_index == CM_INVALID_INDEX_ID ? 1 : old_next_index;
    log_begin = MAX(log_begin, stg_first_index(stream_id));
    uint64 log_count = rep_calu_log_count(stream_id, node_id, default_role, log_begin, last_log_index);
    *node_exists_log = (log_count > 0);

    /* Logs are sent even if log_count==0.
    Periodically sending empty logs ensures that lost packets are retransmitted */
    mec_message_t pack;
    CM_RETURN_IFERR(mec_alloc_pack(&pack, MEC_CMD_APPEND_LOG_RPC_REQ, g_cur_node_id, node_id, stream_id));
    uint64 pre_log_index = log_begin == CM_INVALID_INDEX_ID ? CM_INVALID_INDEX_ID : log_begin - 1;
    rep_apendlog_req_t appendlog_req;
    rep_init_appendlog_head(stream_id, &appendlog_req, pre_log_index, last_log_index);
    CM_RETURN_IFERR_EX(rep_encode_appendlog_head(&pack, &appendlog_req), mec_release_pack(&pack));
    uint32 log_count_pos = mec_get_write_pos(&pack) - sizeof(uint64);

    uint64 j = 0;
    uint32 total_size = 0;
    for (uint64 index = log_begin; j < log_count; index++, j++) {
        log_entry_t* entry = stg_get_entry(stream_id, index);
        if (entry == NULL) {
            break;
        }
        total_size += (sizeof(rep_log_t) + ENTRY_SIZE(entry));
        if (total_size > MESSAGE_BUFFER_SIZE && j > 0) {
            LOG_DEBUG_INF("[REP]total_size[%u] is enough, send size[%u]. log_count[%llu], j[%llu]",
                total_size, (uint32)(total_size - (sizeof(rep_log_t) + ENTRY_SIZE(entry))), log_count, j);
            stg_entry_dec_ref(entry);
            break;
        }
        status_t ret = rep_encode_one_log(&pack, log_count_pos, j + 1, entry);
        stg_entry_dec_ref(entry);
        if (ret != CM_SUCCESS) {
            mec_release_pack(&pack);
            LOG_DEBUG_ERR("[REP]encode_one_log fail, index=%llu, j=%llu", index, j);
            return CM_ERROR;
        }
        ps_record1(PS_PACK, index);
    }
    appendlog_req.log_count = j;

    CM_RETURN_IFERR_EX(mec_send_data(&pack), mec_release_pack(&pack));
    LOG_DEBUG_INF("[REP]rep send succeed: " REP_APPEND_REQ_FMT, REP_APPEND_REQ_VAL(&pack, &appendlog_req, log_begin));
    if (APPEND_MODE == APPEND_NORMAL_MODE) {
        (void)cm_atomic_cas((atomic_t*)&NEXT_INDEX, old_next_index, log_begin + j);
        LOG_DEBUG_INF("[REP]set next_index to %llu,stream_id=%u,node_id=%u", NEXT_INDEX, stream_id, node_id);
    }
    mec_release_pack(&pack);
    return CM_SUCCESS;
}

static bool32 can_append_log(uint32 stream_id, uint64 last_index, uint32 node_id, dcf_role_t default_role)
{
    // only for passive node
    if (default_role == DCF_ROLE_PASSIVE && LOAD_LEVEL == DCF_LOAD_HIGH_LEVEL &&
        (g_timer()->now - PRE_APPTIME) < HIGH_LEVEL_SUSPEND_TIME) {
        return CM_FALSE;
    }

    // dn flow control, pause log replication
    if ((g_timer()->now - PRE_APPTIME) <= PAUSE_TIME) {
        return CM_FALSE;
    }

    /* if flow_ctrl=on, then do flow ctrl. */
    if (g_flow_ctrl_type != FC_NONE) {
        if ((g_timer()->now - PRE_APPTIME) < (g_rep_flow_ctrl_val * REP_FC_TIME_UNIT)) {
            return CM_FALSE;
        }
    }

    if ((APPEND_MODE == APPEND_NORMAL_MODE && last_index >= NEXT_INDEX) ||
        (APPEND_MODE == APPEND_REMATCH_MODE && cm_atomic32_cas(&TRY_REMATCH, 1, 0)) ||
        (g_timer()->now - PRE_APPTIME) > APPEND_INTERVAL*MICROSECS_PER_MILLISEC) {
        return CM_TRUE;
    }

    return CM_FALSE;
}

static status_t rep_appendlog_stream(uint64 thread_id, uint32 stream_id, uint32* stream_flag)
{
    dcf_node_role_t nodes[CM_MAX_NODE_COUNT];
    uint32 node_count;

    uint64 last_index = stg_last_index(stream_id);
    *stream_flag = 0;

    CM_RETURN_IFERR(md_get_stream_node_roles(stream_id, nodes, &node_count));

    for (uint32 i = 0; i < node_count; i++) {
        uint32 node_id = nodes[i].node_id;
        dcf_role_t default_role = nodes[i].default_role;
        if (node_id == g_cur_node_id) {
            continue;
        }

        if (thread_id != g_append_thread_id[node_id]) {
            continue;
        }

        if (!mec_is_ready(stream_id, node_id, PRIV_LOW)) {
            LOG_DEBUG_ERR_EX("[REP]stream_id%u, node_id%u's connection is not ready", stream_id, node_id);
            continue;
        }

        *stream_flag |= FLAG_EXISTS_ACTIVE_NODE;

        if (!can_append_log(stream_id, last_index, node_id, default_role)) {
            *stream_flag |= FLAG_CONTROL_FLOW;
            continue;
        }

        PRE_APPTIME = g_timer()->now;
        bool8 node_exists_log = CM_FALSE;

        if (rep_appendlog_node(stream_id, node_id, default_role, last_index, &node_exists_log) != CM_SUCCESS) {
            LOG_DEBUG_ERR("[REP]rep_appendlog_to_node failed:stream_id=%u,node_id=%u.", stream_id, node_id);
            continue;
        }

        if (node_exists_log) {
            *stream_flag |= FLAG_EXISTS_LOG;
        }
    }

    return CM_SUCCESS;
}

static void rep_appendlog_thread_entry(thread_t *thread)
{
    uint32 streams[CM_MAX_STREAM_COUNT];
    uint32 stream_count;
    uint64 thread_id = (uint64)thread->argument;
    uint32 rep_flag = 0;
    if (cm_set_thread_name("rep_appendlog") != CM_SUCCESS) {
        LOG_DEBUG_ERR("[REP]set apply thread name failed!");
    }

    if (md_get_stream_list(streams, &stream_count) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[REP]md_get_stream_list failed");
        return;
    }

    while (!thread->closed) {
        rep_flag = 0;

        for (uint32 i = 0; i < stream_count; i++) {
            uint32 stream_id = streams[i];
            if (!I_AM_LEADER(stream_id)) {
                continue;
            }

            uint32 stream_flag = 0;
            if (rep_appendlog_stream(thread_id, stream_id, &stream_flag) != CM_SUCCESS) {
                LOG_DEBUG_ERR("[REP]rep_appendlog failed.");
                continue;
            }

            rep_flag |= stream_flag;
        }

        if (!(rep_flag & FLAG_EXISTS_ACTIVE_NODE)) {
            LOG_DEBUG_INF("[REP]not exists active node.");
            cm_sleep(CM_SLEEP_1000_FIXED);
            continue;
        }

        if (rep_flag & FLAG_CONTROL_FLOW) {
            (void)cm_wait_cond(&g_appendlog_cond, CM_SLEEP_1_FIXED);
            continue;
        }
        if (!(rep_flag & FLAG_EXISTS_LOG)) {
            (void)cm_wait_cond(&g_appendlog_cond, CM_SLEEP_500_FIXED);
        }
    }
}

void rep_flow_ctrl_sampling_and_calc()
{
    uint64 commit_count, commit_total, commit_max, avg_delay;
    static uint64 total_delay = 0;
    static uint64 last_avg_delay = UINT64_MAX;
    static uint64 max_delay = 0;
    static uint64 min_delay = UINT64_MAX;
    int32 delta;
    static int32 ctrl = REP_FC_INIT_VAL;
    static int32 direction = 1;
    static uint64 count = 0;
    uint64 cur_delay = 0;

    static timespec_t last = 0;
    if (cm_clock_now() - last >= REP_FC_SAMP_PERIOD * MICROSECS_PER_SECOND) {
        last = cm_clock_now();
        // use commit_delay as sampling value now, should classify by g_flow_ctrl_type if needed.
        ps_get_stat(PS_COMMIT, &commit_count, &commit_total, &commit_max);
        if (commit_count != 0) {
            cur_delay = commit_total / commit_count;
            total_delay += cur_delay;
            max_delay = MAX(max_delay, cur_delay);
            min_delay = MIN(min_delay, cur_delay);

            count++;
            if (count % REP_FC_CTRL_PERIOD == 0) {
                avg_delay = (total_delay - (max_delay + min_delay)) / (REP_FC_CTRL_PERIOD - FC_MIN_MAX);
                delta = MAX(ctrl / CM_10X_FIXED, 1);

                if (avg_delay > last_avg_delay) {
                    direction = 0 - direction;
                } else if (avg_delay == last_avg_delay) {
                    delta = 0;
                }
                last_avg_delay = avg_delay;

                ctrl = (avg_delay < REP_FC_CTRL_THD) ? (ctrl / CM_2X_FIXED) : MAX(ctrl + delta * direction, 1);
                ctrl = MAX(ctrl, 0);
                ctrl = MIN(ctrl, REP_FC_MAX_VAL);
                g_rep_flow_ctrl_val = (uint32)ctrl;
                total_delay = 0;
                max_delay = 0;
                min_delay = UINT64_MAX;
            }
        }
        LOG_PROFILE("commit_cnt=%llu, cur_lat=%llu, flow_ctrl_val=%u", commit_count, cur_delay, g_rep_flow_ctrl_val);
    }
}

static void rep_leader_monitor_entry(thread_t *thread)
{
    if (cm_set_thread_name("rep_leader_monitor") != CM_SUCCESS) {
        LOG_DEBUG_ERR("[REP]set monitor thread name failed!");
    }
    LOG_RUN_INF("leader monitor thread start.");
    while (!thread->closed) {
        if (g_flow_ctrl_type == FC_NONE) {
            cm_sleep(CM_SLEEP_1000_FIXED);
            continue;
        }
        rep_flow_ctrl_sampling_and_calc();
        (void)rep_monitor_statistics(&g_leader_monitor_statistics);
    }
    LOG_RUN_INF("leader monitor thread end.");
}

static status_t rep_adjust_majority_groups(uint32 majority_groups[CM_MAX_GROUP_COUNT],
    uint32 *count, dcf_node_attr_t *sort_index, uint32 voted_cnt)
{
    CM_RETURN_IFERR(md_get_majority_groups(majority_groups, count));
    if (*count == 0) {
        return CM_SUCCESS;
    }

    uint32 total = *count;
    uint32 idx = 0;
    for (uint32 i = 0; i < total; i++) {
        uint32 group_value = majority_groups[i];
        bool32 exists = CM_FALSE;
        for (uint32 j = 0 ; j < voted_cnt; j++) {
            if (sort_index[j].group == group_value) {
                exists = CM_TRUE;
                break;
            }
        }
        if (!exists) {
            majority_groups[i] = CM_INVALID_GROUP_ID;
            (*count)--;
        } else {
            majority_groups[idx] = majority_groups[i];
            idx++;
        }
    }
    return CM_SUCCESS;
}

static void rep_cal_voted_group_count(uint32 majority_groups[CM_MAX_GROUP_COUNT],
    uint32 count, uint32 sort_index_group, uint32 *voted_group_count)
{
    for (uint32 j = 0; j < count; j++) {
        if (majority_groups[j] == sort_index_group && majority_groups[j] != CM_INVALID_GROUP_ID) {
            (*voted_group_count)++;
            majority_groups[j] = CM_INVALID_GROUP_ID;
            break;
        }
    }
    return;
}

static int rep_index_compare(const void *a, const void *b)
{
    if (((dcf_node_attr_t *)a)->index == ((dcf_node_attr_t *)b)->index) {
        return 0;
    } else if (((dcf_node_attr_t *)a)->index > ((dcf_node_attr_t *)b)->index) {
        return -1;
    } else {
        return 1;
    }
}

static status_t rep_cal_commit_index(dcf_node_attr_t *sort_index, uint32 voted_cnt, uint32 stream_id, uint32 quorum,
    uint64 *commit_idx)
{
    uint32 all_votes = 0;
    uint32 majority_groups[CM_MAX_GROUP_COUNT];
    uint32 majority_groups_count = 0;
    uint32 voted_group_count = 0;
    bool32 is_group_voted = CM_TRUE;
    for (uint32 i = 0; i < CM_MAX_GROUP_COUNT; i++) {
        majority_groups[i] = CM_INVALID_GROUP_ID;
    }

    qsort(sort_index, voted_cnt, sizeof(dcf_node_attr_t), rep_index_compare);

    if (rep_adjust_majority_groups(majority_groups, &majority_groups_count, sort_index, voted_cnt) == CM_SUCCESS) {
        is_group_voted = majority_groups_count == 0 ? CM_TRUE : CM_FALSE;
    }

    // for example, there exists 3 node, each node weight is 1, majority_groups is [1,2], while the iteration readed
    // node 2, we match the condition all_votes(2) >= quorum(2), but there is no node in group 2. after readed node 3,
    // group 1 and group 2 has at least one node reached the commit index 100. then we set commit index to 100.
    // NODE_ID  1     2     3
    // INDEX    102   101   100
    // GROUP    1     1     2
    for (uint32 i = 0; i < voted_cnt; i++) {
        all_votes += sort_index[i].weight;
        if (!is_group_voted) {
            rep_cal_voted_group_count(majority_groups, majority_groups_count, sort_index[i].group, &voted_group_count);
            is_group_voted = voted_group_count >= majority_groups_count ? CM_TRUE: CM_FALSE;
        }
        if (all_votes >= quorum && is_group_voted) {
            *commit_idx = sort_index[i].index;
            return CM_SUCCESS;
        }
    }

    if (all_votes < quorum) {
        LOG_RUN_ERR("[REP]rep_cal_commit_index: all_votes %u is less than quorum %u", all_votes, quorum);
    } else if (!is_group_voted) {
        LOG_RUN_ERR("[REP]rep_cal_commit_index: not all group configed in majority groups was voted,"
            "voted group count:%u, majority groups count:%u", voted_group_count, majority_groups_count);
        for (uint32 k = 0; k < majority_groups_count; k++) {
            if (majority_groups[k] != CM_INVALID_GROUP_ID) {
                LOG_RUN_ERR("[REP]rep_cal_commit_index, group: %u", majority_groups[k]);
            }
        }
    }

    return CM_ERROR;
}

static status_t rep_try_commit_log(uint32 stream_id)
{
    uint32 node_count, quorum, weight;
    uint32 vote_count = 0;
    uint32 voted_node = 0;
    bool32 is_elc_voter;
    uint64 commit_index;
    uint32 nodes[CM_MAX_NODE_COUNT];
    dcf_node_attr_t sort_index[CM_MAX_NODE_COUNT];
    uint64 min_apply_id = CM_INVALID_ID64;
    dcf_node_t node_item;

    CM_RETURN_IFERR(elc_get_quorum(stream_id, &quorum));
    CM_RETURN_IFERR(md_get_stream_nodes(stream_id, nodes, &node_count));
    for (uint32 i = 0; i < node_count; i++) {
        uint32 node_id = nodes[i];
        CM_RETURN_IFERR(md_get_node(node_id, &node_item));
        CM_RETURN_IFERR(elc_is_voter(stream_id, node_id, &is_elc_voter));
        if (is_elc_voter) {
            CM_RETURN_IFERR(elc_node_voting_weight(stream_id, node_id, &weight));
            uint64 index = MATCH_INDEX.index;
            sort_index[voted_node].index = index;
            sort_index[voted_node].weight = weight;
            sort_index[voted_node].group = node_item.group;
            vote_count += weight;
            ++voted_node;
            LOG_DEBUG_INF("[REP]rep_try_commit_log:node_id=%u,match_index=%llu,weight=%u.", node_id, index, weight);
        }

        min_apply_id = MIN(min_apply_id, APPLY_INDEX);
    }

    rep_set_cluster_min_apply_idx(stream_id, min_apply_id);
    CM_RETURN_IFERR(rep_cal_commit_index(sort_index, voted_node, stream_id, quorum, &commit_index));
    uint64 log_term = stg_get_term(stream_id, commit_index);
    uint64 cur_term = elc_get_current_term(stream_id);
    LOG_DEBUG_INF("[REP]rep_cal_commit_idx:quorum=%u,try commit_idx=%llu,log_term=%llu,cur_term=%llu.",
        quorum, commit_index, log_term, cur_term);
    if (log_term == cur_term) {
        log_id_t last = rep_get_commit_log(stream_id);
        if (last.index != commit_index) {
            if (commit_index <= last.index) {
                LOG_DEBUG_WAR("[REP]current commit_index(%llu) is not larger than last.index(%llu), work_mode=%d",
                    commit_index, last.index, elc_get_work_mode(stream_id));
            }
            rep_set_commit_log(stream_id, log_term, commit_index);
            rep_apply_trigger();
            LOG_DEBUG_INF("[REP]leader set commit index to (%llu,%llu)", log_term, commit_index);
        }
    } else {
        LOG_DEBUG_INF("[REP]index term is not current term,can't be committed.index=%llu,"
            "log_term=%llu,current term = %llu", commit_index, log_term, cur_term);
    }

    return CM_SUCCESS;
}

status_t rep_leader_acceptlog_proc(uint32 stream_id)
{
    LOG_TRACE(rep_get_tracekey(), "accept:rep_leader_acceptlog_proc rep_try_commit_log.");
    LOG_DEBUG_INF("rep_leader_acceptlog_proc.");
    uint32 node_id = g_cur_node_id;
    APPLY_INDEX = stg_get_applied_index(stream_id);
    CM_RETURN_IFERR(rep_try_commit_log(stream_id));

    return CM_SUCCESS;
}

static void rep_rematch_proc(uint32 stream_id, uint32 node_id, const rep_apendlog_ack_t* ack)
{
    APPEND_MODE = APPEND_REMATCH_MODE;
    log_id_t next_log = rep_get_pre_term_log(stream_id, ack->pre_log.index);
    LOG_DEBUG_INF("[REP] pre_log(%llu,%llu),mismatch_log(%llu,%llu),next_log(%llu,%llu)",
        ack->pre_log.term, ack->pre_log.index,
        ack->mismatch_log.term, ack->mismatch_log.index,
        next_log.term, next_log.index);

    if (next_log.index < ack->mismatch_log.index) {
        next_log = ack->mismatch_log;
    }

    if (NEXT_INDEX > next_log.index) {
        (void)cm_atomic_set((atomic_t*)&NEXT_INDEX, ack->mismatch_log.index);
        LOG_DEBUG_INF("[REP]pre log is mismatch,reset next index to:%llu,stream_id=%u,node_id=%u",
            NEXT_INDEX, stream_id, node_id);
    } else {
        LOG_DEBUG_INF("[REP]pre log is mismatch,next index:%llu,mismatch(%llu,%llu)",
            NEXT_INDEX, ack->mismatch_log.term, ack->mismatch_log.index);
    }
    (void)cm_atomic32_cas(&TRY_REMATCH, 0, 1);

    // retry to append log
    rep_appendlog_trigger(stream_id);
}

static status_t rep_check_appendlog_ack(uint32 stream_id, uint32 node_id, rep_apendlog_ack_t* ack)
{
    uint64 cur_term = elc_get_current_term(stream_id);
    if (ack->follower_term > cur_term) {
        // call election's function
        (void)elc_judge_term(stream_id, ack->follower_term);
        LOG_DEBUG_INF("[REP]follower's term is greater than mine.[%llu > %llu]", ack->follower_term, cur_term);
        return CM_ERROR;
    }

    if (ack->ret_code == ERR_TERM_IS_EXPIRED) {
        // call election's function
        (void)elc_judge_term(stream_id, ack->follower_term);
        LOG_DEBUG_INF("[REP]follower's term is greater than mine.[%llu,%llu]", ack->follower_term, cur_term);
        return CM_ERROR;
    } else if (ack->ret_code == ERR_APPEN_LOG_REQ_LOST) {
        LOG_DEBUG_INF("[REP]append log may be lost.reset next index from %llu to %llu,node_id=%u.",
            NEXT_INDEX, MATCH_INDEX.index + 1, node_id);
        NEXT_INDEX = MATCH_INDEX.index + 1;
    } else if (ack->ret_code == ERR_TERM_IS_NOT_MATCH) {
        rep_rematch_proc(stream_id, node_id, ack);
        return CM_ERROR;
    } else if (ack->ret_code != 0) {
        LOG_DEBUG_INF("[REP]follower process failed.ret_code=%d", ack->ret_code);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

// leader process follower's ack message
static status_t rep_appendlog_ack_proc(mec_message_t *pack)
{
    uint32 stream_id = pack->head->stream_id;
    uint32 node_id = pack->head->src_inst;
    rep_apendlog_ack_t ack;

    if (rep_decode_appendlog_ack(pack, &ack) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[REP]rep_decode_appendlog_ack failed.");
        return CM_ERROR;
    }

    LOG_DEBUG_INF("[REP]recv ack." REP_APPEND_ACK_FMT, REP_APPEND_ACK_VAL(pack, &ack));

    if (ack.follower_accept_log.index != CM_INVALID_INDEX_ID) {
        ps_record1(PS_FOLLOWER_ACCEPT, ack.follower_accept_log.index);
    }

    CM_RETURN_IFERR(rep_check_appendlog_ack(stream_id, node_id, &ack));

    APPLY_INDEX = ack.apply_id;

    if (ack.follower_accept_log.index != CM_INVALID_INDEX_ID ||
        ack.follower_accept_log.term != CM_INVALID_TERM_ID) {
        uint64 my_term = stg_get_term(stream_id, ack.follower_accept_log.index);
        if (my_term == ack.follower_accept_log.term) {
            if (APPEND_MODE == APPEND_REMATCH_MODE) {
                APPEND_MODE = APPEND_NORMAL_MODE;
                (void)cm_atomic32_cas(&TRY_REMATCH, 1, 0);
                NEXT_INDEX = ack.follower_accept_log.index;
            }
            rep_follower_accepted_trigger(stream_id, pack->head->src_inst, ack.follower_accept_log);
            LOG_DEBUG_INF("[REP]follower process succeed,next_index=%llu,set match_index=(%llu,%llu)",
                NEXT_INDEX, MATCH_INDEX.term, MATCH_INDEX.index);
        } else {
            if (APPEND_MODE == APPEND_REMATCH_MODE) {
                APPEND_MODE = APPEND_NORMAL_MODE;
                (void)cm_atomic32_cas(&TRY_REMATCH, 1, 0);
                NEXT_INDEX = NEXT_INDEX + 1;
            }
        }
        log_id_t last_log = stg_last_log_id(stream_id);
        if (last_log.index >= NEXT_INDEX) {
            rep_appendlog_trigger(stream_id);
        }
    }
    (void)elc_set_hb_ack_timeout(stream_id, node_id, cm_clock_now());
    return CM_SUCCESS;
}

void rep_appendlog_trigger(uint32 stream_id)
{
    LOG_DEBUG_INF("rep_appendlog_trigger.");
    cm_release_cond(&g_appendlog_cond);
}

static void rep_follower_accepted_trigger(uint32 stream_id, uint32 node_id, log_id_t log_id)
{
    LOG_TRACE(log_id.index, "rep_follower_accepted_trigger.");
    LOG_TRACE(rep_get_tracekey(), "rep_follower_accepted_trigger.log_id=%llu", log_id.index);
    LOG_DEBUG_INF("[REP]rep_follower_accepted_trigger,node_id=%u,log=(%llu,%llu)",
        node_id, log_id.term, log_id.index);

    MATCH_INDEX = log_id;

    rep_set_accept_flag(stream_id);
}

void rep_leader_acceptlog(uint32 stream_id, uint64 term, uint64 index, status_t status)
{
    if (status != CM_SUCCESS) {
        if (++DISK_ERROR >= DISK_ERROR_THRESHOLD) {
            DISK_ERROR = 0;
            (void)elc_demote_follower(stream_id);
        }
        return;
    }

    LOG_DEBUG_INF("rep_leader_acceptlog.");
    LOG_TRACE(index, "rep_leader_acceptlog.");

    uint32 node_id = g_cur_node_id;

    MATCH_INDEX.term = term;
    MATCH_INDEX.index = index;
    NEXT_INDEX = index + 1;
    DISK_ERROR = 0;
}

log_id_t rep_leader_get_match_index(uint32 stream_id, uint32 node_id)
{
    return MATCH_INDEX;
}

uint64 rep_leader_get_next_index(uint32 stream_id, uint32 node_id)
{
    return NEXT_INDEX;
}

uint64 rep_leader_get_apply_index(uint32 stream_id, uint32 node_id)
{
    return APPLY_INDEX;
}

void rep_set_pause_time(uint32 stream_id, uint32 node_id, uint32 pause_time)
{
    PAUSE_TIME = pause_time;
}

uint32 rep_get_pause_time(uint32 stream_id, uint32 node_id)
{
    return PAUSE_TIME;
}

static inline void rep_init_thread_id()
{
    uint64 node_id;
    uint64 node_cnt = 0;
    uint32 cur_node_id = md_get_cur_node();
    for (node_id = 0; node_id < CM_MAX_NODE_COUNT; node_id++) {
        g_append_thread_id[node_id] = node_cnt % g_append_thread_num;
        if (node_id != cur_node_id) {
            node_cnt++;
        }
    }
}

static status_t rep_check_group_value_valid(uint32 group_value, bool32 *is_valid)
{
    *is_valid = CM_FALSE;
    uint32 node_list[CM_MAX_NODE_COUNT];
    uint32 node_count;
    uint32 stream_list[CM_MAX_STREAM_COUNT];
    uint32 stream_count;
    CM_RETURN_IFERR(md_get_stream_list(stream_list, &stream_count));
    for (uint32 i = 0; i < stream_count; i++) {
        uint32 stream_id = stream_list[i];
        CM_RETURN_IFERR(md_get_stream_nodes(stream_id, node_list, &node_count));
        for (uint32 i = 0; i < node_count; i++) {
            uint32 node_id = node_list[i];
            dcf_node_t node_item;
            bool32 is_voter = CM_FALSE;
            CM_RETURN_IFERR(md_get_node(node_id, &node_item));
            CM_RETURN_IFERR(md_is_voter(stream_id, node_id, &is_voter));
            if (group_value == node_item.group && is_voter) {
                *is_valid = CM_TRUE;
                return CM_SUCCESS;
            }
        }
    }
    return CM_SUCCESS;
}

status_t rep_check_param_majority_groups()
{
    uint32 groups[CM_MAX_GROUP_COUNT] = { 0 };
    uint32 count = 0;
    bool32 is_valid = CM_FALSE;
    CM_RETURN_IFERR(md_get_majority_groups(groups, &count));
    for (int i = 0; i < count; i++) {
        CM_RETURN_IFERR(rep_check_group_value_valid(groups[i], &is_valid));
        if (!is_valid) {
            LOG_RUN_WAR("[REP] group %u in majority_groups is not valid, will ignored,"
                "pls reset param MAJORITY_GROUPS.", groups[i]);
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}
