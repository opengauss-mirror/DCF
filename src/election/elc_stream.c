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
 * elc_stream.c
 *    election process
 *
 * IDENTIFICATION
 *    src/election/elc_stream.c
 *
 * -------------------------------------------------------------------------
 */

#include "elc_stream.h"
#include "stg_manager.h"
#include "mec.h"
#include "cm_timer.h"
#include "replication.h"
#include "util_defs.h"
#include "elc_status_check.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_elc_info {
    latch_t latch;
    uint32 stream_id;
    uint64 current_term;
    uint32 votefor_id;
    uint32 vote_count;
    uint32 vote_no_count;
    dcf_role_t node_role; // current node role
    timespec_t last_hb_time;
    timespec_t last_hb_ack[CM_MAX_NODE_COUNT];
    dcf_work_mode_t work_mode;
    uint32 vote_num;
    dcf_work_mode_t vote_node_work_mode[CM_MAX_NODE_COUNT];
    uint32 old_leader_id;
    timespec_t last_md_rep_time;
    volatile bool32 force_vote;
    bool32 inter_promote_flag; // Whether the leader obtained last time is given up to a high-priority node.
    volatile timespec_t leader_start_time;
    uint32 leader_group;
    uint32 my_group;
    uint64 priority;
} elc_info_t;

static elc_info_t g_stream_list[CM_MAX_STREAM_COUNT];
static role_notify_t g_stream_notify[CM_MAX_STREAM_COUNT];
cm_thread_cond_t g_status_notify_cond;
usr_cb_status_notify_t g_cb_status_notify = NULL;
usr_cb_election_notify_t g_cb_election_notify = NULL;

status_t get_current_node_role(uint32 stream_id, uint32 current_node_id, uint32 leader_id, dcf_role_t *role)
{
    dcf_node_t node_info;
    CM_RETURN_IFERR(md_get_stream_node_ext(stream_id, current_node_id, &node_info));

    /* for 1 node mode, set role as leader */
    uint32 node_num;
    CM_RETURN_IFERR(md_get_stream_nodes_count(stream_id, &node_num));
    if (node_num == 1) {
        if (node_info.default_role != DCF_ROLE_LEADER) {
            LOG_RUN_WAR("[ELC] 1 node mode, force default_role(%d) to leader", node_info.default_role);
        }
        *role = DCF_ROLE_LEADER;
        (void)elc_stream_set_votefor(stream_id, current_node_id);
        return CM_SUCCESS;
    }

    param_run_mode_t run_mode = elc_stream_get_run_mode();
    if (run_mode == ELECTION_AUTO || run_mode == ELECTION_DISABLE) {
        if (node_info.default_role == DCF_ROLE_LEADER) {
            *role = DCF_ROLE_FOLLOWER;
        } else {
            *role = node_info.default_role;
        }
    } else {
        if (leader_id == CM_INVALID_NODE_ID) {
            *role = node_info.default_role;
        } else {
            if (current_node_id == leader_id) {
                *role = DCF_ROLE_LEADER;
            } else {
                *role = (node_info.default_role == DCF_ROLE_LEADER) ? DCF_ROLE_FOLLOWER : node_info.default_role;
            }
        }
    }
    return CM_SUCCESS;
}

uint32 elc_stream_get_elc_timeout_ms()
{
    param_value_t value;
    if (md_get_param(DCF_PARAM_ELECTION_TIMEOUT, &value) == CM_SUCCESS) {
        return value.value_elc_timeout;
    } else {
        return (uint32)CM_DEFAULT_ELC_TIMEOUT;
    }
}

uint32 elc_stream_get_hb_interval_ms()
{
    param_value_t value;
    if (md_get_param(DCF_PARAM_HEARTBEAT_INTERVAL, &value) == CM_SUCCESS) {
        return value.value_hb_interval;
    } else {
        return (uint32)CM_DEFAULT_HB_INTERVAL;
    }
}

uint32 elc_stream_get_elc_switch_thd_sec()
{
    param_value_t value;
    if (md_get_param(DCF_PARAM_ELECTION_SWITCH_THRESHOLD, &value) == CM_SUCCESS) {
        return value.value_elc_switch_thd;
    } else {
        return (uint32)CM_DEFAULT_ELC_SWITCH_THD;
    }
}

bool32 elc_stream_get_auto_elc_pri_en()
{
    param_value_t value;
    if (md_get_param(DCF_PARAM_AUTO_ELC_PRIORITY_EN, &value) == CM_SUCCESS) {
        return value.value_auto_elc_priority_en;
    } else {
        return (bool32)CM_TRUE;
    }
}

param_run_mode_t elc_stream_get_run_mode()
{
    param_value_t value;
    if (md_get_param(DCF_PARAM_RUN_MODE, &value) == CM_SUCCESS) {
        return value.value_mode;
    } else {
        return ELECTION_MANUAL;
    }
}

status_t elc_stream_init()
{
    cm_init_cond(&g_status_notify_cond);

    MEMS_RETURN_IFERR(memset_sp(g_stream_notify, sizeof(role_notify_t) * CM_MAX_STREAM_COUNT, 0,
        sizeof(role_notify_t) * CM_MAX_STREAM_COUNT));
    MEMS_RETURN_IFERR(memset_sp(g_stream_list, sizeof(elc_info_t) * CM_MAX_STREAM_COUNT, 0,
        sizeof(elc_info_t) * CM_MAX_STREAM_COUNT));

    uint32 current_node_id = md_get_cur_node();
    uint32 stream_list[CM_MAX_STREAM_COUNT];
    uint32 stream_count;
    CM_RETURN_IFERR(md_get_stream_list(stream_list, &stream_count));
    for (uint32 i = 0; i < stream_count; i++) {
        uint32 stream_id = stream_list[i];
        uint32 leader_id = stg_get_votedfor(stream_id);

        g_stream_list[stream_id].stream_id = stream_id;
        g_stream_list[stream_id].votefor_id = leader_id;
        g_stream_list[stream_id].current_term = stg_get_current_term(stream_id);
        g_stream_list[stream_id].vote_count = 0;
        g_stream_list[stream_id].vote_no_count = 0;
        dcf_role_t node_role;
        CM_RETURN_IFERR(get_current_node_role(stream_id, current_node_id, leader_id, &node_role));
        g_stream_list[stream_id].node_role = node_role;
        g_stream_list[stream_id].vote_num = 0;
        g_stream_list[stream_id].old_leader_id = CM_INVALID_ID32;
        g_stream_list[stream_id].work_mode = WM_NORMAL;
        g_stream_list[stream_id].force_vote = CM_FALSE;
        g_stream_list[stream_id].inter_promote_flag = CM_FALSE;
        dcf_node_t node_info;
        CM_RETURN_IFERR(md_get_stream_node_ext(stream_id, current_node_id, &node_info));
        g_stream_list[stream_id].my_group = node_info.group;
        g_stream_list[stream_id].leader_group = node_info.group;
        g_stream_list[stream_id].priority = node_info.priority;
        if ((leader_id == current_node_id) || (leader_id == CM_INVALID_NODE_ID
            && node_info.default_role == DCF_ROLE_LEADER)) {
            g_stream_list[stream_id].last_hb_time = 0;
        } else {
            g_stream_list[stream_id].last_hb_time =
                cm_clock_now() + CM_MAX_ELC_INIT_WAIT_TIMES * elc_stream_get_elc_timeout_ms() * MICROSECS_PER_MILLISEC;
        }
        LOG_RUN_INF("[ELC]stream %u init, cur_node_id %u, vote_for %u, last_hb_time %lld",
            stream_id, current_node_id, leader_id, g_stream_list[stream_id].last_hb_time);
        for (uint32 j = 0; j < CM_MAX_NODE_COUNT; j++) {
            g_stream_list[stream_id].last_hb_ack[j] = cm_clock_now();
        }
        cm_latch_init(&g_stream_list[stream_id].latch);
    }

    return CM_SUCCESS;
}

uint64 elc_stream_get_current_term(uint32 stream_id)
{
    return g_stream_list[stream_id].current_term;
}

status_t elc_stream_set_term(uint32 stream_id, uint64 current_term)
{
    g_stream_list[stream_id].current_term = current_term;

    return stg_set_current_term(stream_id, current_term);
}

dcf_role_t elc_stream_get_role(uint32 stream_id)
{
    return g_stream_list[stream_id].node_role;
}

void add_notify_item(uint32 stream_id, uint32 node_id, uint32 new_leader, dcf_role_t old_role, dcf_role_t new_role)
{
    uint32 count = 0;
    LOG_DEBUG_INF("[ELC]add_notify_item start");
    cm_latch_x(&g_stream_notify[stream_id].latch, 0, NULL);
    do {
        uint32 pi = g_stream_notify[stream_id].pi;
        if ((pi + 1) % MAX_NOTIFY_ITEM_NUM != g_stream_notify[stream_id].ci) {
            g_stream_notify[stream_id].item[pi].node_id = node_id;
            g_stream_notify[stream_id].item[pi].new_leader = new_leader;
            g_stream_notify[stream_id].item[pi].old_role = old_role;
            g_stream_notify[stream_id].item[pi].new_role = new_role;
            LOG_DEBUG_INF("[ELC]added item, pi=%u, stream_id=%u, node_id=%u new_leader=%u old_role=%d new_role=%d",
                pi, stream_id, node_id, new_leader, old_role, new_role);
            g_stream_notify[stream_id].pi = (pi + 1) % MAX_NOTIFY_ITEM_NUM;
            break;
        } else {
            cm_unlatch(&g_stream_notify[stream_id].latch, NULL);
            cm_sleep(CM_SLEEP_10_FIXED);
            count++;
            if (count > CM_100X_FIXED) {
                LOG_RUN_ERR("[ELC]add_item timeout.stream_id=%u, node_id=%u new_leader=%u old_role=%d new_role=%d",
                    stream_id, node_id, new_leader, old_role, new_role);
                return;
            }
            cm_latch_x(&g_stream_notify[stream_id].latch, 0, NULL);
        }
    } while (1);
    cm_unlatch(&g_stream_notify[stream_id].latch, NULL);

    cm_release_cond(&g_status_notify_cond);

    LOG_DEBUG_INF("[ELC]add_notify_item end");
}

status_t get_notify_item(uint32 stream_id, role_notify_item_t* notify_item)
{
    cm_latch_x(&g_stream_notify[stream_id].latch, 0, NULL);
    uint32 ci = g_stream_notify[stream_id].ci;
    if (ci != g_stream_notify[stream_id].pi) {
        *notify_item = g_stream_notify[stream_id].item[ci];
        g_stream_notify[stream_id].ci = (ci + 1) % MAX_NOTIFY_ITEM_NUM;
        cm_unlatch(&g_stream_notify[stream_id].latch, NULL);
        LOG_DEBUG_INF("[ELC]get item success, ci=%u, stream_id=%u", ci, stream_id);
        return CM_SUCCESS;
    }
    cm_unlatch(&g_stream_notify[stream_id].latch, NULL);
    return CM_ERROR;
}

void rep_set_can_write_flag(uint32 stream_id, uint32 flag);

void elc_stream_notify_proc()
{
    (void)cm_wait_cond(&g_status_notify_cond, CM_SLEEP_500_FIXED);
    role_notify_item_t notify_item;
    for (uint32 i = 0; i < CM_MAX_STREAM_COUNT; i++) {
        uint32 stream_id = i;
        if (get_notify_item(stream_id, &notify_item) == CM_SUCCESS) {
            dcf_role_t old_role = notify_item.old_role;
            dcf_role_t role = notify_item.new_role;
            LOG_DEBUG_INF("[ELC]got notify item: stream_id=%u old_role=%d new_role=%d", stream_id, old_role, role);
            if ((old_role != DCF_ROLE_LEADER && role == DCF_ROLE_LEADER) ||
                (old_role == DCF_ROLE_LEADER && role != DCF_ROLE_LEADER)) {
                LOG_DEBUG_INF("[ELC]status_changed_notify proc begin");
                /* cancel can_write flag */
                rep_set_can_write_flag(stream_id, CM_FALSE);

                uint32 prio_leader = elc_get_rcv_best_priority_node(stream_id);
                bool32 force_vote = elc_stream_is_force_vote(stream_id);
                elc_stream_set_force_vote_flag(stream_id, CM_FALSE);
                LOG_RUN_INF("[ELC]max_prio_leader=%u force_vote=%d role=%d", prio_leader, force_vote, role);
                if (force_vote == CM_FALSE && role == DCF_ROLE_LEADER && prio_leader != CM_INVALID_NODE_ID) {
                    rep_try_promote_prio_leader(stream_id, prio_leader);
                    if (elc_stream_get_role(stream_id) != DCF_ROLE_LEADER) {
                        elc_stream_set_inter_promote_flag(stream_id, CM_TRUE);
                        continue;
                    }
                }

                if (elc_stream_get_inter_promote_flag(stream_id) == CM_TRUE && role != DCF_ROLE_LEADER) {
                    continue;
                }
                elc_stream_set_inter_promote_flag(stream_id, CM_FALSE);
                
                (void)rep_role_notify(stream_id, old_role, role);
                if (g_cb_status_notify != NULL) {
                    int ret = g_cb_status_notify(stream_id,
                        (uint32)((role == DCF_ROLE_LEADER) ? DCF_ROLE_LEADER : DCF_ROLE_FOLLOWER));
                    LOG_DEBUG_INF("[ELC]Callback: status_changed_notify, retcode=%d", ret);
                }
            }
            if (notify_item.new_leader != CM_INVALID_NODE_ID) {
                if (g_cb_election_notify != NULL) {
                    int ret = g_cb_election_notify(stream_id, notify_item.new_leader);
                    LOG_DEBUG_INF("[ELC]Callback: status_election_notify, retcode=%d", ret);
                }
                notify_item.new_leader = CM_INVALID_NODE_ID;
            }
        }
    }
}

status_t elc_stream_set_role(uint32 stream_id, dcf_role_t role)
{
    dcf_role_t old_role = g_stream_list[stream_id].node_role;
    g_stream_list[stream_id].node_role = role;

    LOG_DEBUG_INF("[ELC]elc stream set role, stream_id=%u old_role=%d new_role=%d ", stream_id, old_role, role);
    if ((old_role != DCF_ROLE_LEADER && role == DCF_ROLE_LEADER) ||
        (old_role == DCF_ROLE_LEADER && role != DCF_ROLE_LEADER)) {
        add_notify_item(stream_id, md_get_cur_node(), CM_INVALID_NODE_ID, old_role, role);
    }
    return CM_SUCCESS;
}

uint32 elc_stream_get_vote_count(uint32 stream_id)
{
    return g_stream_list[stream_id].vote_count;
}

uint32 elc_stream_get_vote_no_count(uint32 stream_id)
{
    return g_stream_list[stream_id].vote_no_count;
}

uint32 elc_stream_is_win(uint32 stream_id, bool32* is_win)
{
    uint32 quorum;

    CM_RETURN_IFERR(elc_stream_get_quorum(stream_id, &quorum));
    *is_win = g_stream_list[stream_id].vote_count >= quorum;

    return CM_SUCCESS;
}

status_t elc_stream_is_not_win(uint32 stream_id, bool32* is_not_win)
{
    uint32 voter_num = 0;
    CM_RETURN_IFERR(md_get_voter_num(stream_id, &voter_num));
    if (g_stream_list[stream_id].work_mode == WM_NORMAL) {
        *is_not_win = g_stream_list[stream_id].vote_no_count >= ((voter_num + 1) / CM_2X_FIXED);
    } else if (g_stream_list[stream_id].work_mode == WM_MINORITY) {
        *is_not_win = g_stream_list[stream_id].vote_no_count > (voter_num - g_stream_list[stream_id].vote_num);
    } else {
        LOG_RUN_ERR("invalid work_mode:%d", g_stream_list[stream_id].work_mode);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t elc_stream_get_quorum(uint32 stream_id, uint32* quorum)
{
    uint32 voter_num = 0;
    if (g_stream_list[stream_id].work_mode == WM_NORMAL) {
        CM_RETURN_IFERR(md_get_voter_num(stream_id, &voter_num));
        *quorum = (voter_num / CM_2X_FIXED) + 1;
    } else if (g_stream_list[stream_id].work_mode == WM_MINORITY) {
        *quorum = g_stream_list[stream_id].vote_num;
    } else {
        LOG_RUN_ERR("invalid work_mode:%d", g_stream_list[stream_id].work_mode);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t elc_stream_increase_vote_count(uint32 stream_id, uint32 voting_weight)
{
    g_stream_list[stream_id].vote_count += voting_weight;
    return CM_SUCCESS;
}

status_t elc_stream_increase_vote_no_count(uint32 stream_id, uint32 voting_weight)
{
    g_stream_list[stream_id].vote_no_count += voting_weight;
    return CM_SUCCESS;
}

void elc_stream_reset_vote_count(uint32 stream_id)
{
    g_stream_list[stream_id].vote_count = 0;
    g_stream_list[stream_id].vote_no_count = 0;
}

timespec_t elc_stream_get_timeout(uint32 stream_id)
{
    return g_stream_list[stream_id].last_hb_time;
}

status_t elc_stream_set_timeout(uint32 stream_id, timespec_t time)
{
    g_stream_list[stream_id].last_hb_time = time;
    return CM_SUCCESS;
}

bool32 elc_stream_is_future_hb(uint32 stream_id)
{
    uint64 hb_time = g_stream_list[stream_id].last_hb_time;
    return (hb_time > cm_clock_now());
}

timespec_t  elc_stream_get_hb_ack_time(uint32 stream_id, uint32 node_id)
{
    return g_stream_list[stream_id].last_hb_ack[node_id];
}

status_t elc_stream_set_hb_ack_time(uint32 stream_id, uint32 node_id, timespec_t time)
{
    g_stream_list[stream_id].last_hb_ack[node_id] = time;
    return CM_SUCCESS;
}

uint32 elc_stream_get_votefor(uint32 stream_id)
{
    return g_stream_list[stream_id].votefor_id;
}

status_t elc_stream_set_votefor(uint32 stream_id, uint32 votefor_id)
{
    LOG_DEBUG_INF("[ELC]set votefor_id to %u", votefor_id);
    if (votefor_id != CM_INVALID_NODE_ID && votefor_id != md_get_cur_node()) {
        timespec_t now = cm_clock_now();
        elc_stream_set_leader_start_time(stream_id, now);
        LOG_DEBUG_INF("[ELC]set leader_start_time to %llu, votefor_id=%u", now, votefor_id);
    }
    g_stream_list[stream_id].votefor_id = votefor_id;
    return stg_set_votedfor(stream_id, votefor_id);
}

uint32 elc_stream_get_old_leader(uint32 stream_id)
{
    return g_stream_list[stream_id].old_leader_id;
}

uint32 elc_stream_set_old_leader(uint32 stream_id, uint32 leader_id)
{
    g_stream_list[stream_id].old_leader_id = leader_id;
    return CM_SUCCESS;
}

status_t elc_stream_vote_node_list(uint32 stream_id, uint64* inst_bits)
{
    uint32 node_list[CM_MAX_NODE_COUNT];
    uint32 node_count;
    CM_RETURN_IFERR(md_get_stream_nodes(stream_id, node_list, &node_count));
    uint32 current_node_id = elc_stream_get_current_node();
    for (uint32 i = 0; i < node_count; i++) {
        uint32 id = node_list[i];
        if (id != current_node_id) {
            MEC_SET_BRD_INST(inst_bits, id);
        }
    }
    return CM_SUCCESS;
}

bool32 elc_stream_is_exists(uint32 stream_id)
{
    if (g_stream_list[stream_id].stream_id == CM_INVALID_STREAM_ID) {
        return CM_FALSE;
    } else {
        return CM_TRUE;
    }
}
uint32 elc_stream_get_current_node()
{
    return md_get_cur_node();
}

void elc_stream_lock_s(uint32 stream_id)
{
    cm_latch_s(&g_stream_list[stream_id].latch, 0, CM_FALSE, NULL);
}

void elc_stream_lock_x(uint32 stream_id)
{
    cm_latch_x(&g_stream_list[stream_id].latch, 0, NULL);
}

void elc_stream_unlock(uint32 stream_id)
{
    cm_unlatch(&g_stream_list[stream_id].latch, NULL);
}

status_t elc_register_notify(usr_cb_status_notify_t cb_func)
{
    g_cb_status_notify = cb_func;
    return CM_SUCCESS;
}

status_t elc_register_election_notify(usr_cb_election_notify_t cb_func)
{
    g_cb_election_notify = cb_func;
    return CM_SUCCESS;
}

status_t elc_stream_change_leader_notify(uint32 stream_id, uint32 leader_id)
{
    dcf_role_t role = g_stream_list[stream_id].node_role;
    uint32 node_id = md_get_cur_node();

    LOG_DEBUG_INF("[ELC]elc stream change leader, stream_id=%u local_node_id=%u new_leader=%u ",
        stream_id, node_id, leader_id);
    add_notify_item(stream_id, node_id, leader_id, role, role);
    return CM_SUCCESS;
}

status_t elc_stream_refresh_hb_time(uint32 stream_id, uint64 leader_term, int32 leader_work_mode,
    uint32 leader_id)
{
    uint32 curr_node_id = elc_stream_get_current_node();
    uint64 current_term = elc_stream_get_current_term(stream_id);
    int32 work_mode = (int32)elc_stream_get_work_mode(stream_id);
    if (leader_term < current_term && leader_work_mode == work_mode) {
        LOG_DEBUG_INF("[ELC]leader's term less than current node, "
            "leader_id=%u, leader_term=%llu, current_id=%u, current_term=%llu",
            leader_id, leader_term, curr_node_id, current_term);
        return CM_SUCCESS;
    }

    if (elc_stream_get_votefor(stream_id) != leader_id) {
        LOG_RUN_INF("[ELC]receive new leader's heartbeat, stream_id=%u, node_id=%u, leader_id=%u",
            stream_id, curr_node_id, leader_id);
        dcf_role_t role = elc_stream_get_role(stream_id);
        if (role == DCF_ROLE_CANDIDATE || role == DCF_ROLE_PRE_CANDIDATE || role == DCF_ROLE_LEADER) {
            CM_RETURN_IFERR(elc_stream_set_role(stream_id, DCF_ROLE_FOLLOWER));
        }
        CM_RETURN_IFERR(elc_stream_set_votefor(stream_id, leader_id));
        LOG_DEBUG_INF("[ELC]Set votefor when refresh hb time, stream_id=%u, votefor=%u", stream_id, leader_id);
        CM_RETURN_IFERR(elc_stream_set_term(stream_id, leader_term));
    } else if (leader_term > current_term) {
        CM_RETURN_IFERR(elc_stream_set_term(stream_id, leader_term));
    }

    if (g_stream_list[stream_id].votefor_id != g_stream_list[stream_id].old_leader_id) {
        CM_RETURN_IFERR(elc_stream_change_leader_notify(stream_id, g_stream_list[stream_id].votefor_id));
        g_stream_list[stream_id].old_leader_id = g_stream_list[stream_id].votefor_id;
    }

    LOG_DEBUG_INF("[ELC]refresh heartbeat, leader_term=%llu, leader_id=%u, current_term=%llu, current_id=%u",
        leader_term, leader_id, current_term, curr_node_id);
    CM_RETURN_IFERR(elc_stream_set_timeout(stream_id, cm_clock_now()));
    return CM_SUCCESS;
}

status_t elc_stream_refresh_hb_ack_time(uint32 stream_id, uint64 leader_term, uint32 node_id)
{
    uint32 curr_node_id = elc_stream_get_current_node();
    uint64 current_term = elc_stream_get_current_term(stream_id);
    if (leader_term != current_term) {
        LOG_DEBUG_INF("[ELC]invalid term, "
            "node_id=%u, leader_term=%llu, current_node_id=%u, current_term=%llu",
            node_id, leader_term, curr_node_id, current_term);
        return CM_SUCCESS;
    }

    CM_RETURN_IFERR(elc_stream_set_hb_ack_time(stream_id, node_id, cm_clock_now()));

    return CM_SUCCESS;
}

status_t elc_stream_set_work_mode(uint32 stream_id, dcf_work_mode_t work_mode, uint32 vote_num)
{
    uint32 count;
    uint32 node_id = md_get_cur_node();
    if (work_mode == WM_MINORITY) {
        CM_RETURN_IFERR(md_get_voter_num(stream_id, &count));
        if (vote_num == 0 || vote_num > count) {
            LOG_RUN_ERR("invalid vote_num:%u", vote_num);
            return CM_ERROR;
        }
        g_stream_list[stream_id].vote_num = vote_num;
        g_stream_list[stream_id].vote_node_work_mode[node_id] = g_stream_list[stream_id].work_mode;
        g_stream_list[stream_id].work_mode = work_mode;
    } else if (work_mode == WM_NORMAL) {
        g_stream_list[stream_id].vote_num = 0;
        g_stream_list[stream_id].vote_node_work_mode[node_id] = g_stream_list[stream_id].work_mode;
        g_stream_list[stream_id].work_mode = work_mode;
    } else {
        LOG_RUN_ERR("invalid work_mode:%d", work_mode);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

dcf_work_mode_t elc_stream_get_work_mode(uint32 stream_id)
{
    return g_stream_list[stream_id].work_mode;
}

status_t elc_stream_set_vote_node_work_mode(uint32 stream_id, uint32 node_id, dcf_work_mode_t work_mode)
{
    g_stream_list[stream_id].vote_node_work_mode[node_id] = work_mode;
    return CM_SUCCESS;
}

dcf_work_mode_t elc_stream_get_vote_node_work_mode(uint32 stream_id, uint32 node_id)
{
    return g_stream_list[stream_id].vote_node_work_mode[node_id];
}

timespec_t elc_stream_get_last_md_rep_time(uint32 stream_id)
{
    return g_stream_list[stream_id].last_md_rep_time;
}

status_t elc_get_voting_weight(uint32 stream_id, uint32 node_id, uint32 *voting_weight)
{
    if (elc_stream_get_work_mode(stream_id) == WM_MINORITY) {
        *voting_weight = CM_ELC_NORS_WEIGHT;
    } else {
        CM_RETURN_IFERR(md_get_stream_node_weight(stream_id, node_id, voting_weight));
    }
    return CM_SUCCESS;
}

status_t elc_stream_set_last_md_rep_time(uint32 stream_id, timespec_t time)
{
    g_stream_list[stream_id].last_md_rep_time = time;
    return CM_SUCCESS;
}

bool32 elc_stream_is_force_vote(uint32 stream_id)
{
    return g_stream_list[stream_id].force_vote;
}

void elc_stream_set_force_vote_flag(uint32 stream_id, bool32 is_force)
{
    g_stream_list[stream_id].force_vote = is_force;
}

bool32 elc_stream_get_inter_promote_flag(uint32 stream_id)
{
    return g_stream_list[stream_id].inter_promote_flag;
}

void elc_stream_set_inter_promote_flag(uint32 stream_id, bool32 flag)
{
    g_stream_list[stream_id].inter_promote_flag = flag;
}

timespec_t elc_stream_get_leader_start_time(uint32 stream_id)
{
    return g_stream_list[stream_id].leader_start_time;
}

void elc_stream_set_leader_start_time(uint32 stream_id, timespec_t time)
{
    g_stream_list[stream_id].leader_start_time = time;
}

bool32 elc_stream_can_switch_now(uint32 stream_id)
{
    timespec_t leader_start = g_stream_list[stream_id].leader_start_time;
    timespec_t now = cm_clock_now();
    uint64 interval = (now < leader_start) ? 0 : (uint64)(now - leader_start);
    LOG_DEBUG_INF("[ELC]elc_switch_thresold now=%llu, leader_start=%llu, interval=%llu", now, leader_start, interval);
    if (interval / MICROSECS_PER_SECOND >= elc_stream_get_elc_switch_thd_sec()) {
        return CM_TRUE;
    }
    return CM_FALSE;
}

void elc_stream_set_leader_group(uint32 stream_id, uint32 leader_group)
{
    g_stream_list[stream_id].leader_group = leader_group;
}

uint32 elc_stream_get_leader_group(uint32 stream_id)
{
    return g_stream_list[stream_id].leader_group;
}

void elc_stream_set_my_group(uint32 stream_id, uint32 my_group)
{
    g_stream_list[stream_id].my_group = my_group;
}

uint32 elc_stream_get_my_group(uint32 stream_id)
{
    return g_stream_list[stream_id].my_group;
}

void elc_stream_set_priority(uint32 stream_id, uint64 priority)
{
    g_stream_list[stream_id].priority = priority;
}

uint64 elc_stream_get_priority(uint32 stream_id)
{
    return g_stream_list[stream_id].priority;
}

#ifdef __cplusplus
}
#endif
