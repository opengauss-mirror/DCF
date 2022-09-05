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
 * election.c
 *    election process
 *
 * IDENTIFICATION
 *    src/election/election.c
 *
 * -------------------------------------------------------------------------
 */

#include "election.h"
#include "elc_msg_proc.h"
#include "elc_stream.h"
#include "elc_status_check.h"
#include "metadata.h"
#include "cm_thread.h"
#include "cm_utils.h"
#include "cm_timer.h"
#include "cb_func.h"
#include "util_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

thread_t g_status_check_thread;
thread_t g_status_notify_thread;
static bool32 g_elc_init = CM_FALSE;

status_t elc_judge_term(uint32 stream_id, uint64 term)
{
    if (!g_elc_init) {
        LOG_RUN_ERR("[ELC]Election module has not been initialized");
        return CM_ERROR;
    }

    if (term > elc_stream_get_current_term(stream_id)) {
        LOG_DEBUG_INF("[ELC]begin elc_judge_term");

        if (elc_stream_get_work_mode(stream_id) == WM_MINORITY) {
            LOG_DEBUG_WAR("[ELC] minority leader receive one's term larger than itself, term=%llu, cuurent_term=%llu",
                term, elc_stream_get_current_term(stream_id));
            return CM_ERROR;
        }

        elc_stream_lock_x(stream_id);
        if (term <= elc_stream_get_current_term(stream_id)) {
            elc_stream_unlock(stream_id);
            return CM_SUCCESS;
        }
        dcf_role_t role = elc_stream_get_role(stream_id);
        if (role == DCF_ROLE_LEADER) {
            LOG_RUN_ERR("[ELC]LEADER receive one's term larger than itself, demote to FOLLOWER");
            CM_RETURN_IFERR_EX(elc_stream_set_role(stream_id, DCF_ROLE_FOLLOWER), elc_stream_unlock(stream_id));
            CM_RETURN_IFERR_EX(elc_stream_set_votefor(stream_id, CM_INVALID_NODE_ID), elc_stream_unlock(stream_id));
            LOG_DEBUG_INF("[ELC]Set votefor as invalid nodeid when elc_judge_term, cuurent_term=%llu, term=%llu",
                elc_stream_get_current_term(stream_id), term);
        } else {
            CM_RETURN_IFERR_EX(elc_stream_set_term(stream_id, term), elc_stream_unlock(stream_id));
        }
        elc_stream_unlock(stream_id);
        LOG_DEBUG_INF("[ELC]end elc_judge_term");
    }
    return CM_SUCCESS;
}

status_t check_timeout_proc(uint32 stream_id, uint32 node_id, timespec_t now)
{
    dcf_role_t role = elc_stream_get_role(stream_id);
    status_t ret = CM_SUCCESS;
    switch (role) {
        case DCF_ROLE_FOLLOWER:
            if (!elc_stream_can_switch_now(stream_id)) {
                LOG_DEBUG_INF("[ELC]elc_switch_thresold is not reached, stream_id=%u, node_id=%u", stream_id, node_id);
                break;
            }
            LOG_RUN_WAR("[ELC]heartbeat timeout, begin voting, stream_id=%u, node_id=%u", stream_id, node_id);
            ret = elc_stream_set_timeout(stream_id, now);
            if (ret != CM_SUCCESS) {
                break;
            }
            ret = elc_stream_set_role(stream_id, DCF_ROLE_PRE_CANDIDATE);
            if (ret != CM_SUCCESS) {
                break;
            }
            uint32 vote_flag = VOTE_FLAG_PRE_VOTE;
            ret = elc_vote_req(stream_id, vote_flag);
            break;
        case DCF_ROLE_CANDIDATE:
        case DCF_ROLE_PRE_CANDIDATE:
            LOG_RUN_INF("[ELC]election timeout, become follower, stream_id=%u, node_id=%u", stream_id, node_id);
            ret = elc_stream_set_role(stream_id, DCF_ROLE_FOLLOWER);
            if (ret != CM_SUCCESS) {
                break;
            }
            ret = elc_stream_set_votefor(stream_id, CM_INVALID_NODE_ID);
            LOG_DEBUG_INF("[ELC]Set votefor as invalid nodeid when election timeout, stream_id=%u", stream_id);
            if (ret != CM_SUCCESS) {
                break;
            }
            (void)elc_stream_set_timeout(stream_id, now);
            break;
        default:
            break;
    }
    return ret;
}

status_t check_timeout(uint32 stream_id, timespec_t now, uint32 elc_timeout)
{
    elc_stream_lock_s(stream_id);
    uint32 node_id = elc_stream_get_current_node();
    timespec_t last_hb_time = elc_stream_get_timeout(stream_id);
    if (now < last_hb_time) {
        LOG_RUN_INF("no need to check timeout, now:%llu, last_hb_time:%lld", now, last_hb_time);
        elc_stream_unlock(stream_id);
        return CM_SUCCESS;
    }

    uint64 interval_time = ((uint64)(now - last_hb_time)) / MICROSECS_PER_MILLISEC;
    uint32 rand_value;
    uint32 votefor = elc_stream_get_votefor(stream_id);
    if (votefor != CM_INVALID_NODE_ID) {
        rand_value = elc_timeout + cm_random(elc_timeout) / CM_10X_FIXED;
    } else {
        rand_value = cm_random(elc_timeout);
    }
    LOG_DEBUG_INF("[ELC]votefor=%u, elc_timeout rand_value=%u", votefor, rand_value);
    if (interval_time < rand_value) {
        elc_stream_unlock(stream_id);
        return CM_SUCCESS;
    }

    dcf_role_t role = elc_stream_get_role(stream_id);
    if (role == DCF_ROLE_LEADER) {
        elc_stream_unlock(stream_id);
        return CM_SUCCESS;
    }
    param_run_mode_t run_mode = elc_stream_get_run_mode();
    if (run_mode == ELECTION_MANUAL || run_mode == ELECTION_DISABLE) {
        elc_stream_unlock(stream_id);
        LOG_RUN_WAR("[ELC]heartbeat timeout, stream_id=%u, node_id=%u", stream_id, node_id);
        return CM_SUCCESS;
    }
    elc_stream_unlock(stream_id);

    elc_stream_lock_x(stream_id);
    status_t ret = check_timeout_proc(stream_id, node_id, now);
    elc_stream_unlock(stream_id);
    return ret;
}

#define HB_SLEEP_TIME 100
void elc_status_check_entry(thread_t *thread)
{
    (void)cm_set_thread_name("elc_status_check");
    timespec_t last_hb = cm_clock_now();
    uint32 node_num = 0;

    while (!thread->closed) {
        uint32 hb_interval = elc_stream_get_hb_interval_ms();
        uint32 elc_timeout = elc_stream_get_elc_timeout_ms();
        timespec_t now = cm_clock_now();
        bool32 need_hb = (((uint64)(now - last_hb)) / MICROSECS_PER_MILLISEC >= hb_interval) ? CM_TRUE : CM_FALSE;

        for (uint32 i = 0; i < CM_MAX_STREAM_COUNT; i++) {
            if (!elc_stream_is_exists(i)) {
                continue;
            }

            /* 1 node mode, don't do hb */
            (void)md_get_stream_nodes_count(i, &node_num);
            if (node_num == 1) {
                continue;
            }

            if (need_hb) {
                last_hb = now;
                // send elc status info
                elc_stream_lock_s(i);
                if (elc_send_status_info(i) != CM_SUCCESS) {
                    LOG_DEBUG_ERR("[ELC]send elc status info failed, stream_id=%u.", i);
                }
                elc_stream_unlock(i);
            }

            status_t ret = CM_SUCCESS;
            if (need_hb && elc_get_node_role(i) == DCF_ROLE_LEADER) {
                last_hb = now;
                elc_stream_lock_s(i);
                if ((elc_stream_get_run_mode() == ELECTION_AUTO) && elc_need_demote_follow(i, now, CM_2X_FIXED)) {
                    elc_stream_unlock(i);
                    ret = elc_demote_follower(i); // don't recieve follow node's hb ack, demote to follower
                    LOG_RUN_INF("[ELC]elc demote follower, stream_id=%u", i);
                } else {
                    elc_stream_unlock(i);
                }
            } else {
                ret = check_timeout(i, now, elc_timeout);
            }
            if (ret != CM_SUCCESS) {
                LOG_DEBUG_ERR("[ELC]check heartbeat time failed, error_code=%d, stream_id=%u", ret, i);
            }
        }
        cm_sleep(HB_SLEEP_TIME);
    }
}

void elc_status_notify_entry(thread_t *thread)
{
    (void)cm_set_thread_name("status_notify");

    usr_cb_thread_memctx_init_t cb_memctx_init = get_dcf_worker_memctx_init_cb();
    if (cb_memctx_init != NULL) {
        cb_memctx_init();
        LOG_DEBUG_INF("[ELC]status_notify thread memctx init callback: cb_memctx_init done");
    }

    while (!thread->closed) {
        elc_stream_notify_proc();
    }
}

status_t elc_init()
{
    if (g_elc_init) {
        return CM_SUCCESS;
    }

    status_t ret = elc_stream_init();
    if (ret != CM_SUCCESS) {
        return ret;
    }

    ret = elc_status_check_init();
    if (ret != CM_SUCCESS) {
        return ret;
    }

    register_msg_process(MEC_CMD_VOTE_REQUEST_RPC_REQ, elc_vote_proc, PRIV_HIGH);
    register_msg_process(MEC_CMD_VOTE_REQUEST_RPC_ACK, elc_vote_ack_proc, PRIV_HIGH);
    register_msg_process(MEC_CMD_PROMOTE_LEADER_RPC_REQ, elc_promote_proc, PRIV_HIGH);

    register_msg_process(MEC_CMD_STATUS_CHECK_RPC_REQ, elc_status_check_req_proc, PRIV_HIGH);
    register_msg_process(MEC_CMD_STATUS_CHECK_RPC_ACK, elc_status_check_ack_proc, PRIV_HIGH);

    ret = cm_create_thread(elc_status_check_entry, 0, NULL, &g_status_check_thread);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    ret = cm_create_thread(elc_status_notify_entry, 0, NULL, &g_status_notify_thread);
    if (ret != CM_SUCCESS) {
        cm_close_thread(&g_status_check_thread);
        return ret;
    }

    g_elc_init = CM_TRUE;
    LOG_RUN_INF("[ELC]Elc init succeed");
    return CM_SUCCESS;
}

void elc_deinit()
{
    if (g_elc_init) {
        cm_close_thread(&g_status_check_thread);
        cm_close_thread(&g_status_notify_thread);

        unregister_msg_process(MEC_CMD_VOTE_REQUEST_RPC_REQ);
        unregister_msg_process(MEC_CMD_VOTE_REQUEST_RPC_ACK);
        unregister_msg_process(MEC_CMD_PROMOTE_LEADER_RPC_REQ);

        unregister_msg_process(MEC_CMD_STATUS_CHECK_RPC_REQ);
        unregister_msg_process(MEC_CMD_STATUS_CHECK_RPC_ACK);
    }
    g_elc_init = CM_FALSE;
}

uint64 elc_get_current_term(uint32 stream_id)
{
    if (!g_elc_init) {
        LOG_RUN_ERR("[ELC]election module has not been initialized");
        return CM_INVALID_TERM_ID;
    }
    elc_stream_lock_s(stream_id);
    uint64 term = elc_stream_get_current_term(stream_id);
    elc_stream_unlock(stream_id);
    return term;
}

dcf_role_t elc_get_node_role(uint32 stream_id)
{
    if (!g_elc_init) {
        LOG_RUN_ERR("[ELC]election module has not been initialized");
        return DCF_ROLE_UNKNOWN;
    }
    elc_stream_lock_s(stream_id);
    dcf_role_t role = elc_stream_get_role(stream_id);
    elc_stream_unlock(stream_id);
    return role;
}

status_t elc_get_current_term_and_role(uint32 stream_id, uint64 *term, dcf_role_t *role)
{
    if (!g_elc_init) {
        LOG_RUN_ERR("[ELC]election module has not been initialized");
        return CM_ERROR;
    }
    elc_stream_lock_s(stream_id);
    *term = elc_stream_get_current_term(stream_id);
    *role = elc_stream_get_role(stream_id);
    elc_stream_unlock(stream_id);
    LOG_DEBUG_INF("[ELC]get term and role ok. cur_term=%llu, role=%u.", *term, *role);
    return CM_SUCCESS;
}

void elc_set_my_priority(uint32 stream_id, uint64 priority)
{
    elc_stream_lock_x(stream_id);
    elc_stream_set_priority(stream_id, priority);
    elc_stream_unlock(stream_id);
    LOG_DEBUG_INF("[ELC]set my_priority=%llu ok.", priority);
}

status_t elc_reload_priority()
{
    if (!g_elc_init) {
        LOG_RUN_INF("[ELC]election not initialized, no need to reload priority.");
        return CM_SUCCESS;
    }

    uint32 stream_list[CM_MAX_STREAM_COUNT];
    uint32 stream_count;
    uint32 current_node_id = md_get_cur_node();
    CM_RETURN_IFERR(md_get_stream_list(stream_list, &stream_count));
    for (uint32 i = 0; i < stream_count; i++) {
        uint32 stream_id = stream_list[i];
        dcf_node_t node_info;
        CM_RETURN_IFERR(md_get_stream_node_ext(stream_id, current_node_id, &node_info));
        elc_set_my_priority(stream_id, node_info.priority);
    }
    return CM_SUCCESS;
}

uint64 elc_get_my_priority(uint32 stream_id)
{
    elc_stream_lock_s(stream_id);
    uint64 priority = elc_stream_get_priority(stream_id);
    elc_stream_unlock(stream_id);
    return priority;
}

uint32 elc_get_my_group(uint32 stream_id)
{
    elc_stream_lock_s(stream_id);
    uint32 group = elc_stream_get_my_group(stream_id);
    elc_stream_unlock(stream_id);
    return group;
}

status_t elc_update_node_role(uint32 stream_id)
{
    dcf_node_t node_info;
    CM_RETURN_IFERR(md_get_stream_node_ext(stream_id, md_get_cur_node(), &node_info));
    dcf_role_t default_role = node_info.default_role;

    elc_stream_lock_x(stream_id);
    dcf_role_t role = elc_stream_get_role(stream_id);
    if (default_role == DCF_ROLE_PASSIVE || role == DCF_ROLE_PASSIVE) {
        CM_RETURN_IFERR_EX(elc_stream_set_role(stream_id, default_role), elc_stream_unlock(stream_id));
    }
    elc_stream_unlock(stream_id);
    LOG_RUN_INF("[ELC]update node role ok. default_role=%u, role=%u.", default_role, role);
    return CM_SUCCESS;
}

status_t elc_update_node_group(uint32 stream_id)
{
    dcf_node_t node_info;
    CM_RETURN_IFERR(md_get_stream_node_ext(stream_id, md_get_cur_node(), &node_info));
    uint32 group = node_info.group;

    elc_stream_lock_x(stream_id);
    elc_stream_set_my_group(stream_id, group);
    elc_stream_unlock(stream_id);
    LOG_RUN_INF("[ELC]update node group ok. new_group=%u.", group);
    return CM_SUCCESS;
}

status_t elc_update_node_priority(uint32 stream_id)
{
    dcf_node_t node_info;
    CM_RETURN_IFERR(md_get_stream_node_ext(stream_id, md_get_cur_node(), &node_info));
    uint64 priority = node_info.priority;

    elc_stream_lock_x(stream_id);
    elc_stream_set_priority(stream_id, priority);
    elc_stream_unlock(stream_id);
    LOG_RUN_INF("[ELC]update node priority ok. new_priority=%llu.", priority);
    return CM_SUCCESS;
}

uint32 elc_get_votefor(uint32 stream_id)
{
    if (!g_elc_init) {
        LOG_RUN_ERR("[ELC]election module has not been initialized");
        return CM_INVALID_NODE_ID;
    }
    elc_stream_lock_s(stream_id);
    uint32 votefor = elc_stream_get_votefor(stream_id);
    elc_stream_unlock(stream_id);
    return votefor;
}

uint32 elc_get_old_leader(uint32 stream_id)
{
    if (!g_elc_init) {
        LOG_RUN_ERR("[ELC]election module has not been initialized");
        return CM_INVALID_NODE_ID;
    }
    elc_stream_lock_s(stream_id);
    uint32 old_leader = elc_stream_get_old_leader(stream_id);
    elc_stream_unlock(stream_id);
    return old_leader;
}

status_t elc_demote_follower(uint32 stream_id)
{
    elc_stream_lock_x(stream_id);
    if (elc_stream_get_role(stream_id) != DCF_ROLE_LEADER) {
        elc_stream_unlock(stream_id);
        return CM_SUCCESS;
    }
    status_t ret = elc_stream_set_role(stream_id, DCF_ROLE_FOLLOWER);
    elc_stream_unlock(stream_id);
    return ret;
}

status_t elc_promote_leader(uint32 stream_id, uint32 node_id)
{
    elc_stream_lock_x(stream_id);
    status_t ret = elc_promote_req(stream_id, node_id);
    elc_stream_unlock(stream_id);
    return ret;
}

status_t elc_set_work_mode(uint32 stream_id, dcf_work_mode_t work_mode, uint32 vote_num)
{
    elc_stream_lock_x(stream_id);
    status_t ret = elc_stream_set_work_mode(stream_id, work_mode, vote_num);
    elc_stream_unlock(stream_id);
    return ret;
}

dcf_work_mode_t elc_get_work_mode(uint32 stream_id)
{
    elc_stream_lock_s(stream_id);
    dcf_work_mode_t work_mode = elc_stream_get_work_mode(stream_id);
    elc_stream_unlock(stream_id);
    return work_mode;
}

status_t elc_get_quorum(uint32 stream_id, uint32* quorum)
{
    elc_stream_lock_s(stream_id);
    status_t ret = elc_stream_get_quorum(stream_id, quorum);
    elc_stream_unlock(stream_id);
    return ret;
}

status_t elc_set_hb_timeout(uint32 stream_id, timespec_t time)
{
    elc_stream_lock_x(stream_id);
    if (elc_stream_set_timeout(stream_id, time) != CM_SUCCESS) {
        elc_stream_unlock(stream_id);
        return CM_ERROR;
    }
    elc_stream_unlock(stream_id);
    return CM_SUCCESS;
}

status_t elc_set_hb_ack_timeout(uint32 stream_id, uint32 node_id, timespec_t time)
{
    elc_stream_lock_x(stream_id);
    if (elc_stream_set_hb_ack_time(stream_id, node_id, time) != CM_SUCCESS) {
        elc_stream_unlock(stream_id);
        return CM_ERROR;
    }
    elc_stream_unlock(stream_id);
    return CM_SUCCESS;
}

status_t elc_is_voter(uint32 stream_id, uint32 node_id, bool32* is_voter)
{
    if (!g_elc_init) {
        LOG_RUN_ERR("[ELC]election module has not been initialized");
        return CM_ERROR;
    }
    *is_voter = CM_FALSE;
    CM_RETURN_IFERR(md_is_voter(stream_id, node_id, is_voter));
    if (!(*is_voter)) {
        return CM_SUCCESS;
    }
    if (node_id == md_get_cur_node()) {
        *is_voter = CM_TRUE;
        return CM_SUCCESS;
    }
    elc_stream_lock_s(stream_id);
    dcf_work_mode_t local_work_mode = elc_stream_get_work_mode(stream_id);
    dcf_work_mode_t vote_node_work_mode = elc_stream_get_vote_node_work_mode(stream_id, node_id);
    *is_voter = (local_work_mode == vote_node_work_mode);
    elc_stream_unlock(stream_id);
    return CM_SUCCESS;
}

bool32 elc_is_notify_thread_closed()
{
    return g_status_notify_thread.closed;
}

bool32 elc_node_is_active(uint32 stream_id)
{
    bool32 is_active = CM_TRUE;
    uint32 elc_timeout = elc_stream_get_elc_timeout_ms();
    timespec_t last_hb = elc_stream_get_timeout(stream_id);
    timespec_t now = cm_clock_now();
    if (((uint64)(now - last_hb)) / MICROSECS_PER_MILLISEC > elc_timeout) {
        is_active = CM_FALSE;
    }
    return is_active;
}

status_t elc_node_is_healthy(uint32 stream_id, dcf_role_t* node_role, unsigned int* is_healthy)
{
    bool32 is_need_demote;
    elc_stream_lock_s(stream_id);
    dcf_role_t role = elc_stream_get_role(stream_id);
    if (role == DCF_ROLE_LEADER) {
        timespec_t now = cm_clock_now();
        is_need_demote = elc_need_demote_follow(stream_id, now, CM_1X_FIXED);
        *is_healthy = (is_need_demote == CM_TRUE) ? CM_FALSE : CM_TRUE;
    } else {
        *is_healthy = elc_node_is_active(stream_id);
    }
    *node_role = role;
    elc_stream_unlock(stream_id);
    return CM_SUCCESS;
}

status_t elc_node_voting_weight(uint32 stream_id, uint32 node_id, uint32* voting_weight)
{
    elc_stream_lock_s(stream_id);
    status_t ret = elc_get_voting_weight(stream_id, node_id, voting_weight);
    elc_stream_unlock(stream_id);
    return ret;
}

#ifdef __cplusplus
}
#endif
