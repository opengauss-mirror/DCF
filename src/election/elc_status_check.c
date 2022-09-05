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
 * elc_status_check.c
 *    election status check
 *
 * IDENTIFICATION
 *    src/election/elc_status_check.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_timer.h"
#include "mec.h"
#include "metadata.h"
#include "stg_manager.h"
#include "rep_msg_pack.h"
#include "elc_stream.h"
#include "elc_status_check.h"

#ifdef __cplusplus
extern "C" {
#endif

static elc_status_check_t g_status_check[CM_MAX_STREAM_COUNT];

static void elc_status_check_lock_s(uint32 stream_id)
{
    cm_latch_s(&g_status_check[stream_id].latch, 0, CM_FALSE, NULL);
}

static void elc_status_check_lock_x(uint32 stream_id)
{
    cm_latch_x(&g_status_check[stream_id].latch, 0, NULL);
}

static void elc_status_check_unlock(uint32 stream_id)
{
    cm_unlatch(&g_status_check[stream_id].latch, NULL);
}

// Whether the current node is in the majority
bool32 elc_is_in_majority(uint32 stream_id)
{
    uint32 quorum;
    if (elc_stream_get_quorum(stream_id, &quorum) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[ELC]in_check_major: get quorum failed, stream_id=%u,", stream_id);
        return CM_FALSE;
    }

    uint32 node_count;
    uint32 nodes[CM_MAX_NODE_COUNT];
    if (md_get_stream_nodes(stream_id, nodes, &node_count) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[ELC]in_check_major: get nodes failed, stream_id=%u,", stream_id);
        return CM_FALSE;
    }

    elc_status_check_t *status_check = &g_status_check[stream_id];
    uint32 cur_node = md_get_cur_node();
    uint32 rcv_voter_num = 0;
    uint32 elc_timeout_us = elc_stream_get_elc_timeout_ms() * MICROSECS_PER_MILLISEC;
    timespec_t now = cm_clock_now();
    elc_status_check_lock_s(stream_id);
    for (uint32 i = 0; i < node_count; i++) {
        uint32 id = nodes[i];
        if (id == cur_node) {
            continue;
        }
        LOG_DEBUG_INF("[ELC]check_major:node=%u,role=%u,priority=%llu,is_in_major=%u,is_future_hb=%u,last_recv=%llu",
            id, status_check->info[id].role, status_check->info[id].priority, status_check->info[id].is_in_majority,
            status_check->info[id].is_future_hb, status_check->info[id].last_recv_time);
        timespec_t last_time = status_check->info[id].last_recv_time;
        if (status_check->info[id].role != DCF_ROLE_PASSIVE &&
            (now < last_time || now - last_time < elc_timeout_us)) {
            uint32 weight = CM_ELC_NORS_WEIGHT;
            (void)elc_get_voting_weight(stream_id, id, &weight);
            rcv_voter_num += weight;
        }
    }
    elc_status_check_unlock(stream_id);

    dcf_role_t role = elc_stream_get_role(stream_id);
    uint32 self_weight = CM_ELC_NORS_WEIGHT;
    (void)elc_get_voting_weight(stream_id, cur_node, &self_weight);
    bool32 ret = (role != DCF_ROLE_PASSIVE && (rcv_voter_num + self_weight) >= quorum) ? CM_TRUE : CM_FALSE;
    LOG_DEBUG_INF("[ELC]check_major:cur_node=%u,role=%u,rcv_voter_num=%u,quorum=%u,is_in_major=%u",
        cur_node, role, rcv_voter_num, quorum, ret);
    return ret;
}

// node_id of recv node in majority and with best (group,priority).
uint32 elc_get_rcv_best_priority_node(uint32 stream_id)
{
    uint32 ret = CM_INVALID_NODE_ID;
    uint32 node_count;
    uint32 nodes[CM_MAX_NODE_COUNT];
    if (md_get_stream_nodes(stream_id, nodes, &node_count) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[ELC]check_max_prio: get nodes failed, stream_id=%u,", stream_id);
        return ret;
    }

    elc_stream_lock_s(stream_id);
    uint32 leader_group = elc_stream_get_leader_group(stream_id);
    uint32 my_group = elc_stream_get_my_group(stream_id);
    uint64 my_prio = elc_stream_get_priority(stream_id);
    elc_stream_unlock(stream_id);
    uint32 best_group = my_group;
    uint64 best_prio = my_prio;

    elc_status_check_t *status_check = &g_status_check[stream_id];
    uint32 cur_node = md_get_cur_node();
    uint32 elc_timeout_us = elc_stream_get_elc_timeout_ms() * MICROSECS_PER_MILLISEC;
    timespec_t now = cm_clock_now();
    elc_status_check_lock_s(stream_id);
    for (uint32 i = 0; i < node_count; i++) {
        uint32 id = nodes[i];
        if (id == cur_node || status_check->info[id].role == DCF_ROLE_UNKNOWN ||
            status_check->info[id].role == DCF_ROLE_LOGGER || status_check->info[id].role == DCF_ROLE_PASSIVE) {
            continue;
        }
        LOG_RUN_INF("[ELC]best_prio:node=%u,role=%u,group=%u,prio=%llu,in_major=%u,is_future_hb=%u,last_recv=%llu",
            id, status_check->info[id].role, status_check->info[id].group, status_check->info[id].priority,
            status_check->info[id].is_in_majority, status_check->info[id].is_future_hb,
            status_check->info[id].last_recv_time);
        timespec_t last_time = status_check->info[id].last_recv_time;
        if ((now < last_time || now - last_time < elc_timeout_us) && status_check->info[id].is_future_hb == CM_FALSE
            && status_check->info[id].is_in_majority == CM_TRUE) {
            if (best_group != leader_group &&
                (status_check->info[id].group == leader_group || status_check->info[id].priority > best_prio)) {
                best_group = status_check->info[id].group;
                best_prio = status_check->info[id].priority;
                ret = id;
            }
            if (best_group == status_check->info[id].group && status_check->info[id].priority > best_prio) {
                best_prio = status_check->info[id].priority;
                ret = id;
            }
        }
    }
    elc_status_check_unlock(stream_id);

    LOG_RUN_INF("[ELC]best_prio:cur_node=%u,my_group=%u,my_prio=%llu,leader_group=%u,best_group=%u,best_prio=%llu,"
        "rcv_best_priority_node=%u", cur_node, my_group, my_prio, leader_group, best_group, best_prio, ret);
    return ret;
}

void elc_save_status_check_info(uint32 stream_id, uint32 src_node, const rcv_node_info_t *rcv_info)
{
    elc_status_check_lock_x(stream_id);
    g_status_check[stream_id].info[src_node] = *rcv_info;
    elc_status_check_unlock(stream_id);
}

status_t elc_status_check_init()
{
    if (memset_sp(g_status_check, sizeof(elc_status_check_t) * CM_MAX_STREAM_COUNT, 0,
                  sizeof(elc_status_check_t) * CM_MAX_STREAM_COUNT) != EOK) {
        LOG_RUN_ERR("[ELC]election status check init mem failed.");
        return CM_ERROR;
    }

    uint32 stream_list[CM_MAX_STREAM_COUNT];
    uint32 stream_count;
    CM_RETURN_IFERR(md_get_stream_list(stream_list, &stream_count));
    for (uint32 i = 0; i < stream_count; i++) {
        uint32 stream_id = stream_list[i];
        cm_latch_init(&g_status_check[stream_id].latch);
    }

    LOG_RUN_INF("[ELC]elc_status_check_init ok.");
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
