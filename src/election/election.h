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
 * election.h
 *    election process
 *
 * IDENTIFICATION
 *    src/election/election.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __ELECTION_H__
#define __ELECTION_H__

#include "cm_types.h"
#include "cm_defs.h"
#include "metadata.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t elc_init();
void elc_deinit();

uint64 elc_get_current_term(uint32 stream_id);

// called by replication at leader node, when term is less than currentTerm,
// 1.Status Change, 2.Status notification and call rep_leader_init
status_t elc_judge_term(uint32 stream_id, uint64 term);

dcf_role_t elc_get_node_role(uint32 stream_id);
status_t elc_get_current_term_and_role(uint32 stream_id, uint64 *term, dcf_role_t *role);
void elc_set_my_priority(uint32 stream_id, uint64 priority);
uint64 elc_get_my_priority(uint32 stream_id);
uint32 elc_get_my_group(uint32 stream_id);

status_t elc_update_node_role(uint32 stream_id);
status_t elc_update_node_group(uint32 stream_id);
status_t elc_update_node_priority(uint32 stream_id);

uint32 elc_get_votefor(uint32 stream_id);

uint32 elc_get_old_leader(uint32 stream_id);
status_t elc_demote_follower(uint32 stream_id);

status_t elc_promote_leader(uint32 stream_id, uint32 node_id);

status_t elc_set_work_mode(uint32 stream_id, dcf_work_mode_t work_mode, uint32 vote_num);
dcf_work_mode_t elc_get_work_mode(uint32 stream_id);
status_t elc_get_quorum(uint32 stream_id, uint32* quorum);
status_t elc_set_hb_timeout(uint32 stream_id, timespec_t time);
status_t elc_set_hb_ack_timeout(uint32 stream_id, uint32 node_id, timespec_t time);

#define I_AM_LEADER(stream_id) (elc_get_node_role(stream_id) == DCF_ROLE_LEADER)
#define I_AM_FOLLOWER(stream_id) \
    (elc_get_node_role(stream_id) == DCF_ROLE_FOLLOWER || \
     elc_get_node_role(stream_id) == DCF_ROLE_PASSIVE || \
     elc_get_node_role(stream_id) == DCF_ROLE_LOGGER)

status_t elc_is_voter(uint32 stream_id, uint32 node_id, bool32* is_voter);
bool32 elc_is_notify_thread_closed();
status_t elc_node_is_healthy(uint32 stream_id, dcf_role_t* node_role, unsigned int* is_healthy);
status_t elc_node_voting_weight(uint32 stream_id, uint32 node_id, uint32* voting_weight);

#ifdef __cplusplus
}
#endif

#endif
