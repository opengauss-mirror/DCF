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
 * elc_stream.h
 *    election metadata
 *
 * IDENTIFICATION
 *    src/election/elc_stream.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __ELC_STREAM_H__
#define __ELC_STREAM_H__

#include "cm_types.h"
#include "metadata.h"
#include "cm_date.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_role_notify {
    latch_t latch;
    uint32 stream_id;
    uint32 node_id;
    uint32 new_leader;
    dcf_role_t old_role;
    dcf_role_t new_role;
} role_notify_t;

status_t elc_stream_init();

uint64 elc_stream_get_current_term(uint32 stream_id);
status_t elc_stream_set_term(uint32 stream_id, uint64 current_term);

dcf_role_t elc_stream_get_role(uint32 stream_id);
status_t elc_stream_set_role(uint32 stream_id, dcf_role_t role);

uint32 elc_stream_get_vote_count(uint32 stream_id);
uint32 elc_stream_get_vote_no_count(uint32 stream_id);
status_t elc_stream_increase_vote_count(uint32 stream_id);
status_t elc_stream_increase_vote_no_count(uint32 stream_id);
void elc_stream_reset_vote_count(uint32 stream_id);
date_t elc_stream_get_timeout(uint32 stream_id);
status_t elc_stream_set_timeout(uint32 stream_id, date_t date);

date_t elc_stream_get_hb_ack_time(uint32 stream_id, uint32 node_id);

status_t elc_stream_set_hb_ack_time(uint32 stream_id, uint32 node_id, date_t date);

uint32 elc_stream_get_votefor(uint32 stream_id);
status_t elc_stream_set_votefor(uint32 stream_id, uint32 votefor_id);

status_t elc_stream_vote_node_list(uint32 stream_id, uint64* inst_bits);
bool32 elc_stream_is_exists(uint32 stream_id);
uint32 elc_stream_get_current_node();

void elc_stream_lock_x(uint32 stream_id);
void elc_stream_lock_s(uint32 stream_id);
void elc_stream_unlock(uint32 stream_id);

status_t elc_register_notify(usr_cb_status_notify_t cb_func);
status_t elc_register_election_notify(usr_cb_election_notify_t cb_func);

status_t elc_stream_refresh_hb_time(uint32 stream_id, uint64 leader_term, int32 leader_work_mode,
    uint32 leader_id);
status_t elc_stream_refresh_hb_ack_time(uint32 stream_id, uint64 leader_term, uint32 node_id);

status_t elc_stream_set_work_mode(uint32 stream_id, dcf_work_mode_t work_mode, uint32 vote_num);
dcf_work_mode_t elc_stream_get_work_mode(uint32 stream_id);

status_t elc_stream_set_vote_node_work_mode(uint32 stream_id, uint32 node_id, dcf_work_mode_t work_mode);
dcf_work_mode_t elc_stream_get_vote_node_work_mode(uint32 stream_id, uint32 node_id);

uint32 elc_stream_is_win(uint32 stream_id, bool32* is_win);
status_t elc_stream_is_not_win(uint32 stream_id, bool32* is_not_win);
status_t elc_stream_get_quorum(uint32 stream_id, uint32* quorum);

uint32 elc_stream_get_elc_timeout_ms();
param_run_mode_t elc_stream_get_run_mode();
uint32 elc_stream_get_hb_interval_ms();

void elc_stream_notify_proc();
void add_notify_item(uint32 stream_id, uint32 node_id, uint32 new_leader, dcf_role_t old_role, dcf_role_t new_role);

date_t elc_stream_get_last_md_rep_time(uint32 stream_id);
status_t elc_stream_set_last_md_rep_time(uint32 stream_id, date_t date);

#ifdef __cplusplus
}
#endif

#endif
