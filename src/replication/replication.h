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
 * replication.h
 *    replication's interface
 *
 * IDENTIFICATION
 *    src/replication/replication.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __REPLICATION_H__
#define __REPLICATION_H__

#include "cm_types.h"
#include "stg_manager.h"
#include "dcf_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t rep_init();

void rep_stop();

// called by client
status_t rep_write(uint32 stream_id, const char* buffer, uint32 length, uint64 key,
    entry_type_t type, uint64* out_index);

// called by storage when log is accepted
void rep_accepted_trigger(uint32 stream_id, uint64 term, uint64 index, int err_code, entry_type_t type);

// called by election when try promote higher-priority leader
void rep_try_promote_prio_leader(uint32 stream_id, uint32 prio_leader);

// called by election when current node becames leader
status_t rep_role_notify(uint32 stream_id, dcf_role_t old_role, dcf_role_t new_role);

// get current node's commit index
uint64 rep_get_commit_index(uint32 stream_id);

// get current node's data log commit index
uint64 rep_get_data_commit_index(uint32 stream_id);

// get current node's last log index
uint64 rep_get_last_index(uint32 stream_id);

// get leader node's last log index
uint64 rep_get_leader_last_index(uint32 stream_id);

uint64 rep_get_cluster_min_apply_idx(uint32 stream_id);

int rep_register_after_writer(entry_type_t type, usr_cb_after_writer_t cb_func);

int rep_register_consensus_notify(entry_type_t type, usr_cb_consensus_notify_t cb_func);

uint64 rep_follower_get_leader_last_idx(uint32 stream_id);

status_t set_node_status(uint32 stream_id, node_status_t status, uint32 block_time_ms);
void clear_node_block_status(uint32 stream_id);

void rep_set_pause_time(uint32 stream_id, uint32 node_id, uint32 pause_time);
uint32 rep_get_pause_time(uint32 stream_id, uint32 node_id);


#ifdef __cplusplus
}
#endif

#endif
