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
 * rep_leader.h
 *    leader  process
 *
 * IDENTIFICATION
 *    src/replication/rep_leader.h
 *
 * -------------------------------------------------------------------------
 */


#ifndef __REP_LEADER_H__
#define __REP_LEADER_H__

#include "cm_types.h"
#include "stg_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

// called by module startup
status_t rep_leader_init();

void     rep_leader_deinit();

// called by election when current node becames leader
status_t rep_leader_reset(uint32 stream_id);

void rep_appendlog_trigger(uint32 stream_id);

status_t rep_leader_acceptlog_proc(uint32 stream_id);

void rep_leader_acceptlog(uint32 stream_id, uint64 term, uint64 index, status_t status);

status_t rep_check_param_majority_groups();
#ifdef __cplusplus
}
#endif

#endif
