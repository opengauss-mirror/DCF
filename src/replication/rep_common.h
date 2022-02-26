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
 * rep_common.h
 *    common  process
 *
 * IDENTIFICATION
 *    src/replication/rep_common.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __REP_COMMON_H__
#define __REP_COMMON_H__

#include "cm_date.h"
#include "election.h"
#include "stg_manager.h"
#include "cm_timer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CHECK_IF_LOGGER_PROC(stream_id, applied_index, commit_index)                             \
    do {                                                                                         \
        dcf_node_t _node_info_;                                                                  \
        CM_RETURN_IFERR(md_get_stream_node_ext(stream_id, md_get_cur_node(), &_node_info_));     \
        dcf_role_t _default_role_ = _node_info_.default_role;                                    \
        if (SECUREC_UNLIKELY(_default_role_ == DCF_ROLE_LOGGER)) {                               \
            if ((commit_index) > (applied_index)) {                                              \
                CM_RETURN_IFERR(stg_set_applied_index(stream_id, commit_index));                 \
                ps_record1(PS_BEING_APPLY, commit_index);                                        \
                ps_record1(PS_END_APPLY, commit_index);                                          \
                return stg_truncate_prefix(stream_id, rep_get_cluster_min_apply_idx(stream_id)); \
            }                                                                                    \
            return CM_SUCCESS;                                                                   \
        }                                                                                        \
    } while (0)


typedef int(*usr_cb_after_commit_t)(unsigned int stream_id, unsigned long long index, int error_no);
int rep_register_after_commit(entry_type_t type, usr_cb_after_commit_t cb_func);

status_t    rep_common_init();
void        rep_common_deinit();
log_id_t    rep_get_commit_log(uint32 stream_id);
void        rep_set_commit_log(uint32 stream_id, uint64 term, uint64 index);
void        rep_set_commit_log1(uint32 stream_id, log_id_t log_id);
void        rep_set_accept_flag(uint32 stream_id);
void        rep_set_can_write_flag(uint32 stream_id, uint32 flag);
uint32      rep_get_can_write_flag(uint32 stream_id);
log_id_t    rep_get_pre_term_log(uint32 stream_id, uint64 index);
void        rep_apply_trigger();
void        rep_set_cluster_min_apply_idx(uint32 stream_id, uint64 cluster_min_apply_id);
uint64      rep_get_cluster_min_apply_idx(uint32 stream_id);
log_id_t    rep_leader_get_match_index(uint32 stream_id, uint32 node_id);
uint64      rep_leader_get_next_index(uint32 stream_id, uint32 node_id);
uint64      rep_leader_get_apply_index(uint32 stream_id, uint32 node_id);
uint64      rep_get_tracekey();
void        rep_save_tracekey(uint64 tracekey);

#ifdef __cplusplus
}
#endif

#endif