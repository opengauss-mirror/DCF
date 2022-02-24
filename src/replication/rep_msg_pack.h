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
 * rep_msg_pack.h
 *    message encode & decode
 *
 * IDENTIFICATION
 *    src/replication/rep_msg_pack.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __REP_MSG_PACK_H__
#define __REP_MSG_PACK_H__

#include "cm_types.h"
#include "stg_manager.h"
#include "mec.h"

#define REP_MSG_VER 1

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_log_info_t {
    uint64       key;
    log_id_t     log_id;
    char*        buf;
    uint32       size;
    entry_type_t type;
}rep_log_t;

typedef struct st_rep_head_t {
    uint64  req_seq;
    uint64  ack_seq;
    uint64  trace_key;
    uint64  msg_ver;
}rep_head_t;

typedef struct st_apendlog_req {
    rep_head_t  head;
    uint64      leader_term;
    uint32      leader_node_id;
    log_id_t    pre_log;
    log_id_t    leader_commit_log;
    log_id_t    leader_first_log;
    uint64      cluster_min_apply_id;
    uint64      leader_last_index;
    uint64      log_count;
}rep_apendlog_req_t;

typedef struct st_apendlog_ack {
    rep_head_t  head;
    uint64      follower_term;
    errno_t     ret_code;
    log_id_t    pre_log;
    log_id_t    mismatch_log;
    log_id_t    follower_accept_log;
    uint64      apply_id;
}rep_apendlog_ack_t;

status_t rep_encode_appendlog_head(mec_message_t* pack, const rep_apendlog_req_t* appendlog);
status_t rep_decode_appendlog_head(mec_message_t* pack, rep_apendlog_req_t* appendlog);
status_t rep_encode_one_log(mec_message_t* pack, uint32 pos, uint64 log_cnt, const log_entry_t* entry);
status_t rep_decode_one_log(mec_message_t* pack, rep_log_t* log);
status_t rep_encode_appendlog_ack(mec_message_t* pack, const rep_apendlog_ack_t* appendlog_ack);
status_t rep_decode_appendlog_ack(mec_message_t* pack, rep_apendlog_ack_t* appendlog_ack);

#define REP_APPEND_REQ_FMT "scn=%u,req_seq=%llu,ack_seq=%llu,src_node=%u,dest_node=%u," \
        "leader=%u,leader_term=%llu,leader_last_index=%llu,pre_log=(%llu,%llu)," \
        "leader_commit_log=(%llu,%llu),cluster_min_apply_id=%llu,log_count=%llu,log_begin=%llu"
#define REP_APPEND_REQ_VAL(pack, req, begin) (pack)->head->serial_no, (req)->head.req_seq, (req)->head.ack_seq, \
    (pack)->head->src_inst, (pack)->head->dst_inst, (req)->leader_node_id, (req)->leader_term, \
    (req)->leader_last_index, (req)->pre_log.term, (req)->pre_log.index, (req)->leader_commit_log.term, \
    (req)->leader_commit_log.index, (req)->cluster_min_apply_id, \
    (req)->log_count, ((req)->log_count > 0 ? (begin) : 0)

#define REP_APPEND_ACK_FMT "scn=%u,req_seq=%llu,ack_seq=%llu,src_node=%u,dest_node=%u,follower_term=%llu," \
        "ret_code=%d,pre_log=(%llu,%llu),mismatch_log=(%llu,%llu),follower_accept_log=(%llu,%llu)," \
        "apply_id=%llu"
#define REP_APPEND_ACK_VAL(pack, ack) (pack)->head->serial_no, (ack)->head.req_seq, (ack)->head.ack_seq, \
    (pack)->head->src_inst, (pack)->head->dst_inst, (ack)->follower_term, (ack)->ret_code, \
    (ack)->pre_log.term, (ack)->pre_log.index, (ack)->mismatch_log.term, (ack)->mismatch_log.index, \
    (ack)->follower_accept_log.term, (ack)->follower_accept_log.index, (ack)->apply_id

#ifdef __cplusplus
}
#endif

#endif
