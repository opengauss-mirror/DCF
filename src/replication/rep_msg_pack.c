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
 * rep_msg_pack.c
 *    message encode & decode
 *
 * IDENTIFICATION
 *    src/replication/rep_msg_pack.c
 *
 * -------------------------------------------------------------------------
 */

#include "rep_msg_pack.h"

status_t rep_encode_appendlog_head(mec_message_t* pack, const rep_apendlog_req_t* appendlog)
{
    CM_RETURN_IFERR(mec_put_int64(pack, appendlog->head.req_seq));
    CM_RETURN_IFERR(mec_put_int64(pack, appendlog->head.ack_seq));
    CM_RETURN_IFERR(mec_put_int64(pack, appendlog->head.trace_key));
    CM_RETURN_IFERR(mec_put_int64(pack, appendlog->leader_term));               // leader term
    CM_RETURN_IFERR(mec_put_int32(pack, appendlog->leader_node_id));            // leader node
    CM_RETURN_IFERR(mec_put_int64(pack, appendlog->leader_last_index));         // leader term
    CM_RETURN_IFERR(mec_put_int64(pack, appendlog->leader_commit_log.term));    // leader committed log
    CM_RETURN_IFERR(mec_put_int64(pack, appendlog->leader_commit_log.index));   // leader committed log
    CM_RETURN_IFERR(mec_put_int64(pack, appendlog->leader_first_log.term));     // leader disk first log
    CM_RETURN_IFERR(mec_put_int64(pack, appendlog->leader_first_log.index));    // leader disk first log
    CM_RETURN_IFERR(mec_put_int64(pack, appendlog->pre_log.term));              // pre log
    CM_RETURN_IFERR(mec_put_int64(pack, appendlog->pre_log.index));             // pre log
    CM_RETURN_IFERR(mec_put_int64(pack, appendlog->cluster_min_apply_id));
    CM_RETURN_IFERR(mec_put_int64(pack, appendlog->log_count));                 // append log count
    return CM_SUCCESS;
}

status_t rep_decode_appendlog_head(mec_message_t* pack, rep_apendlog_req_t* appendlog)
{
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&appendlog->head.req_seq));
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&appendlog->head.ack_seq));
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&appendlog->head.trace_key));
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&appendlog->leader_term));              // leader term
    CM_RETURN_IFERR(mec_get_int32(pack, (int32*)&appendlog->leader_node_id));           // leader node
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&appendlog->leader_last_index));        // leader last index
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&appendlog->leader_commit_log.term));   // leader committed log
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&appendlog->leader_commit_log.index));  // leader committed log
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&appendlog->leader_first_log.term));    // leader disk first log
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&appendlog->leader_first_log.index));   // leader disk first log
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&appendlog->pre_log.term));             // pre log
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&appendlog->pre_log.index));            // pre log
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&appendlog->cluster_min_apply_id));
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&appendlog->log_count));                // append log count
    return CM_SUCCESS;
}

status_t rep_encode_one_log(mec_message_t* pack, uint32 pos, uint64 log_cnt, const log_entry_t* entry)
{
    mec_modify_int64(pack, pos, log_cnt);
    CM_RETURN_IFERR(mec_put_int64(pack, ENTRY_TERM(entry)));
    uint64 index = ENTRY_INDEX(entry);
    CM_RETURN_IFERR(mec_put_int64(pack, index));
    CM_RETURN_IFERR(mec_put_bin(pack, ENTRY_SIZE(entry), ENTRY_BUF(entry)));
    CM_RETURN_IFERR(mec_put_int32(pack, ENTRY_TYPE(entry)));
    CM_RETURN_IFERR(mec_put_int64(pack, ENTRY_KEY(entry)));
    LOG_TRACE(index, "encode package.");
    return CM_SUCCESS;
}

status_t rep_decode_one_log(mec_message_t* pack, rep_log_t* log)
{
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&log->log_id.term));
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&log->log_id.index));
    CM_RETURN_IFERR(mec_get_bin(pack, &log->size, (void**)&log->buf));
    CM_RETURN_IFERR(mec_get_int32(pack, (int32*)&log->type));
    if (log->type < 0 || log->type >= ENTRY_TYPE_CELL) {
        LOG_RUN_ERR("[ELC]decode log type[%d] error.", log->type);
        return CM_ERROR;
    }
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&log->key));
    LOG_TRACE(log->log_id.index, "decode package.");
    return CM_SUCCESS;
}

status_t rep_encode_appendlog_ack(mec_message_t* pack, const rep_apendlog_ack_t* appendlog_ack)
{
    CM_RETURN_IFERR(mec_put_int64(pack, appendlog_ack->head.req_seq));
    CM_RETURN_IFERR(mec_put_int64(pack, appendlog_ack->head.ack_seq));
    CM_RETURN_IFERR(mec_put_int64(pack, appendlog_ack->follower_term));             // follower's current term
    CM_RETURN_IFERR(mec_put_int32(pack, appendlog_ack->ret_code));                  // return code
    CM_RETURN_IFERR(mec_put_int64(pack, appendlog_ack->pre_log.term));              // pre_log
    CM_RETURN_IFERR(mec_put_int64(pack, appendlog_ack->pre_log.index));             // pre_log
    CM_RETURN_IFERR(mec_put_int64(pack, appendlog_ack->mismatch_log.term));         // mismatch log
    CM_RETURN_IFERR(mec_put_int64(pack, appendlog_ack->mismatch_log.index));        // mismatch log
    CM_RETURN_IFERR(mec_put_int64(pack, appendlog_ack->follower_accept_log.term));  // follower last log
    CM_RETURN_IFERR(mec_put_int64(pack, appendlog_ack->follower_accept_log.index)); // follower last
    CM_RETURN_IFERR(mec_put_int64(pack, appendlog_ack->apply_id));                  // apply_id

    return CM_SUCCESS;
}

status_t rep_decode_appendlog_ack(mec_message_t* pack, rep_apendlog_ack_t* appendlog_ack)
{
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&appendlog_ack->head.req_seq));
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&appendlog_ack->head.ack_seq));
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&appendlog_ack->follower_term));              // follower's current term
    CM_RETURN_IFERR(mec_get_int32(pack, (int32*)&appendlog_ack->ret_code));                     // return code
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&appendlog_ack->pre_log.term));                 // pre_log
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&appendlog_ack->pre_log.index));                // pre_log
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&appendlog_ack->mismatch_log.term));            // mismatch log
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&appendlog_ack->mismatch_log.index));           // mismatch log
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&appendlog_ack->follower_accept_log.term));     // follower last log
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&appendlog_ack->follower_accept_log.index));    // follower last
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&appendlog_ack->apply_id));                     // apply_id

    return CM_SUCCESS;
}

