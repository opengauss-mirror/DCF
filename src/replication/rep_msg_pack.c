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

status_t rep_encode_appendlog_req(mec_message_t* pack, rep_apendlog_req_t* appendlog)
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
    for (uint64 i = 0; i < appendlog->log_count; i++) {
        CM_RETURN_IFERR(mec_put_int64(pack, appendlog->logs[i].log_id.term));   // append log
        CM_RETURN_IFERR(mec_put_int64(pack, appendlog->logs[i].log_id.index));  // append log
        CM_RETURN_IFERR(mec_put_bin(pack, appendlog->logs[i].size, appendlog->logs[i].buf));
        CM_RETURN_IFERR(mec_put_int32(pack, appendlog->logs[i].type));
        CM_ASSERT(appendlog->logs[i].type >= 0 && appendlog->logs[i].type < ENTRY_TYPE_CELL);
        CM_RETURN_IFERR(mec_put_int64(pack, appendlog->logs[i].key));
        LOG_TRACE(appendlog->logs[i].log_id.index, "encode package.");
    }

    return CM_SUCCESS;
}

status_t rep_decode_appendlog_req(mec_message_t* pack, rep_apendlog_req_t* appendlog)
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
    for (uint64 i = 0; i < appendlog->log_count; i++) {
        CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&appendlog->logs[i].log_id.term));  // append log
        CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&appendlog->logs[i].log_id.index)); // append log
        CM_RETURN_IFERR(mec_get_bin(pack, &appendlog->logs[i].size, (void**)&appendlog->logs[i].buf));
        CM_RETURN_IFERR(mec_get_int32(pack, (int32*)&appendlog->logs[i].type));
        if (appendlog->logs[i].type < 0 || appendlog->logs[i].type >= ENTRY_TYPE_CELL) {
            LOG_RUN_ERR("[REP]decode logs[%llu]'s type[%d] error.", i, appendlog->logs[i].type);
            return CM_ERROR;
        }
        CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&appendlog->logs[i].key));
        LOG_TRACE(appendlog->logs[i].log_id.index, "decode package.");
    }

    return CM_SUCCESS;
}

status_t rep_encode_appendlog_ack(mec_message_t* pack, rep_apendlog_ack_t* appendlog_ack)
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

