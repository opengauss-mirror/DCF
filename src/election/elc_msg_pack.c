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
 * elc_msg_pack.c
 *    election process
 *
 * IDENTIFICATION
 *    src/election/elc_msg_pack.c
 *
 * -------------------------------------------------------------------------
 */

#include "elc_msg_pack.h"
#include "elc_status_check.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t elc_decode_vote_ack(mec_message_t* pack, elc_vote_ack_t* ack_vote)
{
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&ack_vote->term));
    CM_RETURN_IFERR(mec_get_int32(pack, (int32*)&ack_vote->vote_granted));
    CM_RETURN_IFERR(mec_get_int32(pack, (int32*)&ack_vote->work_mode));
    CM_RETURN_IFERR(mec_get_int32(pack, (int32*)&ack_vote->vote_flag));
    return CM_SUCCESS;
}

status_t elc_encode_vote_ack(mec_message_t* pack, const elc_vote_ack_t* ack_vote)
{
    CM_RETURN_IFERR(mec_put_int64(pack, ack_vote->term));
    CM_RETURN_IFERR(mec_put_int32(pack, ack_vote->vote_granted));
    CM_RETURN_IFERR(mec_put_int32(pack, ack_vote->work_mode));
    CM_RETURN_IFERR(mec_put_int32(pack, ack_vote->vote_flag));
    return CM_SUCCESS;
}

status_t elc_decode_vote_req(mec_message_t* pack, elc_vote_t* req_vote)
{
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&req_vote->candidate_term));
    CM_RETURN_IFERR(mec_get_int32(pack, (int32*)&req_vote->candidate_id));
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&req_vote->last_log.term));
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&req_vote->last_log.index));
    CM_RETURN_IFERR(mec_get_int32(pack, (int32*)&req_vote->vote_flag));
    CM_RETURN_IFERR(mec_get_int32(pack, (int32*)&req_vote->work_mode));
    return CM_SUCCESS;
}

status_t elc_encode_vote_req(mec_message_t* pack, const elc_vote_t* req_vote)
{
    CM_RETURN_IFERR(mec_put_int64(pack, req_vote->candidate_term));
    CM_RETURN_IFERR(mec_put_int32(pack, req_vote->candidate_id));
    CM_RETURN_IFERR(mec_put_int64(pack, req_vote->last_log.term));
    CM_RETURN_IFERR(mec_put_int64(pack, req_vote->last_log.index));
    CM_RETURN_IFERR(mec_put_int32(pack, req_vote->vote_flag));
    CM_RETURN_IFERR(mec_put_int32(pack, req_vote->work_mode));
    return CM_SUCCESS;
}

status_t elc_decode_hb_req(mec_message_t* pack, elc_hb_t* req_vote)
{
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&req_vote->term));
    CM_RETURN_IFERR(mec_get_int32(pack, (int32*)&req_vote->work_mode));
    CM_RETURN_IFERR(mec_get_int32(pack, (int32*)&req_vote->md_chksum));
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&req_vote->send_time));
    return CM_SUCCESS;
}

status_t elc_encode_hb_req(mec_message_t* pack, const elc_hb_t* req_vote)
{
    CM_RETURN_IFERR(mec_put_int64(pack, req_vote->term));
    CM_RETURN_IFERR(mec_put_int32(pack, req_vote->work_mode));
    CM_RETURN_IFERR(mec_put_int32(pack, req_vote->md_chksum));
    CM_RETURN_IFERR(mec_put_int64(pack, req_vote->send_time));
    return CM_SUCCESS;
}

status_t elc_encode_status_check_req(mec_message_t* pack, const rcv_node_info_t* req_status)
{
    CM_RETURN_IFERR(mec_put_int32(pack, req_status->role));
    CM_RETURN_IFERR(mec_put_int32(pack, req_status->group));
    CM_RETURN_IFERR(mec_put_int64(pack, req_status->priority));
    CM_RETURN_IFERR(mec_put_int32(pack, req_status->is_in_majority));
    CM_RETURN_IFERR(mec_put_int32(pack, req_status->is_future_hb));
    return CM_SUCCESS;
}

status_t elc_decode_status_check_req(mec_message_t* pack, rcv_node_info_t* req_status)
{
    CM_RETURN_IFERR(mec_get_int32(pack, (int32*)&req_status->role));
    CM_RETURN_IFERR(mec_get_int32(pack, (int32*)&req_status->group));
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&req_status->priority));
    CM_RETURN_IFERR(mec_get_int32(pack, (int32*)&req_status->is_in_majority));
    CM_RETURN_IFERR(mec_get_int32(pack, (int32*)&req_status->is_future_hb));
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
