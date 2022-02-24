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
 * elc_msg_pack.h
 *    election message process
 *
 * IDENTIFICATION
 *    src/election/elc_msg_pack.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __ELC_MSG_PACK_H__
#define __ELC_MSG_PACK_H__

#include "cm_types.h"
#include "stg_manager.h"
#include "mec.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VOTE_FLAG_INIT         0x00000000
#define VOTE_FLAG_PRE_VOTE     0x00000001
#define VOTE_FLAG_FORCE_VOTE   0x00000002

#define ELC_PRE_VOTE(flag)     ((flag) & VOTE_FLAG_PRE_VOTE)
#define ELC_FORCE_VOTE(flag)   ((flag) & VOTE_FLAG_FORCE_VOTE)

typedef struct st_elc_vote {
    uint64      candidate_term;
    uint32      candidate_id;
    log_id_t    last_log;
    uint32      vote_flag;
    dcf_work_mode_t work_mode;
} elc_vote_t;

typedef struct st_elc_vote_ack {
    uint64      term;
    uint32      vote_granted;
    dcf_work_mode_t work_mode;
    uint32      vote_flag;
} elc_vote_ack_t;

typedef struct st_elc_hb {
    uint64      term;
    dcf_work_mode_t work_mode;
    uint32      md_chksum;
    int64       send_time;
} elc_hb_t;

typedef struct st_rcv_node_info {
    uint32 role;
    uint32 group;
    uint64 priority;
    bool32 is_in_majority; // Whether the recv node is in the majority
    bool32 is_future_hb; // Whether hb time is in future. If yes, old leader or static leader elected preferentially.
    timespec_t last_recv_time;
} rcv_node_info_t;

status_t elc_decode_vote_ack(mec_message_t* pack, elc_vote_ack_t* ack_vote);
status_t elc_encode_vote_ack(mec_message_t* pack, const elc_vote_ack_t* ack_vote);
status_t elc_decode_vote_req(mec_message_t* pack, elc_vote_t* req_vote);
status_t elc_encode_vote_req(mec_message_t* pack, const elc_vote_t* req_vote);

status_t elc_decode_hb_req(mec_message_t* pack, elc_hb_t* req_vote);
status_t elc_encode_hb_req(mec_message_t* pack, const elc_hb_t* req_vote);
status_t elc_encode_status_check_req(mec_message_t* pack, const rcv_node_info_t* req_status);
status_t elc_decode_status_check_req(mec_message_t* pack, rcv_node_info_t* req_status);

#ifdef __cplusplus
}
#endif

#endif
