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
 * elc_msg_proc.h
 *    election message process
 *
 * IDENTIFICATION
 *    src/election/elc_msg_proc.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __ELC_MSG_PROC_H__
#define __ELC_MSG_PROC_H__

#include "elc_msg_pack.h"
#include "util_profile_stat.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t elc_vote_req(uint32 stream_id, uint32 vote_flag);
status_t elc_vote_proc(mec_message_t *pack);
status_t elc_vote_ack_proc(mec_message_t *pack);

status_t elc_send_status_info(uint32 stream_id);
status_t elc_status_check_req_proc(mec_message_t *pack);
status_t elc_status_check_ack_proc(mec_message_t *pack);

status_t elc_promote_req(uint32 stream_id, uint32 node_id);
status_t elc_promote_proc(mec_message_t *pack);

bool32 elc_need_demote_follow(uint32 stream_id, timespec_t now, uint32 elc_timeout_cnt);

#ifdef __cplusplus
}
#endif

#endif
