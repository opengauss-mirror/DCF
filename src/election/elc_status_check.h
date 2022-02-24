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
 * elc_status_check.h
 *    election status check
 *
 * IDENTIFICATION
 *    src/election/elc_status_check.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __ELC_STATUS_CHECK_H__
#define __ELC_STATUS_CHECK_H__

#include "cm_types.h"
#include "cm_date.h"
#include "elc_msg_pack.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_elc_status_check {
    latch_t latch;
    rcv_node_info_t info[CM_MAX_NODE_COUNT];
} elc_status_check_t;

bool32 elc_is_in_majority(uint32 stream_id);
uint32 elc_get_rcv_best_priority_node(uint32 stream_id);
void elc_save_status_check_info(uint32 stream_id, uint32 src_node, const rcv_node_info_t *rcv_info);
status_t elc_status_check_init();

#ifdef __cplusplus
}
#endif

#endif
