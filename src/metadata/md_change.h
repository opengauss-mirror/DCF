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
 * md_change.h
 *    metadata process
 *
 * IDENTIFICATION
 *    src/metadata/md_change.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __MD_CHANGE_H__
#define __MD_CHANGE_H__

#include "cm_types.h"
#include "cm_error.h"
#include "md_param.h"

#ifdef __cplusplus
extern "C" {
#endif

int md_after_write_cb(uint32 stream_id, uint64 index, const char *buf, uint32 size, uint64 key, int32 error_no);
int md_consensus_notify_cb(uint32 stream_id, uint64 index, const char *buf, uint32 size, uint64 key);

status_t mec_update_profile_inst();
status_t elc_update_node_role(uint32 stream_id);
status_t elc_update_node_group(uint32 stream_id);
status_t elc_update_node_priority(uint32 stream_id);
status_t rep_check_param_majority_groups();
#ifdef __cplusplus
}
#endif

#endif