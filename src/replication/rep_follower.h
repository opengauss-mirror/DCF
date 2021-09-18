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
 * rep_follower.h
 *    follower  process
 *
 * IDENTIFICATION
 *    src/replication/rep_follower.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __REP_FOLLOWER_H__
#define __REP_FOLLOWER_H__

#include "util_error.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t rep_follower_init();

void rep_follower_reset(uint32 stream_id);

status_t rep_follower_acceptlog_proc(uint32 stream_id);

void rep_follower_acceptlog(uint32 stream_id, uint64 term, uint64 index, status_t status);

log_id_t rep_get_last_append_log(uint32 stream_id);

#ifdef __cplusplus
}
#endif

#endif
