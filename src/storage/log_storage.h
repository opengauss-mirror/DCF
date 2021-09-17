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
 * log_storage.h
 *    log storage
 *
 * IDENTIFICATION
 *    src/storage/log_storage.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __LOG_STORAGE_H__
#define __LOG_STORAGE_H__

#include "segment.h"
#include "bucket_list.h"
#include "stg_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_log_storage {
    char            *home;
    uint64          first_index;
    uint64          last_term;
    uint64          last_index;
    uint64          segment_size;
    latch_t         latch;
    latch_t         trunc_latch;
    segment_t      *open_segment;
    bucket_list_t   segments;
    mem_pool_t      mem_pool;
} log_storage_t;

#define STG_LOG_META     "log_ctrl"
// format of log meta file
// | ------------------  first index (64bits) ---------------------|
// | -----------checksum (32bits) |

#define LOG_META_OF_FST_INDEX     0
#define LOG_META_OF_CHECKSUM      8
#define LOG_META_LENGTH           12

void destroy_log_storage(log_storage_t *storage);
status_t init_log_storage(log_storage_t *storage, char *home, uint64 applied_index);
status_t storage_write_entry(log_storage_t *storage, log_entry_t *log_entry);
log_entry_t* storage_get_entry(log_storage_t *storage, uint64 index);
uint64 storage_get_term(log_storage_t *storage, uint64 index);
status_t storage_trunc_prefix(log_storage_t *storage, uint64 first_index_kept);
status_t storage_trunc_suffix(log_storage_t *storage, uint64 last_index_kept, uint64 last_term);
segment_t *get_open_segment(log_storage_t *storage);

static inline log_id_t storage_get_last_id(log_storage_t *storage)
{
    log_id_t log_id;
    cm_latch_s(&storage->latch, 0, CM_FALSE, NULL);
    log_id.term  = storage->last_term;
    log_id.index = storage->last_index;
    cm_unlatch(&storage->latch, NULL);
    return log_id;
}

#ifdef __cplusplus
}
#endif

#endif