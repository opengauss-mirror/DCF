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
 * stg_manager.h
 *    storage manager flush
 *
 * IDENTIFICATION
 *    src/storage/stg_manager.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __LOG_MANAGER_H__
#define __LOG_MANAGER_H__

#include "cm_defs.h"
#include "cm_sync.h"
#include "cm_latch.h"
#include "cm_thread.h"
#include "metadata.h"
#include "cm_file.h"
#include "cm_atomic.h"
#include "cm_memory.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BATCHER_BUF_SIZE     SIZE_M(2)

typedef struct st_log_id {
    uint64 term;
    uint64 index;
}log_id_t;

// format of entry head
// | ------------------------ term(64bits) -------------------------|
// | ------------------------ index(64bits)-------------------------|
// | ------------------------ key (64bits) -------------------------|
// | ------------- entry type(32bits) | reserve(32bits) ------------|
// | ------------------- size(32bits) | data checksum(32bits) ------|
// | ---------- head checksum(32bits) |

#define OFFSET_OF_TERM        0
#define OFFSET_OF_INDEX       8
#define OFFSET_OF_KEY         16
#define OFFSET_OF_TYPE        24
#define OFFSET_OF_RES         28
#define OFFSET_OF_SIZE        32
#define OFFSET_OF_DATA_CHKSUM 36
#define OFFSET_OF_HEAD_CHKSUM 40
#define ENTRY_HEAD_SIZE       44

typedef struct st_log_entry {
    latch_t     latch;
    atomic32_t  ref_count;
    bool8       valid;
    bool8       from_pool;
    char        *data; // entry head(32bytes) + data buffer(size bytes)
    cm_event_t *cache_event;
}log_entry_t;

#define IO_BUF_TERM(io_buf)        *(uint64*)((io_buf) + OFFSET_OF_TERM)
#define IO_BUF_INDEX(io_buf)       *(uint64*)((io_buf) + OFFSET_OF_INDEX)
#define IO_BUF_KEY(io_buf)         *(uint64*)((io_buf) + OFFSET_OF_KEY)
#define IO_BUF_TYPE(io_buf)        *(uint32*)((io_buf) + OFFSET_OF_TYPE)
#define IO_BUF_RES(io_buf)         *(uint32*)((io_buf) + OFFSET_OF_RES)
#define IO_BUF_SIZE(io_buf)        *(uint32*)((io_buf) + OFFSET_OF_SIZE)
#define IO_BUF_DATA_CHKSUM(io_buf) *(uint32*)((io_buf) + OFFSET_OF_DATA_CHKSUM)
#define IO_BUF_HEAD_CHKSUM(io_buf) *(uint32*)((io_buf) + OFFSET_OF_HEAD_CHKSUM)
#define IO_BUF_DATA(io_buf)         (char*)((io_buf) + ENTRY_HEAD_SIZE)

#define ENTRY_INDEX(entry)       IO_BUF_INDEX((entry)->data)
#define ENTRY_TERM(entry)        IO_BUF_TERM((entry)->data)
#define ENTRY_KEY(entry)         IO_BUF_KEY((entry)->data)
#define ENTRY_TYPE(entry)        IO_BUF_TYPE((entry)->data)
#define ENTRY_SIZE(entry)        IO_BUF_SIZE((entry)->data)
#define ENTRY_DATA_CHKSUM(entry) IO_BUF_DATA_CHKSUM((entry)->data)
#define ENTRY_HEAD_CHKSUM(entry) IO_BUF_HEAD_CHKSUM((entry)->data)
#define ENTRY_BUF(entry)         IO_BUF_DATA((entry)->data)
#define ENTRY_LENGTH(entry)      (ENTRY_SIZE(entry) + ENTRY_HEAD_SIZE)

typedef status_t(*write_conf_func_t) (const char *buf, uint32 size);
typedef void(*notify_rep_func_t)(uint32 stream_id, uint64 term, uint64 index, status_t status, entry_type_t type);

// init log storage
status_t stg_init();

void stg_deinit();

// register callback function
status_t stg_register_cb(entry_type_t type, void *func);

// append log entry
status_t stg_append_entry(uint32 stream_id, uint64 term, uint64 index, char *buf, uint32 size,
    uint64 key, entry_type_t entry_type, uint64 *out_index);

// get log entry with the specified index
log_entry_t* stg_get_entry(uint32 stream_id, uint64 index);

// get term with the specified index
uint64 stg_get_term(uint32 stream_id, uint64 index);

// get index of the first log entry
uint64 stg_first_index(uint32 stream_id);

// get index of the last log entry
uint64 stg_last_index(uint32 stream_id);

// get log id of the last log entry
log_id_t stg_last_log_id(uint32 stream_id);

// get log id of the last log entry which flushed to disk
log_id_t stg_last_disk_log_id(uint32 stream_id);

// get applied log index
uint64 stg_get_applied_index(uint32 stream_id);

// set applied log index
status_t stg_set_applied_index(uint32 stream_id, uint64 index);

// delete logs from storage's head, [1, first_index_kept) will be discarded
status_t stg_truncate_prefix(uint32 stream_id, uint64 first_index_kept);

// set current term
status_t stg_set_current_term(uint32 stream_id, uint64 term);

// get current term
uint64 stg_get_current_term(uint32 stream_id);

// set votedfor
status_t stg_set_votedfor(uint32 stream_id, uint32 votedfor);

// get votedfor
uint32 stg_get_votedfor(uint32 stream_id);

int64 stg_get_total_mem_used();

log_id_t* get_invalid_log_id();
write_conf_func_t get_write_conf_func();
notify_rep_func_t get_notify_rep_func();
static inline status_t stg_remove_file(char *home, char *file_name)
{
    char full_name[CM_MAX_PATH_LEN];
    PRTS_RETURN_IFERR(snprintf_s(full_name, CM_MAX_PATH_LEN, CM_MAX_PATH_LEN - 1, "%s/%s", home, file_name));
    return cm_remove_file(full_name);
}

static inline int32 log_id_cmp(const log_id_t *id1, const log_id_t *id2)
{
    if (id1->term > id2->term) {
        return 1;
    }
    if (id1->term < id2->term) {
        return -1;
    }
    return (id1->index == id2->index ? 0 : (id1->index > id2->index ? 1 : -1));
}

static inline void free_log_entry(log_entry_t *entry)
{
    if (SECUREC_UNLIKELY(entry->from_pool)) {
        gfree(entry);
        return;
    }
    CM_ASSERT(entry->data != NULL);
    gfree(entry->data);
    entry->data = NULL;
    entry->ref_count = 0;
    cm_event_notify(entry->cache_event);
}

static inline void stg_entry_dec_ref(log_entry_t *entry)
{
    cm_latch_s(&entry->latch, 0, CM_FALSE, NULL);
    int32 ref_count = cm_atomic32_dec(&entry->ref_count);
    CM_ASSERT(ref_count >= 0);
    bool32 need_free = (ref_count == 0 && !entry->valid);
    cm_unlatch(&entry->latch, NULL);
    if (need_free) {
        free_log_entry(entry);
    }
}

static inline void stg_try_release_entry(log_entry_t *entry, uint64 index)
{
    cm_latch_x(&entry->latch, 0, NULL);
    if (!entry->valid || ENTRY_INDEX(entry) != index) {
        cm_unlatch(&entry->latch, NULL);
        return;
    }
    entry->valid = CM_FALSE;
    if (entry->ref_count > 0) {
        cm_unlatch(&entry->latch, NULL);
        return;
    }
    cm_unlatch(&entry->latch, NULL);
    free_log_entry(entry);
}

#ifdef __cplusplus
}
#endif

#endif