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
 * stream.h
 *
 *
 * IDENTIFICATION
 *    src/storage/stream.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __STREAM_H__
#define __STREAM_H__

#include "batcher.h"
#include "cm_atomic.h"
#include "cm_spinlock.h"
#include "stg_manager.h"
#include "log_storage.h"
#include "meta_storage.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_entry_cache {
    uint32       size;
    cm_event_t   event;
    spinlock_t   lock;
    log_entry_t *entrys;
    uint64       begin_index;
}entry_cache_t;

typedef struct st_stream {
    uint32          id;
    spinlock_t      lock;
    uint64          last_term;
    uint64          last_index;
    uint64          first_index;
    uint64          applied_index;
    char            home[CM_MAX_PATH_LEN];
    batcher_t       batcher;
    cm_event_t     *disk_event;
    cm_event_t     *recycle_event;
    mem_pool_t      mem_pool;
    stg_meta_t      stg_meta;
    log_storage_t   log_storage;
    entry_cache_t   entry_cache;
} stream_t;

void disk_thread_entry(thread_t *thread);

void load_stream_entry(thread_t *thread);

void recycle_thread_entry(thread_t *thread);

void destroy_stream(stream_t *stream);

status_t load_stream(stream_t *stream);

status_t init_stream(uint32 stream_id, char *data_path, stream_t *stream);

status_t stream_append_entry(stream_t *stream, uint64 term, uint64 *index, char *data,
    uint32 size, uint64 key, entry_type_t type);

log_entry_t* stream_get_entry(stream_t *stream, uint64 index);

uint64 stream_get_term(stream_t *stream, uint64 index);

log_id_t stream_last_log_id(stream_t *stream, bool32 flush);

status_t stream_trunc_prefix(stream_t *stream, uint64 first_index_kept);

static inline status_t stream_set_applied_index(stream_t *stream, uint64 applied_index)
{
    stream->applied_index = applied_index;
    if (SECUREC_LIKELY(stream->recycle_event != NULL)) {
        cm_event_notify(stream->recycle_event);
    }
    return CM_SUCCESS;
}

static inline uint64 stream_get_applied_index(const stream_t *stream)
{
    return stream->applied_index;
}

/*======================stream metadata========================*/
static inline status_t stream_set_current_term(stream_t *stream, uint64 term)
{
    return meta_set_current_term(&stream->stg_meta, term);
}

static inline uint64 stream_get_current_term(stream_t *stream)
{
    return meta_get_current_term(&stream->stg_meta);
}

static inline status_t stream_set_votedfor(stream_t *stream, uint32 votedfor)
{
    return meta_set_votedfor(&stream->stg_meta, votedfor);
}

static inline uint32 stream_get_votedfor(stream_t *stream)
{
    return meta_get_votedfor(&stream->stg_meta);
}
/*=============================================================*/

static inline uint64 stream_first_index(const stream_t *stream)
{
    return stream->first_index;
}

static inline uint64 stream_last_index(const stream_t *stream)
{
    return stream->last_index;
}

#define ENTRY_CACHE_SIZE         1000000
#define ENTRY_CACHE_RECYCLE_STEP 128
#define ENTRY_CACHE_THRESHOLD    (3 * ENTRY_CACHE_SIZE / 4)

#ifdef __cplusplus
}
#endif

#endif