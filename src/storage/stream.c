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
 * stream.c
 *
 *
 * IDENTIFICATION
 *    src/storage/stream.c
 *
 * -------------------------------------------------------------------------
 */

#include "stream.h"
#include "cm_list.h"
#include "batcher.h"
#include "stg_manager.h"
#include "util_perf_stat.h"
#include "cm_timer.h"
#include "cm_checksum.h"
#include "election.h"
#include "util_profile_stat.h"
#include "cb_func.h"

static status_t stream_alloc_entry_cache(entry_cache_t *entry_cache)
{
    uint32 alloc_size = sizeof(log_entry_t) * ENTRY_CACHE_SIZE;

    entry_cache->entrys = (log_entry_t *)malloc(alloc_size);
    if (entry_cache->entrys == NULL) {
        LOG_DEBUG_ERR("[STG]stream_alloc_entry_cache alloc entrys failed");
        return CM_ERROR;
    }

    if (memset_sp(entry_cache->entrys, alloc_size, 0, alloc_size) != EOK) {
        CM_FREE_PTR(entry_cache->entrys);
        LOG_DEBUG_ERR("[STG]stream_alloc_entry_cache memset entrys failed");
        return CM_ERROR;
    }

    if (cm_event_init(&entry_cache->event) != CM_SUCCESS) {
        CM_FREE_PTR(entry_cache->entrys);
        LOG_DEBUG_ERR("[STG]stream_alloc_entry_cache init event failed");
        return CM_ERROR;
    }

    for (uint32 i = 0; i < ENTRY_CACHE_SIZE; i++) {
        entry_cache->entrys[i].cache_event = &entry_cache->event;
    }
    entry_cache->size = ENTRY_CACHE_SIZE;
    entry_cache->begin_index = 1;
    GS_INIT_SPIN_LOCK(entry_cache->lock);
    return CM_SUCCESS;
}

// [begin, end]
static inline void stream_clear_entry_cache(entry_cache_t *cache, uint64 begin, uint64 end)
{
    for (uint64 index = begin; index <= end; ++index) {
        uint32 slot = index % cache->size;
        log_entry_t *entry = &cache->entrys[slot];
        stg_try_release_entry(entry, index);
    }
}

static inline void stream_destroy_entry_cache(entry_cache_t *entry_cache, uint64 last_index)
{
    if (entry_cache->entrys != NULL) {
        stream_clear_entry_cache(entry_cache, entry_cache->begin_index, last_index);
        CM_FREE_PTR(entry_cache->entrys);
    }
    cm_event_destory(&entry_cache->event);
}

static inline void stream_add_entry_cache(entry_cache_t *entry_cache, uint64 index, char *data_buf)
{
    uint32 slot = index % entry_cache->size;
    log_entry_t *entry = &entry_cache->entrys[slot];

    cm_latch_x(&entry->latch, 0, NULL);
    while (entry->data != NULL) {
        cm_unlatch(&entry->latch, NULL);
        (void)cm_event_timedwait(&entry_cache->event, CM_SLEEP_50_FIXED);
        cm_latch_x(&entry->latch, 0, NULL);
    }
    CM_ASSERT(entry->valid == 0);
    CM_ASSERT(entry->ref_count == 0);
    entry->data  = data_buf;
    entry->valid = CM_TRUE;
    cm_unlatch(&entry->latch, NULL);
}

static inline log_entry_t* stream_find_from_entry_cache(entry_cache_t *entry_cache, uint64 index)
{
    uint32 slot = index % entry_cache->size;
    log_entry_t *entry = &entry_cache->entrys[slot];

    cm_latch_s(&entry->latch, 0, CM_FALSE, NULL);
    if (!entry->valid || entry->data == NULL || ENTRY_INDEX(entry) != index) {
        cm_unlatch(&entry->latch, NULL);
        return NULL;
    }
    (void)cm_atomic32_inc(&entry->ref_count);
    cm_unlatch(&entry->latch, NULL);
    return entry;
}

static inline status_t stream_alloc_event(cm_event_t **event)
{
    *event = (cm_event_t*)malloc(sizeof(cm_event_t));
    if (*event == NULL) {
        LOG_DEBUG_ERR("[STG]stream_alloc_event malloc failed");
        return CM_ERROR;
    }
    if (cm_event_init(*event) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[STG]stream_alloc_event init event failed");
        CM_FREE_PTR(*event);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

void destroy_stream(stream_t *stream)
{
    // free batcher
    destroy_batcher(&stream->batcher);

    // destroy disk event
    if (stream->disk_event != NULL) {
        cm_event_destory(stream->disk_event);
        CM_FREE_PTR(stream->disk_event);
    }

    // destroy recycle event
    if (stream->recycle_event != NULL) {
        cm_event_destory(stream->recycle_event);
        CM_FREE_PTR(stream->recycle_event);
    }

    // destroy entry cache
    stream_destroy_entry_cache(&stream->entry_cache, stream->last_index);

    destroy_log_storage(&stream->log_storage);

    buddy_pool_deinit(&stream->mem_pool);
}

status_t load_stream(stream_t *stream)
{
    if (!cm_dir_exist(stream->home)) {
        CM_RETURN_IFERR(cm_create_dir(stream->home));
    }

    if (init_stg_meta(&stream->stg_meta, stream->home) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (init_log_storage(&stream->log_storage, stream->home, stream->applied_index) != CM_SUCCESS) {
        return CM_ERROR;
    }
    stream->first_index = stream->log_storage.first_index;
    stream->last_term  = stream->log_storage.last_term;
    stream->last_index  = stream->log_storage.last_index;
    stream->entry_cache.begin_index = stream->last_index + 1;
    return CM_SUCCESS;
}

static inline void stream_trunc_cache_suffix(entry_cache_t *cache, uint64 last_index_kept, uint64 last_index)
{
    uint64 begin;

    if (last_index_kept >= last_index) {
        return;
    }

    cm_spin_lock(&cache->lock, NULL);
    if (last_index_kept >= cache->begin_index) {
        begin = last_index_kept + 1;
    } else {
        begin = cache->begin_index;
        cache->begin_index = last_index_kept + 1;
    }
    cm_spin_unlock(&cache->lock);
    stream_clear_entry_cache(cache, begin, last_index);
}

static inline status_t stream_trunc_suffix(stream_t *stream, uint64 last_index_kept, uint64 term)
{
    LOG_DEBUG_INF("[STG]truncate suffix conflict id (%llu, %llu)", term, last_index_kept + 1);
    if (stream->applied_index > last_index_kept) {
        cm_spin_unlock(&stream->lock);
        LOG_DEBUG_ERR("[STG]Can not truncate index which has been applied");
        return CM_SUCCESS;
    }
    stream->last_term = term;
    uint64 old_last_index = stream->last_index;
    stream->last_index = last_index_kept + 1;
    cm_spin_unlock(&stream->lock);
    stream_trunc_cache_suffix(&stream->entry_cache, last_index_kept, old_last_index);
    return storage_trunc_suffix(&stream->log_storage, last_index_kept, term);
}

static status_t stream_check_conflict(stream_t *stream, uint64 index, uint64 term, bool32 *ignore)
{
    // check index validity
    cm_spin_lock(&stream->lock, NULL);
    if (index > stream->last_index + 1) {
        cm_spin_unlock(&stream->lock);
        LOG_DEBUG_ERR("[STG]Log index %llu is not contiguous %llu", index, stream->last_index + 1);
        return CM_ERROR;
    }

    if (index <= stream->applied_index) {
        cm_spin_unlock(&stream->lock);
        *ignore = CM_TRUE;
        LOG_DEBUG_WAR("[STG]Last index:%llu is before applied index:%llu", index, stream->applied_index);
        return CM_SUCCESS;
    }

    // index validity check ok
    if (index == stream->last_index + 1) {
        stream->last_term  = term;
        stream->last_index = index;
        cm_spin_unlock(&stream->lock);
        return CM_SUCCESS;
    }

    // check conflict log index with leader term
    if (term != stream_get_term(stream, index)) {
        // stream lock will be unlocked in this function
        return stream_trunc_suffix(stream, index - 1, term);
    }
    cm_spin_unlock(&stream->lock);
    // duplicate index which already appended
    *ignore = CM_TRUE;
    return CM_SUCCESS;
}

static inline void callback_rep_func(uint32 id, uint64 term, uint64 index, status_t status, entry_type_t type)
{
    ps_record1(PS_ACCEPT, index);

    notify_rep_func_t notify_rep_func = get_notify_rep_func();
    if (notify_rep_func != NULL) {
        notify_rep_func(id, term, index, status, type);
    }
}

static inline void calc_entry_chksum(char *buf, char *data, uint32 size)
{
    uint32 checksum = cm_get_checksum(data, size);
    IO_BUF_DATA_CHKSUM(buf) = checksum;
    checksum = cm_get_checksum(buf, ENTRY_HEAD_SIZE - sizeof(uint32));
    IO_BUF_HEAD_CHKSUM(buf) = checksum;
}

static inline uint64 get_recycle_index(stream_t *stream)
{
    uint64 disk_index = stream->log_storage.last_index;
    if (!I_AM_LEADER(stream->id)) {
        return disk_index;
    }
    return MIN(stream->applied_index, disk_index);
}

static inline bool32 stream_recycle_entrys(stream_t *stream)
{
    uint64 end = get_recycle_index(stream);
    entry_cache_t *cache = &stream->entry_cache;

    cm_spin_lock(&cache->lock, NULL);
    if (cache->begin_index > end) {
        cm_spin_unlock(&cache->lock);
        return CM_FALSE;
    }

    uint64 begin = cache->begin_index;
    end = MIN(end, begin + ENTRY_CACHE_RECYCLE_STEP);
    cache->begin_index = end + 1;
    cm_spin_unlock(&cache->lock);
    stream_clear_entry_cache(cache, begin, end);
    return CM_TRUE;
}

static inline status_t alloc_entry_buf(stream_t *stream, char *data, uint32 size, char **buf)
{
    uint32 buf_size = ENTRY_HEAD_SIZE + size;
    while (CM_TRUE) {
        *buf = (char*)galloc(buf_size, &stream->mem_pool);
        if (*buf != NULL) {
            break;
        }
        if (!stream_recycle_entrys(stream)) {
            break;
        }
    }
    if (*buf == NULL) {
        CM_THROW_ERROR(ERR_STG_MEM_POOL_FULL);
        return CM_ERROR;
    }
    if (memcpy_s(IO_BUF_DATA(*buf), size, data, size) != EOK) {
        gfree(*buf);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static inline void fill_entry_head(uint64 term, uint64 index,
    uint64 key, entry_type_t type, char *data, uint32 size, char *buf)
{
    IO_BUF_TERM(buf)  = term;
    IO_BUF_INDEX(buf) = index;
    IO_BUF_KEY(buf)   = key;
    IO_BUF_TYPE(buf)  = type;
    IO_BUF_RES(buf)   = 0;
    IO_BUF_SIZE(buf)  = size;
    calc_entry_chksum(buf, data, size);
}

static inline void stream_alloc_index(stream_t *stream, uint64 *index, uint64 term)
{
    cm_spin_lock(&stream->lock, NULL);
    *index = ++stream->last_index;
    ps_start1(*index);
    stream->last_term = term;
    cm_spin_unlock(&stream->lock);
}

status_t stream_append_entry(stream_t *stream, uint64 term, uint64 *index,
    char *data, uint32 size, uint64 key, entry_type_t type)
{
    char *buf = NULL;
    CM_RETURN_IFERR(alloc_entry_buf(stream, data, size, &buf));

    if (*index == CM_INVALID_INDEX_ID) { // leader
        stream_alloc_index(stream, index, term);
    } else { // follower
        bool32 ignore = CM_FALSE;
        if (stream_check_conflict(stream, *index, term, &ignore) != CM_SUCCESS) {
            gfree(buf);
            return CM_ERROR;
        }
        if (SECUREC_UNLIKELY(ignore)) {
            gfree(buf);
            return CM_SUCCESS;
        }
    }

    // fill entry head
    fill_entry_head(term, *index, key, type, data, size, buf);

    // add to entry cache
    stream_add_entry_cache(&stream->entry_cache, *index, buf);

    // notify disk thread
    cm_event_notify(stream->disk_event);
    stat_record_by_index(DCF_WRITE_CNT, *index);
    stat_record(DCF_WRITE_SIZE, size);
    return CM_SUCCESS;
}

log_entry_t* stream_get_entry(stream_t *stream, uint64 index)
{
    log_entry_t *entry = stream_find_from_entry_cache(&stream->entry_cache, index);
    if (entry != NULL) {
        return entry;
    }
    return storage_get_entry(&stream->log_storage, index);
}

uint64 stream_get_term(stream_t *stream, uint64 index)
{
    log_entry_t *entry = stream_find_from_entry_cache(&stream->entry_cache, index);
    if (entry != NULL) {
        uint64 term = ENTRY_TERM(entry);
        stg_entry_dec_ref(entry);
        return term;
    }
    return storage_get_term(&stream->log_storage, index);
}

log_id_t stream_last_log_id(stream_t *stream, bool32 flush)
{
    if (flush) {
        return storage_get_last_id(&stream->log_storage);
    }

    log_id_t log_id;
    cm_spin_lock(&stream->lock, NULL);
    log_id.term = stream->last_term;
    log_id.index = stream->last_index;
    cm_spin_unlock(&stream->lock);
    return log_id;
}

static inline void stream_trunc_cache_prefix(entry_cache_t *cache, uint64 first_index_kept, uint64 last_index)
{
    cm_spin_lock(&cache->lock, NULL);
    if (first_index_kept <= cache->begin_index) {
        cm_spin_unlock(&cache->lock);
        return;
    }
    uint64 begin = cache->begin_index;
    cache->begin_index = first_index_kept;
    cm_spin_unlock(&cache->lock);

    uint64 end = first_index_kept > last_index ? last_index : first_index_kept - 1;
    stream_clear_entry_cache(cache, begin, end);
}

status_t stream_trunc_prefix(stream_t *stream, uint64 first_index_kept)
{
    cm_spin_lock(&stream->lock, NULL);
    if (stream->first_index >= first_index_kept) {
        cm_spin_unlock(&stream->lock);
        return CM_SUCCESS;
    }
    stream->first_index = first_index_kept;
    uint64 old_last_index = stream->last_index;
    if (first_index_kept > stream->last_index) {
        stream->last_index = first_index_kept - 1;
    }
    cm_spin_unlock(&stream->lock);
    stream_trunc_cache_prefix(&stream->entry_cache, first_index_kept, old_last_index);
    return storage_trunc_prefix(&stream->log_storage, first_index_kept);
}

static inline status_t stream_append_entry_impl(stream_t *stream, log_entry_t *entry)
{
    status_t status = storage_write_entry(&stream->log_storage, entry);
    callback_rep_func(stream->id, ENTRY_TERM(entry), ENTRY_INDEX(entry), status, ENTRY_TYPE(entry));
    return status;
}

static inline status_t stream_batcher_flush(stream_t *stream, batcher_t *batcher)
{
    status_t status = batcher_flush(&stream->log_storage, batcher);
    callback_rep_func(stream->id, batcher->last_term, batcher->last_index, status, ENTRY_TYPE_LOG);
    batcher_end(&stream->log_storage, batcher);
    return status;
}

static inline status_t stream_try_batcher_flush(stream_t *stream, batcher_t *batcher)
{
    if (batcher->size > 0) {
        return stream_batcher_flush(stream, batcher);
    }
    batcher_end(&stream->log_storage, batcher);
    return CM_SUCCESS;
}

static inline status_t stream_batcher_append(stream_t *stream, batcher_t *batcher, log_entry_t *entry)
{
    if (ENTRY_LENGTH(entry) + batcher->size > batcher->capacity) {
        CM_RETURN_IFERR(stream_batcher_flush(stream, batcher));
    }

    if (batcher->segment == NULL) {
        CM_RETURN_IFERR(batcher_begin(&stream->log_storage, batcher));
    }
    return batcher_append(&stream->log_storage, &stream->batcher, entry);
}

static inline bool32 unsafe_get_disk_flush_info(stream_t *stream, uint64 *start, uint64 *end)
{
    *end   = stream->last_index;
    *start = stream->log_storage.last_index;
    return ((*end) > (*start));
}

static inline status_t process_append_action(stream_t *stream, batcher_t *batcher, log_entry_t *entry)
{
    if (SECUREC_UNLIKELY(ENTRY_TYPE(entry) == ENTRY_TYPE_CONF || ENTRY_LENGTH(entry) > batcher->capacity)) {
        CM_RETURN_IFERR(stream_try_batcher_flush(stream, batcher));
        return stream_append_entry_impl(stream, entry);
    }
    return stream_batcher_append(stream, batcher, entry);
}

void disk_thread_entry(thread_t *thread)
{
    uint64     start, end;
    status_t   status  = CM_SUCCESS;
    stream_t  *stream  = (stream_t*)thread->argument;
    batcher_t *batcher = &stream->batcher;

    if (cm_set_thread_name("disk_write") != CM_SUCCESS) {
        LOG_DEBUG_ERR("[STG] set thread name disk_write error");
    }

    usr_cb_thread_memctx_init_t cb_memctx_init = get_dcf_worker_memctx_init_cb();
    if (cb_memctx_init != NULL) {
        cb_memctx_init();
        LOG_DEBUG_INF("[STG]disk_write thread memctx init callback: g_cb_thread_memctx_init done");
    }

    while (!thread->closed) {
        if (!unsafe_get_disk_flush_info(stream, &start, &end)) {
            (void)cm_event_timedwait(stream->disk_event, CM_SLEEP_50_FIXED);
            continue;
        }

        // (start, end]
        for (uint64 index = start; index < end; ++index) {
            log_entry_t *entry = stream_find_from_entry_cache(&stream->entry_cache, index + 1);
            if (entry == NULL) {
                break;
            }
            status = process_append_action(stream, batcher, entry);
            stg_entry_dec_ref(entry);
            if (status != CM_SUCCESS) {
                break;
            }
        }
        if (status == CM_SUCCESS) {
            (void)stream_try_batcher_flush(stream, batcher);
        }
    }
}

static inline bool32 if_exceed_cache_threshold(stream_t *stream)
{
    entry_cache_t *cache = &stream->entry_cache;
    if (SECUREC_UNLIKELY(cache->begin_index > stream->last_index)) {
        return CM_FALSE;
    }
    return (((stream->last_index - cache->begin_index) + 1) >= ENTRY_CACHE_THRESHOLD);
}

static inline bool32 if_exceed_mem_threshold(mem_pool_t *mem_pool)
{
    return (mem_used_size(mem_pool) >= (mem_max_size(mem_pool) / CM_2X_FIXED));
}

static inline void stream_recycle_internal(stream_t *stream)
{
    while (CM_TRUE) {
        if (!if_exceed_cache_threshold(stream) && !if_exceed_mem_threshold(&stream->mem_pool)) {
            break;
        }
        if (!stream_recycle_entrys(stream)) {
            break;
        }
    }
}

void recycle_thread_entry(thread_t *thread)
{
    stream_t *stream = (stream_t*)thread->argument;
    if (cm_set_thread_name("recycle") != CM_SUCCESS) {
        LOG_DEBUG_ERR("[STG] set thread name recycle error");
    }
    while (!thread->closed) {
        stream_recycle_internal(stream);
        (void)cm_event_timedwait(stream->recycle_event, CM_SLEEP_50_FIXED);
    }
}

void load_stream_entry(thread_t *thread)
{
    stream_t *stream = (stream_t*)thread->argument;
    thread->result = load_stream(stream);
}

status_t init_stream(uint32 stream_id, char *data_path, stream_t *stream)
{
    CM_RETURN_IFERR(stream_alloc_event(&stream->disk_event));

    CM_RETURN_IFERR(stream_alloc_event(&stream->recycle_event));

    CM_RETURN_IFERR(create_batcher(&stream->batcher, BATCHER_BUF_SIZE));

    param_value_t init_size, max_size;
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_STG_POOL_INIT_SIZE, &init_size));
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_STG_POOL_MAX_SIZE, &max_size));
    CM_RETURN_IFERR(buddy_pool_init("stream", init_size.stg_pool_init_size,
        max_size.stg_pool_max_size, &stream->mem_pool));

    CM_RETURN_IFERR(stream_alloc_entry_cache(&stream->entry_cache));

    PRTS_RETURN_IFERR(snprintf_s(stream->home, CM_MAX_PATH_LEN,
        CM_MAX_PATH_LEN - 1, "%s/stream%02u", data_path, stream_id));

    stream->id            = stream_id;
    stream->first_index   = 1;
    GS_INIT_SPIN_LOCK(stream->lock);
    return CM_SUCCESS;
}
