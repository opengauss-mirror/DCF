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
 * stg_manager.c
 *    storage manager flush
 *
 * IDENTIFICATION
 *    src/storage/stg_manager.c
 *
 * -------------------------------------------------------------------------
 */

#include "stg_manager.h"
#include "stream.h"

static latch_t    g_latch = {0};
static thread_t   g_timed_task;
static bool32     g_inited = CM_FALSE;
static stream_t   g_streams[CM_MAX_STREAM_COUNT];
static thread_t   g_disk_thread[CM_MAX_STREAM_COUNT];
static thread_t   g_recycle_thread[CM_MAX_STREAM_COUNT];

log_id_t g_invalid_log_id = {CM_INVALID_TERM_ID, CM_INVALID_INDEX_ID};
write_conf_func_t g_write_conf_func = NULL;
notify_rep_func_t g_notify_rep_func = NULL;

write_conf_func_t get_write_conf_func()
{
    return g_write_conf_func;
}

notify_rep_func_t get_notify_rep_func()
{
    return g_notify_rep_func;
}

log_id_t* get_invalid_log_id()
{
    return &g_invalid_log_id;
}

status_t stg_register_cb(entry_type_t type, void *func)
{
    switch (type) {
        case ENTRY_TYPE_CONF:
            g_write_conf_func = (write_conf_func_t)func;
            break;
        case ENTRY_TYPE_LOG:
            g_notify_rep_func = (notify_rep_func_t)func;
            break;
        default:
            LOG_RUN_ERR("[STG]Register callback failed");
            return CM_ERROR;
    }
    return CM_SUCCESS;
}

static inline void try_clean_up_junk_file(char *home, char *file_name)
{
    if (strncmp(file_name + (strlen(file_name) - strlen(".tmp")), ".tmp", strlen(".tmp")) != 0) {
        return;
    }
    (void)stg_remove_file(home, file_name);
}

static void clean_up_junk_files(stream_t *stream)
{
#ifdef WIN32
    intptr_t handle;
    struct _finddata_t fileData;
    char file_name[CM_MAX_PATH_LEN] = { 0 };
    char *suffix = (char *)"*.tmp";

    if (snprintf_s(file_name, CM_MAX_PATH_LEN, CM_MAX_PATH_LEN - 1, "%s/%s", stream->home, suffix) == -1) {
        return;
    }

    handle = (intptr_t)_findfirst(file_name, &fileData);
    if (-1L == handle) {
        return;
    }

    try_clean_up_junk_file(stream->home, (char *)fileData.name);
    while (_findnext(handle, &fileData) == 0) {
        try_clean_up_junk_file(stream->home, (char *)fileData.name);
    }
    _findclose(handle);
#else
    DIR *dirPtr = NULL;
    struct dirent *direntPtr = NULL;

    dirPtr = opendir(stream->home);
    if (dirPtr == NULL) {
        return;
    }

    direntPtr = readdir(dirPtr);
    while (direntPtr != NULL) {
        try_clean_up_junk_file(stream->home, (char *)direntPtr->d_name);
        direntPtr = readdir(dirPtr);
    }
    (void)closedir(dirPtr);
#endif
}

static void print_stream_info(stream_t *stream)
{
    LOG_PROFILE("[STG]:%6s %10s %10s %10s %10s %10s %11s %12s",
        "stm id", "stm fst", "stm last", "stg fst", "stg last", "applied", "cache begin", "stm mem used");

    uint64 last_applied_index = stream_get_applied_index(stream);
    log_storage_t *storage = &stream->log_storage;
    LOG_PROFILE("[STG]:%6u %10llu %10llu %10llu %10llu %10llu %11llu %12llu",
        stream->id, stream->first_index, stream->last_index, storage->first_index,
        storage->last_index, last_applied_index, stream->entry_cache.begin_index, stream->mem_pool.used_size);
}

#define TIME_TASK_RATE  20
static void stg_timed_task(thread_t *thread)
{
    uint32 count;
    uint32 rate = 0;
    uint32 stream_id[CM_MAX_STREAM_COUNT];

    if (cm_set_thread_name("stg_timed_task") != CM_SUCCESS) {
        LOG_DEBUG_ERR("[STG] set thread name stg_timed_task error");
    }

    while (!thread->closed) {
        if (rate++ < TIME_TASK_RATE) {
            cm_sleep(CM_SLEEP_500_FIXED);
            continue;
        }
        rate = 0;
        if (md_get_stream_list(stream_id, &count) != CM_SUCCESS) {
            LOG_DEBUG_ERR("[STG]Timed task get stream metadata failed");
            continue;
        }
        for (uint32 i = 0; i < count; ++i) {
            if (stream_id[i] >= CM_MAX_STREAM_COUNT) {
                continue;
            }
            stream_t *stream = &g_streams[stream_id[i]];
            // clean up temp files
            clean_up_junk_files(stream);
            // printf stream static info
            print_stream_info(stream);
        }
    }
}

static inline status_t create_timed_task(thread_t *timed_thread)
{
    return cm_create_thread(stg_timed_task, 0, NULL, timed_thread);
}

static inline status_t init_stream_instance(const uint32 *ids, uint32 count, char *data_path)
{
    for (uint32 i = 0; i < count; ++i) {
        CM_RETURN_IFERR(init_stream(ids[i], data_path, &g_streams[ids[i]]));
    }
    return CM_SUCCESS;
}

static inline void destroy_stream_instance(const uint32 *ids, uint32 count)
{
    for (uint32 i = 0; i < count; ++i) {
        destroy_stream(&g_streams[ids[i]]);
    }
}

static inline status_t create_stream_disk_thread(const uint32 *ids, uint32 count)
{
    for (uint32 i = 0; i < count; ++i) {
        CM_RETURN_IFERR(cm_create_thread(disk_thread_entry, 0,
            &g_streams[ids[i]], &g_disk_thread[ids[i]]));
    }
    return CM_SUCCESS;
}

static inline void destroy_stream_disk_thread(const uint32 *ids, uint32 count)
{
    for (uint32 i = 0; i < count; ++i) {
        cm_close_thread(&g_disk_thread[ids[i]]);
    }
}

static inline status_t create_stream_recycle_thread(uint32 *ids, uint32 count)
{
    for (uint32 i = 0; i < count; ++i) {
        CM_RETURN_IFERR(cm_create_thread(recycle_thread_entry, 0,
            &g_streams[ids[i]], &g_recycle_thread[ids[i]]));
    }
    return CM_SUCCESS;
}

static inline void destroy_stream_recycle_thread(const uint32 *ids, uint32 count)
{
    for (uint32 i = 0; i < count; ++i) {
        cm_close_thread(&g_recycle_thread[ids[i]]);
    }
}

static status_t load_stream_instance(const uint32 *ids, uint32 count)
{
    uint32   loop = 0;
    thread_t thread[CM_MAX_STREAM_COUNT];

    for (; loop < count - 1; ++loop) {
        if (cm_create_thread(load_stream_entry, 0, &g_streams[ids[loop]], &thread[loop]) != CM_SUCCESS) {
            break;
        }
    }
    if (loop != count - 1) {
        return CM_ERROR;
    }
    status_t status = load_stream(&g_streams[ids[count - 1]]);

    for (uint32 i = 0; i < loop; i++) {
        cm_close_thread(&thread[i]);
        status = thread[i].result == CM_ERROR ? CM_ERROR : status;
    }
    return status;
}

static void stg_deinit_impl()
{
    uint32 count;
    uint32 stream_id[CM_MAX_STREAM_COUNT];

    if (md_get_stream_list(stream_id, &count) != CM_SUCCESS) {
        return;
    }

    destroy_stream_disk_thread(stream_id, count);

    destroy_stream_recycle_thread(stream_id, count);

    cm_close_thread(&g_timed_task);

    destroy_stream_instance(stream_id, count);

    g_write_conf_func = NULL;
    g_notify_rep_func  = NULL;
}

void stg_deinit()
{
    cm_latch_x(&g_latch, 0, NULL);

    if (!g_inited) {
        cm_unlatch(&g_latch, NULL);
        return;
    }
    g_inited = CM_FALSE;

    stg_deinit_impl();
    cm_unlatch(&g_latch, NULL);

    MEMS_RETVOID_IFERR(memset_sp(g_streams, sizeof(stream_t) * CM_MAX_STREAM_COUNT, 0,
        sizeof(stream_t) * CM_MAX_STREAM_COUNT));
}

static status_t stg_init_impl()
{
    param_value_t param;

    CM_RETURN_IFERR(md_get_param(DCF_PARAM_DATA_PATH, &param));

    if (!cm_dir_exist(param.data_path)) {
        CM_RETURN_IFERR(cm_create_dir_ex(param.data_path));
    }

    uint32 count;
    uint32 stream_id[CM_MAX_STREAM_COUNT];

    CM_RETURN_IFERR(md_get_stream_list(stream_id, &count));
    if (count == 0) {
        LOG_RUN_ERR("invalid stream count:%u", count);
        return CM_ERROR;
    }

    CM_RETURN_IFERR(init_stream_instance(stream_id, count, param.data_path));

    CM_RETURN_IFERR(load_stream_instance(stream_id, count));

    CM_RETURN_IFERR(create_stream_disk_thread(stream_id, count));

    CM_RETURN_IFERR(create_stream_recycle_thread(stream_id, count));

    return create_timed_task(&g_timed_task);
}

status_t stg_init()
{
    cm_latch_x(&g_latch, 0, NULL);
    if (g_inited) {
        cm_unlatch(&g_latch, NULL);
        return CM_SUCCESS;
    }

    if (stg_init_impl() != CM_SUCCESS) {
        stg_deinit_impl();
        cm_unlatch(&g_latch, NULL);
        return CM_ERROR;
    }

    g_inited = CM_TRUE;
    cm_unlatch(&g_latch, NULL);
    LOG_RUN_INF("[STG]Stg init succeed");
    return CM_SUCCESS;
}

status_t stg_append_entry(uint32 stream_id, uint64 term, uint64 index, char *buf, uint32 size,
    uint64 key, entry_type_t entry_type, uint64 *out_index)
{
    CM_RETURN_IFERR(stream_append_entry(&g_streams[stream_id], term, &index, buf, size, key, entry_type));
    if (out_index != NULL) {
        *out_index = index;
    }
    return CM_SUCCESS;
}

log_entry_t* stg_get_entry(uint32 stream_id, uint64 index)
{
    return stream_get_entry(&g_streams[stream_id], index);
}

status_t stg_set_applied_index(uint32 stream_id, uint64 index)
{
    return stream_set_applied_index(&g_streams[stream_id], index);
}

uint64 stg_get_applied_index(uint32 stream_id)
{
    return stream_get_applied_index(&g_streams[stream_id]);
}

uint64 stg_get_term(uint32 stream_id, uint64 index)
{
    return stream_get_term(&g_streams[stream_id], index);
}

uint64 stg_first_index(uint32 stream_id)
{
    return stream_first_index(&g_streams[stream_id]);
}

uint64 stg_last_index(uint32 stream_id)
{
    return stream_last_index(&g_streams[stream_id]);
}

log_id_t stg_last_log_id(uint32 stream_id)
{
    return stream_last_log_id(&g_streams[stream_id], CM_FALSE);
}

log_id_t stg_last_disk_log_id(uint32 stream_id)
{
    return stream_last_log_id(&g_streams[stream_id], CM_TRUE);
}

status_t stg_truncate_prefix(uint32 stream_id, uint64 first_index_kept)
{
    return stream_trunc_prefix(&g_streams[stream_id], first_index_kept);
}

status_t stg_set_current_term(uint32 stream_id, uint64 term)
{
    return stream_set_current_term(&g_streams[stream_id], term);
}

uint64 stg_get_current_term(uint32 stream_id)
{
    return stream_get_current_term(&g_streams[stream_id]);
}

status_t stg_set_votedfor(uint32 stream_id, uint32 votedfor)
{
    return stream_set_votedfor(&g_streams[stream_id], votedfor);
}

uint32 stg_get_votedfor(uint32 stream_id)
{
    return stream_get_votedfor(&g_streams[stream_id]);
}

int64 stg_get_total_mem_used()
{
    uint32 count;
    int64 total_mem = 0;
    uint32 stream_id[CM_MAX_STREAM_COUNT];
    if (md_get_stream_list(stream_id, &count) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[STG]cal total mem, get stream metadata failed");
        return 0;
    }
    for (uint32 i = 0; i < count; ++i) {
        if (stream_id[i] >= CM_MAX_STREAM_COUNT) {
            continue;
        }
        stream_t *stream = &g_streams[stream_id[i]];
        // mem of stream
        total_mem += stream->mem_pool.used_size;
        // mem of storage
        total_mem += stream->log_storage.mem_pool.used_size;
    }

    return total_mem;
}