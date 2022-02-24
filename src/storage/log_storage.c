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
 * log_storage.c
 *    log storage
 *
 * IDENTIFICATION
 *    src/storage/log_storage.c
 *
 * -------------------------------------------------------------------------
 */

#include "log_storage.h"
#include "cm_list.h"
#include "cm_text.h"
#include "cm_checksum.h"
#include "meta_storage.h"


static inline bool32 is_valid_log_file(const char *file_name, bool32 is_empty)
{
    if ((is_empty && strncmp(file_name, "log_", strlen("log_")) == 0) ||
        (strncmp(file_name + (strlen(file_name) - strlen(".tmp")), ".tmp", strlen(".tmp"))) == 0) {
        return CM_FALSE;
    }
    return CM_TRUE;
}

static inline segment_t *alloc_segment(char *home, uint64 first_index, uint64 last_index, bool32 is_open)
{
    segment_t *segment = (segment_t *)malloc(sizeof(segment_t));
    if (segment == NULL) {
        LOG_DEBUG_ERR("[STG]alloc_segment malloc failed");
        return NULL;
    }

    segment->fd          = -1;
    segment->home        = home;
    segment->size        = 0;
    segment->valid       = CM_TRUE;
    segment->is_open     = is_open;
    segment->ref_count   = 0;
    segment->last_index  = last_index;
    segment->first_index = first_index;
    cm_latch_init(&segment->latch);
    index_buf_init(&segment->indexes);
    return segment;
}

static inline segment_t *create_open_segment(log_storage_t *storage)
{
    char file_name[CM_MAX_PATH_LEN];

    if (make_file_name(file_name, storage->home, storage->last_index + 1,
        storage->last_index, CM_TRUE) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[STG]create_open_segment make file name failed");
        return NULL;
    }

    segment_t *segment = alloc_segment(storage->home, storage->last_index + 1, storage->last_index, CM_TRUE);
    if (segment == NULL) {
        LOG_DEBUG_ERR("[STG]create_open_segment alloc_segment failed");
        return NULL;
    }

    if (cm_create_file(file_name, O_RDWR | O_TRUNC | O_BINARY | O_SYNC, &(segment->fd)) != CM_SUCCESS) {
        destroy_segment_object(segment);
        LOG_DEBUG_ERR("[STG]create_open_segment create file failed");
        return NULL;
    }
    return segment;
}

segment_t *get_open_segment(log_storage_t *storage)
{
    cm_latch_x(&storage->latch, 0, NULL);
    if (storage->open_segment == NULL) {
        storage->open_segment = create_open_segment(storage);
    } else if (storage->open_segment->size >= storage->segment_size) {
        if (bucket_list_add(&storage->segments, storage->open_segment) != CM_SUCCESS) {
            cm_unlatch(&storage->latch, NULL);
            LOG_DEBUG_ERR("[STG]get_open_segment add segment failed");
            return NULL;
        }
        if (switch_segment_to(storage->open_segment, CM_FALSE) != CM_SUCCESS) {
            bucket_list_del_last(&storage->segments);
            cm_unlatch(&storage->latch, NULL);
            LOG_DEBUG_ERR("[STG]get_open_segment switch segment failed");
            return NULL;
        }
        storage->open_segment = create_open_segment(storage);
    }

    if (storage->open_segment != NULL) {
        segment_inc_def(storage->open_segment);
    }

    cm_unlatch(&storage->latch, NULL);
    return storage->open_segment;
}

static status_t load_segment(log_storage_t *storage, char *file_name, bool32 is_empty)
{
    if (CM_STR_EQUAL(file_name, ".") || CM_STR_EQUAL(file_name, "..") || CM_STR_EQUAL(file_name, STG_LOG_META) ||
        CM_STR_EQUAL(file_name, STG_RAFT_META_01) || CM_STR_EQUAL(file_name, STG_RAFT_META_02)) {
        return CM_SUCCESS;
    }

    if (!is_valid_log_file(file_name, is_empty)) {
        return stg_remove_file(storage->home, file_name);
    }

    uint64 first_index = 0;
    uint64 last_index = 0;
    segment_t *segment = NULL;
    int match = sscanf_s(file_name, STG_CLOSE_PATTERN, &first_index, &last_index);
    if (match == 2) {
        segment = alloc_segment(storage->home, first_index, last_index, CM_FALSE);
        if (segment == NULL) {
            return CM_ERROR;
        }
        if (bucket_list_add(&storage->segments, segment) != CM_SUCCESS) {
            destroy_segment_object(segment);
            return CM_ERROR;
        }
        return CM_SUCCESS;
    }

    match = sscanf_s(file_name, STG_OPEN_PATTERN, &first_index);
    if (match != 1) {
        LOG_DEBUG_ERR("[STG]Invalid log file %s", file_name);
        return CM_ERROR;
    }

    if (storage->open_segment != NULL) {
        LOG_DEBUG_ERR("[STG]Invalid log file %s", file_name);
        return CM_ERROR;
    }

    storage->open_segment = alloc_segment(storage->home, first_index, first_index - 1, CM_TRUE);
    return storage->open_segment == NULL ? CM_ERROR : CM_SUCCESS;
}

static status_t check_segments(log_storage_t *storage)
{
    uint64 last_index = CM_INVALID_ID64;

    for (uint32 i = 0; i < storage->segments.size; ++i) {
        segment_t *segment = (segment_t *)bucket_list_get(&storage->segments, i);
        if (segment->first_index > segment->last_index) {
            LOG_DEBUG_ERR("[STG]Segment first index is greater than last index");
            return CM_ERROR;
        }
        if (last_index != CM_INVALID_ID64 && segment->first_index != last_index + 1) {
            LOG_DEBUG_ERR("[STG]Index is discontinuous between segments");
            return CM_ERROR;
        }
        if (last_index == CM_INVALID_ID64 && segment->first_index > storage->first_index) {
            LOG_DEBUG_ERR("[STG]First segment's first index is greater than storage's");
            return CM_ERROR;
        }
        if (last_index == CM_INVALID_ID64 && segment->last_index < storage->first_index) {
            LOG_DEBUG_WAR("[STG]Segment is garbage data, remove it");
            bucket_list_del_first(&storage->segments);
            (void)destroy_segment_instance(segment);
            continue;
        }
        last_index = segment->last_index;
    }

    if (storage->open_segment != NULL) {
        if (last_index == CM_INVALID_ID64 && storage->open_segment->first_index > storage->first_index) {
            LOG_DEBUG_ERR("[STG]First segment's first index is greater than storage's");
            return CM_ERROR;
        }
        if (last_index != CM_INVALID_ID64 && storage->open_segment->first_index != last_index + 1) {
            LOG_DEBUG_ERR("[STG]Index is discontinuous between segments");
            return CM_ERROR;
        }
    }

    storage->last_index = last_index != CM_INVALID_ID64 ? last_index : storage->last_index;
    return CM_SUCCESS;
}

static status_t list_segments(log_storage_t *storage, bool32 is_empty)
{
#ifdef WIN32
    intptr_t handle;
    struct _finddata_t fileData;
    char file_name[CM_MAX_PATH_LEN] = { 0 };
    char *prefix = (char *)"log_*";

    PRTS_RETURN_IFERR(snprintf_s(file_name, CM_MAX_PATH_LEN, CM_MAX_PATH_LEN - 1, "%s/%s", storage->home, prefix));

    handle = (intptr_t)_findfirst(file_name, &fileData);
    if (-1L == handle) {
        return CM_SUCCESS;
    }
    if (load_segment(storage, (char *)fileData.name, is_empty) != CM_SUCCESS) {
        _findclose(handle);
        return CM_ERROR;
    }
    while (_findnext(handle, &fileData) == 0) {
        if (load_segment(storage, (char *)fileData.name, is_empty) != CM_SUCCESS) {
            _findclose(handle);
            return CM_ERROR;
        }
    }
    _findclose(handle);
#else
    DIR *dirPtr = NULL;
    struct dirent *direntPtr = NULL;

    dirPtr = opendir(storage->home);
    if (dirPtr == NULL) {
        return CM_ERROR;
    }

    direntPtr = readdir(dirPtr);
    while (direntPtr != NULL) {
        if (load_segment(storage, (char *)direntPtr->d_name, is_empty) != CM_SUCCESS) {
            (void)closedir(dirPtr);
            return CM_ERROR;
        }
        direntPtr = readdir(dirPtr);
    }
    (void)closedir(dirPtr);
#endif
    return CM_SUCCESS;
}

static inline int32 segment_cmp_2(const pointer_t seg1, const pointer_t seg2)
{
    if (((segment_t*)seg1)->last_index < ((segment_t*)seg2)->first_index) {
        return -1;
    }

    if (((segment_t*)seg1)->first_index > ((segment_t*)seg2)->last_index) {
        return 1;
    }
    return 0;
}

static status_t load_segments(log_storage_t *storage, bool32 is_empty)
{
    if (list_segments(storage, is_empty) != CM_SUCCESS) {
        return CM_ERROR;
    }

    bucket_list_sort(&storage->segments, segment_cmp_2);
    return check_segments(storage);
}

static status_t load_open_segment_index(log_storage_t *storage)
{
    segment_t *segment = storage->open_segment;
    if (segment != NULL) {
        CM_RETURN_IFERR(try_load_index(segment));
        if (segment->last_index < storage->first_index) {
            storage->open_segment = NULL;
            LOG_DEBUG_WAR("[STG]open file is garbage data");
            CM_RETURN_IFERR(destroy_segment_instance(segment));
        } else {
            storage->last_index = segment->last_index;
            storage->last_term = segment_get_term(segment, segment->last_index);
        }
    }
    if (storage->last_index == 0) {
        storage->last_index = storage->first_index - 1;
    }
    return CM_SUCCESS;
}

void destroy_log_storage(log_storage_t *storage)
{
    if (storage->open_segment != NULL) {
        try_destroy_segment_object(storage->open_segment);
    }

    while (!bucket_list_empty(&storage->segments)) {
        segment_t *segment = bucket_list_first(&storage->segments);
        bucket_list_del_first(&storage->segments);
        try_destroy_segment_object(segment);
    }
    bucket_list_deinit(&storage->segments);
    buddy_pool_deinit(&storage->mem_pool);
}

static status_t save_log_meta(log_storage_t *storage, uint64 first_kept_index)
{
    char file_name[CM_MAX_PATH_LEN];
    PRTS_RETURN_IFERR(snprintf_s(file_name, CM_MAX_PATH_LEN, CM_MAX_PATH_LEN - 1, "%s/%s",
        storage->home, STG_LOG_META));

    int32 fd = -1;
    CM_RETURN_IFERR(cm_open_file(file_name, O_RDWR | O_CREAT | O_BINARY, &fd));

    char buf[LOG_META_LENGTH];
    *(uint64*)(buf + LOG_META_OF_FST_INDEX) = first_kept_index;
    uint32 checksum = cm_get_checksum(buf, LOG_META_LENGTH - sizeof(uint32));
    *(uint32*)(buf + LOG_META_OF_CHECKSUM)  = checksum;

    if (cm_write_file(fd, buf, (int32)LOG_META_LENGTH) != CM_SUCCESS) {
        cm_close_file(fd);
        return CM_ERROR;
    }

    status_t status = cm_fdatasync_file(fd);
    cm_close_file(fd);
    return status;
}

static status_t load_log_meta(log_storage_t *storage, bool32 *is_empty)
{
    char  file_name[CM_MAX_PATH_LEN];

    PRTS_RETURN_IFERR(snprintf_s(file_name, CM_MAX_PATH_LEN, CM_MAX_PATH_LEN - 1, "%s/%s",
        storage->home, STG_LOG_META));
    if (!cm_file_exist(file_name)) {
        *is_empty = CM_TRUE;
        return save_log_meta(storage, storage->first_index);
    }

    int32 fd = -1;
    if (cm_open_file(file_name, O_RDONLY | O_BINARY, &fd) != CM_SUCCESS) {
        return CM_ERROR;
    }

    int32 read_size;
    char  buf[LOG_META_LENGTH];
    if (cm_read_file(fd, buf, LOG_META_LENGTH, &read_size) != CM_SUCCESS || read_size != LOG_META_LENGTH) {
        cm_close_file(fd);
        LOG_DEBUG_ERR("[STG]Read log meta file failed");
        return CM_ERROR;
    }
    cm_close_file(fd);
    uint32 chksum = *(uint32 *)(buf + LOG_META_OF_CHECKSUM);
    if (!cm_verify_checksum(buf, LOG_META_LENGTH - sizeof(uint32), chksum)) {
        LOG_DEBUG_ERR("[STG]Read log meta file failed, mismatch checksum");
        return CM_ERROR;
    }
    storage->first_index = *(uint64 *)(buf + LOG_META_OF_FST_INDEX);
    return CM_SUCCESS;
}

static status_t load_log_storage(log_storage_t *storage)
{
    bool32 is_empty = CM_FALSE;

    if (load_log_meta(storage, &is_empty) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (load_segments(storage, is_empty) != CM_SUCCESS) {
        return CM_ERROR;
    }

    return load_open_segment_index(storage);
}

status_t init_log_storage(log_storage_t *storage, char *home, uint64 applied_index)
{
    storage->home         = home;
    storage->first_index  = 1;
    storage->last_index   = 0;
    storage->open_segment = NULL;
    cm_latch_init(&storage->latch);
    cm_latch_init(&storage->trunc_latch);

    param_value_t init_size, max_size, file_size;
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_STG_POOL_INIT_SIZE, &init_size));
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_STG_POOL_MAX_SIZE, &max_size));
    CM_RETURN_IFERR(buddy_pool_init("storage", init_size.stg_pool_init_size,
        max_size.stg_pool_max_size, &storage->mem_pool));
    CM_RETURN_IFERR(bucket_list_init(&storage->segments));
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_DATA_FILE_SIZE, &file_size));
    storage->segment_size = file_size.data_file_size;
    CM_RETURN_IFERR(load_log_storage(storage));

    if (storage->last_index != CM_INVALID_INDEX_ID || applied_index == CM_INVALID_INDEX_ID) {
        return CM_SUCCESS;
    }
    storage->first_index = applied_index + 1;
    storage->last_index  = applied_index;
    return save_log_meta(storage, storage->first_index);
}

static inline int32 segment_cmp(const segment_t *segment, uint64 index)
{
    if (index < segment->first_index) {
        return -1;
    }

    if (index > segment->last_index) {
        return 1;
    }
    return 0;
}

static segment_t* find_archive_segment(bucket_list_t *list, uint64 index)
{
    uint32 curr;
    uint32 begin = 0;
    uint32 end = list->size;

    while (begin < end) {
        curr = (begin + end) / CM_2X_FIXED;
        segment_t *segment = (segment_t *)bucket_list_get(list, curr);
        int32 result = segment_cmp(segment, index);
        if (result > 0) {
            begin = curr + 1;
        } else if (result < 0) {
            end = curr;
        } else {
            return segment;
        }
    }
    return NULL;
}

static segment_t* get_segment(log_storage_t *storage, uint64 index)
{
    cm_latch_s(&storage->latch, 0, CM_FALSE, NULL);
    if (storage->first_index == storage->last_index + 1) {
        cm_unlatch(&storage->latch, NULL);
        return NULL;
    }

    if (index < storage->first_index || index > storage->last_index) {
        cm_unlatch(&storage->latch, NULL);
        return NULL;
    }

    segment_t *segment = storage->open_segment;
    if (segment == NULL || index < segment->first_index) {
        segment = find_archive_segment(&storage->segments, index);
    }

    if (segment == NULL) {
        cm_unlatch(&storage->latch, NULL);
        return NULL;
    }

    segment_inc_def(segment);
    cm_unlatch(&storage->latch, NULL);

    if (try_load_index(segment) != CM_SUCCESS) {
        segment_dec_def(segment);
        return NULL;
    }
    return segment;
}

log_entry_t* storage_get_entry(log_storage_t *storage, uint64 index)
{
    segment_t *segment = get_segment(storage, index);
    if (segment == NULL) {
        return NULL;
    }

    log_entry_t *log_entry = segment_get_entry(segment, index, &storage->mem_pool);
    segment_dec_def(segment);
    return log_entry;
}

status_t storage_write_entry_impl(log_storage_t *storage, log_entry_t *entry)
{
    segment_t *segment = get_open_segment(storage);
    if (segment == NULL) {
        return CM_ERROR;
    }

    CM_ASSERT(storage->last_index == segment->last_index);
    if (ENTRY_INDEX(entry) != segment->last_index + 1) {
        LOG_DEBUG_WAR("[STG]Invalid log index %llu, segment's %llu", ENTRY_INDEX(entry), segment->last_index + 1);
        segment_dec_def(segment);
        return CM_SUCCESS;
    }

    if (segment_write_entry(segment, entry) != CM_SUCCESS) {
        segment_dec_def(segment);
        return CM_ERROR;
    }

    cm_latch_x(&storage->latch, 0, NULL);
    storage->last_index++;
    storage->last_term = ENTRY_TERM(entry);
    cm_unlatch(&storage->latch, NULL);

    segment_dec_def(segment);
    return CM_SUCCESS;
}

status_t storage_write_entry(log_storage_t *storage, log_entry_t *entry)
{
    cm_latch_s(&storage->trunc_latch, 0, CM_FALSE, NULL);
    status_t status = storage_write_entry_impl(storage, entry);
    cm_unlatch(&storage->trunc_latch, NULL);
    return status;
}

uint64 storage_get_term(log_storage_t *storage, uint64 index)
{
    segment_t *segment = get_segment(storage, index);
    if (segment == NULL) {
        return CM_INVALID_TERM_ID;
    }

    uint64 term = segment_get_term(segment, index);
    segment_dec_def(segment);
    return term;
}

static status_t pop_segment_from_first(log_storage_t *storage, uint64 first_index_kept, ptlist_t *list)
{
    cm_latch_x(&storage->latch, 0, NULL);
    storage->first_index = first_index_kept;

    while (!bucket_list_empty(&storage->segments)) {
        segment_t *segment = bucket_list_first(&storage->segments);
        if (segment->last_index >= first_index_kept) {
            cm_unlatch(&storage->latch, NULL);
            return CM_SUCCESS;
        }
        if (cm_ptlist_add(list, segment) != CM_SUCCESS) {
            cm_unlatch(&storage->latch, NULL);
            return CM_ERROR;
        }
        bucket_list_del_first(&storage->segments);
    }

    if (storage->open_segment == NULL) {
        storage->last_index = first_index_kept - 1;
        cm_unlatch(&storage->latch, NULL);
        return CM_SUCCESS;
    }

    if (storage->open_segment->last_index < first_index_kept) {
        if (cm_ptlist_add(list, storage->open_segment) != CM_SUCCESS) {
            cm_unlatch(&storage->latch, NULL);
            return CM_ERROR;
        }
        storage->open_segment = NULL;
        storage->last_index = first_index_kept - 1;
    }
    cm_unlatch(&storage->latch, NULL);
    return CM_SUCCESS;
}

static status_t storage_trunc_prefix_impl(log_storage_t *storage, uint64 first_index_kept)
{
    if (save_log_meta(storage, first_index_kept) != CM_SUCCESS) {
        return CM_ERROR;
    }

    ptlist_t remove_list;
    cm_ptlist_init(&remove_list);

    if (pop_segment_from_first(storage, first_index_kept, &remove_list) != CM_SUCCESS) {
        cm_destroy_ptlist(&remove_list);
        return CM_ERROR;
    }

    for (uint32 i = 0; i < remove_list.count; ++i) {
        segment_t *segment = (segment_t *)cm_ptlist_get(&remove_list, i);
        (void)destroy_segment_instance(segment);
    }

    cm_destroy_ptlist(&remove_list);
    return CM_SUCCESS;
}

status_t storage_trunc_prefix(log_storage_t *storage, uint64 first_index_kept)
{
    cm_latch_x(&storage->trunc_latch, 0, NULL);
    status_t status = storage_trunc_prefix_impl(storage, first_index_kept);
    cm_unlatch(&storage->trunc_latch, NULL);
    return status;
}

static status_t storage_unsafe_trunc_suffix(log_storage_t *storage, uint64 last_index_kept, uint64 last_term,
    segment_t **last_segment)
{
    storage->last_term  = last_term;
    storage->last_index = last_index_kept;

    if (storage->open_segment != NULL) {
        if (storage->open_segment->first_index <= last_index_kept) {
            *last_segment = storage->open_segment;
            return CM_SUCCESS;
        }
        CM_RETURN_IFERR(segment_unlink(storage->open_segment));
        try_destroy_segment_object(storage->open_segment);
        storage->open_segment = NULL;
    }

    while (!bucket_list_empty(&storage->segments)) {
        segment_t *segment = bucket_list_last(&storage->segments);
        if (segment->first_index <= last_index_kept) {
            break;
        }
        CM_RETURN_IFERR(segment_unlink(segment));
        bucket_list_del_last(&storage->segments);
        try_destroy_segment_object(segment);
    }

    if (bucket_list_empty(&storage->segments)) {
        storage->first_index = last_index_kept + 1;
        return CM_SUCCESS;
    }
    *last_segment = bucket_list_last(&storage->segments);
    return CM_SUCCESS;
}

static status_t storage_trunc_suffix_impl(log_storage_t *storage, uint64 last_index_kept, uint64 last_term)
{
    segment_t *last_segment = NULL;

    cm_latch_x(&storage->latch, 0, NULL);
    if (storage_unsafe_trunc_suffix(storage, last_index_kept, last_term, &last_segment) != CM_SUCCESS) {
        cm_unlatch(&storage->latch, NULL);
        return CM_ERROR;
    }

    if (last_segment == NULL) {
        cm_unlatch(&storage->latch, NULL);
        return CM_SUCCESS;
    }

    bool32 is_closed = !last_segment->is_open;
    if (segment_trunc_suffix(last_segment, last_index_kept) != CM_SUCCESS) {
        cm_unlatch(&storage->latch, NULL);
        return CM_ERROR;
    }

    if (is_closed == CM_FALSE || last_segment->is_open == CM_FALSE) {
        cm_unlatch(&storage->latch, NULL);
        return CM_SUCCESS;
    }

    bucket_list_del_last(&storage->segments);
    storage->open_segment = last_segment;
    cm_unlatch(&storage->latch, NULL);
    return CM_SUCCESS;
}

status_t storage_trunc_suffix(log_storage_t *storage, uint64 last_index_kept, uint64 last_term)
{
    cm_latch_x(&storage->trunc_latch, 0, NULL);
    status_t status = storage_trunc_suffix_impl(storage, last_index_kept, last_term);
    cm_unlatch(&storage->trunc_latch, NULL);
    return status;
}
