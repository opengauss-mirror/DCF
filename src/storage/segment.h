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
 * segment.h
 *
 *
 * IDENTIFICATION
 *    src/storage/segment.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __SEGMENT_H__
#define __SEGMENT_H__

#include "bucket_list.h"
#include "stg_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_log_index {
    uint64       term;
    uint64       offset;
}log_index_t;

typedef struct st_log_meta {
    uint32       size;
    uint64       term;
    uint64       offset;
}log_meta_t;

typedef struct st_index_buf {
    uint32       size;
    uint32       capacity;
    log_index_t *buf;
}index_buf_t;

typedef struct st_segment {
    int           fd;
    char         *home;
    uint64        first_index;
    uint64        last_index;
    uint64        size;
    latch_t       latch;
    bool32        valid;
    bool32        is_open;
    uint32        ref_count;
    index_buf_t   indexes;
}segment_t;

#define IBUF_EXTENT_SIZE  100000
static inline void index_buf_init(index_buf_t *ibuf)
{
    ibuf->size = 0;
    ibuf->buf = NULL;
    ibuf->capacity = 0;
}

static inline status_t index_buf_add(index_buf_t *ibuf, const log_index_t *log_index)
{
    if (ibuf->size >= ibuf->capacity) {
        uint32 buf_size = (ibuf->capacity + IBUF_EXTENT_SIZE) * sizeof(log_index_t);
        char *new_buf = (char *)malloc(buf_size);
        if (new_buf == NULL) {
            LOG_DEBUG_ERR("[STG]index_buf_add malloc %d failed", buf_size);
            return CM_ERROR;
        }

        if (ibuf->buf != NULL) {
            errno_t errcode = memcpy_sp(new_buf, (size_t)buf_size, ibuf->buf,
                (size_t)(ibuf->size * sizeof(log_index_t)));
            if (errcode != EOK) {
                CM_FREE_PTR(new_buf);
                LOG_DEBUG_ERR("[STG]index_buf_add memcpy_sp failed");
                return CM_ERROR;
            }
            CM_FREE_PTR(ibuf->buf);
        }
        ibuf->buf = (log_index_t *)new_buf;
        ibuf->capacity += IBUF_EXTENT_SIZE;
    }
    ibuf->buf[ibuf->size++] = *log_index;
    return CM_SUCCESS;
}

static inline status_t index_buf_add_batch(index_buf_t *dst, const index_buf_t *src)
{
    if (dst->size + src->size > dst->capacity) {
        uint32 buf_size = (dst->capacity + src->size + IBUF_EXTENT_SIZE) * sizeof(log_index_t);
        char *new_buf = (char *)malloc(buf_size);
        if (new_buf == NULL) {
            LOG_DEBUG_ERR("[STG]index_buf_add_batch malloc %d failed", buf_size);
            return CM_ERROR;
        }

        if (dst->buf != NULL) {
            errno_t errcode = memcpy_sp(new_buf, (size_t)buf_size, dst->buf, (size_t)(dst->size * sizeof(log_index_t)));
            if (errcode != EOK) {
                CM_FREE_PTR(new_buf);
                LOG_DEBUG_ERR("[STG]index_buf_add_batch memcpy_sp failed");
                return CM_ERROR;
            }
            CM_FREE_PTR(dst->buf);
        }
        dst->buf = (log_index_t *)new_buf;
        dst->capacity += IBUF_EXTENT_SIZE + src->size;
    }

    if (memcpy_sp(dst->buf + dst->size, (size_t)((dst->capacity - dst->size) * sizeof(log_index_t)),
                  src->buf, (size_t)(src->size * sizeof(log_index_t))) != EOK) {
        LOG_DEBUG_ERR("[STG]index_buf_add_batch memcpy_sp failed");
        return CM_ERROR;
    }
    dst->size += src->size;
    return CM_SUCCESS;
}

static inline status_t index_buf_get(const index_buf_t *ibuf, uint32 index, log_index_t *log_index)
{
    if (index >= ibuf->size) {
        return CM_ERROR;
    }
    *log_index = ibuf->buf[index];
    return CM_SUCCESS;
}

static inline void index_buf_resize(index_buf_t *ibuf, uint32 size)
{
    ibuf->size = size;
}

static inline void index_buf_deinit(index_buf_t *ibuf)
{
    if (ibuf->buf != NULL) {
        CM_FREE_PTR(ibuf->buf);
    }
    index_buf_init(ibuf);
}

typedef struct st_entry_head {
    uint64  term;
    uint64  index;
    uint64  key;
    uint32  type;
    uint32  size;
    uint32  data_chksum;
    uint32  head_chksum;
}entry_head_t;

#define STG_CLOSE_PATTERN "log_%020" "llu" "_%020" "llu"
#define STG_OPEN_PATTERN "log_inprogress_%020" "llu"

status_t try_load_index(segment_t *segment);
log_entry_t* segment_get_entry(segment_t *segment, uint64 index, mem_pool_t *pool);
status_t segment_write_entry(segment_t *segment, log_entry_t *log_entry);
uint64 segment_get_term(segment_t *segment, uint64 index);
status_t segment_trunc_suffix(segment_t *segment, uint64 last_index_kept);
status_t switch_segment_to(segment_t *segment, bool32 to_open);
status_t load_log_entry(int32 fd, int64 offset, char *buf, uint32 size, entry_head_t *head, bool32 *is_valid);

static inline status_t make_file_name(char *name, char *home, uint64 first_index, uint64 last_index, bool32 is_open)
{
    if (!is_open) {
        PRTS_RETURN_IFERR(snprintf_s(name, CM_MAX_PATH_LEN, CM_MAX_PATH_LEN - 1,
            "%s/" STG_CLOSE_PATTERN, home, first_index, last_index));
        return CM_SUCCESS;
    }

    PRTS_RETURN_IFERR(snprintf_s(name, CM_MAX_PATH_LEN, CM_MAX_PATH_LEN - 1,
        "%s/" STG_OPEN_PATTERN, home, first_index));
    return CM_SUCCESS;
}

static inline status_t segment_unlink(segment_t *segment)
{
#ifdef WIN32
    if (segment->fd != -1) {
        cm_close_file(segment->fd);
        segment->fd = -1;
    }
#endif
    char file_name[CM_MAX_PATH_LEN];
    CM_RETURN_IFERR(make_file_name(file_name, segment->home, segment->first_index,
        segment->last_index, segment->is_open));

    char tmp_name[CM_MAX_PATH_LEN];
    PRTS_RETURN_IFERR(snprintf_s(tmp_name, CM_MAX_PATH_LEN, CM_MAX_PATH_LEN - 1, "%s.tmp", file_name));
    return cm_rename_file(file_name, tmp_name);
}

static inline void release_segment_resource(segment_t *segment)
{
    if (segment->fd != -1) {
        cm_close_file(segment->fd);
        segment->fd = -1;
    }
    index_buf_deinit(&segment->indexes);
}

static inline void destroy_segment_object(segment_t *segment)
{
    release_segment_resource(segment);
    CM_FREE_PTR(segment);
}

static inline void try_destroy_segment_object(segment_t *segment)
{
    cm_latch_x(&segment->latch, 0, NULL);
    segment->valid = CM_FALSE;
    if (segment->ref_count > 0) {
        cm_unlatch(&segment->latch, NULL);
        return;
    }
    cm_unlatch(&segment->latch, NULL);
    destroy_segment_object(segment);
}

static inline status_t destroy_segment_instance(segment_t *segment)
{
    status_t status = segment_unlink(segment);
    try_destroy_segment_object(segment);
    return status;
}

static inline void segment_inc_def(segment_t *segment)
{
    cm_latch_x(&segment->latch, 0, NULL);
    segment->ref_count++;
    cm_unlatch(&segment->latch, NULL);
}

static inline void segment_dec_def(segment_t *segment)
{
    bool32 need_free = CM_FALSE;

    cm_latch_x(&segment->latch, 0, NULL);
    if (segment->ref_count == 1 && !segment->valid) {
        need_free = CM_TRUE;
    } else {
        segment->ref_count--;
    }
    cm_unlatch(&segment->latch, NULL);

    if (need_free) {
        destroy_segment_object(segment);
    }
}

#ifdef __cplusplus
}
#endif

#endif