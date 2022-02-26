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
 * batcher.h
 *    batch flush
 *
 * IDENTIFICATION
 *    src/storage/batcher.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __BATCHER_H__
#define __BATCHER_H__

#include "cm_log.h"
#include "cm_defs.h"
#include "log_storage.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_batcher {
    char        *buf;
    uint32       size;
    uint64       offset;
    uint32       capacity;
    uint64       last_term;
    uint64       last_index;
    index_buf_t  ibuf;
    segment_t   *segment;
}batcher_t;

static inline status_t create_batcher(batcher_t *batcher, uint32 capacity)
{
    if (capacity == 0 || capacity > SIZE_G(1)) {
        LOG_DEBUG_ERR("[STG]Create batcher malloc buf %u is not allowed", capacity);
        return CM_ERROR;
    }
    batcher->size     = 0;
    batcher->capacity = capacity;
    batcher->buf      = (char *)malloc(capacity);
    if (batcher->buf == NULL) {
        LOG_DEBUG_ERR("[STG]Create batcher malloc buf %u failed", capacity);
        return CM_ERROR;
    }
    index_buf_init(&batcher->ibuf);
    return CM_SUCCESS;
}

static inline void destroy_batcher(batcher_t *batcher)
{
    if (batcher->buf != NULL) {
        CM_FREE_PTR(batcher->buf);
        batcher->buf = NULL;
    }
    index_buf_deinit(&batcher->ibuf);
}

static inline status_t batcher_begin(log_storage_t *storage, batcher_t *batcher)
{
    // this latch will be unlatched in batcher_end function
    cm_latch_s(&storage->trunc_latch, 0, CM_FALSE, NULL);
    batcher->segment = get_open_segment(storage);
    if (batcher->segment == NULL) {
        cm_unlatch(&storage->trunc_latch, NULL);
        return CM_ERROR;
    }

    batcher->size       = 0;
    batcher->offset     = batcher->segment->size;
    batcher->last_index = batcher->segment->last_index;
    index_buf_resize(&batcher->ibuf, 0);
    return CM_SUCCESS;
}

static inline void batcher_end(log_storage_t *storage, batcher_t *batcher)
{
    if (SECUREC_UNLIKELY(batcher->segment == NULL)) {
        return;
    }
    segment_dec_def(batcher->segment);
    batcher->size    = 0;
    batcher->segment = NULL;
    cm_unlatch(&storage->trunc_latch, NULL);
}

status_t batcher_flush(log_storage_t *storage, batcher_t *batcher);

status_t batcher_append(log_storage_t *log_storage, batcher_t *batcher, const log_entry_t *entry);

#ifdef __cplusplus
}
#endif

#endif