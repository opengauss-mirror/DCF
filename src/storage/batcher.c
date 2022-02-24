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
 * batcher.c
 *    batch flush
 *
 * IDENTIFICATION
 *    src/storage/batcher.c
 *
 * -------------------------------------------------------------------------
 */

#include "batcher.h"
#include "util_profile_stat.h"

status_t batcher_append(log_storage_t *storage, batcher_t *batcher, const log_entry_t *entry)
{
    if (ENTRY_INDEX(entry) != batcher->last_index + 1) {
        LOG_DEBUG_WAR("[STG]Invalid log index %llu, segment's %llu", ENTRY_INDEX(entry), batcher->last_index + 1);
        return CM_SUCCESS;
    }

    log_index_t log_index;
    log_index.term   = ENTRY_TERM(entry);
    log_index.offset = batcher->offset + batcher->size;
    if (index_buf_add(&batcher->ibuf, &log_index) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[STG]batcher_append add index cache failed");
        return CM_ERROR;
    }

    if (memcpy_sp(batcher->buf + batcher->size, batcher->capacity - batcher->size,
        entry->data, ENTRY_LENGTH(entry)) != EOK) {
        LOG_DEBUG_ERR("[STG]batcher_append add entry to batch buf failed");
        return CM_ERROR;
    }

    batcher->last_index++;
    batcher->last_term = ENTRY_TERM(entry);
    batcher->size += ENTRY_LENGTH(entry);
    return CM_SUCCESS;
}

status_t batcher_flush(log_storage_t *storage, batcher_t *batcher)
{
    segment_t *segment = batcher->segment;
    if (cm_pwrite_file_stat(segment->fd, batcher->buf, (int32)batcher->size, (int64)batcher->offset) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[STG]batcher_flush write file failed");
        return CM_ERROR;
    }

    cm_latch_x(&segment->latch, 0, NULL);
    if (index_buf_add_batch(&segment->indexes, &batcher->ibuf) != CM_SUCCESS) {
        cm_unlatch(&segment->latch, NULL);
        LOG_DEBUG_ERR("[STG]batcher_flush add index failed");
        return CM_ERROR;
    }

    segment->size      += batcher->size;
    segment->last_index = batcher->last_index;
    cm_unlatch(&segment->latch, NULL);

    cm_latch_x(&storage->latch, 0, NULL);
    storage->last_term  = batcher->last_term;
    storage->last_index = batcher->last_index;
    cm_unlatch(&storage->latch, NULL);
    return CM_SUCCESS;
}