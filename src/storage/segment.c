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
 * segment.c
 *
 *
 * IDENTIFICATION
 *    src/storage/segment.c
 *
 * -------------------------------------------------------------------------
 */

#include "segment.h"
#include "cm_list.h"
#include "cm_text.h"
#include "stream.h"
#include "cm_checksum.h"
#include "util_profile_stat.h"

status_t switch_segment_to(segment_t *segment, bool32 to_open)
{
#ifdef WIN32
    release_segment_resource(segment);
#endif
    char old_name[CM_MAX_PATH_LEN];
    CM_RETURN_IFERR(make_file_name(old_name, segment->home, segment->first_index, segment->last_index, !to_open));

    char new_name[CM_MAX_PATH_LEN];
    CM_RETURN_IFERR(make_file_name(new_name, segment->home, segment->first_index, segment->last_index, to_open));

    CM_RETURN_IFERR(cm_rename_file(old_name, new_name));
    segment->is_open = to_open;
    return CM_SUCCESS;
}

static inline void decode_entry_head(const char *buf, entry_head_t *head)
{
    head->term  = *(uint64*)(buf + OFFSET_OF_TERM);
    head->index = *(uint64*)(buf + OFFSET_OF_INDEX);
    head->key   = *(uint64*)(buf + OFFSET_OF_KEY);
    head->type  = *(uint32*)(buf + OFFSET_OF_TYPE);
    head->size  = *(uint32*)(buf + OFFSET_OF_SIZE);
    head->data_chksum = *(uint32*)(buf + OFFSET_OF_DATA_CHKSUM);
    head->head_chksum = *(uint32*)(buf + OFFSET_OF_HEAD_CHKSUM);
}

status_t load_log_entry(int32 fd, int64 offset, char *buf, uint32 size, entry_head_t *head, bool32 *is_valid)
{
    int32 read_size;

    size = MAX(size, ENTRY_HEAD_SIZE);
    CM_RETURN_IFERR(cm_pread_file(fd, buf, size, offset, &read_size));
    *is_valid = read_size != size ? CM_FALSE : CM_TRUE;
    if (!(*is_valid)) {
        return CM_SUCCESS;
    }

    decode_entry_head(buf, head);
    if (!cm_verify_checksum(buf, ENTRY_HEAD_SIZE - sizeof(uint32), head->head_chksum)) {
        LOG_DEBUG_ERR("[STG]Log entry head checksum is invalid at offset:%lld", offset);
        *is_valid = CM_FALSE;
        return CM_SUCCESS;
    }

    if (size == ENTRY_HEAD_SIZE) {
        return CM_SUCCESS;
    }

    if (!cm_verify_checksum(buf + ENTRY_HEAD_SIZE, head->size, head->data_chksum)) {
        LOG_DEBUG_ERR("[STG]Log entry data checksum is invalid at offset:%lld", offset);
        *is_valid = CM_FALSE;
        return CM_SUCCESS;
    }
    return CM_SUCCESS;
}

static status_t load_index(segment_t *segment)
{
    char log_file[CM_MAX_PATH_LEN];

    CM_RETURN_IFERR(make_file_name(log_file, segment->home, segment->first_index, segment->last_index,
        segment->is_open));
    CM_RETURN_IFERR(cm_open_file(log_file, O_BINARY | O_RDWR | O_SYNC, &segment->fd));

    int64  entry_off  = 0;
    bool32 is_valid   = CM_TRUE;
    uint64 last_index = segment->first_index - 1;
    int64  file_size  = cm_file_size(segment->fd);

    entry_head_t entry_head;
    char  head_buf[ENTRY_HEAD_SIZE];

    for (int64 i = segment->first_index; entry_off < file_size; i++) {
        CM_RETURN_IFERR(load_log_entry(segment->fd, entry_off, head_buf, ENTRY_HEAD_SIZE, &entry_head, &is_valid));
        if (!is_valid) { // The last log was not completely written, which should be truncated
            break;
        }
        int64 skip_len = entry_head.size + ENTRY_HEAD_SIZE;
        if (entry_off + skip_len > file_size) {
            // The last log was not completely written and it should be truncated
            break;
        }
        log_index_t log_index;
        log_index.term   = entry_head.term;
        log_index.offset = (uint64)entry_off;
        CM_RETURN_IFERR(index_buf_add(&segment->indexes, &log_index));
        ++last_index;
        entry_off += skip_len;
    }

    if (segment->is_open) {
        segment->last_index = last_index;
    } else if (last_index < segment->last_index) {
        LOG_DEBUG_ERR("[STG]Last index does not match between file and segment");
        return CM_ERROR;
    }

    // truncate last uncompleted entry
    if (entry_off != file_size) {
        CM_RETURN_IFERR(cm_truncate_file(segment->fd, entry_off));
    }

    // seek to end, for opening segment
    if (cm_seek_file(segment->fd, entry_off, SEEK_SET) < 0) {
        return CM_ERROR;
    }
    segment->size = (uint64)entry_off;
    return CM_SUCCESS;
}

status_t try_load_index(segment_t *segment)
{
    if (segment->fd != -1) {
        return CM_SUCCESS;
    }

    cm_latch_x(&segment->latch, 0, NULL);
    if (segment->fd != -1) {
        cm_unlatch(&segment->latch, NULL);
        return CM_SUCCESS;
    }

    if (load_index(segment) != CM_SUCCESS) {
        release_segment_resource(segment);
        cm_unlatch(&segment->latch, NULL);
        return CM_ERROR;
    }

    cm_unlatch(&segment->latch, NULL);
    return CM_SUCCESS;
}

static status_t segment_get_log_meta(segment_t *segment, uint64 index, log_meta_t *meta)
{
    cm_latch_s(&segment->latch, 0, CM_FALSE, NULL);
    if (segment->first_index == segment->last_index + 1) {
        cm_unlatch(&segment->latch, NULL);
        return CM_ERROR;
    }

    if (index > segment->last_index || index < segment->first_index) {
        cm_unlatch(&segment->latch, NULL);
        return CM_ERROR;
    }

    log_index_t curr, next;
    uint32 curr_idx = (uint32)(index - segment->first_index);
    if (index_buf_get(&segment->indexes, curr_idx, &curr) != CM_SUCCESS) {
        cm_unlatch(&segment->latch, NULL);
        return CM_ERROR;
    }

    meta->term   = curr.term;
    meta->offset = curr.offset;
    if (index < segment->last_index) {
        if (index_buf_get(&segment->indexes, curr_idx + 1, &next) != CM_SUCCESS) {
            cm_unlatch(&segment->latch, NULL);
            return CM_ERROR;
        }
        meta->size = (uint32)((next.offset - curr.offset) - ENTRY_HEAD_SIZE);
    } else {
        meta->size = (uint32)((segment->size - curr.offset) - ENTRY_HEAD_SIZE);
    }
    cm_unlatch(&segment->latch, NULL);
    return CM_SUCCESS;
}

log_entry_t* segment_get_entry(segment_t *segment, uint64 index, mem_pool_t *pool)
{
    log_meta_t meta;
    if (segment_get_log_meta(segment, index, &meta) != CM_SUCCESS) {
        return NULL;
    }

    uint32 total_size = sizeof(log_entry_t) + ENTRY_HEAD_SIZE + meta.size;
    log_entry_t *entry = (log_entry_t*)galloc(total_size, pool);
    if (entry == NULL) {
        LOG_DEBUG_ERR("[STG]segment_get_entry alloc entry failed");
        return NULL;
    }
    entry->ref_count = 1;
    entry->valid     = CM_FALSE;
    entry->from_pool = CM_TRUE;
    entry->data      = (char *)entry + sizeof(log_entry_t);
    cm_latch_init(&entry->latch);

    bool32 is_valid = CM_TRUE;
    char  *io_buf   = entry->data;
    uint32 io_size  = meta.size + ENTRY_HEAD_SIZE;
    entry_head_t entry_head;
    if (load_log_entry(segment->fd, meta.offset, io_buf, io_size, &entry_head, &is_valid) != CM_SUCCESS || !is_valid) {
        gfree(entry);
        return NULL;
    }

    if (entry_head.term != meta.term) {
        LOG_DEBUG_ERR("[STG]Mismatch term  %llu with index %llu", entry_head.term, meta.term);
        gfree(entry);
        return NULL;
    }
    return entry;
}

status_t segment_write_entry(segment_t *segment, log_entry_t *entry)
{
    char  *io_buf  = entry->data;
    uint32 io_size = ENTRY_LENGTH(entry);
    if (cm_pwrite_file_stat(segment->fd, io_buf, (int32)io_size, (int64)segment->size) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[STG]segment_write_entry:write segment file failed");
        return CM_ERROR;
    }

    write_conf_func_t write_conf_func = get_write_conf_func();
    if (ENTRY_TYPE(entry) == ENTRY_TYPE_CONF && write_conf_func != NULL) {
        if (write_conf_func(ENTRY_BUF(entry), ENTRY_SIZE(entry)) != CM_SUCCESS) {
            LOG_DEBUG_ERR("[STG]segment_write_entry:write config file failed");
            return CM_ERROR;
        }
    }

    log_index_t log_index;
    cm_latch_x(&segment->latch, 0, NULL);
    log_index.offset = segment->size;
    log_index.term   = ENTRY_TERM(entry);
    if (index_buf_add(&segment->indexes, &log_index) != CM_SUCCESS) {
        cm_unlatch(&segment->latch, NULL);
        LOG_DEBUG_ERR("[STG]segment_write_entry:add index cache failed");
        return CM_ERROR;
    }

    segment->last_index++;
    segment->size += io_size;
    cm_unlatch(&segment->latch, NULL);
    return CM_SUCCESS;
}

uint64 segment_get_term(segment_t *segment, uint64 index)
{
    log_meta_t meta;
    if (segment_get_log_meta(segment, index, &meta) != CM_SUCCESS) {
        return CM_INVALID_TERM_ID;
    }
    return meta.term;
}

status_t segment_trunc_suffix(segment_t *segment, uint64 last_index_kept)
{
    if (last_index_kept >= segment->last_index) {
        return CM_SUCCESS;
    }

    // if segment is close, need switch to open
    if (!segment->is_open) {
        CM_RETURN_IFERR(switch_segment_to(segment, CM_TRUE));
    }

    CM_RETURN_IFERR(try_load_index(segment));

    cm_latch_s(&segment->latch, 0, CM_FALSE, NULL);
    uint32 trunc_id = (uint32)(last_index_kept + 1 - segment->first_index);
    log_index_t trunc_index;
    if (index_buf_get(&segment->indexes, trunc_id, &trunc_index) != CM_SUCCESS) {
        cm_unlatch(&segment->latch, NULL);
        return CM_ERROR;
    }
    cm_unlatch(&segment->latch, NULL);

    CM_RETURN_IFERR(cm_truncate_file(segment->fd, trunc_index.offset));
    // seek to end, for opening segment
    if (cm_seek_file(segment->fd, trunc_index.offset, SEEK_SET) < 0) {
        return CM_ERROR;
    }
    cm_latch_x(&segment->latch, 0, NULL);
    segment->size = trunc_index.offset;
    segment->last_index = last_index_kept;
    index_buf_resize(&segment->indexes, trunc_id);
    cm_unlatch(&segment->latch, NULL);
    return CM_SUCCESS;
}
