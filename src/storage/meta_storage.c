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
 * meta_storage.c
 *    meta storage
 *
 * IDENTIFICATION
 *    src/storage/meta_storage.c
 *
 * -------------------------------------------------------------------------
 */

#include "meta_storage.h"
#include "cm_checksum.h"
#include "md_defs.h"

static inline void encode_meta_info(stg_meta_t *stg_meta, char *buf)
{
    *(uint64*)(buf + META_OF_VERSION)   = ++stg_meta->version;
    *(uint64*)(buf + META_OF_CURR_TERM) = stg_meta->curr_term;
    *(uint32*)(buf + META_OF_VOTEDFOR)  = stg_meta->votedfor;
    uint32 checksum = cm_get_checksum(buf, STG_META_LENGTH - sizeof(uint32));
    *(uint32*)(buf + META_OF_CHECKSUM)  = checksum;
}

static inline status_t decode_meta_info(stg_meta_t *stg_meta, const char *buf)
{
    stg_meta->version   = *(uint64*)(buf + META_OF_VERSION);
    stg_meta->curr_term = *(uint64*)(buf + META_OF_CURR_TERM);
    stg_meta->votedfor  = *(uint32*)(buf + META_OF_VOTEDFOR);
    return CM_SUCCESS;
}

static status_t save_stg_meta(stg_meta_t *stg_meta)
{
    char file_name[CM_MAX_PATH_LEN];
    char *prefix = (stg_meta->version + 1) % CM_2X_FIXED == 0 ? STG_RAFT_META_02 : STG_RAFT_META_01;
    PRTS_RETURN_IFERR(snprintf_s(file_name, CM_MAX_PATH_LEN, CM_MAX_PATH_LEN - 1, "%s/%s", stg_meta->home, prefix));

    int32 fd = -1;
    CM_RETURN_IFERR(cm_open_file(file_name, O_RDWR | O_CREAT | O_BINARY | O_SYNC, &fd));

    char buf[STG_META_LENGTH];
    encode_meta_info(stg_meta, buf);

    status_t status = cm_write_file(fd, buf, (int32)STG_META_LENGTH);
    cm_close_file(fd);
    return status;
}

status_t read_meta_file(char *file_name, char *buf, bool32 *exists, bool32 *valid)
{
    *exists = cm_file_exist(file_name);
    if (!(*exists)) {
        return CM_SUCCESS;
    }

    int32 fd = -1;
    if (cm_open_file(file_name, O_RDONLY | O_BINARY, &fd) != CM_SUCCESS) {
        return CM_ERROR;
    }

    int32 read_size;
    if (cm_read_file(fd, buf, STG_META_LENGTH, &read_size) != CM_SUCCESS || read_size != STG_META_LENGTH) {
        cm_close_file(fd);
        LOG_DEBUG_ERR("[STG]Read meta file %s failed", file_name);
        return CM_ERROR;
    }
    cm_close_file(fd);
    uint32 chksum = *(uint32 *)(buf + META_OF_CHECKSUM);
    *valid = cm_verify_checksum(buf, STG_META_LENGTH - sizeof(uint32), chksum);
    return CM_SUCCESS;
}

static status_t load_stg_meta(stg_meta_t *stg_meta)
{
    bool32 exists = CM_FALSE;
    bool32 valid1 = CM_FALSE;
    bool32 valid2 = CM_FALSE;
    char  file_name[CM_MAX_PATH_LEN];
    char  stg_meta_01[STG_META_LENGTH];
    char  stg_meta_02[STG_META_LENGTH];

    PRTS_RETURN_IFERR(snprintf_s(file_name, CM_MAX_PATH_LEN, CM_MAX_PATH_LEN - 1,
        "%s/%s", stg_meta->home, STG_RAFT_META_01));
    CM_RETURN_IFERR(read_meta_file(file_name, stg_meta_01, &exists, &valid1));
    if (!exists) {
        return save_stg_meta(stg_meta);
    }

    PRTS_RETURN_IFERR(snprintf_s(file_name, CM_MAX_PATH_LEN, CM_MAX_PATH_LEN - 1,
        "%s/%s", stg_meta->home, STG_RAFT_META_02));
    CM_RETURN_IFERR(read_meta_file(file_name, stg_meta_02, &exists, &valid2));

    // stg_meta_02 not exists or invalid
    if (valid1 && !valid2) {
        return decode_meta_info(stg_meta, stg_meta_01);
    }

    // stg_meta_01 invalid, stg_meta_02 exists and valid
    if (!valid1 && valid2) {
        return decode_meta_info(stg_meta, stg_meta_02);
    }

    // both stg_meta_01 and stg_meta_02 all valid
    if (valid1 && valid2) {
        uint64 version1 = *(uint64*)(stg_meta_01 + META_OF_VERSION);
        uint64 version2 = *(uint64*)(stg_meta_02 + META_OF_VERSION);

        if (version1 > version2) {
            return decode_meta_info(stg_meta, stg_meta_01);
        }
        return decode_meta_info(stg_meta, stg_meta_02);
    }
    // both stg_meta_01 and stg_meta_02 all are invalid
    LOG_DEBUG_ERR("[STG]load_raft_meta failed: all ctrl files are invalid");
    return CM_ERROR;
}

status_t init_stg_meta(stg_meta_t *stg_meta, char *home)
{
    stg_meta->home      = home;
    stg_meta->version   = 0;
    stg_meta->curr_term = 1;
    stg_meta->votedfor  = CM_INVALID_NODE_ID;
    cm_latch_init(&stg_meta->latch);
    return load_stg_meta(stg_meta);
}

uint64 meta_get_current_term(stg_meta_t *stg_meta)
{
    cm_latch_s(&stg_meta->latch, 0, CM_FALSE, NULL);
    uint64 curr_term = stg_meta->curr_term;
    cm_unlatch(&stg_meta->latch, NULL);
    return curr_term;
}

status_t meta_set_current_term(stg_meta_t *stg_meta, uint64 term)
{
    cm_latch_x(&stg_meta->latch, 0, NULL);
    stg_meta->curr_term = term;
    status_t status = save_stg_meta(stg_meta);
    cm_unlatch(&stg_meta->latch, NULL);
    return status;
}

uint32 meta_get_votedfor(stg_meta_t *stg_meta)
{
    cm_latch_s(&stg_meta->latch, 0, CM_FALSE, NULL);
    uint32 votedfor = stg_meta->votedfor;
    cm_unlatch(&stg_meta->latch, NULL);
    return votedfor;
}

status_t meta_set_votedfor(stg_meta_t *stg_meta, uint32 votedfor)
{
    cm_latch_x(&stg_meta->latch, 0, NULL);
    stg_meta->votedfor = votedfor;
    status_t status = save_stg_meta(stg_meta);
    cm_unlatch(&stg_meta->latch, NULL);
    return status;
}
