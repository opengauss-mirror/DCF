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
 * md_store.c
 *    metadata process
 *
 * IDENTIFICATION
 *    src/metadata/md_store.c
 *
 * -------------------------------------------------------------------------
 */

#include "md_store.h"
#include "metadata.h"
#include "cm_checksum.h"

#define DCF_VERSION            "_dcf_version"
#define DCF_METADATA_DIR       "metadata"
#define DCF_METADATA_FILE      "_dcf_metadata"
#define DCF_METADATA_FILE_BAK  "_dcf_metadata.bak"
#define DCF_METADATA_HEAD_SIZE  sizeof(uint32)

static char g_meta_file[CM_MAX_PATH_LEN];
static char g_meta_file_bak[CM_MAX_PATH_LEN];

static status_t md_save_dcf_version(const char* file_name)
{
    int fd = -1;
    CM_RETURN_IFERR(cm_open_file(file_name, O_CREAT | O_RDWR | O_BINARY | O_TRUNC, &fd));
    const char* version = dcf_get_version();
    if (cm_write_file(fd, version, strlen(version)) != CM_SUCCESS) {
        cm_close_file(fd);
        return CM_ERROR;
    }

    status_t status = cm_fdatasync_file(fd);
    cm_close_file(fd);
    return status;
}

status_t md_store_init()
{
    param_value_t param;
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_DATA_PATH, &param));

    char meta_dir[CM_MAX_PATH_LEN];
    PRTS_RETURN_IFERR(snprintf_s(meta_dir, CM_MAX_PATH_LEN,
        CM_MAX_PATH_LEN - 1, "%s/%s", param.data_path, DCF_METADATA_DIR));

    if (!cm_dir_exist(meta_dir)) {
        CM_RETURN_IFERR(cm_create_dir_ex(meta_dir));
    }
    PRTS_RETURN_IFERR(snprintf_s(g_meta_file, CM_MAX_PATH_LEN,
        CM_MAX_PATH_LEN - 1, "%s/%s", meta_dir, DCF_METADATA_FILE));

    PRTS_RETURN_IFERR(snprintf_s(g_meta_file_bak, CM_MAX_PATH_LEN,
        CM_MAX_PATH_LEN - 1, "%s/%s", meta_dir, DCF_METADATA_FILE_BAK));

    char version_path[CM_MAX_PATH_LEN];
    PRTS_RETURN_IFERR(snprintf_s(version_path, CM_MAX_PATH_LEN, CM_MAX_PATH_LEN - 1, "%s/%s", meta_dir, DCF_VERSION));
    if (md_save_dcf_version(version_path) != CM_SUCCESS) {
        LOG_RUN_ERR("[META]save dcf version failed.");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t md_write_file(const char *file, const char *buf, int32 size, uint32 chksum)
{
    int fd = -1;
    CM_RETURN_IFERR(cm_open_file(file, O_CREAT | O_RDWR | O_BINARY | O_TRUNC, &fd));

    if (cm_write_file(fd, &chksum, DCF_METADATA_HEAD_SIZE) != CM_SUCCESS) {
        cm_close_file(fd);
        return CM_ERROR;
    }

    if (cm_write_file(fd, buf, size) != CM_SUCCESS) {
        cm_close_file(fd);
        return CM_ERROR;
    }

    status_t status = cm_fdatasync_file(fd);
    cm_close_file(fd);
    return status;
}

static status_t md_read_file(const char *file, char **buf, int32 *size, bool32 *is_valid)
{
    int32 fd = -1;
    int32 read_size;

    CM_RETURN_IFERR(cm_open_file(file, O_RDWR | O_BINARY, &fd));

    int32 file_size = (int32)cm_file_size(fd);
    if ((uint32)file_size <= DCF_METADATA_HEAD_SIZE) {
        cm_close_file(fd);
        return CM_SUCCESS;
    }

    uint32 chksum = 0;
    if (cm_pread_file(fd, &chksum, DCF_METADATA_HEAD_SIZE, 0, &read_size) != CM_SUCCESS
        || read_size != DCF_METADATA_HEAD_SIZE) {
        cm_close_file(fd);
        return CM_ERROR;
    }

    *size = file_size - DCF_METADATA_HEAD_SIZE;
    *buf = (char*)malloc(*size);
    if (*buf == NULL) {
        cm_close_file(fd);
        return CM_ERROR;
    }

    if (cm_pread_file(fd, *buf, *size, DCF_METADATA_HEAD_SIZE, &read_size) != CM_SUCCESS || *size != read_size) {
        cm_close_file(fd);
        CM_FREE_PTR(*buf);
        return CM_ERROR;
    }
    cm_close_file(fd);

    *is_valid = cm_verify_checksum(*buf, *size, chksum);
    if (!(*is_valid)) {
        CM_FREE_PTR(*buf);
    }
    return CM_SUCCESS;
}

status_t md_store_write(char *buf, int32 size)
{
    if (size <= 0) {
        return CM_ERROR;
    }

    uint32 chksum = cm_get_checksum(buf, size);
    LOG_DEBUG_INF("[META]Md store write, chksum:%u buf:%s", chksum, buf);

    if (md_write_file(g_meta_file_bak, buf, size, chksum) != CM_SUCCESS) {
        return CM_ERROR;
    }
    return md_write_file(g_meta_file, buf, size, chksum);
}

status_t md_store_read(char **buf, int32 *size)
{
    uint32 file_cnt = 0;
    bool32 is_valid = CM_FALSE;

    if (cm_file_exist(g_meta_file)) {
        file_cnt++;
        CM_RETURN_IFERR(md_read_file(g_meta_file, buf, size, &is_valid));
        if (is_valid) {
            return CM_SUCCESS;
        }
    }

    if (cm_file_exist(g_meta_file_bak)) {
        file_cnt++;
        CM_RETURN_IFERR(md_read_file(g_meta_file_bak, buf, size, &is_valid));
        if (is_valid) {
            return CM_SUCCESS;
        }
    }

    *size = 0;
    *buf = NULL;
    return file_cnt == 0 ? CM_SUCCESS : CM_ERROR;
}
