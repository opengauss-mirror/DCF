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
 * cm_log.c
 *
 *
 * IDENTIFICATION
 *    src/common/cm_utils/cm_log.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_log.h"
#include "cm_file.h"
#include "cm_date.h"
#include "cm_thread.h"
#include "cm_timer.h"

#ifndef _WIN32
#include <dirent.h>
#include <execinfo.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define CM_MIN_LOG_FILE_SIZE        SIZE_M(1)                  // this value can not be less than 1M
#define CM_MAX_LOG_FILE_SIZE        ((uint64)SIZE_M(1024) * 4) // this value can not be larger than 4G
#define CM_MAX_LOG_FILE_COUNT       128                        // this value can not be larger than 128
#define CM_MAX_LOG_CONTENT_LENGTH   CM_MESSAGE_BUFFER_SIZE
#define CM_MAX_LOG_HEAD_LENGTH      100     // UTC+8 2019-01-16 22:40:15.292|CM|00000|140084283451136|INFO> 65
#define CM_MAX_LOG_NEW_BUFFER_SIZE  1048576 // (1024 * 1024)
#define CM_INVALID_FD               (-1)
#define CM_FILENAME_FORMAT_DEFAULT  0
#define CM_FILENAME_FORMAT_SEPARATED 1
#define CM_MAX_LENGTH               64

static log_file_handle_t g_logger[LOG_COUNT] = {
    [LOG_RUN] = {
        .file_handle = CM_INVALID_FD,
        .file_inode = 0 },
    [LOG_DEBUG] = {
        .file_handle = CM_INVALID_FD,
        .file_inode = 0 },
    [LOG_ALARM] = {
        .file_handle = CM_INVALID_FD,
        .file_inode = 0 },
    [LOG_AUDIT] = {
        .file_handle = CM_INVALID_FD,
        .file_inode = 0 },
    [LOG_OPER] = {
        .file_handle = CM_INVALID_FD,
        .file_inode = 0 },
    [LOG_MEC] = {
        .file_handle = CM_INVALID_FD,
        .file_inode = 0 },
    [LOG_TRACE] = {
        .file_handle = CM_INVALID_FD,
        .file_inode = 0 },
    [LOG_PROFILE] = {
        .file_handle = CM_INVALID_FD,
        .file_inode = 0 }
};

#define MAX_LOG_SUPPRESS_COUNT 128
#define LOG_SUPPRESS_TIMEOUT (int32)(5 * 60 *  MICROSECS_PER_SECOND) // 5min
#define LOG_SUPPRESS_TIME_THRESHOLD (int32)(1 * MICROSECS_PER_SECOND) // 1s
#define LOG_SUPPRESS_MAX_COUNT 10
#define MAX_LOG_SUPPRESS_EXPIRED_TIME (int32)(2 * LOG_SUPPRESS_TIMEOUT)

typedef enum en_log_suppress_status {
    LOG_NORMAL = 0,
    LOG_SUPPRESS,
    LOG_SUPPRESS_TMOUT,
    LOG_SUPPRESS_BEGIN,
    LOG_SUPPRESS_END,
    LOG_SUPPRESS_STATUS_CEIL
} log_suppress_status;

typedef struct st_log_suppress {
    int64 print_time;
    int32 count;
    log_suppress_status suppress_status;
    uint32 line;
    log_type_t type;
    char name[CM_FILE_NAME_BUFFER_SIZE];
    bool8 is_used;
} log_suppress_t;
static thread_local_var log_suppress_t *g_log_suppress[MAX_LOG_SUPPRESS_COUNT] = { (void*)0 };
static const char *g_log_suppress_status_str[LOG_SUPPRESS_STATUS_CEIL] = {
    [LOG_NORMAL] = "",
    [LOG_SUPPRESS] = "",
    [LOG_SUPPRESS_TMOUT] = "LOG_SUPPRESS>",
    [LOG_SUPPRESS_BEGIN] = "LOG_SUPPRESS_BEGIN>",
    [LOG_SUPPRESS_END] = "LOG_SUPPRESS_END>"
};
log_file_handle_t *cm_log_logger_file(uint32 log_count)
{
    return &g_logger[log_count];
}
static log_param_t g_log_param = {0};
inline log_param_t *cm_log_param_instance(void)
{
    return &g_log_param;
}

status_t cm_set_log_module_name(const char* module_name, int32 len)
{
    if (len > CM_MAX_LOG_MODULE_NAME || len < 0) {
        return CM_ERROR;
    }

    errno_t errcode;
    log_param_t *log_param = cm_log_param_instance();
    errcode = strncpy_s(log_param->log_module_name, CM_MAX_LOG_MODULE_NAME, module_name, len);
    if (errcode != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static void cm_log_remove_file(const char *file_name)
{
    (void)chmod(file_name, S_IRUSR | S_IWUSR | S_IXUSR);
    (void)__unlink(file_name);
}

static int32 cm_log_convert_token(const char *src, char *dst, size_t len)
{
    int32 count = 0;

    if (src == NULL || dst == NULL) {
        return 0;
    }

    size_t file_name_len = strlen(src);
    if (file_name_len >= len) {
        return 0;
    }

    if (strncpy_s(dst, len, src, file_name_len) != EOK) {
        return 0;
    }

    char *psz = dst;
    char *pszEnd = psz + strlen(dst);
    while (psz < pszEnd) {
        // replace instances of the specified character only
        if (*psz == '\\') {
            *psz = '/';
            count++;
        }
        psz++;
    }

    return count;
}

static status_t cm_log_create_directory(const char *log_dir)
{
    char tmp[CM_MAX_PATH_LEN] = {0};
    char path_name[CM_MAX_PATH_LEN] = {0};

    (void)cm_log_convert_token(log_dir, tmp, CM_MAX_PATH_LEN);
    size_t len = strlen(tmp);
    size_t count;

    if (tmp[len - 1] != '/') {
        tmp[len] = '/';
        len++;
        tmp[len] = '\0';
    }

    // Create the specified directory recursively to achieve the effect of the mkdir -p command.
    size_t lastPos = 0;
    for (size_t i = 1; i < len; i++) {
        if (tmp[i] == '/') {
            count = (i - lastPos) + 1;
            MEMS_RETURN_IFERR(strncat_s(path_name, CM_MAX_PATH_LEN, &tmp[lastPos], (size_t)count));
            lastPos = i;
            if (make_dir(path_name, g_log_param.log_path_permissions) != 0
                && errno != EEXIST && errno != EACCES) {
                return CM_ERROR;
            }
        }
    }
    return CM_SUCCESS;
}

static void cm_log_get_dir(char *log_dir, uint32 buf_size, const char *file_name)
{
    char *p = NULL;
    size_t file_name_len = strlen(file_name);
    MEMS_RETVOID_IFERR(strncpy_s(log_dir, buf_size, file_name, file_name_len));
    p = strrchr(log_dir, '/');
    if (p == NULL) {
        return;
    }
    *p = '\0';
}

// The current log has a maximum of two paths: log/debug(run)
static void cm_log_chmod_dir(const char *log_dir, log_type_t log_type)
{
    (void)chmod(log_dir, g_log_param.log_path_permissions);

    if (log_type == LOG_ALARM) {
        return;
    }

    char *p = strrchr(log_dir, '/');
    if (p == NULL) {
        return;
    }
    *p = '\0';
    (void)chmod(log_dir, g_log_param.log_path_permissions);
}

static void cm_log_create_dir(log_file_handle_t *log_file_handle)
{
    char log_dir[CM_FILE_NAME_BUFFER_SIZE] = {0};
    cm_log_get_dir(log_dir, CM_FILE_NAME_BUFFER_SIZE, log_file_handle->file_name);
    if (cm_log_create_directory((const char *)log_dir) != CM_SUCCESS) {
        return;
    }
    cm_log_chmod_dir(log_dir, log_file_handle->log_type);
}

static void cm_log_build_normal_head(char *buf, uint32 buf_size, log_level_t log_level, const char *module_name,
    log_suppress_status suppress_status)
{
    int tz;
    char date[CM_MAX_TIME_STRLEN] = {0};
    errno_t errcode;
    const char *log_level_str = NULL;

    switch (log_level) {
        case LEVEL_ERROR:
            log_level_str = "ERROR";
            break;
        case LEVEL_WARN:
            log_level_str = "WARN";
            break;
        default:
            log_level_str = "INFO";
            break;
    }

    (void)cm_date2str(g_timer()->now, "yyyy-mm-dd hh24:mi:ss.ff3", date, CM_MAX_TIME_STRLEN);
    tz = g_timer()->tz;
    if (tz >= 0) {
        // truncation CM_MAX_LOG_HEAD_LENGTH content
        errcode = snprintf_s(buf, (size_t)buf_size, CM_MAX_LOG_HEAD_LENGTH - 1, "UTC+%d %s|%s|%u|%s>%s", tz, date,
            module_name, cm_get_current_thread_id(), log_level_str, g_log_suppress_status_str[suppress_status]);
    } else {
        // truncation CM_MAX_LOG_HEAD_LENGTH content
        errcode = snprintf_s(buf, (size_t)buf_size, CM_MAX_LOG_HEAD_LENGTH - 1, "UTC%d %s|%s|%u|%s>%s", tz, date,
            module_name, cm_get_current_thread_id(), log_level_str, g_log_suppress_status_str[suppress_status]);
    }

    if (SECUREC_UNLIKELY(errcode == -1)) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return;
    }
}

static void cm_log_close_file(log_file_handle_t *log_file_handle)
{
    if (log_file_handle->file_handle != CM_INVALID_FD) {
        close(log_file_handle->file_handle);
        log_file_handle->file_handle = CM_INVALID_FD;
        log_file_handle->file_inode = 0;
    }
}

static bool32 cm_log_stat_file(const log_file_handle_t *log_file_handle, uint64 *file_size, uint32 *file_inode)
{
    struct stat st;

    /*
    The value of the two output parameters is unpredictable when the function returns false,
    so the file_size and file_inode are initialized to 0?
    */
    *file_size = 0;
    *file_inode = 0;

    if (stat(log_file_handle->file_name, &st) != 0) {
        return CM_FALSE;
    }

    *file_size = (uint64)st.st_size;
    *file_inode = (uint32)st.st_ino;
    return CM_TRUE;
}

/*
The parameter bak_file_name is the backup file name that is currently searched.
for example, "zenith_20081104160845999.log"
The parameter log_file_name is the file name of the log file?for example, "zenith"
The parameter log_ext_name is the extension of the log file?for example, ".log"
*/
static bool32 is_backup_file(const char *bak_file_name, const char *log_file_name, const char *log_ext_name)
{
    size_t log_file_name_len = strlen(log_file_name);
    size_t log_ext_name_len = strlen(log_ext_name);
    size_t bak_file_name_len = strlen(bak_file_name);
    size_t timestamp_len = (g_log_param.log_filename_format == CM_FILENAME_FORMAT_SEPARATED) ?
        strlen("_yyyy-mm-dd_hhmissfff") : strlen("_yyyymmddhhmissfff");
    // the 1 in the if condition is the length of the '.'
    if (log_file_name_len + timestamp_len + log_ext_name_len + 1 != bak_file_name_len) {
        return CM_FALSE;
    }

    // Compare the file names.
    if (strncmp(bak_file_name, log_file_name, (size_t)log_file_name_len) != 0) {
        return CM_FALSE;
    }

    // Compare the extension of the log file.
    // the 1 in the if condition is the length of the '.'
    const char *bak_file_ext_name = bak_file_name + log_file_name_len + timestamp_len + 1;
    if (strcmp(bak_file_ext_name, log_ext_name) != 0) {
        return CM_FALSE;
    }

    const char *timestamp = bak_file_name + log_file_name_len;
    if (timestamp[0] != '_') {
        return CM_FALSE;
    }
    for (unsigned int i = 1; i < timestamp_len; i++) {
        if (g_log_param.log_filename_format == CM_FILENAME_FORMAT_SEPARATED
            && (timestamp[i] == '-' || timestamp[i] == '_')) {
            continue;
        }
        if (timestamp[i] < '0' || timestamp[i] > '9') {
            return CM_FALSE;
        }
    }

    return CM_TRUE;
}

// left_file_name is the backup file already in the list, and right_file_name is the new file to be inserted.
static bool32 cm_log_compare_file(const char *left_file_name, const char *right_file_name)
{
    struct stat left_file_stat;
    struct stat right_file_stat;

    // if left has a problem, continues to iterate, the left early deletion
    if (stat(left_file_name, &left_file_stat) != 0) {
        return CM_FALSE;
    }

    // if right has a problem, insert list, the right early deletion
    if (stat(right_file_name, &right_file_stat) != 0) {
        return CM_TRUE;
    }

    if (left_file_stat.st_mtime == right_file_stat.st_mtime) {
        return (strcmp(left_file_name, right_file_name) > 0);
    }

    return left_file_stat.st_mtime > right_file_stat.st_mtime;
}

static status_t cm_log_add_backup_file(char *backup_file_name[CM_MAX_LOG_FILE_COUNT],
    uint32 *backup_file_count, const char *log_dir, const char *bak_file)
{
    uint32 i, j;
    bool32 need_insert = CM_TRUE;
    errno_t errcode;

    char *file_name = (char *)malloc(CM_FILE_NAME_BUFFER_SIZE);  // free in remove_bak_file
    if (file_name == NULL) {
        CM_THROW_ERROR(ERR_MALLOC_BYTES_MEMORY, CM_FILE_NAME_BUFFER_SIZE);
        return CM_ERROR;
    }

    errcode = snprintf_s(file_name, CM_FILE_NAME_BUFFER_SIZE, CM_MAX_FILE_NAME_LEN, "%s/%s", log_dir, bak_file);
    if (SECUREC_UNLIKELY(errcode == -1)) {
        CM_FREE_PTR(file_name);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }

    // sort by filename from small to large.
    for (i = 0; i < *backup_file_count; ++i) {
        if (cm_log_compare_file(backup_file_name[i], file_name)) {
            break;
        }
    }

    if (*backup_file_count == CM_MAX_LOG_FILE_COUNT) {
        if (i == 0) {
            cm_log_remove_file(file_name);
            CM_FREE_PTR(file_name);
            need_insert = CM_FALSE;
        } else {
            cm_log_remove_file(backup_file_name[0]);
            CM_FREE_PTR(backup_file_name[0]);
            for (j = 0; j < (*backup_file_count - 1); ++j) {
                backup_file_name[j] = backup_file_name[j + 1];
            }
            backup_file_name[j] = NULL;
            i--;
        }
    } else {
        (*backup_file_count)++;
    }

    if (need_insert) {
        for (j = (*backup_file_count) - 1; j > i; j--) {
            backup_file_name[j] = backup_file_name[j - 1];
        }
        backup_file_name[i] = file_name;
    }

    return CM_SUCCESS;
}

#ifdef _WIN32
static status_t cm_log_search_backup_file(char *backup_file_name[CM_MAX_LOG_FILE_COUNT],
    uint32 *backup_file_count, const char *log_dir, const char *log_file_name, const char *log_ext_name)
{
    char bak_file_fmt[CM_FILE_NAME_BUFFER_SIZE] = {0};
    WIN32_FIND_DATA data;

    PRTS_RETURN_IFERR(snprintf_s(bak_file_fmt,
        CM_FILE_NAME_BUFFER_SIZE, CM_MAX_FILE_NAME_LEN, "%s/%s*.%s", log_dir, log_file_name, log_ext_name));

    HANDLE handle = FindFirstFile(bak_file_fmt, &data);
    if (handle == INVALID_HANDLE_VALUE) {
        CM_THROW_ERROR(ERR_INVALID_DIR, bak_file_fmt);
        return CM_ERROR;
    }

    do {
        if (is_backup_file(data.cFileName, log_file_name, log_ext_name)) {
            if (cm_log_add_backup_file(backup_file_name, backup_file_count, log_dir, data.cFileName) != CM_SUCCESS) {
                FindClose(handle);
                return CM_ERROR;
            }
        }
    } while (FindNextFile(handle, &data));

    FindClose(handle);
    return CM_SUCCESS;
}
#else
static status_t cm_log_search_backup_file(char *backup_file_name[CM_MAX_LOG_FILE_COUNT],
    uint32 *backup_file_count, const char *log_dir, const char *file_name, const char *log_ext_name)
{
    struct dirent *ent = NULL;

    DIR *dir = opendir(log_dir);
    if (dir == NULL) {
        CM_THROW_ERROR(ERR_INVALID_DIR, log_dir);
        return CM_ERROR;
    }

    ent = readdir(dir);
    while (ent != NULL) {
        if (is_backup_file(ent->d_name, file_name, log_ext_name)) {
            if (cm_log_add_backup_file(backup_file_name, backup_file_count, log_dir, ent->d_name) != CM_SUCCESS) {
                (void)closedir(dir);
                return CM_ERROR;
            }
        }
        ent = readdir(dir);
    }

    (void)closedir(dir);
    return CM_SUCCESS;
}
#endif

status_t cm_log_get_bak_file_list(
    char *backup_file_name[CM_MAX_LOG_FILE_COUNT], uint32 *backup_file_count, const char *log_file)
{
    // 1.The log file path, the file name, and extension of the log file are parsed from the input parameters
    const char *log_dir = NULL;
    const char *log_file_name = NULL;
    const char *log_ext_name = NULL;
    errno_t errcode;
    /*
    for example , if log_file = "/home/enipcore/log/run/zenith.log"
    then log_dir = "/home/enipcore/log/run", log_file_name = "zenith", log_ext_name = "log"
    */
    char buf[CM_FILE_NAME_BUFFER_SIZE] = {0};
    errcode = strncpy_s(buf, CM_FILE_NAME_BUFFER_SIZE, log_file, CM_MAX_FILE_NAME_LEN);
    if (errcode != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }

    char *p = NULL;
    p = strrchr(buf, '/');
    if (p == NULL) {
        CM_THROW_ERROR(ERR_INVALID_DIR, log_file);
        return CM_ERROR;
    }
    *p = '\0';
    log_dir = buf;

    log_file_name = p + 1;
    p = strrchr((char *)log_file_name, '.');
    if (p == NULL) {
        CM_THROW_ERROR(ERR_INVALID_DIR, log_file);
        return CM_ERROR;
    }
    *p = '\0';

    log_ext_name = p + 1;

    // 2.Iterate through the directory and add the found backup files to the backup_file_name.
    return cm_log_search_backup_file(backup_file_name, backup_file_count, log_dir, log_file_name, log_ext_name);
}

// Deletes redundant backup files with the number of files that need to be preserved
static void cm_log_remove_bak_file(char *backup_file_name[CM_MAX_LOG_FILE_COUNT],
                                   uint32 *remove_file_count,
                                   uint32 backup_file_count,
                                   uint32 need_backup_count)
{
    uint32 i;
    *remove_file_count = 0;

    if (backup_file_count > need_backup_count) {
        *remove_file_count = backup_file_count - need_backup_count;
    }

    for (i = 0; i < backup_file_count; ++i) {
        if (i < *remove_file_count) {
            cm_log_remove_file(backup_file_name[i]);
        } else {
            /* free name of file that is not removed
            name of removed file will be freed after log */
            CM_FREE_PTR(backup_file_name[i]);
        }
    }
}

static status_t cm_log_get_timestamp(char* timestamp, uint32 max_length)
{
    errno_t errcode;
    date_detail_t detail = g_timer()->detail;

    if (g_log_param.log_filename_format == CM_FILENAME_FORMAT_DEFAULT) {
        errcode = snprintf_s(timestamp, max_length, max_length - 1, "%4u%02u%02u%02u%02u%02u%03u",
                             detail.year, detail.mon, detail.day,
                             detail.hour, detail.min, detail.sec, detail.millisec);
    } else if (g_log_param.log_filename_format == CM_FILENAME_FORMAT_SEPARATED) {
        errcode = snprintf_s(timestamp, max_length, max_length - 1, "%4u-%02u-%02u_%02u%02u%02u%03u",
                             detail.year, detail.mon, detail.day,
                             detail.hour, detail.min, detail.sec, detail.millisec);
    } else {
        return CM_ERROR;
    }
    if (SECUREC_UNLIKELY(errcode == -1)) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static void cm_log_get_bak_file_name(const log_file_handle_t *log_file_handle, char *bak_file)
{
    /*
    The name of the backup log?logFile.ext ==> logFile_yyyymmddhhmissff3.ext
    Where logFile is the file name, ext is the file extension, and yyyymmddhhmissff3 is in milliseconds.
    */
    char file_name[CM_FILE_NAME_BUFFER_SIZE] = {0};
    char ext_name[CM_MAX_LENGTH] = {0};
    char timestamp[CM_MAX_LENGTH] = {0};
    char *file_ext_name = NULL;
    size_t name_len = CM_MAX_FILE_NAME_LEN;
    errno_t errcode;

    // Get current timestamp
    if (cm_log_get_timestamp(timestamp, CM_MAX_LENGTH) != CM_SUCCESS) {
        return;
    }

    // Gets the file name and extension of the backup file.
    errcode = strncpy_s(file_name, sizeof(file_name), log_file_handle->file_name, (size_t)name_len);
    if (errcode != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return;
    }

    /*
    Find the character '.' from the file_name.
    Because the log file name is generated inside the code, there must be a character '.'
    */
    char *p = strrchr(file_name, '.');
    if (p == NULL) {
        return;
    }
    *p = '\0';

    file_ext_name = p + 1;
    name_len = (uint32)strlen(file_ext_name);
    errcode = strncpy_s(ext_name, sizeof(ext_name), file_ext_name, (size_t)name_len);
    if (errcode != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return;
    }

    errcode = snprintf_s(bak_file, CM_FILE_NAME_BUFFER_SIZE, CM_MAX_FILE_NAME_LEN, "%s_%s.%s", file_name, timestamp,
                         ext_name);
    if (SECUREC_UNLIKELY(errcode == -1)) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return;
    }
}

/*
    1.Back up the current log file (ensure that the current log file has been turned off before backing up the file)
    2.bak_file_name : all backup file name before transfer, 0 ~ remove_file_count need to be removed
    3.new_bak_file_name : a new log file name dcf.rlog transferred to, for example dcf.rlog
*/
static status_t cm_rmv_and_bak_log_file(log_file_handle_t *log_file_handle,
                                        char *bak_file_name[CM_MAX_LOG_FILE_COUNT],
                                        char new_bak_file_name[CM_FILE_NAME_BUFFER_SIZE],
                                        uint32 *remove_file_count)
{
    uint32 backup_file_count = 0;
    uint64 file_size;
    uint32 file_inode;
    uint32 need_bak_file_count = log_file_handle->log_type == LOG_AUDIT ?
        g_log_param.audit_backup_file_count : g_log_param.log_backup_file_count;
    uint32 file_name_len = CM_MAX_FILE_NAME_LEN;

    // When you do not back up, delete the log file directly, and re-open will automatically generate a new empty file.
    if (need_bak_file_count == 0) {
        cm_log_remove_file(log_file_handle->file_name);
        bak_file_name[0] = (char *)malloc(CM_FILE_NAME_BUFFER_SIZE);
        if (bak_file_name[0] == NULL) {
            return CM_ERROR;
        }
        *remove_file_count = 1;
        MEMS_RETURN_IFERR(strncpy_s(bak_file_name[0], CM_FILE_NAME_BUFFER_SIZE, log_file_handle->file_name,
            (size_t)file_name_len));
        return CM_SUCCESS;
    }

    CM_RETURN_IFERR(cm_log_get_bak_file_list(bak_file_name, &backup_file_count, log_file_handle->file_name));

    // Passing need_bak_file_count - 1 is because log_file_handle->file_name is about to be converted to a backup file.
    cm_log_remove_bak_file(bak_file_name, remove_file_count, backup_file_count, need_bak_file_count - 1);

    cm_log_get_bak_file_name(log_file_handle, new_bak_file_name);
    cm_log_remove_file(new_bak_file_name);
    if (log_file_handle->log_type == LOG_OPER
        && cm_log_stat_file(log_file_handle, &file_size, &file_inode) == CM_TRUE) {
        if (file_size < g_log_param.max_log_file_size) {
            // multi zsqls write one zsql.olog: zsql.olog has already be renamed
            // double check zsql.olog size
            return CM_SUCCESS;
        }
    }

    if (rename(log_file_handle->file_name, new_bak_file_name) == 0 &&
        chmod(new_bak_file_name, g_log_param.log_bak_file_permissions) == 0) {
        return CM_SUCCESS;
    }

    return CM_ERROR;
}

static inline int cm_log_open_flag(log_type_t log_type)
{
    // run/alarm/oper/blackbox should be written synchronously to avoid erroneous data caused by power failure
    switch (log_type) {
        case LOG_ALARM:
        case LOG_OPER:
        case LOG_RUN:
        default:
            return O_RDWR | O_APPEND | O_CREAT;
    }
}

void cm_log_open_file(log_file_handle_t *log_file_handle)
{
    uint64 file_size;
    uint32 file_inode;

    log_file_handle->file_inode = 0;
    log_file_handle->file_handle = CM_INVALID_FD;

    // check log dir, if have not dir, then create dir
    cm_log_create_dir(log_file_handle);

    int flags = cm_log_open_flag(log_file_handle->log_type);
    int handle = open(log_file_handle->file_name, flags, g_log_param.log_file_permissions);
    if (handle == CM_INVALID_FD) {
        return;
    }
    (void)chmod(log_file_handle->file_name, g_log_param.log_file_permissions);

    if (!cm_log_stat_file(log_file_handle, &file_size, &file_inode)) {
        close(handle);
        return;
    }

    log_file_handle->file_handle = handle;
    log_file_handle->file_inode = file_inode;
}

static void cm_write_log_file(log_file_handle_t *log_file_handle, char *buf, uint32 size)
{
    if (log_file_handle->file_handle == CM_INVALID_FD) {
        cm_log_open_file(log_file_handle);
    }

    // It is possible to fail because of the open file.
    if (log_file_handle->file_handle != CM_INVALID_FD && buf != NULL) {
        // Replace the string terminator '\0' with newline character '\n'.
        if (log_file_handle->log_type != LOG_MEC) {
            buf[size] = '\n';
            size++;
        }

        if (write(log_file_handle->file_handle, buf, size) == -1) {
            return;
        }
    }
}

static void cm_write_rmv_and_bak_file_log(char *bak_file_name[CM_MAX_LOG_FILE_COUNT],
                                          uint32 remove_file_count,
                                          char curr_bak_file_name[CM_FILE_NAME_BUFFER_SIZE])
{
    for (uint32 i = 0; i < remove_file_count; ++i) {
        LOG_RUN_FILE_INF(CM_FALSE, "[LOG] file '%s' is removed", bak_file_name[i]);
    }

    if (strlen(curr_bak_file_name) != 0) {
        LOG_RUN_FILE_INF(CM_FALSE, "[LOG] file '%s' is added", curr_bak_file_name);
    }
}

static void cm_stat_and_write_log(log_file_handle_t *log_file_handle, char *buf, uint32 size,
                                  bool32 need_rec_filelog, cm_log_write_func_t func)
{
    uint64 file_size = 0;
    uint32 file_inode = 0;
    // TEST RESULT: 10000 timeout_ticks is approximately 1 second
    // in SUSE 11 (8  Intel(R) Xeon(R) CPU E5-2690 v2 @ 3.00GHz)
    uint32 timeout_ticks = 10000;
    char new_bak_file_name[CM_FILE_NAME_BUFFER_SIZE];
    char *bak_file_name[CM_MAX_LOG_FILE_COUNT];
    uint32 remove_file_count = 0;
    int handle_before_log;
    uint64 max_file_size;
    new_bak_file_name[0] = '\0';
    status_t ret = CM_SUCCESS;

    if (LOG_DEBUG_INF_ON) {
        timeout_ticks = 100000;
    }

    if (!cm_spin_timed_lock(&log_file_handle->lock, timeout_ticks)) {
        return;
    }

    if (!cm_log_stat_file(log_file_handle, &file_size, &file_inode)) {
        cm_log_close_file(log_file_handle);
    }

    if (file_inode != log_file_handle->file_inode) {
        cm_log_close_file(log_file_handle);
    }

    max_file_size = log_file_handle->log_type == LOG_AUDIT ? g_log_param.max_audit_file_size :
                    g_log_param.max_log_file_size;
    if ((file_size + 100 > max_file_size && need_rec_filelog == CM_TRUE)
        /*
        1.reserve 2000 bytes in case of run log increasing continuously with backup file log
        2.in case of dead loop when file_size larger than max_file_size + SIZE_K(2)
        */
        || (file_size < max_file_size + SIZE_K(3) && file_size > max_file_size + SIZE_K(2)
            && need_rec_filelog == CM_FALSE)) {
        cm_log_close_file(log_file_handle);
        ret = cm_rmv_and_bak_log_file(log_file_handle, bak_file_name, new_bak_file_name, &remove_file_count);
    }

    if (ret == CM_SUCCESS) {
        handle_before_log = log_file_handle->file_handle;
        func(log_file_handle, buf, size);
        cm_spin_unlock(&log_file_handle->lock);
        cm_write_rmv_and_bak_file_log(bak_file_name, remove_file_count, new_bak_file_name);
        if (handle_before_log == CM_INVALID_FD && log_file_handle->file_handle != CM_INVALID_FD) {
            LOG_RUN_FILE_INF(CM_FALSE, "[LOG] file '%s' is added", log_file_handle->file_name);
        }
    } else {
        cm_spin_unlock(&log_file_handle->lock);
    }
    for (uint32 i = 0; i < remove_file_count; ++i) {
        CM_FREE_PTR(bak_file_name[i]);
    }
}

static void cm_log_write_large_buf(const char *buf, bool32 need_rec_filelog, const char *format,
                                   va_list ap, log_file_handle_t *log_file_hanle)
{
    size_t log_head_len = strlen(buf);
    va_list ap1;
    errno_t errcode;
    va_copy(ap1, ap);
    char *pTmp = (char *)malloc(CM_MAX_LOG_NEW_BUFFER_SIZE);
    if (pTmp == NULL) {
        va_end(ap1);
        return;
    }

    errcode = strncpy_s(pTmp, CM_MAX_LOG_NEW_BUFFER_SIZE, buf, log_head_len);
    if (errcode != EOK) {
        CM_FREE_PTR(pTmp);
        va_end(ap1);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return;
    }

    errcode = vsnprintf_s(pTmp + log_head_len, (size_t)(CM_MAX_LOG_NEW_BUFFER_SIZE - log_head_len),
        (size_t)((CM_MAX_LOG_NEW_BUFFER_SIZE - log_head_len) - 1), format, ap1);
    va_end(ap1);
    if (errcode >= 0) {
        cm_stat_and_write_log(log_file_hanle, pTmp, (uint32)strlen(pTmp), need_rec_filelog, cm_write_log_file);
    } else {
        // if the security function fails, continue to write the log after the string is truncated
        cm_stat_and_write_log(log_file_hanle, pTmp, (uint32)strlen(pTmp), need_rec_filelog, cm_write_log_file);
    }
    CM_FREE_PTR(pTmp);
}

static void cm_log_fulfil_write_buf(log_file_handle_t *log_file_handle, text_t *buf_text, uint32 buf_size,
                                    bool32 need_rec_filelog, const char *format, va_list ap)
{
    va_list ap1;
    va_copy(ap1, ap);
    int32 iRtn = vsnprintf_s(buf_text->str + buf_text->len, (size_t)(buf_size - buf_text->len),
        (size_t)((buf_size - buf_text->len) - 1), format, ap1);
    va_end(ap1);
    if (iRtn < 0) {
        CM_NULL_TERM(buf_text);
        cm_log_write_large_buf(buf_text->str, need_rec_filelog, format, ap, log_file_handle);
        return;
    }
    cm_stat_and_write_log(log_file_handle, buf_text->str, (uint32)strlen(buf_text->str),
        need_rec_filelog, cm_write_log_file);
}

static uint32 get_log_index(log_type_t log_type, const char *code_file_name, uint32 code_line_num)
{
    char buf[CM_FILE_NAME_BUFFER_SIZE + CM_MAX_NAME_LEN] = {0};
    errno_t errcode = snprintf_s(buf, CM_FILE_NAME_BUFFER_SIZE + CM_MAX_NAME_LEN,
        CM_FILE_NAME_BUFFER_SIZE + CM_MAX_NAME_LEN - 1,
        "%u%s:%u", (uint32)log_type, code_file_name, code_line_num);
    if (SECUREC_UNLIKELY(errcode == -1)) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return MAX_LOG_SUPPRESS_COUNT;
    }
    uint32 name_len = strlen(buf);
    uint32 name_hash_val = cm_hash_bytes((uint8 *)buf, name_len, name_len);
    uint32 index = name_hash_val % MAX_LOG_SUPPRESS_COUNT;
    for (uint32 i = index; i < MAX_LOG_SUPPRESS_COUNT + index; i++) {
        uint32 index_tmp = i % MAX_LOG_SUPPRESS_COUNT;
        if (g_log_suppress[index_tmp] == NULL) {
            g_log_suppress[index_tmp] = (log_suppress_t*)malloc(sizeof(log_suppress_t));
            if (g_log_suppress[index_tmp] == NULL) {
                return MAX_LOG_SUPPRESS_COUNT;
            }
            (void)memset_s(g_log_suppress[index_tmp], sizeof(log_suppress_t), 0, sizeof(log_suppress_t));
        }
        if (!g_log_suppress[index_tmp]->is_used) {
            g_log_suppress[index_tmp]->is_used = CM_TRUE;
            g_log_suppress[index_tmp]->line = code_line_num;
            g_log_suppress[index_tmp]->type = log_type;
            g_log_suppress[index_tmp]->count = 0;
            g_log_suppress[index_tmp]->print_time = g_timer()->now;
            g_log_suppress[index_tmp]->suppress_status = LOG_NORMAL;
            errcode = strcpy_s(g_log_suppress[index_tmp]->name, CM_FILE_NAME_BUFFER_SIZE, code_file_name);
            if (SECUREC_UNLIKELY(errcode == -1)) {
                CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
                return MAX_LOG_SUPPRESS_COUNT;
            }
            return index_tmp;
        } else {
            if (g_log_suppress[index_tmp]->line == code_line_num &&
                g_log_suppress[index_tmp]->type == log_type &&
                (strcmp(g_log_suppress[index_tmp]->name, code_file_name) == 0)) {
                return index_tmp;
            }
        }
    }
    return MAX_LOG_SUPPRESS_COUNT;
}

static inline bool32 is_log_match_suppress_rule(uint32 log_index)
{
    bool8 need_suppress = CM_FALSE;
    int64 time_diff = g_timer()->now - g_log_suppress[log_index]->print_time;
    if ((time_diff < LOG_SUPPRESS_TIME_THRESHOLD && g_log_suppress[log_index]->count >= LOG_SUPPRESS_MAX_COUNT)) {
        need_suppress = CM_TRUE;
    }
    if (time_diff > LOG_SUPPRESS_TIME_THRESHOLD) {
        g_log_suppress[log_index]->print_time = g_timer()->now;
        g_log_suppress[log_index]->count = 0;
    }
    return need_suppress;
}

static inline void clear_expired_suppress_status(uint32 log_index)
{
    if (((g_timer()->now - g_log_suppress[log_index]->print_time) > MAX_LOG_SUPPRESS_EXPIRED_TIME)) {
        (void)memset_s(g_log_suppress[log_index], sizeof(log_suppress_t), 0, sizeof(log_suppress_t));
    }
}

static log_suppress_status check_log_suppress(log_type_t log_type, const char *code_file_name, uint32 code_line_num)
{
    uint32 index = get_log_index(log_type, code_file_name, code_line_num);
    if (index == MAX_LOG_SUPPRESS_COUNT) {
        return LOG_NORMAL;
    }
    switch (g_log_suppress[index]->suppress_status) {
        case LOG_NORMAL:
            if (is_log_match_suppress_rule(index)) {
                g_log_suppress[index]->suppress_status = LOG_SUPPRESS_BEGIN;
            } else {
                g_log_suppress[index]->count++;
            }
            break;
        case LOG_SUPPRESS_BEGIN:
            g_log_suppress[index]->print_time = g_timer()->now + LOG_SUPPRESS_TIMEOUT;
            g_log_suppress[index]->count = 0;
            g_log_suppress[index]->suppress_status = LOG_SUPPRESS;
            break;
        case LOG_SUPPRESS_TMOUT:
            if (g_log_suppress[index]->count >=
                LOG_SUPPRESS_MAX_COUNT * (LOG_SUPPRESS_TIMEOUT / LOG_SUPPRESS_TIME_THRESHOLD)) {
                g_log_suppress[index]->print_time = g_timer()->now + LOG_SUPPRESS_TIMEOUT;
                g_log_suppress[index]->count = 1;
                g_log_suppress[index]->suppress_status = LOG_SUPPRESS;
            } else {
                g_log_suppress[index]->suppress_status = LOG_SUPPRESS_END;
            }
            break;
        case LOG_SUPPRESS:
            if (g_timer()->now > g_log_suppress[index]->print_time) {
                g_log_suppress[index]->suppress_status = LOG_SUPPRESS_TMOUT;
            }
            g_log_suppress[index]->count++;
            break;
        case LOG_SUPPRESS_END:
            g_log_suppress[index]->print_time = g_timer()->now;
            g_log_suppress[index]->count = 0;
            g_log_suppress[index]->is_used = CM_FALSE;
            g_log_suppress[index]->suppress_status = LOG_NORMAL;
            break;
        default:
            break;
    }
    clear_expired_suppress_status(index);
    return g_log_suppress[index]->suppress_status;
}
void cm_write_normal_log(log_type_t log_type, log_level_t log_level, const char *code_file_name, uint32 code_line_num,
    const char *module_name, bool32 need_rec_filelog, const char *format, ...)
{
    char buf[CM_MAX_LOG_CONTENT_LENGTH + CM_MAX_LOG_HEAD_LENGTH + 2] = {0};
    char new_format[CM_MAX_LOG_CONTENT_LENGTH] = {0};
    log_file_handle_t *log_file_handle = &g_logger[log_type];
    text_t buf_text;
    char *last_file = NULL;
    log_param_t *log_param = cm_log_param_instance();
    errno_t errcode;

#ifdef WIN32
    last_file = strrchr(code_file_name, '\\');
#else
    last_file = strrchr(code_file_name, '/');
#endif
    if (last_file == NULL) {
        last_file = "unknow";
    }
    if (log_param->log_instance_startup) {
        errcode = snprintf_s(new_format, CM_MAX_LOG_CONTENT_LENGTH, CM_MAX_LOG_CONTENT_LENGTH - 1, "%s", format);
    } else {
        errcode = snprintf_s(new_format, CM_MAX_LOG_CONTENT_LENGTH, CM_MAX_LOG_CONTENT_LENGTH - 1, "%s [%s:%u]",
                             format, last_file + 1, code_line_num);
    }

    if (log_param->log_suppress_enable && (log_type == LOG_RUN || log_type == LOG_DEBUG)) {
        log_suppress_status suppress_status = check_log_suppress(log_type, code_file_name, code_line_num);
        if (suppress_status == LOG_SUPPRESS) {
            return;
        }
        cm_log_build_normal_head((char *)buf, sizeof(buf), log_level, module_name, suppress_status);
    } else {
        cm_log_build_normal_head((char *)buf, sizeof(buf), log_level, module_name, LOG_NORMAL);
    }

    va_list args;
    va_start(args, format);
    buf_text.str = buf;
    buf_text.len = (uint32)strlen(buf);
    if (errcode >= 0) {
        cm_log_fulfil_write_buf(log_file_handle, &buf_text, sizeof(buf), need_rec_filelog, new_format, args);
    } else {
        // if the security function fails, continue to write the log after the string is truncated
        cm_log_fulfil_write_buf(log_file_handle, &buf_text, sizeof(buf), need_rec_filelog, new_format, args);
    }
    va_end(args);
}

void cm_write_audit_log(const char *format, ...)
{
    char buf[CM_MAX_LOG_CONTENT_LENGTH + 1] = {0};
    text_t buf_text;
    log_file_handle_t *log_file_handle = &g_logger[LOG_AUDIT];
    va_list args;
    va_start(args, format);
    buf_text.str = buf;
    buf_text.len = 0;
    cm_log_fulfil_write_buf(log_file_handle, &buf_text, sizeof(buf), CM_TRUE, format, args);
    va_end(args);
}

uint32 g_warn_id[] = {
    WARN_FILEDESC_ID,
};

char *g_warning_desc[] = {
    "InsufficientDataInstFileDesc",
};

void cm_write_alarm_log(uint32 warn_id, const char *format, ...)
{
    char buf[CM_MAX_LOG_CONTENT_LENGTH + 2] = {0};
    text_t buf_text;
    log_file_handle_t *log_file_handle = &g_logger[LOG_ALARM];
    char date[CM_MAX_TIME_STRLEN] = {0};
    errno_t errcode;

    (void)cm_date2str(g_timer()->now, "yyyy-mm-dd hh24:mi:ss", date, CM_MAX_TIME_STRLEN);
    // Format: Date | Warn_Id | Warn_Desc | Components | Instance_name | parameters
    errcode = snprintf_s(buf, sizeof(buf), CM_MAX_LOG_CONTENT_LENGTH + 1,
                         "%s|%u|%s|%s|%s|{'component-name':'%s','datanode-name':'%s',", date,
                         g_warn_id[warn_id], g_warning_desc[warn_id], LOG_MODULE_NAME,
                         g_log_param.instance_name, LOG_MODULE_NAME, g_log_param.instance_name);
    if (errcode < 0) {
        return;
    }

    va_list args;
    va_start(args, format);
    buf_text.str = buf;
    buf_text.len = (uint32)strlen(buf);
    cm_log_fulfil_write_buf(log_file_handle, &buf_text, sizeof(buf), CM_TRUE, format, args);
    va_end(args);
}

void cm_write_oper_log(const char *format, ...)
{
    char buf[CM_MAX_LOG_CONTENT_LENGTH + 1] = {0};
    text_t buf_text;
    log_file_handle_t *log_file_handle = &g_logger[LOG_OPER];

    cm_log_build_normal_head((char *)buf, sizeof(buf), LEVEL_INFO, LOG_MODULE_NAME, LOG_NORMAL);

    va_list args;
    va_start(args, format);
    buf_text.str = buf;
    buf_text.len = (uint32)strlen(buf);
    cm_log_fulfil_write_buf(log_file_handle, &buf_text, sizeof(buf), CM_TRUE, format, args);
    va_end(args);
}

status_t cm_log_init(log_type_t log_type, const char *file_name)
{
    log_file_handle_t *log_file = &g_logger[log_type];
    uint32 file_name_len = (uint32)strlen(file_name);
    errno_t errcode;

    GS_INIT_SPIN_LOCK(log_file->lock);
    /* log_file->file_name including the length of 'PATH + FILENAME' */
    errcode = strncpy_s(log_file->file_name, CM_FULL_PATH_BUFFER_SIZE, file_name, (size_t)file_name_len);
    if (errcode != EOK) {
        LOG_DEBUG_ERR("[LOG]log init fail, log_type:%d file_name:%s", log_type, file_name);
        return CM_ERROR;
    }

    log_file->file_handle = CM_INVALID_FD;
    log_file->file_inode = 0;
    log_file->log_type = log_type;
    return CM_SUCCESS;
}

// if val = 700, log_file_permissions is (S_IRUSR | S_IWUSR | S_IXUSR)
void cm_log_set_file_permissions(uint16 val)
{
    uint16 usr_perm;
    uint16 grp_perm;
    uint16 oth_perm;
    uint32 log_file_perm = 0;
    uint32 log_bak_file_perm = 0;

    usr_perm = (val / 100) % 10;
    if (usr_perm & 1) {
        log_file_perm |= S_IXUSR;
    }

    if (usr_perm & 2) {
        log_file_perm |= S_IWUSR;
    }

    if (usr_perm & 4) {
        log_file_perm |= S_IRUSR;
        log_bak_file_perm |= S_IRUSR;
    }

    grp_perm = (val / 10) % 10;
    if (grp_perm & 1) {
        log_file_perm |= S_IXGRP;
        log_bak_file_perm |= S_IXGRP;
    }

    if (grp_perm & 2) {
        log_file_perm |= S_IWGRP;
    }

    if (grp_perm & 4) {
        log_file_perm |= S_IRGRP;
        log_bak_file_perm |= S_IRGRP;
    }

    oth_perm = val % 10;
    if (oth_perm & 1) {
        log_file_perm |= S_IXOTH;
        log_bak_file_perm |= S_IXOTH;
    }

    if (oth_perm & 2) {
        log_file_perm |= S_IWOTH;
    }

    if (oth_perm & 4) {
        log_file_perm |= S_IROTH;
        log_bak_file_perm |= S_IROTH;
    }

    g_log_param.log_bak_file_permissions = log_bak_file_perm;
    g_log_param.log_file_permissions = log_file_perm;
}

// if val = 700, log_path_permissions is (S_IRUSR | S_IWUSR | S_IXUSR)
void cm_log_set_path_permissions(uint16 val)
{
    uint16 usr_perm;
    uint16 grp_perm;
    uint16 oth_perm;
    uint32 log_path_perm = 0;

    usr_perm = (val / 100) % 10;
    if (usr_perm & 1) {
        log_path_perm |= S_IXUSR;
    }

    if (usr_perm & 2) {
        log_path_perm |= S_IWUSR;
    }

    if (usr_perm & 4) {
        log_path_perm |= S_IRUSR;
    }

    grp_perm = (val / 10) % 10;
    if (grp_perm & 1) {
        log_path_perm |= S_IXGRP;
    }

    if (grp_perm & 2) {
        log_path_perm |= S_IWGRP;
    }

    if (grp_perm & 4) {
        log_path_perm |= S_IRGRP;
    }

    oth_perm = val % 10;
    if (oth_perm & 1) {
        log_path_perm |= S_IXOTH;
    }

    if (oth_perm & 2) {
        log_path_perm |= S_IWOTH;
    }

    if (oth_perm & 4) {
        log_path_perm |= S_IROTH;
    }

    g_log_param.log_path_permissions = log_path_perm;
}

void cm_fync_logfile(void)
{
#ifndef _WIN32
    for (int i = 0; i < LOG_COUNT; i++) {
        if (g_logger[i].file_handle != CM_INVALID_FD) {
            (void)fsync(g_logger[i].file_handle);
            cm_log_close_file(&g_logger[i]);
        }
    }
#endif
}

void cm_close_logfile(void)
{
    for (uint32 i = 0; i < LOG_COUNT; i++) {
        if (g_logger[i].file_handle == CM_INVALID_FD) {
            cm_log_close_file(&g_logger[i]);
        }
    }
}

void cm_write_mec_log(const char *format, ...)
{
    char buf[CM_MAX_LOG_CONTENT_LENGTH + 1] = {0};
    text_t buf_text;
    log_file_handle_t *log_file_handle = &g_logger[LOG_MEC];

    va_list args;
    va_start(args, format);
    buf_text.str = buf;
    buf_text.len = (uint32)strlen(buf);
    cm_log_fulfil_write_buf(log_file_handle, &buf_text, sizeof(buf), CM_TRUE, format, args);
    va_end(args);
}

static uint64 g_tracekey = (uint64)-1;

void set_trace_key(uint64 tracekey)
{
    g_tracekey = tracekey;
}

uint64 get_trace_key()
{
    return g_tracekey;
}

void unset_trace_key()
{
    g_tracekey = (uint64)-1;
}

bool8 is_trace_key(uint64 tracekey)
{
    return(g_tracekey == tracekey && g_tracekey != (uint64)-1);
}

void cm_write_trace_log(uint64 tracekey, const char *format, ...)
{
    if (!is_trace_key(tracekey)) {
        return;
    }

    date_t now = g_timer()->now;
    char date[CM_MAX_TIME_STRLEN] = {0};
    uint64 tid = (uint64)cm_get_current_thread_id();
    (void)cm_date2str(now, "yyyy-mm-dd hh24:mi:ss.FF3", date, CM_MAX_TIME_STRLEN);

    char buf[CM_MAX_LOG_CONTENT_LENGTH + 1] = {0};
    text_t buf_text;

    errno_t errcode = snprintf_s(buf, sizeof(buf), CM_MAX_LOG_CONTENT_LENGTH,
        "%s|%llu|KEY:%llu:", date, tid, tracekey);
    if (errcode < 0) {
        return;
    }

    log_file_handle_t *log_file_handle = &g_logger[LOG_TRACE];

    va_list args;
    va_start(args, format);
    buf_text.str = buf;
    buf_text.len = (uint32)strlen(buf);
    cm_log_fulfil_write_buf(log_file_handle, &buf_text, sizeof(buf), CM_TRUE, format, args);
    va_end(args);
}

#ifdef __cplusplus
}
#endif
