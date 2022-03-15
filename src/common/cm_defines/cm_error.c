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
 * cm_error.c
 *
 *
 * IDENTIFICATION
 *    src/common/cm_defines/cm_error.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_error.h"
#include "cm_debug.h"
#include "cm_log.h"
#include "cm_text.h"

#ifdef WIN32
#include "winsock.h"
#pragma comment(lib, "ws2_32.lib")
#endif

#ifndef WIN32
#include <execinfo.h>
#endif
#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
__declspec(thread) error_info_t g_tls_error = {0};
#else
__thread error_info_t g_tls_error = {0};
#endif


/*
* one error no corresponds to one error desc
* Attention: keep the array index same as error no
*/
const char *g_error_desc[CM_ERROR_COUNT] = {

    [ERR_ERRNO_BASE]               = "Normal, no error reported",

    [ERR_SYSTEM_CALL]              = "Secure C lib has thrown an error %d",
    [ERR_RESET_MEMORY]             = "Reset memory error %s",
    [ERR_ALLOC_MEMORY_REACH_LIMIT] = "Have reach the memory limit %lld",
    [ERR_ALLOC_MEMORY]             = "Failed to allocate %llu bytes for %s",
    [ERR_LOAD_LIBRARY]             = "Failed to load library '%s': error code %d",
    [ERR_LOAD_SYMBOL]              = "Failed to load symbol '%s': error reason %s",
    [ERR_DATAFILE_FSYNC]           = "Failed to fsync the file, the error code was %d",
    [ERR_DATAFILE_FDATASYNC]       = "Failed to fdatasync the file, the error code was %d",
    [ERR_INVALID_FILE_NAME]        = "The file name (%s) exceeded the maximum length (%u)",
    [ERR_CREATE_FILE]              = "Failed to create the file %s, the error code was %d",
    [ERR_OPEN_FILE]                = "Failed to open the file %s, the error code was %d",
    [ERR_READ_FILE]                = "Failed to read data from the file, the error code was %d",
    [ERR_WRITE_FILE]               = "Failed to write the file, the error code was %d",
    [ERR_WRITE_FILE_PART_FINISH]   = "Write size %d, expected size %d, mostly because file size is larger than disk, "
                                     "please delete the incomplete file",
    [ERR_SEEK_FILE]                = "Failed to seek file, offset:%llu, origin:%d, error code %d",
    [ERR_CREATE_DIR]               = "Failed to create the path %s, error code %d",
    [ERR_RENAME_FILE]              = "Failed to rename the file %s to %s, error code %d",
    [ERR_FILE_SIZE_MISMATCH]       = "File size(%lld) does not match with the expected(%llu)",
    [ERR_REMOVE_FILE]              = "Failed to remove file %s, error code %d",
    [ERR_TRUNCATE_FILE]            = "Failed to truncate file, offset:%llu, error code %d",
    [ERR_LOCK_FILE]                = "Failed to lock file, error code %d",
    [ERR_CREATE_THREAD]            = "Failed to create a new thread, %s",
    [ERR_INIT_THREAD]              = "Failed to init thread attribute",
    [ERR_SET_THREAD_STACKSIZE]     = "Failed to set thread stacksize",
    [ERR_INVALID_DIR]              = "Directory '%s' not exist or not reachable or invalid",
    [ERR_NULL_PTR]                 = "Null pointer error",
    [ERR_MEM_ZONE_INIT_FAIL]       = "Failed to init buddy memory zone",
    [ERR_MEM_OUT_OF_MEMORY]        = "Failed to allocate %llu bytes from buddy memory pool",
    [ERR_CREATE_EVENT]             = "Failed to initialize event notification, error code %d",
    /* internal errors or common errors: 100 - 199 */
    [ERR_TEXT_FORMAT_ERROR]        = "Invalid format of %s",
    [ERR_BUFFER_OVERFLOW]          = "Current text buffer is %d, longer than the maximum %d",
    [ERR_COVNERT_FORMAT_ERROR]     = "Too many bytes to converting as %s",
    [ERR_ZERO_DIVIDE]              = "The divisor was zero",
    [ERR_RBT_INSERT_ERROR]         = "Insert into red black tree failed, because the node is existed",
    [ERR_TYPE_OVERFLOW]            = "%s out of range",
    [ERR_ASSERT_ERROR]             = "Assert raised, expect: %s",
    [ERR_VALUE_ERROR]              = "Value error: %s",
    [ERR_INVALID_VALUE]            = "Invalid %s: %u",
    [ERR_MALLOC_BYTES_MEMORY]      = "Can't malloc %d bytes",
    /* invalid configuration errors: 200 - 299 */
    [ERR_INIT_LOGGER]              = "Failed to init logger module",
    [ERR_PARAMETERS]               = "Parameter error, the param type: %s, value: %s",
    [ERR_TCP_INVALID_IPADDRESS]    = "Invalid IP address: %s"
};

void cm_register_error(uint16 errnum, const char *errmsg)
{
    cm_assert(errnum < CM_ERROR_COUNT);
    g_error_desc[errnum] = errmsg;
}

void cm_reset_error()
{
    g_tls_error.code = 0;
    g_tls_error.message[0] = '\0';
}

int cm_get_os_error()
{
#ifdef WIN32
    return GetLastError();
#else
    return errno;
#endif
}

int cm_get_sock_error()
{
#ifdef WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

void cm_set_sock_error(int32 e)
{
#ifdef WIN32
    WSASetLastError(e);
#else
    errno = e;
#endif
}

int32 cm_get_error_code()
{
    return g_tls_error.code;
}

const char *cm_get_errormsg(int32 code)
{
    return g_tls_error.message;
}

void cm_get_error(int32 *code, const char **message)
{
    *code = g_tls_error.code;
    *message = g_tls_error.message;
}


status_t cm_set_srv_error(const char *file, uint32 line, cm_errno_t code, const char *format, va_list args)
{
    char log_msg[CM_MESSAGE_BUFFER_SIZE] = {0};

    errno_t err = vsnprintf_s(log_msg, CM_MESSAGE_BUFFER_SIZE, CM_MESSAGE_BUFFER_SIZE - 1, format, args);
    if (SECUREC_UNLIKELY(err == -1)) {
        LOG_RUN_ERR("Secure C lib has thrown an error %d while setting error, %s:%u", err, file, line);
    }

    if (g_tls_error.code == 0) {
        /* override srv error when err superposed disable */
        g_tls_error.code = code;
        MEMS_RETURN_IFERR(memcpy_sp(g_tls_error.message, CM_MESSAGE_BUFFER_SIZE, log_msg, CM_MESSAGE_BUFFER_SIZE));
    }

    return CM_SUCCESS;
}

void cm_set_error(const char *file, uint32 line, cm_errno_t code, const char *format, ...)
{
    va_list args;

    va_start(args, format);

    if (cm_set_srv_error(file, line, code, format, args) != CM_SUCCESS) {
        LOG_DEBUG_ERR("cm_set_srv_error failed");
    }

    va_end(args);
}

void cm_set_error_ex(const char *file, uint32 line, cm_errno_t code, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    char tmp[CM_MAX_LOG_CONTENT_LENGTH];
    errno_t err = vsnprintf_s(tmp, CM_MAX_LOG_CONTENT_LENGTH, CM_MAX_LOG_CONTENT_LENGTH - 1, format, args);
    if (SECUREC_UNLIKELY(err == -1)) {
        LOG_RUN_ERR("Secure C lib has thrown an error %d while setting error, %s:%u", err, file, line);
    }
    cm_set_error(file, line, code, g_error_desc[code], tmp);

    va_end(args);
}

char *cm_get_t2s_addr(void)
{
    return g_tls_error.t2s_buf1;
}

char *cm_t2s(const char *buf, uint32 len)
{
    uint32 copy_size;
    errno_t errcode;
    copy_size = (len >= CM_T2S_LARGER_BUFFER_SIZE) ? CM_T2S_LARGER_BUFFER_SIZE - 1 : len;
    if (copy_size != 0) {
        errcode = memcpy_sp(g_tls_error.t2s_buf1, (size_t)CM_T2S_LARGER_BUFFER_SIZE, buf, (size_t)copy_size);
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return NULL;
        }
    }
    g_tls_error.t2s_buf1[copy_size] = '\0';
    return g_tls_error.t2s_buf1;
}

char *cm_concat_t2s(const char *buf1, uint32 len1, const char *buf2, uint32 len2, char c_mid)
{
    uint32 copy_size = 0;
    errno_t errcode;
    if (len1 + len2 + 1 < CM_T2S_LARGER_BUFFER_SIZE) {
        if (len1 > 0) {
            copy_size = len1;
            errcode = memcpy_sp(g_tls_error.t2s_buf1, (size_t)CM_T2S_LARGER_BUFFER_SIZE, buf1, (size_t)len1);
            if (SECUREC_UNLIKELY(errcode != EOK)) {
                CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
                return NULL;
            }
        }
        if (len1 > 0 && len2 > 0) {
            g_tls_error.t2s_buf1[copy_size] = c_mid;
            copy_size += 1;
        }
        if (len2 > 0) {
            errcode = memcpy_sp(g_tls_error.t2s_buf1 + copy_size, (size_t)CM_T2S_LARGER_BUFFER_SIZE - copy_size, buf2,
                (size_t)len2);
            if (SECUREC_UNLIKELY(errcode != EOK)) {
                CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
                return NULL;
            }
            copy_size += len2;
        }
    }
    g_tls_error.t2s_buf1[copy_size] = '\0';
    return g_tls_error.t2s_buf1;
}

char *cm_t2s_case(const char *buf, uint32 len, bool32 case_sensitive)
{
    uint32 copy_size = (len >= CM_T2S_LARGER_BUFFER_SIZE) ? CM_T2S_LARGER_BUFFER_SIZE - 1 : len;
    if (copy_size != 0) {
        errno_t errcode = memcpy_sp(g_tls_error.t2s_buf1, (size_t)CM_T2S_LARGER_BUFFER_SIZE, buf, (size_t)copy_size);
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return NULL;
        }
    }
    g_tls_error.t2s_buf1[copy_size] = '\0';
    if (!case_sensitive) {
        cm_str_upper(g_tls_error.t2s_buf1);
    }
    return g_tls_error.t2s_buf1;
}

char *cm_t2s_ex(const char *buf, uint32 len)
{
    uint32 copy_size;
    errno_t errcode;
    copy_size = (len >= CM_T2S_BUFFER_SIZE) ? CM_T2S_BUFFER_SIZE - 1 : len;
    if (copy_size != 0) {
        errcode = memcpy_sp(g_tls_error.t2s_buf2, (size_t)CM_T2S_BUFFER_SIZE, buf, (size_t)copy_size);
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return NULL;
        }
    }
    g_tls_error.t2s_buf2[copy_size] = '\0';
    return g_tls_error.t2s_buf2;
}


#ifdef __cplusplus
}
#endif
