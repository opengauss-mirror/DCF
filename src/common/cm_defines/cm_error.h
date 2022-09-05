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
 * cm_error.h
 *
 *
 * IDENTIFICATION
 *    src/common/cm_defines/cm_error.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_ERROR_H_
#define __CM_ERROR_H_

#include <stdarg.h>
#include "cm_types.h"
#include "cm_defs.h"

#ifdef __cplusplus
extern "C" {
#endif
#define CM_ERROR_COUNT 3000
#define CM_BASE_ERROR_COUNT 500

typedef enum en_status {
    CM_ERROR = -1,
    CM_SUCCESS = 0,
    CM_TIMEDOUT = 1,
} status_t;

/*
 * @Note
 *   Attention1: add error code to the corresponding range
 *
 *   ERROR                                  |   RANGE
 *   OS errors                              |   1 - 99
 *   internal errors or common errors       |   100 - 199
 *   configuration errors                   |   200 - 299
 *   reserved errors                        |   300 - 499
 */
typedef enum en_cm_errno {
    ERR_ERRNO_BASE               = 0,
    /* OS errors: 1 - 99 */
    CM_ERRNO_OS_BEGIN            = 1,
    ERR_SYSTEM_CALL              = 1,
    ERR_RESET_MEMORY             = 2,
    ERR_ALLOC_MEMORY_REACH_LIMIT = 3,
    ERR_ALLOC_MEMORY             = 4,
    ERR_LOAD_LIBRARY             = 5,
    ERR_LOAD_SYMBOL              = 6,
    ERR_DATAFILE_FSYNC           = 7,
    ERR_DATAFILE_FDATASYNC       = 8,
    ERR_INVALID_FILE_NAME        = 9,
    ERR_CREATE_FILE              = 10,
    ERR_OPEN_FILE                = 11,
    ERR_READ_FILE                = 12,
    ERR_WRITE_FILE               = 13,
    ERR_WRITE_FILE_PART_FINISH   = 14,
    ERR_SEEK_FILE                = 15,
    ERR_CREATE_DIR               = 16,
    ERR_RENAME_FILE              = 17,
    ERR_FILE_SIZE_MISMATCH       = 18,
    ERR_REMOVE_FILE              = 19,
    ERR_TRUNCATE_FILE            = 20,
    ERR_LOCK_FILE                = 21,
    ERR_CREATE_THREAD            = 22,
    ERR_INIT_THREAD              = 23,
    ERR_SET_THREAD_STACKSIZE     = 24,
    ERR_INVALID_DIR              = 25,
    ERR_NULL_PTR                 = 26,
    ERR_MEM_ZONE_INIT_FAIL       = 27,
    ERR_MEM_OUT_OF_MEMORY        = 28,
    ERR_CREATE_EVENT             = 29,
    // need update CM_ERRNO_OS_END after add new ERRNO
    CM_ERRNO_OS_END             = ERR_CREATE_EVENT + 1,
    /* internal errors or common errors: 100 - 199 */
    CM_ERRNO_INTERNAL_BEGIN  = 100,
    ERR_TEXT_FORMAT_ERROR    = 100,
    ERR_BUFFER_OVERFLOW      = 101,
    ERR_COVNERT_FORMAT_ERROR = 102,
    ERR_ZERO_DIVIDE          = 103,
    ERR_RBT_INSERT_ERROR     = 104,
    ERR_TYPE_OVERFLOW        = 105,
    ERR_ASSERT_ERROR         = 106,
    ERR_VALUE_ERROR          = 107,
    ERR_INVALID_VALUE        = 108,
    ERR_MALLOC_BYTES_MEMORY  = 109,
    // need update CM_ERRNO_INTERNAL_END after add new ERRNO
    CM_ERRNO_INTERNAL_END    = ERR_MALLOC_BYTES_MEMORY + 1,
    /* invalid configuration errors: 200 - 299 */
    CM_ERRNO_CONFIG_BEGIN     = 200,
    ERR_INIT_LOGGER           = 200,
    ERR_PARAMETERS            = 201,
    ERR_TCP_INVALID_IPADDRESS = 202,
    CM_ERRNO_CONFIG_END       = ERR_TCP_INVALID_IPADDRESS + 1,

    // The max error number of common
    CM_ERRNO_CEIL = CM_BASE_ERROR_COUNT,

    // The max error number
    ERR_CODE_CEIL = CM_ERROR_COUNT,
} cm_errno_t;

// buf in thread local storage, which used for converting text to string
#define CM_T2S_BUFFER_SIZE        (uint32)256
#define CM_T2S_LARGER_BUFFER_SIZE SIZE_K(16)

/* using for client communication with server, such as error buffer */
#define CM_MESSAGE_BUFFER_SIZE    (uint32)2048

typedef struct st_error_info_t {
    int32 code;
    char t2s_buf1[CM_T2S_LARGER_BUFFER_SIZE];
    char t2s_buf2[CM_T2S_BUFFER_SIZE];
    char message[CM_MESSAGE_BUFFER_SIZE];
} error_info_t;

#ifndef EOK
#define EOK (0)
#endif
#ifndef errno_t
typedef int errno_t;
#endif

int cm_get_os_error();
int cm_get_sock_error();
void cm_set_sock_error(int32 e);
void cm_reset_error();

int32 cm_get_error_code();
const char *cm_get_errormsg(int32 code);
void cm_get_error(int32 *code, const char **message);

#define CM_THROW_ERROR(error_no, ...)                                                                      \
    do {                                                                                                   \
        cm_set_error((char *)__FILE__, (uint32)__LINE__, (cm_errno_t)error_no, g_error_desc[error_no], ##__VA_ARGS__); \
    } while (0)

#define CM_THROW_ERROR_EX(error_no, format, ...)                                              \
    do {                                                                                      \
        cm_set_error_ex((char *)__FILE__, (uint32)__LINE__, (cm_errno_t)error_no, format, ##__VA_ARGS__); \
    } while (0)

void cm_set_error(const char *file, uint32 line, cm_errno_t code, const char *format, ...) CM_CHECK_FMT(4, 5);
void cm_set_error_ex(const char *file, uint32 line, cm_errno_t code, const char *format, ...) CM_CHECK_FMT(4, 5);

extern const char *g_error_desc[CM_ERROR_COUNT];

/* convert text to string, using local thread buffer */
char *cm_get_t2s_addr(void);
char *cm_t2s(const char *buf, uint32 len);
char *cm_concat_t2s(const char *buf1, uint32 len1, const char *buf2, uint32 len2, char c_mid);
char *cm_t2s_ex(const char *buf, uint32 len);
char *cm_t2s_case(const char *buf, uint32 len, bool32 case_sensitive);
void cm_register_error(uint16 errnum, const char *errmsg);

#define T2S(text)            cm_t2s((text)->str, (text)->len)
#define T2S_EX(text)         cm_t2s_ex((text)->str, (text)->len)
#define T2S_CASE(text, flag) cm_t2s_case((text)->str, (text)->len, (flag))
#define CC_T2S(text1, text2, c_mid) cm_concat_t2s((text1)->str, (text1)->len, (text2)->str, (text2)->len, (c_mid))

#ifdef __cplusplus
}
#endif
#endif
