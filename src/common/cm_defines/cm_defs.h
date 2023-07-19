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
 * cm_defs.h
 *
 *
 * IDENTIFICATION
 *    src/common/cm_defines/cm_defs.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_DEFS__
#define __CM_DEFS__
#include "cm_base.h"
#include "cm_types.h"

#include <limits.h>
#include <float.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#include <time.h>
#endif
#ifdef __cplusplus
extern "C" {
#endif

/*
 * @Note
 *   Attention: add definitions by module, new module appends to the end
 */

/* common const */
#define CM_FALSE (uint8)0
#define CM_TRUE  (uint8)1

#define SIZE_K(n) (uint32)((n) * 1024)
#define SIZE_M(n) (1024 * SIZE_K(n))
#define SIZE_G(n) (1024 * (uint64)SIZE_M(n))
#define SIZE_T(n) (1024 * (uint64)SIZE_G(n))

#define CM_DFLT_THREAD_STACK_SIZE     SIZE_M(1)


/* invalid id */
#define CM_INVALID_INT8     ((int8)(-1))
#define CM_INVALID_ID8      (uint8)0xFF
#define CM_INVALID_OFFSET16 (uint16)0xFFFF
#define CM_INVALID_ID16     (uint16)0xFFFF
#define CM_INVALID_ID24     (uint32)0xFFFFFF
#define CM_INVALID_ID32     (uint32)0xFFFFFFFF
#define CM_INVALID_OFFSET32 (uint32)0xFFFFFFFF
#define CM_INVALID_ID64     (uint64)0xFFFFFFFFFFFFFFFF
#define CM_INFINITE32       (uint32)0xFFFFFFFF
#define CM_NULL_VALUE_LEN   (uint16)0xFFFF
#define CM_INVALID_INT32    (uint32)0x7FFFFFFF
#define CM_INVALID_INT64    (int64)0x7FFFFFFFFFFFFFFF
#define CM_INVALID_HANDLE   (int32)(-1)
#define CM_INVALID_FILEID   CM_INVALID_ID16


/* TCP options */
#define CM_TCP_DEFAULT_BUFFER_SIZE SIZE_M(64)
#define CM_TCP_KEEP_IDLE           (uint32)120 /* seconds */
#define CM_TCP_KEEP_INTERVAL       (uint32)5
#define CM_TCP_KEEP_COUNT          (uint32)3
#define CM_TCP_PORT_MAX_LENGTH     (uint32)5
#define CM_POLL_WAIT               (uint32)50   /* mill-seconds */
#define CM_CONNECT_TIMEOUT         (uint32)60000 /* mill-seconds */
#define CM_TIME_THOUSAND_UN        (uint32)1000
#define CM_HANDSHAKE_TIMEOUT       (uint32)600000 /* mill-seconds */
#define CM_HOST_NAME_BUFFER_SIZE   (uint32)64

#define CM_NETWORK_IO_TIMEOUT      (uint32)5000 /* mill-seconds */
#define CM_SSL_IO_TIMEOUT          (uint32)30000 /* mill-seconds */
#define CM_MIN_CONNECT_TIMEOUT     (10) /* mill-seconds */
#define CM_MAX_MEC_BATCH_SIZE      (1024)

#define CM_PROTO_CODE                *(uint32 *)"\xFE\xDC\xBA\x98"
#define CM_MAX_LSNR_HOST_COUNT     (uint32)8
#define CM_MAX_PACKET_SIZE         (uint32) SIZE_K(96)
#define CM_INFINITE_TIMEOUT        (uint32)0xFFFFFFFF
#define CM_MAX_THREAD_NAME_LEN     (128)

// XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:xxx.xxx.xxx.xxx%local-link: 5*6+4*4+16+1=63
// 64 bytes is enough expect local-link > 16 bytes,
// it's not necessary to enlarge to NI_MAXHOST(1025 bytes).
#define CM_MAX_IP_LEN 64
#define CM_ALIGN4_SIZE 4

/* size alignment */
#define CM_ALIGN4(size)  ((((size) & 0x03) == 0) ? (size) : ((size) + 0x04 - ((size) & 0x03)))
#define CM_ALIGN8(size)  ((((size) & 0x07) == 0) ? (size) : ((size) + 0x08 - ((size) & 0x07)))
#define CM_ALIGN16(size) ((((size) & 0x0F) == 0) ? (size) : ((size) + 0x10 - ((size) & 0x0F)))
// align to power of 2
#define CM_CALC_ALIGN(size, align) (((size) + (align) - 1) & (~((align) - 1)))
#define CM_CALC_ALIGN_FLOOR(size, align) (((size) -1) & (~((align) - 1)))
/* align to any positive integer */
#define CM_ALIGN_ANY(size, align) (((size) + (align) - 1) / (align) * (align))

#define CM_ALIGN_CEIL(size, align) (((size) + (align) - 1) / (align))

#define CM_IS_ALIGN2(size) (((size) & 0x01) == 0)
#define CM_IS_ALIGN4(size) (((size) & 0x03) == 0)
#define CM_IS_ALIGN8(size) (((size) & 0x07) == 0)

#define CM_ALIGN16_CEIL(size) ((((size) & 0x0F) == 0) ? ((size) + 0x10) : ((size) + 0x10 - ((size) & 0x0F)))
#define CM_ALIGN4_FLOOR(size) ((((size) & 0x03) == 0) ? (size) : ((size) - ((size) & 0x03)))
#define CM_ALIGN_8K(size)     (((size) + 0x00001FFF) & 0xFFFFE000)

#define IS_BIG_ENDIAN (*(uint32 *)"\x01\x02\x03\x04" == (uint32)0x01020304)

#define OFFSET_OF offsetof

#define CM_GET_MASK(bit)         (uint64)((uint64)0x1 << (bit))
#define CM_BIT_TEST(bits, mask)  ((bits) & (mask))
#define CM_BIT_SET(bits, mask)   ((bits) |= (mask))
#define CM_BIT_RESET(bits, mask) ((bits) &= ~(mask))


/* The format effector when a data type is printed */
#define PRINT_FMT_INTEGER "%d"
#define PRINT_FMT_INT32   PRINT_FMT_INTEGER
#define PRINT_FMT_UINT32  "%u"
#ifdef WIN32
#define PRINT_FMT_BIGINT "%I64d"
#else
#define PRINT_FMT_BIGINT "%lld"
#endif
#define PRINT_FMT_INT64  PRINT_FMT_BIGINT
#define PRINT_FMT_UINT64 "%llu"
#define PRINT_MAX_REAL_PREC   15  // # of decimal digits of precision
/* The format effector for GS_TYPE_REAL, %g can removing tailing zeros */
#define PRINT_FMT_REAL "%." #PRINT_MAX_REAL_PREC "g"  // * == GS_MAX_REAL_PREC

/* if the condition is true, throw return the value.
* Note: this Macro used to reduce Circle Complexity */
#define CM_THROW(cond, value) \
    do {                      \
        if (cond) {           \
            return (value);   \
        }                     \
    } while (0)

/* function retrun */
// free memory and set the pointer to NULL
#define CM_FREE_PTR(pointer)      \
    do {                          \
        if ((pointer) != NULL) { \
            free(pointer);       \
            (pointer) = NULL;    \
        }                        \
    } while (0)

// check the pointer to NULL
#define CM_CHECK_NULL_PTR(pointer)      \
    do {                          \
        if (SECUREC_UNLIKELY((pointer) == NULL)) { \
            CM_THROW_ERROR(ERR_NULL_PTR); \
            return CM_ERROR;    \
        }                        \
    } while (0)

// securec memory function check
#define MEMS_RETURN_IFERR(func)        \
    do {                                               \
        int32 __code__ = (func);                       \
        if (SECUREC_UNLIKELY(__code__ != EOK)) {       \
            CM_THROW_ERROR(ERR_SYSTEM_CALL, __code__); \
            return CM_ERROR;                           \
        }                                              \
    } while (0)

// securec memory function check
#define MEMS_RETVOID_IFERR(func)        \
    do {                                               \
        int32 __code__ = (func);                       \
        if (SECUREC_UNLIKELY(__code__ != EOK)) {       \
            CM_THROW_ERROR(ERR_SYSTEM_CALL, __code__); \
            return;                                   \
        }                                              \
    } while (0)

// for snprintf_s/sprintf_s..., return CM_ERROR if error
#define PRTS_RETURN_IFERR(func)     \
    do {                                               \
        int32 __code__ = (func);                       \
        if (SECUREC_UNLIKELY(__code__ == -1)) {        \
            CM_THROW_ERROR(ERR_SYSTEM_CALL, __code__); \
            return CM_ERROR;                           \
        }                                              \
    } while (0)

// for snprintf_s/sprintf_s..., return if error
#define PRTS_RETVOID_IFERR(func)     \
    do {                                               \
        int32 __code__ = (func);                       \
        if (SECUREC_UNLIKELY(__code__ == -1)) {        \
            CM_THROW_ERROR(ERR_SYSTEM_CALL, __code__); \
            return;                                   \
        }                                              \
    } while (0)

#define CM_RETSUCCESS_IFYES(cond) \
    do {                                \
        if (cond) {                     \
            return CM_SUCCESS;          \
        }                               \
    } while (0)

// return CM_ERROR if error occurs
#define CM_RETURN_IFERR(ret)           \
    do {                               \
        status_t _status_ = (ret);     \
        if (SECUREC_UNLIKELY(_status_ != CM_SUCCESS)) { \
            return _status_;          \
        }                             \
    } while (0)

#define CM_RETURN_IF_FALSE(ret) \
    do {                        \
        if ((ret) != CM_TRUE) { \
            return CM_ERROR;    \
        }                       \
    } while (0)

#define CM_RETURN_IF_FALSE_EX(ret, func) \
    do {                                 \
        if ((ret) != CM_TRUE) {          \
            (func);                      \
            return CM_ERROR;             \
        }                                \
    } while (0)

#define CM_RETURN_IFERR_EX(ret, func)  \
    do {                               \
        status_t _status_ = (ret);     \
        if (SECUREC_UNLIKELY(_status_ != CM_SUCCESS)) { \
            func;                     \
            return _status_;          \
        }                             \
    } while (0)


/* is letter */
#define CM_IS_LETER(c) (((c) >= 'a' && (c) <= 'z') || ((c) >= 'A' && (c) <= 'Z'))


/* The limitation for native data type */
#define CM_MAX_UINT32 (uint32) UINT_MAX
#define CM_MIN_UINT32 (uint32)0

#define CM_MAX_NUMBER_LEN       (uint32)128
#define CM_DEFAULT_DIGIT_RADIX  10


// check if overflow for converting int32/int64/uint64/double to uint32
// note: when convert int32 to uint32, type should be set to int64
#define TO_UINT32_OVERFLOW_CHECK(u32, type)                                               \
    do {                                                                                  \
        if (SECUREC_UNLIKELY((type)(u32) < (type)CM_MIN_UINT32 || (type)(u32) > (type)CM_MAX_UINT32)) {     \
            CM_THROW_ERROR(ERR_TYPE_OVERFLOW, "UNSIGNED INTEGER");                        \
            return CM_ERROR;                                                              \
        }                                                                                 \
    } while (0)

/* simple mathematical calculation */
#define MIN(A, B)        ((B) < (A) ? (B) : (A))
#define MAX(A, B)        ((B) > (A) ? (B) : (A))
#define SWAP(type, A, B) \
    do {                 \
        type t_ = (A);   \
        (A) = (B);       \
        (B) = t_;        \
    } while (0)
#define CM_DELTA(A, B)   (((A) > (B)) ? ((A) - (B)) : ((B) - (A)))

#ifndef ELEMENT_COUNT
#define ELEMENT_COUNT(x) ((uint32)(sizeof(x) / sizeof((x)[0])))
#endif
/* compiler adapter */
#ifdef WIN32
#define inline       __inline
#define cm_sleep(ms) Sleep(ms)

#define strcpy_sp   strcpy_s
#define strncpy_sp  strncpy_s
#define strcat_sp   strcat_s
#define strncat_sp  strncat_s
#define memcpy_sp   memcpy_s
#define memset_sp   memset_s

#else
static inline void cm_sleep(uint32 ms)
{
    struct timespec tq, tr;
    tq.tv_sec = ms / 1000;
    tq.tv_nsec = (ms % 1000) * 1000000;

    (void)nanosleep(&tq, &tr);
}
#endif

#define cm_abs32(val) abs(val)
#ifdef WIN32
#define cm_abs64(big_val) _abs64(big_val)
#else
#define cm_abs64(big_val) llabs(big_val)
#endif


#ifdef WIN32
#define CM_CHECK_FMT(a, b)
#else
#define CM_CHECK_FMT(a, b) __attribute__((format(printf, a, b)))
#endif  // WIN32

#ifdef WIN32
#define CM_STR_ICASE_CMP(a, b) stricmp((a), (b))
#else
#define CM_STR_ICASE_CMP(a, b) strcasecmp((a), (b))
#endif

#define CM_MAX_NAME_LEN                 (uint32)64
#define CM_NAME_BUFFER_SIZE             (uint32)CM_ALIGN4(CM_MAX_NAME_LEN + 1)
// file_name may be with path prefix ,eg: /root/**/file.log
#define CM_FILE_NAME_BUFFER_SIZE        (uint32)256
#define CM_MAX_FILE_NAME_LEN            (uint32)(CM_FILE_NAME_BUFFER_SIZE - 1)

// FULL_PATH = PATH + FILENAME
#define CM_FULL_PATH_BUFFER_SIZE        (uint32)256

#define CM_MAX_PATH_BUFFER_SIZE         (uint32)(CM_FILE_NAME_BUFFER_SIZE - CM_NAME_BUFFER_SIZE)
#define CM_MAX_PATH_LEN                 (uint32)(CM_MAX_PATH_BUFFER_SIZE - 4)
#define CM_MAX_LOG_HOME_LEN             \
    (uint32)(CM_MAX_PATH_LEN - 20) // reserve 20 characters for the stitching path(e. g./run)

#define CM_BUFLEN_32             32
#define CM_BUFLEN_64             64
#define CM_BUFLEN_128            128
#define CM_BUFLEN_256            256
#define CM_BUFLEN_512            512
#define CM_BUFLEN_1K             1024
#define CM_BUFLEN_4K             4096

static inline uint64 cm_get_next_2power(uint64 size)
{
    uint64 val = 1;

    while (val < size) {
        val <<= 1;
    }
    return val;
}

static inline uint64 cm_get_prev_2power(uint64 size)
{
    uint64 val = 1;

    while (val <= size) {
        val <<= 1;
    }
    return val / 2;
}

#define BUDDY_MEM_POOL_MAX_SIZE        SIZE_G((uint64)10)
#define BUDDY_MIN_BLOCK_SIZE           (uint64)64
#define BUDDY_MAX_BLOCK_SIZE           SIZE_G(2)

#define ARRAY_NUM(a) (sizeof(a) / sizeof((a)[0]))

#define CM_PASSWD_MIN_LEN   8
#define CM_PASSWD_MAX_LEN   64
#define CM_MAX_SSL_CIPHER_LEN   (uint32)1024
#define CM_MAX_SSL_EXPIRE_THRESHOLD   (uint32)180
#define CM_MIN_SSL_EXPIRE_THRESHOLD   (uint32)7
#define CM_PASSWORD_BUFFER_SIZE (uint32)512


#define KEY_LF                  10L
#define KEY_CR                  13L
#define KEY_BS                  8L
#define KEY_BS_LNX              127L
#define KEY_TAB                 9L
#define KEY_ESC                 27L
#define KEY_LEFT_SQAURE_EMBRACE 91L
#define KEY_CTRL_U              21L
#define KEY_CTRL_W              23L

#define CM_1X_FIXED 1
#define CM_2X_FIXED 2
#define CM_3X_FIXED 3
#define CM_10X_FIXED 10
#define CM_100X_FIXED 100
#define CM_1000X_FIXED 1000

#define CM_SLEEP_1_FIXED 1
#define CM_SLEEP_5_FIXED 5
#define CM_SLEEP_10_FIXED 10
#define CM_SLEEP_50_FIXED 50
#define CM_SLEEP_500_FIXED 500
#define CM_SLEEP_1000_FIXED 1000

#define CM_LEAST_VOTER 3

#ifdef __cplusplus
}
#endif

#endif
