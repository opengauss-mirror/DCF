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
 * cm_num.h
 *
 *
 * IDENTIFICATION
 *    src/common/cm_types/cm_num.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CM_NUM_H__
#define __CM_NUM_H__

#include "cm_types.h"
#include "cm_text.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
* @addtogroup NUMERIC
* @brief The settings for Nebula's number and decimal types
* The minimal and maximal precision when parsing number datatype  */
#define CM_MIN_NUM_SCALE (int32)(-84)
#define CM_MAX_NUM_SCALE (int32)127

#define CM_MIN_NUM_PRECISION (int32)1
#define CM_MAX_NUM_PRECISION (int32)38

#define CM_MAX_NUM_SAVING_PREC (int32)40 /* the maximal precision that stored into DB */

/* The default settings for DECIMAL/NUMBER/NUMERIC, when the precision and
* scale of the them are not given. When encountering these two settings,
* it indicating the precision and scale of a decimal is not limited */
#define CM_UNSPECIFIED_NUM_PREC  0
#define CM_UNSPECIFIED_NUM_SCALE (-100)

/* The default settings for DOUBLE/FLOAT, when the precision and
* scale of the them are not given. When encountering these two settings,
* it indicating the precision and scale of a decimal is not limited */
#define CM_UNSPECIFIED_REAL_PREC  CM_UNSPECIFIED_NUM_PREC
#define CM_UNSPECIFIED_REAL_SCALE CM_UNSPECIFIED_NUM_SCALE

#define CM_MIN_REAL_SCALE CM_MIN_NUM_SCALE
#define CM_MAX_REAL_SCALE CM_MAX_NUM_SCALE

#define CM_MIN_REAL_PRECISION CM_MIN_NUM_PRECISION
#define CM_MAX_REAL_PRECISION CM_MAX_NUM_PRECISION

    /* The maximal precision for outputting a decimal */
#define CM_MAX_DEC_OUTPUT_PREC     CM_MAX_NUM_SAVING_PREC
#define CM_MAX_DEC_OUTPUT_ALL_PREC (int32)52
#define CM_MAX_NUM_OUTPUT_PREC     CM_MAX_NUM_SAVING_PREC

    /* Default precision for outputting a decimal */
#define CM_DEF_DEC_OUTPUT_PREC (int32)10
#define CM_DEF_NUM_OUTPUT_PREC (int32)10 // end group NUMERIC

#define CM_MAX_NUM_PART_BUFF (CM_MAX_DEC_OUTPUT_ALL_PREC)

#define CM_MAX_REAL_EXPN DBL_MAX_10_EXP // max decimal exponent
#define CM_MIN_REAL_EXPN (-308)         // DBL_MIN_10_EXP    // min decimal exponent

/*  The DECIMAL/NUMBER/NUMERIC data type stores zero as well as positive
*  and negative fixed numbers with absolute values from 1.0*10^MIN_NUMERIC_EXPN
*  to 1.0*10^CM_MAX_NUM_EXPN. When the exponent of a decimal is
*  greater than CM_MAX_NUM_EXPN, an error will be returned. If the exponent
*  is less than CM_MIN_NUM_EXPN, a zero will be returned. */
#define CM_MAX_NUM_EXPN (int32)127
#define CM_MIN_NUM_EXPN ((int32) - 127)

/** The maximal precision of a native datatype. The precision means the
** number of significant digits in a number */
#define CM_MAX_INT64_PREC  19
#define CM_MAX_UINT64_PREC 20
#define CM_MAX_INT32_PREC  10
#define CM_MAX_UINT32_PREC 10

/* The limitation for native data type */
#define CM_MAX_UINT8  UINT8_MAX
#define CM_MIN_UINT8  0
#define CM_MIN_INT16  INT16_MIN
#define CM_MAX_INT16  INT16_MAX
#define CM_MAX_UINT16 UINT16_MAX
#define CM_MIN_UINT16 0
#define CM_MAX_INT32  (int32) INT_MAX
#define CM_MIN_INT32  (int32) INT_MIN
#define CM_MAX_UINT32 (uint32) UINT_MAX
#define CM_MIN_UINT32 (uint32)0
#define CM_MAX_INT64  LLONG_MAX
#define CM_MIN_INT64  LLONG_MIN
#define CM_MAX_UINT64 ULLONG_MAX
#define CM_MIN_UINT64 0
#define CM_MAX_REAL   (double)DBL_MAX
#define CM_MIN_REAL   (double)DBL_MIN
#define CM_MAX_DOUBLE CM_MAX_REAL
#define CM_MIN_DOUBLE CM_MIN_REAL

typedef struct st_digitext {
    char str[CM_MAX_NUM_PART_BUFF];
    uint32 len;
} digitext_t;

/* !
* \brief An internal struct used to parse and extract the part of a
* numeric text
*/
typedef struct st_num_part {
    bool32 is_neg;
    bool32 has_dot;
    bool32 has_expn;
    bool32 do_round;
    int32 sci_expn;
    /* indicating which num flag should be excluded, it should be specified
    * before parsing. */
    uint32 excl_flag;
    digitext_t digit_text;

    /* for parse size type (unsigned integer with [K|M|G|T|P...]) */
    char sz_indicator;
} num_part_t;

#define INIT_NUMPART(np)            \
    do {                            \
        (np)->digit_text.len = 0;   \
        (np)->has_dot = CM_FALSE;   \
        (np)->has_expn = CM_FALSE;  \
        (np)->do_round = CM_FALSE;  \
        (np)->is_neg = CM_FALSE;    \
        (np)->sci_expn = 0;         \
    } while (0)

#define NUMPART_IS_ZERO(np) ((np)->digit_text.len == 1 && CM_IS_ZERO((np)->digit_text.str[0]))

#define CM_ZERO_NUMPART(np)             \
    do {                                \
        (np)->digit_text.str[0] = '0';  \
        (np)->digit_text.str[1] = '\0'; \
        (np)->digit_text.len = 1;       \
    } while (0)

typedef enum en_num_errno {
    NERR_SUCCESS = 0,  // CM_SUCCESS
    NERR_ERROR,        /* error without concrete reason */
    NERR_INVALID_LEN,
    NERR_NO_DIGIT,
    NERR_UNEXPECTED_CHAR,
    NERR_NO_EXPN_DIGIT,
    NERR_EXPN_WITH_NCHAR,
    NERR_EXPN_TOO_LONG,
    NERR_EXPN_OVERFLOW,
    NERR_OVERFLOW,
    NERR_UNALLOWED_NEG,
    NERR_UNALLOWED_DOT,
    NERR_UNALLOWED_EXPN,
    NERR_MULTIPLE_DOTS,
    NERR_EXPECTED_INTEGER,
    NERR_EXPECTED_POS_INT,
    NERR__NOT_USED__ /* for safely accessing the error information */
} num_errno_t;

typedef enum en_num_flag {
    NF_NONE = 0x0,
    NF_NEGATIVE_SIGN = 0x0001,                    /* `-` */
    NF_POSTIVE_SIGN = 0x0002,                     /* `+` */
    NF_SIGN = NF_NEGATIVE_SIGN | NF_POSTIVE_SIGN, /* `+` */
    NF_DOT = 0x0004,                              /* `.` */
    NF_EXPN = 0x0008,                             /* `E` or `e` */
    NF_SZ_INDICATOR = 0x0010,                     /* B, K, M, G, T, P, E */
    NF_ALL = 0xFFFF
} num_flag_t;

#define CM_TYPE_I(type)         ((type) - CM_TYPE_BASE)
#define CM_TYPE_MASK(type)      ((uint64)1 << (uint64)(CM_TYPE_I(type)))
#define CM_TYPE_MASK_UNSIGNED_INTEGER                               \
    (CM_TYPE_MASK(CM_TYPE_UINT32) | CM_TYPE_MASK(CM_TYPE_UINT64) |  \
        CM_TYPE_MASK(CM_TYPE_USMALLINT) | CM_TYPE_MASK(CM_TYPE_UTINYINT))
#define CM_TYPE_MASK_SIGNED_INTEGER                                  \
    (CM_TYPE_MASK(CM_TYPE_INTEGER) | CM_TYPE_MASK(CM_TYPE_BIGINT) |  \
        CM_TYPE_MASK(CM_TYPE_SMALLINT) | CM_TYPE_MASK(CM_TYPE_TINYINT))
#define CM_TYPE_MASK_INTEGER \
    (CM_TYPE_MASK_UNSIGNED_INTEGER | CM_TYPE_MASK_SIGNED_INTEGER)
#define CM_IS_INTEGER_TYPE(type)                                                                                       \
    ((type) > CM_TYPE_BASE && (type) < CM_TYPE__DO_NOT_USE && (CM_TYPE_MASK(type) & CM_TYPE_MASK_INTEGER) > 0)

extern const char *g_num_errinfos[NERR__NOT_USED__];

#define CM_CHECK_NUM_ERRNO(err_no)  \
    if ((err_no) != NERR_SUCCESS) { \
        return (err_no);            \
    }

#define CM_TRY_THROW_NUM_ERR(err_no)                                        \
    do {                                                                    \
        if ((err_no) != NERR_SUCCESS) {                                     \
            LEX_THROW_ERROR(ERR_LEX_INVALID_NUMBER, cm_get_num_errinfo(err_no)); \
            return CM_ERROR;                                                \
        }                                                                   \
    } while (0)

static inline const char *cm_get_num_errinfo(uint32 err_no)
{
    CM_ASSERT(err_no < NERR__NOT_USED__);
    CM_ASSERT(err_no != NERR_SUCCESS);
    return (g_num_errinfos[err_no] != NULL) ? g_num_errinfos[err_no] : "";
}

bool32 cm_is_short(const text_t *text);
num_errno_t cm_decide_numtype(const num_part_t *np, cm_type_t *type);
num_errno_t cm_numpart2int(num_part_t *np, int32 *value);
num_errno_t cm_numpart2uint32(const num_part_t *np, uint32 *value);
num_errno_t cm_numpart2bigint(const num_part_t *np, int64 *i64);
num_errno_t cm_numpart2uint64(const num_part_t *np, uint64 *value);
num_errno_t cm_numpart2size(const num_part_t *np, int64 *value);
num_errno_t cm_split_num_text(const text_t *num_text, num_part_t *np);
status_t cm_str2uint16(const char *str, uint16 *value);
status_t cm_str2uint32(const char *str, uint32 *value);
status_t cm_text2uint16(const text_t *text_src, uint16 *value);
status_t cm_text2uint32(const text_t *text_src, uint32 *value);
status_t cm_str2uint64(const char *str, uint64 *value);
status_t cm_check_is_number(const char *str);

static inline void cm_text2digitext(const text_t *num_text, digitext_t *dig_text)
{
    (void)cm_text2str(num_text, dig_text->str, CM_MAX_NUM_PART_BUFF);
    dig_text->len = num_text->len;
}

static inline int32 cm_compare_digitext(const digitext_t *dtext1, const digitext_t *dtext2)
{
    const text_t text1 = { (char *)dtext1->str, dtext1->len };
    const text_t text2 = { (char *)dtext2->str, dtext2->len };
    return cm_compare_text(&text1, &text2);
}

#ifdef __cplusplus
}
#endif

#endif
