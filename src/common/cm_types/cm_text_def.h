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
 * cm_text.h
 *
 *
 * IDENTIFICATION
 *    src/common/cm_types/cm_text_def.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CM_TEXT_DEF_H__
#define __CM_TEXT_DEF_H__
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <stdint.h>
#include "cm_defs.h"
#include "cm_debug.h"
#include "cm_error.h"
#include "securectype.h"
#include "cm_log.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CASE_SENSITIVE = 1,
    CASE_INSENSITIVE = 2,
} case_mode_t;

#pragma pack(4)
typedef struct st_text {
    char *str;
    uint32 len;
} text_t;
#pragma pack()

#define CM_IS_SIGN_CHAR(c)     ((c) == '-' || ((c) == '+'))
#define CM_IS_EXPN_CHAR(c)     ((c) == 'e' || ((c) == 'E'))
#define CM_IS_DOT(c)           ((c) == '.')
#define CM_IS_ZERO(c)          ((c) == '0')
#define CM_IS_DIGIT(c)         ((c) >= '0' && ((c) <= '9'))

/** A text buffer that along with a maximal length */
typedef union un_text_buf {
    text_t value;

    struct {
        char *str;
        uint32 len;
        uint32 max_size;
    };
} text_buf_t;

/* macro CM_INIT_TEXTBUF() will help make it easier to assign the buffer and length to text_buf_t */
#define CM_INIT_TEXTBUF(text_buf, buf_size, buf) \
    do {                                         \
        (text_buf)->max_size = (buf_size);       \
        (text_buf)->str = (buf);                 \
        (text_buf)->len = 0;                     \
    } while (0)

#define GS_MAX_INT64_SIZE 22

#define CM_TEXT_BEGIN(text)  ((text)->str[0])
#define CM_TEXT_FIRST(text)  ((text)->str[0])
#define CM_TEXT_SECOND(text) ((text)->str[1])
#define CM_TEXT_END(text)    ((text)->str[(text)->len - 1])
#define CM_TEXT_SECONDTOLAST(text)      (((text)->len >= 2) ? ((text)->str[(text)->len - 2]) : '\0')
#define CM_NULL_TERM(text)   \
    {                                    \
        (text)->str[(text)->len] = '\0'; \
    }
#define CM_IS_EMPTY(text) (((text)->str == NULL) || ((text)->len == 0))
#define CM_IS_QUOTE_CHAR(c1) ((c1)== '\'' || (c1) == '"' || (c1) == '`')
#define CM_IS_QUOTE_STRING(c1, c2) ((c1) == (c2) && CM_IS_QUOTE_CHAR(c1))

#define CM_REMOVE_FIRST(text) \
    do {                      \
        --((text)->len);      \
        ++((text)->str);      \
    } while (0)

/* n must be less than text->len */
#define CM_REMOVE_FIRST_N(text, n) \
    do {                           \
        uint32 _nn = (uint32)(n);  \
        (text)->len -= _nn;        \
        (text)->str += _nn;        \
    } while (0)

#define CM_REMOVE_LAST(text) \
    {                        \
        --((text)->len);     \
    }
#define CM_IS_EMPTY_STR(str)     (((str) == NULL) || ((str)[0] == 0))
#define CM_STR_REMOVE_FIRST(str) \
    {                            \
        (str)++;                 \
    }
#define CM_STR_REMOVE_FIRST_N(str, cnt) \
    do {                         \
        uint32 _cnt = cnt;       \
        while (_cnt > 0) {        \
            (str)++;             \
            _cnt--;              \
        }                        \
    } while (0)
#define CM_STR_GET_FIRST(str, out) \
    {                              \
        (out) = (str)[0];          \
    }
#define CM_STR_POP_FIRST(str, out)      \
    do {                                \
        CM_STR_GET_FIRST((str), (out)); \
        CM_STR_REMOVE_FIRST((str));     \
    } while (0)
#define CM_STR_BEGIN_WITH(str1, str2)     (strncmp((str1), (str2), strlen(str2)) == 0)
#define CM_IS_ENCLOSED_WITH_CHAR(text, c) ((text)->len >= 2 && (text)->str[0] == (c) &&  \
        (text)->str[(text)->len - 1] == (c))
#define CM_STR_EQUAL(str1, str2) (strlen(str1) == strlen(str2) && strncmp((str1), (str2), strlen(str2)) == 0)

/* Remove the enclosed char or the head and the tail of the text */
#define CM_REMOVE_ENCLOSED_CHAR(text) \
    do {                              \
        ++((text)->str);              \
        (text)->len -= 2;             \
    } while (0)

/* Get the tail address of a text */
#define CM_GET_TAIL(text) ((text)->str + (text)->len)

/* Get the i-th char of the text */
#define CM_GET_CHAR(text, i) ((text)->str[(i)])

/** Append a char at the end of text */
#define CM_TEXT_APPEND(text, c) ((text)->str[(text)->len++] = (c))

/** Clear all characters of the text */
#define CM_TEXT_CLEAR(text) ((text)->len = 0)

#define UPPER(c) (((c) >= 'a' && (c) <= 'z') ? ((c) - 32) : (c))
#define LOWER(c) (((c) >= 'A' && (c) <= 'Z') ? ((c) + 32) : (c))

#define CM_IS_HEX(c)   ((bool32)isxdigit(c))
#define CM_IS_ASCII(c) ((c) >= 0)

/** An enclosed char must be an ASCII char */
#define CM_IS_VALID_ENCLOSED_CHAR(c) CM_IS_ASCII(((char)(c)))

/** Convert a digital char into numerical digit */
#define CM_C2D(c) ((c) - '0')

#ifdef WIN32
#define cm_strcmpi  _strcmpi
#define cm_strcmpni _strnicmp
#else
#define cm_strcmpi  strcasecmp
#define cm_strcmpni strncasecmp
#endif

#define cm_compare_str(str1, str2)     strcmp(str1, str2)
#define cm_compare_str_ins(str1, str2) cm_strcmpi(str1, str2)
#define cm_str_equal(str1, str2)       (strcmp(str1, str2) == 0)
#define cm_str_equal_ins(str1, str2)   (cm_strcmpi(str1, str2) == 0)


static inline void cm_str2text(char *str, text_t *text)
{
    text->str = str;
    text->len = (str == NULL) ? 0 : (uint32)strlen(str);
}

static inline void cm_str2text_safe(char *str, uint32 len, text_t *text)
{
    text->str = str;
    text->len = len;
}

/** Copy src text to dest text */
static inline status_t cm_text_copy(text_t *dest, text_t *src)
{
    if (src->len != 0) {
        MEMS_RETURN_IFERR(memcpy_sp((dest)->str, (src)->len, (src)->str, (src)->len));
        (dest)->len = (src)->len;
    }
    return CM_SUCCESS;
}

static inline void cm_concat_text(text_t *text, uint32 max_len, const text_t *part)
{
    if (SECUREC_UNLIKELY(part->len == 0 || text->len >= max_len)) {
        return;
    }

    uint32 cat_len = ((text->len + part->len) <= max_len) ? part->len : (max_len - text->len);
    MEMS_RETVOID_IFERR(memcpy_s(text->str + text->len, max_len - text->len, part->str, cat_len));
    text->len += cat_len;
}

/**
 * concatenate a text with a given maximal buf size, if the result length
 * exceeds the maximal buf size return CM_FALSE; else return CM_TRUE
 */
static inline bool32 cm_buf_append_text(text_buf_t *dst, const text_t *part)
{
    if (dst->len + part->len >= dst->max_size) {
        return CM_FALSE;
    }

    for (uint32 i = 0; i < part->len; ++i) {
        CM_TEXT_APPEND(dst, part->str[i]);
    }

    return CM_TRUE;
}

static inline bool32 cm_buf_append_char(text_buf_t *dst, char c)
{
    if (dst->len + 1 >= dst->max_size) {
        return CM_FALSE;
    }

    CM_TEXT_APPEND(dst, c);

    return CM_TRUE;
}

static inline bool32 cm_buf_append_str(text_buf_t *dst, const char *str)
{
    size_t len = strlen(str);
    if (dst->len + len >= dst->max_size) {
        return CM_FALSE;
    }

    for (uint32 i = 0; i < len; ++i) {
        CM_TEXT_APPEND(dst, str[i]);
    }

    return CM_TRUE;
}

static inline void cm_concat_text_upper(text_t *text, const text_t *part)
{
    for (uint32 i = 0; i < part->len; ++i) {
        CM_TEXT_APPEND(text, UPPER(part->str[i]));
    }
}

static inline void cm_concat_text_with_cut(text_t *text, uint32 len, const text_t *part)
{
    uint32 real_len = (part->len <= len) ? part->len : len;
    for (uint32 i = 0; i < real_len; ++i) {
        CM_TEXT_APPEND(text, part->str[i]);
    }
}

static inline void cm_concat_text_upper_with_cut(text_t *text, uint32 len, const text_t *part)
{
    uint32 real_len = (part->len <= len) ? part->len : len;
    for (uint32 i = 0; i < real_len; ++i) {
        CM_TEXT_APPEND(text, UPPER(part->str[i]));
    }
}

/**
* Append first num characters of src into dst;
* + if num<=0, do nothing;
* + if num <= src.len, the first num characters are appended
* + if num > src.len, all characters of src are copyed, and the dst.len += src.len
* @note the user must ensure sufficient space to store them
* @author Added at 2018/03/30
*/
static inline status_t cm_concat_ntext(text_t *dst, const text_t *src, int32 num)
{
    if (num <= 0) {
        return CM_SUCCESS;
    }
    if ((uint32)num > src->len) {
        num = (int32)src->len;
    }
    if (num != 0) {
        MEMS_RETURN_IFERR(memcpy_sp(CM_GET_TAIL(dst), num, src->str, num));
    }
    dst->len += (uint32)num;
    return CM_SUCCESS;
}

static inline status_t cm_concat_string(text_t *text, uint32 maxsize, const char *part)
{
    uint32 len = (uint32)strlen(part);
    MEMS_RETURN_IFERR(memcpy_sp(text->str + text->len, maxsize - text->len, part, len));
    text->len += len;
    return CM_SUCCESS;
}

static inline status_t cm_concat_n_string(text_t *text, uint32 maxsize, const char *part, uint32 size)
{
    if (size != 0) {
        MEMS_RETURN_IFERR(memcpy_sp(text->str + text->len, maxsize - text->len, part, size));
        text->len += size;
    }
    return CM_SUCCESS;
}

static inline status_t cm_concat_str(text_t *text, const char *part)
{
    uint32 len = (uint32)strlen(part);
    if (len != 0) {
        MEMS_RETURN_IFERR(memcpy_sp(text->str + text->len, len, part, len));
        text->len += len;
    }
    return CM_SUCCESS;
}

static inline status_t cm_concat_n_str(text_t *text, const char *str, uint32 size)
{
    if (size != 0) {
        MEMS_RETURN_IFERR(memcpy_sp(text->str + text->len, size, str, size));
        text->len += size;
    }

    return CM_SUCCESS;
}


static inline void cm_rtrim_text(text_t *text)
{
    int32 index;

    if (text->str == NULL) {
        text->len = 0;
        return;
    } else if (text->len == 0) {
        return;
    }

    index = (int32)text->len - 1;
    while (index >= 0) {
        if ((uchar)text->str[index] > (uchar)' ') {
            text->len = (uint32)(index + 1);
            return;
        }

        --index;
    }
}

static inline void cm_ltrim_text(text_t *text)
{
    if (text->str == NULL) {
        text->len = 0;
        return;
    } else if (text->len == 0) {
        return;
    }

    while (text->len > 0) {
        if ((uchar)*text->str > ' ') {
            break;
        }
        text->str++;
        text->len--;
    }
}

static inline void cm_trim_text(text_t *text)
{
    cm_ltrim_text(text);
    cm_rtrim_text(text);
}

#ifdef __cplusplus
}
#endif

#endif
