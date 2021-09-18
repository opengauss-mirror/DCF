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
 *    src/common/cm_types/cm_text.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CM_TEXT_H__
#define __CM_TEXT_H__

#include "cm_text_def.h"

#ifdef __cplusplus
extern "C" {
#endif

void cm_concat_fmt(text_t *text, uint32 fmt_size, const char *fmt, ...);
bool32 cm_buf_append_fmt(text_buf_t *dst, const char *fmt, ...);

static bool32 cm_is_bracket_text(const text_t *text)
{
    bool32 in_string = CM_FALSE;
    uint32 depth;

    if (text->len < 2) {
        return CM_FALSE;
    }

    bool32 flag = CM_TEXT_BEGIN(text) != '(' || CM_TEXT_END(text) != ')';
    if (flag) {
        return CM_FALSE;
    }

    depth = 1;
    for (uint32 i = 1; i < text->len; i++) {
        if (text->str[i] == '\'') {
            in_string = !in_string;
            continue;
        }

        if (in_string) {
            continue;
        } else if (text->str[i] == '(') {
            depth++;
        } else if (text->str[i] == ')') {
            depth--;
            if (depth == 0) {
                return (i == text->len - 1);
            }
        }
    }

    return CM_FALSE;
}

static inline void cm_remove_brackets(text_t *text)
{
    while (cm_is_bracket_text(text) == CM_TRUE) {
        text->str++;
        text->len -= 2;
        cm_trim_text(text);
    }
}

// case sensitive
static inline bool32 cm_text_equal(const text_t *text1, const text_t *text2)
{
    uint32 i;

    if (text1->len != text2->len) {
        return CM_FALSE;
    }

    for (i = 0; i < text1->len; i++) {
        if (text1->str[i] != text2->str[i]) {
            return CM_FALSE;
        }
    }

    return CM_TRUE;
}

// case insensitive, all text uses upper mode to compare.
static inline bool32 cm_text_equal_ins(const text_t *text1, const text_t *text2)
{
    uint32 i;

    if (text1->len != text2->len) {
        return CM_FALSE;
    }

    for (i = 0; i < text1->len; i++) {
        if (UPPER(text1->str[i]) != UPPER(text2->str[i])) {
            return CM_FALSE;
        }
    }

    return CM_TRUE;
}

static inline bool32 cm_text_str_equal(const text_t *text, const char *str)
{
    uint32 i;

    for (i = 0; i < text->len; i++) {
        if (text->str[i] != str[i] || str[i] == '\0') {
            return CM_FALSE;
        }
    }

    return (str[text->len] == '\0');
}

static inline bool32 cm_text_str_equal_ins(const text_t *text, const char *str)
{
    uint32 i;

    for (i = 0; i < text->len; i++) {
        if (UPPER(text->str[i]) != UPPER(str[i]) || str[i] == '\0') {
            return CM_FALSE;
        }
    }

    return (str[text->len] == '\0');
}

static inline bool32 cm_text_str_less_equal_ins(const text_t *text, const char *str, const uint32 less_len)
{
    uint32 i;

    if (text->len < less_len) {
        return CM_FALSE;
    }

    for (i = 0; i < text->len; i++) {
        if (UPPER(text->str[i]) != UPPER(str[i]) || str[i] == '\0') {
            return CM_FALSE;
        }
    }

    return CM_TRUE;
}

static inline bool32 cm_text_str_contain_equal_ins(const text_t *text, const char *str, const uint32 str_len)
{
    uint32 i;

    if (text->len < str_len) {
        return CM_FALSE;
    }

    for (i = 0; i < str_len; i++) {
        if (UPPER(text->str[i]) != UPPER(str[i])) {
            return CM_FALSE;
        }
    }

    return CM_TRUE;
}

static inline int32 cm_compare_text(const text_t *text1, const text_t *text2)
{
    uint32 i, cmp_len;
    uchar c1, c2;

    cmp_len = (text1->len < text2->len) ? text1->len : text2->len;
    for (i = 0; i < cmp_len; i++) {
        c1 = (uchar)text1->str[i];
        c2 = (uchar)text2->str[i];

        if (c1 > c2) {
            return 1;
        } else if (c1 < c2) {
            return -1;
        }
    }
    return (text1->len > text2->len) ? 1 : ((text1->len == text2->len) ? 0 : -1);
}

static inline int32 cm_compare_text_rtrim(const text_t *text1, const text_t *text2)
{
    text_t l_text = *text1;
    text_t r_text = *text2;

    cm_rtrim_text(&l_text);
    cm_rtrim_text(&r_text);
    return cm_compare_text(&l_text, &r_text);
}

static inline int32 cm_compare_text_ins(const text_t *text1, const text_t *text2)
{
    uint32 i, cmp_len;
    uchar c1, c2;

    cmp_len = (text1->len < text2->len) ? text1->len : text2->len;

    for (i = 0; i < cmp_len; i++) {
        c1 = (uchar)UPPER(text1->str[i]);
        c2 = (uchar)UPPER(text2->str[i]);
        if (c1 > c2) {
            return 1;
        } else if (c1 < c2) {
            return -1;
        }
    }

    return (text1->len > text2->len) ? 1 : ((text1->len == text2->len) ? 0 : -1);
}

static inline int32 cm_compare_text_str(const text_t *text, const char *str)
{
    uint32 i;
    uchar c1, c2;
    for (i = 0; i < text->len; i++) {
        c1 = (uchar)text->str[i];
        c2 = (uchar)str[i];

        if (c1 > c2) {
            return 1;
        } else if (c1 < c2) {
            return -1;
        }
    }
    return (str[i] == '\0') ? 0 : -1;
}

static inline int32 cm_compare_text_str_ins(const text_t *text, const char *str)
{
    uint32 i;
    uchar c1, c2;
    for (i = 0; i < text->len; i++) {
        c1 = (uchar)UPPER(text->str[i]);
        c2 = (uchar)UPPER(str[i]);
        if (c1 > c2) {
            return 1;
        } else if (c1 < c2) {
            return -1;
        }
    }
    return (str[i] == '\0') ? 0 : -1;
}

static inline const char *cm_strstri(const char *str, const char *subStr)
{
    size_t len = strlen(subStr);
    if (len == 0) {
        return NULL;
    }

    while (*str) {
        if (cm_strcmpni(str, subStr, len) == 0) {
            return str;
        }
        ++str;
    }
    return NULL;
}

static inline const char *cm_strnstri(const char *str, uint32 len, const char *sub_str, uint32 sub_len)
{
    uint32 match_count = 0;

    if (len < sub_len) {
        return NULL;
    }

    for (uint32 i = 0; i < len; i++) {
        if (UPPER(str[i]) != UPPER(sub_str[match_count])) {
            match_count = 0;
            if (UPPER(str[i]) == UPPER(sub_str[match_count])) {
                ++match_count;
            }
            continue;
        }

        if (++match_count == sub_len) {
            return str + i + 1 - sub_len;
        }
    }
    return NULL;
}

static inline bool32 cm_char_in_text(char c, const text_t *set)
{
    return memchr((void *)set->str, c, set->len) != NULL;
}

static inline void cm_rtrim_text_func(text_t *text, const text_t *set)
{
    while (text->len > 0) {
        if (!cm_char_in_text(text->str[text->len - 1], set)) {
            break;
        }
        text->len--;
    }
}

/**
 * Append num characters c to the text; if num<=0, do nothing;
 * @note the user must ensure sufficient space to store them
 * @author Added at 2018/03/30
 */
static inline void cm_text_appendc(text_t *text, int32 num, char c)
{
    while (num-- > 0) {
        CM_TEXT_APPEND(text, c);
    }
}

static inline uint32 cm_get_first_pos(const text_t *text, const char c)
{
    for (uint32 i = 0; i < text->len; i++) {
        if (text->str[i] == c) {
            return i;
        }
    }
    return CM_INVALID_ID32;
}

static inline uint32 cm_get_last_pos(const text_t *text, const char c)
{
    for (uint32 i = text->len; i > 0; i--) {
        if (text->str[i - 1] == c) {
            return (uint32)(i - 1);
        }
    }
    return CM_INVALID_ID32;
}

status_t cm_text2str(const text_t *text, char *buf, uint32 buf_size);

void cm_text2str_with_upper(const text_t *text, char *buf, uint32 buf_size);
void cm_split_text(const text_t *text, char split_char, char enclose_char, text_t *left, text_t *right);
bool32 cm_split_rtext(const text_t *text, char split_char, char enclose_char, text_t *left, text_t *right);
void cm_truncate_text(text_t *text, uint32 max_len);

bool32 cm_fetch_text(text_t *text, char split_char, char enclose_char, text_t *sub);
bool32 cm_fetch_rtext(text_t *text, char split_char, char enclose_char, text_t *sub);
bool32 cm_is_enclosed(const text_t *text, char enclosed_char);
uint32 cm_fetch_line(text_t *text, text_t *line, bool32 eof);

void cm_str_upper(char *str);
void cm_str_lower(char *str);
void cm_text_upper(text_t *text);
void cm_text_lower(text_t *text);
void cm_str_reverse(char *dst, const char *src, uint32 dst_len);
status_t cm_substrb(const text_t *src, int32 start, uint32 size, text_t *dst);

char *cm_strchr(const text_t *str, const int32 c);
status_t cm_replace_regexp_spec_chars(text_t *regexp, char *ret, uint32 ret_size);


/** Set at most num characters of text by c */
static inline void cm_text_set(text_t *text, uint32 num, char c)
{
    if (text->len < num) {
        num = text->len;
    }

    while (num > 0) {
        num--;
        text->str[num] = c;
    }
}

/* Locate first occurrence of character in string
 * Returns the first position of the character in the text.
 * If the character is not found return -1
 * */
static inline int32 cm_text_chr(const text_t *text, char c)
{
    for (uint32 i = 0; i < text->len; i++) {
        if (text->str[i] == c) {
            return (int32)i;
        }
    }

    return -1;
}

/* Locate first occurrence of character in string that ignoring the character
 * enclosed by enclosed_char
 * IF c == enclosed_char
 * + if count(text, c) is odd, return the last postion of c
 * + if count(text, c) is even, return -1
 * IF c != enclosed_char return the first c that are not enclosed
* Returns the first position of the character in the text.
* If the character is not found return -1
* */
static inline int32 cm_text_enclosed_chr(const text_t *text, char c, char enclose_char)
{
    int32 last_enclosed_pos = -1;
    bool32 in_enclosed = CM_FALSE;

    for (uint32 i = 0; i < text->len; i++) {
        if (CM_IS_VALID_ENCLOSED_CHAR(enclose_char) && text->str[i] == enclose_char) {
            in_enclosed = !in_enclosed;
            last_enclosed_pos = (int32)i;
        }
        if (in_enclosed) {
            continue;
        }
        if (text->str[i] == c) {
            return (int32)i;
        }
    }

    if (CM_IS_VALID_ENCLOSED_CHAR(enclose_char) && c == enclose_char && in_enclosed) {
        return last_enclosed_pos;
    }

    return -1;
}

/**
 * Locate first occurrence of a string in another string that ignoring the character
 *
 * this method is imitated by method cm_text_enclosed_chr.
 */
static inline int32 cm_str_enclosed_chr(const text_t *text, const char *search_str, char enclose_char)
{
    int32 last_enclosed_pos = -1;
    bool32 in_enclosed = CM_FALSE;

    for (uint32 i = 0; i < text->len; i++) {
        if (CM_IS_VALID_ENCLOSED_CHAR(enclose_char) && text->str[i] == enclose_char) {
            in_enclosed = !in_enclosed;
            last_enclosed_pos = (int32)i;
        }
        if (in_enclosed) {
            continue;
        }

        bool32 flag = 1;

        if (text->str[i] == search_str[0]) {
            // text->str[i] and search_str[0] are '/0', (example SQL, fields terminated by '\0') need Special handling.
            if (strlen(search_str) == 0) {
                return (int32)i;
            }

            size_t len = strlen(search_str);

            for (uint32 j = 1; j < len; j++) {
                if (i + j < text->len && text->str[i + j] == search_str[j]) {
                    continue;
                } else {
                    flag = 0;
                    break;
                }
            }

            if (flag) {
                return (int32)i;
            }
        }
    }

    if (CM_IS_VALID_ENCLOSED_CHAR(enclose_char) && strlen(search_str) == 1 && search_str[0] == enclose_char &&
        in_enclosed) {
        return last_enclosed_pos;
    }

    return -1;
}

/* Locate last occurrence of character in string
* Returns the last position of the character in the text.
* If the character is not found return -1
* */
static inline int32 cm_text_rchr(const text_t *text, char c)
{
    for (int32 i = (int32)(text->len - 1); i >= 0; --i) {
        if (text->str[i] == c) {
            return i;
        }
    }

    return -1;
}

static inline int32 cm_text_text(const text_t *src, const text_t *sub)
{
    uint32 i, j;

    if (src->len < sub->len) {
        return -1;
    }

    for (i = 0; i < src->len; i++) {
        for (j = 0; j < sub->len; j++) {
            if (i + j >= src->len) {
                return -1;
            }
            if (src->str[i + j] != sub->str[j]) {
                break;
            }
        }
        if (j == sub->len) {
            return (int32)i;
        }
    }
    return -1;
}

static inline void cm_text_skip(text_t *text, uint32 step)
{
    step = MIN(step, text->len);
    text->str += step;
    text->len -= step;
}

static inline void cm_text_skip_spaces(text_t *text)
{
    while (text->len > 0 && text->str[0] == ' ') {
        text->str++;
        text->len--;
    }

    while (text->len > 0 && text->str[text->len - 1] == ' ') {
        text->len--;
    }
}

static inline status_t cm_chk_and_upper_base16(text_t *text)
{
    // make sure the length of text is odd
    if (text->len % 2 != 0) {
        return CM_ERROR;
    }

    for (uint32 i = 0; i < text->len; ++i) {
        char c = text->str[i];
        if (c >= 'a' && c <= 'f') {
            text->str[i] = c - 32;
            continue;
        }
        if ((c >= 'A' && c <= 'F') || (c >= '0' && c <= '9')) {
            continue;
        }
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static inline void cm_text_ltrim_zero(text_t *text)
{
    while (text->len > 1 && CM_IS_ZERO(CM_TEXT_FIRST(text))) {
        CM_REMOVE_FIRST(text);
    }
}

#ifdef __cplusplus
}
#endif

#endif
