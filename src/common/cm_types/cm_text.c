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
 * cm_text.c
 *
 *
 * IDENTIFICATION
 *    src/common/cm_types/cm_text.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_text.h"

#ifdef __cplusplus
extern "C" {
#endif

const text_t g_null_text = {
    .str = "",
    .len = 0 };

/**
 * append at most (fmt_size - 1) characters to text,
 * @note The caller should grant sufficient spaces to accommodate them
 */
void cm_concat_fmt(text_t *text, uint32 fmt_size, const char *fmt, ...)
{
    va_list var_list;
    int32 len;

    va_start(var_list, fmt);
    len = vsnprintf_s(CM_GET_TAIL(text), fmt_size, fmt_size - 1, fmt, var_list);
    PRTS_RETVOID_IFERR(len);
    va_end(var_list);
    if (len < 0) {
        return;
    }
    text->len += (uint32)len;
}

bool32 cm_buf_append_fmt(text_buf_t *tbuf, const char *fmt, ...)
{
    va_list var_list;
    size_t sz;
    int32 len;
    if (tbuf->max_size < tbuf->len) {
        return CM_FALSE;
    }

    sz = tbuf->max_size - tbuf->len;
    va_start(var_list, fmt);
    len = vsnprintf_s(CM_GET_TAIL(tbuf), sz, sz - 1, fmt, var_list);
    if (SECUREC_UNLIKELY(len == -1)) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, len);
        return CM_FALSE;
    }
    va_end(var_list);

    tbuf->len += (uint32)len;
    return CM_TRUE;
}


status_t cm_text2str(const text_t *text, char *buf, uint32 buf_size)
{
    uint32 copy_size;
    CM_ASSERT(buf_size > 1);
    copy_size = (text->len >= buf_size) ? buf_size - 1 : text->len;
    if (copy_size > 0) {
        MEMS_RETURN_IFERR(memcpy_sp(buf, copy_size, text->str, copy_size));
    }

    buf[copy_size] = '\0';
    return CM_SUCCESS;
}

void cm_text2str_with_upper(const text_t *text, char *buf, uint32 buf_size)
{
    uint32 copy_size;
    copy_size = (text->len >= buf_size) ? buf_size - 1 : text->len;
    for (uint32 i = 0; i < copy_size; i++) {
        buf[i] = UPPER(text->str[i]);
    }

    buf[copy_size] = '\0';
}

/**
 * Split a text by split_char starting from 0, if split_char is enclosed by
 * *enclose_char*, it will be skipped. Note that enclose_char = 0 means no
 * enclose_char.
 *
 * If no split_char is found, the left = text, and the right = empty_text
 * @see cm_split_rtext
 * @author Comment Added, 2018/04/11
 */
void cm_split_text(const text_t *text, char split_char, char enclose_char, text_t *left, text_t *right)
{
    uint32 i;
    bool32 is_enclosed = CM_FALSE;

    left->str = text->str;

    for (i = 0; i < text->len; i++) {
        if (enclose_char != 0 && text->str[i] == enclose_char) {
            is_enclosed = !is_enclosed;
            continue;
        }

        if (is_enclosed) {
            continue;
        }

        if (text->str[i] == split_char) {
            left->len = i;
            right->str = text->str + i + 1;
            right->len = text->len - (i + 1);
            return;
        }
    }
    /* if the split_char is not found */
    left->len = text->len;
    right->len = 0;
    right->str = NULL;
}

/**
 * Reversely split a text from starting from its end, if the *split_char*
 * is enclosed in *enclose_char*, then skipping it.
 * @note enclose_char = 0 means no enclose_char.
 * @note If no split_char is found, the left = text, and the right = empty_text
 * @see cm_split_text
 * @author Added, 2018/04/10
 */
bool32 cm_split_rtext(const text_t *text, char split_char, char enclose_char, text_t *left, text_t *right)
{
    int32 i;
    bool32 is_enclosed = CM_FALSE;

    left->str = text->str;
    for (i = (int32)text->len; i-- > 0;) {
        if (enclose_char != 0 && text->str[i] == enclose_char) {
            is_enclosed = !is_enclosed;
            continue;
        }

        if (is_enclosed) {
            continue;
        }

        if (text->str[i] == split_char) {
            left->len = (uint32)i;
            right->str = text->str + i + 1;
            right->len = text->len - (i + 1);
            return CM_TRUE;
        }
    }

    /* if the split_char is not found */
    left->len = text->len;
    right->len = 0;
    right->str = NULL;
    return CM_FALSE;
}

/* Fetch a text starting from 0, if the *split_char* is
 * enclosed in *enclose_char*, then skipping it. If the input text is
 * empty, then FALSE is returned.
 * @see cm_fetch_text, cm_split_text, cm_split_rtext
 * */
bool32 cm_fetch_text(text_t *text, char split_char, char enclose_char, text_t *sub)
{
    text_t remain;
    if (text->len == 0) {
        CM_TEXT_CLEAR(sub);
        return CM_FALSE;
    }

    cm_split_text(text, split_char, enclose_char, sub, &remain);

    text->len = remain.len;
    text->str = remain.str;
    return CM_TRUE;
}

/* Reversely fetch a text starting from its end, if the *split_char* is
 * enclosed in *enclose_char*, then skipping it. If the input text is
 * empty, then FALSE is returned.
 * @see cm_fetch_text, cm_split_text, cm_split_rtext
 * */
bool32 cm_fetch_rtext(text_t *text, char split_char, char enclose_char, text_t *sub)
{
    if (text->len == 0) {
        CM_TEXT_CLEAR(sub);
        return CM_FALSE;
    }

    return cm_split_rtext(text, split_char, enclose_char, sub, text);
}

bool32 cm_is_enclosed(const text_t *text, char enclosed_char)
{
    if (text->len < 2) {
        return CM_FALSE;
    }

    if (enclosed_char == (CM_TEXT_BEGIN(text)) && (enclosed_char == CM_TEXT_END(text))) {
        return CM_TRUE;
    }
    return CM_FALSE;
}

bool32 cm_fetch_line(text_t *text, text_t *line, bool32 eof)
{
    text_t remain;
    if (text->len == 0) {
        CM_TEXT_CLEAR(line);
        return CM_FALSE;
    }

    cm_split_text(text, '\n', '\0', line, &remain);

    if (remain.len == text->len) { /* no spilting char found */
        if (!eof) {
            CM_TEXT_CLEAR(line);
            return CM_FALSE;
        }

        line->len = remain.len;
        line->str = remain.str;
        CM_TEXT_CLEAR(text);
        return CM_TRUE;
    }

    text->len = remain.len;
    text->str = remain.str;
    return CM_TRUE;
}


char *cm_strchr(const text_t *str, const int32 c)
{
    for (uint32 i = 0; i < str->len; ++i) {
        if (str->str[i] == c) {
            return str->str + i;
        }
    }

    return NULL;
}

void cm_str_upper(char *str)
{
    char *tmp = NULL;

    tmp = str;
    while (*tmp != '\0') {
        *tmp = UPPER(*tmp);
        tmp++;
    }

    return;
}

void cm_str_lower(char *str)
{
    char *tmp = NULL;

    tmp = str;
    while (*tmp != '\0') {
        *tmp = LOWER(*tmp);
        tmp++;
    }

    return;
}


void cm_str_reverse(char *dst, const char *src, uint32 dst_len)
{
    uint32 i;
    size_t len = strlen(src);
    if (len >= dst_len) {
        CM_THROW_ERROR_EX(ERR_ASSERT_ERROR, "len(%lu) < dst_len(%u)", len, dst_len);
        return;
    }

    for (i = 0; i < len; i++) {
        dst[i] = src[(len - 1) - i];
    }
    dst[len] = '\0';
}

void cm_text_upper(text_t *text)
{
    uint32 i;

    for (i = 0; i < text->len; i++) {
        text->str[i] = UPPER(text->str[i]);
    }
}

void cm_text_lower(text_t *text)
{
    uint32 i;

    for (i = 0; i < text->len; i++) {
        text->str[i] = LOWER(text->str[i]);
    }
}

/**
 * Truncate a text from tailing to the maximal. If the text is too long
 * '...' is appended.
 */
void cm_truncate_text(text_t *text, uint32 max_len)
{
    if (text == NULL || text->str == NULL) {
        CM_THROW_ERROR(ERR_ASSERT_ERROR, "text != NULL and text->str != NULL");
        return;
    }
    if (text->len > max_len && max_len > 3) {
        text->len = max_len - 3;
        CM_TEXT_APPEND(text, '.');
        CM_TEXT_APPEND(text, '.');
        CM_TEXT_APPEND(text, '.');
    }
    CM_NULL_TERM(text);
}

status_t cm_substrb(const text_t *src, int32 start, uint32 size, text_t *dst)
{
    uint32 copy_size;
    if ((uint32)abs(start) > src->len) {
        dst->len = 0;
        return CM_SUCCESS;
    }

    if (start > 0) {
        start--;
    } else if (start < 0) {
        start = (int32)src->len + start;
    }

    copy_size = ((uint32)(src->len - start)) > size ? size : ((uint32)(src->len - start));
    if (copy_size > 0) {
        MEMS_RETURN_IFERR(memcpy_sp(dst->str, copy_size, src->str + start, copy_size));
    }
    dst->len = copy_size;
    return CM_SUCCESS;
}


#ifdef __cplusplus
}
#endif
