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
 * lang_error.h
 *
 *
 * IDENTIFICATION
 *    src/common/lexer/lang_error.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __LANG_ERROR_H__
#define __LANG_ERROR_H__

#include "lang_text.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_lex_errno {
    ERR_LEX_SYNTAX_ERROR = 2001,
    ERR_LEX_INVALID_NUMBER = ERR_LEX_SYNTAX_ERROR + 1,
    ERR_LEX_INVALID_ARRAY_FORMAT = ERR_LEX_SYNTAX_ERROR + 2,
}lex_errno_t;

void lang_set_error_loc(src_loc_t loc);
void lang_error_init();

#define LEX_THROW_ERROR(loc, err_no, ...) \
    do { \
        lang_error_init(); \
        cm_set_error((char *)__FILE__, (uint32)__LINE__, (cm_errno_t)err_no, g_error_desc[err_no], ##__VA_ARGS__); \
        lang_set_error_loc(loc); \
    } while (0)

#define LEX_THROW_ERROR_EX(loc, err_no, format, ...) \
    do { \
        lang_error_init(); \
        cm_set_error_ex((char *)__FILE__, (uint32)__LINE__, (cm_errno_t)err_no, format, ##__VA_ARGS__); \
        lang_set_error_loc(loc); \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif
