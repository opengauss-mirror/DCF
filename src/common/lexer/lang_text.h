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
 * lang_text.h
 *
 *
 * IDENTIFICATION
 *    src/common/lexer/lang_text.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __LANG_TEXT_H__
#define __LANG_TEXT_H__

#include "cm_text.h"

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(4)
    typedef struct st_src_loc {
        uint16 line;
        uint16 column;
} src_loc_t;
#pragma pack()

typedef struct st_lang_text_t {
    union {
        text_t txt;
        struct {
            char *str;
            uint32 len;
        };
    };
    union {
        src_loc_t loc;
        struct {
            uint16 line;
            uint16 column;
        };
    };
}lang_text_t;

#ifdef __cplusplus
}
#endif
#endif
