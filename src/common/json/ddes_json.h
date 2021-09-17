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
 * ddes_json.h
 *
 *
 * IDENTIFICATION
 *    src/common/json/ddes_json.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DDES_JSON_H__
#define __DDES_JSON_H__


#include "cm_text.h"
#include "cm_hash.h"
#include "ddes_lexer.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_json_type {
    JSON_BOOL,
    JSON_NUM,
    JSON_STR,
    JSON_OBJ,
    JSON_ARRAY,
}json_type_t;

typedef struct st_jtxt_val {
    json_type_t type;
    text_t val;
}jtxt_val_t;

typedef struct st_jtxt_prop {
    text_t key;
    jtxt_val_t val;
}jtxt_prop_t;

typedef struct st_json_iter {
    lex_t lexer;
}jtxt_iter_t;


status_t jtxt_iter_init(jtxt_iter_t *jtxt, const text_t *txt);
status_t jtxt_iter_obj(bool32 *eof, jtxt_iter_t *json, jtxt_prop_t *prop);
status_t jtxt_iter_arr(bool32 *eof, jtxt_iter_t *json, jtxt_val_t *jval);

/* This function just for test convenience */
status_t jtxt_traverse(jtxt_iter_t *json, uint32 step);

typedef struct st_json_val {
    struct st_json_val *next;
    json_type_t type;
    char data[0];
}json_val_t;

typedef struct st_json_obj {
    hash_map_t props;
}json_obj_t;

typedef struct st_json_arr {
    json_val_t *vals;
    uint32 num;
}json_arr_t;

typedef struct st_json {
    malloc_t f_alloc;
    void *mem_ctx;
    json_obj_t obj;
}json_t;

status_t json_create(json_t *json, const text_t *txt, malloc_t alloc, void *mem_ctx);

#ifdef __cplusplus
}
#endif

#endif
