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
 * ddes_json.c
 *
 *
 * IDENTIFICATION
 *    src/common/json/ddes_json.c
 *
 * -------------------------------------------------------------------------
 */

#include "ddes_json.h"

#define LEXER(json) (&(json)->lexer)

status_t jtxt_iter_init(jtxt_iter_t *jtxt, const text_t *txt)
{
    lang_text_t lang_txt = {
        .txt = *txt,
        .column = 0,
        .line = 0
    };
    lex_init(LEXER(jtxt), &lang_txt);
    word_t word;
    bool32 found = CM_FALSE;
    CM_RETURN_IFERR(lex_try_fetch_cbrackets(LEXER(jtxt), &word, &found));
    if (found) {
        lex_init(LEXER(jtxt), &word.text);
        return CM_SUCCESS;
    }
    CM_RETURN_IFERR(lex_try_fetch_sbrackets(LEXER(jtxt), &word, &found));
    if (found) {
        lex_init(LEXER(jtxt), &word.text);
        return CM_SUCCESS;
    }
    LEX_THROW_ERROR(LEXER(jtxt)->loc, ERR_LEX_SYNTAX_ERROR, "curly or square bracket expected.");
    return CM_ERROR;
}

static status_t fetch_key(jtxt_iter_t *jtxt, jtxt_prop_t *prop)
{
    word_t word;
    bool32 found;
    lex_t *lex = LEXER(jtxt);
    CM_RETURN_IFERR(lex_try_fetch_dquota(lex, &word, &found));
    if (!found) {
        LEX_THROW_ERROR(LEXER(jtxt)->loc, ERR_LEX_SYNTAX_ERROR, "double qutation expected.");
        return CM_ERROR;
    }
    prop->key = word.text.txt;
    return CM_SUCCESS;
}

static status_t fetch_value(jtxt_iter_t *jtxt, jtxt_val_t *jval)
{
    word_t word;
    lex_t *lex = LEXER(jtxt);

    status_t ret;
    CM_RETURN_IFERR(lex_fetch(lex, &word));
    switch (word.type) {
        case WORD_TYPE_BRACKET:
            if (word.text.str[0] == LBRACKET(CURLY_BRACKETS)) {
                jval->type = JSON_OBJ;
            } else {
                jval->type = JSON_ARRAY;
            }
            ret = CM_SUCCESS;
            break;
        case WORD_TYPE_NUMBER:
            jval->type = JSON_NUM;
            ret = CM_SUCCESS;
            break;
        case WORD_TYPE_DQ_STRING:
            jval->type = JSON_STR;
            ret = CM_SUCCESS;
            break;
        case WORD_TYPE_RESERVED:
            if (word.id == RES_WORD_TRUE || word.id == RES_WORD_FALSE) {
                jval->type = JSON_BOOL;
                ret = CM_SUCCESS;
                break;
            }
            ret = CM_ERROR;
            break;
        default:
            LEX_THROW_ERROR(LEXER(jtxt)->loc, ERR_LEX_SYNTAX_ERROR, "invalid value");
            ret = CM_ERROR;
            break;
    }
    jval->val = word.text.txt;
    return ret;
}

static inline status_t skip_comma(jtxt_iter_t *jtxt)
{
    lex_t *lex = LEXER(jtxt);
    word_t word;
    CM_RETURN_IFERR(lex_fetch(lex, &word));
    if (word.type != WORD_TYPE_SPEC_CHAR && word.type != WORD_TYPE_EOF) {
        LEX_THROW_ERROR(LEXER(jtxt)->loc, ERR_LEX_SYNTAX_ERROR, "comma expected.");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t jtxt_iter_obj(bool32 *eof, jtxt_iter_t *jtxt, jtxt_prop_t *prop)
{
    lex_t *lex = LEXER(jtxt);
    bool32 found;

    lex_begin_fetch(lex, NULL);

    if (LEX_CURR == LEX_END) {
        *eof = CM_TRUE;
        return CM_SUCCESS;
    }

    *eof = CM_FALSE;
    CM_RETURN_IFERR(fetch_key(jtxt, prop));
    CM_RETURN_IFERR(lex_try_fetch(lex, ":", &found));
    if (!found) {
        LEX_THROW_ERROR(LEXER(jtxt)->loc, ERR_LEX_SYNTAX_ERROR, "colon expected.");
        return CM_ERROR;
    }
    CM_RETURN_IFERR(fetch_value(jtxt, &prop->val));

    return skip_comma(jtxt);
}

status_t jtxt_iter_arr(bool32 *eof, jtxt_iter_t *jtxt, jtxt_val_t *jval)
{
    lex_t *lex = &jtxt->lexer;

    if (LEX_CURR == LEX_END) {
        *eof = CM_TRUE;
        return CM_SUCCESS;
    }

    *eof = CM_FALSE;
    CM_RETURN_IFERR(fetch_value(jtxt, jval));
    return skip_comma(jtxt);
}

typedef uint16 key_len_t;
#define JSON_OFFSET_KEY(jval) (((json_val_t *)(jval))->data)
#define JSON_OFFSET_VAL(jval) (JSON_OFFSET_KEY(jval) + key_len_t + *(key_len_t *)JSON_OFFSET_KEY(jval))

static inline void key2text(void *key, text_t *txt)
{
    txt->str = (char *)key + sizeof(key_len_t);
    txt->len = *(key_len_t *)key - 1;
}

static bool32 json_equal(void *lkey, void *rkey)
{
    text_t ltxt, rtxt;
    key2text(lkey, &ltxt);
    key2text(rkey, &rtxt);
    return (cm_compare_text_ins(&ltxt, &rtxt) == 0);
}
static uint32 json_hash(void *key)
{
    text_t txt;
    key2text(key, &txt);
    return cm_hash_bytes((uint8 *)txt.str, txt.len, 0);
}
static void *json_key(hash_node_t *node)
{
    return JSON_OFFSET_KEY((json_val_t *)node);
}

static hash_funcs_t g_json_hashs = {
    .f_key = json_key,
    .f_equal = json_equal,
    .f_hash = json_hash
};

static inline uint32 add_val_size(uint32 size, const jtxt_val_t *jtxt_val)
{
    switch (jtxt_val->type) {
        case JSON_BOOL:
            return size + sizeof(bool32);
        case JSON_NUM:
            return size + sizeof(digitext_t);
        case JSON_STR:
            return size + sizeof(uint32) + jtxt_val->val.len + 1; // include terminator
        case JSON_OBJ:
            return size + sizeof(json_obj_t);
        case JSON_ARRAY:
            return size + sizeof(json_arr_t);
        default:
            return size;
    }
}

static inline uint32 calc_prop_size(jtxt_prop_t *jtxt_prop)
{
    jtxt_val_t *jtxt_val = &jtxt_prop->val;

    /* json value struct|key size|key|val(include terminator) */
    uint32 size = sizeof(json_val_t) + sizeof(uint16) + jtxt_prop->key.len + 1;

    return add_val_size(size, jtxt_val);
}

#define TRUE_OR_FALSE(str) (((str)[0] == 't' || (str)[0] == 'T') ? 1 : 0)

static inline void assign_val_data(jtxt_val_t *jtxt_val, char *data)
{
    text_t *txt = &jtxt_val->val;
    switch (jtxt_val->type) {
        case JSON_BOOL:
            *(bool32 *)data = TRUE_OR_FALSE(txt->str);
            break;
        case JSON_NUM:
            cm_text2digitext(txt, (digitext_t *)data);
            break;
        case JSON_STR:
            *(uint32 *)data = txt->len;
            memcpy_s(data + sizeof(uint32), txt->len, txt->str, txt->len);
            data[txt->len + sizeof(uint32)] = '\0';
            break;
        case JSON_OBJ:
        case JSON_ARRAY:
        default:
            // currently do nothing
            break;
    }
}

static void assign_prop_data(jtxt_prop_t *jtxt_prop, json_val_t *jval)
{
    jtxt_val_t *jtxt_val = &jtxt_prop->val;
    char *data = jval->data;

    /* assign key */
    *(uint16 *)data = jtxt_prop->key.len + 1;
    data += sizeof(uint16);
    memcpy_s(data, jtxt_prop->key.len, jtxt_prop->key.str, jtxt_prop->key.len);
    jval->data[jtxt_prop->key.len] = '\0';
    data += jtxt_prop->key.len + 1;

    /* assign val */
    assign_val_data(jtxt_val, data);
}

static status_t construct_obj(json_t *json, json_obj_t *obj, const text_t *txt);
static status_t construct_arr(json_t *json, json_arr_t *arr, const text_t *txt);
static status_t new_obj_prop(json_t *json, jtxt_prop_t *jtxt_prop, json_val_t **jval)
{
    uint32 size = calc_prop_size(jtxt_prop);
    CM_RETURN_IFERR(json->f_alloc(json->mem_ctx, size, (void**)jval));
    assign_prop_data(jtxt_prop, *jval);

    jtxt_val_t *jtxt_val = &jtxt_prop->val;
    switch (jtxt_val->type) {
        case JSON_OBJ:
            return construct_obj(json, (json_obj_t *)(*jval)->data, &jtxt_val->val);
        case JSON_ARRAY:
            return construct_arr(json, (json_arr_t *)(*jval)->data, &jtxt_val->val);
        default:
            return CM_SUCCESS;
    }
}

static inline status_t construct_obj(json_t *json, json_obj_t *obj, const text_t *txt)
{
    jtxt_iter_t jtxt;
    CM_RETURN_IFERR(jtxt_iter_init(&jtxt, txt));

    json_val_t *first = NULL;
    json_val_t *last = NULL;
    uint32 count = 0;
    for (;;) {
        bool32 eof;
        jtxt_prop_t jtxt_prop;
        json_val_t *jval;
        CM_RETURN_IFERR(jtxt_iter_obj(&eof, &jtxt, &jtxt_prop));
        if (SECUREC_UNLIKELY(eof)) {
            break;
        }
        CM_RETURN_IFERR(new_obj_prop(json, &jtxt_prop, &jval));
        ++count;
        if (first == NULL) {
            jval->next = NULL;
            first = jval;
            last = jval;
        } else {
            jval->next = NULL;
            last->next = jval;
            last = jval;
        }
    }

    hash_map_t *hmap = &obj->props;
    cm_hmap_init(hmap, json->f_alloc, json->mem_ctx, &g_json_hashs, count);
    last = first;
    while (last != NULL) {
        cm_hmap_insert(hmap, (hash_node_t *)last);
        last = last->next;
    }
    return CM_SUCCESS;
}

static inline uint32 calc_item_size(jtxt_val_t *jtxt_val)
{
    /* json value struct|key size|key|val(include terminator) */
    uint32 size = sizeof(json_val_t);
    return add_val_size(size, jtxt_val);
}

static inline status_t append_item(json_t *json, json_arr_t *arr, jtxt_val_t *jtxt_val)
{
    json_val_t *jval;
    uint32 size = calc_item_size(jtxt_val);
    CM_RETURN_IFERR(json->f_alloc(json->mem_ctx, size, (void**)(&jval)));
    assign_val_data(jtxt_val, jval->data);

    jval->next = NULL;
    jval->type = jtxt_val->type;
    if (arr->vals) {
        arr->vals->next = jval;
        ++arr->num;
        return CM_SUCCESS;
    }
    arr->vals = jval;
    arr->num = 1;
    return CM_SUCCESS;
}

static status_t construct_arr(json_t *json, json_arr_t *arr, const text_t *txt)
{
    jtxt_iter_t jtxt;
    CM_RETURN_IFERR(jtxt_iter_init(&jtxt, txt));
    for (;;) {
        bool32 eof;
        jtxt_val_t jtxt_val;
        CM_RETURN_IFERR(jtxt_iter_arr(&eof, &jtxt, &jtxt_val));
        if (SECUREC_UNLIKELY(eof)) {
            break;
        }
        CM_RETURN_IFERR(append_item(json, arr, &jtxt_val));
    }
    return CM_SUCCESS;
}

status_t json_create(json_t *json, const text_t *txt, malloc_t alloc, void *mem_ctx)
{
    json->f_alloc = alloc;
    json->mem_ctx = mem_ctx;
    return construct_obj(json, &json->obj, txt);
}

