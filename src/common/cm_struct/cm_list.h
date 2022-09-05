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
 * cm_list.h
 *
 *
 * IDENTIFICATION
 *    src/common/cm_struct/cm_list.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_LIST_H__
#define __CM_LIST_H__
#include "cm_defs.h"
#include "cm_log.h"
#ifdef WIN32
#else
#include <string.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define LIST_EXTENT_SIZE 32

/* pointer list */
typedef struct st_ptlist {
    pointer_t *items;
    uint32 capacity;
    uint32 count;
} ptlist_t;

static inline void cm_ptlist_init(ptlist_t *list)
{
    list->items = NULL;
    list->capacity = 0;
    list->count = 0;
}

static inline void cm_ptlist_reset(ptlist_t *list)
{
    list->count = 0;
}

static inline void cm_destroy_ptlist(ptlist_t *list)
{
    if (list->items != NULL) {
        CM_FREE_PTR(list->items);
    }

    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static inline pointer_t cm_ptlist_get(ptlist_t *list, uint32 index)
{
    if (index >= list->capacity) {
        return NULL;
    }
    return list->items[index];
}

static inline void cm_ptlist_set(ptlist_t *list, uint32 index, pointer_t item)
{
    list->items[index] = item;
}

static inline status_t cm_ptlist_extend(ptlist_t *list, uint32 extent_size)
{
    pointer_t *new_items = NULL;
    uint32 buf_size;
    errno_t errcode;
    buf_size = (list->capacity + extent_size) * sizeof(pointer_t);
    if (buf_size == 0 || (buf_size / sizeof(pointer_t) != list->capacity + extent_size)) {
        LOG_DEBUG_ERR("cm_ptlist_add extending list failed");
        return CM_ERROR;
    }
    new_items = (pointer_t *)malloc(buf_size);
    if (new_items == NULL) {
        LOG_DEBUG_ERR("cm_ptlist_add extending list failed");
        return CM_ERROR;
    }
    errcode = memset_sp(new_items, buf_size, 0, buf_size);
    if (errcode != EOK) {
        CM_FREE_PTR(new_items);
        LOG_DEBUG_ERR("cm_ptlist_add extending list failed");
        return CM_ERROR;
    }
    if (list->items != NULL) {
        if (list->capacity != 0) {
            errcode = memcpy_sp(new_items, buf_size, list->items,
                (uint32)(list->capacity * sizeof(pointer_t)));
            if (errcode != EOK) {
                CM_FREE_PTR(new_items);
                LOG_DEBUG_ERR("cm_ptlist_add extending list failed");
                return CM_ERROR;
            }
        }

        CM_FREE_PTR(list->items);
    }
    list->items = new_items;
    list->capacity += extent_size;

    return CM_SUCCESS;
}

static inline status_t cm_ptlist_add(ptlist_t *list, pointer_t item)
{
    if (list->count >= list->capacity) { /* extend the list */
        if (cm_ptlist_extend(list, LIST_EXTENT_SIZE) != CM_SUCCESS) {
            return CM_ERROR;
        }
    }
    list->items[list->count] = item;
    list->count++;
    return CM_SUCCESS;
}

static inline status_t cm_ptlist_insert(ptlist_t *list, uint32 index, pointer_t item)
{
    if (index >= list->capacity) { /* extend the list */
        if (cm_ptlist_extend(list, (index - list->capacity) + LIST_EXTENT_SIZE) != CM_SUCCESS) {
            return CM_ERROR;
        }
    }

    list->count++;
    list->items[index] = item;
    return CM_SUCCESS;
}

static inline status_t cm_ptlist_remove(ptlist_t *list, uint32 index)
{
    if (index >= list->capacity || list->count == 0) {
        LOG_DEBUG_ERR("cm_ptlist_remove failed");
        return CM_ERROR;
    }
    if (list->items[index] == NULL) {
        return CM_SUCCESS;
    }
    list->items[index] = NULL;
    list->count--;
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#endif

