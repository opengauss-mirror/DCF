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
 * bucket_list.h
 *
 *
 * IDENTIFICATION
 *    src/storage/bucket_list.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __BUCKET_LIST_H__
#define __BUCKET_LIST_H__

#include "cm_defs.h"
#include "util_error.h"
#include "cm_log.h"
#ifdef WIN32
#else
#include <string.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define BUCKET_BIT_COUNT   11
#define BUCKET_SIZE        (1<<BUCKET_BIT_COUNT)        // 2048
#define BUCKET_BITMAP      (BUCKET_SIZE - 1)            // 0x7ff

#define EXTENT_BUCKET_SIZE 32

typedef int32 (*bucket_list_cmp_func_t)(const pointer_t item1, const pointer_t item2);

typedef struct st_bucket {
    uint16    pos;
    uint16    offset;
    pointer_t items[BUCKET_SIZE];
}bucket_t;

typedef struct st_bucket_list {
    uint32    size;
    uint32    capacity;
    uint32    bucket_count;
    uint32    first_offset;
    bucket_t *buckets;
}bucket_list_t;

static inline void bucket_reset(bucket_t *bucket)
{
    bucket->pos = bucket->offset = 0;
}

static inline bool32 bucket_empty(const bucket_t *bucket)
{
    return (bucket->pos - bucket->offset) == 0;
}

static inline bool32 bucket_full(const bucket_t *bucket)
{
    return bucket->pos == BUCKET_SIZE;
}

static inline void bucket_add(bucket_t *bucket, pointer_t item)
{
    bucket->items[bucket->pos++] = item;
}

static inline void bucket_set(bucket_t *bucket, uint32 idx, pointer_t item)
{
    bucket->items[idx] = item;
}

static inline pointer_t bucket_get(bucket_t *bucket, uint32 idx)
{
    return bucket->items[idx];
}

static inline pointer_t bucket_first(bucket_t *bucket)
{
    return bucket->items[bucket->offset];
}

static inline pointer_t bucket_last(bucket_t *bucket)
{
    return bucket->items[bucket->pos - 1];
}

static inline void bucket_del_first(bucket_t *bucket)
{
    bucket->items[bucket->offset] = NULL;
    bucket->offset++;
}

static inline void bucket_del_last(bucket_t *bucket)
{
    bucket->items[bucket->pos - 1] = NULL;
    bucket->pos--;
}

static status_t bucket_list_extent(bucket_list_t *list)
{
    uint32 old_capacity = list->capacity;
    uint32 new_capacity = old_capacity + EXTENT_BUCKET_SIZE;
    uint32 buf_size     = new_capacity * sizeof(bucket_t);

    bucket_t *new_buckets = (bucket_t *)malloc(buf_size);
    if (new_buckets == NULL) {
        LOG_DEBUG_ERR("[STG]bucket_list_extent malloc %d failed", buf_size);
        return CM_ERROR;
    }

    errno_t errcode = memset_s((char *)new_buckets, buf_size, 0, buf_size);
    if (errcode != EOK) {
        CM_FREE_PTR(new_buckets);
        LOG_DEBUG_ERR("[STG]bucket_list_extent memset_s failed");
        return CM_ERROR;
    }

    if (old_capacity > 0) {
        errcode = memcpy_sp((char*)new_buckets, (size_t)buf_size, (char*)list->buckets,
            (size_t)(old_capacity * sizeof(bucket_t)));
        if (errcode != EOK) {
            CM_FREE_PTR(new_buckets);
            LOG_DEBUG_ERR("[STG]bucket_list_extent memcpy_sp failed");
            return CM_ERROR;
        }
        CM_FREE_PTR(list->buckets);
    }

    list->buckets  = new_buckets;
    list->capacity = new_capacity;
    return CM_SUCCESS;
}

static inline status_t bucket_list_init(bucket_list_t *list)
{
    list->size         = 0;
    list->capacity     = 0;
    list->bucket_count = 0;
    list->first_offset = 0;
    return bucket_list_extent(list);
}

static inline void bucket_list_deinit(bucket_list_t *list)
{
    list->size         = 0;
    list->capacity     = 0;
    list->bucket_count = 0;
    list->first_offset = 0;
    CM_FREE_PTR(list->buckets);
    list->buckets = NULL;
}

static inline uint32 bucket_list_size(const bucket_list_t *list)
{
    return list->size;
}

static inline uint32 bucket_list_empty(const bucket_list_t *list)
{
    return list->size == 0;
}

static inline status_t bucket_list_add(bucket_list_t *list, pointer_t item)
{
    if (bucket_full(&list->buckets[list->bucket_count])) {
        /* extend the list */
        if (list->bucket_count + 1 >= list->capacity) {
            CM_RETURN_IFERR(bucket_list_extent(list));
        }
        list->bucket_count++;
    }
    bucket_add(&list->buckets[list->bucket_count], item);
    list->size++;
    return CM_SUCCESS;
}

static inline void bucket_list_set(bucket_list_t *list, uint32 index, pointer_t item)
{
    uint32 item_idx = (index + list->first_offset) % BUCKET_SIZE;
    uint32 bucket_idx = (index + list->first_offset) / BUCKET_SIZE;
    bucket_set(&list->buckets[bucket_idx], item_idx, item);
}

static inline pointer_t bucket_list_get(bucket_list_t *list, uint32 index)
{
    uint32 item_idx = (index + list->first_offset) & BUCKET_BITMAP;
    uint32 bucket_idx = (index + list->first_offset) >> BUCKET_BIT_COUNT;
    return bucket_get(&list->buckets[bucket_idx], item_idx);
}

static inline pointer_t bucket_list_get1(bucket_list_t *list, uint32 index)
{
    uint32 item_idx = (index + list->first_offset) & BUCKET_BITMAP;
    uint32 bucket_idx = (index + list->first_offset) >> BUCKET_BIT_COUNT;
    if (SECUREC_UNLIKELY(bucket_idx > list->bucket_count)) {
        return NULL;
    }

    return bucket_get(&list->buckets[bucket_idx], item_idx);
}


static inline void bucket_list_recycle(bucket_list_t *list)
{
    bucket_reset(&list->buckets[list->bucket_count]);
    if (list->bucket_count == 0) {
        list->size = list->first_offset = 0;
    } else {
        list->bucket_count--;
    }
}

static inline pointer_t bucket_list_first(bucket_list_t *list)
{
    bucket_t *bucket = &list->buckets[0];
    return bucket_first(bucket);
}

static inline void bucket_list_del_first(bucket_list_t *list)
{
    bucket_t *bucket = &list->buckets[0];

    list->size--;
    bucket_del_first(bucket);
    if (!bucket_empty(bucket)) {
        list->first_offset = bucket->offset;
    } else {
        list->first_offset = 0;
        for (uint32 i = 1; i <= list->bucket_count; ++i) {
            list->buckets[i - 1] = list->buckets[i];
        }
        bucket_list_recycle(list);
    }
}

static inline pointer_t bucket_list_last(bucket_list_t *list)
{
    bucket_t *bucket = &list->buckets[list->bucket_count];
    return bucket_last(bucket);
}

static inline void bucket_list_del_last(bucket_list_t *list)
{
    bucket_t *bucket = &list->buckets[list->bucket_count];

    list->size--;
    bucket_del_last(bucket);
    if (bucket_empty(bucket)) {
        bucket_list_recycle(list);
    }
}

static inline void bucket_list_sort(bucket_list_t *list, bucket_list_cmp_func_t cmp_func)
{
    if (list->size <= 1) {
        return;
    }

    for (uint32 j = 0; j < list->size - 1; j++) {
        for (uint32 i = 0; i < ((list->size - 1) - j); i++) {
            pointer_t item1 = bucket_list_get(list, i);
            pointer_t item2 = bucket_list_get(list, i + 1);
            if (cmp_func(item1, item2) > 0) {
                bucket_list_set(list, i, item2);
                bucket_list_set(list, i + 1, item1);
            }
        }
    }
}

#ifdef __cplusplus
}
#endif

#endif
