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
 * cm_hash.c
 *
 *
 * IDENTIFICATION
 *    src/common/cm_struct/cm_hash.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_hash.h"
#include <math.h>

static uint32 cm_hash_big_endian(const uint8 *bytes, uint32 length, uint32 range)
{
    uint32 value = HASH_SEED;
    uint32 size = length;
    char seed[4];
    uint8 *ptr = (uint8 *)bytes;
    if (size == 0) {
        return 0;
    }

    while (size >= 4) {
        seed[0] = (char)ptr[0];
        seed[1] = (char)ptr[1];
        seed[2] = (char)ptr[2];
        seed[3] = (char)ptr[3];

        value *= HASH_PRIME;
        value ^= *(uint32 *)seed;

        ptr += 4;
        size -= 4;
    }

    if (size == 0) {
        return (range == INFINITE_HASH_RANGE) ? value : (value % range);
    }

    *(uint32 *)seed = 0;
    if (size == 1) {
        seed[0] = (char)ptr[0];
    } else if (size == 2) {
        seed[0] = (char)ptr[0];
        seed[1] = (char)ptr[1];
    } else if (size == 3) {
        seed[0] = (char)ptr[0];
        seed[1] = (char)ptr[1];
        seed[2] = (char)ptr[2];
    }

    value *= HASH_PRIME;
    value ^= *(uint32 *)seed;
    return (range == INFINITE_HASH_RANGE) ? value : (value % range);
}

static uint32 cm_hash_little_endian(const uint8 *bytes, uint32 length, uint32 range)
{
    uint32 value = HASH_SEED;
    uint32 size = length;
    char seed[4];
    uint8 *ptr;

    ptr = (uint8 *)bytes;
    if (size == 0) {
        return 0;
    }

    while (size >= 4) {
        seed[0] = (char)ptr[3];
        seed[1] = (char)ptr[2];
        seed[2] = (char)ptr[1];
        seed[3] = (char)ptr[0];

        value *= HASH_PRIME;
        value ^= *(uint32 *)seed;

        ptr += 4;
        size -= 4;
    }

    if (size == 0) {
        return (range == INFINITE_HASH_RANGE) ? value : (value % range);
    }

    *(uint32 *)seed = 0;
    if (size == 1) {
        seed[3] = (char)ptr[0];
    } else if (size == 2) {
        seed[3] = (char)ptr[0];
        seed[2] = (char)ptr[1];
    } else if (size == 3) {
        seed[3] = (char)ptr[0];
        seed[2] = (char)ptr[1];
        seed[1] = (char)ptr[2];
    }

    value *= HASH_PRIME;
    value ^= *(uint32 *)seed;
    return (range == INFINITE_HASH_RANGE) ? value : (value % range);
}

uint32 cm_hash_bytes(const uint8 *bytes, uint32 length, uint32 range)
{
    if (IS_BIG_ENDIAN) {
        return cm_hash_big_endian(bytes, length, range);
    } else {
        return cm_hash_little_endian(bytes, length, range);
    }
}


#define F_KEY ((hmap)->hash_funcs.f_key)
#define F_HASH ((hmap)->hash_funcs.f_hash)
#define F_EQUAL ((hmap)->hash_funcs.f_equal)

hash_node_t *cm_hmap_find(hash_map_t *hmap, void *key)
{
    uint32 hval = F_HASH(key);
    uint32 bucket = hval % hmap->bucket_num;
    hash_node_t *curr = hmap->buckets[bucket];
    while (curr) {
        void *rkey = F_KEY(curr);
        if (F_EQUAL(key, rkey)) {
            return curr;
        }
        curr = curr->next;
    }
    return NULL;
}

bool32 cm_hmap_insert(hash_map_t *hmap, hash_node_t *node)
{
    void *key = F_KEY(node);
    uint32 hval = F_HASH(key);
    uint32 bucket = hval % hmap->bucket_num;
    hash_node_t *first = hmap->buckets[bucket];

    if (!first) {
        hmap->buckets[bucket] = node;
        return CM_TRUE;
    }

    hash_node_t *curr = first;
    hash_node_t *last;
    while (curr) {
        void *rkey = F_KEY(curr);
        if (F_EQUAL(key, rkey)) {
            return CM_FALSE;
        }
        last = curr;
        curr = curr->next;
    }
    node->next = NULL;
    last->next = node;
    return CM_TRUE;
}

hash_node_t *cm_hmap_delete(hash_map_t *hmap, void *key)
{
    uint32 hval = F_HASH(key);
    uint32 bucket = hval % hmap->bucket_num;
    hash_node_t *curr = hmap->buckets[bucket];
    hash_node_t *prev = NULL;
    while (curr) {
        void *rkey = F_KEY(curr);
        if (F_EQUAL(key, rkey)) {
            break;
        }
        prev = curr;
        curr = curr->next;
    }
    if (!curr) {
        return NULL;
    }
    if (prev == NULL) {
        hmap->buckets[bucket] = curr->next;
    } else {
        prev->next = curr->next;
    }
    return curr;
}
