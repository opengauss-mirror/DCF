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
 * cm_hash.h
 *
 *
 * IDENTIFICATION
 *    src/common/cm_struct/cm_hash.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_HASH_H__
#define __CM_HASH_H__

#include "cm_defs.h"
#include "cm_error.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef union {
    uint64 u64;
    struct {
        uint32 u32p0;
        uint32 u32p1;
    };
} u64shape_t;

/** left rotate u32 by n bits */
static inline uint32 cm_crol(uint32 u32, uint32 n)
{
#ifdef WIN32
    u64shape_t shape;
    shape.u64 = ((uint64)u32) << n;
    return shape.u32p0 | shape.u32p1;
#else
    /* In GCC or Linux, this following codes can be optimized by merely
    * one instruction, i.e.: rol  eax, cl */
    return (u32 >> (UINT32_BITS - n)) | (u32 << n);
#endif
}


#define INFINITE_HASH_RANGE (uint32)0
#define HASH_PRIME          (uint32)0x01000193
#define HASH_SEED           (uint32)0x811c9dc5

static inline uint32 cm_hash_uint32(uint32 i32, uint32 range)
{
    i32 *= HASH_SEED;

    if (range != INFINITE_HASH_RANGE) {
        return i32 % range;
    }

    return i32;
}

uint32 cm_hash_bytes(const uint8 *bytes, uint32 size, uint32 range);


typedef struct st_hash_node {
    struct st_hash_node *next;
}hash_node_t;

typedef status_t (*malloc_t)(void *ctx, uint32 size, void **buf);
typedef bool32 (*hash_equal_t)(void *lkey, void *rkey);
typedef uint32 (*hash_func_t)(void *key);
typedef void* (*hash_key_t)(hash_node_t *node);

typedef struct st_hash_funcs {
    hash_key_t f_key;
    hash_equal_t f_equal;
    hash_func_t f_hash;
}hash_funcs_t;

typedef struct st_hash_map {
    hash_funcs_t hash_funcs;
    hash_node_t **buckets;
    uint32 bucket_num;
}hash_map_t;

static inline status_t cm_hmap_init(hash_map_t *hmap, malloc_t f_alloc, void *mem_ctx,
    const hash_funcs_t *funcs, uint32 buckets)
{
    uint32 size = sizeof(hash_node_t *) * buckets;
    CM_RETURN_IFERR(f_alloc(mem_ctx, size, (void **)&hmap->buckets));
    hmap->hash_funcs = *funcs;
    hmap->bucket_num = buckets;
    return CM_SUCCESS;
}

bool32 cm_hmap_insert(hash_map_t *hmap, hash_node_t *node);
hash_node_t *cm_hmap_find(hash_map_t *hmap, void *key);
hash_node_t *cm_hmap_delete(hash_map_t *hmap, void *key);

#ifdef __cplusplus
}
#endif

#endif
