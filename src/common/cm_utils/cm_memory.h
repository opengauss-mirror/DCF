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
 * cm_memory.h
 *
 *
 * IDENTIFICATION
 *    src/common/cm_utils/cm_memory.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_MEMORY_H__
#define __CM_MEMORY_H__

#include "cm_defs.h"
#include "cm_text.h"
#include "cm_spinlock.h"
#ifndef WIN32
#include <sys/mman.h>
#include <execinfo.h>
#include <pthread.h>
#endif
#include "cm_bilist.h"
#ifdef __cplusplus
extern "C" {
#endif


#ifdef WIN32
#ifdef _WIN64
#define CM_MFENCE        \
    {                    \
        _mm_mfence();    \
    }
#else
#define CM_MFENCE        \
    {                    \
        __asm {mfence }  \
    }
#endif
#elif defined(__arm__) || defined(__aarch64__)
#define CM_MFENCE                         \
    {                                     \
        __asm__ volatile("dmb ish" ::     \
                             : "memory"); \
    }
#elif defined(__i386__) || defined(__x86_64__)
#define CM_MFENCE                         \
    {                                     \
        __asm__ volatile("mfence" ::      \
                             : "memory"); \
    }
#elif defined(__loongarch__)
#define CM_MFENCE                         \
    {                                     \
        __asm__ volatile("" ::            \
                             : "memory"); \
    }
#endif


typedef struct st_mem_block {
    struct st_mem_zone *mem_zone;
    uint64 size;         // current block size, contain sizeof(mem_block_t)
    uint64 actual_size;  //
    uint64 bitmap;       // block bitmap at the left and right positions of buddy at all levels
    bilist_node_t link;  // block lst node
    bool8 use_flag;      // block is used
    bool8 reserved[3];
    CM_MAGIC_DECLARE   // first above data field
    char data[4];  // data pointer
} mem_block_t;

#define MEM_BLOCK_LEFT 0
#define MEM_BLOCK_RIGHT 1
#define MEM_BLOCK_SIZE (OFFSET_OF(mem_block_t, data))

#define mem_block_t_MAGIC 8116518
#define mem_zone_t_MAGIC 8116517
#define mem_pool_t_MAGIC 8116519

#define MEM_NUM_FREELISTS 26

typedef struct st_mem_zone {
    struct st_mem_pool *mem;  // memory pool
    uint64 total_size;        // this zone total size
    uint64 used_size;         // used size
    bilist_node_t link;
    union {
        bilist_t list[MEM_NUM_FREELISTS];
        struct {
            bilist_t list_64;
            bilist_t list_128;
            bilist_t list_256;
            bilist_t list_512;
            bilist_t list_1k;
            bilist_t list_2k;
            bilist_t list_4k;
            bilist_t list_8k;
            bilist_t list_16k;
            bilist_t list_32k;
            bilist_t list_64k;
            bilist_t list_128k;
            bilist_t list_256k;
            bilist_t list_512k;
            bilist_t list_1m;
            bilist_t list_2m;
            bilist_t list_4m;
            bilist_t list_8m;
            bilist_t list_16m;
            bilist_t list_32m;
            bilist_t list_64m;
            bilist_t list_128m;
            bilist_t list_256m;
            bilist_t list_512m;
            bilist_t list_1g;
            bilist_t list_2g;
        };
    };
    CM_MAGIC_DECLARE
} mem_zone_t;

typedef struct st_mem_pool {
    char name[CM_NAME_BUFFER_SIZE];  // memory pool name
    uint64 total_size;               // total size
    uint64 max_size;                 // max size
    uint64 used_size;                // current used size
    spinlock_t lock;
    bilist_t mem_zone_lst;  // mem zone list
    CM_MAGIC_DECLARE
} mem_pool_t;

status_t buddy_pool_init(char *pool_name, uint64 init_size, uint64 max_size, mem_pool_t *mem);
void *galloc(uint64 size, mem_pool_t *mem);
void *grealloc(void *p, uint64 size, mem_pool_t *mem);
void gfree(void *p);
void buddy_pool_deinit(mem_pool_t *mem);
static inline uint64 mem_used_size(const mem_pool_t *mem)
{
    return mem->used_size;
}

static inline uint64 mem_max_size(const mem_pool_t *mem)
{
    return mem->max_size;
}

#ifdef __cplusplus
}
#endif

#endif

