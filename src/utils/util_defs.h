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
 * util_defs.h
 *
 *
 * IDENTIFICATION
 *    src/utils/util_defs.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __UTIL_DEFS__
#define __UTIL_DEFS__
#include "cm_defs.h"
#include "cm_log.h"
#include "time.h"
#include "cm_date_to_text.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MEC_MIN_CHANNEL_NUM      (uint32)(1)
#define MEC_DEFAULT_CHANNEL_NUM  (uint32)(5)
#define MEC_MAX_CHANNEL_NUM      (uint32)(64)

#define MEC_DEFALT_THREAD_NUM            (16)
#define MEC_DEFALT_AGENT_NUM             (10)
#define MEC_MAX_AGENT_NUM                (1000)
#define MEC_MAX_REACTOR_NUM              (100)
#define MEC_MAX_COMPRESS_LEVEL_ZSTD      (22)
#define MEC_MAX_COMPRESS_LEVEL_LZ4       (9)
#define MEC_DEFAULT_COMPRESS_LEVEL       (1)

#define REP_DEFALT_APPEND_THREAS_NUM     (2)
#define REP_MAX_APPEND_THREAS_NUM        (1000)

#define COMM_MEM_POOL_MAX_SIZE         SIZE_M(256)
#define COMM_MEM_POOL_MIN_SIZE         SIZE_M(32)

#define STG_MEM_POOL_MAX_SIZE         SIZE_M(200)
#define STG_MEM_POOL_MIN_SIZE         SIZE_M(32)

#define MEC_MEM_POOL_MAX_SIZE         SIZE_M(100)

#define MESSAGE_BUFFER_SIZE      (SIZE_K(64))
#define PADDING_BUFFER_SIZE      (SIZE_K(1))
#define MEC_BUFFER_RESV_SIZE     (SIZE_K(2)) // used for rep head、mec head and PADDING_BUFFER_SIZE
#define DEFAULT_MEC_BATCH_SIZE            0

#define MEC_MAX_MESSAGE_BUFFER_SIZE      (10 * 1024)
#define MEC_MIN_MESSAGE_BUFFER_SIZE      (32)

#define MAX_MAJORITY_GROUPS_STR_LEN  (1024)

typedef enum en_compress_algorithm {
    COMPRESS_NONE = 0,
    COMPRESS_ZSTD = 1,
    COMPRESS_LZ4  = 2,
    COMPRESS_CEIL = 3,
} compress_algorithm_t;

typedef enum en_flow_ctrl_type {
    FC_NONE         = 0,
    FC_COMMIT_DELAY = 1,
    // add new types here if needed
    FC_CEIL,
} flow_ctrl_type_t;

// XXX, 4*128=512
#define MAX_INST_STR_LEN (512 + 1)

typedef enum en_node_status {
    NODE_UNINIT = 0,
    NODE_NORMAL,
    NODE_BLOCKED,
} node_status_t;

#define CM_CHECK_CJSON_OPER_ERR_AND_RETURN(ret) \
do { \
    if ((ret) == NULL) { \
        LOG_DEBUG_ERR("[CJSON]cJSON API called fail"); \
        return CM_ERROR; \
    } \
} while (0)

typedef uint64 timespec_t;

static inline uint64 cm_clock_now()
{
#ifndef WIN32
    struct timespec now = {0, 0};
    (void)clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec * MICROSECS_PER_SECOND + now.tv_nsec / NANOSECS_PER_MICROSECS;
#else
    uint64 now = GetTickCount();
    return (now * MICROSECS_PER_MILLISEC);
#endif
}

#ifdef __cplusplus
}
#endif

#endif