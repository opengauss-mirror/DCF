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
 * util_perf_stat.h
 *    performance statistics
 *
 * IDENTIFICATION
 *    src/utils/util_perf_stat.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_PERF_STAT_H__
#define __CM_PERF_STAT_H__

#include "cm_defs.h"
#include "cm_atomic.h"

#define MAX_PERF_STAT_COUNT 0x400000
#define MAX_PERF_STAT_MOD   0x3fffff

typedef enum em_ps_stat_type_t {
    PS_WRITE = 0,
    PS_ACCEPT,
    PS_PACK,
    PS_FOLLOWER_ACCEPT,
    PS_COMMIT,
    PS_BEING_APPLY,
    PS_END_APPLY,
    PS_COUNT
}ps_stat_type_t;

typedef struct st_perf_stat_t {
    volatile uint64  pre_index[PS_COUNT];
    volatile uint64  cur_index[PS_COUNT];
    atomic_t log_id[MAX_PERF_STAT_COUNT];
    atomic_t act_time[PS_COUNT][MAX_PERF_STAT_COUNT];
}perf_stat_t;

perf_stat_t *util_get_perf_stat();

#define ps_start(index, time)  \
    do { \
        uint64 pos = (index)&MAX_PERF_STAT_MOD; \
        if (cm_atomic_cas(&util_get_perf_stat()->log_id[pos], 0, index)) { \
            util_get_perf_stat()->cur_index[PS_WRITE] = index; \
            util_get_perf_stat()->act_time[PS_WRITE][pos] = (time); \
        } else { \
        } \
    } while (0);

#define ps_start1(index)  \
    do { \
        uint64 pos = (index)&MAX_PERF_STAT_MOD; \
        if (cm_atomic_cas(&util_get_perf_stat()->log_id[pos], 0, index)) { \
        } else { \
        } \
    } while (0);

#define ps_stop(index)  \
    do { \
        uint64 pos = (index)&MAX_PERF_STAT_MOD; \
        cm_atomic_set(&util_get_perf_stat()->log_id[pos], 0); \
    }while (0);

#define ps_record(type, index, time)  \
    do { \
        uint64 pos = (index)&MAX_PERF_STAT_MOD; \
        if (cm_atomic_get(&util_get_perf_stat()->log_id[pos]) == (index)) { \
            if (cm_atomic_cas(&util_get_perf_stat()->act_time[(type)][pos], 0, (time))) { \
                if ((index) > util_get_perf_stat()->cur_index[(type)]) { \
                    util_get_perf_stat()->cur_index[(type)] = (index); \
                } else { \
                } \
            } \
        } \
    } while (0);

#define ps_record1(type, index)  ps_record(type, index, g_timer()->now)

void ps_get_stat(ps_stat_type_t type, uint64* count, uint64* total, uint64* max);
void ps_get_and_reset_stat(ps_stat_type_t type, uint64* count, uint64* total, uint64* max);

#endif
