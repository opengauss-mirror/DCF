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
 * util_perf_stat.c
 *    performance statistics
 *
 * IDENTIFICATION
 *    src/utils/util_perf_stat.c
 *
 * -------------------------------------------------------------------------
 */

#include "util_perf_stat.h"

perf_stat_t g_perf_stat;

perf_stat_t *util_get_perf_stat()
{
    return &g_perf_stat;
}

static void ps_get_cur_stat(uint64 start, uint64 end, ps_stat_type_t type, uint64* count, uint64* total, uint64* max)
{
    (*count) = 0;
    (*total) = 0;
    (*max) = 0;
    if (end == 0) {
        return;
    }

    uint64 pre_end_time = 0;

    for (uint64 index = end; index >= start; index--) {
        uint64 pos = index&MAX_PERF_STAT_MOD;
        if (index != cm_atomic_get(&g_perf_stat.log_id[pos])) {
            continue;
        }
        uint64 end_time = g_perf_stat.act_time[type][pos];
        uint64 start_time = g_perf_stat.act_time[PS_WRITE][pos];
        if (start_time == 0) {
            continue;
        }

        if (end_time == 0) {
            if (pre_end_time != 0) {
                end_time = pre_end_time;
            } else {
                continue;
            }
        } else {
            pre_end_time = end_time;
        }

        if (end_time < start_time) {
            continue;
        }

        (*count)++;
        uint64 delay = end_time - start_time;
        (*total) += delay;
        (*max) = (*max) < delay ? delay : (*max);
    }
}

void ps_get_stat(ps_stat_type_t type, uint64* count, uint64* total, uint64* max)
{
    uint64 start = g_perf_stat.pre_index[type] + 1;
    uint64 end = g_perf_stat.cur_index[type];
    ps_get_cur_stat(start, end, type, count, total, max);
}

void ps_get_and_reset_stat(ps_stat_type_t type, uint64* count, uint64* total, uint64* max)
{
    uint64 start = g_perf_stat.pre_index[type] + 1;
    uint64 end = g_perf_stat.cur_index[type];
    g_perf_stat.pre_index[type] = end;

    ps_get_cur_stat(start, end, type, count, total, max);

    if (type == PS_COUNT - 1) {
        for (uint64 index = end; index >= start; index--) {
            uint64 pos = index&MAX_PERF_STAT_MOD;
            for (int i = 0; i < PS_COUNT; i++) {
                g_perf_stat.act_time[i][pos] = 0;
            }
            cm_atomic_set(&g_perf_stat.log_id[pos], 0);
        }
    }
}

