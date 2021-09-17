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
 * rep_monitor.h
 *    leader monitor
 *
 * IDENTIFICATION
 *    src/replication/rep_monitor.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DCF_REP_MONITOR_H__
#define __DCF_REP_MONITOR_H__

#include "util_monitor.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DURATION_MID_LEVEL_TIMES    (32)
#define HIGH_LEVEL_ADJUST_STEP      (0.8)
#define HIGH_LEVEL_SUSPEND_TIME     (1000 * 1000)   // 1s

typedef enum en_monitor_load_level {
    DCF_LOAD_LOW_LEVEL = 0,
    DCF_LOAD_MID_LEVEL,
    DCF_LOAD_HIGH_LEVEL,
} monitor_load_level_t;

typedef struct st_rep_monitor_statistics {
    monitor_load_level_t load_level;
    double adjust_step;
    uint32 high_level_times;
    uint32 mid_level_times;
} rep_monitor_statistics_t;

status_t rep_monitor_init();
status_t rep_monitor_statistics(rep_monitor_statistics_t *statistics);

monitor_load_level_t cal_cpu_and_disk_load_level();
monitor_load_level_t cal_load_level();

#ifdef __cplusplus
}
#endif

#endif // DCF_REP_MONITOR_H
