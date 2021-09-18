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
 * util_monitor.h
 *    the head file of cm_monitor
 *
 * IDENTIFICATION
 *    src/utils/util_monitor.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __UTIL_MONITOR_H__
#define __UTIL_MONITOR_H__

#include "cm_error.h"

#ifdef __cplusplus
extern "C" {
#endif

#define COLLECT_TIMES           3               // the number of times to get the occupancy
#define WAIT_MILLISECOND        1000            // 1 second apart
#define DEV_NAME_LEN            32

typedef struct st_cpu_and_disk_load {
    double cpu_rate;
    char dev_name[DEV_NAME_LEN];
    double r_await;
    double w_await;
} cpu_disk_load_t;

status_t cal_cpu_and_disk_load(cpu_disk_load_t *load_rate, const char *log_path);

#ifdef __cplusplus
}
#endif

#endif // __UTIL_MONITOR_H__
