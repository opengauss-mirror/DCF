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
 * rep_monitor.c
 *    leader monitor
 *
 * IDENTIFICATION
 *    src/replication/rep_monitor.c
 *
 * -------------------------------------------------------------------------
 */

#include "rep_monitor.h"
#include "md_defs.h"
#include "mec.h"
#include "cm_file.h"
#include "cm_log.h"
#include "cm_date_to_text.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MID_LEVEL_RATE              0.7
#define PERCENTAGE                  100

static char g_log_home[CM_FULL_PATH_BUFFER_SIZE] = {0};  // log path to find the disk's sector

static inline uint32 rep_monitor_get_cpu_threshold()
{
    param_value_t value;
    if (md_get_param(DCF_PARAM_CPU_THRESHOLD, &value) == CM_SUCCESS) {
        return value.cpu_load_threshold;
    } else {
        return (uint32)CM_DEFAULT_CPU_THRESHOLD;
    }
}

static inline uint32 rep_monitor_get_network_threshold()
{
    param_value_t value;
    if (md_get_param(DCF_PARAM_NET_QUEUE_THRESHOLD, &value) == CM_SUCCESS) {
        return value.net_queue_threshold;
    } else {
        return (uint32)CM_DEFAULT_NET_QUEUE_MESS_NUM;
    }
}
static inline uint32 rep_monitor_get_disk_threshold()
{
    param_value_t value;
    if (md_get_param(DCF_PARAM_DISK_RAWAIT_THRESHOLD, &value) == CM_SUCCESS) {
        return value.disk_rawait_threshold;
    } else {
        return (uint32)CM_DEFAULT_DISK_RAWAIT_THRESHOLD;
    }
}

status_t rep_monitor_init()
{
    param_value_t param_value;

    LOG_RUN_INF("[monitor]monitor init start.");

    // find the log path
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_DATA_PATH, &param_value));
    PRTS_RETURN_IFERR(snprintf_s(g_log_home, CM_FULL_PATH_BUFFER_SIZE, CM_FULL_PATH_BUFFER_SIZE - 1, "%s",
        param_value.log_path));

    LOG_RUN_INF("[monitor]dcf log path: %s", g_log_home);

    LOG_RUN_INF("[monitor]monitor init end.");
    return CM_SUCCESS;
}

status_t rep_monitor_statistics(rep_monitor_statistics_t *statistics)
{
    statistics->load_level = cal_load_level();
    if (statistics->load_level == DCF_LOAD_HIGH_LEVEL) {
        if (statistics->adjust_step > 0.0001) {
            statistics->high_level_times++;
        }
        statistics->mid_level_times = 0;
    } else if (statistics->load_level == DCF_LOAD_MID_LEVEL) {
        if (statistics->mid_level_times > DURATION_MID_LEVEL_TIMES && statistics->high_level_times > 0) {
            statistics->high_level_times--;
        } else {
            statistics->mid_level_times++;
        }
    } else {
        statistics->mid_level_times =  0;
        statistics->high_level_times = 0;
    }
    statistics->adjust_step = pow(HIGH_LEVEL_ADJUST_STEP, statistics->high_level_times);
    LOG_DEBUG_INF("[monitor]statistics high: %u, mid: %u, load level: %d, step: %f",
        statistics->high_level_times, statistics->mid_level_times, statistics->load_level, statistics->adjust_step);

    return CM_SUCCESS;
}

static monitor_load_level_t cal_net_load_level()
{
    uint64 average_count;
    uint64 queue_count = 0;
    for (int i = 0; i < COLLECT_TIMES; i++) {
        cm_sleep(CM_SLEEP_50_FIXED);
        queue_count += mec_get_send_que_count(PRIV_LOW);
    }
    LOG_DEBUG_INF("send queue count : %llu", queue_count);

    average_count = queue_count / COLLECT_TIMES;
    if (average_count > rep_monitor_get_network_threshold()) {
        return DCF_LOAD_HIGH_LEVEL;
    } else if (average_count > rep_monitor_get_network_threshold() * MID_LEVEL_RATE) {
        return DCF_LOAD_MID_LEVEL;
    } else {
        return DCF_LOAD_LOW_LEVEL;
    }
}

static inline uint32 ms_to_us(double r_await)
{
    return (uint32)(r_await * MICROSECS_PER_MILLISEC);
}

monitor_load_level_t cal_cpu_and_disk_load_level()
{
    cpu_disk_load_t load_rate;
    (void)cal_cpu_and_disk_load(&load_rate, g_log_home);
    if (load_rate.cpu_rate * PERCENTAGE > rep_monitor_get_cpu_threshold() ||
        ms_to_us(load_rate.r_await) > rep_monitor_get_disk_threshold()) {
        return DCF_LOAD_HIGH_LEVEL;
    } else if (load_rate.cpu_rate * PERCENTAGE > rep_monitor_get_cpu_threshold() * MID_LEVEL_RATE ||
               ms_to_us(load_rate.r_await) > rep_monitor_get_disk_threshold() * MID_LEVEL_RATE) {
        return DCF_LOAD_MID_LEVEL;
    } else {
        return DCF_LOAD_LOW_LEVEL;
    }
}

monitor_load_level_t cal_load_level()
{
    monitor_load_level_t disk_and_cpu_load_level = cal_cpu_and_disk_load_level();
    if (disk_and_cpu_load_level == DCF_LOAD_HIGH_LEVEL) {
        return DCF_LOAD_HIGH_LEVEL;
    }

    monitor_load_level_t net_load_level = cal_net_load_level();
    return disk_and_cpu_load_level > net_load_level ? disk_and_cpu_load_level : net_load_level;
}

#ifdef __cplusplus
}
#endif