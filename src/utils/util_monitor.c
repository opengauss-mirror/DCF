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
 * util_monitor.c
 *
 *
 * IDENTIFICATION
 *    src/utils/util_monitor.c
 *
 * -------------------------------------------------------------------------
 */

#include "util_monitor.h"
#include "../common/cm_utils/cm_file.h"
#include "../common/cm_utils/cm_log.h"

#ifdef WIN32
#define major(dev) (dev)
#define minor(dev) (dev)
#else

#include <sys/sysmacros.h>

#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_cpu {
    char name[DEV_NAME_LEN];
    int64 user;
    int64 nice;
    int64 system;
    int64 idle;
    int64 iowait;
    int64 irq;
    int64 softrq;
} cpu_t;

typedef struct st_disk {
    uint32 major;
    uint32 minor;
    char dev_name[DEV_NAME_LEN];
    uint32 rd_ticks;
    uint32 wr_ticks;
    ulong rd_ios;
    ulong wr_ios;
} disk_t;

typedef struct st_monitor_status {
    cpu_t cpu_usage;
    disk_t disk_usage;
} monitor_status_t;

cpu_disk_load_t g_load_rates[COLLECT_TIMES];
volatile uint64 g_collect_count = 0;

#define CPU_STAT_FILE_NAME      "/proc/stat"
#define DISK_STAT_FILE_NAME     "/proc/diskstats"
#define MAX_BUF_SIZE            256

#define CPU_CONTEXT_FORMAT      "%s %lld %lld %lld %lld %lld %lld %lld"

static status_t read_cpu_usage(monitor_status_t *monitor_status)
{
    int32 fd = -1;
    int32 real_size;
    char buff[MAX_BUF_SIZE];

    CM_RETURN_IFERR(cm_open_file(CPU_STAT_FILE_NAME, O_RDONLY, &fd));
    if (cm_read_file(fd, buff, MAX_BUF_SIZE, &real_size) != CM_SUCCESS) {
        cm_close_file(fd);
        return CM_ERROR;
    }
    cm_close_file(fd);

    CM_RETURN_IFERR(sscanf_s(buff, CPU_CONTEXT_FORMAT, monitor_status->cpu_usage.name,
                             (uint32)sizeof(monitor_status->cpu_usage.name), &monitor_status->cpu_usage.user,
                             &monitor_status->cpu_usage.nice, &monitor_status->cpu_usage.system,
                             &monitor_status->cpu_usage.idle, &monitor_status->cpu_usage.iowait,
                             &monitor_status->cpu_usage.irq, &monitor_status->cpu_usage.softrq) != 8);
    return CM_SUCCESS;
}

static inline status_t get_device_major_and_minor(const char *path, uint32 *major, uint32 *minor)
{
    struct stat buf;
    CM_RETURN_IFERR(stat(path, &buf));
    *major = major(buf.st_dev);
    *minor = minor(buf.st_dev);
    return CM_SUCCESS;
}

#define DISK_DELAY_FORMAT "%u %u %s %lu %*u %lu %u %lu %*u %lu %u %*u %u %u"

static status_t read_disk_delay(const char *log_path, monitor_status_t *monitor_status)
{
    FILE *fp = NULL;
    ulong ulong_tmp;
    char line[MAX_BUF_SIZE];
    uint32 device_major, device_minor, tmp;

    CM_RETURN_IFERR(get_device_major_and_minor(log_path, &device_major, &device_minor));
    fp = fopen(DISK_STAT_FILE_NAME, "r");
    if (fp == NULL) {
        LOG_DEBUG_ERR("[monitor disk] open file failed!");
        return CM_ERROR;
    }
    while (fgets(line, sizeof(line), fp) != NULL) {
        CM_RETURN_IFERR(sscanf_s(line, DISK_DELAY_FORMAT, &monitor_status->disk_usage.major,
                                 &monitor_status->disk_usage.minor, monitor_status->disk_usage.dev_name,
                                 (uint32)sizeof(monitor_status->disk_usage.dev_name),
                                 &monitor_status->disk_usage.rd_ios,
                                 &ulong_tmp, &monitor_status->disk_usage.rd_ticks, &monitor_status->disk_usage.wr_ios,
                                 &ulong_tmp, &monitor_status->disk_usage.wr_ticks, &tmp, &tmp) != 11);
        if (monitor_status->disk_usage.major == device_major && monitor_status->disk_usage.minor == device_minor) {
            LOG_DEBUG_INF("[monitor disk]dev_name: %s, rd_ios: %lu, rd_ticks: %u, wr_ios: %lu, wr_ticks: %u",
                          monitor_status->disk_usage.dev_name, monitor_status->disk_usage.rd_ios,
                          monitor_status->disk_usage.rd_ticks, monitor_status->disk_usage.wr_ios,
                          monitor_status->disk_usage.wr_ticks);
            break;
        }
    }
    (void)fclose(fp);

    return CM_SUCCESS;
}

static status_t cal_cpu_usage(monitor_status_t *monitor_status, uint32 cur, cpu_disk_load_t *load_rate)
{
    int64 fir_count, sec_count, user_and_sys_count;

    cpu_t *sec = &monitor_status[cur].cpu_usage;
    cpu_t *fir = &monitor_status[!cur].cpu_usage;

    fir_count = fir->user + fir->nice + fir->system + fir->idle + fir->iowait + fir->irq + fir->softrq;
    sec_count = sec->user + sec->nice + sec->system + sec->idle + sec->iowait + sec->irq + sec->softrq;
    user_and_sys_count = llabs(((sec->user - fir->user) + sec->system) - fir->system);
    if ((sec_count - fir_count) == 0) {
        load_rate->cpu_rate = 0;
        return CM_SUCCESS;
    }
    load_rate->cpu_rate = (double) user_and_sys_count / ((double) sec_count - (double) fir_count);
    return CM_SUCCESS;
}

static status_t cal_disk_usage(monitor_status_t *monitor_status, uint32 cur, cpu_disk_load_t *load_rate)
{
    errno_t errcode;
    disk_t *tmp;
    disk_t *sec = &monitor_status[cur].disk_usage;
    disk_t *fir = &monitor_status[!cur].disk_usage;
    if (sec->rd_ticks < fir->rd_ticks) {
        tmp = sec;
        sec = fir;
        fir = tmp;
    }

    errcode = strncpy_s(load_rate->dev_name, DEV_NAME_LEN, fir->dev_name, (size_t) strlen(fir->dev_name));
    if (errcode != EOK) {
        return CM_ERROR;
    }

    load_rate->r_await = 0.0;
    if ((sec->rd_ios - fir->rd_ios) != 0) {
        load_rate->r_await = (sec->rd_ticks - fir->rd_ticks) / ((double) (sec->rd_ios - fir->rd_ios));
    }

    load_rate->w_await = 0.0;
    if ((sec->wr_ios - fir->wr_ios) != 0) {
        load_rate->w_await = (sec->wr_ticks - fir->wr_ticks) / ((double) (sec->wr_ios - fir->wr_ios));
    }
    return CM_SUCCESS;
}

status_t cal_cpu_and_disk_load(cpu_disk_load_t *load_rate, const char *log_path)
{
#ifdef WIN32
    load_rate->cpu_rate = 0.0f;
    load_rate->r_await = 0.0f;
    load_rate->w_await = 0.0f;
#else
    errno_t errcode;
    uint32 cur = 0;
    monitor_status_t monitor_status[2] = {0};

    CM_RETURN_IFERR(read_cpu_usage(&monitor_status[0]));
    CM_RETURN_IFERR(read_disk_delay(log_path, &monitor_status[0]));

    cm_sleep(WAIT_MILLISECOND);
    cur = !cur;

    MEMS_RETURN_IFERR(memset_sp(&monitor_status[cur], sizeof(monitor_status_t), 0, sizeof(monitor_status_t)));
    CM_RETURN_IFERR(read_cpu_usage(&monitor_status[cur]));
    CM_RETURN_IFERR(read_disk_delay(log_path, &monitor_status[cur]));

    uint64 old_collect_count = (uint64)cm_atomic_get((atomic_t*)&g_collect_count);
    CM_RETURN_IFERR(cal_cpu_usage(monitor_status, cur, &g_load_rates[old_collect_count]));
    CM_RETURN_IFERR(cal_disk_usage(monitor_status, cur, &g_load_rates[old_collect_count]));

    errcode = strncpy_s(load_rate->dev_name, DEV_NAME_LEN, g_load_rates[0].dev_name,
                        (size_t) strlen(g_load_rates[0].dev_name));
    if (errcode != EOK) {
        return CM_ERROR;
    }

    // latest three results
    load_rate->cpu_rate =
        (g_load_rates[2].cpu_rate + g_load_rates[1].cpu_rate + g_load_rates[0].cpu_rate) / COLLECT_TIMES;
    load_rate->w_await = (g_load_rates[2].w_await + g_load_rates[1].w_await + g_load_rates[0].w_await) / COLLECT_TIMES;
    load_rate->r_await = (g_load_rates[2].r_await + g_load_rates[1].r_await + g_load_rates[0].r_await) / COLLECT_TIMES;

    cm_atomic_cas((atomic_t*)&g_collect_count, old_collect_count, ((old_collect_count + 1) % COLLECT_TIMES));

    LOG_DEBUG_INF("[monitor]cpu_rate: %f,disk w_await: %f (ms),disk r_await: %f (ms)",
                  load_rate->cpu_rate, load_rate->w_await, load_rate->r_await);
#endif
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif