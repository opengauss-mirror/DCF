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
 * cm_timer.h
 *    update system timer timely
 *
 * IDENTIFICATION
 *    src/common/cm_time/cm_timer.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_TIMER_H__
#define __CM_TIMER_H__

#include "cm_defs.h"
#include "cm_thread.h"
#include "cm_date.h"

#ifdef __cplusplus
extern "C" {
#endif
#define CM_HOST_TIMEZONE (g_timer()->host_tz_offset)


typedef struct st_gs_timer {
    volatile date_detail_t detail;  // detail of date, yyyy-mm-dd hh24:mi:ss
    volatile date_t now;
    volatile date_t today;          // the day with time 00:00:00
    volatile uint32 systime;        // seconds between timer started and now
    volatile int32 tz;              // time zone (h)
    volatile int64 host_tz_offset;  // host timezone offset (us)
    thread_t thread;
} gs_timer_t;

status_t cm_start_timer(gs_timer_t *timer);
void cm_close_timer(gs_timer_t *timer);
gs_timer_t *g_timer();
void cm_set_timer(gs_timer_t *input_timer);

#ifdef __cplusplus
}
#endif

#endif
