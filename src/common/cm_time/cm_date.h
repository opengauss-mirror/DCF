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
 * cm_date.h
 *
 *
 * IDENTIFICATION
 *    src/common/cm_time/cm_date.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_DATE_H_
#define __CM_DATE_H_

#include <time.h>
#ifndef WIN32
#include <sys/time.h>
#else
#include <Winsock2.h>
#endif
#include <math.h>

#include "cm_date_to_text.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The date type is represented by a 64-bit signed integer. The minimum unit
 * is 1 microsecond. This indicates the precision can reach up to 6 digits after
 * the decimal point.
 */
typedef int64 date_t;

#ifndef WIN32
#define cm_gettimeofday(a) gettimeofday(a, NULL)
#else
#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
#define GS_DELTA_EPOCH_IN_MICROSECS 11644473600000000Ui64
#else
#define GS_DELTA_EPOCH_IN_MICROSECS 11644473600000000ULL
#endif
int cm_gettimeofday(struct timeval *tv);
#endif


#define timeval_t struct timeval

#define TIMEVAL_DIFF_US(t_start, t_end) (((t_end)->tv_sec - (t_start)->tv_sec) * 1000000ULL +  \
        (t_end)->tv_usec - (t_start)->tv_usec)
#define TIMEVAL_DIFF_S(t_start, t_end)  ((t_end)->tv_sec - (t_start)->tv_sec)

/* the minimal units of a day == SECONDS_PER_DAY * MILLISECS_PER_SECOND * MICROSECS_PER_MILLISEC */
#define UNITS_PER_DAY 86400000000LL

/* the difference between 1970.01.01-2000.01.01 in microseconds */
/* FILETIME of Jan 1 1970 00:00:00 GMT, the Zenith epoch */
#define CM_UNIX_EPOCH (-946684800000000LL)

#define CM_MIN_YEAR      1
#define CM_MAX_YEAR      9999

#define CM_IS_VALID_YEAR(year) ((year) >= CM_MIN_YEAR && (year) <= CM_MAX_YEAR)

#define CM_BASELINE_DAY ((int32)730120) /* == days_before_year(CM_BASELINE_YEAY) + 1 */

#define IS_LEAP_YEAR(year) (((year) % 4 == 0) && (((year) % 100 != 0) || ((year) % 400 == 0)) ? 1 : 0)

date_t cm_now();
void cm_now_detail(date_detail_t *detail);
date_t cm_encode_date(const date_detail_t *detail);
time_t cm_current_time();

status_t cm_date2text_ex(date_t date, const text_t *fmt, uint32 precision, text_t *text, uint32 max_len);

static inline status_t cm_date2str_ex(date_t date, text_t *fmt_text, char *str, uint32 max_len)
{
    text_t date_text;
    date_text.str = str;
    date_text.len = 0;

    return cm_date2text_ex(date, fmt_text, 0, &date_text, max_len);
}

static inline status_t cm_date2str(date_t date, const char *fmt, char *str, uint32 max_len)
{
    text_t fmt_text;
    cm_str2text((char *)fmt, &fmt_text);
    return cm_date2str_ex(date, &fmt_text, str, max_len);
}

#ifdef __cplusplus
}
#endif

#endif
