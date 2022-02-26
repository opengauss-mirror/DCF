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
 * cm_date.c
 *    Implement of date
 *
 * IDENTIFICATION
 *    src/common/cm_time/cm_date.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_date.h"
#include "cm_timer.h"
#include "cm_date_to_text.h"

static text_t CM_NLS_DATE_FORMAT = { "YYYY-MM-DD HH24:MI:SS", 21 };

uint16 g_month_days[2][12] = {
    { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
    { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
};

typedef enum g_date_time_mask {
    MASK_NONE = 0,
    MASK_YEAR = 0x0000001,
    MASK_MONTH = 0x0000002,
    MASK_DAY = 0x0000004,
    MASK_HOUR = 0x0000008,
    MASK_MINUTE = 0x0000010,
    MASK_SECOND = 0x0000020,
    MASK_USEC = 0x0000040,
    MASK_TZ_HOUR = 0x0000080,
    MASK_TZ_MINUTE = 0x0000100,
} date_time_mask_t;

static format_item_t g_formats[] = {
    {
        .name = { (char *)"%Y", 2 },
        .id = FMT_YEAR4,
        .fmask = MASK_YEAR,
        .placer = 4,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"%D", 2 },
        .id = FMT_DAY_OF_MONTH,
        .fmask = MASK_DAY,
        .placer = -1,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"%M", 2 },
        .id = FMT_MONTH_NAME,
        .fmask = MASK_MONTH,
        .placer = -1,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"%h", 2 },
        .id = FMT_HOUR_OF_DAY24,
        .fmask = MASK_HOUR,
        .placer = -1,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"%i", 2 },
        .id = FMT_MINUTE,
        .fmask = MASK_MINUTE,
        .placer = -1,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"%s", 2 },
        .id = FMT_SECOND,
        .fmask = MASK_SECOND,
        .placer = -1,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"%x", 2 },
        .id = FMT_YEAR4,
        .fmask = MASK_YEAR,
        .placer = 4,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)" ", 1 },
        .id = FMT_SPACE,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"-", 1 },
        .id = FMT_MINUS,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"\\", 1 },
        .id = FMT_SLASH,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"/", 1 },
        .id = FMT_BACK_SLASH,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)",", 1 },
        .id = FMT_COMMA,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)".", 1 },
        .id = FMT_DOT,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)";", 1 },
        .id = FMT_SEMI_COLON,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)":", 1 },
        .id = FMT_COLON,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"X", 1 },
        .id = FMT_X,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"\"", 1 },
        .id = FMT_DQ_TEXT,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"AM", 2 },
        .id = FMT_AM_INDICATOR,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CM_FALSE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"A.M.", 4 },
        .id = FMT_AM_INDICATOR,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CM_FALSE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"PM", 2 },
        .id = FMT_PM_INDICATOR,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CM_FALSE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"P.M.", 4 },
        .id = FMT_PM_INDICATOR,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CM_FALSE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"CC", 2 },
        .id = FMT_CENTURY,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CM_FALSE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"SCC", 3 },
        .id = FMT_CENTURY,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CM_FALSE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"DAY", 3 },
        .id = FMT_DAY_NAME,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CM_FALSE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"DY", 2 },
        .id = FMT_DAY_ABBR_NAME,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CM_FALSE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"DDD", 3 },
        .id = FMT_DAY_OF_YEAR,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CM_FALSE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"DD", 2 },
        .id = FMT_DAY_OF_MONTH,
        .fmask = MASK_DAY,
        .placer = -1,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"D", 1 },
        .id = FMT_DAY_OF_WEEK,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CM_FALSE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"FF1", 3 },
        .id = FMT_FRAC_SECOND1,
        .fmask = MASK_USEC,
        .placer = 1,
        .reversible = CM_TRUE,
        .dt_used = CM_FALSE,
    },
    {
        .name = { (char *)"FF2", 3 },
        .id = FMT_FRAC_SECOND2,
        .fmask = MASK_USEC,
        .placer = 2,
        .reversible = CM_TRUE,
        .dt_used = CM_FALSE,
    },
    {
        .name = { (char *)"FF3", 3 },
        .id = FMT_FRAC_SECOND3,
        .fmask = MASK_USEC,
        .placer = 3,
        .reversible = CM_TRUE,
        .dt_used = CM_FALSE,
    },
    {
        .name = { (char *)"FF4", 3 },
        .id = FMT_FRAC_SECOND4,
        .fmask = MASK_USEC,
        .placer = 4,
        .reversible = CM_TRUE,
        .dt_used = CM_FALSE,
    },
    {
        .name = { (char *)"FF5", 3 },
        .id = FMT_FRAC_SECOND5,
        .fmask = MASK_USEC,
        .placer = 5,
        .reversible = CM_TRUE,
        .dt_used = CM_FALSE,
    },
    {
        .name = { (char *)"FF6", 3 },
        .id = FMT_FRAC_SECOND6,
        .fmask = MASK_USEC,
        .placer = 6,
        .reversible = CM_TRUE,
        .dt_used = CM_FALSE,
    },
    {
        .name = { (char *)"FF", 2 },
        .id = FMT_FRAC_SEC_VAR_LEN,
        .fmask = MASK_USEC,
        .placer = 6,
        .reversible = CM_TRUE,
        .dt_used = CM_FALSE,
    }, /* FF must be after FF3, FF6, FF9 */
    {
        .name = { (char *)"HH12", 4 },
        .id = FMT_HOUR_OF_DAY12,
        .fmask = MASK_HOUR,
        .placer = -1,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"HH24", 4 },
        .id = FMT_HOUR_OF_DAY24,
        .fmask = MASK_HOUR,
        .placer = -1,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"HH", 2 },
        .id = FMT_HOUR_OF_DAY12,
        .fmask = MASK_HOUR,
        .placer = -1,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"MI", 2 },
        .id = FMT_MINUTE,
        .fmask = MASK_MINUTE,
        .placer = -1,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"MM", 2 },
        .id = FMT_MONTH,
        .fmask = MASK_MONTH,
        .placer = -1,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"RM", 2 },
        .id = FMT_MONTH_RM,
        .fmask = MASK_MONTH,
        .placer = -1,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"MONTH", 5 },
        .id = FMT_MONTH_NAME,
        .fmask = MASK_MONTH,
        .placer = -1,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"MON", 3 },
        .id = FMT_MONTH_ABBR_NAME,
        .fmask = MASK_MONTH,
        .placer = -1,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"Q", 1 },
        .id = FMT_QUARTER,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CM_FALSE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"SSSSS", 5 },
        .id = FMT_SECOND_PASS,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CM_FALSE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"SS", 2 },
        .id = FMT_SECOND,
        .fmask = MASK_SECOND,
        .placer = -1,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"WW", 2 },
        .id = FMT_WEEK_OF_YEAR,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CM_FALSE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"W", 1 },
        .id = FMT_WEEK_OF_MONTH,
        .fmask = MASK_NONE,
        .placer = -1,
        .reversible = CM_FALSE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"YYYY", 4 },
        .id = FMT_YEAR4,
        .fmask = MASK_YEAR,
        .placer = 4,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"YYY", 3 },
        .id = FMT_YEAR3,
        .fmask = MASK_NONE,
        .placer = 3,
        .reversible = CM_FALSE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"YY", 2 },
        .id = FMT_YEAR2,
        .fmask = MASK_NONE,
        .placer = 2,
        .reversible = CM_FALSE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"Y", 1 },
        .id = FMT_YEAR1,
        .fmask = MASK_NONE,
        .placer = 1,
        .reversible = CM_FALSE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"TZH", 3 },
        .id = FMT_TZ_HOUR,
        .fmask = MASK_TZ_HOUR,
        .placer = -1,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
    {
        .name = { (char *)"TZM", 3 },
        .id = FMT_TZ_MINUTE,
        .fmask = MASK_TZ_MINUTE,
        .placer = -1,
        .reversible = CM_TRUE,
        .dt_used = CM_TRUE,
    },
};

#define DATE_FORMAT_COUNT (sizeof(g_formats) / sizeof(format_item_t))

date_t cm_now()
{
    date_t dt = CM_UNIX_EPOCH + CM_HOST_TIMEZONE;
    timeval_t tv;

    (void)cm_gettimeofday(&tv);
    dt += ((int64)tv.tv_sec * MICROSECS_PER_SECOND + tv.tv_usec);
    return dt;
}


#ifdef WIN32
int cm_gettimeofday(struct timeval *tv)
{
    if (tv == NULL) {
        return 0;
    }

    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);

    uint64 temp = ((uint64)ft.dwLowDateTime | ((uint64)ft.dwHighDateTime << 32)) / 10; /* convert into microseconds */

    /* converting file time to unix epoch */
    temp -= GS_DELTA_EPOCH_IN_MICROSECS;
    tv->tv_sec = (long)(temp / 1000000UL);
    tv->tv_usec = (long)(temp % 1000000UL);

    return 0;
}
#endif

void cm_now_detail(date_detail_t *detail)
{
#ifdef WIN32
    SYSTEMTIME sys_time;
    GetLocalTime(&sys_time);

    detail->year = (uint16)sys_time.wYear;
    detail->mon = (uint8)sys_time.wMonth;
    detail->day = (uint8)sys_time.wDay;
    detail->hour = (uint8)sys_time.wHour;
    detail->min = (uint8)sys_time.wMinute;
    detail->sec = (uint8)sys_time.wSecond;
    detail->millisec = (uint16)sys_time.wMilliseconds;
    detail->microsec = 0;
    detail->nanosec = 0;
#else
    time_t t_var;
    struct timeval tv;
    struct tm ut;

    (void)gettimeofday(&tv, NULL);
    t_var = tv.tv_sec;
    (void)localtime_r(&t_var, &ut);

    detail->year = (uint16)ut.tm_year + 1900;
    detail->mon = (uint8)ut.tm_mon + 1;
    detail->day = (uint8)ut.tm_mday;
    detail->hour = (uint8)ut.tm_hour;
    detail->min = (uint8)ut.tm_min;
    detail->sec = (uint8)ut.tm_sec;
    detail->millisec = (uint16)((tv.tv_usec) / 1000);
    detail->microsec = (uint16)(tv.tv_usec % 1000);
    detail->nanosec = 0;
#endif
}

/* "year -> number of days before January 1st of year" */
static inline int32 days_before_year(int32 year)
{
    --year;
    return (((year * 365) + (year / 4)) - (year / 100)) + (year / 400);
}

static inline int32 total_days_before_date(const date_detail_t *detail)
{
    int32 i;
    int32 total_days;

    // compute total days
    total_days = days_before_year((int32)detail->year) - CM_BASELINE_DAY;
    uint16 *day_tab = (uint16 *)g_month_days[IS_LEAP_YEAR(detail->year)];
    for (i = 0; i < (int32)(detail->mon - 1); i++) {
        total_days += (int32)day_tab[i];
    }
    total_days += detail->day;

    return total_days;
}

date_t cm_encode_date(const date_detail_t *detail)
{
    int32 total_days;
    date_t date_tmp;

    CM_ASSERT(CM_IS_VALID_YEAR(detail->year));
    CM_ASSERT(detail->mon >= 1 && detail->mon <= 12);
    CM_ASSERT(detail->day >= 1 && detail->day <= 31);
    CM_ASSERT(detail->hour <= 23);
    CM_ASSERT(detail->min <= 59);
    CM_ASSERT(detail->sec <= 59);
    CM_ASSERT(detail->microsec <= 999);
    CM_ASSERT(detail->millisec <= 999);

    // compute total days
    total_days = total_days_before_date(detail);

    // encode the date into an integer with 1 nanosecond as the the minimum unit
    date_tmp = (int64)total_days * SECONDS_PER_DAY;
    date_tmp += (uint32)detail->hour * SECONDS_PER_HOUR;
    date_tmp += (uint32)detail->min * SECONDS_PER_MIN;
    date_tmp += detail->sec;
    date_tmp = date_tmp * MILLISECS_PER_SECOND + detail->millisec;
    date_tmp = date_tmp * MICROSECS_PER_MILLISEC + detail->microsec;

    return date_tmp;
}

time_t cm_current_time()
{
    return time(NULL);
}

/*
 * Fetch the double-quote-text item from format text, and extract the text into extra
 */
static inline status_t cm_fetch_dqtext_item(text_t *fmt, text_t *extra, bool32 do_trim)
{
    int32 pos;

    CM_REMOVE_FIRST(fmt);  // remove the first quote "
    pos = cm_text_chr(fmt, '"');
    if (pos < 0) {
        return ERR_TEXT_FORMAT_ERROR;
    }

    extra->str = fmt->str;
    extra->len = (uint32)pos;
    if (do_trim) {
        cm_trim_text(extra);
    }
    CM_REMOVE_FIRST_N(fmt, pos + 1);
    return CM_SUCCESS;
}

/**
 * extra -- the extra information for the format_item
 */
static inline status_t cm_fetch_format_item(text_t *fmt, format_item_t **item, text_t *extra, bool32 do_trim)
{
    uint32 i;
    text_t cmp_text;

    if (do_trim) {
        cm_trim_text(fmt);
    }
    cmp_text.str = fmt->str;

    for (i = 0; i < DATE_FORMAT_COUNT; i++) {
        cmp_text.len = MIN(g_formats[i].name.len, fmt->len);

        if (cm_text_equal_ins(&g_formats[i].name, &cmp_text)) {
            *item = &g_formats[i];
            if ((*item)->id == FMT_DQ_TEXT) {
                return cm_fetch_dqtext_item(fmt, extra, do_trim);
            }

            CM_REMOVE_FIRST_N(fmt, cmp_text.len);
            return CM_SUCCESS;
        }
    }

    return ERR_TEXT_FORMAT_ERROR;
}

static uint32 cm_get_day_of_year(const date_detail_t *detail)
{
    uint32 days;
    uint32 i;

    uint16 *day_tab = (uint16 *)g_month_days[IS_LEAP_YEAR(detail->year)];
    days = 0;

    for (i = 0; i < (uint32)detail->mon - 1; i++) {
        days += day_tab[i];
    }

    days += (uint32)detail->day;
    return days;
}

#define CM_DAYS_PER_WEEK 7
/* week start with SATURDAY, day of 2001-01-01 is MONDAY */
static inline int32 cm_get_day_of_week(const date_detail_t *detail)
{
    int32 day_of_week = total_days_before_date(detail) + CM_BASELINE_DAY;

    day_of_week %= CM_DAYS_PER_WEEK;
    if (day_of_week < 0) {
        day_of_week += CM_DAYS_PER_WEEK;
    }

    CM_ASSERT(day_of_week >= 0 && day_of_week < CM_DAYS_PER_WEEK);
    return day_of_week;
}

void cm_get_detail_ex(const date_detail_t *detail, date_detail_ex_t *detail_ex)
{
    detail_ex->day_of_week = (uint8)cm_get_day_of_week(detail);
    detail_ex->is_am = (bool32)(detail->hour < 12);
    detail_ex->quarter = (uint8)((detail->mon - 1) / 3 + 1);
    detail_ex->day_of_year = (uint16)cm_get_day_of_year(detail);
    detail_ex->week = (uint8)((detail_ex->day_of_year - 1) / 7 + 1);
    detail_ex->seconds = (uint32)(detail->hour * 3600 + detail->min * 60 + detail->sec);
}

static inline status_t cm_append_date_text(const date_detail_t *detail, const date_detail_ex_t *detail_ex,
                                           format_item_t *item, text_t *fmt_extra,
                                           uint32 prec, text_t *date_text, uint32 max_len)
{
    char item_str[FORMAT_ITEM_BUFFER_SIZE] = { 0 };
    text_t append_text = {
        .str = NULL,
        .len = 0
    };

    append_date_text_para_t param = {
        .detail     = detail,
        .detail_ex  = detail_ex,
        .item       = item,
        .fmt_extra  = fmt_extra,
        .prec       = prec,
        .date_text  = date_text,
        .max_len    = max_len
    };

    append_date_text_res_t res = {
        .append_text    = &append_text,
        .item_str       = item_str
    };

    for (uint32 i = 0; i < CM_DATE_TEXT_ARR_LEN; i++) {
        if (g_append_date_text_arr[i].format_id == item->id) {
            append_date_text_func func = g_append_date_text_arr[i].func;
            errno_t errcode = func(&param, &res);
            if (errcode != CM_SUCCESS) {
                return errcode;
            }
        }
    }

    if (append_text.str == NULL) {
        return cm_concat_string(date_text, max_len, item_str);
    }

    cm_concat_text(date_text, max_len, &append_text);
    return CM_SUCCESS;
}

static status_t cm_detail2text(const date_detail_t *detail, text_t *fmt, uint32 precision, text_t *text,
                               uint32 max_len)
{
    date_detail_ex_t detail_ex;
    format_item_t *item = NULL;
    text_t fmt_extra = {
        .str = NULL,
        .len = 0
    };

    cm_get_detail_ex(detail, &detail_ex);

    text->len = 0;

    while (fmt->len > 0) {
        if (cm_fetch_format_item(fmt, &item, &fmt_extra, CM_FALSE) != CM_SUCCESS) {
            return CM_ERROR;
        }

        /* check fmt */
        if ((!cm_validate_timezone(detail->tz_offset))
            && (item->id == FMT_TZ_HOUR || item->id == FMT_TZ_MINUTE)) {
            CM_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "datetime");
            return CM_ERROR;
        }

        CM_RETURN_IFERR(cm_append_date_text(detail, &detail_ex, item,
                                            &fmt_extra, precision, text, max_len));
    }

    CM_NULL_TERM(text);
    return CM_SUCCESS;
}

#define DAYS_1   365
#define DAYS_4   (DAYS_1 * 4 + 1)
#define DAYS_100 (DAYS_4 * 25 - 1)
#define DAYS_400 (DAYS_100 * 4 + 1)
static inline void cm_decode_leap(date_detail_t *detail, int32 *d)
{
    uint32 hundred_count;
    int32 days = *d;

    while (days >= DAYS_400) {
        detail->year += 400;
        days -= DAYS_400;
    }

    for (hundred_count = 1; days >= DAYS_100 && hundred_count < 4; hundred_count++) {
        detail->year += 100;
        days -= DAYS_100;
    }

    while (days >= DAYS_4) {
        detail->year += 4;
        days -= DAYS_4;
    }

    while (days > DAYS_1) {
        if (IS_LEAP_YEAR(detail->year)) {
            days--;
        }

        detail->year++;
        days -= DAYS_1;
    }

    *d = days;
}

void cm_decode_date(date_t date, date_detail_t *detail)
{
    int32 i;
    int32 days;
    uint16 *day_tab = NULL;
    int64 time;

    // decode time
    time = date;
    date /= UNITS_PER_DAY;
    time -= date * UNITS_PER_DAY;

    if (time < 0) {
        time += UNITS_PER_DAY;
        date -= 1;
    }

    detail->microsec = (uint16)(time % (int16)MICROSECS_PER_MILLISEC);
    time /= MICROSECS_PER_MILLISEC;

    detail->millisec = (uint16)(time % (int16)MILLISECS_PER_SECOND);
    time /= MILLISECS_PER_SECOND;

    detail->hour = (uint8)(time / (int16)SECONDS_PER_HOUR);
    time -= (uint32)detail->hour * SECONDS_PER_HOUR;

    detail->min = (uint8)(time / (int16)SECONDS_PER_MIN);
    time -= (uint32)detail->min * SECONDS_PER_MIN;

    detail->sec = (uint8)time;

    // "days -> (year, month, day), considering 01-Jan-0001 as day 1."
    days = (int32)(date + CM_BASELINE_DAY);  // number of days since 1.1.1 to the date
    detail->year = 1;

    cm_decode_leap(detail, &days);

    if (days == 0) {
        detail->year--;
        detail->mon = 12;
        detail->day = 31;
    } else {
        day_tab = g_month_days[IS_LEAP_YEAR(detail->year)];
        detail->mon = 1;

        i = 0;
        while (days > (int32)day_tab[i]) {
            days -= (int32)day_tab[i];
            i++;
        }

        detail->mon = (uint8)(detail->mon + i);
        detail->day = (uint8)(days);
    }
}

status_t cm_date2text_ex(date_t date, const text_t *fmt, uint32 precision, text_t *text, uint32 max_len)
{
    date_detail_t detail;
    text_t format_text;

    cm_decode_date(date, &detail);

    if (fmt == NULL || fmt->str == NULL) {
        format_text = CM_NLS_DATE_FORMAT;
    } else {
        format_text = *fmt;
    }
    return cm_detail2text(&detail, &format_text, precision, text, max_len);
}


#ifdef __cplusplus
}
#endif

