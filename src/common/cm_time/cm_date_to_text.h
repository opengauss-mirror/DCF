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
 * cm_date_to_text.h
 *
 *
 * IDENTIFICATION
 *    src/common/cm_time/cm_date_to_text.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_DATE_TO_TEXT_H_
#define __CM_DATE_TO_TEXT_H_

#include "cm_defs.h"
#include "cm_timezone.h"
#include "cm_text.h"

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(4)

/* To represent all parts of a date type */
typedef struct st_date_detail {
    uint16 year;
    uint8 mon;
    uint8 day;
    uint8 hour;
    uint8 min;
    uint8 sec;
    uint16 millisec;           /* millisecond: 0~999, 1000 millisec = 1 sec */
    uint16 microsec;           /* microsecond: 0~999, 1000 microsec = 1 millisec */
    uint16 nanosec;            /* nanosecond:  0~999, 1000 nanoseconds = 1 millisec */
    timezone_info_t tz_offset; /* time zone */
} date_detail_t;

typedef struct st_date_detail_ex {
    bool32 is_am;
    uint32 seconds;
    char ad;
    uint8 week;          // total weeks of current year
    uint8 quarter;       // quarter of current month
    uint8 day_of_week;   // (0..6 means Sun..Sat)
    uint16 day_of_year;  // total days of current year
    char reserve[2];     // not used, for byte alignment
} date_detail_ex_t;
#pragma pack()

typedef enum en_format_id {
    FMT_AM_INDICATOR = 100,
    FMT_PM_INDICATOR = 101,
    FMT_SPACE = 102,
    FMT_MINUS = 103,
    FMT_SLASH = 104,
    FMT_BACK_SLASH = 105,
    FMT_COMMA = 106,
    FMT_DOT = 107,
    FMT_SEMI_COLON = 108,
    FMT_COLON = 109,
    FMT_X = 110,
    FMT_CENTURY = 201,
    FMT_DAY_OF_WEEK = 202,
    FMT_DAY_NAME = 203,
    FMT_DAY_ABBR_NAME = 204,
    FMT_DAY_OF_MONTH = 205,
    FMT_DAY_OF_YEAR = 206,
    FMT_FRAC_SECOND1 = 207,
    FMT_FRAC_SECOND2 = 208,
    FMT_FRAC_SECOND3 = 209,
    FMT_FRAC_SECOND4 = 210,
    FMT_FRAC_SECOND5 = 211,
    FMT_FRAC_SECOND6 = 212,
    FMT_FRAC_SECOND7 = 213,
    FMT_FRAC_SECOND8 = 214,
    FMT_FRAC_SECOND9 = 215,
    FMT_FRAC_SEC_VAR_LEN = 250,

    FMT_DQ_TEXT = 313, /* "text" is allowed in format */
    FMT_MINUTE = 314,
    FMT_MONTH = 315,
    FMT_MONTH_ABBR_NAME = 316,
    FMT_MONTH_NAME = 317,
    FMT_QUARTER = 318,
    FMT_SECOND = 319,
    FMT_SECOND_PASS = 320,
    FMT_WEEK_OF_YEAR = 321,
    FMT_WEEK_OF_MONTH = 322,
    /* The order of FMT_YEAR1, FMT_YEAR2, FMT_YEAR3 and FMT_YEAR4 can
     * not be changed */
    FMT_YEAR1 = 323,
    FMT_YEAR2 = 324,
    FMT_YEAR3 = 325,
    FMT_YEAR4 = 326,
    FMT_HOUR_OF_DAY12 = 328,
    FMT_HOUR_OF_DAY24 = 329,
    FMT_TZ_HOUR = 330,   /* time zone hour */
    FMT_TZ_MINUTE = 331, /* time zone minute */
    FMT_MONTH_RM = 332
} format_id_t;

#define SECONDS_PER_DAY         86400U
#define SECONDS_PER_HOUR        3600U
#define SECONDS_PER_MIN         60U
#define MILLISECS_PER_SECOND    1000U
#define MICROSECS_PER_MILLISEC  1000U
#define MICROSECS_PER_SECOND    1000000U
#define NANOSECS_PER_MICROSECS  1000U
#define DEFAULT_DIGIT_RADIX     10
#define MICROSECS_PER_SECOND_LL 1000000LL

#define CM_MAX_DATETIME_PRECISION     6

typedef struct en_format_item {
    text_t name;
    format_id_t id;
    uint32 fmask; /* Added for parsing date/timestamp from text */
    int8 placer;  /* the length of the placers, -1 denoting unspecified or uncaring */
    bool8 reversible;
    bool8 dt_used; /* can the item be used in DATE_FORMAT */
} format_item_t;

typedef struct st_append_date_text_para {
    const date_detail_t* detail;
    const date_detail_ex_t* detail_ex;
    format_item_t* item;
    text_t* fmt_extra;
    uint32 prec;
    text_t* date_text;
    uint32 max_len;
} append_date_text_para_t;

typedef struct st_append_date_text_res {
    text_t* append_text;
    char* item_str;
} append_date_text_res_t;

// <format_id, func>
typedef errno_t (* append_date_text_func)(const append_date_text_para_t* para, append_date_text_res_t* res);

typedef struct st_append_date_pair {
    uint32 format_id;
    append_date_text_func func;
} t_append_date_pair;


#define FORMAT_ITEM_BUFFER_SIZE 16

#define CM_DATE_TEXT_ARR_LEN 43

extern const t_append_date_pair g_append_date_text_arr[CM_DATE_TEXT_ARR_LEN];

errno_t cm_fmt_indicator(const append_date_text_para_t* para, append_date_text_res_t* res);

errno_t cm_fmt_dq_text(const append_date_text_para_t* para, append_date_text_res_t* res);

errno_t cm_fmt_dot_to_colon(const append_date_text_para_t* para, append_date_text_res_t* res);

errno_t cm_fmt_x(const append_date_text_para_t* para, append_date_text_res_t* res);

errno_t cm_fmt_day_name(const append_date_text_para_t* para, append_date_text_res_t* res);

errno_t cm_fmt_day_abbr_name(const append_date_text_para_t* para, append_date_text_res_t* res);

errno_t cm_fmt_month_abbr_name(const append_date_text_para_t* para, append_date_text_res_t* res);

errno_t cm_fmt_month_rm(const append_date_text_para_t* para, append_date_text_res_t* res);

errno_t cm_fmt_month_name(const append_date_text_para_t* para, append_date_text_res_t* res);

errno_t cm_fmt_year1_to_year4(const append_date_text_para_t* para, append_date_text_res_t* res);

errno_t cm_fmt_century(const append_date_text_para_t* para, append_date_text_res_t* res);

errno_t cm_fmt_day_of_week(const append_date_text_para_t* para, append_date_text_res_t* res);

errno_t cm_fmt_hour_of_day12(const append_date_text_para_t* para, append_date_text_res_t* res);

errno_t cm_fmt_hour_of_day24(const append_date_text_para_t* para, append_date_text_res_t* res);

errno_t cm_fmt_quarter(const append_date_text_para_t* para, append_date_text_res_t* res);

errno_t cm_fmt_second(const append_date_text_para_t* para, append_date_text_res_t* res);

errno_t cm_fmt_second_pass(const append_date_text_para_t* para, append_date_text_res_t* res);

errno_t cm_fmt_week_of_year(const append_date_text_para_t* para, append_date_text_res_t* res);

errno_t cm_fmt_week_of_month(const append_date_text_para_t* para, append_date_text_res_t* res);

errno_t cm_fmt_day_of_month(const append_date_text_para_t* para, append_date_text_res_t* res);

errno_t cm_fmt_day_of_year(const append_date_text_para_t* para, append_date_text_res_t* res);

errno_t cm_fmt_frac_second1_to_second3(const append_date_text_para_t* para, append_date_text_res_t* res);

errno_t cm_fmt_frac_second4_to_second6(const append_date_text_para_t* para, append_date_text_res_t* res);

errno_t cm_fmt_frac_sec_var_len(const append_date_text_para_t* para, append_date_text_res_t* res);

errno_t cm_fmt_minute(const append_date_text_para_t* para, append_date_text_res_t* res);

errno_t cm_fmt_month(const append_date_text_para_t* para, append_date_text_res_t* res);

errno_t cm_fmt_tz_hour(const append_date_text_para_t* para, append_date_text_res_t* res);

errno_t cm_fmt_tz_minute(const append_date_text_para_t* para, append_date_text_res_t* res);

#ifdef __cplusplus
}
#endif

#endif
