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
 * cm_date_to_text.c
 *    Implementation of date 2 text
 *
 * IDENTIFICATION
 *    src/common/cm_time/cm_date_to_text.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_date_to_text.h"

/* weekdays */
static text_t g_week_days[7] = {
    { "SUNDAY",    6 },
    { "MONDAY",    6 },
    { "TUESDAY",   7 },
    { "WEDNESDAY", 9 },
    { "THURSDAY",  8 },
    { "FRIDAY",    6 },
    { "SATURDAY",  8 }
};

/* months */
static text_t g_month_names[12] = {
    { "JANUARY",   7 },
    { "FEBRUARY",  8 },
    { "MARCH",     5 },
    { "APRIL",     5 },
    { "MAY",       3 },
    { "JUNE",      4 },
    { "JULY",      4 },
    { "AUGUST",    6 },
    { "SEPTEMBER", 9 },
    { "OCTOBER",   7 },
    { "NOVEMBER",  8 },
    { "DECEMBER",  8 }
};

static text_t g_month_roman_names[12] = {
    { "I",    1 },
    { "II",   2 },
    { "III",  3 },
    { "IV",   2 },
    { "V",    1 },
    { "VI",   2 },
    { "VII",  3 },
    { "VIII", 4 },
    { "IX",   2 },
    { "X",    1 },
    { "XI",   2 },
    { "XII",  3 }
};

#define FORMAT_ITEM_BUFFER_SIZE 16
errno_t cm_fmt_indicator(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    res->append_text->str = para->detail_ex->is_am ? (char *)"AM" : (char *)"PM";
    res->append_text->len = 2;
    return CM_SUCCESS;
}

errno_t cm_fmt_dq_text(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    *res->append_text = *(para->fmt_extra);
    return CM_SUCCESS;
}

errno_t cm_fmt_dot_to_colon(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    *res->append_text = para->item->name;
    return CM_SUCCESS;
}

errno_t cm_fmt_x(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    res->append_text->str = (char *)".";
    res->append_text->len = 1;
    return CM_SUCCESS;
}

errno_t cm_fmt_day_name(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    *res->append_text = g_week_days[para->detail_ex->day_of_week];
    return CM_SUCCESS;
}

errno_t cm_fmt_day_abbr_name(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    res->append_text->str = g_week_days[para->detail_ex->day_of_week].str;
    res->append_text->len = 3; /* for abbreviation, the length is 3 */
    return CM_SUCCESS;
}

errno_t cm_fmt_month_abbr_name(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    res->append_text->str = g_month_names[para->detail->mon - 1].str;
    res->append_text->len = 3;
    return CM_SUCCESS;
}

errno_t cm_fmt_month_rm(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    *res->append_text = g_month_roman_names[para->detail->mon - 1];
    return CM_SUCCESS;
}

errno_t cm_fmt_month_name(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    *res->append_text = g_month_names[para->detail->mon - 1];
    return CM_SUCCESS;
}

errno_t cm_fmt_year1_to_year4(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    PRTS_RETURN_IFERR(snprintf_s(res->item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1,
                                 "%04u", para->detail->year));
    CM_ASSERT(para->item->placer > 0 && para->item->placer <= 4);
    res->append_text->len = (uint32)para->item->placer;
    res->append_text->str = res->item_str + (4 - para->item->placer);
    return CM_SUCCESS;
}

#define CM_YEARS_PER_CMNTURY 100u
/* compute the century of a date_detail */
static inline uint32 cm_get_century(const date_detail_t *detail)
{
    return ((uint32)detail->year - 1) / CM_YEARS_PER_CMNTURY + 1;
}

errno_t cm_fmt_century(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    PRTS_RETURN_IFERR(snprintf_s(res->item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1, "%02u",
                                 cm_get_century(para->detail)));
    return CM_SUCCESS;
}

errno_t cm_fmt_day_of_week(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    PRTS_RETURN_IFERR(snprintf_s(res->item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1, "%u",
                                 para->detail_ex->day_of_week + 1));
    return CM_SUCCESS;
}

errno_t cm_fmt_hour_of_day12(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    uint8 hh12_value;
    if (para->detail->hour == 0) {
        hh12_value = 12;
    } else if (para->detail->hour > 12) {
        hh12_value = para->detail->hour - 12;
    } else {
        hh12_value = para->detail->hour;
    }
    PRTS_RETURN_IFERR(snprintf_s(res->item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1,
                                 "%02u", hh12_value));
    return CM_SUCCESS;
}

errno_t cm_fmt_hour_of_day24(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    PRTS_RETURN_IFERR(snprintf_s(res->item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1,
                                 "%02u", para->detail->hour));
    return CM_SUCCESS;
}

errno_t cm_fmt_quarter(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    PRTS_RETURN_IFERR(snprintf_s(res->item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1,
                                 "%u", para->detail_ex->quarter));
    return CM_SUCCESS;
}

errno_t cm_fmt_second(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    PRTS_RETURN_IFERR(snprintf_s(res->item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1,
                                 "%02u", para->detail->sec));
    return CM_SUCCESS;
}

errno_t cm_fmt_second_pass(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    PRTS_RETURN_IFERR(snprintf_s(res->item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1,
                                 "%05u", para->detail_ex->seconds));
    return CM_SUCCESS;
}

errno_t cm_fmt_week_of_year(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    PRTS_RETURN_IFERR(snprintf_s(res->item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1,
                                 "%02u", para->detail_ex->week));
    return CM_SUCCESS;
}

errno_t cm_fmt_week_of_month(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    PRTS_RETURN_IFERR(snprintf_s(res->item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1, "%u",
                                 (para->detail->day / 7) + 1));
    return CM_SUCCESS;
}

errno_t cm_fmt_day_of_month(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    PRTS_RETURN_IFERR(snprintf_s(res->item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1, "%02u",
                                 (para->detail->day)));
    return CM_SUCCESS;
}

errno_t cm_fmt_day_of_year(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    PRTS_RETURN_IFERR(snprintf_s(res->item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1, "%03u",
                                 para->detail_ex->day_of_year));
    return CM_SUCCESS;
}

errno_t cm_fmt_frac_second1_to_second3(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    PRTS_RETURN_IFERR(snprintf_s(res->item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1, "%03u",
                                 para->detail->millisec));
    CM_ASSERT(para->item->placer > 0 && para->item->placer <= 3);
    res->append_text->str = res->item_str;
    res->append_text->len = (uint32)para->item->placer;
    return CM_SUCCESS;
}

errno_t cm_fmt_frac_second4_to_second6(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    uint32 frac;
    frac = (uint32)para->detail->millisec * MICROSECS_PER_MILLISEC + para->detail->microsec;
    PRTS_RETURN_IFERR(snprintf_s(res->item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1, "%06u",
                                 frac));
    CM_ASSERT(para->item->placer >= 4 && para->item->placer <= 6);
    res->append_text->str = res->item_str;
    res->append_text->len = (uint32)para->item->placer;
    return CM_SUCCESS;
}

errno_t cm_fmt_frac_sec_var_len(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    uint32 frac;
    if (para->prec == 0) {
        /* remove last '.' */
        if (para->date_text->len > 0 && para->date_text->str[para->date_text->len - 1] == '.') {
            para->date_text->len--;
        }
        return CM_SUCCESS;
    }

    frac = (uint32)para->detail->millisec * MICROSECS_PER_MILLISEC + para->detail->microsec;
    PRTS_RETURN_IFERR(snprintf_s(res->item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1, "%06u",
                                 frac));
    CM_ASSERT(para->prec <= CM_MAX_DATETIME_PRECISION);
    res->append_text->str = res->item_str;
    res->append_text->len = para->prec;
    return CM_SUCCESS;
}

errno_t cm_fmt_minute(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    PRTS_RETURN_IFERR(snprintf_s(res->item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1,
                                 "%02u", para->detail->min));
    return CM_SUCCESS;
}

errno_t cm_fmt_month(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    PRTS_RETURN_IFERR(snprintf_s(res->item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1,
                                 "%02u", para->detail->mon));
    return CM_SUCCESS;
}

errno_t cm_fmt_tz_hour(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    int32 tz_hour;
    tz_hour = TIMEZONE_GET_HOUR(para->detail->tz_offset);
    PRTS_RETURN_IFERR(snprintf_s(res->item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1, "%+03d",
                                 tz_hour));
    return CM_SUCCESS;
}

errno_t cm_fmt_tz_minute(const append_date_text_para_t* para, append_date_text_res_t* res)
{
    int32 tz_minute;
    tz_minute = TIMEZONE_GET_MINUTE(para->detail->tz_offset);
    PRTS_RETURN_IFERR(snprintf_s(res->item_str, FORMAT_ITEM_BUFFER_SIZE, FORMAT_ITEM_BUFFER_SIZE - 1, "%02d",
                                 tz_minute));
    return CM_SUCCESS;
}

const t_append_date_pair g_append_date_text_arr[] = {
    {
        .format_id = FMT_AM_INDICATOR,
        .func = cm_fmt_indicator
    },
    {
        .format_id = FMT_PM_INDICATOR,
        .func = cm_fmt_indicator
    },
    {
        .format_id = FMT_DQ_TEXT,
        .func = cm_fmt_dq_text
    },
    {
        .format_id = FMT_DOT,
        .func = cm_fmt_dot_to_colon
    },
    {
        .format_id = FMT_SPACE,
        .func = cm_fmt_dot_to_colon
    },
    {
        .format_id = FMT_MINUS,
        .func = cm_fmt_dot_to_colon
    },
    {
        .format_id = FMT_SLASH,
        .func = cm_fmt_dot_to_colon
    },
    {
        .format_id = FMT_BACK_SLASH,
        .func = cm_fmt_dot_to_colon
    },
    {
        .format_id = FMT_COMMA,
        .func = cm_fmt_dot_to_colon
    },
    {
        .format_id = FMT_SEMI_COLON,
        .func = cm_fmt_dot_to_colon
    },
    {
        .format_id = FMT_COLON,
        .func = cm_fmt_dot_to_colon
    },
    {
        .format_id = FMT_X,
        .func = cm_fmt_x
    },
    {
        .format_id = FMT_DAY_NAME,
        .func = cm_fmt_day_name
    },
    {
        .format_id = FMT_DAY_ABBR_NAME,
        .func = cm_fmt_day_abbr_name
    },
    {
        .format_id = FMT_MONTH_ABBR_NAME,
        .func = cm_fmt_month_abbr_name
    },
    {
        .format_id = FMT_MONTH_RM,
        .func = cm_fmt_month_rm
    },
    {
        .format_id = FMT_MONTH_NAME,
        .func = cm_fmt_month_name
    },
    {
        .format_id = FMT_YEAR1,
        .func = cm_fmt_year1_to_year4
    },
    {
        .format_id = FMT_YEAR2,
        .func = cm_fmt_year1_to_year4
    },
    {
        .format_id = FMT_YEAR3,
        .func = cm_fmt_year1_to_year4
    },
    {
        .format_id = FMT_YEAR4,
        .func = cm_fmt_year1_to_year4
    },
    {
        .format_id = FMT_CENTURY,
        .func = cm_fmt_century
    },
    {
        .format_id = FMT_DAY_OF_WEEK,
        .func = cm_fmt_day_of_week
    },
    {
        .format_id = FMT_HOUR_OF_DAY12,
        .func = cm_fmt_hour_of_day12
    },
    {
        .format_id = FMT_HOUR_OF_DAY24,
        .func = cm_fmt_hour_of_day24
    },
    {
        .format_id = FMT_QUARTER,
        .func = cm_fmt_quarter
    },
    {
        .format_id = FMT_SECOND,
        .func = cm_fmt_second
    },
    {
        .format_id = FMT_SECOND_PASS,
        .func = cm_fmt_second_pass
    },
    {
        .format_id = FMT_WEEK_OF_YEAR,
        .func = cm_fmt_week_of_year
    },
    {
        .format_id = FMT_WEEK_OF_MONTH,
        .func = cm_fmt_week_of_month
    },
    {
        .format_id = FMT_DAY_OF_MONTH,
        .func = cm_fmt_day_of_month
    },
    {
        .format_id = FMT_DAY_OF_YEAR,
        .func = cm_fmt_day_of_year
    },
    {
        .format_id = FMT_FRAC_SECOND1,
        .func = cm_fmt_frac_second1_to_second3
    },
    {
        .format_id = FMT_FRAC_SECOND2,
        .func = cm_fmt_frac_second1_to_second3
    },
    {
        .format_id = FMT_FRAC_SECOND3,
        .func = cm_fmt_frac_second1_to_second3
    },
    {
        .format_id = FMT_FRAC_SECOND4,
        .func = cm_fmt_frac_second4_to_second6
    },
    {
        .format_id = FMT_FRAC_SECOND5,
        .func = cm_fmt_frac_second4_to_second6
    },
    {
        .format_id = FMT_FRAC_SECOND6,
        .func = cm_fmt_frac_second4_to_second6
    },
    {
        .format_id = FMT_FRAC_SEC_VAR_LEN,
        .func = cm_fmt_frac_sec_var_len
    },
    {
        .format_id = FMT_MINUTE,
        .func = cm_fmt_minute
    },
    {
        .format_id = FMT_MONTH,
        .func = cm_fmt_month},
    {
        .format_id = FMT_TZ_HOUR,
        .func = cm_fmt_tz_hour
    },
    {
        .format_id = FMT_TZ_MINUTE,
        .func = cm_fmt_tz_minute
    }
};