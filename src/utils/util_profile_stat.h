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
 * util_profile_stat.h
 *    cm profile statistics
 *
 * IDENTIFICATION
 *    src/utils/util_profile_stat.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __UTIL_PROFILE_STAT_H__
#define __UTIL_PROFILE_STAT_H__

#include <cm_error.h>
#include "cm_defs.h"
#include "cm_thread.h"
#include "../common/cm_utils/cm_utils.h"
#include "cm_timer.h"
#include "cm_error.h"
#include "cm_defs.h"
#include "cm_date_to_text.h"
#include "cm_date.h"
#include "cm_num.h"
#include "cm_latch.h"
#include "cm_file.h"
#include "cJSON.h"

#define DEFAULT_STAT_INTERVAL 3
#define MAX_ITEM_COUNT 100
#define STAT_TABLE_SIZE 2
#define STAT_ITEM_WIDTH 21
#define STAT_ITEM_NAME_MAX_LEN 20

#define STAT_INDICATOR_ACC 0x00000001
#define STAT_INDICATOR_AVG 0x00000002
#define STAT_INDICATOR_MAX 0x00000004
#define STAT_INDICATOR_MIN 0x00000010

#define stat_record_by_index(type, index)  \
    do { \
        static uint64 pre_index; \
        stat_record((type), ((index) - (pre_index))); \
        (pre_index) = (index); \
    } while (0);

typedef enum stat_unit {
    UNIT_DEFAULT = 0,
    UNIT_US,
    UNIT_MS,
    UNIT_S,
    UNIT_BYTES,
    UNIT_KB,
    UNIT_MB,
    UNIT_GB,
    UNIT_CEIL
}stat_unit_t;

typedef enum stat_item_id {
    DCF_WRITE_CNT = 0,
    DCF_WRITE_SIZE,
    DISK_WRITE,
    SEND_PACK_SIZE,
    SEND_DELAY,
    SEND_WAIT,
    RECV_DELAY,
    SEND_QUEUE_COUNT,
    RECV_QUEUE_COUNT,
    SEND_QUEUE_COUNT_HIGH,
    RECV_QUEUE_COUNT_HIGH,
    STG_MEM_USED,
    MEC_SEND_MEM,
    MEC_RECV_MEM,
    HB_SEND_COUNT,
    HB_RECV_COUNT,
    HB_RTT,
    MEC_BUDDY_MEM,
    STAT_ITEM_ID_CEIL
} stat_item_id_t;

typedef int64 (*cb_get_value_func_t)(stat_item_id_t stat_id);
typedef struct stat_item_attr {
    char name[STAT_ITEM_NAME_MAX_LEN];
    stat_unit_t unit;
    uint32 indicator;
    cb_get_value_func_t func;
} stat_item_attr_t;
typedef struct stat_item {
    stat_item_id_t id;
    uint64 count;
    uint64 value;
    double avg_value;
    uint64 max;
    uint64 min;
} stat_item_t;

typedef struct stat_item_result {
    stat_item_id_t id;
    latch_t latch;
    uint32 is_valid;
    double value;
    double avg_value;
    double max;
    double min;
}stat_item_result_t;

typedef struct stat_result {
    latch_t latch;
    stat_item_result_t result_cache[STAT_ITEM_ID_CEIL];
}stat_result_t;

status_t cm_profile_stat_init();

void cm_profile_stat_uninit();

status_t cm_reg_stat_item(stat_item_id_t item_id, const char* name, stat_unit_t unit, uint32 indicator,
    cb_get_value_func_t value_func);

void stat_record(stat_item_id_t item_id, uint64 value);

status_t cm_pwrite_file_stat(int32 file, const char *buf, int32 size, int64 offset);
status_t util_append_statistics_info(cJSON *obj);

#endif
