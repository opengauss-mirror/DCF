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
 * util_profile_stat.c
 *    cm profile statistics
 *
 * IDENTIFICATION
 *    src/utils/util_profile_stat.c
 *
 * -------------------------------------------------------------------------
 */

#include "util_profile_stat.h"
#include "util_perf_stat.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_LINES_PRINT_HEAD 50
#define STAT_THREAD_SLEEP_TIME 100

thread_t g_profile_stat_thread;
static bool32 g_profile_stat_init = CM_FALSE;
static stat_item_t *g_stat_table[STAT_TABLE_SIZE][STAT_ITEM_ID_CEIL][MAX_ITEM_COUNT] = { NULL };
static uint32 g_stat_count[STAT_TABLE_SIZE][STAT_ITEM_ID_CEIL] = { 0 };
spinlock_t g_lock;
static thread_local_var stat_item_t *stat_item_local[STAT_TABLE_SIZE][STAT_ITEM_ID_CEIL] = { NULL };
atomic_t g_stat_table_id;
stat_result_t g_stat_result;
char *g_stat_unit_str[UNIT_CEIL] = {"", "us", "ms", "s", "byte", "KB", "MB", "GB"};
stat_item_attr_t g_stat_item_attrs[STAT_ITEM_ID_CEIL] = { 0 };

// called by inner module: need register statistics item firstly
status_t cm_reg_stat_item(stat_item_id_t item_id, const char* name, stat_unit_t unit, uint32 indicator,
    cb_get_value_func_t value_func)
{
    MEMS_RETURN_IFERR(strcpy_s(g_stat_item_attrs[item_id].name, STAT_ITEM_NAME_MAX_LEN, name));
    g_stat_item_attrs[item_id].unit = unit;
    g_stat_item_attrs[item_id].indicator = indicator;
    g_stat_item_attrs[item_id].func = value_func;
    return CM_SUCCESS;
}

// called by inner module: record value by item_id
void stat_record(stat_item_id_t item_id, uint64 value)
{
    if (!LOG_PROFILE_ON || !g_profile_stat_init) {
        return;
    }
    int64 table_id = cm_atomic_get(&g_stat_table_id);
    stat_item_t *item_local = stat_item_local[table_id][item_id];
    if (item_local == NULL) {
        cm_spin_lock(&g_lock, NULL);
        uint32 cnt = g_stat_count[table_id][item_id];
        if (cnt >= MAX_ITEM_COUNT) {
            cm_spin_unlock(&g_lock);
            return;
        }
        item_local = (stat_item_t *) malloc(sizeof(stat_item_t));
        if (item_local == NULL) {
            cm_spin_unlock(&g_lock);
            return;
        }
        stat_item_local[table_id][item_id] = item_local;
        g_stat_count[table_id][item_id]++;
        cm_spin_unlock(&g_lock);

        item_local->count = 0;
        item_local->value = 0;
        item_local->avg_value = 0;
        item_local->max = 0;
        item_local->min = CM_MAX_UINT64;
        item_local->id = item_id;
        g_stat_table[table_id][item_id][cnt] = item_local;
    }

    item_local->value += value;
    item_local->count++;
    if (g_stat_item_attrs[item_id].indicator & STAT_INDICATOR_MAX) {
        item_local->max = MAX(value, item_local->max);
    }
    if (g_stat_item_attrs[item_id].indicator & STAT_INDICATOR_MIN) {
        item_local->min = MIN(value, item_local->min);
    }
}
static inline int get_cal_table_id()
{
    return (int)(cm_atomic_get(&g_stat_table_id) ^ 1);
}
static inline void cal_item_result_by_ratio(const stat_item_t *stat_item, stat_item_result_t *result, double ratio)
{
    result->id = stat_item->id;
    if (g_stat_item_attrs[stat_item->id].func != NULL) {
        result->value = stat_item->value * ratio;
        return;
    }
    result->value = stat_item->value * ratio;
    result->avg_value = stat_item->avg_value * ratio;
    result->max = stat_item->max * ratio;
    result->min = stat_item->min *ratio;
    return;
}

void transform_unit(stat_item_t *stat_item, stat_item_result_t *result)
{
    uint32 unit = g_stat_item_attrs[stat_item->id].unit;
    result->is_valid = stat_item->count != 0;
    switch (unit) {
        case UNIT_DEFAULT:
        case UNIT_BYTES:
        case UNIT_US:
            cal_item_result_by_ratio(stat_item, result, 1.0);
            break;
        case UNIT_MS:
            cal_item_result_by_ratio(stat_item, result, 1.0 / MICROSECS_PER_MILLISEC);
            break;
        case UNIT_S:
            cal_item_result_by_ratio(stat_item, result, 1.0 / MICROSECS_PER_SECOND);
            break;
        case UNIT_MB:
            cal_item_result_by_ratio(stat_item, result, 1.0 / SIZE_M(1));
            break;
        case UNIT_KB:
            cal_item_result_by_ratio(stat_item, result, 1.0 / SIZE_K(1));
            break;
        case UNIT_GB:
            cal_item_result_by_ratio(stat_item, result, 1.0 / SIZE_G(1));
            break;
        default:
            break;
    }
}

void stat_agg_items(stat_item_t *stat_item)
{
    int cal_table_id = get_cal_table_id();
    if (g_stat_item_attrs[stat_item->id].func != NULL) {
        stat_item->count = 1;
        stat_item->value = g_stat_item_attrs[stat_item->id].func(stat_item->id);
        stat_item->avg_value = (double)stat_item->value;
        stat_item->max = stat_item->value;
        stat_item->min = stat_item->value;
        return;
    }
    uint32 item_count_total = g_stat_count[cal_table_id][stat_item->id];
    for (uint32 item_count = 0; item_count < item_count_total; item_count++) {
        stat_item_t *tmp = g_stat_table[cal_table_id][stat_item->id][item_count];
        if (tmp == NULL) {
            continue;
        }
        stat_item->value += tmp->value;
        stat_item->count += tmp->count;
        stat_item->max = ((g_stat_item_attrs[stat_item->id].indicator & STAT_INDICATOR_MAX) &&
                          (tmp->max > stat_item->max)) ? tmp->max : stat_item->max;
        stat_item->min = ((g_stat_item_attrs[stat_item->id].indicator & STAT_INDICATOR_MIN)
                          && (tmp->min < stat_item->min)) ? tmp->min : stat_item->min;
        tmp->count = 0;
        tmp->value = 0;
        tmp->max = 0;
        tmp->min = CM_MAX_UINT64;
    }
    if ((g_stat_item_attrs[stat_item->id].indicator & STAT_INDICATOR_AVG) && stat_item->count != 0) {
        stat_item->avg_value = stat_item->value / (1.0 * stat_item->count);
    }
}

void stat_calculate()
{
    if (!cm_atomic_cas(&g_stat_table_id, 0, 1)) {
        cm_atomic_cas(&g_stat_table_id, 1, 0);
    }
    cm_latch_x(&g_stat_result.latch, 0, NULL);
    for (int i = 0; i < STAT_ITEM_ID_CEIL; i++) {
        stat_item_t stat_item = {i, 0, 0, 0, 0, CM_MAX_UINT64};
        stat_agg_items(&stat_item);
        transform_unit(&stat_item, &g_stat_result.result_cache[i]);
    }
    cm_unlatch(&g_stat_result.latch, NULL);
}

static inline status_t build_item_head(char *item_name, const char *suffix, const char *item_unit, char *item_buf)
{
    item_buf[0] = '\0';
    MEMS_RETURN_IFERR(strncat_s(item_buf, STAT_ITEM_WIDTH + 1, item_name, strlen(item_name)));
    MEMS_RETURN_IFERR(strncat_s(item_buf, STAT_ITEM_WIDTH + 1, suffix, strlen(suffix)));
    if (item_unit != NULL && strlen(item_unit) != 0) {
        MEMS_RETURN_IFERR(strncat_s(item_buf, STAT_ITEM_WIDTH + 1, "(", 1));
        MEMS_RETURN_IFERR(strncat_s(item_buf, STAT_ITEM_WIDTH + 1, item_unit, strlen(item_unit)));
        MEMS_RETURN_IFERR(strncat_s(item_buf, STAT_ITEM_WIDTH + 1, ")", 1));
    }
    for (int i = strlen(item_buf); i < STAT_ITEM_WIDTH; i++) {
        MEMS_RETURN_IFERR(strncat_s(item_buf, STAT_ITEM_WIDTH + 1, " ", 1));
    }
    return CM_SUCCESS;
}

status_t stat_build_head(char *buf, stat_item_id_t begin, stat_item_id_t end)
{
    char tmp_buf[STAT_ITEM_WIDTH + 1] = {'\0'};
    for (uint32 i = (uint32)begin; i < (uint32)end; i++) {
        stat_unit_t unit = g_stat_item_attrs[i].unit;
        if (g_stat_item_attrs[i].indicator & STAT_INDICATOR_ACC) {
            CM_RETURN_IFERR(build_item_head(g_stat_item_attrs[i].name, "", g_stat_unit_str[unit], tmp_buf));
            MEMS_RETURN_IFERR(strncat_s(buf, CM_MAX_LOG_CONTENT_LENGTH, tmp_buf, STAT_ITEM_WIDTH));
        }
        if (g_stat_item_attrs[i].indicator & STAT_INDICATOR_AVG) {
            CM_RETURN_IFERR(build_item_head(g_stat_item_attrs[i].name, "Avg", g_stat_unit_str[unit], tmp_buf));
            MEMS_RETURN_IFERR(strncat_s(buf, CM_MAX_LOG_CONTENT_LENGTH, tmp_buf, STAT_ITEM_WIDTH));
        }
        if (g_stat_item_attrs[i].indicator & STAT_INDICATOR_MAX) {
            CM_RETURN_IFERR(build_item_head(g_stat_item_attrs[i].name, "Max", g_stat_unit_str[unit], tmp_buf));
            MEMS_RETURN_IFERR(strncat_s(buf, CM_MAX_LOG_CONTENT_LENGTH, tmp_buf, STAT_ITEM_WIDTH));
        }
        if (g_stat_item_attrs[i].indicator & STAT_INDICATOR_MIN) {
            CM_RETURN_IFERR(build_item_head(g_stat_item_attrs[i].name, "Min", g_stat_unit_str[unit], tmp_buf));
            MEMS_RETURN_IFERR(strncat_s(buf, CM_MAX_LOG_CONTENT_LENGTH, tmp_buf, STAT_ITEM_WIDTH));
        }
    }
    return CM_SUCCESS;
}
static status_t stat_concat_content_format(char *buf, double value, bool32 need_converted)
{
    char tmp_buf[STAT_ITEM_WIDTH + 1] = {'\0'};
    if (need_converted) {
        PRTS_RETURN_IFERR(
            snprintf_s(tmp_buf, STAT_ITEM_WIDTH + 1, STAT_ITEM_WIDTH, "%-*llu", STAT_ITEM_WIDTH, (uint64)(value)));
    } else {
        PRTS_RETURN_IFERR(snprintf_s(tmp_buf, STAT_ITEM_WIDTH + 1, STAT_ITEM_WIDTH, "%-*.3f", STAT_ITEM_WIDTH, value));
    }
    MEMS_RETURN_IFERR(strncat_s(buf, CM_MAX_LOG_CONTENT_LENGTH, tmp_buf, STAT_ITEM_WIDTH));
    return CM_SUCCESS;
}
status_t stat_build_content(char *buf, stat_item_id_t begin, stat_item_id_t end)
{
    for (uint32 i = (uint32)begin; i < (uint32)end; i++) {
        bool32 need_converted = g_stat_item_attrs[i].unit == UNIT_DEFAULT ||
            g_stat_item_attrs[i].unit == UNIT_US || g_stat_item_attrs[i].unit == UNIT_BYTES;
        if (g_stat_item_attrs[i].indicator & STAT_INDICATOR_ACC) {
            CM_RETURN_IFERR(stat_concat_content_format(buf, g_stat_result.result_cache[i].value, need_converted));
        }
        if (g_stat_item_attrs[i].indicator & STAT_INDICATOR_AVG) {
            CM_RETURN_IFERR(stat_concat_content_format(buf, g_stat_result.result_cache[i].avg_value, 0));
        }
        if (g_stat_item_attrs[i].indicator & STAT_INDICATOR_MAX) {
            CM_RETURN_IFERR(stat_concat_content_format(buf, g_stat_result.result_cache[i].max, need_converted));
        }
        if (g_stat_item_attrs[i].indicator & STAT_INDICATOR_MIN) {
            CM_RETURN_IFERR(stat_concat_content_format(buf, g_stat_result.result_cache[i].min, need_converted));
        }
    }
    return CM_SUCCESS;
}

// print item content range: [begin, end)
void stat_print_range(bool8 head_off, stat_item_id_t begin, stat_item_id_t end)
{
    if (begin > end) {
        return;
    }
    if (end > STAT_ITEM_ID_CEIL) {
        end = STAT_ITEM_ID_CEIL;
    }
    char buf[CM_MAX_LOG_CONTENT_LENGTH] = {'\0'};
    status_t ret;
    if (!head_off) {
        ret = stat_build_head(buf, begin, end);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("[STAT] profile stat build head failed , retcode=%d, error code=%d, error info=%s",
                        ret, cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
            return;
        } else {
            LOG_PROFILE("[STAT] %s", buf);
            buf[0] = '\0';
        }
    }
    cm_latch_s(&g_stat_result.latch, 0, CM_FALSE, NULL);
    ret = stat_build_content(buf, begin, end);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[STAT] profile stat build content failed , retcode=%d, error code=%d, error info=%s",
                    ret, cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
    }
    cm_unlatch(&g_stat_result.latch, NULL);
    LOG_PROFILE("[STAT] %s", buf);
}

void stat_print()
{
    int max_num_aline = 7;
    int i;
    for (i = 0; i < STAT_ITEM_ID_CEIL; i += max_num_aline) {
        stat_print_range(CM_FALSE, i, i + max_num_aline);
    }
    if (i < STAT_ITEM_ID_CEIL) {
        stat_print_range(CM_FALSE, i, STAT_ITEM_ID_CEIL);
    }
}

void stat_free()
{
    for (uint32 table_id = 0; table_id < STAT_TABLE_SIZE; table_id++) {
        for (int item_id = 0; item_id < STAT_ITEM_ID_CEIL; item_id++) {
            uint32 item_count_total = g_stat_count[table_id][item_id];
            for (uint32 item_count = 0; item_count < item_count_total; item_count++) {
                if (g_stat_table[table_id][item_id][item_count] != NULL) {
                    free(g_stat_table[table_id][item_id][item_count]);
                    g_stat_table[table_id][item_id][item_count] = NULL;
                }
            }
        }
    }
}

#define UTIL_PRINT_COUNT 30
#define UTIL_PRINT_PRECISION 1000.0

void print_perf()
{
    uint64 write_count, write_total, write_max;
    uint64 accept_count, accept_total, accept_max;
    uint64 pack_count, pack_total, pack_max;
    uint64 fo_accept_count, fo_accept_total, fo_accept_max;
    uint64 commit_count, commit_total, commit_max;
    uint64 apply1_count, apply1_total, apply1_max;
    uint64 apply2_count, apply2_total, apply2_max;

    ps_get_and_reset_stat(PS_WRITE, &write_count, &write_total, &write_max);
    ps_get_and_reset_stat(PS_ACCEPT, &accept_count, &accept_total, &accept_max);
    ps_get_and_reset_stat(PS_PACK, &pack_count, &pack_total, &pack_max);
    ps_get_and_reset_stat(PS_FOLLOWER_ACCEPT, &fo_accept_count, &fo_accept_total, &fo_accept_max);
    ps_get_and_reset_stat(PS_COMMIT, &commit_count, &commit_total, &commit_max);
    ps_get_and_reset_stat(PS_BEING_APPLY, &apply1_count, &apply1_total, &apply1_max);
    ps_get_and_reset_stat(PS_END_APPLY, &apply2_count, &apply2_total, &apply2_max);
    static thread_local_var uint32 count = 0;
    if (count++ % UTIL_PRINT_COUNT == 0) {
        LOG_PROFILE("\n[PERF]%12s%12s%12s%12s%12s%12s\n[PERF]%12.3f%12.3f%12.3f%12.3f%12.3f%12.3f",
            "total-ms", "apply-ms", "commit-ms", "l_accept-ms", "append-ms", "r_accept-ms",
            ((double)apply2_total / UTIL_PRINT_PRECISION) / apply2_count,
            ((double)apply1_total / UTIL_PRINT_PRECISION) / apply1_count,
            ((double)commit_total / UTIL_PRINT_PRECISION) / commit_count,
            ((double)accept_total / UTIL_PRINT_PRECISION) / accept_count,
            ((double)pack_total / UTIL_PRINT_PRECISION) / pack_count,
            ((double)fo_accept_total / UTIL_PRINT_PRECISION) / fo_accept_count);
    } else {
        LOG_PROFILE("\n[PERF]%12.3f%12.3f%12.3f%12.3f%12.3f%12.3f",
            ((double)apply2_total / UTIL_PRINT_PRECISION) / apply2_count,
            ((double)apply1_total / UTIL_PRINT_PRECISION) / apply1_count,
            ((double)commit_total / UTIL_PRINT_PRECISION) / commit_count,
            ((double)accept_total / UTIL_PRINT_PRECISION) / accept_count,
            ((double)pack_total / UTIL_PRINT_PRECISION) / pack_count,
            ((double)fo_accept_total / UTIL_PRINT_PRECISION) / fo_accept_count);
    }
}

void cm_profile_stat_entry(thread_t *thread)
{
    if (cm_set_thread_name("cm_profile_stat") != CM_SUCCESS) {
        LOG_DEBUG_ERR("[STAT] set thread name cm_profile_stat error");
    }

    date_t last_check_time = g_timer()->now;

    while (!thread->closed) {
        cm_sleep(STAT_THREAD_SLEEP_TIME);
        if (!LOG_PROFILE_ON) {
            continue;
        }
        date_t now = g_timer()->now;
        if (now - last_check_time >= DEFAULT_STAT_INTERVAL * MICROSECS_PER_SECOND) {
            last_check_time = now;
            stat_calculate();
            stat_print();
            print_perf();
        }
    }
}

status_t cm_profile_stat_init()
{
    if (g_profile_stat_init) {
        return CM_SUCCESS;
    }

    (void) cm_atomic_set(&g_stat_table_id, 0);
    cm_latch_init(&g_stat_result.latch);

    status_t ret = cm_create_thread(cm_profile_stat_entry, 0, NULL, &g_profile_stat_thread);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    g_profile_stat_init = CM_TRUE;
    return CM_SUCCESS;
}

static void cm_set_stat_item_null(void)
{
    for (uint32 i = 0; i < STAT_TABLE_SIZE; i++) {
        for (uint32 j = 0; j < STAT_ITEM_ID_CEIL; j++) {
            stat_item_local[i][j] = NULL;
        }
    }
}

void cm_profile_stat_uninit()
{
    if (g_profile_stat_init) {
        cm_close_thread(&g_profile_stat_thread);
        stat_free();
        cm_set_stat_item_null();
    }
    g_profile_stat_init = CM_FALSE;
}

// for test
typedef struct st_disk_perf_t {
    uint64 delay;
    uint64 count;
    uint64 size;
}disk_perf_t;

disk_perf_t g_disk_perf;

void cm_get_disk_delay(uint64* delay, uint64* count, uint64* size)
{
    static disk_perf_t pre_stat;
    disk_perf_t cur_stat = g_disk_perf;
    *delay = cur_stat.delay - pre_stat.delay;
    *count = cur_stat.count - pre_stat.count;
    *size =  cur_stat.size - pre_stat.size;
    pre_stat = cur_stat;
}
// for test end
status_t cm_pwrite_file_stat(int32 file, const char *buf, int32 size, int64 offset)
{
    uint64 begin = g_timer()->now;
    uint64 begin1 = 0;
    if (LOG_PROFILE_ON) {
        begin1 = g_timer()->now;
    }
    status_t ret = cm_pwrite_file(file, buf, size, offset);
    if (ret == CM_ERROR) {
        return CM_ERROR;
    }
    g_disk_perf.delay += g_timer()->now - begin;
    g_disk_perf.size += size;
    g_disk_perf.count++;
    stat_record(DISK_WRITE, g_timer()->now - begin1);
    return CM_SUCCESS;
}

static status_t append_stat_info_item(cJSON *value_item, uint32 index)
{
    if (g_stat_item_attrs[index].indicator & STAT_INDICATOR_ACC) {
        CM_CHECK_NULL_PTR(cJSON_AddNumberToObject(value_item, "value", g_stat_result.result_cache[index].value));
    }
    if (g_stat_item_attrs[index].indicator & STAT_INDICATOR_AVG) {
        CM_CHECK_NULL_PTR(cJSON_AddNumberToObject(value_item, "avg value",
            g_stat_result.result_cache[index].avg_value));
    }
    if (g_stat_item_attrs[index].indicator & STAT_INDICATOR_MAX) {
        CM_CHECK_NULL_PTR(cJSON_AddNumberToObject(value_item, "max value", g_stat_result.result_cache[index].max));
    }
    if (g_stat_item_attrs[index].indicator & STAT_INDICATOR_MIN) {
        CM_CHECK_NULL_PTR(cJSON_AddNumberToObject(value_item, "min value", g_stat_result.result_cache[index].min));
    }
    if (strlen(g_stat_unit_str[g_stat_item_attrs[index].unit]) == 0) {
        CM_CHECK_NULL_PTR(cJSON_AddStringToObject(value_item, "unit", "default"));
    } else {
        CM_CHECK_NULL_PTR(cJSON_AddStringToObject(value_item, "unit", g_stat_unit_str[g_stat_item_attrs[index].unit]));
    }
    return CM_SUCCESS;
}

static status_t append_statistics_info_array_item(cJSON *item_array)
{
    cm_latch_s(&g_stat_result.latch, 0, CM_FALSE, NULL);
    for (uint32 i = 0; i < STAT_ITEM_ID_CEIL; i++) {
        cJSON *item = cJSON_CreateObject();
        if (!g_stat_result.result_cache[i].is_valid) {
            (void) cJSON_AddNullToObject(item, g_stat_item_attrs[i].name);
            (void) cJSON_AddItemToArray(item_array, item);
            continue;
        }
        cJSON *value_array = cJSON_CreateArray();
        cJSON *value_item = cJSON_CreateObject();

        if (append_stat_info_item(value_item, i) != CM_SUCCESS) {
            cm_unlatch(&g_stat_result.latch, NULL);
            LOG_DEBUG_ERR("cJSON add object fail when append_statistics_info");
            return CM_ERROR;
        }

        if (cJSON_AddItemToArray(value_array, value_item) == CM_FALSE) {
            cm_unlatch(&g_stat_result.latch, NULL);
            LOG_DEBUG_ERR("cJSON AddItemToArray fail when append_statistics_info");
            return CM_ERROR;
        }
        if (cJSON_AddItemToObject(item, g_stat_item_attrs[i].name, value_item) == CM_FALSE) {
            cm_unlatch(&g_stat_result.latch, NULL);
            LOG_DEBUG_ERR("cJSON AddItemToObject fail when append_statistics_info");
            return CM_ERROR;
        }
        if (cJSON_AddItemToArray(item_array, item) == CM_FALSE) {
            cm_unlatch(&g_stat_result.latch, NULL);
            LOG_DEBUG_ERR("cJSON AddItemToArray fail when append_statistics_info");
            return CM_ERROR;
        }
    }
    cm_unlatch(&g_stat_result.latch, NULL);
    return CM_SUCCESS;
}

status_t util_append_statistics_info(cJSON *obj)
{
    cJSON *item_array = cJSON_CreateArray();
    if (append_statistics_info_array_item(item_array) != CM_SUCCESS) {
        LOG_DEBUG_ERR("append statistics info_array item fail");
        cJSON_Delete(item_array);
        return CM_ERROR;
    }

    if (cJSON_AddItemToObject(obj, "statistics_info", item_array) == CM_FALSE) {
        LOG_DEBUG_ERR("cJSON AddItemToObject fail");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif