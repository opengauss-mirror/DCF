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
 * md_param.c
 *    metadata process
 *
 * IDENTIFICATION
 *    src/metadata/md_param.c
 *
 * -------------------------------------------------------------------------
 */

#include "md_param.h"
#include "cm_text.h"
#include "cm_latch.h"
#include "cm_log.h"
#include "cm_timer.h"
#include "cm_num.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MD_DEFAULT_LOG_FILE_BACKUP_COUNT 10
#define MD_MAX_LOG_FILE_COUNT 100
#define MD_DEFAULT_LOG_FILE_SIZE 10  // unit (M)
#define MD_MAX_LOG_FILE_SIZE 1000  // unit (M)
#define MD_LOG_FILE_PERMISSION 600
#define MD_LOG_PATH_PERMISSION 700

#define MD_MAX_LOG_FILE_PERMISSION 640
#define MD_MAX_LOG_PATH_PERMISSION 750
#define MAX_LOG_LEVEL_SIZE 10
static char *g_log_level_str[MAX_LOG_LEVEL_SIZE] = {
    "RUN_ERR", "RUN_WAR", "RUN_INF", "DEBUG_ERR", "DEBUG_WAR", "DEBUG_INF", "MEC", "OPER", "TRACE", "PROFILE"};
static uint32 g_log_level_val[MAX_LOG_LEVEL_SIZE] = {
    LOG_RUN_ERR_LEVEL,
    LOG_RUN_WAR_LEVEL,
    LOG_RUN_INF_LEVEL,
    LOG_DEBUG_ERR_LEVEL,
    LOG_DEBUG_WAR_LEVEL,
    LOG_DEBUG_INF_LEVEL,
    LOG_MEC_LEVEL,
    LOG_OPER_LEVEL,
    LOG_TRACE_LEVEL,
    LOG_PROFILE_LEVEL
};

typedef enum en_param_val_type {
    PARAM_STRING,
    PARAM_UINT32,
    PARAM_SIZE_T,
    PARAM_ENUM,
    PARAM_UNKNOW
} param_val_type_t;

typedef struct st_param_item {
    char *name; // param name
    param_value_t value;
    param_verify_t verify;
    bool32 is_dynamic;
    char *range;
    param_val_type_t val_type;
} param_item_t;

static uint32 g_majority_groups[CM_MAX_GROUP_COUNT] = { 0 };
static uint32 g_majority_group_count = 0;

static param_item_t g_parameters[] = {
    // ------------------------      name  setdefaultvalue  verify    is_dynamic    range
    [DCF_PARAM_ELECTION_TIMEOUT] = {"ELECTION_TIMEOUT", {.value_elc_timeout = CM_DEFAULT_ELC_TIMEOUT},
         verify_param_election_timeout, CM_TRUE, "[1s,600s]", PARAM_UINT32},
    [DCF_PARAM_AUTO_ELC_PRIORITY_EN] = {"AUTO_ELC_PRIORITY_EN", {.value_auto_elc_priority_en = CM_TRUE},
    verify_param_int_auto_elc_prio_en, CM_TRUE, "[0,+]", PARAM_UINT32},
    [DCF_PARAM_HEARTBEAT_INTERVAL] = {"HEARTBEAT_INTERVAL", {.value_hb_interval = CM_DEFAULT_HB_INTERVAL},
         NULL, CM_TRUE, "computed from election_timeout", PARAM_UINT32},
    [DCF_PARAM_ELECTION_SWITCH_THRESHOLD] = {"ELECTION_SWITCH_THRESHOLD",
        {.value_elc_switch_thd = CM_DEFAULT_ELC_SWITCH_THD},
        verify_param_int_common, CM_TRUE, "[0,+]", PARAM_UINT32}, // unit s
    [DCF_PARAM_RUN_MODE] = {"RUN_MODE",
         {.value_mode = ELECTION_AUTO}, verify_param_int_run_mode, CM_TRUE, "[0,2]", PARAM_ENUM},
    [DCF_PARAM_INSTANCE_NAME] = {"INSTANCE_NAME",
         {.instance_name = ""}, verify_param_string, CM_FALSE, "", PARAM_STRING},
    [DCF_PARAM_DATA_PATH] = {"DATA_PATH", {.data_path = ""}, verify_param_string, CM_FALSE, "", PARAM_STRING},
    [DCF_PARAM_LOG_PATH] = {"LOG_PATH", {.log_path = ""}, verify_param_string, CM_FALSE, "", PARAM_STRING},
    [DCF_PARAM_LOG_LEVEL] = {"LOG_LEVEL", {.value_loglevel = DEFAULT_LOG_LEVEL}, verify_param_log_level, CM_TRUE,
         "RUN_ERR|RUN_WAR|RUN_INF|DEBUG_ERR|DEBUG_WAR|DEBUG_INF|OPER|TRACE|PROFILE", PARAM_UINT32},
    [DCF_PARAM_LOG_FILENAME_FORMAT] = {"LOG_FILENAME_FORMAT", {.value_log_filename_format = LOG_FILENAME_DEFAULT},
         verify_param_int_filename_format, CM_FALSE, "[0,1]", PARAM_ENUM},
    [DCF_PARAM_LOG_BACKUP_FILE_COUNT] = {"LOG_BACKUP_FILE_COUNT",
         {.value_log_backup_count = MD_DEFAULT_LOG_FILE_BACKUP_COUNT}, verify_param_log_backup_file_count, CM_TRUE,
         "[1,100]", PARAM_UINT32},
    [DCF_PARAM_MAX_LOG_FILE_SIZE] = {"MAX_LOG_FILE_SIZE", {.value_max_log_file_size = MD_DEFAULT_LOG_FILE_SIZE},
         verify_param_max_log_file_size, CM_TRUE, "[1,1000]", PARAM_UINT32},
    [DCF_PARAM_LOG_FILE_PERMISSION] = {"LOG_FILE_PERMISSION", {.value_log_file_permission = MD_LOG_FILE_PERMISSION},
         verify_param_log_file_permission, CM_FALSE, "[600,640]", PARAM_UINT32},
    [DCF_PARAM_LOG_PATH_PERMISSION] = {"LOG_PATH_PERMISSION", {.value_log_path_permission = MD_LOG_PATH_PERMISSION},
         verify_param_log_path_permission, CM_FALSE, "[700,750]", PARAM_UINT32},
    [DCF_PARAM_MEC_AGENT_THREAD_NUM] = {"MEC_AGENT_THREAD_NUM", {.agent_num = MEC_DEFALT_AGENT_NUM},
          verify_param_int_agent_num, CM_FALSE, "[1,1000]", PARAM_UINT32},
    [DCF_PARAM_MEC_REACTOR_THREAD_NUM] = {"MEC_REACTOR_THREAD_NUM", {.reactor_num = 1},
         verify_param_int_reactor_num, CM_FALSE, "[1,100]", PARAM_UINT32},
    [DCF_PARAM_MEC_CHANNEL_NUM] = {"MEC_CHANNEL_NUM", {.channel_num = 1}, verify_param_int_channel_num, CM_FALSE,
         "[1,64]", PARAM_UINT32},
    [DCF_PARAM_MEM_POOL_INIT_SIZE] = {"MEM_POOL_INIT_SIZE", {.buddy_init_size = (size_t) COMM_MEM_POOL_MIN_SIZE},
         verify_param_size, CM_FALSE, "[32M,+)", PARAM_SIZE_T}, // unit MB
    [DCF_PARAM_MEM_POOL_MAX_SIZE] = {"MEM_POOL_MAX_SIZE", {.buddy_max_size = (size_t) COMM_MEM_POOL_MAX_SIZE},
         verify_param_size, CM_FALSE, "[32M,+)", PARAM_SIZE_T}, // unit MB
    [DCF_PARAM_COMPRESS_ALGORITHM] = {"COMPRESS_ALGORITHM", {.compress = COMPRESS_NONE},
         verify_param_int_compress_algorithm, CM_FALSE, "[0,1,2]", PARAM_UINT32},
    [DCF_PARAM_COMPRESS_LEVEL] = {"COMPRESS_LEVEL", {.level = MEC_DEFAULT_COMPRESS_LEVEL},
         verify_param_int_compress_level, CM_FALSE, "[1,22]", PARAM_UINT32},
    [DCF_PARAM_SOCKET_TIMEOUT] = {"SOCKET_TIMEOUT", {.socket_timeout = CM_NETWORK_IO_TIMEOUT},
         verify_param_socket_timeout, CM_FALSE, "[10,600000]", PARAM_UINT32},
    [DCF_PARAM_CONNECT_TIMEOUT] = {"CONNECT_TIMEOUT", {.connect_timeout = CM_CONNECT_TIMEOUT},
         verify_param_connect_timeout, CM_FALSE, "[10,600000]", PARAM_UINT32},
    [DCF_REP_APPEND_THREAD_NUM] = {"REP_APPEND_THREAD_NUM", {.rep_append_thread_num = REP_DEFALT_APPEND_THREAS_NUM},
         verify_param_int_append_thread_num, CM_FALSE, "[1,1000]", PARAM_UINT32},
    [DCF_PARAM_MEC_FRAGMENT_SIZE] = {"MEC_FRAGMENT_SIZE", {.frag_size = MESSAGE_BUFFER_SIZE},
         verify_param_mec_fragment_size, CM_FALSE, "[32K,10240K]", PARAM_UINT32}, // unit KB
    [DCF_PARAM_STG_POOL_INIT_SIZE] = {"STG_POOL_INIT_SIZE", {.stg_pool_init_size = (size_t) STG_MEM_POOL_MIN_SIZE},
         verify_param_size, CM_FALSE, "[32M,+]", PARAM_SIZE_T}, // unit MB
    [DCF_PARAM_STG_POOL_MAX_SIZE] = {"STG_POOL_MAX_SIZE", {.stg_pool_max_size = (size_t) STG_MEM_POOL_MAX_SIZE},
         verify_param_size, CM_FALSE, "[32M,+]", PARAM_SIZE_T}, // unit MB
    [DCF_PARAM_MEC_POOL_MAX_SIZE] = {"MEC_POOL_MAX_SIZE", {.mec_pool_max_size = (size_t) MEC_MEM_POOL_MAX_SIZE},
         verify_param_size, CM_FALSE, "[32M,+]", PARAM_SIZE_T}, // unit MB
    [DCF_PARAM_MEC_BATCH_SIZE] = {"MEC_BATCH_SIZE", {.batch_size = DEFAULT_MEC_BATCH_SIZE},
         verify_param_mec_batch_size, CM_FALSE, "[0,1024]", PARAM_UINT32},
    [DCF_PARAM_CPU_THRESHOLD] = {"FLOW_CONTROL_CPU_THRESHOLD", {.cpu_load_threshold = CM_DEFAULT_CPU_THRESHOLD},
         verify_param_int_common, CM_TRUE, "[0,+]", PARAM_UINT32}, // unit %
    [DCF_PARAM_NET_QUEUE_THRESHOLD] = {"FLOW_CONTROL_NET_QUEUE_MESSAGE_NUM_THRESHOLD",
         {.net_queue_threshold = CM_DEFAULT_NET_QUEUE_MESS_NUM}, verify_param_int_common, CM_TRUE, "[0,+]",
         PARAM_UINT32}, // unit %
    [DCF_PARAM_DISK_RAWAIT_THRESHOLD] = {"FLOW_CONTROL_DISK_RAWAIT_THRESHOLD", // unit us
         {.disk_rawait_threshold = CM_DEFAULT_DISK_RAWAIT_THRESHOLD}, verify_param_int_common, CM_TRUE, "[0,+]",
         PARAM_UINT32},
    [DCF_PARAM_SSL_CA] = {"SSL_CA", {.ssl_ca = ""}, verify_param_string, CM_FALSE, "", PARAM_STRING},
    [DCF_PARAM_SSL_KEY] = {"SSL_KEY", {.ssl_key = ""}, verify_param_string, CM_FALSE, "", PARAM_STRING},
    [DCF_PARAM_SSL_CRL] = {"SSL_CRL", {.ssl_crl = ""}, verify_param_string, CM_FALSE, "", PARAM_STRING},
    [DCF_PARAM_SSL_CERT] = {"SSL_CERT", {.ssl_cert = ""}, verify_param_string, CM_FALSE, "", PARAM_STRING},
    [DCF_PARAM_SSL_CIPHER] = {"SSL_CIPHER", {.ssl_cipher = ""}, verify_param_string, CM_FALSE, "", PARAM_STRING},
    [DCF_PARAM_SSL_PWD_PLAINTEXT] = {"SSL_PWD_PLAINTEXT", {0}, verify_param_password, CM_FALSE, "", PARAM_STRING},
    [DCF_PARAM_SSL_PWD_CIPHERTEXT] = {"SSL_PWD_CIPHERTEXT", {.ext_pwd = ""}, verify_param_string, CM_FALSE, "",
         PARAM_STRING},
    [DCF_PARAM_SSL_CERT_NOTIFY_TIME] = {"SSL_CERT_NOTIFY_TIME", {.ssl_cert_notify_time = 30},
         verify_param_ssl_notify_time, CM_FALSE, "[7,180]", PARAM_UINT32},
    [DCF_PARAM_DATA_FILE_SIZE] = {"DATA_FILE_SIZE", {.data_file_size = SIZE_M(500)},
         verify_param_size, CM_FALSE, "[10M,2G]", PARAM_UINT32},
    [DCF_PARAM_DN_FLOW_CONTROL_RTO] = {"DN_FLOW_CONTROL_RTO", {.dn_flow_control_rto = 0}, verify_param_int_common,
         CM_TRUE, "[0,+]", PARAM_UINT32},
    [DCF_PARAM_DN_FLOW_CONTROL_RPO] = {"DN_FLOW_CONTROL_RPO", {.dn_flow_control_rpo = 0}, verify_param_int_common,
        CM_TRUE, "[0,+]", PARAM_UINT32},
    [DCF_PARAM_LOG_SUPPRESS_ENABLE] = {"LOG_SUPPRESS_ENABLE", {.log_suppress_enable = 0},
        verify_param_log_suppress_enable, CM_TRUE, "[0,1]", PARAM_UINT32},
    [DCF_PARAM_MAJORITY_GROUPS] = {"MAJORITY_GROUPS", {.majority_groups=""},
        verify_param_majority_groups, CM_FALSE, "valid group value", PARAM_STRING},
};

status_t get_param(dcf_param_t param_type, param_value_t *param_value)
{
    if (param_type >= DCF_PARAM_CEIL) {
        return CM_ERROR;
    }
    *param_value = g_parameters[param_type].value;
    return CM_SUCCESS;
}

status_t set_param(dcf_param_t param_type, const param_value_t *param_value)
{
    if (param_value == NULL) {
        return CM_ERROR;
    }
    g_parameters[param_type].value = *param_value;
    return CM_SUCCESS;
}

static inline status_t get_param_id_by_name(const char *param_name, uint32 *param_name_id)
{
    uint32 count = ELEMENT_COUNT(g_parameters);
    for (uint32 i = 0; i < count; i++) {
        if (g_parameters[i].name == NULL) {
            continue;
        }
        if (cm_str_equal(param_name, g_parameters[i].name)) {
            *param_name_id = i;
            return CM_SUCCESS;
        }
    }

    return CM_ERROR;
}

status_t get_param_by_name(const char *param_name, char *param_value, unsigned int size)
{
    uint32 len;
    uint32 param_id;
    CM_RETURN_IFERR(get_param_id_by_name(param_name, &param_id));

    if (param_id >= DCF_PARAM_CEIL) {
        return CM_ERROR;
    }
    param_value_t out_value = g_parameters[param_id].value;
    switch (g_parameters[param_id].val_type) {
        case PARAM_UINT32:
        case PARAM_ENUM:
            if (size < sizeof(uint32)) {
                LOG_RUN_ERR("[param] the output buffer is small");
                return CM_ERROR;
            }
            sprintf_s(param_value, size, "%u", out_value.v_uint32);
            break;
        case PARAM_SIZE_T:
            if (size < sizeof(size_t)) {
                LOG_RUN_ERR("[param] the output buffer is small");
                return CM_ERROR;
            }
            sprintf_s(param_value, size, "%lu", out_value.v_size);
            break;
        case PARAM_STRING:
            len = (uint32) strlen(out_value.v_char_array);
            if (size < len) {
                LOG_RUN_ERR("[param] the output buffer is small");
                return CM_ERROR;
            }
            memcpy_sp(param_value, len, out_value.v_char_array, len);
            break;
        case PARAM_UNKNOW:
            return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t verify_param_value(const char *param_name, const char *param_value,
                            dcf_param_t *param_type, param_value_t *out_value)
{
    status_t ret;
    uint32 param_name_id;
    ret = get_param_id_by_name(param_name, &param_name_id);
    if (ret == CM_ERROR || g_parameters[param_name_id].verify == NULL) {
        CM_THROW_ERROR(ERR_PARAMETERS, param_name, param_value);
        return CM_ERROR;
    }
    *param_type = (dcf_param_t) param_name_id;
    ret = g_parameters[param_name_id].verify((dcf_param_t) param_name_id, param_value, out_value);
    if (ret != CM_SUCCESS) {
        CM_THROW_ERROR(ERR_PARAMETERS, param_name, param_value);
        LOG_DEBUG_ERR("[PARAM] verify param_name: %s, param_value: %s", param_name, param_value);
    }
    return ret;
}

// make sure setvalue range : [minval, maxval]
static inline status_t check_param_int_range(dcf_param_t param_type, uint32 setvalue, uint32 minval, uint32 maxval)
{
    if (setvalue > maxval || setvalue < minval) {
        LOG_RUN_ERR("[param] the parameter of %s should be between %d and %d",
            g_parameters[param_type].name, minval, maxval);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static inline status_t check_param_size_range(dcf_param_t param_type, uint64 setvalue, uint64 minval, uint64 maxval)
{
    if (setvalue > maxval || setvalue < minval) {
        LOG_RUN_ERR("[param] the parameter of %s should be between %lld and %lld",
            g_parameters[param_type].name, minval, maxval);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t parse_log_level_cfg(const char *log_cfg, uint32 *log_level)
{
    *log_level = LOG_NONE;
    text_t text, left, right, tmp;
    text_t text_none = {
        .str = "NONE",
        .len = 4
    };
    cm_str2text((char *) log_cfg, &text);
    if (text.len == 0) {
        return CM_ERROR;
    }
    if (cm_text_equal_ins(&text, &text_none)) {
        return CM_SUCCESS;
    }
    while (text.len != 0) {
        cm_split_text(&text, SPLIT_CHR_LOG_LEVEL, 0, &left, &right);
        if (left.len == 0) {
            return CM_ERROR;
        }
        bool32 found = CM_FALSE;
        for (int i = 0; i < MAX_LOG_LEVEL_SIZE; i++) {
            cm_str2text(g_log_level_str[i], &tmp);
            if (cm_text_equal_ins(&left, &tmp)) {
                *log_level |= g_log_level_val[i];
                found = CM_TRUE;
                break;
            }
        }
        if (!found) {
            return CM_ERROR;
        }
        text = right;
    }
    return CM_SUCCESS;
}

status_t verify_param_log_level(dcf_param_t param_type, const char *param_value, param_value_t *out_value)
{
    uint32 value = 0;
    // only handle NULL or "" error, set to default log level
    if (CM_IS_EMPTY_STR(param_value)) {
        out_value->value_loglevel = DEFAULT_LOG_LEVEL;
        cm_log_param_instance()->log_level = DEFAULT_LOG_LEVEL;
        return CM_SUCCESS;
    }
    int ret = parse_log_level_cfg(param_value, &value);
    if (ret != CM_SUCCESS || value > MAX_LOG_LEVEL) {
        return CM_ERROR;
    }
    out_value->value_loglevel = value;
    cm_log_param_instance()->log_level = value;
    return CM_SUCCESS;
}

status_t verify_param_log_backup_file_count(dcf_param_t param_type, const char *param_value, param_value_t *out_value)
{
    uint32 val;
    CM_CHECK_NULL_PTR(param_value);
    if (cm_str2uint32(param_value, &val) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (check_param_int_range(param_type, val, 1, MD_MAX_LOG_FILE_COUNT)) {
        return CM_ERROR;
    }
    out_value->value_log_backup_count = val;
    cm_log_param_instance()->log_backup_file_count = val;

    return CM_SUCCESS;
}

status_t verify_param_max_log_file_size(dcf_param_t param_type, const char *param_value, param_value_t *out_value)
{
    uint32 val;
    CM_CHECK_NULL_PTR(param_value);
    if (cm_str2uint32(param_value, &val) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (check_param_int_range(param_type, val, 1, MD_MAX_LOG_FILE_SIZE)) {
        return CM_ERROR;
    }
    out_value->value_max_log_file_size = val;
    cm_log_param_instance()->max_log_file_size = val * SIZE_M(1);

    return CM_SUCCESS;
}

status_t verify_param_log_path_permission(dcf_param_t param_type, const char *param_value, param_value_t *out_value)
{
    uint32 val;
    CM_CHECK_NULL_PTR(param_value);
    if (cm_str2uint32(param_value, &val) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (val != MD_MAX_LOG_PATH_PERMISSION && val != MD_LOG_PATH_PERMISSION) {
        return CM_ERROR;
    }
    out_value->value_log_path_permission = val;

    return CM_SUCCESS;
}

status_t verify_param_log_file_permission(dcf_param_t param_type, const char *param_value, param_value_t *out_value)
{
    uint32 val;
    CM_CHECK_NULL_PTR(param_value);
    if (cm_str2uint32(param_value, &val) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (val != MD_MAX_LOG_FILE_PERMISSION && val != MD_LOG_FILE_PERMISSION) {
        return CM_ERROR;
    }
    out_value->value_log_file_permission = val;

    return CM_SUCCESS;
}

status_t verify_param_time_val(dcf_param_t param_type, const char *param_value, param_value_t *out_value)
{
    uint32 val;
    CM_CHECK_NULL_PTR(param_value);
    if (cm_str2uint32(param_value, &val) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (check_param_int_range(param_type, val, 0, CM_MAX_MSG_TIMEOUT)) {
        return CM_ERROR;
    }
    out_value->v_uint32 = val;
    return CM_SUCCESS;
}

status_t verify_param_int_common(dcf_param_t param_type, const char *param_value, param_value_t *out_value)
{
    uint32 val;
    CM_CHECK_NULL_PTR(param_value);
    if (cm_str2uint32(param_value, &val) != CM_SUCCESS) {
        return CM_ERROR;
    }
    out_value->v_uint32 = val;
    return CM_SUCCESS;
}

status_t elc_reload_priority();

status_t verify_param_int_auto_elc_prio_en(dcf_param_t param_type, const char *param_value, param_value_t *out_value)
{
    uint32 val;
    CM_CHECK_NULL_PTR(param_value);
    if (cm_str2uint32(param_value, &val) != CM_SUCCESS) {
        return CM_ERROR;
    }
    out_value->v_uint32 = val;

    if (g_parameters[DCF_PARAM_AUTO_ELC_PRIORITY_EN].value.value_auto_elc_priority_en != CM_FALSE && val == CM_FALSE) {
        return elc_reload_priority();
    }

    return CM_SUCCESS;
}

static inline status_t parse_and_check_int_range(dcf_param_t param_type, const char *param_value,
    uint32 minval, uint32 maxval, uint32 *out_val)
{
    uint32 val;
    CM_CHECK_NULL_PTR(param_value);
    if (cm_str2uint32(param_value, &val) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (check_param_int_range(param_type, val, minval, maxval)) {
        return CM_ERROR;
    }
    *out_val = val;
    return CM_SUCCESS;
}

status_t verify_param_election_timeout(dcf_param_t param_type, const char *param_value, param_value_t *out_value)
{
    uint32 val;
    if (parse_and_check_int_range(param_type, param_value, CM_MIN_ELC_TIMEOUT, CM_MAX_ELC_TIMEOUT, &val)) {
        return CM_ERROR;
    }
    val *= MILLISECS_PER_SECOND;
    out_value->v_uint32 = val;

    param_value_t heartbeat_interval;
    heartbeat_interval.value_hb_interval = val / CM_3X_FIXED;
    if (set_param(DCF_PARAM_HEARTBEAT_INTERVAL, &heartbeat_interval)) {
        LOG_DEBUG_ERR("heartbeat interval set error, %u\n", heartbeat_interval.value_hb_interval);
        return CM_ERROR;
    }
    LOG_DEBUG_INF("election timeout : %u, heartbeat interval is : %u\n", val, heartbeat_interval.value_hb_interval);

    return CM_SUCCESS;
}

status_t verify_param_socket_timeout(dcf_param_t param_type, const char *param_value, param_value_t *out_value)
{
    if (parse_and_check_int_range(param_type, param_value, CM_MIN_CONNECT_TIMEOUT, CM_MAX_MSG_TIMEOUT,
        &out_value->v_uint32)) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t verify_param_connect_timeout(dcf_param_t param_type, const char *param_value, param_value_t *out_value)
{
    if (parse_and_check_int_range(param_type, param_value, CM_MIN_CONNECT_TIMEOUT, CM_MAX_MSG_TIMEOUT,
        &out_value->v_uint32)) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t verify_param_mec_batch_size(dcf_param_t param_type, const char *param_value, param_value_t *out_value)
{
    if (parse_and_check_int_range(param_type, param_value, 0, CM_MAX_MEC_BATCH_SIZE, &out_value->v_uint32)) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t verify_param_ssl_notify_time(dcf_param_t param_type, const char *param_value, param_value_t *out_value)
{
    if (parse_and_check_int_range(param_type, param_value, CM_SSL_NOTI_TIME_MIN, CM_SSL_NOTI_TIME_MAX,
        &out_value->v_uint32)) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t verify_param_int_agent_num(dcf_param_t param_type, const char *param_value, param_value_t *out_value)
{
    if (parse_and_check_int_range(param_type, param_value, 1, MEC_MAX_AGENT_NUM, &out_value->v_uint32)) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t verify_param_int_reactor_num(dcf_param_t param_type, const char *param_value, param_value_t *out_value)
{
    if (parse_and_check_int_range(param_type, param_value, 1, MEC_MAX_REACTOR_NUM, &out_value->v_uint32)) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t verify_param_int_channel_num(dcf_param_t param_type, const char *param_value, param_value_t *out_value)
{
    if (parse_and_check_int_range(param_type, param_value, 1, MEC_MAX_CHANNEL_NUM, &out_value->v_uint32)) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t verify_param_int_compress_algorithm(dcf_param_t param_type, const char *param_value, param_value_t *out_value)
{
    if (parse_and_check_int_range(param_type, param_value, 0, COMPRESS_CEIL - 1, &out_value->v_uint32)) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t verify_param_int_compress_level(dcf_param_t param_type, const char *param_value, param_value_t *out_value)
{
    uint32 val = 0;
    if (parse_and_check_int_range(param_type, param_value, MEC_DEFAULT_COMPRESS_LEVEL,
        MEC_MAX_COMPRESS_LEVEL_ZSTD, &val)) {
        out_value->v_uint32 = MEC_DEFAULT_COMPRESS_LEVEL;
        return CM_ERROR;
    }
    param_value_t *param_val = &g_parameters[DCF_PARAM_COMPRESS_ALGORITHM].value;
    if (param_val->compress == COMPRESS_LZ4 && val > MEC_MAX_COMPRESS_LEVEL_LZ4) {
        // for lz4, if compress level large than 9, assign this value to max val 9
        out_value->v_uint32 = MEC_MAX_COMPRESS_LEVEL_LZ4;
        return CM_SUCCESS;
    }
    out_value->v_uint32 = val;
    return CM_SUCCESS;
}

status_t verify_param_int_run_mode(dcf_param_t param_type, const char *param_value, param_value_t *out_value)
{
    if (parse_and_check_int_range(param_type, param_value, 0, ELECTION_CEIL - 1, &out_value->v_uint32)) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t verify_param_log_suppress_enable(dcf_param_t param_type, const char *param_value, param_value_t *out_value)
{
    if (parse_and_check_int_range(param_type, param_value, 0, 1, &out_value->log_suppress_enable)) {
        return CM_ERROR;
    }
    cm_log_param_instance()->log_suppress_enable = (bool32)out_value->log_suppress_enable;
    return CM_SUCCESS;
}

static status_t set_majority_groups(const char *majority_groups_str)
{
    if (CM_IS_EMPTY_STR(majority_groups_str)) {
        g_majority_group_count = 0;
        return CM_SUCCESS;
    }
    text_t text, left, right;
    uint32 group;
    cm_str2text((char *)majority_groups_str, &text);
    uint32 idx = 0;
    while (text.len != 0) {
        cm_split_text(&text, ',', 0, &left, &right);
        CM_RETURN_IFERR(cm_text2uint32(&left, &group));
        g_majority_groups[idx] = group;
        idx++;
        text = right;
    }
    g_majority_group_count = idx;
    return CM_SUCCESS;
}

status_t check_majority_groups_valid(const char *majority_groups_str)
{
    status_t ret;
    text_t left, right;
    uint32 group_value;
    uint32 groups[CM_MAX_NODE_COUNT] = {0};
    if (CM_IS_EMPTY_STR(majority_groups_str)) {
        return CM_SUCCESS;
    }
    text_t text = {.str = (char *)majority_groups_str, .len = strlen(majority_groups_str)};
    uint32 count = 0;
    while (text.len != 0) {
        cm_split_text(&text, ',', 0, &left, &right);
        ret = cm_text2uint32(&left, &group_value);
        if (ret == CM_ERROR) {
            LOG_DEBUG_ERR("[PARAM] group value in majority groups contain none number value");
            return CM_ERROR;
        }
        groups[count++] = group_value;
        text = right;
    }
    for (int i = 0; i < count; i++) {
        for (int j = i + 1; j < count; j++) {
            if (groups[i] == groups[j]) {
                LOG_DEBUG_ERR("[PARAM] group value in majority groups conflict %u", groups[i]);
                return CM_ERROR;
            }
        }
    }
    return CM_SUCCESS;
}

status_t verify_param_majority_groups(dcf_param_t param_type, const char *param_value, param_value_t *out_value)
{
    status_t ret = check_majority_groups_valid(param_value);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[PARAM] config majority groups str is invalid %s", param_value);
        return CM_ERROR;
    }
    errno_t errcode = strncpy_s(out_value->majority_groups, MAX_MAJORITY_GROUPS_STR_LEN, (const char *) param_value,
        strlen((const char *) param_value));
    ret = errcode == EOK ? CM_SUCCESS : CM_ERROR;
    if (ret == CM_SUCCESS) {
        CM_RETURN_IFERR(set_majority_groups(param_value));
        LOG_RUN_INF("[PARAM] set majority groups value %s success", out_value->majority_groups);
    }

    return ret;
}

status_t verify_param_int_filename_format(dcf_param_t param_type, const char *param_value, param_value_t *out_value)
{
    if (parse_and_check_int_range(param_type, param_value, 0, LOG_FILENAME_UNKNOW - 1, &out_value->v_uint32)) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t verify_param_int_append_thread_num(dcf_param_t param_type, const char *param_value, param_value_t *out_value)
{
    if (parse_and_check_int_range(param_type, param_value, 1, REP_MAX_APPEND_THREAS_NUM, &out_value->v_uint32)) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t verify_param_mec_fragment_size(dcf_param_t param_type, const char *param_value, param_value_t *out_value)
{
    uint32 val;
    if (parse_and_check_int_range(param_type, param_value, MEC_MIN_MESSAGE_BUFFER_SIZE,
        MEC_MAX_MESSAGE_BUFFER_SIZE, &val)) {
        return CM_ERROR;
    }
    out_value->v_size = (size_t) (val) * SIZE_K(1);
    return CM_SUCCESS;
}

status_t verify_param_size(dcf_param_t param_type, const char *param_value, param_value_t *out_value)
{
    uint64 value;
    int ret;
    CM_CHECK_NULL_PTR(param_value);
    ret = cm_str2uint64(param_value, &value);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[param] the parameter is not a number");
        return CM_ERROR;
    }

    uint32 min_pool_size = 32;
    switch (param_type) {
        case DCF_PARAM_MEM_POOL_INIT_SIZE:
        case DCF_PARAM_MEM_POOL_MAX_SIZE:
        case DCF_PARAM_STG_POOL_INIT_SIZE:
        case DCF_PARAM_STG_POOL_MAX_SIZE:
        case DCF_PARAM_MEC_POOL_MAX_SIZE:
            ret = check_param_size_range(param_type, value, min_pool_size, INT_MAX);
            break;
        case DCF_PARAM_DATA_FILE_SIZE:
            ret = check_param_size_range(param_type, value, 10, CM_2X_FIXED * SIZE_K(1));
            break;
        default:
            return CM_ERROR;
    }
    // config unit is MB, need transferr to byte
    out_value->v_size = (size_t) (value * SIZE_M(1));
    return (ret == CM_SUCCESS) ? CM_SUCCESS : CM_ERROR;
}

status_t verify_param_string(dcf_param_t param_type, const char *param_value, param_value_t *out_value)
{
    errno_t errcode = EOK;
    CM_CHECK_NULL_PTR(param_value);
    switch (param_type) {
        case DCF_PARAM_INSTANCE_NAME:
            errcode = strncpy_s(out_value->instance_name, CM_MAX_NAME_LEN, (const char *) param_value,
                strlen((const char *) param_value));
            break;
        case DCF_PARAM_DATA_PATH:
            errcode = strncpy_s(out_value->data_path, CM_MAX_PATH_LEN, (const char *) param_value,
                strlen((const char *) param_value));
            break;
        case DCF_PARAM_LOG_PATH:
            errcode = strncpy_s(out_value->log_path, CM_MAX_LOG_HOME_LEN, (const char *) param_value,
                strlen((const char *) param_value));
            break;
        case DCF_PARAM_SSL_CA:
            errcode = strncpy_s(out_value->ssl_ca, CM_FULL_PATH_BUFFER_SIZE, (const char *) param_value,
                strlen((const char *) param_value));
            break;
        case DCF_PARAM_SSL_KEY:
            errcode = strncpy_s(out_value->ssl_key, CM_FULL_PATH_BUFFER_SIZE, (const char *) param_value,
                strlen((const char *) param_value));
            break;
        case DCF_PARAM_SSL_CRL:
            errcode = strncpy_s(out_value->ssl_crl, CM_FULL_PATH_BUFFER_SIZE, (const char *) param_value,
                strlen((const char *) param_value));
            break;
        case DCF_PARAM_SSL_CERT:
            errcode = strncpy_s(out_value->ssl_cert, CM_FULL_PATH_BUFFER_SIZE, (const char *) param_value,
                strlen((const char *) param_value));
            break;
        case DCF_PARAM_SSL_CIPHER:
            errcode = strncpy_s(out_value->ssl_cipher, CM_MAX_SSL_CIPHER_LEN, (const char *) param_value,
                strlen((const char *) param_value));
            break;
        case DCF_PARAM_SSL_PWD_CIPHERTEXT:
            if (g_parameters[DCF_PARAM_SSL_PWD_PLAINTEXT].value.inter_pwd.cipher_len > 0) {
                LOG_DEBUG_ERR("ssl key password has already been set");
                return CM_ERROR;
            }
            errcode = strncpy_s(out_value->ext_pwd, CM_PASSWORD_BUFFER_SIZE, (const char *) param_value,
                strlen((const char *) param_value));
            break;
        default:
            return CM_ERROR;
    }
    return errcode == EOK ? CM_SUCCESS : CM_ERROR;
}

status_t verify_param_password(dcf_param_t param_type, const char *param_value, param_value_t *out_value)
{
    param_value_t *param_val = &g_parameters[DCF_PARAM_SSL_PWD_CIPHERTEXT].value;
    if (!CM_IS_EMPTY_STR(param_val->ext_pwd)) {
        LOG_RUN_ERR("ssl key password has already been set");
        return CM_ERROR;
    }
    return cm_encrypt_pwd((uchar *) param_value, (uint32) strlen(param_value), &out_value->inter_pwd);
}

status_t get_param_magority_groups(uint32 groups[CM_MAX_GROUP_COUNT], uint32 *count)
{
    *count = g_majority_group_count;
    if (g_majority_group_count == 0) {
        return CM_SUCCESS;
    }

    for (int i = 0; i < g_majority_group_count; i++) {
        groups[i] = g_majority_groups[i];
    }
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
