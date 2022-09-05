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
 * md_param.h
 *    metadata process
 *
 * IDENTIFICATION
 *    src/metadata/md_param.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __MD_PARAM_H__
#define __MD_PARAM_H__

#include "cm_types.h"
#include "cm_defs.h"
#include "md_defs.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef status_t (*param_verify_t)(dcf_param_t param_type, const char *param_value, param_value_t *out_value);

status_t get_param(dcf_param_t param_type, param_value_t* param_value);
status_t get_param_by_name(const char *param_name, char *param_value, unsigned int size);
status_t set_param(dcf_param_t param_type, const param_value_t* param_value);
status_t verify_param_value(const char *param_name, const char *param_value,
    dcf_param_t *param_type, param_value_t *out_value);
status_t get_param_magority_groups(uint32 groups[CM_MAX_GROUP_COUNT], uint32 *count);

status_t verify_param_int_common(dcf_param_t param_type, const char *param_value, param_value_t *out_value);
status_t verify_param_int_auto_elc_prio_en(dcf_param_t param_type, const char *param_value, param_value_t *out_value);
status_t verify_param_int_agent_num(dcf_param_t param_type, const char *param_value, param_value_t *out_value);
status_t verify_param_int_reactor_num(dcf_param_t param_type, const char *param_value, param_value_t *out_value);
status_t verify_param_int_channel_num(dcf_param_t param_type, const char *param_value, param_value_t *out_value);
status_t verify_param_int_compress_level(dcf_param_t param_type, const char *param_value, param_value_t *out_value);
status_t verify_param_int_run_mode(dcf_param_t param_type, const char *param_value, param_value_t *out_value);
status_t verify_param_int_filename_format(dcf_param_t param_type, const char *param_value, param_value_t *out_value);
status_t verify_param_int_compress_algorithm(dcf_param_t param_type, const char *param_value, param_value_t *out_value);
status_t verify_param_int_append_thread_num(dcf_param_t param_type, const char *param_value, param_value_t *out_value);
status_t verify_param_size(dcf_param_t param_type, const char *param_value, param_value_t *out_value);
status_t verify_param_string(dcf_param_t param_type, const char *param_value, param_value_t *out_value);
status_t verify_param_log_backup_file_count(dcf_param_t param_type, const char *param_value, param_value_t *out_value);
status_t verify_param_max_log_file_size(dcf_param_t param_type, const char *param_value, param_value_t *out_value);
status_t verify_param_log_path_permission(dcf_param_t param_type, const char *param_value, param_value_t *out_value);
status_t verify_param_log_file_permission(dcf_param_t param_type, const char *param_value, param_value_t *out_value);
status_t verify_param_password(dcf_param_t param_type, const char *param_value, param_value_t *out_value);
status_t verify_param_log_level(dcf_param_t param_type, const char *param_value, param_value_t *out_value);
status_t verify_param_election_timeout(dcf_param_t param_type, const char *param_value, param_value_t *out_value);
status_t verify_param_ssl_notify_time(dcf_param_t param_type, const char *param_value, param_value_t *out_value);
status_t verify_param_mec_batch_size(dcf_param_t param_type, const char *param_value, param_value_t *out_value);
status_t verify_param_mec_fragment_size(dcf_param_t param_type, const char *param_value, param_value_t *out_value);
status_t verify_param_socket_timeout(dcf_param_t param_type, const char *param_value, param_value_t *out_value);
status_t verify_param_connect_timeout(dcf_param_t param_type, const char *param_value, param_value_t *out_value);
status_t verify_param_log_suppress_enable(dcf_param_t param_type, const char *param_value, param_value_t *out_value);
status_t verify_param_majority_groups(dcf_param_t param_type, const char *param_value, param_value_t *out_value);

#ifdef __cplusplus
}
#endif

#endif
