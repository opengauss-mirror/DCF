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
 * metadata.h
 *    metadata process
 *
 * IDENTIFICATION
 *    src/metadata/metadata.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __METADATA_H__
#define __METADATA_H__

#include "cm_types.h"
#include "util_error.h"
#include "cm_defs.h"
#include "cm_log.h"
#include "md_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t md_init(uint32 node_id, const char* cfg_str);
void md_uninit();
uint32 md_get_cur_node();
status_t md_get_node_list(uint32 list[CM_MAX_NODE_COUNT], uint32* count);
status_t md_get_node(uint32 node_id, dcf_node_t* node_item);

status_t md_get_stream_list(uint32 list[CM_MAX_STREAM_COUNT], uint32* count);
status_t md_get_stream_nodes(uint32 stream_id, uint32 list[CM_MAX_NODE_COUNT], uint32* count);
status_t md_get_stream_nodes_count(uint32 stream_id, uint32* count);
status_t md_get_stream_node_roles(uint32 stream_id, dcf_node_role_t list[CM_MAX_NODE_COUNT], uint32* count);
status_t md_get_stream_node_ext(uint32 stream_id, uint32 node_id, dcf_node_t* node_info);
status_t md_get_stream_node_weight(uint32 stream_id, uint32 node_id, uint32* weight);
status_t md_check_stream_node_exist(uint32 stream_id, uint32 node_id);
status_t md_get_streams_by_node(uint32 node_id, uint32 list[CM_MAX_STREAM_COUNT], uint32* count);

status_t md_add_stream_member(uint32 stream_id, dcf_node_t* node_info);
status_t md_remove_stream_member(uint32 stream_id, uint32 node_id);
status_t md_change_stream_member(uint32 stream_id, uint32 node_id, dcf_change_member_t *change_info);

const char* md_get_rolename_by_type(dcf_role_t type);
const dcf_role_t md_get_roletype_by_name(const char *name);

status_t md_get_param(dcf_param_t param_type, param_value_t* param_value);
status_t md_get_param_by_name(const char *param_name, char *param_value, unsigned int size);
status_t md_set_param(dcf_param_t param_type, const param_value_t* param_value);
status_t md_verify_param(const char *param_name, const char *param_value,
    dcf_param_t *param_type, param_value_t *out_value);

status_t md_to_string(char* buffer, uint32 length, uint32* size);
status_t md_save(const char* cfg_str, uint32 size);

status_t md_get_voter_num(uint32 stream_id, uint32* quorum);
status_t md_is_voter(uint32 stream_id, uint32 node_id, bool32* is_voter);
status_t md_set_status(meta_status_t new_status);
meta_status_t md_get_status();
uint32 md_get_checksum();
status_t md_set_checksum(uint32 checksum);

char* md_get_buffer();
status_t parse_change_member_str(const char *change_str, uint32 *stream_id, uint32 *node_id,
    dcf_change_member_t *change_info);

status_t md_get_majority_groups(uint32 groups[CM_MAX_GROUP_COUNT], uint32 *count);

#ifdef __cplusplus
}
#endif

#endif
