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
 * md_stream.h
 *    metadata process
 *
 * IDENTIFICATION
 *    src/metadata/md_stream.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __MD_STREAM_H__
#define __MD_STREAM_H__

#include "cm_types.h"
#include "cm_error.h"
#include "cm_defs.h"
#include "md_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

// add node define
status_t append_node_info(dcf_node_t** node_list, dcf_node_t* node);
status_t get_node_list(dcf_node_t** node_list, uint32 list[CM_MAX_NODE_COUNT], uint32* count);
status_t get_node(dcf_node_t** node_list, uint32 node_id, dcf_node_t* node_item);

// add stream define
status_t add_stream_member(dcf_streams_t* stream_list, uint32 stream_id, dcf_node_t* node_info);
status_t remove_stream_member(dcf_streams_t* stream_list, uint32 stream_id, uint32 node_id);
status_t change_stream_member(dcf_streams_t* stream_list, uint32 stream_id, uint32 node_id,
    dcf_change_member_t *change_info);

status_t get_stream_list(dcf_streams_t* stream_list, uint32 list[CM_MAX_STREAM_COUNT], uint32* count);
status_t get_stream_nodes(dcf_streams_t* stream_list, uint32 stream_id, uint32 list[CM_MAX_NODE_COUNT], uint32* count);
status_t get_stream_nodes_count(dcf_streams_t* stream_list, uint32 stream_id, uint32* count);
status_t get_stream_node_roles(dcf_streams_t* stream_list, uint32 stream_id, dcf_node_role_t list[CM_MAX_NODE_COUNT],
    uint32* count);
status_t get_stream_node_weight(dcf_streams_t* stream_list, uint32 stream_id, uint32 node_id, uint32* weight);
status_t get_stream_node_ext(dcf_streams_t* stream_list, uint32 stream_id, uint32 node_id, dcf_node_t* node_info);
status_t check_stream_node_exist(dcf_streams_t* stream_list, uint32 stream_id, uint32 node_id);
status_t get_streams_by_node(dcf_streams_t* stream_list, uint32 node_id, uint32 list[CM_MAX_STREAM_COUNT],
    uint32* count);
status_t get_stream_voter_num(dcf_streams_t* stream_list, uint32 stream_id, uint32* count);
bool32 node_is_voter(dcf_streams_t* stream_list, uint32 stream_id, uint32 node_id);

#ifdef __cplusplus
}
#endif

#endif
