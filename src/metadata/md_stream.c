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
 * md_stream.c
 *    metadata process
 *
 * IDENTIFICATION
 *    src/metadata/md_stream.c
 *
 * -------------------------------------------------------------------------
 */

#include "md_stream.h"
#include "cm_text.h"
#include "cm_log.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t check_node_id(uint32 node_id)
{
    if (node_id >= CM_MAX_NODE_COUNT) {
        LOG_DEBUG_ERR("[META]invalid node id");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t check_voting_weight(uint32 weight)
{
    if (weight >= CM_MAX_NODE_COUNT) {
        LOG_DEBUG_ERR("[META]invalid voting weight");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t append_node_info(dcf_node_t** node_list, dcf_node_t* node)
{
    if (check_node_id(node->node_id) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (check_voting_weight(node->voting_weight) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (node_list == NULL) {
        return CM_ERROR;
    }

    if (node_list[node->node_id] != NULL) { // already exists
        dcf_node_t* exists_node = node_list[node->node_id];
        *exists_node = *node;
        return CM_SUCCESS;
    }

    dcf_node_t* new_node = malloc(sizeof(dcf_node_t));
    if (new_node == NULL) {
        return CM_ERROR;
    }
    *new_node = *node;
    node_list[new_node->node_id] = new_node;

    return CM_SUCCESS;
}

status_t get_node(dcf_node_t** node_list, uint32 node_id, dcf_node_t* node_item)
{
    if (node_item == NULL || node_list == NULL) {
        return CM_ERROR;
    }

    if (check_node_id(node_id) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (node_list[node_id] == NULL) {
        return CM_ERROR;
    }
    *node_item = *node_list[node_id];
    return CM_SUCCESS;
}

status_t get_node_list(dcf_node_t** node_list, uint32 list[CM_MAX_NODE_COUNT], uint32* count)
{
    *count = 0;
    if (node_list == NULL) {
        return CM_SUCCESS;
    }

    for (uint32 i = 0; i < CM_MAX_NODE_COUNT; i++) {
        if (node_list[i] == NULL) {
            continue;
        }
        list[*count] = node_list[i]->node_id;
        (*count)++;
    }
    return CM_SUCCESS;
}

status_t check_stream_id(uint32 stream_id)
{
    if (stream_id >= CM_MAX_STREAM_COUNT) {
        LOG_DEBUG_ERR("[META]invalid stream id");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

bool32 stream_isexists(dcf_streams_t* stream_list, uint32 stream_id)
{
    if (stream_list == NULL) {
        return CM_FALSE;
    }

    if (MD_GET_STREAM(stream_list, stream_id) != NULL) {
        return CM_TRUE;
    }
    return CM_FALSE;
}

bool32 stream_node_isexists(dcf_streams_t* stream_list, uint32 stream_id, uint32 node_id)
{
    if (stream_list == NULL) {
        LOG_DEBUG_ERR("[META]null stream list");
        return CM_FALSE;
    }

    if (stream_isexists(stream_list, stream_id)) {
        if (MD_GET_STREAMS_NODE(stream_list, stream_id, node_id) != NULL) {
            return CM_TRUE;
        }
    }

    return CM_FALSE;
}

status_t check_stream_node_exist(dcf_streams_t* stream_list, uint32 stream_id, uint32 node_id)
{
    if (check_stream_id(stream_id) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (check_node_id(node_id) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (stream_node_isexists(stream_list, stream_id, node_id) == CM_FALSE) {
        LOG_DEBUG_ERR("[META]stream_id=%d node_id=%d not exist", stream_id, node_id);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t add_stream_member(dcf_streams_t* stream_list, uint32 stream_id, dcf_node_t* node_info)
{
    uint32 node_id = node_info->node_id;
    if (check_stream_id(stream_id) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (check_node_id(node_id) != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (check_voting_weight(node_info->voting_weight) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (stream_list == NULL) {
        LOG_DEBUG_ERR("[META]null stream list");
        return CM_ERROR;
    }

    bool32 stream_exists = CM_FALSE;
    dcf_stream_t* stream = MD_GET_STREAM(stream_list, stream_id);

    if (stream != NULL) {
        if (stream_node_isexists(stream_list, stream_id, node_id)) {
            return CM_ERROR;
        }
        stream_exists = CM_TRUE;
    } else {
        stream = malloc(sizeof(dcf_stream_t));
        if (stream == NULL) {
            return CM_ERROR;
        }
        if (memset_sp(stream, sizeof(dcf_stream_t), 0, sizeof(dcf_stream_t)) != EOK) {
            CM_FREE_PTR(stream);
            return CM_ERROR;
        }
        stream->stream_id = stream_id;
    }

    dcf_node_t* node_new = malloc(sizeof(dcf_node_t));
    if (node_new == NULL) {
        if (!stream_exists) {
            CM_FREE_PTR(stream);
        }
        return CM_ERROR;
    }
    *node_new = *node_info;
    CM_RETURN_IFERR(cm_ptlist_insert(&stream->node_list, node_id, node_new));
    CM_RETURN_IFERR(cm_ptlist_add(&stream->valid_nodes, node_new));
    if (stream_exists == CM_FALSE) {
        CM_RETURN_IFERR(cm_ptlist_insert(&stream_list->stream_list, stream_id, stream));
    }
    return CM_SUCCESS;
}

static status_t remove_member_from_stream_valid_nodes(dcf_stream_t* stream, uint32 node_id)
{
    ptlist_t *valid_node_list = &stream->valid_nodes;
    dcf_node_t *node = NULL;
    uint32 i, j;

    for (i = 0; i < valid_node_list->count; i++) {
        node = cm_ptlist_get(valid_node_list, i);
        CM_CHECK_NULL_PTR(node);
        if (node->node_id == node_id) {
            break;
        }
    }
    if (i == valid_node_list->count) {
        return CM_ERROR;
    }
    for (j = i; j < valid_node_list->count - 1; j++) {
        cm_ptlist_set(valid_node_list, j, cm_ptlist_get(valid_node_list, j + 1));
    }
    CM_RETURN_IFERR(cm_ptlist_remove(valid_node_list, valid_node_list->count - 1));
    return CM_SUCCESS;
}

status_t remove_stream_member(dcf_streams_t* stream_list, uint32 stream_id, uint32 node_id)
{
    if (check_stream_node_exist(stream_list, stream_id, node_id) != CM_SUCCESS) {
        return CM_ERROR;
    }

    dcf_stream_t* stream = MD_GET_STREAM(stream_list, stream_id);
    dcf_node_t *node = MD_GET_STREAM_NODE(stream, node_id);
    CM_RETURN_IFERR(cm_ptlist_remove(&stream->node_list, node_id));
    CM_RETURN_IFERR(remove_member_from_stream_valid_nodes(stream, node_id));
    CM_FREE_PTR(node);
    return CM_SUCCESS;
}

status_t change_stream_member(dcf_streams_t* stream_list, uint32 stream_id, uint32 node_id,
    dcf_change_member_t *change_info)
{
    if (check_stream_node_exist(stream_list, stream_id, node_id) != CM_SUCCESS) {
        return CM_ERROR;
    }

    dcf_node_t *node = MD_GET_STREAMS_NODE(stream_list, stream_id, node_id);
    CM_CHECK_NULL_PTR(node);
    if (NEED_CHANGE_ROLE(change_info->op_type)) {
        node->default_role = change_info->new_role;
    }
    if (NEED_CHANGE_GROUP(change_info->op_type)) {
        node->group = change_info->new_group;
    }
    if (NEED_CHANGE_PRIORITY(change_info->op_type)) {
        node->priority = change_info->new_priority;
    }
    return CM_SUCCESS;
}

status_t get_stream_list(dcf_streams_t* stream_list, uint32 list[CM_MAX_STREAM_COUNT], uint32* count)
{
    *count = 0;
    if (stream_list == NULL) {
        return CM_SUCCESS;
    }
    for (uint32 i = 0; i < CM_MAX_STREAM_COUNT; i++) {
        dcf_stream_t *stream = MD_GET_STREAM(stream_list, i);
        if (stream == NULL) {
            continue;
        }
        list[*count] = stream->stream_id;
        (*count)++;
    }
    return CM_SUCCESS;
}

status_t get_stream_nodes(dcf_streams_t* stream_list, uint32 stream_id, uint32 list[CM_MAX_NODE_COUNT], uint32* count)
{
    *count = 0;
    if (stream_isexists(stream_list, stream_id) == CM_FALSE) {
        return CM_ERROR;
    }

    dcf_stream_t* stream = MD_GET_STREAM(stream_list, stream_id);
    for (uint32 j = 0; j < CM_MAX_NODE_COUNT; j++) {
        dcf_node_t* node = MD_GET_STREAM_NODE(stream, j);
        if (node == NULL) {
            continue;
        }
        list[*count] = node->node_id;
        (*count)++;
    }

    return CM_SUCCESS;
}

status_t get_stream_nodes_count(dcf_streams_t* stream_list, uint32 stream_id, uint32* count)
{
    *count = 0;
    if (stream_isexists(stream_list, stream_id) == CM_FALSE) {
        return CM_ERROR;
    }

    dcf_stream_t* stream = MD_GET_STREAM(stream_list, stream_id);
    *count = stream->node_list.count;
    return CM_SUCCESS;
}

status_t get_stream_node_roles(dcf_streams_t* stream_list, uint32 stream_id,
    dcf_node_role_t list[CM_MAX_NODE_COUNT], uint32* count)
{
    *count = 0;
    if (stream_isexists(stream_list, stream_id) == CM_FALSE) {
        return CM_ERROR;
    }

    dcf_stream_t* stream = MD_GET_STREAM(stream_list, stream_id);
    uint32 stream_node_count = stream->valid_nodes.count;
    for (uint32 j = 0; j < stream_node_count; j++) {
        dcf_node_t* node = (dcf_node_t *)cm_ptlist_get(&stream->valid_nodes, j);
        CM_CHECK_NULL_PTR(node);
        list[*count].node_id = node->node_id;
        list[*count].default_role = node->default_role;
        (*count)++;
    }
    return CM_SUCCESS;
}

status_t get_stream_node_weight(dcf_streams_t* stream_list, uint32 stream_id, uint32 node_id, uint32* weight)
{
    if (stream_isexists(stream_list, stream_id) == CM_FALSE) {
        return CM_ERROR;
    }

    dcf_stream_t* stream = MD_GET_STREAM(stream_list, stream_id);
    uint32 stream_node_count = stream->valid_nodes.count;
    for (uint32 j = 0; j < stream_node_count; j++) {
        dcf_node_t* node = (dcf_node_t *)cm_ptlist_get(&stream->valid_nodes, j);
        CM_CHECK_NULL_PTR(node);
        if (node->node_id == node_id) {
            *weight = node->voting_weight;
            return CM_SUCCESS;
        }
    }
    return CM_ERROR;
}

status_t get_stream_node_ext(dcf_streams_t* stream_list, uint32 stream_id, uint32 node_id, dcf_node_t* node_info)
{
    if (node_info == NULL) {
        return CM_ERROR;
    }

    if (check_stream_node_exist(stream_list, stream_id, node_id) != CM_SUCCESS) {
        return CM_ERROR;
    }

    *node_info = *(MD_GET_STREAMS_NODE(stream_list, stream_id, node_id));
    return CM_SUCCESS;
}

status_t get_streams_by_node(dcf_streams_t* stream_list, uint32 node_id,
    uint32 list[CM_MAX_STREAM_COUNT], uint32* count)
{
    *count = 0;
    for (uint32 i = 0; i < CM_MAX_STREAM_COUNT; i++) {
        if (stream_node_isexists(stream_list, i, node_id)) {
            dcf_stream_t *stream = MD_GET_STREAM(stream_list, i);
            list[*count] = stream->stream_id;
            (*count)++;
        }
    }
    return CM_SUCCESS;
}

status_t get_stream_voter_num(dcf_streams_t* stream_list, uint32 stream_id, uint32* count)
{
    *count = 0;
    if (stream_list == NULL) {
        return CM_SUCCESS;
    }

    if (stream_isexists(stream_list, stream_id) == CM_FALSE) {
        return CM_ERROR;
    }

    *count = MD_GET_STREAM(stream_list, stream_id)->voter_num;
    return CM_SUCCESS;
}

bool32 node_is_voter(dcf_streams_t* stream_list, uint32 stream_id, uint32 node_id)
{
    if (stream_list == NULL) {
        return CM_FALSE;
    }

    if (stream_node_isexists(stream_list, stream_id, node_id) == CM_FALSE) {
        return CM_FALSE;
    }
    if (MD_GET_STREAMS_NODE(stream_list, stream_id, node_id)->default_role < DCF_ROLE_PASSIVE) {
        return CM_TRUE;
    }

    return CM_FALSE;
}

#ifdef __cplusplus
}
#endif
