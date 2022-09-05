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
 * metadata.c
 *    metadata process
 *
 * IDENTIFICATION
 *    src/metadata/metadata.c
 *
 * -------------------------------------------------------------------------
 */

#include "metadata.h"
#include "cm_text.h"
#include "cm_num.h"
#include "cm_latch.h"
#include "cm_log.h"
#include "cm_checksum.h"
#include "md_defs.h"
#include "md_stream.h"
#include "md_param.h"
#include "md_store.h"
#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

static dcf_meta_t g_metadata;

static status_t parse_streams_cfg(dcf_streams_t* streams, const char *cfg_str);

dcf_streams_t* new_streams()
{
    dcf_streams_t* streams = NULL;
    streams = malloc(sizeof(dcf_streams_t));
    if (streams == NULL) {
        LOG_RUN_ERR("[META]malloc streams failed");
        return NULL;
    }
    cm_ptlist_init(&streams->stream_list);
    return streams;
}

dcf_stream_t* new_stream()
{
    dcf_stream_t* stream = NULL;
    stream = malloc(sizeof(dcf_stream_t));
    if (stream == NULL) {
        return NULL;
    }
    cm_ptlist_init(&stream->node_list);
    cm_ptlist_init(&stream->valid_nodes);
    return stream;
}

status_t get_store_stream(dcf_meta_t* metadata, bool32* is_exists)
{
    char* buffer = NULL;
    int32 len;
    CM_RETURN_IFERR(md_store_read(&buffer, &len)); // buffer need free by caller
    if (len == 0) {
        *is_exists = CM_FALSE;
        return CM_SUCCESS;
    }
    metadata->streams = new_streams();
    if (metadata->streams == NULL) {
        CM_FREE_PTR(buffer);
        return CM_ERROR;
    }
    if (parse_streams_cfg(metadata->streams, buffer) != CM_SUCCESS) {
        CM_FREE_PTR(buffer);
        CM_FREE_PTR(metadata->streams);
        return CM_ERROR;
    }

    metadata->checksum = cm_get_checksum(buffer, len);
    *is_exists = CM_TRUE;
    CM_FREE_PTR(buffer);
    return CM_SUCCESS;
}

status_t append_nodes(dcf_node_t** node_list, dcf_streams_t* streams)
{
    if (streams == NULL) {
        return CM_SUCCESS;
    }

    for (uint32 i = 0; i < CM_MAX_STREAM_COUNT; i++) {
        dcf_stream_t* stream = MD_GET_STREAM(streams, i);
        if (stream == NULL) {
            continue;
        }
        stream->voter_num = 0;
        for (uint32 j = 0; j < CM_MAX_NODE_COUNT; j++) {
            dcf_node_t *node = MD_GET_STREAM_NODE(stream, j);
            if (node == NULL) {
                continue;
            }
            if (node->default_role < DCF_ROLE_PASSIVE) {
                stream->voter_num += node->voting_weight;
            }
            CM_RETURN_IFERR(append_node_info(node_list, node));
        }
    }
    return CM_SUCCESS;
}

status_t reset_node_list(dcf_node_t** node_list, dcf_streams_t* streams)
{
    for (uint32 i = 0; i < CM_MAX_NODE_COUNT; i++) {
        CM_FREE_PTR(node_list[i]);
    }

    CM_RETURN_IFERR(append_nodes(node_list, streams));
    return CM_SUCCESS;
}

static bool32 is_valid_node_role_cfg(dcf_role_t role_type)
{
    return ((role_type == DCF_ROLE_FOLLOWER) || (role_type == DCF_ROLE_LEADER) || (role_type == DCF_ROLE_LOGGER) ||
        (role_type == DCF_ROLE_PASSIVE));
}

static status_t parse_stream_cfg_single(dcf_streams_t* streams, const cJSON* stream)
{
    uint32 stream_id;
    dcf_node_t node_info;
    cJSON *cfg_item = NULL;

    // stream_id
    cfg_item = cJSON_GetObjectItem(stream, "stream_id");
    CM_RETURN_IF_FALSE(cJSON_IsNumber(cfg_item));
    stream_id = cfg_item->valueint;
    // node_id
    cfg_item = cJSON_GetObjectItem(stream, "node_id");
    CM_RETURN_IF_FALSE(cJSON_IsNumber(cfg_item));
    node_info.node_id = cfg_item->valueint;
    // ip
    cfg_item = cJSON_GetObjectItem(stream, "ip");
    CM_RETURN_IF_FALSE(cJSON_IsString(cfg_item));
    char *ip = cJSON_GetStringValue(cfg_item);
    MEMS_RETURN_IFERR(strcpy_s(node_info.ip, CM_MAX_IP_LEN, ip));
    // port
    cfg_item = cJSON_GetObjectItem(stream, "port");
    CM_RETURN_IF_FALSE(cJSON_IsNumber(cfg_item));
    node_info.port = cfg_item->valueint;
    // role
    cfg_item = cJSON_GetObjectItem(stream, "role");
    CM_RETURN_IF_FALSE(cJSON_IsString(cfg_item));
    char *role_name = cJSON_GetStringValue(cfg_item);
    dcf_role_t role_type = md_get_roletype_by_name(role_name);
    if (!is_valid_node_role_cfg(role_type)) {
        LOG_DEBUG_ERR("[META] parse stream info: invalid node role(%d) cfg", role_type);
        return CM_ERROR;
    }
    node_info.default_role = role_type;

    node_info.voting_weight = CM_ELC_NORS_WEIGHT;
    node_info.group = CM_DEFAULT_GROUP_ID;
    node_info.priority = CM_DEFAULT_ELC_PRIORITY;
    // weight
    if (cJSON_HasObjectItem(stream, "weight") == 1) {
        cfg_item = cJSON_GetObjectItem(stream, "weight");
        CM_RETURN_IF_FALSE(cJSON_IsNumber(cfg_item));
        node_info.voting_weight = cfg_item->valueint;
    }
    // group
    if (cJSON_HasObjectItem(stream, "group") == 1) {
        cfg_item = cJSON_GetObjectItem(stream, "group");
        CM_RETURN_IF_FALSE(cJSON_IsNumber(cfg_item));
        node_info.group = MAX(cfg_item->valueint, 0); // group in cfg_str should be 0~INT32_MAX
    }
    // priority
    if (cJSON_HasObjectItem(stream, "priority") == 1) {
        cfg_item = cJSON_GetObjectItem(stream, "priority");
        CM_RETURN_IF_FALSE(cJSON_IsNumber(cfg_item));
        node_info.priority = MAX(cfg_item->valueint, 0); // priority in cfg_str should be 0~INT32_MAX
    }
    LOG_DEBUG_INF("[META] parse stream info: stream_id=%u node_id=%u ip=%s port=%u role=%s group=%u priority=%llu",
        stream_id, node_info.node_id, ip, node_info.port, role_name, node_info.group, node_info.priority);
    return add_stream_member(streams, stream_id, &node_info);
}

static status_t parse_streams_cfg(dcf_streams_t* streams, const char *cfg_str)
{
    cJSON *stream_list = cJSON_Parse(cfg_str);
    CM_RETURN_IF_FALSE_EX(cJSON_IsArray(stream_list), cJSON_Delete(stream_list));
    cJSON *stream_item = NULL;
    cJSON_ArrayForEach(stream_item, stream_list) {
        CM_RETURN_IF_FALSE_EX(cJSON_IsObject(stream_item), cJSON_Delete(stream_list));
        CM_RETURN_IFERR_EX(parse_stream_cfg_single(streams, stream_item), cJSON_Delete(stream_list));
    }
    cJSON_Delete(stream_list);
    return CM_SUCCESS;
}

static status_t parse_change_member_single(const cJSON* stream, uint32 *stream_id, uint32 *node_id,
    dcf_change_member_t *change_info)
{
    cJSON *cfg_item = NULL;

    // init op_type
    change_info->op_type = OP_FLAG_NONE;
    // stream_id
    cfg_item = cJSON_GetObjectItem(stream, "stream_id");
    CM_RETURN_IF_FALSE(cJSON_IsNumber(cfg_item));
    *stream_id = cfg_item->valueint;
    // node_id
    cfg_item = cJSON_GetObjectItem(stream, "node_id");
    CM_RETURN_IF_FALSE(cJSON_IsNumber(cfg_item));
    *node_id = cfg_item->valueint;
    // group
    if (cJSON_HasObjectItem(stream, "group") == 1) {
        cfg_item = cJSON_GetObjectItem(stream, "group");
        CM_RETURN_IF_FALSE(cJSON_IsNumber(cfg_item));
        change_info->new_group = MAX(cfg_item->valueint, 0); // group in change_str should be 0~INT32_MAX
        change_info->op_type |= OP_FLAG_CHANGE_GROUP;
    }
    // priority
    if (cJSON_HasObjectItem(stream, "priority") == 1) {
        cfg_item = cJSON_GetObjectItem(stream, "priority");
        CM_RETURN_IF_FALSE(cJSON_IsNumber(cfg_item));
        change_info->new_priority = MAX(cfg_item->valueint, 0); // priority in change_str should be 0~INT32_MAX
        change_info->op_type |= OP_FLAG_CHANGE_PRIORITY;
    }
    // role
    if (cJSON_HasObjectItem(stream, "role") == 1) {
        cfg_item = cJSON_GetObjectItem(stream, "role");
        CM_RETURN_IF_FALSE(cJSON_IsString(cfg_item));
        char *role_name = cJSON_GetStringValue(cfg_item);
        dcf_role_t role_type = md_get_roletype_by_name(role_name);
        if (!is_valid_node_role_cfg(role_type)) {
            LOG_DEBUG_ERR("[META] parse change_member info: invalid node role(%d) cfg", role_type);
            return CM_ERROR;
        }
        change_info->new_role = role_type;
        change_info->op_type |= OP_FLAG_CHANGE_ROLE;
    }

    LOG_DEBUG_INF("[META]change_member info:stream_id=%u node_id=%u op_type=%u role=%u group=%u priority=%llu",
        *stream_id, *node_id, change_info->op_type, change_info->new_role,
        change_info->new_group, change_info->new_priority);
    return CM_SUCCESS;
}

status_t parse_change_member_str(const char *change_str, uint32 *stream_id, uint32 *node_id,
    dcf_change_member_t *change_info)
{
    cJSON *stream_list = cJSON_Parse(change_str);
    CM_RETURN_IF_FALSE_EX(cJSON_IsArray(stream_list), cJSON_Delete(stream_list));

    if (cJSON_GetArraySize(stream_list) > 1) {
        LOG_DEBUG_ERR("[META] change_str(%s) is not the only array.", change_str);
        cJSON_Delete(stream_list);
        return CM_ERROR;
    }
    cJSON *stream_item = NULL;
    cJSON_ArrayForEach(stream_item, stream_list) {
        CM_RETURN_IF_FALSE_EX(cJSON_IsObject(stream_item), cJSON_Delete(stream_list));
        CM_RETURN_IFERR_EX(parse_change_member_single(stream_item, stream_id, node_id, change_info),
            cJSON_Delete(stream_list));
        break;
    }
    cJSON_Delete(stream_list);
    return CM_SUCCESS;
}

static inline bool32 check_node_id_valid(uint32 node_id)
{
    bool32 is_valid = CM_FALSE;
    cm_latch_s(&g_metadata.latch, 0, CM_FALSE, NULL);
    for (int i = 0; i < CM_MAX_NODE_COUNT; i++) {
        if (g_metadata.all_nodes[i] == NULL) {
            continue;
        }
        if (node_id == g_metadata.all_nodes[i]->node_id) {
            is_valid = CM_TRUE;
            break;
        }
    }
    cm_unlatch(&g_metadata.latch, NULL);
    if (!is_valid) {
        LOG_DEBUG_ERR("node id %u is invalid", node_id);
    }
    return is_valid;
}

// need call md_uninit when call md_init failed to free resource
status_t md_init(uint32 node_id, const char* cfg_str)
{
    if (memset_sp(&g_metadata, sizeof(dcf_meta_t), 0, sizeof(dcf_meta_t)) != EOK) {
        LOG_RUN_ERR("[META]init metadata failed");
        return CM_ERROR;
    }
    cm_latch_init(&g_metadata.latch);
    g_metadata.buffer = malloc(CM_METADATA_DEF_MAX_LEN);
    if (g_metadata.buffer == NULL) {
        LOG_RUN_ERR("[META]malloc buffer failed");
        return CM_ERROR;
    }

    CM_RETURN_IFERR(md_store_init());

    bool32 is_exists = CM_FALSE;
    CM_RETURN_IFERR(get_store_stream(&g_metadata, &is_exists));
    if (is_exists == CM_FALSE) {
        dcf_streams_t* streams = new_streams();
        if (streams == NULL) {
            LOG_RUN_ERR("[META]init metadata stream failed");
            return CM_ERROR;
        }
        status_t ret = parse_streams_cfg(streams, cfg_str);
        if (ret != CM_SUCCESS) {
            CM_THROW_ERROR(ERR_PARSE_CFG_STR, cfg_str);
            return ret;
        }
        g_metadata.streams = streams;

        uint32 size;
        CM_RETURN_IFERR(md_to_string(md_get_buffer(), CM_METADATA_DEF_MAX_LEN, &size));
        g_metadata.checksum = cm_get_checksum(md_get_buffer(), size);
        CM_RETURN_IFERR(md_store_write(md_get_buffer(), (int32)size));
    }
    g_metadata.status = META_NORMAL;
    CM_RETURN_IFERR(reset_node_list(g_metadata.all_nodes, g_metadata.streams));
    CM_RETURN_IF_FALSE(check_node_id_valid(node_id));
    g_metadata.current_node_id = node_id;
    LOG_RUN_INF("[META]Md init succeed, checksum:%u", g_metadata.checksum);

    return CM_SUCCESS;
}

void free_streams(dcf_streams_t* streams)
{
    if (streams == NULL) {
        return;
    }

    for (uint32 i = 0; i < CM_MAX_STREAM_COUNT; i++) {
        dcf_stream_t* stream = MD_GET_STREAM(streams, i);
        if (stream == NULL) {
            continue;
        }
        for (uint32 j = 0; j < CM_MAX_NODE_COUNT; j++) {
            dcf_node_t *node = MD_GET_STREAM_NODE(stream, j);
            if (node == NULL) {
                continue;
            }
            CM_FREE_PTR(node);
        }
        cm_destroy_ptlist(&stream->node_list);
        cm_destroy_ptlist(&stream->valid_nodes);
        CM_FREE_PTR(stream);
    }
    cm_destroy_ptlist(&streams->stream_list);
    CM_FREE_PTR(streams);
    return;
}

void md_uninit()
{
    cm_latch_x(&g_metadata.latch, 0, NULL);
    for (uint32 i = 0; i < CM_MAX_NODE_COUNT; i++) {
        CM_FREE_PTR(g_metadata.all_nodes[i]);
    }

    free_streams(g_metadata.streams);
    g_metadata.streams = NULL;
    CM_FREE_PTR(g_metadata.buffer);
    g_metadata.status = META_UNINIT;
    cm_unlatch(&g_metadata.latch, NULL);
}

status_t stream_to_string(dcf_streams_t* streams, text_buf_t* buffer)
{
    cJSON *obj = cJSON_CreateArray();

    for (uint32 i = 0; i < CM_MAX_STREAM_COUNT; i++) {
        dcf_stream_t* stream = MD_GET_STREAM(streams, i);
        if (stream == NULL) {
            continue;
        }
        for (uint32 j = 0; j < CM_MAX_NODE_COUNT; j++) {
            dcf_node_t* node = MD_GET_STREAM_NODE(stream, j);
            if (node == NULL) {
                continue;
            }
            cJSON *node_item = cJSON_CreateObject();
            CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(node_item, "stream_id", stream->stream_id));
            CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(node_item, "node_id", node->node_id));
            CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddStringToObject(node_item, "ip", node->ip));
            CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(node_item, "port", node->port));
            CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddStringToObject(node_item, "role",
                md_get_rolename_by_type(node->default_role)));
            CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(node_item, "weight", node->voting_weight));
            CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(node_item, "group", node->group));
            CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(node_item, "priority", node->priority));
            if (cJSON_AddItemToArray(obj, node_item) == CM_FALSE) {
                LOG_DEBUG_ERR("[META]cJSON AddItemToArray fail when stream to string");
                cJSON_Delete(obj);
                return CM_ERROR;
            }
        }
    }

    status_t ret = memset_s(buffer->str, CM_METADATA_DEF_MAX_LEN, 0, CM_METADATA_DEF_MAX_LEN);
    if (ret != EOK) {
        CM_THROW_ERROR(ERR_MEM_ZONE_INIT_FAIL, ret);
        cJSON_Delete(obj);
        return CM_ERROR;
    }
    if (!cJSON_PrintPreallocated(obj, buffer->str, buffer->max_size, 0)) {
        cJSON_Delete(obj);
        return CM_ERROR;
    }
    buffer->len = strlen(buffer->str) + 1;
    cJSON_Delete(obj);

    return CM_SUCCESS;
}

status_t md_to_string(char* buffer, uint32 length, uint32* size)
{
    text_buf_t out_buf;
    out_buf.max_size = length;
    out_buf.str = buffer;
    out_buf.len = 0;
    cm_latch_s(&g_metadata.latch, 0, CM_FALSE, NULL);
    CM_RETURN_IFERR_EX(stream_to_string(g_metadata.streams, &out_buf), cm_unlatch(&g_metadata.latch, NULL));
    *size = out_buf.len;
    cm_unlatch(&g_metadata.latch, NULL);
    LOG_DEBUG_INF("[META]md_to_string len:%u value:%s", out_buf.len, out_buf.str);
    return CM_SUCCESS;
}

uint32 md_get_cur_node()
{
    uint32 node_id;
    cm_latch_s(&g_metadata.latch, 0, CM_FALSE, NULL);
    node_id = g_metadata.current_node_id;
    cm_unlatch(&g_metadata.latch, NULL);
    return node_id;
}

status_t md_get_node_list(uint32 list[CM_MAX_NODE_COUNT], uint32* count)
{
    status_t ret;
    cm_latch_s(&g_metadata.latch, 0, CM_FALSE, NULL);
    ret = get_node_list(g_metadata.all_nodes, list, count);
    cm_unlatch(&g_metadata.latch, NULL);
    return ret;
}

status_t md_get_node(uint32 node_id, dcf_node_t* node_item)
{
    status_t ret;
    cm_latch_s(&g_metadata.latch, 0, CM_FALSE, NULL);
    ret = get_node(g_metadata.all_nodes, node_id, node_item);
    cm_unlatch(&g_metadata.latch, NULL);
    return ret;
}

status_t md_get_stream_list(uint32 list[CM_MAX_STREAM_COUNT], uint32* count)
{
    status_t ret;
    cm_latch_s(&g_metadata.latch, 0, CM_FALSE, NULL);
    ret = get_stream_list(g_metadata.streams, list, count);
    cm_unlatch(&g_metadata.latch, NULL);
    return ret;
}

status_t md_get_stream_nodes(uint32 stream_id, uint32 list[CM_MAX_NODE_COUNT], uint32* count)
{
    status_t ret;
    cm_latch_s(&g_metadata.latch, 0, CM_FALSE, NULL);
    ret = get_stream_nodes(g_metadata.streams, stream_id, list, count);
    cm_unlatch(&g_metadata.latch, NULL);
    return ret;
}

status_t md_get_stream_nodes_count(uint32 stream_id, uint32* count)
{
    status_t ret;
    cm_latch_s(&g_metadata.latch, 0, CM_FALSE, NULL);
    ret = get_stream_nodes_count(g_metadata.streams, stream_id, count);
    cm_unlatch(&g_metadata.latch, NULL);
    return ret;
}

status_t md_get_stream_node_roles(uint32 stream_id, dcf_node_role_t list[CM_MAX_NODE_COUNT], uint32* count)
{
    status_t ret;
    cm_latch_s(&g_metadata.latch, 0, CM_FALSE, NULL);
    ret = get_stream_node_roles(g_metadata.streams, stream_id, list, count);
    cm_unlatch(&g_metadata.latch, NULL);
    return ret;
}

status_t md_get_stream_node_ext(uint32 stream_id, uint32 node_id, dcf_node_t* node_info)
{
    status_t ret;
    cm_latch_s(&g_metadata.latch, 0, CM_FALSE, NULL);
    ret = get_stream_node_ext(g_metadata.streams, stream_id, node_id, node_info);
    cm_unlatch(&g_metadata.latch, NULL);
    return ret;
}

status_t md_get_stream_node_weight(uint32 stream_id, uint32 node_id, uint32* weight)
{
    status_t ret;
    cm_latch_s(&g_metadata.latch, 0, CM_FALSE, NULL);
    ret = get_stream_node_weight(g_metadata.streams, stream_id, node_id, weight);
    cm_unlatch(&g_metadata.latch, NULL);
    return ret;
}

status_t md_check_stream_node_exist(uint32 stream_id, uint32 node_id)
{
    status_t ret;
    cm_latch_s(&g_metadata.latch, 0, CM_FALSE, NULL);
    ret = check_stream_node_exist(g_metadata.streams, stream_id, node_id);
    cm_unlatch(&g_metadata.latch, NULL);
    return ret;
}

status_t md_get_streams_by_node(uint32 node_id, uint32 list[CM_MAX_STREAM_COUNT], uint32* count)
{
    status_t ret;
    cm_latch_s(&g_metadata.latch, 0, CM_FALSE, NULL);
    ret = get_streams_by_node(g_metadata.streams, node_id, list, count);
    cm_unlatch(&g_metadata.latch, NULL);
    return ret;
}

status_t md_add_stream_member(uint32 stream_id, dcf_node_t* node_info)
{
    cm_latch_x(&g_metadata.latch, 0, NULL);
    CM_RETURN_IFERR_EX(add_stream_member(g_metadata.streams, stream_id, node_info),
        cm_unlatch(&g_metadata.latch, NULL));
    CM_RETURN_IFERR_EX(reset_node_list(g_metadata.all_nodes, g_metadata.streams), cm_unlatch(&g_metadata.latch, NULL));
    cm_unlatch(&g_metadata.latch, NULL);
    return CM_SUCCESS;
}

status_t md_remove_stream_member(uint32 stream_id, uint32 node_id)
{
    status_t ret;
    cm_latch_x(&g_metadata.latch, 0, NULL);
    ret = remove_stream_member(g_metadata.streams, stream_id, node_id);
    if (ret == CM_SUCCESS) {
        ret = reset_node_list(g_metadata.all_nodes, g_metadata.streams);
    }
    cm_unlatch(&g_metadata.latch, NULL);
    return ret;
}

status_t md_change_stream_member(uint32 stream_id, uint32 node_id, dcf_change_member_t *change_info)
{
    cm_latch_x(&g_metadata.latch, 0, NULL);
    CM_RETURN_IFERR_EX(change_stream_member(g_metadata.streams, stream_id, node_id, change_info),
        cm_unlatch(&g_metadata.latch, NULL));
    CM_RETURN_IFERR_EX(reset_node_list(g_metadata.all_nodes, g_metadata.streams), cm_unlatch(&g_metadata.latch, NULL));
    cm_unlatch(&g_metadata.latch, NULL);
    return CM_SUCCESS;
}

const char* md_get_rolename_by_type(dcf_role_t type)
{
    switch (type) {
        case DCF_ROLE_LEADER:
            return "LEADER";
        case DCF_ROLE_FOLLOWER:
            return "FOLLOWER";
        case DCF_ROLE_LOGGER:
            return "LOGGER";
        case DCF_ROLE_PASSIVE:
            return "PASSIVE";
        case DCF_ROLE_PRE_CANDIDATE:
            return "PRE_CANDIDATE";
        case DCF_ROLE_CANDIDATE:
            return "CANDIDATE";
        default:
            return "UNKNOWN";;
    }
}

const dcf_role_t md_get_roletype_by_name(const char *name)
{
    if (!CM_STR_ICASE_CMP(name, "LEADER")) {
        return DCF_ROLE_LEADER;
    } else if (!CM_STR_ICASE_CMP(name, "FOLLOWER")) {
        return DCF_ROLE_FOLLOWER;
    } else if (!CM_STR_ICASE_CMP(name, "LOGGER")) {
        return DCF_ROLE_LOGGER;
    } else if (!CM_STR_ICASE_CMP(name, "PASSIVE")) {
        return DCF_ROLE_PASSIVE;
    } else if (!CM_STR_ICASE_CMP(name, "PRE_CANDIDATE")) {
        return DCF_ROLE_PRE_CANDIDATE;
    } else if (!CM_STR_ICASE_CMP(name, "CANDIDATE")) {
        return DCF_ROLE_CANDIDATE;
    }
    return DCF_ROLE_UNKNOWN;
}

status_t md_get_param(dcf_param_t param_type, param_value_t* param_value)
{
    cm_latch_s(&g_metadata.latch, 0, CM_FALSE, NULL);
    status_t ret = get_param(param_type, param_value);
    cm_unlatch(&g_metadata.latch, NULL);
    return ret;
}

status_t md_get_param_by_name(const char *param_name, char *param_value, unsigned int size)
{
    cm_latch_s(&g_metadata.latch, 0, CM_FALSE, NULL);
    status_t ret = get_param_by_name(param_name, param_value, size);
    cm_unlatch(&g_metadata.latch, NULL);
    return ret;
}

status_t md_set_param(dcf_param_t param_type, const param_value_t* param_value)
{
    cm_latch_x(&g_metadata.latch, 0, NULL);
    status_t ret = set_param(param_type, param_value);
    cm_unlatch(&g_metadata.latch, NULL);
    return ret;
}

status_t md_verify_param(const char *param_name, const char *param_value,
    dcf_param_t *param_type, param_value_t *out_value)
{
    cm_latch_s(&g_metadata.latch, 0, CM_FALSE, NULL);
    status_t ret = verify_param_value(param_name, param_value, param_type, out_value);
    cm_unlatch(&g_metadata.latch, NULL);
    return ret;
}

status_t md_get_voter_num(uint32 stream_id, uint32* quorum)
{
    cm_latch_s(&g_metadata.latch, 0, CM_FALSE, NULL);
    status_t ret = get_stream_voter_num(g_metadata.streams, stream_id, quorum);
    cm_unlatch(&g_metadata.latch, NULL);
    return ret;
}

status_t md_is_voter(uint32 stream_id, uint32 node_id, bool32* is_voter)
{
    cm_latch_s(&g_metadata.latch, 0, CM_FALSE, NULL);
    *is_voter = CM_FALSE;
    if (node_is_voter(g_metadata.streams, stream_id, node_id)) {
        *is_voter = CM_TRUE;
    }
    cm_unlatch(&g_metadata.latch, NULL);
    return CM_SUCCESS;
}

status_t md_save(const char* cfg_str, uint32 size)
{
    cm_latch_x(&g_metadata.latch, 0, NULL);

    dcf_streams_t* streams = new_streams();
    if (streams == NULL) {
        cm_unlatch(&g_metadata.latch, NULL);
        return CM_ERROR;
    }

    CM_RETURN_IFERR_EX(md_store_write((char*)cfg_str, (int32)size), cm_unlatch(&g_metadata.latch, NULL));
    g_metadata.checksum = cm_get_checksum(cfg_str, size);
    CM_RETURN_IFERR_EX(parse_streams_cfg(streams, cfg_str), cm_unlatch(&g_metadata.latch, NULL));
    CM_RETURN_IFERR_EX(reset_node_list(g_metadata.all_nodes, streams), cm_unlatch(&g_metadata.latch, NULL));

    free_streams(g_metadata.streams);
    g_metadata.streams = streams;
    cm_unlatch(&g_metadata.latch, NULL);
    return CM_SUCCESS;
}

status_t md_set_status(meta_status_t new_status)
{
    cm_latch_x(&g_metadata.latch, 0, NULL);
    if (new_status == META_CATCH_UP && g_metadata.status != META_NORMAL) {
        // don't change when last request complete
        LOG_DEBUG_ERR("can't catch up, old status=%d.", g_metadata.status);
        cm_unlatch(&g_metadata.latch, NULL);
        return CM_ERROR;
    }
    g_metadata.status = new_status;
    cm_unlatch(&g_metadata.latch, NULL);
    return CM_SUCCESS;
}

meta_status_t md_get_status()
{
    cm_latch_s(&g_metadata.latch, 0, CM_FALSE, NULL);
    meta_status_t current_status = g_metadata.status;
    cm_unlatch(&g_metadata.latch, NULL);
    return current_status;
}

uint32 md_get_checksum()
{
    cm_latch_s(&g_metadata.latch, 0, CM_FALSE, NULL);
    uint32 checksum = g_metadata.checksum;
    cm_unlatch(&g_metadata.latch, NULL);
    return checksum;
}

status_t md_set_checksum(uint32 checksum)
{
    cm_latch_x(&g_metadata.latch, 0, NULL);
    g_metadata.checksum = checksum;
    cm_unlatch(&g_metadata.latch, NULL);
    return CM_SUCCESS;
}

char* md_get_buffer()
{
    return g_metadata.buffer;
}

status_t md_get_majority_groups(uint32 groups[CM_MAX_GROUP_COUNT], uint32 *count)
{
    cm_latch_s(&g_metadata.latch, 0, CM_FALSE, NULL);
    status_t ret = get_param_magority_groups(groups, count);
    if (ret != CM_SUCCESS) {
        cm_unlatch(&g_metadata.latch, NULL);
        return CM_ERROR;
    }
    cm_unlatch(&g_metadata.latch, NULL);
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
