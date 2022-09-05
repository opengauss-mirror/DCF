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
 * md_change.c
 *    metadata process
 *
 * IDENTIFICATION
 *    src/metadata/md_change.c
 *
 * -------------------------------------------------------------------------
 */

#include "md_change.h"
#include "metadata.h"

#ifdef __cplusplus
extern "C" {
#endif

int md_consensus_notify_cb(uint32 stream_id, uint64 index, const char *buf, uint32 size, uint64 key)
{
    status_t ret = CM_SUCCESS;
    uint32 node = CFG_LOG_NODE(key);
    uint32 src = md_get_cur_node();
 
    LOG_RUN_INF("[META]md_consensus_notify. node=%u, src=%u, key=0x%llx.", node, src, key);
    if (node != CM_NODE_ID_ALL && node != src) {
        CM_RETURN_IFERR(md_set_status(META_NORMAL));
        return CM_SUCCESS;
    }
    
    if (NEED_ADD(key) || NEED_REMOVE(key)) {
        ret = mec_update_profile_inst();
        if (ret != CM_SUCCESS) {
            LOG_DEBUG_ERR("[META]consensus_notify:mec_update_profile_inst failed.");
        } else {
            (void)rep_check_param_majority_groups();
        }
    }

    if (NEED_CHANGE_ROLE(key)) {
        ret = elc_update_node_role(stream_id);
        if (ret != CM_SUCCESS) {
            LOG_DEBUG_ERR("[META]consensus_notify:elc_update_node_role failed.");
        }
    }

    if (NEED_CHANGE_GROUP(key)) {
        ret = elc_update_node_group(stream_id);
        if (ret != CM_SUCCESS) {
            LOG_DEBUG_ERR("[META]consensus_notify:elc_update_node_group failed.");
        } else {
            (void)rep_check_param_majority_groups();
        }
    }

    if (NEED_CHANGE_PRIORITY(key)) {
        ret = elc_update_node_priority(stream_id);
        if (ret != CM_SUCCESS) {
            LOG_DEBUG_ERR("[META]consensus_notify:elc_update_node_priority failed.");
        }
    }

    CM_RETURN_IFERR(md_set_status(META_NORMAL));
    return ret;
}

int md_after_write_cb(uint32 stream_id, uint64 index, const char *buf, uint32 size, uint64 key, int32 error_no)
{
    return md_consensus_notify_cb(stream_id, index, buf, size, key);
}

#ifdef __cplusplus
}
#endif