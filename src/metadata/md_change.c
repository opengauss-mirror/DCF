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

int md_after_write_cb(uint32 stream_id, uint64 index, const char *buf, uint32 size, uint64 key, int32 error_no)
{
    status_t ret = elc_update_node_role(stream_id);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[META]after_write:elc_update_node_role failed.");
    }
    ret = mec_update_profile_inst();
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[META]after_write:mec_update_profile_inst failed.");
    }
    CM_RETURN_IFERR(md_set_status(META_NORMAL));
    return ret;
}

int md_consensus_notify_cb(uint32 stream_id, uint64 index, const char *buf, uint32 size, uint64 key)
{
    status_t ret = elc_update_node_role(stream_id);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[META]consensus_notify:elc_update_node_role failed.");
    }
    ret = mec_update_profile_inst();
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[META]consensus_notify:mec_update_profile_inst failed.");
    }
    CM_RETURN_IFERR(md_set_status(META_NORMAL));
    return ret;
}


#ifdef __cplusplus
}
#endif