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
 * mec_profile.h
 *    mec process
 *
 * IDENTIFICATION
 *    src/network/mec/mec_profile.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __MEC_PROFILE_H__
#define __MEC_PROFILE_H__

// MQ = Message Queue
#include "cm_defs.h"
#include "cm_spinlock.h"
#include "md_defs.h"
#ifdef __cplusplus
extern "C" {
#endif


typedef struct st_mec_tcp_addr {
    char   ip[CM_MAX_IP_LEN];
    uint16 port;
    uint8  reserved[2];
} mec_tcp_addr_t;

typedef union st_mec_addr {
    mec_tcp_addr_t t_addr;
} mec_addr_t;

typedef struct st_mec_profile {
    spinlock_t           lock;
    uint16               inst_id;
    volatile uint16      inst_count;
    mec_addr_t           inst_arr[CM_MAX_NODE_COUNT];
    int16                maps[CM_MAX_NODE_COUNT];
    uint8                pipe_type;
    uint8                reserved;
    uint16               channel_num;
    uint64               msg_pool_size;
    uint32               frag_size;
    uint32               batch_size;
    uint32               agent_num;
    uint32               reactor_num;
    compress_algorithm_t algorithm;
    uint32               level;
    int32                connect_timeout;  // ms
    int32                socket_timeout;   // ms
} mec_profile_t;


#ifdef __cplusplus
}
#endif


#endif
