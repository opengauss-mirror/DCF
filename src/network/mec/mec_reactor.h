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
 * mec_reactor.h
 *    mec process
 *
 * IDENTIFICATION
 *    src/network/mec/mec_reactor.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __MEC_REACTOR_H__
#define __MEC_REACTOR_H__

#include "cm_defs.h"
#include "cm_thread.h"
#include "cm_queue.h"
#include "cm_spinlock.h"
#include "cm_epoll.h"
#include "mec_agent.h"

#ifdef __cplusplus
extern "C" {
#endif

#define REACOTR_EVENT_WAIT_NUM    256
#define EV_WAIT_TIMEOUT           16
#define EV_WAIT_NUM               256

typedef enum en_reactor_status {
    REACTOR_STATUS_RUNNING,
    REACTOR_STATUS_PAUSING,
    REACTOR_STATUS_PAUSED,
    REACTOR_STATUS_STOPPED,
} reactor_status_t;

typedef struct st_reactor {
    uint32 id;
    thread_t thread;
    int epollfd;
    atomic32_t channel_count;
    uint32 avg_oagents;
    reactor_status_t status;
    agent_pool_t  *agent_pool;
} reactor_t;

typedef struct st_reactor_pool {
    uint32 reactor_count;
    uint32 roudroubin;
    uint32 roudroubin2;
    uint32 avg_channels;
    reactor_t *reactors;
} reactor_pool_t;

static inline bool32 reactor_in_dedicated_mode(const reactor_t *reactor)
{
    return (uint32)reactor->channel_count < (uint32)reactor->avg_oagents;
}

void proc_attached_failed_agent(const mec_pipe_t *pipe);
void reactor_entry(thread_t *thread);
status_t reactor_set_oneshot(mec_pipe_t *pipe);
status_t reactor_register_pipe(mec_pipe_t *pipe, reactor_pool_t *pool);
void reactor_unregister_pipe(mec_pipe_t *pipe);
status_t reactor_create_pool(reactor_pool_t *pool, agent_pool_t *agent_pool, mec_profile_t *profile);
void reactor_destroy_pool(reactor_pool_t *pool);
void reactor_pause_pool(reactor_pool_t *pool);


#ifdef __cplusplus
}
#endif

#endif