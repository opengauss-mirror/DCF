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
 * mec_agent.h
 *    mec process
 *
 * IDENTIFICATION
 *    src/network/mec/mec_agent.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __MEC_AGENT_H__
#define __MEC_AGENT_H__

#include "cm_defs.h"
#include "cm_thread.h"
#include "cm_spinlock.h"
#include "cm_atomic.h"
#include "cm_sync.h"
#include "cm_queue.h"
#include "cs_pipe.h"
#include "mec_profile.h"
#include "mec_func.h"
#ifdef __cplusplus
extern "C" {
#endif


typedef struct st_agent {
    mec_pipe_t *pipe;
    thread_t thread;
    cm_event_t event;
    struct {
        uint32 mode : 2;
        uint32 reserved : 30;
    };
    struct st_agent *prev;
    struct st_agent *next;
    struct st_agent_pool *pool;
} agent_t;

typedef struct st_agent_pool {
    struct st_agent *agents;
    spinlock_t lock_idle;  // lock for idle queue
    biqueue_t idle_agents;
    uint32 idle_count;
    spinlock_t lock_new;     // lock for creating new agent
    biqueue_t blank_agents;  // agents not initialized (for example: private memory not allocated, etc.)
    uint32 blank_count;
    volatile uint32 curr_count;  // agent pool has create thread num
    atomic32_t channel_count;
    uint32 optimized_count;
    cm_event_t idle_evnt;  // when an session detached from agent, this event will be triggered
} agent_pool_t;


status_t agent_create_pool(agent_pool_t *agent_pool, uint32 agent_num);
void agent_destroy_pool(agent_pool_t *agent_pool);
status_t attach_agent(mec_pipe_t *pipe, agent_pool_t *agent_pool, attach_mode_t mode, agent_t **agent);
void detach_agent(mec_pipe_t *pipe, attach_mode_t mode);
void agent_detach_and_set_oneshot(mec_pipe_t *pipe);
void sync_agents_closed(agent_pool_t *agent_pool);
void show_agent_count(agent_pool_t *agent_pool, msg_priv_t priv);


#ifdef __cplusplus
}
#endif

#endif
