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
 * mec_agent.c
 *    mec process
 *
 * IDENTIFICATION
 *    src/network/mec/mec_agent.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_log.h"
#include "cm_file.h"
#include "mec_reactor.h"
#include "cm_memory.h"
#include "mec_profile.h"
#include "mec_func.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t agent_create_pool(agent_pool_t *agent_pool, uint32 agent_num)
{
    size_t size;
    uint32 loop;
    agent_t *agent = NULL;
    agent_pool->optimized_count = agent_num;

    size = sizeof(agent_t) * agent_pool->optimized_count;
    if (size == 0 || size / sizeof(agent_t) != agent_pool->optimized_count) {
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, "creating agent pool");
        return CM_ERROR;
    }
    agent_pool->agents = (agent_t *)malloc(size);
    if (agent_pool->agents == NULL) {
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, "creating agent pool");
        return CM_ERROR;
    }
    errno_t err = memset_s(agent_pool->agents, size, 0, size);
    if (err != EOK) {
        CM_FREE_PTR(agent_pool->agents);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CM_ERROR;
    }

    agent_pool->lock_idle = 0;
    biqueue_init(&agent_pool->idle_agents);

    agent_pool->lock_new = 0;
    biqueue_init(&agent_pool->blank_agents);
    for (loop = 0; loop < agent_pool->optimized_count; ++loop) {
        agent = &agent_pool->agents[loop];
        agent->pool = agent_pool;
        biqueue_add_tail(&agent_pool->blank_agents, QUEUE_NODE_OF(agent));
    }
    agent_pool->blank_count = agent_pool->optimized_count;

    if (cm_event_init(&agent_pool->idle_evnt) != CM_SUCCESS) {
        CM_FREE_PTR(agent_pool->agents);
        CM_THROW_ERROR(ERR_CREATE_EVENT, cm_get_os_error());
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

void agent_detach_and_set_oneshot(mec_pipe_t *pipe)
{
    detach_agent(pipe, RECV_MODE);

    CM_MFENCE;
    if (reactor_set_oneshot(pipe) != CM_SUCCESS) {
        LOG_RUN_ERR("[MEC]set oneshot flag of socket failed, "
                    "channel %d, os error %d",
                    pipe->channel->id, cm_get_sock_error());
    }
}

static void try_process_multi_channels(agent_t *agent)
{
    mec_pipe_t *pipe = NULL;

    for (;;) {
        // event will be set by reactor
        if (cm_event_timedwait(&agent->event, CM_SLEEP_50_FIXED) == CM_SUCCESS) {
            break;
        }

        if (agent->thread.closed) {
            return;
        }
    }

    if (agent->mode >= MODE_END || agent->pipe->attach[agent->mode].job == NULL) {
        LOG_DEBUG_ERR("[MEC]agent mode=%u or job=%p err.", agent->mode, agent->pipe->attach[agent->mode].job);
        return;
    }

    pipe = agent->pipe;
    pipe->attach[agent->mode].spid = cm_get_current_thread_id();

    LOG_DEBUG_INF("[MEC]begin to process job from inst id %u, channel id %u.",
                  MEC_INSTANCE_ID(pipe->channel->id),
                  MEC_CHANNEL_ID(pipe->channel->id));
    bool32 is_continue;
    while (!agent->thread.closed) {
        pipe->attach[agent->mode].job((void *)pipe, &is_continue);
        if (is_continue) {
            continue;
        }
        return;
    }
}


static inline void return_agent2blankqueue(agent_t *agent, agent_pool_t *agent_pool)
{
    // when failed to start an agent, the agent has not be added to idle queue
    // so then pointer 'next' could be null
    if (agent->next != NULL) {
        // remove agent from idle queue
        cm_spin_lock(&agent_pool->lock_idle, NULL);
        if (agent->next != NULL) {          // re-check to protect change by reactor thread
            biqueue_del_node(QUEUE_NODE_OF(agent));
            agent_pool->idle_count--;
        }
        cm_spin_unlock(&agent_pool->lock_idle);
    }

    // add agent to blank queue
    cm_spin_lock(&agent_pool->lock_new, NULL);
    biqueue_add_tail(&agent_pool->blank_agents, QUEUE_NODE_OF(agent));

    --agent_pool->curr_count;
    agent_pool->blank_count++;
    // can not process agent member after agent back to blank queue, otherwise will core.
    cm_spin_unlock(&agent_pool->lock_new);
}


void agent_entry(thread_t *thread)
{
    agent_t *agent = (agent_t *)thread->argument;

    (void)cm_set_thread_name("agent");
    LOG_RUN_INF("[MEC]agent thread started, tid:%lu, close:%u", thread->id, thread->closed);
    while (!thread->closed) {
        try_process_multi_channels(agent);
    }
    LOG_RUN_INF("[MEC]agent thread closed, tid:%lu, close:%u", thread->id, thread->closed);
    cm_event_destory(&agent->event);
    cm_release_thread(thread);
    return_agent2blankqueue(agent, agent->pool);
}

status_t start_agent(agent_t *agent, thread_entry_t entry)
{
    return cm_create_thread(entry, 0, agent, &agent->thread);
}


void sync_agents_closed(agent_pool_t *agent_pool)
{
    if (agent_pool->agents != NULL) {
        for (uint32 i = 0; i < agent_pool->optimized_count; i++) {
            agent_pool->agents[i].thread.closed = CM_TRUE;
        }
    }

    while (agent_pool->curr_count > 0) {
        cm_sleep(1);
    }
}

static void shutdown_agent_pool(agent_pool_t *agent_pool)
{
    LOG_RUN_INF("[MEC]all agents' thread have been closed");
    sync_agents_closed(agent_pool);
    cm_event_destory(&agent_pool->idle_evnt);
    biqueue_init(&agent_pool->idle_agents);
    biqueue_init(&agent_pool->blank_agents);
    agent_pool->blank_count = 0;
    agent_pool->idle_count = 0;
    CM_FREE_PTR(agent_pool->agents);
}

void agent_destroy_pool(agent_pool_t *agent_pool)
{
    LOG_RUN_INF("[MEC]begin to destroy agent pool");
    shutdown_agent_pool(agent_pool);
    LOG_RUN_INF("[MEC]destroy agent pool end");
}


static inline status_t create_agent(agent_t *agent)
{
    if (cm_event_init(&agent->event) != CM_SUCCESS) {
        CM_THROW_ERROR(ERR_CREATE_EVENT, cm_get_os_error());
        return CM_ERROR;
    }
    if (start_agent(agent, agent_entry) != CM_SUCCESS) {
        LOG_RUN_ERR("[MEC]create agent thread failed, os error %d", cm_get_os_error());
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static inline void bind_channel_agent(mec_pipe_t *pipe, attach_mode_t mode, agent_t *agent)
{
    agent->mode = mode;
    agent->pipe = pipe;
    pipe->attach[mode].agent = agent;
    pipe->attach[mode].status = ACTIVE;
}


static inline status_t try_create_agent(agent_pool_t *agent_pool, agent_t **agent)
{
    biqueue_node_t *node = NULL;
    bool32 need_create;

    if (agent_pool->curr_count == agent_pool->optimized_count) {
        *agent = NULL;
        return CM_SUCCESS;
    }

    cm_spin_lock(&agent_pool->lock_new, NULL);

    need_create = agent_pool->curr_count < agent_pool->optimized_count;
    if (!need_create) {
        cm_spin_unlock(&agent_pool->lock_new);
        *agent = NULL;
        return CM_SUCCESS;
    }
    node = biqueue_del_head(&agent_pool->blank_agents);
    ++agent_pool->curr_count;
    agent_pool->blank_count--;
    cm_spin_unlock(&agent_pool->lock_new);

    *agent = OBJECT_OF(agent_t, node);
    if (create_agent(*agent) != CM_SUCCESS) {
        return_agent2blankqueue(*agent, agent_pool);
        *agent = NULL;
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t try_attach_agent(mec_pipe_t *pipe, agent_pool_t *agent_pool, attach_mode_t mode, agent_t **agent)
{
    status_t status;
    biqueue_node_t *node = NULL;

    // if not empty , get agent from idle pool.
    if (!biqueue_empty(&agent_pool->idle_agents)) {
        cm_spin_lock(&agent_pool->lock_idle, NULL);
        node = biqueue_del_head(&agent_pool->idle_agents);
        if (node != NULL) {
            agent_pool->idle_count--;
        }
        cm_spin_unlock(&agent_pool->lock_idle);

        if (node != NULL) {
            *agent = OBJECT_OF(agent_t, node);
            bind_channel_agent(pipe, mode, *agent);
            return CM_SUCCESS;
        }
    }

    status = try_create_agent(agent_pool, agent);
    CM_RETURN_IFERR(status);

    if (*agent != NULL) {
        bind_channel_agent(pipe, mode, *agent);
    }

    return CM_SUCCESS;
}

status_t attach_agent(mec_pipe_t *pipe, agent_pool_t *agent_pool, attach_mode_t mode, agent_t **agent)
{
    *agent = NULL;
    for (;;) {
        /* hit scenario: enter deadloop, after create agent failed */
        status_t status = try_attach_agent(pipe, agent_pool, mode, agent);
        CM_RETURN_IFERR(status);

        if (*agent != NULL) {
            return CM_SUCCESS;
        }

        cm_event_wait(&agent_pool->idle_evnt);
    }
}

void detach_agent(mec_pipe_t *pipe, attach_mode_t mode)
{
    volatile agent_t *agent = pipe->attach[mode].agent;
    if (agent == NULL) {
        return;
    }
    agent_pool_t *agent_pool = agent->pool;

    CM_ASSERT(pipe == agent->pipe);
    agent->pipe = NULL;
    agent->mode = MODE_END;
    /* status might still be ACTIVE while being detached from agent, so need to reset */
    pipe->attach[mode].status = INACTIVE;

    cm_spin_lock(&agent_pool->lock_idle, NULL);
    biqueue_add_tail(&agent_pool->idle_agents, QUEUE_NODE_OF(agent));
    agent_pool->idle_count++;
    cm_spin_unlock(&agent_pool->lock_idle);
    cm_event_notify(&agent_pool->idle_evnt);
    CM_MFENCE;
    /* agent must be freed in the end */
    pipe->attach[mode].agent = NULL;
    LOG_DEBUG_INF("[MEC]detach channel %u from agent %lu success, idle agent num %u.",
                  pipe->channel->id, agent->thread.id, agent_pool->idle_count);
}

void show_agent_count(agent_pool_t *agent_pool, msg_priv_t priv)
{
    LOG_DEBUG_INF("[MEC]priv[%u] agent_pool count info: "
                  "idle_count[%u] blank_count[%u] curr_count[%u] optimized_count[%u].",
                  priv,
                  agent_pool->idle_count,
                  agent_pool->blank_count,
                  agent_pool->curr_count,
                  agent_pool->optimized_count);
}


#ifdef __cplusplus
}
#endif
