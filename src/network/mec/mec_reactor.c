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
 * mec_reactor.c
 *    mec process
 *
 * IDENTIFICATION
 *    src/network/mec/mec_reactor.c
 *
 * -------------------------------------------------------------------------
 */

#include "mec_reactor.h"
#include "cm_memory.h"
#include "mec_profile.h"
#include "mec_func.h"

#define POLL_TIME_OUT          5
#define SLEEP_TIME             5
#define WAIT_TIME             50

status_t reactor_work(reactor_t *reactor)
{
    if (cm_create_thread(reactor_entry, 0, (void *)reactor, &reactor->thread) != CM_SUCCESS) {
        LOG_RUN_ERR("[MEC]failed to create reactor thread, errno %d", cm_get_os_error());
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

void proc_attached_failed_agent(const mec_pipe_t *pipe)
{
    int32 code;
    const char *message = NULL;
    LOG_RUN_ERR("[MEC]attach agent failed, channel id [%u], os error %d",
                pipe->channel->id, cm_get_sock_error());
    cm_get_error(&code, &message);
    if (code == ERR_ALLOC_MEMORY || code == ERR_CREATE_THREAD) {
        cm_sleep(WAIT_TIME);
    }
}

static void reactor_wait4events(reactor_t *reactor)
{
    mec_pipe_t *pipe = NULL;
    agent_t *agent = NULL;
    int loop, nfds;
    struct epoll_event events[EV_WAIT_NUM];
    struct epoll_event *ev = NULL;

    if (reactor->status != REACTOR_STATUS_RUNNING) {
        return;
    }

    nfds = epoll_wait(reactor->epollfd, events, EV_WAIT_NUM, EV_WAIT_TIMEOUT);
    if (nfds == -1) {
        if (errno != EINTR) {
            LOG_RUN_ERR("[MEC]Failed to wait for connection request, OS error:%d", cm_get_os_error());
        }
        return;
    }
    if (nfds == 0) {
        return;
    }

    for (loop = 0; loop < nfds; ++loop) {
        ev = &events[loop];
        pipe = (mec_pipe_t *)ev->data.ptr;

        if (reactor->status != REACTOR_STATUS_RUNNING) {
            if (reactor_set_oneshot(pipe) != CM_SUCCESS) {
                LOG_RUN_ERR("[MEC]set oneshot flag of socket failed, channel %d, "
                    " os error %d", pipe->channel->id, cm_get_sock_error());
            }

            continue;
        }

        CM_ASSERT(pipe->attach[RECV_MODE].agent == NULL);
        status_t status = attach_agent(pipe, reactor->agent_pool, RECV_MODE, &agent);
        if (status != CM_SUCCESS) {
            // decrement the active session if failed to attach agent
            if (status != CM_SUCCESS) {
                proc_attached_failed_agent(pipe);
                return;
            }
        }

        if (agent != NULL) {
            LOG_DEBUG_INF("[MEC]receive message from channel %d, attached agent %lu",
                pipe->channel->id, agent->thread.id);
            cm_event_notify(&agent->event);
        }
    }
}

static void reactor_handle_events(reactor_t *reactor)
{
    reactor_wait4events(reactor);
    if (reactor_in_dedicated_mode(reactor)) {
        cm_sleep(SLEEP_TIME);
    }
}

void reactor_entry(thread_t *thread)
{
    reactor_t *reactor = (reactor_t *)thread->argument;

    (void)cm_set_thread_name("reactor");
    LOG_RUN_INF("[MEC]reactor thread started");
    while (!thread->closed) {
        reactor_handle_events(reactor);
        if (reactor->status == REACTOR_STATUS_PAUSING) {
            reactor->status = REACTOR_STATUS_PAUSED;
        }
    }
    LOG_RUN_INF("[MEC]reactor thread closed");
    (void)epoll_close(reactor->epollfd);
}

#define AVG_ROUND_CEIL(a, b) (((a) + (b)-1) / (b))


static inline status_t reactor_start(reactor_t *reactor, uint32 avg_oagents)
{
    reactor->status = REACTOR_STATUS_RUNNING;
    reactor->epollfd = epoll_create1(0);
    reactor->avg_oagents = avg_oagents;

    return reactor_work(reactor);
}


static status_t reactor_start_pool(reactor_pool_t *pool, agent_pool_t *agent_pool)
{
    reactor_t *reactor = NULL;
    uint32 size = pool->reactor_count;
    uint32 optimized_agents, remainder, avg_oagents;

    optimized_agents = agent_pool->optimized_count / pool->reactor_count;
    remainder = agent_pool->optimized_count % pool->reactor_count;
    for (uint32 loop = 0; loop < size; loop++) {
        reactor = &pool->reactors[loop];
        reactor->id = loop;
        reactor->agent_pool = agent_pool;
        avg_oagents = optimized_agents + (loop < remainder ? 1 : 0);
        CM_RETURN_IFERR(reactor_start(reactor, avg_oagents));
    }

    return CM_SUCCESS;
}

status_t reactor_set_oneshot(mec_pipe_t *pipe)
{
    struct epoll_event ev;
    int fd = (int)pipe->recv_pipe.link.tcp.sock;

    ev.events = EPOLLIN | EPOLLRDHUP | EPOLLONESHOT;
    ev.data.ptr = (void *)pipe;

    if (epoll_ctl(pipe->reactor->epollfd, EPOLL_CTL_MOD, fd, &ev) != 0) {
        return CM_ERROR;
    }
    LOG_DEBUG_INF("[MEC]channel %u set_oneshot success", pipe->channel->id);
    return CM_SUCCESS;
}

static status_t reactor_add_epoll_pipe(mec_pipe_t *pipe)
{
    reactor_t *reactor = pipe->reactor;
    struct epoll_event ev;
    int fd = (int)pipe->recv_pipe.link.tcp.sock;
    cm_thread_lock(&pipe->recv_epoll_lock);

    (void)cm_atomic32_inc(&reactor->channel_count);
    ev.events = EPOLLIN |  EPOLLRDHUP | EPOLLONESHOT;
    ev.data.ptr = (void *)pipe;
    if (epoll_ctl(reactor->epollfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        (void)cm_atomic32_dec(&reactor->channel_count);
        cm_thread_unlock(&pipe->recv_epoll_lock);
        LOG_RUN_ERR("[MEC]register session to reactor failed, channel %u, reactor %lu, active agent num %u,os error %d",
                    pipe->channel->id, reactor->thread.id, reactor->agent_pool->curr_count, cm_get_sock_error());
        return CM_ERROR;
    }

    pipe->is_reg = CM_TRUE;
    cm_thread_unlock(&pipe->recv_epoll_lock);
    LOG_DEBUG_INF("[MEC]register channel %u to reactor %lu sucessfully, current channel count %ld",
                  pipe->channel->id, reactor->thread.id, (long)reactor->channel_count);

    return CM_SUCCESS;
}

status_t reactor_register_pipe(mec_pipe_t *pipe, reactor_pool_t *pool)
{
    reactor_t *reactor = NULL;
    uint32 count = 0;

    // dispatch by load
    while (1) {
        ++count;
        reactor = &pool->reactors[pool->roudroubin++ % pool->reactor_count];
        /* agent pool no idle thread, continue to check */
        if (reactor_in_dedicated_mode(reactor)) {
            break;
        }

        if (count == pool->reactor_count) {
            reactor = &pool->reactors[pool->roudroubin2++ % pool->reactor_count];
            break;
        }
    }

    pipe->reactor = reactor;
    CM_MFENCE;

    return reactor_add_epoll_pipe(pipe);
}

void reactor_unregister_pipe(mec_pipe_t *pipe)
{
    int fd = (int)pipe->recv_pipe.link.tcp.sock;
    reactor_t *reactor = pipe->reactor;

    cm_thread_lock(&pipe->recv_epoll_lock);
    if (pipe->is_reg == CM_FALSE) {
        cm_thread_unlock(&pipe->recv_epoll_lock);
        return;
    }

    if (epoll_ctl(reactor->epollfd, EPOLL_CTL_DEL, fd, NULL) != 0) {
        LOG_RUN_ERR("[MEC]unregister channel [%u] from reactor[%lu] failed, os error %d",
                    pipe->channel->id, reactor->thread.id, cm_get_sock_error());
        cm_thread_unlock(&pipe->recv_epoll_lock);
        return;
    }

    (void)cm_atomic32_dec(&reactor->channel_count);
    pipe->is_reg = CM_FALSE;
    pipe->reactor = NULL;
    cm_thread_unlock(&pipe->recv_epoll_lock);
    LOG_DEBUG_INF("[MEC]unregister channel [%u] from reactor[%lu] success, current channel count %ld",
                  pipe->channel->id, reactor->thread.id, (long)reactor->channel_count);
}

status_t reactor_create_pool(reactor_pool_t *pool, agent_pool_t *agent_pool, mec_profile_t *profile)
{
    size_t size;
    errno_t err;
    pool->reactor_count = profile->reactor_num;
    pool->roudroubin = 0;
    pool->roudroubin2 = 0;

    pool->avg_channels = AVG_ROUND_CEIL(profile->channel_num * CM_MAX_NODE_COUNT, pool->reactor_count);
    size = sizeof(reactor_t) * pool->reactor_count;

    if (size == 0 || size / sizeof(reactor_t) != pool->reactor_count) {
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)0, "creating reactor pool");
        return CM_ERROR;
    }
    pool->reactors = (reactor_t *)malloc(size);
    if (pool->reactors == NULL) {
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)size, "creating reactor pool");
        return CM_ERROR;
    }

    err = memset_s(pool->reactors, size, 0, size);
    if (err != EOK) {
        CM_FREE_PTR(pool->reactors);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return CM_ERROR;
    }

    if (reactor_start_pool(pool, agent_pool) != CM_SUCCESS) {
        reactor_destroy_pool(pool);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

void reactor_destroy_pool(reactor_pool_t *pool)
{
    reactor_t *reactor = NULL;

    for (uint32 loop = 0; loop < pool->reactor_count; loop++) {
        reactor = &pool->reactors[loop];
        cm_close_thread(&reactor->thread);
        reactor->status = REACTOR_STATUS_STOPPED;
    }
    pool->reactor_count = 0;
    CM_FREE_PTR(pool->reactors);
}

void reactor_pause_pool(reactor_pool_t *pool)
{
    reactor_t *reactor = NULL;
    for (uint32 loop = 0; loop < pool->reactor_count; loop++) {
        reactor = &pool->reactors[loop];
        reactor->status = REACTOR_STATUS_PAUSING;
        while (reactor->status != REACTOR_STATUS_PAUSED && !reactor->thread.closed) {
            cm_sleep(CM_SLEEP_5_FIXED);
        }
    }
}
