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
 * cs_listener.c
 *    protocol process
 *
 * IDENTIFICATION
 *    src/network/protocol/cs_listener.c
 *
 * -------------------------------------------------------------------------
 */

#include "cs_listener.h"
#include "cm_epoll.h"
#include "cm_file.h"
#include "mec.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t cs_check_link_ip(tcp_link_t *link)
{
    char temp_ip[CM_MAX_IP_LEN] = { 0 };
    (void)cm_inet_ntop(SOCKADDR(&link->remote), temp_ip, CM_MAX_IP_LEN);
    int32 ip_len = strlen(temp_ip);

    uint32 list[CM_MAX_NODE_COUNT];
    uint32 count;
    if (md_get_node_list(list, &count) != CM_SUCCESS) {
        return CM_ERROR;
    }

    dcf_node_t node_item;
    int32 node_ip_len;
    uint32 local_node_id = md_get_cur_node();
    for (uint32 i = 0; i < count; i++) {
        if (md_get_node(list[i], &node_item) != CM_SUCCESS) {
            return CM_ERROR;
        }
        if (local_node_id == node_item.node_id) {
            continue;
        }
        node_ip_len = strlen(node_item.ip);
        if (ip_len == node_ip_len
            && memcmp(node_item.ip, temp_ip, ip_len) == EOK) {
            return CM_SUCCESS;
        }
    }
    LOG_RUN_ERR("[MEC]connection for ip: %s is refused, not in whitelist.", temp_ip);
    return CM_ERROR;
}

static bool32 cs_create_tcp_link(socket_t sock_ready, cs_pipe_t *pipe)
{
    pipe->type = CS_TYPE_TCP;
    tcp_link_t *link  = &pipe->link.tcp;
    link->local.salen = sizeof(link->local.addr);
    (void)getsockname(sock_ready, (struct sockaddr *)&link->local.addr, (socklen_t *)&link->local.salen);

    link->remote.salen = sizeof(link->remote.addr);
    link->sock = (socket_t)accept(sock_ready,
                                  SOCKADDR(&link->remote),
                                  &link->remote.salen);

    if (link->sock == CS_INVALID_SOCKET) {
        return CM_FALSE;
    }
    if (cs_check_link_ip(link) != CM_SUCCESS) {
        cs_disconnect(pipe);
        return CM_FALSE;
    }

    /* set default options of sock */
    cs_set_io_mode(link->sock, CM_TRUE, CM_TRUE);
    cs_set_buffer_size(link->sock, CM_TCP_DEFAULT_BUFFER_SIZE, CM_TCP_DEFAULT_BUFFER_SIZE);
    cs_set_keep_alive(link->sock, CM_TCP_KEEP_IDLE, CM_TCP_KEEP_INTERVAL, CM_TCP_KEEP_COUNT);
    cs_set_linger(link->sock, 1, 1);

    link->closed = CM_FALSE;
    return CM_TRUE;
}

void cs_try_tcp_accept(tcp_lsnr_t *lsnr, cs_pipe_t *pipe)
{
    socket_t sock_ready;
    int32 loop;
    int32 ret;
    struct epoll_event evnts[CM_MAX_LSNR_HOST_COUNT];

    ret = epoll_wait(lsnr->epoll_fd, evnts, (int)lsnr->sock_count, CM_POLL_WAIT);
    if (ret == 0) {
        return;
    }
    if (ret < 0) {
        return;
    }

    for (loop = 0; loop < ret && (uint32)loop < CM_MAX_LSNR_HOST_COUNT; ++loop) {
        sock_ready = evnts[loop].data.fd;
        if (!cs_create_tcp_link(sock_ready, pipe)) {
            continue;
        }
        if (lsnr->status != LSNR_STATUS_RUNNING) {
            cs_tcp_disconnect(&pipe->link.tcp);
            continue;
        }
        if (lsnr->action(lsnr, pipe) != CM_SUCCESS) {
            cs_tcp_disconnect(&pipe->link.tcp);
            continue;
        }
    }
}

static void srv_tcp_lsnr_proc(thread_t *thread)
{
    cs_pipe_t pipe;
    tcp_lsnr_t *lsnr = NULL;
    errno_t rc_memzero;

    lsnr = (tcp_lsnr_t *)thread->argument;

    rc_memzero = memset_s(&pipe, sizeof(cs_pipe_t), 0, sizeof(cs_pipe_t));
    MEMS_RETVOID_IFERR(rc_memzero);

    pipe.type = CS_TYPE_TCP;
    (void)cm_set_thread_name("tcp_lsnr");

    while (!thread->closed) {
        cs_try_tcp_accept(lsnr, &pipe);
        if (lsnr->status == LSNR_STATUS_PAUSING) {
            lsnr->status = LSNR_STATUS_PAUSED;
        }
    }
}


static status_t cs_alloc_sock_slot(tcp_lsnr_t *lsnr, int32 *slot_id)
{
    uint32 loop;
    for (loop = 0; loop < CM_MAX_LSNR_HOST_COUNT; ++loop) {
        if (lsnr->socks[loop] == CS_INVALID_SOCKET) {
            lsnr->socks[loop] = CS_SOCKET_SLOT_USED;
            *slot_id = loop;
            return CM_SUCCESS;
        }
    }

    CM_THROW_ERROR(ERR_IPADDRESS_NUM_EXCEED, (uint32)CM_MAX_LSNR_HOST_COUNT);
    return CM_ERROR;
}

static status_t cs_create_one_lsnr_sock(tcp_lsnr_t *lsnr, const char *host, int32 *slot_id)
{
    socket_t *sock = NULL;
    tcp_option_t option;
    int32 code;
    sock_addr_t sock_addr;

    if (lsnr->sock_count == CM_MAX_LSNR_HOST_COUNT) {
        CM_THROW_ERROR(ERR_IPADDRESS_NUM_EXCEED, (uint32)CM_MAX_LSNR_HOST_COUNT);
        return CM_ERROR;
    }

    CM_RETURN_IFERR(cm_ipport_to_sockaddr(host, lsnr->port, &sock_addr));

    CM_RETURN_IFERR(cs_alloc_sock_slot(lsnr, slot_id));
    sock = &lsnr->socks[*slot_id];
    if (cs_create_socket(SOCKADDR_FAMILY(&sock_addr), sock) != CM_SUCCESS) {
        return CM_ERROR;
    }

    cs_set_io_mode(*sock, CM_TRUE, CM_TRUE);

    /************************************************************************
        When a process is killed, the address bound by the process can not be bound
        by other process immediately, this situation is unacceptable, so we use the
        SO_REUSEADDR parameter which allows the socket to be bound to an address
        that is already in use.
        ************************************************************************/
    option = 1;
    code = setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, (char *)&option, sizeof(uint32));
    if (-1 == code) {
        CM_THROW_ERROR(ERR_SET_SOCKET_OPTION);
        goto error;
    }

    /************************************************************************
        Because of two processes could bpage to the same address, so we need check
        whether the address has been bound before bpage to it.
        ************************************************************************/
    if (cs_tcp_try_connect(host, lsnr->port)) {
        CM_THROW_ERROR(ERR_TCP_PORT_CONFLICTED, host, (uint32)lsnr->port);
        goto error;
    }

    code = bind(*sock, SOCKADDR(&sock_addr), sock_addr.salen);
    if (code != 0) {
        CM_THROW_ERROR(ERR_SOCKET_BIND, host, (uint32)lsnr->port, cm_get_os_error());
        goto error;
    }

    code = listen(*sock, SOMAXCONN);
    if (code != 0) {
        CM_THROW_ERROR(ERR_SOCKET_LISTEN, "listen socket", cm_get_os_error());
        goto error;
    }

    (void)cm_atomic_inc(&lsnr->sock_count);
    return CM_SUCCESS;
error:
    (void)cs_close_socket(*sock);
    *sock = CS_INVALID_SOCKET;
    return CM_ERROR;
}


void cs_close_lsnr_socks(tcp_lsnr_t *lsnr)
{
    uint32 loop;
    for (loop = 0; loop < CM_MAX_LSNR_HOST_COUNT; ++loop) {
        if (lsnr->socks[loop] != CS_INVALID_SOCKET) {
            (void)cs_close_socket(lsnr->socks[loop]);
            lsnr->socks[loop] = CS_INVALID_SOCKET;
        }
    }
    (void)cm_atomic_set(&lsnr->sock_count, 0);
}

status_t cs_create_lsnr_socks(tcp_lsnr_t *lsnr)
{
    char(*host)[CM_MAX_IP_LEN] = lsnr->host;
    int32 slot_id;
    lsnr->sock_count = 0;

    for (uint32 loop = 0; loop < CM_MAX_LSNR_HOST_COUNT; loop++) {
        if (host[loop][0] != '\0') {
            if (cs_create_one_lsnr_sock(lsnr, host[loop], &slot_id) != CM_SUCCESS) {
                cs_close_lsnr_socks(lsnr);
                return CM_ERROR;
            }
        }
    }

    return CM_SUCCESS;
}


status_t cs_lsnr_init_epoll_fd(tcp_lsnr_t *lsnr)
{
    struct epoll_event ev;
    uint32 loop;

    lsnr->epoll_fd = epoll_create1(0);
    if (-1 == lsnr->epoll_fd) {
        CM_THROW_ERROR(ERR_SOCKET_LISTEN, "create epoll fd for listener", cm_get_os_error());
        return CM_ERROR;
    }

    ev.events = EPOLLIN;
    for (loop = 0; loop < CM_MAX_LSNR_HOST_COUNT; ++loop) {
        if (lsnr->socks[loop] == CS_INVALID_SOCKET) {
            continue;
        }
        ev.data.fd = (int)lsnr->socks[loop];
        if (epoll_ctl(lsnr->epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev) != 0) {
            cm_close_file(lsnr->epoll_fd);
            CM_THROW_ERROR(ERR_SOCKET_LISTEN, "add socket for listening to epoll fd", cm_get_os_error());
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

status_t cs_start_tcp_lsnr(tcp_lsnr_t *lsnr, connect_action_t action)
{
    uint32 loop;
    lsnr->status = LSNR_STATUS_STOPPED;
    lsnr->action = action;

    for (loop = 0; loop < CM_MAX_LSNR_HOST_COUNT; loop++) {
        lsnr->socks[loop] = CS_INVALID_SOCKET;
    }

    if (cs_create_lsnr_socks(lsnr) != CM_SUCCESS) {
        LOG_RUN_ERR("[MEC]failed to create lsnr sockets for listener type %d", lsnr->type);
        return CM_ERROR;
    }

    if (cs_lsnr_init_epoll_fd(lsnr) != CM_SUCCESS) {
        cs_close_lsnr_socks(lsnr);
        LOG_RUN_ERR("[MEC]failed to init epoll fd for listener type %d", lsnr->type);
        return CM_ERROR;
    }

    lsnr->status = LSNR_STATUS_RUNNING;
    if (cm_create_thread(srv_tcp_lsnr_proc, 0, lsnr, &lsnr->thread) != CM_SUCCESS) {
        cs_close_lsnr_socks(lsnr);
        (void)epoll_close(lsnr->epoll_fd);
        lsnr->status = LSNR_STATUS_STOPPED;
        LOG_RUN_ERR("[MEC]failed to create accept thread for listener type %d", lsnr->type);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

void cs_stop_tcp_lsnr(tcp_lsnr_t *lsnr)
{
    cm_close_thread(&lsnr->thread);
    cs_close_lsnr_socks(lsnr);
    (void)epoll_close(lsnr->epoll_fd);
}

void cs_pause_tcp_lsnr(tcp_lsnr_t *lsnr)
{
    lsnr->status = LSNR_STATUS_PAUSING;
    while (lsnr->status != LSNR_STATUS_PAUSED && !lsnr->thread.closed) {
        cm_sleep(CM_SLEEP_5_FIXED);
    }
}

#ifdef __cplusplus
}
#endif
