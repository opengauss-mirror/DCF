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
 * cs_pipe.c
 *    protocol process
 *
 * IDENTIFICATION
 *    src/network/protocol/cs_pipe.c
 *
 * -------------------------------------------------------------------------
 */

#include "cs_pipe.h"
#include "cm_num.h"
#include "util_profile_stat.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef status_t (*recv_func_t)(void *link, char *buf, uint32 size, int32 *recv_size, uint32 *wait_event);
typedef status_t (*send_func_t)(void *link, const char *buf, uint32 size, int32 *send_size);
typedef status_t (*recv_timed_func_t)(void *link, char *buf, uint32 size, uint32 timeout);
typedef status_t (*send_timed_func_t)(void *link, const char *buf, uint32 size, uint32 timeout);
typedef status_t (*wait_func_t)(void *link, uint32 wait_for, int32 timeout, bool32 *ready);

const text_t g_pipe_type_names[CS_TYPE_CEIL] = {
    { "UNKNOWN", 7 },
    { "TCP", 3 },
    { "SSL", 3 },
};

typedef struct st_vio {
    recv_func_t vio_recv;
    send_func_t vio_send;
    wait_func_t vio_wait;
    recv_timed_func_t vio_recv_timed;
    send_timed_func_t vio_send_timed;
} vio_t;


static const vio_t g_vio_list[] = {
    { NULL, NULL, NULL, NULL, NULL },

    // TCP io functions
    { (recv_func_t)cs_tcp_recv, (send_func_t)cs_tcp_send, (wait_func_t)cs_tcp_wait,
      (recv_timed_func_t)cs_tcp_recv_timed, (send_timed_func_t)cs_tcp_send_timed },

    // SSL io functions
    { (recv_func_t)cs_ssl_recv, (send_func_t)cs_ssl_send, (wait_func_t)cs_ssl_wait,
      (recv_timed_func_t)cs_ssl_recv_timed, (send_timed_func_t)cs_ssl_send_timed },
};

/*
  Macro definitions for pipe I/O operations
  @note
    Performance sensitive, the pipe->type should be guaranteed by the caller.
      e.g. CS_TYPE_TCP, CS_TYPE_SSL, CS_TYPE_DOMAIN_SOCKET
*/
#define GET_VIO(pipe) \
    (&g_vio_list[MIN((pipe)->type, CS_TYPE_CEIL - 1)])

#define VIO_SEND(pipe, buf, size, len) \
    GET_VIO(pipe)->vio_send(&(pipe)->link, buf, size, len)

#define VIO_SEND_TIMED(pipe, buf, size, timeout) \
    GET_VIO(pipe)->vio_send_timed(&(pipe)->link, buf, size, timeout)

#define VIO_RECV(pipe, buf, size, len, wait_event) \
    GET_VIO(pipe)->vio_recv(&(pipe)->link, buf, size, len, wait_event)

#define VIO_RECV_TIMED(pipe, buf, size, timeout) \
    GET_VIO(pipe)->vio_recv_timed(&(pipe)->link, buf, size, timeout)

#define VIO_WAIT(pipe, ev, timeout, ready) \
    GET_VIO(pipe)->vio_wait(&(pipe)->link, ev, timeout, ready)


static status_t cs_open_tcp_link(const char *host, uint16 port, cs_pipe_t *pipe, link_ready_ack_t *ack,
                                 const char *bind_host)
{
    tcp_link_t *link = NULL;
    bool32 ready = CM_FALSE;
    uint32 proto_code = CM_PROTO_CODE;
    uint8 local_endian;
    socket_attr_t sock_attr = {
        .connect_timeout = pipe->connect_timeout,
        .l_onoff = pipe->l_onoff,
        .l_linger = pipe->l_linger };

    link = &pipe->link.tcp;

    /* create socket */
    CM_RETURN_IFERR(cs_tcp_connect(host, port, link, bind_host, &sock_attr));
    LOG_RUN_INF("[MEC]after cs_tcp_connect to host %s port %u.", host, port);
    do {
        if (cs_tcp_send_timed(link, (char *)&proto_code, sizeof(proto_code), CM_NETWORK_IO_TIMEOUT) != CM_SUCCESS) {
            LOG_DEBUG_WAR("[MEC]cs_tcp_send_timed fail, proto_code=%u.", proto_code);
            break;
        }

        if (cs_tcp_wait(link, CS_WAIT_FOR_READ, pipe->connect_timeout, &ready) != CM_SUCCESS) {
            LOG_DEBUG_WAR("[MEC]cs_tcp_wait fail when cs_open_tcp_link.");
            break;
        }

        if (!ready) {
            LOG_DEBUG_WAR("[MEC]connect wait fail, not ready.");
            CM_THROW_ERROR(ERR_TCP_TIMEOUT, "connect wait for server response");
            break;
        }

        // read link_ready_ack
        if (cs_tcp_recv_timed(link, (char *)ack, sizeof(link_ready_ack_t), CM_NETWORK_IO_TIMEOUT) != CM_SUCCESS) {
            LOG_DEBUG_WAR("[MEC]cs_tcp_recv_timed fail, read ack timeout.");
            break;
        }

        // reverse if endian is different
        local_endian = (IS_BIG_ENDIAN ? (uint8)1 : (uint8)0);
        if (local_endian != ack->endian) {
            ack->flags = cs_reverse_int16(ack->flags);
            ack->version = cs_reverse_int32(ack->version);
            pipe->options |= CSO_DIFFERENT_ENDIAN;
        }
        LOG_RUN_INF("[MEC]cs_open_tcp_link success.");
        return CM_SUCCESS;
    } while (0);

    LOG_DEBUG_WAR("[MEC]cs_open_tcp_link fail.");
    /* close socket */
    (void)cs_close_socket(link->sock);
    link->sock = CS_INVALID_SOCKET;
    link->closed = CM_TRUE;
    return CM_ERROR;
}


/* URL SAMPLE:
TCP 192.168.1.10:1622, database_server1:1622
RDMA: RDMA@192.168.1.10:1622
IPC:/home/gsdb
UDS:/home/gsdb */
typedef struct st_server_info {
    cs_pipe_type_t type;
    char path[CM_FILE_NAME_BUFFER_SIZE]; /* host name(TCP) or home path(IPC) or domain socket file (uds) */
    uint16 port;
} server_info_t;

static status_t cs_parse_url(const char *url, server_info_t *server)
{
    text_t text, part1, part2;
    cm_str2text((char *)url, &text);
    (void)cm_split_rtext(&text, ':', '\0', &part1, &part2);

    server->type = CS_TYPE_TCP;
    CM_RETURN_IFERR(cm_text2str(&part1, server->path, CM_FILE_NAME_BUFFER_SIZE));
    if (!cm_is_short(&part2)) {
        CM_THROW_ERROR(ERR_INVALID_VALUE, "URL", url);
        return CM_ERROR;
    }

    if (cm_text2uint16(&part2, &server->port) != CM_SUCCESS) {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t cs_connect(const char *url, cs_pipe_t *pipe, const char *bind_host)
{
    link_ready_ack_t ack;
    server_info_t server;

    /* parse url and get pipe type */
    CM_RETURN_IFERR(cs_parse_url(url, &server));
    pipe->type = server.type;

    /* create socket to server */
    if (pipe->type == CS_TYPE_TCP) {
        CM_RETURN_IFERR(cs_open_tcp_link(server.path, server.port, pipe, &ack, bind_host));
    } else {
        CM_THROW_ERROR(ERR_PROTOCOL_NOT_SUPPORT);
        return CM_ERROR;
    }

    /* SSL before handshake since v9.0 */
    pipe->version = ack.version;
    return CM_SUCCESS;
}

void cs_disconnect(cs_pipe_t *pipe)
{
    if (pipe->type == CS_TYPE_TCP) {
        cs_tcp_disconnect(&pipe->link.tcp);
    }
    if (pipe->type == CS_TYPE_SSL) {
        cs_ssl_disconnect(&pipe->link.ssl);
    }
}

void cs_shutdown(cs_pipe_t *pipe)
{
    switch (pipe->type) {
        case CS_TYPE_TCP:
            cs_shutdown_socket(pipe->link.tcp.sock);
            break;
        case CS_TYPE_SSL:
            cs_shutdown_socket(pipe->link.ssl.tcp.sock);
            break;
        default:
            break;
    }
}

status_t cs_send_fixed_size(cs_pipe_t *pipe, char *buf, int32 size)
{
    bool32 ready;
    int32  send_size;
    int32  remain_size = size;
    char *send_buf = buf;
    int32 wait_interval = 0;

    if (VIO_SEND(pipe, send_buf, remain_size, &send_size) != CM_SUCCESS) {
        return CM_ERROR;
    }

    send_buf    += send_size;
    remain_size -= send_size;

    while (remain_size > 0) {
        if (cs_wait(pipe, CS_WAIT_FOR_WRITE, CM_POLL_WAIT, &ready) != CM_SUCCESS) {
            return CM_ERROR;
        }

        if (!ready) {
            wait_interval += CM_POLL_WAIT;
            if (wait_interval >= pipe->socket_timeout) {
                CM_THROW_ERROR(ERR_TCP_TIMEOUT, "send data");
                return CM_ERROR;
            }
            continue;
        }
        if (VIO_SEND(pipe, send_buf, remain_size, &send_size) != CM_SUCCESS) {
            return CM_ERROR;
        }

        send_buf    += send_size;
        remain_size -= send_size;
    }

    return CM_SUCCESS;
}

status_t cs_send_bytes(cs_pipe_t *pipe, const char *buf, uint32 size)
{
    return VIO_SEND_TIMED(pipe, buf, size, CM_NETWORK_IO_TIMEOUT);
}

status_t cs_read_bytes(cs_pipe_t *pipe, char *buf, uint32 max_size, int32 *size)
{
    uint32 wait_event;
    if (cs_wait(pipe, CS_WAIT_FOR_READ, CM_NETWORK_IO_TIMEOUT, NULL) != CM_SUCCESS) {
        return CM_ERROR;
    }

    return VIO_RECV(pipe, buf, max_size, size, &wait_event);
}

status_t cs_read_fixed_size(cs_pipe_t *pipe, char *buf, int32 size)
{
    bool32 ready;
    int32  read_size;
    uint32 wait_event;
    int32  remain_size = size;
    char *read_buf = buf;
    int32 wait_interval = 0;
    if (size == 0) {
        return CM_SUCCESS;
    }

    if (VIO_RECV(pipe, read_buf, remain_size, &read_size, &wait_event) != CM_SUCCESS) {
        return CM_ERROR;
    }

    read_buf    += read_size;
    remain_size -= read_size;

    while (remain_size > 0) {
        if (cs_wait(pipe, CS_WAIT_FOR_READ, CM_POLL_WAIT, &ready) != CM_SUCCESS) {
            return CM_ERROR;
        }

        if (!ready) {
            wait_interval += CM_POLL_WAIT;
            if (wait_interval >= pipe->socket_timeout) {
                CM_THROW_ERROR(ERR_TCP_TIMEOUT, "recv data");
                return CM_ERROR;
            }
            continue;
        }

        if (VIO_RECV(pipe, read_buf, remain_size, &read_size, &wait_event) != CM_SUCCESS) {
            return CM_ERROR;
        }

        read_buf    += read_size;
        remain_size -= read_size;
    }

    return CM_SUCCESS;
}

status_t cs_wait(cs_pipe_t *pipe, uint32 wait_for, int32 timeout, bool32 *ready)
{
    if (pipe->type == CS_TYPE_TCP) {
        return cs_tcp_wait(&pipe->link.tcp, wait_for, timeout, ready);
    }
    if (pipe->type == CS_TYPE_SSL) {
        return cs_ssl_wait(&pipe->link.ssl, wait_for, timeout, ready);
    }
    return CM_ERROR;
}


socket_t cs_get_socket_fd(const cs_pipe_t* pipe)
{
    if (pipe->type == CS_TYPE_TCP) {
        return pipe->link.tcp.sock;
    } else if (pipe->type == CS_TYPE_SSL) {
        return pipe->link.ssl.tcp.sock;
    } else {
        return CS_INVALID_SOCKET;
    }
}

status_t cs_ssl_accept(ssl_ctx_t *fd, cs_pipe_t *pipe)
{
    ssl_link_t *link = NULL;
    link = &pipe->link.ssl;
    link->ssl_ctx = fd;
    if (cs_ssl_accept_socket(link, pipe->link.tcp.sock, CM_SSL_IO_TIMEOUT) != CM_SUCCESS) {
        return CM_ERROR;
    }
    pipe->type = CS_TYPE_SSL;
    return CM_SUCCESS;
}

status_t cs_ssl_connect(ssl_ctx_t *fd, cs_pipe_t *pipe)
{
    ssl_link_t *link = NULL;
    link = &pipe->link.ssl;
    link->ssl_ctx = fd;
    if (cs_ssl_connect_socket(link, pipe->link.tcp.sock, CM_SSL_IO_TIMEOUT) != CM_SUCCESS) {
        return CM_ERROR;
    }
    pipe->type = CS_TYPE_SSL;
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
