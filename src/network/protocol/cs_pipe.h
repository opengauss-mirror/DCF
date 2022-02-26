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
 * cs_pipe.h
 *    protocol process
 *
 * IDENTIFICATION
 *    src/network/protocol/cs_pipe.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CS_PIPE_H__
#define __CS_PIPE_H__

#include "cm_defs.h"
#include "cm_binary.h"
#include "cs_tcp.h"
#include "cs_packet.h"
#include "cs_ssl.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_cs_pipe_type {
    CS_TYPE_NONE = 0,
    CS_TYPE_TCP = 1,
    CS_TYPE_SSL = 2,
    CS_TYPE_CEIL
} cs_pipe_type_t;

typedef union un_cs_link {
    tcp_link_t tcp;
    ssl_link_t ssl;
    // other links can be added later
} cs_link_t;

typedef struct st_cs_pipe {
    cs_pipe_type_t type;
    cs_link_t link;
    uint32 options;
    uint32 version;
    int32 connect_timeout;  // ms
    int32 socket_timeout;   // ms
    int32 l_onoff;
    int32 l_linger;
} cs_pipe_t;

typedef struct st_link_ready_ack {
    uint32 version;
    uint16 flags;
    uint8 endian;
    uint8 reserved;
} link_ready_ack_t;

extern const text_t g_pipe_type_names[CS_TYPE_CEIL];

status_t cs_connect(const char *url, cs_pipe_t *pipe, const char *bind_host);
void     cs_disconnect(cs_pipe_t *pipe);
void     cs_shutdown(cs_pipe_t *pipe);
status_t cs_wait(cs_pipe_t *pipe, uint32 wait_for, int32 timeout, bool32 *ready);
status_t cs_read_bytes(cs_pipe_t *pipe, char *buf, uint32 max_size, int32 *size);
status_t cs_read_fixed_size(cs_pipe_t *pipe, char *buf, int32 size);
status_t cs_send_fixed_size(cs_pipe_t *pipe, char *buf, int32 size);
status_t cs_send_bytes(cs_pipe_t *pipe, const char *buf, uint32 size);
socket_t cs_get_socket_fd(const cs_pipe_t *pipe);

/* This function build SSL channel using a accepted socket */
status_t cs_ssl_accept(ssl_ctx_t *fd, cs_pipe_t *pipe);
/* This function build SSL channel using a connected socket */
status_t cs_ssl_connect(ssl_ctx_t *fd, cs_pipe_t *pipe);

#ifdef __cplusplus
}
#endif

#endif
