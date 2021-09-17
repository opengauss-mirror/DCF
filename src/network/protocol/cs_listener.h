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
 * cs_listener.h
 *    protocol process
 *
 * IDENTIFICATION
 *    src/network/protocol/cs_listener.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CS_LISTENER_H__
#define __CS_LISTENER_H__

#include "cm_defs.h"
#include "cm_thread.h"
#include "cm_spinlock.h"
#include "cs_tcp.h"
#include "cs_pipe.h"
#include "util_error.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CS_SOCKET_SLOT_USED  (CS_INVALID_SOCKET - 1)

typedef enum en_lsnr_type {
    LSNR_TYPE_MES,
    LSNR_TYPE_ALL,
} lsnr_type_t;

typedef enum en_lsnr_status {
    LSNR_STATUS_RUNNING,
    LSNR_STATUS_PAUSING,
    LSNR_STATUS_PAUSED,
    LSNR_STATUS_STOPPED,
} lsnr_status_t;

typedef struct st_tcp_lsnr tcp_lsnr_t;
typedef status_t (*connect_action_t)(tcp_lsnr_t *lsnr, cs_pipe_t *pipe);

typedef struct st_tcp_lsnr {
    spinlock_t lock;
    lsnr_type_t type;
    lsnr_status_t status;
    char host[CM_MAX_LSNR_HOST_COUNT][CM_MAX_IP_LEN];
    uint16 port;
    int epoll_fd;       // for listened sockets
    atomic_t sock_count;  // may listen on multiple IP address
    socket_t socks[CM_MAX_LSNR_HOST_COUNT];
    thread_t thread;
    connect_action_t action;  // action when a connect accepted
} tcp_lsnr_t;

status_t cs_start_tcp_lsnr(tcp_lsnr_t *lsnr, connect_action_t action);
void cs_stop_tcp_lsnr(tcp_lsnr_t *lsnr);

status_t cs_create_lsnr_socks(tcp_lsnr_t *lsnr);
status_t cs_lsnr_init_epoll_fd(tcp_lsnr_t *lsnr);
void cs_close_lsnr_socks(tcp_lsnr_t *lsnr);
void cs_try_tcp_accept(tcp_lsnr_t *lsnr, cs_pipe_t *pipe);
void cs_pause_tcp_lsnr(tcp_lsnr_t *lsnr);

#ifdef __cplusplus
}
#endif

#endif
