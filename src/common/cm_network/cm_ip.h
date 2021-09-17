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
 * cm_ip.h
 *
 *
 * IDENTIFICATION
 *    src/common/cm_network/cm_ip.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_IP_H__
#define __CM_IP_H__

#include "cm_defs.h"
#include "cm_error.h"
#include "cm_text.h"

#ifndef WIN32
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#else
#include <winsock2.h>
#include <mstcpip.h>
#include <Ws2tcpip.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_sock_addr {
    struct sockaddr_storage addr;
    socklen_t salen;
} sock_addr_t;

// sa: sock_addr_t
#define SOCKADDR(sa)        ((struct sockaddr *)&(sa)->addr)
#define SOCKADDR_IN4(sa)    ((struct sockaddr_in *)&(sa)->addr)
#define SOCKADDR_IN6(sa)    ((struct sockaddr_in6 *)&(sa)->addr)
#define SOCKADDR_FAMILY(sa) (SOCKADDR(sa)->sa_family)
#define SOCKADDR_PORT(sa)   (SOCKADDR_FAMILY(sa) == AF_INET ? SOCKADDR_IN4(sa)->sin_port : SOCKADDR_IN6(sa)->sin6_port)


static inline const char *cm_inet_ntop(struct sockaddr *addr, char *buffer, int size)
{
    errno_t errcode = 0;
    void *sin_addr = (addr->sa_family == AF_INET6) ?
                     (void *)&((struct sockaddr_in6 *)addr)->sin6_addr :
                     (void *)&((struct sockaddr_in *)addr)->sin_addr;

    buffer[0] = '\0';
    if (inet_ntop(addr->sa_family, sin_addr, buffer, (size_t)size) == NULL) {
        errcode = strncpy_s(buffer, size, "0.0.0.0", sizeof("0.0.0.0") - 1);
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return NULL;
        }
    }

    return buffer;
}

static inline bool32 cm_is_lookback_ip(const char *client_ip)
{
    if (cm_str_equal(client_ip, "127.0.0.1") ||
        cm_str_equal(client_ip, "::1") ||
        cm_str_equal(client_ip, "::ffff:127.0.0.1")) {
        return CM_TRUE;
    }
    return CM_FALSE;
}

static inline bool32 cm_is_equal_ip(const char *client_ip, const char *local_ip)
{
    // IPV6 PREFIX FOR IPV4 ADDR
#define IPV6_PREFIX         "::ffff:"
#define IPV6_PREFIX_LEN     7
#define HAS_IPV6_PREFIX(ip) ((strlen(ip) > IPV6_PREFIX_LEN) && memcmp((ip), IPV6_PREFIX, IPV6_PREFIX_LEN) == 0)
    if (cm_str_equal_ins(client_ip, local_ip) ||
        (HAS_IPV6_PREFIX(client_ip) && cm_str_equal_ins(client_ip + IPV6_PREFIX_LEN, local_ip))) {
        return CM_TRUE;
    }
    return CM_FALSE;
}


status_t cm_ipport_to_sockaddr(const char *host, int port, sock_addr_t *sock_addr);
status_t cm_ip_to_sockaddr(const char *host, sock_addr_t *sock_addr);
bool32 cm_check_ip_valid(const char *ip);


#ifdef __cplusplus
}
#endif

#endif

