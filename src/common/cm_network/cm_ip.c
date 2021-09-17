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
 * cm_ip.c
 *
 *
 * IDENTIFICATION
 *    src/common/cm_network/cm_ip.c
 *
 * -------------------------------------------------------------------------
 */
#ifndef WIN32
#include <netdb.h>
#include <net/if.h>
#else
#include <ws2tcpip.h>
#endif
#include "cm_ip.h"

static inline int32 cm_get_ip_version(const char *ip_str)
{
    const char *temp_ip = ip_str;

    // support IPV6 local-link
    if (strchr(temp_ip, '%') != NULL) {
        return AF_INET6;
    }

    // cidr or ip string
#define IP_CHARS "0123456789ABCDEFabcdef.:*/"
    if (strspn(temp_ip, IP_CHARS) != strlen(temp_ip)) {
        return -1;
    }

    while (*temp_ip != '\0') {
        if (*temp_ip == '.') {
            return AF_INET;
        }

        if (*temp_ip == ':') {
            return AF_INET6;
        }

        ++temp_ip;
    }

    return AF_INET;
}

static inline char *ipv6_local_link(const char *host, char *ip, uint32 ip_len)
{
    errno_t errcode;
    size_t host_len;

    int i = 0;

    while (host[i] && host[i] != '%') {
        i++;
    }

    if (host[i] == '\0') {
        return NULL;
    } else {  // handle local link
        host_len = (uint32)strlen(host);
        errcode = strncpy_s(ip, (size_t)ip_len, host, (size_t)host_len);
        if (SECUREC_UNLIKELY(errcode != EOK)) {
            CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return NULL;
        }

        ip[i] = '\0';
        return ip + i + 1;
    }
}

static inline status_t cm_ipport_to_sockaddr_ipv4(const char* host, int port, sock_addr_t* sock_addr)
{
    struct sockaddr_in *in4 = NULL;

    sock_addr->salen = sizeof(struct sockaddr_in);
    in4 = SOCKADDR_IN4(sock_addr);

    MEMS_RETURN_IFERR(memset_sp(in4, sizeof(struct sockaddr_in), 0, sizeof(struct sockaddr_in)));

    in4->sin_family = AF_INET;
    in4->sin_port = htons(port);
#ifndef WIN32
    in4->sin_addr.s_addr = inet_addr(host);
        // Upon successful completion, inet_addr() shall return the Internet address.
        // Otherwise, it shall return (in_addr_t)(-1).
        if (in4->sin_addr.s_addr == (in_addr_t)(-1) ||
            (inet_pton(AF_INET, host, &in4->sin_addr.s_addr) != 1)) {
#else
// If no error occurs, the InetPton function returns a value of 1.
    if (InetPton(AF_INET, host, &in4->sin_addr.s_addr) != 1) {
#endif
        CM_THROW_ERROR_EX(ERR_TCP_INVALID_IPADDRESS, "%s", host);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static inline status_t cm_ipport_to_sockaddr_ipv6(const char* host, int port, sock_addr_t* sock_addr)
{
    struct sockaddr_in6 *in6 = NULL;
#ifndef WIN32
    char ip[CM_MAX_IP_LEN];
        char *scope = NULL;
#endif

    sock_addr->salen = sizeof(struct sockaddr_in6);
    in6 = SOCKADDR_IN6(sock_addr);

    MEMS_RETURN_IFERR(memset_sp(in6, sizeof(struct sockaddr_in6), 0, sizeof(struct sockaddr_in6)));

    in6->sin6_family = AF_INET6;
    in6->sin6_port = htons(port);

#ifndef WIN32
    scope = ipv6_local_link(host, ip, CM_MAX_IP_LEN);
        if (scope != NULL) {
            in6->sin6_scope_id = if_nametoindex(scope);
            if (in6->sin6_scope_id == 0) {
                CM_THROW_ERROR_EX(ERR_TCP_INVALID_IPADDRESS, "invalid local link \"%s\"", scope);
                return CM_ERROR;
            }

            host = ip;
        }
        // The inet_pton() function shall return 1 if the conversion succeeds
        if (inet_pton(AF_INET6, host, &in6->sin6_addr) != 1) {
#else
// If no error occurs, the InetPton function returns a value of 1.
    if (InetPton(AF_INET6, host, &in6->sin6_addr) != 1) {
#endif
        CM_THROW_ERROR_EX(ERR_TCP_INVALID_IPADDRESS, "%s", host);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t cm_ipport_to_sockaddr(const char *host, int port, sock_addr_t *sock_addr)
{
    int sa_family = cm_get_ip_version(host);
    switch (sa_family) {
        case AF_INET: {
            return cm_ipport_to_sockaddr_ipv4(host, port, sock_addr);
        }
        case AF_INET6: {
            return cm_ipport_to_sockaddr_ipv6(host, port, sock_addr);
        }
        default: {
            CM_THROW_ERROR_EX(ERR_TCP_INVALID_IPADDRESS, "%s", host);
            return CM_ERROR;
        }
    }
}

status_t cm_ip_to_sockaddr(const char *host, sock_addr_t *sock_addr)
{
#define INVALID_PORT 0
    return cm_ipport_to_sockaddr(host, INVALID_PORT, sock_addr);
}

bool32 cm_check_ip_valid(const char *ip)
{
    sock_addr_t sock_addr;

    if (cm_ip_to_sockaddr(ip, &sock_addr) != CM_SUCCESS) {
        return CM_FALSE;
    }

    return CM_TRUE;
}

