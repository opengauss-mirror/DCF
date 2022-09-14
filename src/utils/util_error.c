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
 * util_error.c
 *
 *
 * IDENTIFICATION
 *    src/utils/util_error.c
 *
 * -------------------------------------------------------------------------
 */


#include "util_error.h"


#ifdef __cplusplus
extern "C" {
#endif

static const char *dcf_error_desc[CM_ERROR_COUNT] = {
    // network errors 500~599
    [ERR_INIT_NETWORK_ENV]         = "Init network env failed, %s",
    [ERR_ESTABLISH_TCP_CONNECTION] = "Failed to establish tcp connection to [%s]:[%u], errno %d",
    [ERR_PEER_CLOSED]              = "%s connection is closed",
    [ERR_TCP_TIMEOUT]              = "%s timeout",
    [ERR_CREATE_SOCKET]            = "Failed to create new socket, errno %d",
    [ERR_SET_SOCKET_OPTION]        = "Failed to set SO_REUSEADDR option for listener socket",
    [ERR_TCP_PORT_CONFLICTED]      = "Tcp port conflict %s:%u",
    [ERR_SOCKET_BIND]              = "Failed to bind socket for %s:%u, error code %d",
    [ERR_SOCKET_LISTEN]            = "Failed to %s, error code %d",
    [ERR_INVALID_PROTOCOL]         = "Invalid protocol %s",
    [ERR_SOCKET_TIMEOUT]           = "Socket wait timeout, timeout=[%ds]",
    [ERR_TCP_RECV]                 = "Failed to recv from %s pipe, errno %d",
    [ERR_PACKET_READ]              = "Receive packet has no more data to read, packet size: %u, offset: %u, read: %u",
    [ERR_IPADDRESS_NUM_EXCEED]     = "Number of IP address exceeds the maximum(%u)",
    [ERR_PEER_CLOSED_REASON]       = "%s connection is closed, reason: %d",
    [ERR_PACKET_SEND]              = "Send packet has no more space to put data, "
                                     "buff size: %u, head size: %u, put size: %u",
    [ERR_PROTOCOL_NOT_SUPPORT]     = "Protocol not supported",
    [ERR_MEC_INIT_FAIL]            = "MEC init failed, %s.",
    [ERR_MEC_CREATE_AREA]          = "MEC create mes area failed, %s",
    [ERR_MEC_CREATE_SOCKET]        = "MEC create socket failed.",
    [ERR_MEC_INVALID_CMD]          = "MEC invalid mes command, %s",
    [ERR_MEC_RECV_FAILED]          = "MEC recv failed, %s",
    [ERR_MEC_CREATE_MUTEX]         = "MEC create mutex failed, %s",
    [ERR_MEC_ILEGAL_MESSAGE]       = "MEC invalid message, %s",
    [ERR_MEC_PARAMETER]            = "MEC invalid parameter, %s",
    [ERR_MEC_ALREADY_CONNECT]      = "MEC has already connected before, %s",
    [ERR_MEC_SEND_FAILED]          = "MEC send package failed, %s",
    [ERR_MEC_FRAGMENT_THRESHOLD]   = "MEC fragment ctrl number limit %u reached",
    [ERR_MEC_INCONSISTENT_FRAG_NO] = "MEC last fragment number [%d] is not consistent with new [%d]",
    [ERR_SSL_INIT_FAILED]          = "SSL init error: %s",
    [ERR_SSL_RECV_FAILED]          = "Failed to recv from ssl pipe, sslerr: %d, errno: %d, errmsg: %s",
    [ERR_SSL_VERIFY_CERT]          = "Failed to verify SSL certificate, reason %s",
    [ERR_SSL_CONNECT_FAILED]       = "The SSL connection failed, %s",
    [ERR_SSL_FILE_PERMISSION]      = "SSL certificate file \"%s\" has execute, group or world access permission",
    [ERR_COMPRESS_INIT_ERROR]      = "%s failed to init stream context, errno=%d, %s",
    [ERR_COMPRESS_ERROR]           = "%s failed to compress, errno=%d, %s",
    [ERR_DECOMPRESS_ERROR]         = "%s failed to decompress, errno=%d, %s",
    [ERR_COMPRESS_FREE_ERROR]      = "%s failed to free stream context, errno=%d, %s",
    /* replication errors: 600 - 699 */
    [ERR_TERM_IS_NOT_MATCH]	       = "Term is not matched",
    [ERR_TERM_IS_EXPIRED]		   = "Term is expired",
    [ERR_APPEN_LOG_REQ_LOST]       = "Append log request is lost",
    [ERR_ROLE_NOT_LEADER]          = "Current node is not leader",
    /* storage errors: 700 - 799 */
    [ERR_APPEND_ENTRY_FAILED]     = "Failed to append entry",
    [ERR_INDEX_NOT_CONTIGUOUS]    = "Index is not contiguous",
    [ERR_INDEX_BEFORE_APPLIED]    = "Index is before applied",
    [ERR_ADD_CACHE_FAILED]        = "Failed to add cache",
    [ERR_ADD_QUEUE_FAILED]        = "Failed to add queue",
    [ERR_STG_INTERNAL_ERROR]      = "Storage internal error",
    [ERR_STG_MEM_POOL_FULL]       = "Storage memory pool is full",
    /* configuration errors: 800 - 899 */
    [ERR_PARSE_CFG_STR]           = "Failed to parse dcf_config, the cfg_str is %s",
    [ERR_QUERY_DCF_INFO_ERR]      = "Failed to query dcf info, %s, errno=%d",
};

void init_dcf_errno_desc(void)
{
    for (int i = DCF_ERRNO_NETWORK_BEGIN; i < DCF_ERRNO_NETWORK_END; i++) {
        cm_register_error(i, dcf_error_desc[i]);
    }
    for (int i = DCF_ERRNO_REP_BEGIN; i < DCF_ERRNO_REP_END; i++) {
        cm_register_error(i, dcf_error_desc[i]);
    }
    for (int i = DCF_ERRNO_STG_BEGIN; i < DCF_ERRNO_STG_END; i++) {
        cm_register_error(i, dcf_error_desc[i]);
    }
    for (int i = DCF_ERRNO_CFG_BEGIN; i < DCF_ERRNO_CFG_END; i++) {
        cm_register_error(i, dcf_error_desc[i]);
    }
}

bool32 is_dcf_errno_msg_defined(int errnum)
{
    if (errnum >= (int)CM_ERROR_COUNT || errnum < 0) {
        return CM_FALSE;
    }
    if (CM_IS_EMPTY_STR(dcf_error_desc[errnum])) {
        return CM_FALSE;
    }
    return CM_TRUE;
}

#ifdef __cplusplus
}
#endif
