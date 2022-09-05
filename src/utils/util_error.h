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
 * util_error.h
 *
 *
 * IDENTIFICATION
 *    src/utils/util_error.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __UTIL_ERROR__
#define __UTIL_ERROR__
#include "cm_error.h"
#include "cm_text.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @Note
 *   Attention1: add error code to the corresponding range
 *
 *   ERROR                                  |   RANGE
 *   network errors                         |   500 - 599
 *   replication errors                     |   600 - 699
 *   storage errors                         |   700 - 799
 *   configuration errors                   |   800 - 899
 */
typedef enum en_dcf_errno {
    ERR_DCF_BASE = CM_BASE_ERROR_COUNT,

    /* network errors: 500 - 599 */
    DCF_ERRNO_NETWORK_BEGIN      = 500,
    ERR_INIT_NETWORK_ENV         = 500,
    ERR_ESTABLISH_TCP_CONNECTION = 501,
    ERR_PEER_CLOSED              = 502,
    ERR_TCP_TIMEOUT              = 503,
    ERR_CREATE_SOCKET            = 504,
    ERR_SET_SOCKET_OPTION        = 505,
    ERR_TCP_PORT_CONFLICTED      = 506,
    ERR_SOCKET_BIND              = 507,
    ERR_SOCKET_LISTEN            = 508,
    ERR_INVALID_PROTOCOL         = 509,
    ERR_SOCKET_TIMEOUT           = 510,
    ERR_TCP_RECV                 = 511,
    ERR_PACKET_READ              = 512,
    ERR_IPADDRESS_NUM_EXCEED     = 513,
    ERR_PEER_CLOSED_REASON       = 514,
    ERR_PACKET_SEND              = 515,
    ERR_PROTOCOL_NOT_SUPPORT     = 516,
    ERR_MEC_INIT_FAIL            = 517,
    ERR_MEC_CREATE_AREA          = 518,
    ERR_MEC_CREATE_SOCKET        = 519,
    ERR_MEC_INVALID_CMD          = 520,
    ERR_MEC_RECV_FAILED          = 521,
    ERR_MEC_CREATE_MUTEX         = 522,
    ERR_MEC_ILEGAL_MESSAGE       = 523,
    ERR_MEC_PARAMETER            = 524,
    ERR_MEC_ALREADY_CONNECT      = 525,
    ERR_MEC_SEND_FAILED          = 526,
    ERR_MEC_FRAGMENT_THRESHOLD   = 527,
    ERR_MEC_INCONSISTENT_FRAG_NO = 528,
    ERR_SSL_INIT_FAILED          = 529,
    ERR_SSL_RECV_FAILED          = 530,
    ERR_SSL_VERIFY_CERT          = 531,
    ERR_SSL_CONNECT_FAILED       = 532,
    ERR_SSL_FILE_PERMISSION      = 533,
    ERR_COMPRESS_INIT_ERROR      = 534,
    ERR_COMPRESS_ERROR           = 535,
    ERR_DECOMPRESS_ERROR         = 536,
    ERR_COMPRESS_FREE_ERROR      = 537,
    // need update DCF_ERRNO_NETWORK_END after add new ERRNO
    DCF_ERRNO_NETWORK_END        = ERR_COMPRESS_FREE_ERROR + 1,
    /* replication errors: 600 - 699 */
    DCF_ERRNO_REP_BEGIN          = 600,
    ERR_TERM_IS_NOT_MATCH	     = 600,
    ERR_TERM_IS_EXPIRED		     = 601,
    ERR_APPEN_LOG_REQ_LOST       = 602,
    ERR_ROLE_NOT_LEADER          = 603,
    // need update DCF_ERRNO_REP_END after add new ERRNO
    DCF_ERRNO_REP_END            = ERR_ROLE_NOT_LEADER + 1,
    /* storage errors: 700 - 799 */
    DCF_ERRNO_STG_BEGIN         = 700,
    ERR_APPEND_ENTRY_FAILED     = 700,
    ERR_INDEX_NOT_CONTIGUOUS    = 701,
    ERR_INDEX_BEFORE_APPLIED    = 702,
    ERR_ADD_CACHE_FAILED        = 703,
    ERR_ADD_QUEUE_FAILED        = 704,
    ERR_STG_INTERNAL_ERROR      = 705,
    ERR_STG_MEM_POOL_FULL       = 706,
    // need update DCF_ERRNO_STG_END after add new ERRNO
    DCF_ERRNO_STG_END           = ERR_STG_MEM_POOL_FULL + 1,
    /* configuration errors: 800 - 899 */
    DCF_ERRNO_CFG_BEGIN        = 800,
    ERR_PARSE_CFG_STR          = 800,
    ERR_QUERY_DCF_INFO_ERR     = 801,
    DCF_ERRNO_CFG_END          = ERR_QUERY_DCF_INFO_ERR + 1,

    ERR_DCF_CEIL = CM_ERROR_COUNT,
}dcf_errno_t;

void init_dcf_errno_desc(void);
bool32 is_dcf_errno_msg_defined(int errnum);

#ifdef __cplusplus
}
#endif

#endif