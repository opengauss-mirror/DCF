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
 * cs_packet.h
 *    protocol process
 *
 * IDENTIFICATION
 *    src/network/protocol/cs_packet.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __GS_PACK_H__
#define __GS_PACK_H__
#include "cm_base.h"
#ifndef WIN32
#include <string.h>
#endif

#include "cm_defs.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef enum en_cs_minor_version {
    MIN_VERSION_0 = 0,
} cs_minor_version_t;

typedef enum en_cs_major_version {
    MJR_VERSION_0 = 0,
} cs_major_version_t;


#define CS_PROTOCOL_MAJOR(v)    ((v) >> 16)
#define CS_PROTOCOL_MINOR(v)    ((v) & 0x0000ffff)
#define CS_PROTOCOL(m, n)        (((m) << 16) | (n))


#define CS_LOCAL_VERSION (uint32) CS_PROTOCOL(MJR_VERSION_0, MIN_VERSION_0)

#define CS_CMD_UNKONOW       (uint8)0
#define CS_CMD_HANDSHAKE     (uint8)1 /* process before login, added since v2.0; for SSL only since v9.0 */
#define CS_CMD_AUTH_INIT     (uint8)2 /* request for user auth info, added since v9.0 */
#define CS_CMD_LOGIN         (uint8)3
#define CS_CMD_LOGOUT        (uint8)4
#define CS_CMD_CEIL          (uint8)5 /* the ceil of cmd */


/* every option use one bit of flags in cs_packet_head_t */
#define CS_FLAG_NONE                 0x0000
#define CS_FLAG_MORE_DATA            0x0001  // continue to recv more data
#define CS_FLAG_END_DATA             0x0002  // end to last packet
#define CS_FLAG_PEER_CLOSED          0x0004
#define CS_FLAG_COMPRESS             0x0008
#define CS_FLAG_PRIV_LOW             0x0010
#define CS_FLAG_BATCH                0x0020

#define CS_ALIGN_SIZE     4

#define CS_WAIT_FOR_READ  1
#define CS_WAIT_FOR_WRITE 2

typedef enum en_cs_option {
    CSO_DIFFERENT_ENDIAN = 0x00000001,
    CSO_BUFF_IN_QUEUE    = 0x00000002,
} cs_option_t;

#define CS_DIFFERENT_ENDIAN(options) ((options) & CSO_DIFFERENT_ENDIAN)
#define CS_MORE_DATA(flag) ((flag) & CS_FLAG_MORE_DATA)
#define CS_END_DATA(flag) ((flag) & CS_FLAG_END_DATA)

#define CS_COMPRESS(flag) ((flag) & CS_FLAG_COMPRESS)
#define CS_PRIV_LOW(flag) ((flag) & CS_FLAG_PRIV_LOW)
#define CS_BATCH(flag) ((flag) & CS_FLAG_BATCH)

static inline uint32 cs_reverse_int32(uint32 value)
{
    uint32 result;
    uint8 *v_bytes = (uint8 *)&value;
    uint8 *r_bytes = (uint8 *)&result;
    r_bytes[0] = v_bytes[3];
    r_bytes[1] = v_bytes[2];
    r_bytes[2] = v_bytes[1];
    r_bytes[3] = v_bytes[0];
    return result;
}

static inline uint32 cs_reverse_uint32(uint32 value)
{
    return cs_reverse_int32(value);
}

static inline uint16 cs_reverse_int16(uint16 value)
{
    uint16 result;
    uint8 *v_bytes = (uint8 *)&value;
    uint8 *r_bytes = (uint8 *)&result;
    r_bytes[0] = v_bytes[1];
    r_bytes[1] = v_bytes[0];
    return result;
}

static inline uint64 cs_reverse_int64(uint64 value)
{
    uint64 result;
    uint32 *v_int32, *r_int32;

    v_int32 = (uint32 *)&value;
    r_int32 = (uint32 *)&result;
    r_int32[1] = cs_reverse_int32(v_int32[0]);
    r_int32[0] = cs_reverse_int32(v_int32[1]);
    return result;
}

static inline double cs_reverse_real(double value)
{
    double tmp_value, result;
    uint16 *v_int16 = (uint16 *)&value;
    uint16 *tmp_int16 = (uint16 *)&tmp_value;
    uint16 *r_int16 = (uint16 *)&result;
    uint32 *tmp_int32 = (uint32 *)&tmp_value;

    tmp_int16[0] = v_int16[0];
    tmp_int16[1] = v_int16[3];
    tmp_int16[2] = v_int16[1];
    tmp_int16[3] = v_int16[2];

    tmp_int32[0] = cs_reverse_int32(tmp_int32[0]);
    tmp_int32[1] = cs_reverse_int32(tmp_int32[1]);

    r_int16[0] = tmp_int16[0];
    r_int16[3] = tmp_int16[1];
    r_int16[1] = tmp_int16[2];
    r_int16[2] = tmp_int16[3];

    return result;
}

#ifdef __cplusplus
}
#endif

#endif
