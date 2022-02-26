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
 * mec.h
 *    mec process
 *
 * IDENTIFICATION
 *    src/network/mec.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __MEC_H__
#define __MEC_H__

#include "cm_defs.h"
#include "cm_text.h"
#include "metadata.h"


#ifdef __cplusplus
extern "C" {
#endif


typedef struct st_mec_message_head {
    uint8      cmd;       // command
    uint8      flags;
    uint16     batch_size; // batch size
    uint32     src_inst;  // from instance
    uint32     dst_inst;  // to instance
    uint32     stream_id;   // stream id
    uint32     size;
    uint32     serial_no;
    uint32     frag_no;
    uint32     version;
    uint64     time1;
    uint64     time2;
    uint64     time3;
} mec_message_head_t;

typedef struct st_mec_message {
    mec_message_head_t *head;
    char               *buffer;
    uint32              buf_size;
    uint32              aclt_size;
    uint32              offset;   // for reading
    uint32              options;  // options
} mec_message_t;


typedef enum en_mec_command {
    // normal cmd:
    MEC_CMD_CONNECT                = 0,
    MEC_CMD_HEALTH_CHECK_HIGH      = 1,
    MEC_CMD_HEALTH_CHECK_LOW       = 2,
    MEC_CMD_APPEND_LOG_RPC_REQ     = 3,
    MEC_CMD_APPEND_LOG_RPC_ACK     = 4,
    MEC_CMD_VOTE_REQUEST_RPC_REQ   = 5,
    MEC_CMD_VOTE_REQUEST_RPC_ACK   = 6,
    MEC_CMD_GET_COMMIT_INDEX_REQ   = 7,
    MEC_CMD_GET_COMMIT_INDEX_ACK   = 8,
    MEC_CMD_PROMOTE_LEADER_RPC_REQ = 9,
    MEC_CMD_BLOCK_NODE_RPC_REQ     = 10,
    MEC_CMD_BLOCK_NODE_RPC_ACK     = 11,
    MEC_CMD_SEND_COMMON_MSG        = 12,
    MEC_CMD_CHANGE_MEMBER_RPC_REQ  = 13,
    MEC_CMD_UNIVERSAL_WRITE_REQ    = 14,
    MEC_CMD_UNIVERSAL_WRITE_ACK    = 15,
    MEC_CMD_STATUS_CHECK_RPC_REQ   = 16,
    MEC_CMD_STATUS_CHECK_RPC_ACK   = 17,

    MEC_CMD_NORMAL_CEIL, // please add normal cmd before this

    // test cmd:
    MEC_CMD_TEST_REQ  = MEC_CMD_NORMAL_CEIL + 1,
    MEC_CMD_TEST_ACK  = MEC_CMD_NORMAL_CEIL + 2,
    MEC_CMD_TEST1_REQ = MEC_CMD_NORMAL_CEIL + 3,
    MEC_CMD_TEST1_ACK = MEC_CMD_NORMAL_CEIL + 4,
    MEC_CMD_BRD_TEST  = MEC_CMD_NORMAL_CEIL + 5,

    MEC_CMD_CEIL,
} mec_command_t;


typedef enum en_mec_type {
    TYPE_INT64,
    TYPE_INT32,
    TYPE_INT16,
    TYPE_DOUBLE,
    TYPE_BINARY,
} mec_type_t;


typedef enum en_msg_priv {
    PRIV_HIGH = 0, // high priority message
    PRIV_LOW  = 1, // low priority message
    PRIV_CEIL,
} msg_priv_t;

typedef status_t(*msg_proc_t)(mec_message_t *pack);
void register_msg_process(mec_command_t cmd, msg_proc_t proc, msg_priv_t priv);
void unregister_msg_process(mec_command_t cmd);


#define INST_STEP (sizeof(uint64) * 8)
#define INSTS_BIT_SZ ((CM_MAX_NODE_COUNT - 1) / INST_STEP + 1)

#define MEC_SET_BRD_INST(bits, id) CM_BIT_SET((bits)[(id) / INST_STEP], CM_GET_MASK((id) % INST_STEP))
#define MEC_RESET_BRD_INST(bits, id) CM_BIT_RESET((bits)[(id) / INST_STEP], CM_GET_MASK((id) % INST_STEP))
#define MEC_IS_INST_SEND(bits, id) CM_BIT_TEST((bits)[(id) / INST_STEP], CM_GET_MASK((id) % INST_STEP))
#define MEC_INST_SENT_SUCCESS(bits, id) ((bits)[(id) / INST_STEP] |= ((uint64)0x1 << ((id) % INST_STEP)))

/* in broadcast scenary, dst_inst must be CM_INVALID_NODE_ID */
status_t mec_alloc_pack(mec_message_t *pack, mec_command_t cmd, uint32 src_inst, uint32 dst_inst, uint32 stream_id);
status_t mec_init();
void     mec_deinit();
status_t mec_send_data(mec_message_t *pack);
/* pack memory released by mec_broadcast itself, invoker no need to care */
void mec_broadcast(uint32 stream_id, uint64 inst_bits[INSTS_BIT_SZ], mec_message_t *pack,
    uint64 success_bits[INSTS_BIT_SZ]);
void mec_release_pack(mec_message_t *pack);


status_t mec_put_int64(mec_message_t *pack, uint64 value);
status_t mec_put_int32(mec_message_t *pack, uint32 value);
status_t mec_put_int16(mec_message_t *pack, uint16 value);
status_t mec_put_double(mec_message_t *pack, double value);
status_t mec_put_bin(mec_message_t *pack, uint32 size, const void *buffer);

status_t mec_get_int64(mec_message_t *pack, int64 *value);
status_t mec_get_int32(mec_message_t *pack, int32 *value);
status_t mec_register_decrypt_pwd(usr_cb_decrypt_pwd_t cb_func);

/* need keep 4-byte align by the caller */
status_t mec_get_int16(mec_message_t *pack, int16 *value);

status_t mec_get_double(mec_message_t *pack, double *value);
status_t mec_get_bin(mec_message_t *pack, uint32 *size, void **buffer);
uint32 mec_get_send_que_count(msg_priv_t priv);
uint32 mec_get_recv_que_count(msg_priv_t priv);
int64 mec_get_send_mem_capacity(msg_priv_t priv);
int64 mec_get_recv_mem_capacity(msg_priv_t priv);
bool32 mec_check_all_connect();
bool32 mec_is_ready(uint32 stream_id, uint32 dst_inst, msg_priv_t priv);
status_t mec_get_peer_version(uint32 stream_id, uint32 dst_inst, uint32 *peer_version);
static inline uint32 mec_get_recv_pack_version(const mec_message_t *pack)
{
    return pack->head->version;
}

uint32 mec_get_write_pos(const mec_message_t *pack);
void mec_modify_int64(mec_message_t *pack, uint32 pos, uint64 value);

#ifdef __cplusplus
}
#endif


#endif
