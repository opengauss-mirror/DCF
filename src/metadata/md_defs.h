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
 * md_defs.h
 *    metadata process
 *
 * IDENTIFICATION
 *    src/metadata/md_defs.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __MD_DEFS_H__
#define __MD_DEFS_H__

#include "cm_types.h"
#include "util_error.h"
#include "cm_defs.h"
#include "cm_log.h"
#include "cm_latch.h"
#include "cm_list.h"
#include "util_defs.h"
#include "cm_cipher.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CM_MAX_STREAM_COUNT  64
#define CM_MAX_NODE_COUNT    256
#define CM_MAX_NODE_PER_STREAM    32
#define CM_MAX_MSG_TIMEOUT 600000   // 10min
#define CM_MAX_GROUP_COUNT    128

#define CM_INVALID_NODE_ID   0
#define CM_NODE_ID_ALL       0xFFFFFFFF

#define CM_INVALID_STREAM_ID 0
#define CM_INVALID_TERM_ID   0
#define CM_INVALID_INDEX_ID  0
#define CM_MAX_ELC_INIT_WAIT_TIMES (20)

#define CM_MD_MISMATCH_REP_INTERVAL 5000 // ms

#define CM_DEFAULT_ELC_TIMEOUT 3000 // ms
#define CM_DEFAULT_ELC_PRIORITY 0
#define CM_DEFAULT_HB_INTERVAL 1000 // ms
#define CM_DEFAULT_ELC_SWITCH_THD 0

#define CM_DEFAULT_CPU_THRESHOLD 100 // unit (%)
#define CM_MAX_CPU_THRESHOLD 100 // unit (%)

#define CM_DEFAULT_NET_QUEUE_MESS_NUM 1024
#define CM_DEFAULT_DISK_RAWAIT_THRESHOLD 100000   // unit (us) 100ms
#define CM_MAX_DISK_RAWAIT_THRESHOLD 600000000   // unit (us) 10min

#define CM_SSL_NOTI_TIME_MIN   7
#define CM_SSL_NOTI_TIME_MAX   180
#define CM_MIN_ELC_TIMEOUT     1   // s
#define CM_MAX_ELC_TIMEOUT     600 // s
#define CM_ELC_NORS_WEIGHT     1
#define CM_DEFAULT_GROUP_ID    0
#define CM_INVALID_GROUP_ID    (uint32)(0xFFFFFFFF)

#define SPLIT_CHR_LOG_LEVEL '|'

#define CM_METADATA_DEF_MAX_LEN (100 * (CM_MAX_NODE_PER_STREAM) * (CM_MAX_STREAM_COUNT))
#define CM_MAX_CHAR_ARRAY_LEN 256

#define MD_GET_STREAM(streams, stream_id) ((dcf_stream_t *)cm_ptlist_get(&(streams)->stream_list, (stream_id)))
#define MD_GET_STREAM_NODE(stream, node_id) ((dcf_node_t *)cm_ptlist_get(&(stream)->node_list, (node_id)))
#define MD_GET_STREAMS_NODE(streams, stream_id, node_id) \
    MD_GET_STREAM_NODE(MD_GET_STREAM((streams), (stream_id)), (node_id))

/* every option use one bit of flags */
#define OP_FLAG_NONE                 0x0000
#define OP_FLAG_ADD                  0x0001  // add member
#define OP_FLAG_REMOVE               0x0002  // remove member
#define OP_FLAG_CHANGE_ROLE          0x0004  // change member role
#define OP_FLAG_CHANGE_GROUP         0x0008  // change member group
#define OP_FLAG_CHANGE_PRIORITY      0x0010  // change member priority
#define OP_FLAG_ALL   ((OP_FLAG_ADD) | (OP_FLAG_REMOVE) | (OP_FLAG_CHANGE_ROLE) | \
                            (OP_FLAG_CHANGE_GROUP) | (OP_FLAG_CHANGE_PRIORITY))
#define CFG_LOG_KEY(node, flag) (((uint64)(node) << 32) | (flag))
#define CFG_LOG_NODE(key) (uint32)(((key) >> 32))
#define NEED_ADD(flag) ((flag) & OP_FLAG_ADD)
#define NEED_REMOVE(flag) ((flag) & OP_FLAG_REMOVE)
#define NEED_CHANGE_ROLE(flag) ((flag) & OP_FLAG_CHANGE_ROLE)
#define NEED_CHANGE_GROUP(flag) ((flag) & OP_FLAG_CHANGE_GROUP)
#define NEED_CHANGE_PRIORITY(flag) ((flag) & OP_FLAG_CHANGE_PRIORITY)

typedef struct st_dcf_node {
    uint32 node_id;
    char ip[CM_MAX_IP_LEN];
    uint32 port;
    dcf_role_t default_role;
    uint32 voting_weight;
    uint32 group;
    uint64 priority;
} dcf_node_t;

typedef struct st_dcf_change_member {
    uint32 op_type;
    dcf_role_t new_role;
    uint32 new_group;
    uint64 new_priority;
} dcf_change_member_t;

typedef struct st_dcf_node_role {
    uint32 node_id;
    dcf_role_t default_role;
} dcf_node_role_t;

typedef struct st_dcf_node_attr {
    uint64 index;
    uint32 weight;
    uint32 group;
} dcf_node_attr_t;

typedef struct st_stream_t {
    uint32 stream_id;
    uint32 voter_num;
    ptlist_t node_list;
    ptlist_t valid_nodes;
} dcf_stream_t;

typedef struct st_streams_t {
    ptlist_t stream_list;
} dcf_streams_t;

typedef enum en_entry_type {
    ENTRY_TYPE_LOG  = 0,
    ENTRY_TYPE_CONF = 1,
    ENTRY_TYPE_CELL
} entry_type_t;

typedef enum en_dcf_param {
    DCF_PARAM_UNKNOWN = 0,
    DCF_PARAM_ELECTION_TIMEOUT,
    DCF_PARAM_AUTO_ELC_PRIORITY_EN,
    DCF_PARAM_HEARTBEAT_INTERVAL,
    DCF_PARAM_ELECTION_SWITCH_THRESHOLD,
    DCF_PARAM_RUN_MODE,
    DCF_PARAM_INSTANCE_NAME,
    DCF_PARAM_DATA_PATH,
    DCF_PARAM_LOG_PATH,
    DCF_PARAM_LOG_LEVEL,
    DCF_PARAM_LOG_FILENAME_FORMAT,
    DCF_PARAM_LOG_BACKUP_FILE_COUNT,
    DCF_PARAM_MAX_LOG_FILE_SIZE,
    DCF_PARAM_LOG_FILE_PERMISSION,
    DCF_PARAM_LOG_PATH_PERMISSION,
    DCF_PARAM_MEC_AGENT_THREAD_NUM,
    DCF_PARAM_MEC_REACTOR_THREAD_NUM,
    DCF_PARAM_MEC_CHANNEL_NUM,
    DCF_PARAM_MEC_POOL_MAX_SIZE,
    DCF_PARAM_MEM_POOL_INIT_SIZE,
    DCF_PARAM_MEM_POOL_MAX_SIZE,
    DCF_PARAM_STG_POOL_INIT_SIZE,
    DCF_PARAM_STG_POOL_MAX_SIZE,
    DCF_PARAM_COMPRESS_ALGORITHM,
    DCF_PARAM_COMPRESS_LEVEL,
    DCF_PARAM_SOCKET_TIMEOUT,
    DCF_PARAM_CONNECT_TIMEOUT,
    DCF_REP_APPEND_THREAD_NUM,
    DCF_PARAM_MEC_FRAGMENT_SIZE,
    DCF_PARAM_MEC_BATCH_SIZE,
    DCF_PARAM_CPU_THRESHOLD,
    DCF_PARAM_NET_QUEUE_THRESHOLD,
    DCF_PARAM_DISK_RAWAIT_THRESHOLD,
    DCF_PARAM_SSL_CA,
    DCF_PARAM_SSL_KEY,
    DCF_PARAM_SSL_CRL,
    DCF_PARAM_SSL_CERT,
    DCF_PARAM_SSL_CIPHER,
    DCF_PARAM_SSL_PWD_PLAINTEXT,
    DCF_PARAM_SSL_PWD_CIPHERTEXT,
    DCF_PARAM_SSL_CERT_NOTIFY_TIME,
    DCF_PARAM_DATA_FILE_SIZE,
    DCF_PARAM_DN_FLOW_CONTROL_RTO,
    DCF_PARAM_DN_FLOW_CONTROL_RPO,
    DCF_PARAM_LOG_SUPPRESS_ENABLE,
    DCF_PARAM_MAJORITY_GROUPS,
    DCF_PARAM_CEIL,
} dcf_param_t;

typedef enum en_log_filename_format {
    LOG_FILENAME_DEFAULT = 0,
    LOG_FILENAME_SEPARATED,
    LOG_FILENAME_UNKNOW
} log_filename_format_t;

typedef enum en_param_run_mode {
    ELECTION_AUTO,
    ELECTION_MANUAL,
    ELECTION_DISABLE,
    ELECTION_CEIL,
} param_run_mode_t;

typedef union un_param_value {
    uint32 value_elc_timeout;
    uint32 value_auto_elc_priority_en;
    uint32 value_hb_interval;
    uint32 value_elc_switch_thd;
    param_run_mode_t value_mode;
    char instance_name[CM_MAX_NAME_LEN];
    char data_path[CM_MAX_PATH_LEN];
    char log_path[CM_MAX_LOG_HOME_LEN];
    uint32 value_log_filename_format;
    uint32 value_loglevel;
    uint32 value_log_backup_count;
    uint32 value_max_log_file_size;
    uint32 value_log_file_permission;
    uint32 value_log_path_permission;
    uint32 reactor_num;
    uint32 agent_num;
    uint32 channel_num;
    uint32 pool_num;
    size_t mec_pool_max_size;
    size_t buddy_init_size;
    size_t buddy_max_size;
    size_t stg_pool_init_size;
    size_t stg_pool_max_size;
    compress_algorithm_t compress;
    uint32 level;
    uint32 connect_timeout;
    uint32 socket_timeout;
    uint32 rep_append_thread_num;
    size_t frag_size;
    uint32 batch_size;
    uint32 v_uint32;
    int32 v_int32;
    size_t v_size;
    // Notice The length of the char array needs to be changed.
    char v_char_array[CM_MAX_CHAR_ARRAY_LEN];
    uint32 cpu_load_threshold;
    uint32 net_queue_threshold;
    uint32 disk_rawait_threshold;
    uint32 ssl_cert_notify_time;
    uint32 data_file_size;
    char ssl_ca[CM_FULL_PATH_BUFFER_SIZE];
    char ssl_key[CM_FULL_PATH_BUFFER_SIZE];
    char ssl_crl[CM_FULL_PATH_BUFFER_SIZE];
    char ssl_cert[CM_FULL_PATH_BUFFER_SIZE];
    char ssl_cipher[CM_MAX_SSL_CIPHER_LEN];
    char ext_pwd[CM_PASSWORD_BUFFER_SIZE];
    uint32 dn_flow_control_rto;
    uint32 dn_flow_control_rpo;
    uint32 log_suppress_enable;
    char majority_groups[MAX_MAJORITY_GROUPS_STR_LEN];
    cipher_t inter_pwd;
} param_value_t;

typedef enum en_meta_status {
    META_UNINIT = 0,
    META_CATCH_UP,
    META_JOIN,
    META_NORMAL,
} meta_status_t;
typedef struct st_dcf_meta {
    latch_t latch;
    meta_status_t status;
    uint32 current_node_id;
    dcf_node_t* all_nodes[CM_MAX_NODE_COUNT];
    dcf_streams_t* streams;
    char* buffer;
    uint32 checksum;
} dcf_meta_t;

#ifdef __cplusplus
}
#endif

#endif
