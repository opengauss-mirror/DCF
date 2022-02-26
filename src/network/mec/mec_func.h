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
 * mec_func.h
 *    mec process
 *
 * IDENTIFICATION
 *    src/network/mec/mec_func.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __MEC_FUNC_H__
#define __MEC_FUNC_H__

#include "mec_queue.h"
#include "mec.h"
#include "compress.h"
#include "cm_defs.h"
#include "cm_latch.h"
#include "cm_date.h"
#include "cm_thread.h"
#include "cm_memory.h"
#include "cs_pipe.h"
#include "cs_listener.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MEC_CONNECT_TIMEOUT 500000000 // mill-seconds

#define MEC_CHANNEL_TIMEOUT 50

#define MEC_INSTANCE_ID(id) (uint8)((id) >> 8)
#define MEC_CHANNEL_ID(id) (uint8)((id) & 0x00FF)

#define MEC_URL_BUFFER_SIZE     (CM_HOST_NAME_BUFFER_SIZE + 16)


#define MEC_ACTL_MSG_BUFFER_SIZE(profile) (uint64)((profile)->frag_size + MEC_BUFFER_RESV_SIZE + \
    sizeof(mec_message_head_t))
#define MEC_MESSAGE_BUFFER_SIZE(profile) (uint64)(MEC_ACTL_MSG_BUFFER_SIZE(profile) - PADDING_BUFFER_SIZE)
#define MEC_PRIV_MESSAGE_BUFFER_SIZE (uint64)(SIZE_K(1) + sizeof(mec_message_head_t))
#define MEC_PRIV_MESSAGE_POOL_SIZE (uint64)(128)


#define MEC_MAX_BUFFERLIST      4   /* Number of buffers supported by the bufferlist */

#define SECOND_TO_MILLISECOND   (uint32)(1000)
#define SECOND_TO_MICROSECOND   (uint32)(1000000)
#define SECOND_TO_NANOSECOND    (uint32)(1000000000)
#define MEG_GET_BUF_ID(msg_buf) (*(uint32 *)((char *)(msg_buf) - sizeof(uint32)))

#define MEC_DEFAULT_PRIV_AGENT   (uint32)(10)


typedef enum en_mec_time_stat {
    MEC_TIME_TEST_SEND = 0,
    MEC_TIME_TEST_RECV,
    MEC_TIME_TEST_BROADCAST,
    MEC_TIME_TEST_BROADCAST_AND_WAIT,
    MEC_TIME_TEST_MULTICAST,
    MEC_TIME_TEST_MULTICAST_AND_WAIT,
    MEC_TIME_GET_BUF,
    MEC_TIME_READ_MES,
    MEC_TIME_PROC_FUN,
    MEC_TIME_PUT_QUEUE,
    MEC_TIME_GET_QUEUE,
    MEC_TIME_QUEUE_PROC,
    MEC_TIME_PUT_BUF,
    MEC_TIME_TEST_CHECK,
    MEC_TIME_CEIL
} mec_time_stat_t;

#define MEC_STREAM_TO_CHANNEL_ID(stream_id, channel_num) (uint8)((stream_id) % (channel_num))

#define MEC_MESSAGE_ATTACH(msg, profile, priv, buf)  \
    do {                                           \
        (msg)->buffer = (buf);                     \
        (msg)->head = (mec_message_head_t *)(buf); \
        (msg)->buf_size  = ((priv) == PRIV_LOW) ? MEC_MESSAGE_BUFFER_SIZE(profile) : MEC_PRIV_MESSAGE_BUFFER_SIZE;  \
        (msg)->aclt_size = ((priv) == PRIV_LOW) ? MEC_ACTL_MSG_BUFFER_SIZE(profile) : MEC_PRIV_MESSAGE_BUFFER_SIZE; \
        (msg)->options = 0;                         \
        (msg)->offset = sizeof(mec_message_head_t); \
    } while (0)

#define MEC_MESSAGE_ATTACH2(msg, buf)               \
    do {                                            \
        (msg)->buffer = (buf);                      \
        (msg)->head = (mec_message_head_t *)(buf);  \
        (msg)->options = 0;                         \
        (msg)->offset = sizeof(mec_message_head_t); \
    } while (0)

#define MEC_MESSAGE_DETACH(msg)     \
    do {                            \
        (msg)->buffer = NULL;       \
        (msg)->head = NULL;         \
    } while (0)

typedef enum en_channel_status {
    INACTIVE = 0,
    ACTIVE = 1,
} channel_status_t;

typedef enum en_attach_mode {
    SEND_MODE = 0,
    RECV_MODE = 1,
    MODE_END,
} attach_mode_t;


struct st_mec_pipe;

typedef void(*agent_job_t)(struct st_mec_pipe *pipe, bool32 *is_continue);

typedef struct st_attach_info {
    uint32            spid;
    channel_status_t  status;
    volatile struct st_agent   *agent;
    agent_job_t        job;
} attach_info_t;


typedef struct st_mec_pipe {
    thread_lock_t send_lock;
    thread_lock_t recv_lock;
    thread_lock_t recv_epoll_lock;
    struct {
        volatile uint16 is_reg : 1;
        volatile uint16 recv_pipe_active : 1;
        volatile uint16 send_pipe_active : 1;
        uint16 priv : 1;
        volatile uint16 try_connet_count : 12;
    };
    cs_pipe_t          send_pipe;
    cs_pipe_t          recv_pipe;
    atomic32_t         send_need_close;
    atomic32_t         recv_need_close;
    struct st_reactor *reactor;
    struct st_mec_channel *channel;
    attach_info_t      attach[MODE_END];
} mec_pipe_t;

typedef struct st_mec_channel {
    uint32        id;
    atomic32_t    serial_no;
    mec_pipe_t    pipe[PRIV_CEIL];
} mec_channel_t;


typedef struct st_mec_lsnr {
    cs_pipe_type_t type;
    union {
        tcp_lsnr_t tcp;
    };
} mec_lsnr_t;

static inline void mec_init_get(mec_message_t *pack)
{
    pack->options = 0;
    pack->offset = sizeof(mec_message_head_t);
}

typedef struct st_fragment_key {
    uint32 stream_id;
    uint32 inst_id;
    uint32 serial_no;
} fragment_key_t;

typedef struct st_fragment_ctrl {
    spinlock_t lock;
    uint32     size;
    uint32     id;
    uint32     sn;
    uint32     prev;
    uint32     next;
    uint32     bucket;
    char      *buffer;
    date_t     now;
} fragment_ctrl_t;

typedef struct st_fragment_bucket {
    latch_t latch;
    uint32 id;
    uint32 first;
} fragment_bucket_t;

#define FRAGMENT_BUCKETS          (uint32) SIZE_K(1)
#define FRAGMENT_MAX_EXTENTS      (64)
#define FRAGMENT_EXTENT           (1024)
#define FRAGMENT_MAX_ITEMS        (FRAGMENT_MAX_EXTENTS * FRAGMENT_EXTENT)


typedef struct st_fragment_ctrl_pool {
    spinlock_t lock;
    char *extents[FRAGMENT_MAX_EXTENTS];
    volatile uint32 capacity;
    uint32 count;
    uint32 ext_cnt;
    uint32 free_first;
    volatile uint32 free_count;
    volatile bool32 extending;
} fragment_ctrl_pool_t;

#define FRAGMENT_CTRL_PTR(pool, id) ((fragment_ctrl_t *)((pool)->extents[(id) / FRAGMENT_EXTENT] + \
                                  sizeof(fragment_ctrl_t) * ((id) % FRAGMENT_EXTENT)))


typedef struct st_fragment_ctx {
    fragment_ctrl_pool_t  ctrl_pool;
    fragment_bucket_t     buckets[FRAGMENT_BUCKETS];
} fragment_ctx_t;

typedef struct st_mec_cb {
    msg_proc_t proc;
    msg_priv_t priv;
} mec_cb_t;

typedef enum en_shutdown_phase {
    SHUTDOWN_PHASE_NOT_BEGIN = 0,
    SHUTDOWN_PHASE_INPROGRESS,
    SHUTDOWN_PHASE_DONE
} shutdown_phase_t;

typedef struct st_mec_context {
    mec_lsnr_t        lsnr;
    mec_channel_t   **channels;
    bool8             is_connect[CM_MAX_NODE_COUNT][MEC_MAX_CHANNEL_NUM];
    mec_cb_t          cb_processer[MEC_CMD_CEIL];
    shutdown_phase_t  phase;
} mec_context_t;


typedef struct st_mec_buffer {
    char       *buf;    /* data buffer */
    uint32      len;    /* buffer length */
} mec_buffer_t;

typedef struct st_mec_bufflist {
    uint16       cnt;
    mec_buffer_t buffers[MEC_MAX_BUFFERLIST];
} mec_bufflist_t;


typedef struct st_mec_error_msg {
    mec_message_head_t head;
    int32 code;
} mec_error_msg_t;

typedef struct timeval cm_timeval;

#define FILL_FRAGMENT_KEY(head, key)      \
do {                                      \
    (key).inst_id = (head)->src_inst;     \
    (key).stream_id = (head)->stream_id;  \
    (key).serial_no = (head)->serial_no;  \
} while (0)

#define GET_INST_INDEX(id, profile) ((profile)->maps[id])
#define MEC_HOST_NAME(id, profile) ((char *)(profile)->inst_arr[id].t_addr.ip)
#define MEC_HOST_PORT(id, profile) ((profile)->inst_arr[id].t_addr.port)

#define GET_FROM_FREE_LST(pool, item)                       \
    do {                                                    \
        CM_ASSERT((pool)->free_count > 0);                  \
        (item) = MSG_GET_ITEMS((pool), (pool)->free_first); \
        (pool)->free_first = (item)->next;                  \
        (pool)->free_count--;                               \
        (item)->next = CM_INVALID_ID32;                     \
    } while (0)

#define ALLOC_FROM_POOL(pool, item)                  \
    do {                                             \
        (item) = MSG_GET_ITEMS(pool, (pool)->count); \
        (item)->id = (pool)->count;                  \
        (item)->pool = (pool);                       \
        (item)->next = CM_INVALID_ID32;              \
        ++(pool)->count;                             \
    } while (0)

#define RESET_POOL(pool)                       \
    do {                                       \
        (pool)->capacity = 0;                  \
        (pool)->count = 0;                     \
        (pool)->ext_cnt = 0;                   \
        (pool)->free_first = CM_INVALID_ID32;  \
        (pool)->free_count = 0;                \
        (pool)->extending = CM_FALSE;          \
    } while (0)

#define INIT_POOL(pool)                       \
    do {                                      \
        (pool)->capacity = 0;                 \
        (pool)->count = 0;                    \
        (pool)->lock = 0;                     \
        (pool)->ext_cnt = 0;                  \
        (pool)->free_first = CM_INVALID_ID32; \
        (pool)->free_count = 0;               \
        (pool)->extending = CM_FALSE;         \
    } while (0)

#define GET_FROM_FREE_LIST(ctrl, pool)                        \
    do {                                                      \
        (ctrl) = FRAGMENT_CTRL_PTR(pool, (pool)->free_first); \
        (pool)->free_first = (ctrl)->next;                    \
        (pool)->free_count--;                                 \
    } while (0)

#define FRAGMENT_EQUAL(key, head)               \
        (key)->stream_id == (head)->stream_id && \
        (key)->inst_id   == (head)->src_inst  && \
        (key)->serial_no == (head)->serial_no

#define GET_MSG_HEAD(pack) (pack)->head
#define GET_MSG_BUFF(pack) (pack)->buffer

#define MEC_WRITE_ADDR(pack)           (GET_MSG_BUFF(pack) + GET_MSG_HEAD(pack)->size)
#define MEC_READ_ADDR(pack)            (GET_MSG_BUFF(pack) + (pack)->offset)
#define MEC_REMAIN_SIZE(pack)          ((int32)((pack)->buf_size - (int32)(GET_MSG_HEAD(pack)->size)))
#define MEC_HAS_REMAIN(pack, sz)       (((sz) < (pack)->buf_size) && \
    (GET_MSG_HEAD(pack)->size + (sz) <= (pack)->buf_size))
#define MEC_DATA_ADDR(pack)            (GET_MSG_BUFF(pack) + sizeof(mec_message_head_t))
#define MEC_HAS_RECV_REMAIN(pack, sz)  (((sz) < GET_MSG_HEAD(pack)->size) && \
    ((pack)->offset + (sz) <= GET_MSG_HEAD(pack)->size))

#define MEC_CHECK_RECV_PACK_FREE(pack, len)                                                   \
    {                                                                                         \
        if (!MEC_HAS_RECV_REMAIN(pack, len)) {                                                \
            CM_THROW_ERROR(ERR_PACKET_READ, GET_MSG_HEAD(pack)->size, (pack)->offset, (uint32)(len)); \
            return CM_ERROR;                                                                  \
        }                                                                                     \
    }

status_t mec_connect(uint32 node_id);
void mec_disconnect(uint32 node_id);
status_t mec_get_message_buf(mec_message_t *pack, uint32 dst_inst, msg_priv_t priv);
void mec_close_send_pipe(mec_pipe_t *pipe);
void mec_close_recv_pipe(mec_pipe_t *pipe);

void mec_release_message_buf(const char *msg_buf);
status_t mec_get_data(mec_message_t *pack, uint32 size, void **buf);
status_t init_mec_profile_inst(mec_profile_t *profile);

void release_fragment_ctrl(fragment_ctrl_t *ctrl, uint32 del_sn);
status_t concat_fragment_pack(fragment_ctrl_t *ctrl, mec_message_head_t *head);
fragment_ctrl_t *find_fragment_ctrl(fragment_bucket_t *bucket, const fragment_key_t *key);
status_t insert_fragment_pack(mec_message_head_t *head, fragment_bucket_t *bucket);
status_t fragment_alloc_ctrl(fragment_ctrl_t **ctrl);
void fragment_free_ctrl(fragment_ctrl_t *ctrl);
void mec_proc_recv_pipe(struct st_mec_pipe *pipe, bool32 *is_continue);
void mec_proc_send_pipe(struct st_mec_pipe *pipe, bool32 *is_continue);
status_t mec_alloc_msg_item(message_pool_t *pool, msg_item_t **item);

#ifdef __cplusplus
}
#endif

#endif
