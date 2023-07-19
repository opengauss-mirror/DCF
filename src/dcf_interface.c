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
 * dcf_interface.c
 *    DCF API
 *
 * IDENTIFICATION
 *    src/dcf_interface.c
 *
 * -------------------------------------------------------------------------
 */

#include "interface/dcf_interface.h"
#include "cm_defs.h"
#include "util_error.h"
#include "cm_types.h"
#include "cm_log.h"
#include "cm_memory.h"
#include "cm_text.h"
#include "cm_num.h"
#include "mec.h"
#include "metadata.h"
#include "md_change.h"
#include "replication.h"
#include "rep_common.h"
#include "elc_stream.h"
#include "elc_status_check.h"
#include "util_perf_stat.h"
#include "cm_ip.h"
#include "cJSON.h"
#include "util_profile_stat.h"
#include "stream.h"
#include "cb_func.h"
#include "mec_reactor.h"
#include "mec_instance.h"
#include "md_param.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_block_ack {
    NO_ACK = 0,
    SUCCESS_ACK,
    ERROR_ACK,
} block_ack_t;

typedef struct st_block_info {
    uint32 block_time_ms;
    block_ack_t ack;
    uint64 leader_last_index;
    thread_t thread;
    cm_event_t event;
} block_info_t;

typedef struct st_dcf_status {
    node_status_t status;
    block_info_t block;
    atomic32_t writing_cnt; // dcf writing count
    latch_t latch;
} dcf_status_t;

typedef struct st_dcf_exception_report {
    cm_event_t      exception_event;
    thread_t        exception_thread;
    uint32          stream_id;
    dcf_exception_t exception;
    bool32          exception_init_flag;
} dcf_exception_report_t;

static dcf_status_t g_node_status[CM_MAX_STREAM_COUNT] = {0};

static latch_t    g_dcf_latch = {0};
static bool32     g_dcf_inited = CM_FALSE;

static usr_cb_msg_proc_t            g_cb_send_msg_notify = NULL;
static usr_cb_exception_notify_t    g_cb_exception_notify = NULL;
static dcf_exception_report_t       g_dcf_exception;
static bool32    g_node_inited = CM_FALSE;

#define MAX_PARALLEL_MAX_NUM 256
typedef struct st_dcf_parallel_msg {
    spinlock_t   lock;
    uint32       cursor;
    uint8        req_id_status[MAX_PARALLEL_MAX_NUM];
    atomic_t     ack_result[MAX_PARALLEL_MAX_NUM];
    cm_event_t   event[MAX_PARALLEL_MAX_NUM];
} dcf_parallel_msg_t;
static dcf_parallel_msg_t  g_universal_write_info = {0};
static dcf_parallel_msg_t  g_consensus_hc_info = {0};

status_t set_node_status(uint32 stream_id, node_status_t status, uint32 block_time_ms)
{
    dcf_status_t *node_status = &g_node_status[stream_id];
    cm_latch_x(&node_status->latch, 0, NULL);
    if (status == NODE_BLOCKED) {
        if (node_status->status == NODE_BLOCKED) {
            cm_unlatch(&node_status->latch, NULL);
            LOG_DEBUG_WAR("already blocked, can't set again.");
            return CM_ERROR;
        }
        node_status->block.block_time_ms = block_time_ms;
    }
    node_status->status = status;
    cm_unlatch(&node_status->latch, NULL);
    return CM_SUCCESS;
}

static inline node_status_t get_node_status(uint32 stream_id)
{
    dcf_status_t *node_status = &g_node_status[stream_id];
    cm_latch_s(&node_status->latch, 0, CM_FALSE, NULL);
    node_status_t status = node_status->status;
    cm_unlatch(&node_status->latch, NULL);
    return status;
}

void clear_node_block_status(uint32 stream_id)
{
    if (get_node_status(stream_id) == NODE_BLOCKED) {
        (void)set_node_status(stream_id, NODE_NORMAL, 0);
    }
}

static inline uint32 get_block_time(uint32 stream_id)
{
    dcf_status_t *node_status = &g_node_status[stream_id];
    cm_latch_s(&node_status->latch, 0, CM_FALSE, NULL);
    uint32 block_time = node_status->block.block_time_ms;
    cm_unlatch(&node_status->latch, NULL);
    return block_time;
}

static inline void set_block_ack(uint32 stream_id, block_ack_t ack, uint64 last_index)
{
    dcf_status_t *node_status = &g_node_status[stream_id];
    cm_latch_x(&node_status->latch, 0, NULL);
    node_status->block.leader_last_index = last_index;
    node_status->block.ack = ack;
    cm_unlatch(&node_status->latch, NULL);
}

static inline block_ack_t get_block_ack(uint32 stream_id)
{
    dcf_status_t *node_status = &g_node_status[stream_id];
    cm_latch_s(&node_status->latch, 0, CM_FALSE, NULL);
    block_ack_t ack = node_status->block.ack;
    cm_unlatch(&node_status->latch, NULL);
    return ack;
}

static inline uint64 get_block_last_index(uint32 stream_id)
{
    dcf_status_t *node_status = &g_node_status[stream_id];
    cm_latch_s(&node_status->latch, 0, CM_FALSE, NULL);
    uint64 last_index = node_status->block.leader_last_index;
    cm_unlatch(&node_status->latch, NULL);
    return last_index;
}

status_t block_node_req(uint32 stream_id, uint32 node_id, uint32 block_time_ms)
{
    mec_message_t pack;
    uint32 src_node = md_get_cur_node();
    CM_RETURN_IFERR(mec_alloc_pack(&pack, MEC_CMD_BLOCK_NODE_RPC_REQ, src_node, node_id, stream_id));
    if (mec_put_int32(&pack, block_time_ms) != CM_SUCCESS) {
        mec_release_pack(&pack);
        LOG_DEBUG_ERR("block node req, encode fail.");
        return CM_ERROR;
    }
    LOG_DEBUG_INF("send blockreq: stream=%u,src=%u,dst=%u,block_time=%u.", stream_id, src_node, node_id, block_time_ms);
    status_t ret = mec_send_data(&pack);
    mec_release_pack(&pack);
    return ret;
}

status_t block_node_ack(uint32 stream_id, unsigned int node_id, block_ack_t ack)
{
    if (ack == SUCCESS_ACK) {
        timespec_t begin = cm_clock_now();
        do {
            cm_sleep(CM_SLEEP_10_FIXED);
            if ((cm_clock_now() - begin) > MICROSECS_PER_SECOND) {
                LOG_RUN_ERR("wait dcf write timeout, writing_cnt=%u.", g_node_status[stream_id].writing_cnt);
                break;
            }
        } while (g_node_status[stream_id].writing_cnt != 0);
    }

    mec_message_t pack;
    uint32 src_node = md_get_cur_node();
    CM_RETURN_IFERR(mec_alloc_pack(&pack, MEC_CMD_BLOCK_NODE_RPC_ACK, src_node, node_id, stream_id));
    uint64 last_index = stg_last_log_id(stream_id).index;
    if (mec_put_int32(&pack, ack) != CM_SUCCESS || mec_put_int64(&pack, last_index) != CM_SUCCESS) {
        mec_release_pack(&pack);
        LOG_DEBUG_ERR("block node ack, encode fail.");
        return CM_ERROR;
    }
    LOG_DEBUG_INF("send blockack: stream=%u,src=%u,dst=%u,ack=%d,last_index=%llu.",
        stream_id, src_node, node_id, ack, last_index);
    status_t ret = mec_send_data(&pack);
    mec_release_pack(&pack);
    return ret;
}

status_t block_node_req_proc(mec_message_t *pack)
{
    uint32 stream_id = pack->head->stream_id;
    uint32 src_node_id = pack->head->src_inst;
    LOG_DEBUG_INF("recv blockreq: stream_id=%u, node_id=%u", stream_id, src_node_id);

    uint32 block_time_ms;
    CM_RETURN_IFERR(mec_get_int32(pack, (int32*)&block_time_ms));

    block_ack_t ack = SUCCESS_ACK;
    if (elc_get_node_role(stream_id) != DCF_ROLE_LEADER
        || set_node_status(stream_id, NODE_BLOCKED, block_time_ms) != CM_SUCCESS) {
        ack = ERROR_ACK;
    }
    CM_RETURN_IFERR(block_node_ack(stream_id, src_node_id, ack));

    if (ack == ERROR_ACK) {
        return CM_SUCCESS;
    }

    LOG_DEBUG_INF("set node blocked, block_time_ms=%u.", block_time_ms);
    cm_event_notify(&g_node_status[stream_id].block.event);
    return CM_SUCCESS;
}

status_t block_node_ack_proc(mec_message_t *pack)
{
    uint32 stream_id = pack->head->stream_id;
    uint32 ack;
    CM_RETURN_IFERR(mec_get_int32(pack, (int32*)&ack));
    uint64 last_index;
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&last_index));
    LOG_DEBUG_INF("recv blockack: stream_id=%u, ack=%u, last_index=%llu.", stream_id, ack, last_index);

    ack = (ack == SUCCESS_ACK) ? SUCCESS_ACK : ERROR_ACK;
    set_block_ack(stream_id, ack, last_index);
    return CM_SUCCESS;
}

static void block_thread_entry(thread_t *thread)
{
    uint32 stream_id  = (uint32)(uint64)thread->argument;
    LOG_DEBUG_INF("block_thread_entry: stream_id=%u.", stream_id);
    cm_event_t *block_event = &g_node_status[stream_id].block.event;

    (void)cm_set_thread_name("block_node");

    while (!thread->closed) {
        (void)cm_event_timedwait(block_event, CM_SLEEP_500_FIXED);

        if (get_node_status(stream_id) == NODE_BLOCKED) {
            timespec_t begin = cm_clock_now();
            uint32 block_time_ms = get_block_time(stream_id);
            while (((uint64)(cm_clock_now() - begin)) / MICROSECS_PER_MILLISEC < block_time_ms) {
                cm_sleep(CM_SLEEP_1_FIXED);
            }
            (void)set_node_status(stream_id, NODE_NORMAL, 0);
        }
    }
}

static void exception_thread_entry(thread_t *thread)
{
    dcf_exception_report_t *cur_exception  = (dcf_exception_report_t *)thread->argument;
    (void)cm_set_thread_name("exception reporting thread");
    bool32 is_triggered = CM_FALSE;
    while (!thread->closed) {
        (void)cm_event_timedwait(&(cur_exception->exception_event), CM_SLEEP_1000_FIXED);
        if (cur_exception->exception != DCF_RUNNING_NORMAL && is_triggered == CM_FALSE) {
            is_triggered = CM_TRUE;
            if (g_cb_exception_notify != NULL) {
                int ret = g_cb_exception_notify(cur_exception->stream_id, (uint32) (cur_exception->exception));
                LOG_DEBUG_INF("exception report callback: g_cb_exception_notify, retcode=%d", ret);
            }
        }
    }
}

static status_t init_exception_report()
{
    LOG_RUN_INF("init exception report");
    g_dcf_exception.exception_init_flag = CM_FALSE;
    g_dcf_exception.stream_id = CM_INVALID_STREAM_ID;
    g_dcf_exception.exception = DCF_RUNNING_NORMAL;
    CM_RETURN_IFERR(cm_event_init(&(g_dcf_exception.exception_event)));
    CM_RETURN_IFERR(cm_create_thread(exception_thread_entry, 0, (void *)&g_dcf_exception,
                                     &(g_dcf_exception.exception_thread)));
    g_dcf_exception.exception_init_flag = CM_TRUE;
    return CM_SUCCESS;
}

static status_t deinit_exception_report()
{
    LOG_RUN_INF("deinit exception report");
    if (g_dcf_exception.exception_init_flag) {
        cm_close_thread(&(g_dcf_exception.exception_thread));
        cm_event_destory(&(g_dcf_exception.exception_event));
    }
    g_dcf_exception.exception_init_flag = CM_FALSE;
    return CM_SUCCESS;
}

status_t common_msg_proc(mec_message_t *pack)
{
    int ret = CM_SUCCESS;
    uint32 stream_id = pack->head->stream_id;
    uint32 src_node_id = pack->head->src_inst;
    char *msg = NULL;
    uint32 msg_size = 0;
    CM_RETURN_IFERR(mec_get_bin(pack, &msg_size, (void **)&msg));
    if (g_cb_send_msg_notify != NULL) {
        ret = g_cb_send_msg_notify(stream_id, src_node_id, msg, msg_size);
        LOG_DEBUG_INF("Callback: dn_send_msg_notify, retcode=%d", ret);
    }

    return ret;
}

status_t change_member_req_proc(mec_message_t *pack);
status_t universal_write_req_proc(mec_message_t *pack);
status_t universal_write_ack_proc(mec_message_t *pack);
status_t dcf_get_commit_index_req_proc(mec_message_t *pack);
status_t dcf_get_commit_index_ack_proc(mec_message_t *pack);

status_t init_node_status()
{
    uint32 streams[CM_MAX_STREAM_COUNT];
    uint32 stream_count;

    if (g_node_inited) {
        LOG_RUN_INF("init_node_status already sucessful");
        return CM_SUCCESS;
    }

    for (uint32 i = 0; i < MAX_PARALLEL_MAX_NUM; i++) {
        CM_RETURN_IFERR(cm_event_init(&g_universal_write_info.event[i]));
        CM_RETURN_IFERR(cm_event_init(&g_consensus_hc_info.event[i]));
    }

    if (md_get_stream_list(streams, &stream_count) != CM_SUCCESS) {
        LOG_DEBUG_ERR("md_get_stream_list failed");
        return CM_ERROR;
    }

    for (uint32 i = 0; i < stream_count; i++) {
        uint32 stream_id = streams[i];
        dcf_status_t *node_status = &g_node_status[stream_id];
        cm_latch_init(&node_status->latch);
        node_status->status = NODE_NORMAL;
        node_status->block.ack = NO_ACK;
        CM_RETURN_IFERR(cm_event_init(&node_status->block.event));
        CM_RETURN_IFERR(cm_create_thread(block_thread_entry, 0, (void *)(uint64)stream_id, &node_status->block.thread));
    }

    register_msg_process(MEC_CMD_BLOCK_NODE_RPC_REQ, block_node_req_proc, PRIV_HIGH);
    register_msg_process(MEC_CMD_BLOCK_NODE_RPC_ACK, block_node_ack_proc, PRIV_HIGH);
    register_msg_process(MEC_CMD_SEND_COMMON_MSG, common_msg_proc, PRIV_LOW);
    register_msg_process(MEC_CMD_CHANGE_MEMBER_RPC_REQ, change_member_req_proc, PRIV_HIGH);
    register_msg_process(MEC_CMD_UNIVERSAL_WRITE_REQ, universal_write_req_proc, PRIV_LOW);
    register_msg_process(MEC_CMD_UNIVERSAL_WRITE_ACK, universal_write_ack_proc, PRIV_LOW);
    register_msg_process(MEC_CMD_GET_COMMIT_INDEX_REQ, dcf_get_commit_index_req_proc, PRIV_LOW);
    register_msg_process(MEC_CMD_GET_COMMIT_INDEX_ACK, dcf_get_commit_index_ack_proc, PRIV_LOW);
    g_node_inited = CM_TRUE;

    return CM_SUCCESS;
}

static inline void deinit_node_status()
{
    uint32 streams[CM_MAX_STREAM_COUNT];
    uint32 stream_count;

    if (md_get_stream_list(streams, &stream_count) != CM_SUCCESS) {
        LOG_DEBUG_ERR("md_get_stream_list failed");
        return;
    }

    if (!g_node_inited) {
        return;
    }

    for (uint32 i = 0; i < stream_count; i++) {
        uint32 stream_id = streams[i];
        dcf_status_t *node_status = &g_node_status[stream_id];
        if (set_node_status(stream_id, NODE_UNINIT, 0) != CM_SUCCESS) {
            LOG_DEBUG_ERR("set node status to NODE_UNINIT failed in deinit");
        }
        cm_close_thread(&node_status->block.thread);
        cm_event_destory(&node_status->block.event);
    }

    for (uint32 i = 0; i < MAX_PARALLEL_MAX_NUM; i++) {
        cm_event_destory(&g_universal_write_info.event[i]);
        cm_event_destory(&g_consensus_hc_info.event[i]);
    }

    MEMS_RETVOID_IFERR(memset_sp(g_node_status, sizeof(dcf_status_t) * CM_MAX_STREAM_COUNT, 0,
        sizeof(dcf_status_t) * CM_MAX_STREAM_COUNT));
    g_node_inited = CM_FALSE;
}

static inline bool32 check_if_node_inited(uint32 stream_id)
{
    if (stream_id >= CM_MAX_STREAM_COUNT) {
        LOG_DEBUG_ERR("stream_id=%u invalid", stream_id);
        return CM_FALSE;
    }
    node_status_t status = get_node_status(stream_id);
    LOG_DEBUG_INF("stream_id=%u node_status=%d", stream_id, status);
    return (status == NODE_UNINIT) ? CM_FALSE : CM_TRUE;
}

static inline void wait_if_node_blocked(uint32 stream_id)
{
    node_status_t status = get_node_status(stream_id);
    if (status == NODE_BLOCKED) {
        timespec_t begin = cm_clock_now();
        while (status == NODE_BLOCKED) {
            if ((cm_clock_now() - begin) > MICROSECS_PER_SECOND) {
                LOG_DEBUG_WAR("node is blocked now, waiting...");
                begin = cm_clock_now();
            }
            cm_sleep(1);
            status = get_node_status(stream_id);
        }
    }
}

static usr_cb_log_output_t g_log_output_cb = NULL;

status_t init_logger_param(log_param_t *log_param)
{
    param_value_t param_value;
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_LOG_PATH, &param_value));
    if (strlen(param_value.log_path) == 0) {
        CM_RETURN_IFERR(md_get_param(DCF_PARAM_DATA_PATH, &param_value));
        PRTS_RETURN_IFERR(snprintf_s(log_param->log_home, CM_MAX_LOG_HOME_LEN, CM_MAX_LOG_HOME_LEN - 1,
            "%s", param_value.data_path));
    } else {
        PRTS_RETURN_IFERR(snprintf_s(log_param->log_home, CM_MAX_LOG_HOME_LEN, CM_MAX_LOG_HOME_LEN - 1,
            "%s", param_value.log_path));
    }

    CM_RETURN_IFERR(md_get_param(DCF_PARAM_INSTANCE_NAME, &param_value));
    PRTS_RETURN_IFERR(snprintf_s(log_param->instance_name, CM_MAX_NAME_LEN, CM_MAX_NAME_LEN - 1,
        "%s", param_value.instance_name));

    CM_RETURN_IFERR(md_get_param(DCF_PARAM_LOG_FILENAME_FORMAT, &param_value));
    log_param->log_filename_format = param_value.value_log_filename_format;

    CM_RETURN_IFERR(md_get_param(DCF_PARAM_LOG_LEVEL, &param_value));
    log_param->log_level = param_value.value_loglevel;

    CM_RETURN_IFERR(md_get_param(DCF_PARAM_LOG_BACKUP_FILE_COUNT, &param_value));
    log_param->log_backup_file_count = param_value.value_log_backup_count;

    CM_RETURN_IFERR(md_get_param(DCF_PARAM_MAX_LOG_FILE_SIZE, &param_value));
    log_param->max_log_file_size = param_value.value_max_log_file_size * SIZE_M(1);

    CM_RETURN_IFERR(md_get_param(DCF_PARAM_LOG_FILE_PERMISSION, &param_value));
    cm_log_set_file_permissions((uint16)param_value.value_log_file_permission);

    CM_RETURN_IFERR(md_get_param(DCF_PARAM_LOG_PATH_PERMISSION, &param_value));
    cm_log_set_path_permissions((uint16)param_value.value_log_path_permission);

    CM_RETURN_IFERR(md_get_param(DCF_PARAM_LOG_SUPPRESS_ENABLE, &param_value));
    log_param->log_suppress_enable = param_value.log_suppress_enable;

    return CM_SUCCESS;
}

int64 cb_get_value_impl(stat_item_id_t item_id)
{
    int64 value = 0;
    switch (item_id) {
        case SEND_QUEUE_COUNT:
            value = mec_get_send_que_count(PRIV_LOW);
            break;
        case RECV_QUEUE_COUNT:
            value = mec_get_recv_que_count(PRIV_LOW);
            break;
        case SEND_QUEUE_COUNT_HIGH:
            value = mec_get_send_que_count(PRIV_HIGH);
            break;
        case RECV_QUEUE_COUNT_HIGH:
            value = mec_get_recv_que_count(PRIV_HIGH);
            break;
        case STG_MEM_USED:
            value = stg_get_total_mem_used();
            break;
        case MEC_SEND_MEM:
            value = mec_get_send_mem_capacity(PRIV_LOW);
            break;
        case MEC_RECV_MEM:
            value = mec_get_recv_mem_capacity(PRIV_LOW);
            break;
        case MEC_BUDDY_MEM:
            value = get_mem_pool()->used_size;
            break;
        default:
            break;
    }
    return value;
}

status_t register_stat_items()
{
    CM_RETURN_IFERR(cm_reg_stat_item(DCF_WRITE_CNT, "DCFWriteCount", UNIT_DEFAULT, STAT_INDICATOR_ACC, NULL));
    CM_RETURN_IFERR(cm_reg_stat_item(DCF_WRITE_SIZE, "DCFWriteSize", UNIT_MB, STAT_INDICATOR_ACC, NULL));
    CM_RETURN_IFERR(cm_reg_stat_item(DISK_WRITE, "DiskWrite", UNIT_MS, STAT_INDICATOR_AVG, NULL));
    CM_RETURN_IFERR(cm_reg_stat_item(SEND_PACK_SIZE, "SendPackSize", UNIT_MB, STAT_INDICATOR_ACC, NULL));
    CM_RETURN_IFERR(cm_reg_stat_item(SEND_DELAY, "SendDelay", UNIT_MS, STAT_INDICATOR_AVG, NULL));
    CM_RETURN_IFERR(cm_reg_stat_item(SEND_WAIT, "SendWait", UNIT_MS, STAT_INDICATOR_AVG, NULL));
    CM_RETURN_IFERR(cm_reg_stat_item(RECV_DELAY, "RecvDelay", UNIT_MS, STAT_INDICATOR_AVG, NULL));
    CM_RETURN_IFERR(
        cm_reg_stat_item(SEND_QUEUE_COUNT, "SendQueueLowCount", UNIT_DEFAULT, STAT_INDICATOR_ACC, cb_get_value_impl));
    CM_RETURN_IFERR(
        cm_reg_stat_item(RECV_QUEUE_COUNT, "RecvQueueLowCount", UNIT_DEFAULT, STAT_INDICATOR_ACC, cb_get_value_impl));
    CM_RETURN_IFERR(cm_reg_stat_item(SEND_QUEUE_COUNT_HIGH, "SendQueueHighCount",
        UNIT_DEFAULT, STAT_INDICATOR_ACC, cb_get_value_impl));
    CM_RETURN_IFERR(cm_reg_stat_item(RECV_QUEUE_COUNT_HIGH, "RecvQueueHighCount",
        UNIT_DEFAULT, STAT_INDICATOR_ACC, cb_get_value_impl));
    CM_RETURN_IFERR(
        cm_reg_stat_item(STG_MEM_USED, "StgMemUsed", UNIT_MB, STAT_INDICATOR_ACC, cb_get_value_impl));
    CM_RETURN_IFERR(
        cm_reg_stat_item(MEC_SEND_MEM, "MecSendMem", UNIT_MB, STAT_INDICATOR_ACC, cb_get_value_impl));
    CM_RETURN_IFERR(
        cm_reg_stat_item(MEC_RECV_MEM, "MecRecvMem", UNIT_MB, STAT_INDICATOR_ACC, cb_get_value_impl));
    CM_RETURN_IFERR(cm_reg_stat_item(HB_SEND_COUNT, "HBSendCount", UNIT_DEFAULT, STAT_INDICATOR_ACC, NULL));
    CM_RETURN_IFERR(cm_reg_stat_item(HB_RECV_COUNT, "HBRecvCount", UNIT_DEFAULT, STAT_INDICATOR_ACC, NULL));
    CM_RETURN_IFERR(cm_reg_stat_item(HB_RTT, "HBRTT", UNIT_MS, STAT_INDICATOR_AVG, NULL));
    CM_RETURN_IFERR(
        cm_reg_stat_item(MEC_BUDDY_MEM, "MecBuddyMem", UNIT_MB, STAT_INDICATOR_ACC, cb_get_value_impl));
    return CM_SUCCESS;
}

status_t init_logger()
{
    char file_name[CM_FULL_PATH_BUFFER_SIZE] = { '\0' };

    log_param_t *log_param = cm_log_param_instance();
    log_param->log_instance_startup = CM_FALSE;
    CM_RETURN_IFERR(cm_set_log_module_name("DCF", sizeof("DCF") - 1));
    CM_RETURN_IFERR(init_logger_param(log_param));

    log_param->log_write = (usr_cb_log_output_t)g_log_output_cb;

    PRTS_RETURN_IFERR(snprintf_s(file_name, CM_FULL_PATH_BUFFER_SIZE, CM_FULL_PATH_BUFFER_SIZE - 1, "%s/run/%s",
        log_param->log_home, "dcf.rlog"));
    CM_RETURN_IFERR(cm_log_init(LOG_RUN, file_name));

    PRTS_RETURN_IFERR(snprintf_s(file_name, CM_FULL_PATH_BUFFER_SIZE, CM_FULL_PATH_BUFFER_SIZE - 1, "%s/debug/%s",
        log_param->log_home, "dcf.dlog"));
    CM_RETURN_IFERR(cm_log_init(LOG_DEBUG, file_name));

    PRTS_RETURN_IFERR(snprintf_s(file_name, CM_FULL_PATH_BUFFER_SIZE, CM_FULL_PATH_BUFFER_SIZE - 1, "%s/oper/%s",
        log_param->log_home, "oper.log"));
    CM_RETURN_IFERR(cm_log_init(LOG_OPER, file_name));

    PRTS_RETURN_IFERR(snprintf_s(file_name, CM_FULL_PATH_BUFFER_SIZE, CM_FULL_PATH_BUFFER_SIZE - 1, "%s/alarm/%s",
        log_param->log_home, "alarm.log"));
    CM_RETURN_IFERR(cm_log_init(LOG_ALARM, file_name));

    PRTS_RETURN_IFERR(snprintf_s(file_name, CM_FULL_PATH_BUFFER_SIZE, CM_FULL_PATH_BUFFER_SIZE - 1, "%s/mec/%s",
        log_param->log_home, "mec.log"));
    CM_RETURN_IFERR(cm_log_init(LOG_MEC, file_name));

    PRTS_RETURN_IFERR(snprintf_s(file_name, CM_FULL_PATH_BUFFER_SIZE, CM_FULL_PATH_BUFFER_SIZE - 1, "%s/trace/%s",
        log_param->log_home, "trace.log"));
    CM_RETURN_IFERR(cm_log_init(LOG_TRACE, file_name));

    PRTS_RETURN_IFERR(snprintf_s(file_name, CM_FULL_PATH_BUFFER_SIZE, CM_FULL_PATH_BUFFER_SIZE - 1, "%s/profile/%s",
                                 log_param->log_home, "dcf.plog"));
    CM_RETURN_IFERR(cm_log_init(LOG_PROFILE, file_name));

    log_param->log_instance_startup = CM_TRUE;
    LOG_RUN_INF("[DCF]Logger init succeed");
    return CM_SUCCESS;
}

static inline status_t profile_stat_init()
{
    uint32 ret = cm_profile_stat_init();
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("DCF init profile statistics failed, %s, retcode=%d, error code=%d, error info=%s",
                    "config init failed",
                    ret, cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
        cm_profile_stat_uninit();
        return CM_ERROR;
    }
    CM_RETURN_IFERR(register_stat_items());
    return CM_SUCCESS;
}

int dcf_set_param(const char* param_name, const char* param_value)
{
    CM_CHECK_NULL_PTR(param_name);
    cm_reset_error();
    init_dcf_errno_desc();
    dcf_param_t param_type;
    param_value_t out_value;

    if (cm_str_equal(param_name, "SSL_PWD_PLAINTEXT")) {
        LOG_OPER("dcf set param, param_name=%s param_value=%s", param_name, "***");
    } else {
        LOG_OPER("dcf set param, param_name=%s param_value=%s", param_name, param_value);
    }

    CM_RETURN_IFERR(md_verify_param(param_name, param_value, &param_type, &out_value));
    return md_set_param(param_type, &out_value);
}

int dcf_get_param(const char *param_name, char *param_value, unsigned int size)
{
    CM_CHECK_NULL_PTR(param_name);
    cm_reset_error();
    init_dcf_errno_desc();
    CM_RETURN_IFERR(md_get_param_by_name(param_name, param_value, size));
    return CM_SUCCESS;
}

int dcf_register_after_writer(usr_cb_after_writer_t cb_func)
{
    return rep_register_after_writer(ENTRY_TYPE_LOG, cb_func);
}

int dcf_register_consensus_notify(usr_cb_consensus_notify_t cb_func)
{
    return rep_register_consensus_notify(ENTRY_TYPE_LOG, cb_func);
}

int dcf_register_status_notify(usr_cb_status_notify_t cb_func)
{
    return elc_register_notify(cb_func);
}

int dcf_register_log_output(usr_cb_log_output_t cb_func)
{
    g_log_output_cb = cb_func;
    return CM_SUCCESS;
}

int dcf_register_exception_report(usr_cb_exception_notify_t cb_func)
{
    g_cb_exception_notify = cb_func;
    return CM_SUCCESS;
}

int dcf_register_decrypt_pwd(usr_cb_decrypt_pwd_t cb_func)
{
    return mec_register_decrypt_pwd(cb_func);
}

int dcf_register_election_notify(usr_cb_election_notify_t cb_func)
{
    return elc_register_election_notify(cb_func);
}

int dcf_register_msg_proc(usr_cb_msg_proc_t cb_func)
{
    g_cb_send_msg_notify = cb_func;
    return CM_SUCCESS;
}

int dcf_register_thread_memctx_init(usr_cb_thread_memctx_init_t cb_func)
{
    return cb_register_thread_memctx_init(cb_func);
}

static inline status_t register_conf_type_cb()
{
    // register callback function, used by member changed API
    CM_RETURN_IFERR(rep_register_after_writer(ENTRY_TYPE_CONF, md_after_write_cb));
    CM_RETURN_IFERR(rep_register_consensus_notify(ENTRY_TYPE_CONF, md_consensus_notify_cb));
    CM_RETURN_IFERR(stg_register_cb(ENTRY_TYPE_CONF, md_save));
    return CM_SUCCESS;
}

// this function is for auxiliary process
static status_t init_tool_threads()
{
    int ret = init_node_status();
    if (ret != CM_SUCCESS) {
        deinit_node_status();
        return CM_ERROR;
    }

    ret = profile_stat_init();
    if (ret != CM_SUCCESS) {
        return CM_ERROR;
    }

    ret = init_exception_report();
    if (ret != CM_SUCCESS) {
        deinit_exception_report();
        return CM_ERROR;
    }

    LOG_RUN_INF("[DCF]Tool init succeed");
    return CM_SUCCESS;
}

// this function is for main process
static status_t init_main_threads(unsigned int node_id, const char *cfg_str)
{
    CM_RETURN_IFERR(cm_start_timer(g_timer()));
    CM_RETURN_IFERR_EX(init_logger(), CM_THROW_ERROR(ERR_INIT_LOGGER));

    LOG_OPER("dcf start, node_id=%u cfg_str=%s", node_id, cfg_str);

    status_t ret = md_init(node_id, cfg_str);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("metadata init failed, error code=%d, error info=%s",
                    cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
        return CM_ERROR;
    }

    ret = register_conf_type_cb();
    if (ret != CM_SUCCESS) {
        return CM_ERROR;
    }

    // network init
    ret = mec_init();
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("network init failed, error code=%d, error info=%s",
                    cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
        return CM_ERROR;
    }

    ret = stg_init();
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("storage init failed, error code=%d, error info=%s",
                    cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
        return CM_ERROR;
    }

    ret = elc_init();
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("election init failed, error code=%d, error info=%s",
                    cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
        return CM_ERROR;
    }

    ret = rep_init();
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("replication init failed, error code=%d, error info=%s",
                    cm_get_error_code(), cm_get_errormsg(cm_get_error_code()));
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t add_manual_notify_item()
{
    if (elc_stream_get_run_mode() != ELECTION_MANUAL) {
        return CM_SUCCESS;
    }

    uint32 node_id = md_get_cur_node();
    uint32 stream_list[CM_MAX_STREAM_COUNT];
    uint32 stream_count;
    if (md_get_stream_list(stream_list, &stream_count) != CM_SUCCESS) {
        LOG_DEBUG_ERR("md get stream list fail when add manual notify item");
        return CM_ERROR;
    }
    for (uint32 i = 0; i < stream_count; i++) {
        uint32 stream_id = stream_list[i];
        if (elc_get_node_role(stream_id) == DCF_ROLE_LEADER) {
            CM_RETURN_IFERR(elc_stream_set_role(stream_id, DCF_ROLE_LEADER));
            CM_RETURN_IFERR(elc_stream_set_votefor(stream_id, node_id));
            LOG_DEBUG_INF("Set votefor when add manual notify item, stream_id=%u, votefor=%u", stream_id, node_id);
            add_notify_item(stream_id, node_id, node_id, DCF_ROLE_FOLLOWER, DCF_ROLE_LEADER);
            LOG_RUN_INF("dcf start as manual mode, add notify item for leader, stream_id=%u, node_id=%u",
                stream_id, node_id);
        }
    }

    return CM_SUCCESS;
}

static void clear_resource()
{
    LOG_RUN_INF("begin to clear_resource");
    cm_profile_stat_uninit();
    // election
    elc_deinit();
    rep_stop();
    // storage
    stg_deinit();
    // network
    mec_deinit();

    // depend on metadata
    deinit_node_status();
    // exception report
    if (deinit_exception_report() != CM_SUCCESS) {
        LOG_DEBUG_ERR("deinit_exception_report failed");
    }
    // which clear the metadata, if a function depend on metadata, should before this function.
    md_uninit();
    cm_close_timer(g_timer());
    LOG_RUN_INF("clear_resource succeed");
}

int dcf_start(unsigned int node_id, const char *cfg_str)
{
    CM_CHECK_NULL_PTR(cfg_str);

    cm_latch_x(&g_dcf_latch, 0, NULL);
    if (g_dcf_inited) {
        cm_unlatch(&g_dcf_latch, NULL);
        return CM_SUCCESS;
    }
    init_dcf_errno_desc();
    cm_reset_error();

    do {
        status_t ret = init_main_threads(node_id, cfg_str);
        if (ret != CM_SUCCESS) {
            break;
        }

        ret = init_tool_threads();
        if (ret != CM_SUCCESS) {
            break;
        }

        ret = add_manual_notify_item();
        if (ret != CM_SUCCESS) {
            break;
        }

        (void)rep_check_param_majority_groups();
        LOG_RUN_INF("dcf start succeed.");
        g_dcf_inited = CM_TRUE;
        cm_unlatch(&g_dcf_latch, NULL);
        return CM_SUCCESS;
    } while (0);

    clear_resource();
    cm_unlatch(&g_dcf_latch, NULL);
    LOG_RUN_INF("dcf start failed");

    return CM_ERROR;
}

int dcf_write(unsigned int stream_id, const char *buffer, unsigned int length,
    unsigned long long key, unsigned long long *index)
{
    unsigned long long index_in;
    uint64 now = g_timer()->now;

    cm_reset_error();
    CM_RETURN_IF_FALSE(check_if_node_inited(stream_id));

    if (rep_get_can_write_flag(stream_id) != CM_TRUE) {
        LOG_DEBUG_ERR("[DCF]can_write_flag false,can't write now, key=%llu.", key);
        return CM_ERROR;
    }

    mem_pool_t* buddy_pool = get_mem_pool();
    if (length > (buddy_pool->max_size >> CM_2X_FIXED)) {
        LOG_DEBUG_ERR("[DCF]write_size[%u] is too big, don't support,key=%llu.", length, key);
        return CM_ERROR;
    }

    wait_if_node_blocked(stream_id);

    (void)cm_atomic32_inc(&g_node_status[stream_id].writing_cnt);
    status_t ret = rep_write(stream_id, buffer, length, key, ENTRY_TYPE_LOG, &index_in);
    (void)cm_atomic32_dec(&g_node_status[stream_id].writing_cnt);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[DCF]rep_write failed, error code=%d key=%llu", ret, key);
        return CM_ERROR;
    }

    ps_record(PS_WRITE, index_in, now);
    if (index != NULL) {
        *index = index_in;
        LOG_DEBUG_INF("[DCF]write succeed, stream_id=%u buflength=%u key=%llu index=%llu",
                      stream_id, length, key, *index);
    } else {
        LOG_DEBUG_INF("[DCF]write succeed, stream_id=%u buflength=%u key=%llu", stream_id, length, key);
    }

    return CM_SUCCESS;
}

int dcf_set_trace_key(unsigned long long trace_key)
{
    if (trace_key == (uint64)-1) {
        LOG_DEBUG_ERR("tracekey %llu is invalid", trace_key);
        return CM_ERROR;
    }
    set_trace_key(trace_key);

    return CM_SUCCESS;
}

int dcf_read(unsigned int stream_id, unsigned long long index, char* buffer, unsigned int length)
{
    CM_RETURN_IF_FALSE(check_if_node_inited(stream_id));
    log_entry_t *entry = stg_get_entry(stream_id, index);
    if (entry == NULL) {
        LOG_DEBUG_ERR("[DCF] index %llu not found", index);
        return CM_ERROR;
    }

    if (length < ENTRY_SIZE(entry)) {
        LOG_DEBUG_ERR("[DCF] buffer is too small, buffer[%u] - log[%u]", length, ENTRY_SIZE(entry));
        stg_entry_dec_ref(entry);
        return CM_ERROR;
    }

    errno_t ret = memcpy_s(buffer, length, ENTRY_BUF(entry), ENTRY_SIZE(entry));
    stg_entry_dec_ref(entry);
    return ret == EOK ? ENTRY_SIZE(entry) : CM_ERROR;
}

int dcf_truncate(unsigned int stream_id, unsigned long long first_index_kept)
{
    CM_RETURN_IF_FALSE(check_if_node_inited(stream_id));
    LOG_DEBUG_INF("dcf truncate, stream_id=%u first_index_kept=%llu", stream_id, first_index_kept);
    return stg_truncate_prefix(stream_id, first_index_kept);
}

int dcf_stop()
{
    LOG_OPER("dcf stop");

    cm_latch_x(&g_dcf_latch, 0, NULL);
    if (!g_dcf_inited) {
        cm_unlatch(&g_dcf_latch, NULL);
        return CM_SUCCESS;
    }
    cm_reset_error();

    // clear resource
    clear_resource();
    g_dcf_inited = CM_FALSE;
    cm_unlatch(&g_dcf_latch, NULL);

    LOG_RUN_INF("dcf stop succeed");
    return CM_SUCCESS;
}

static status_t append_local_node(unsigned int stream_id, cJSON *obj)
{
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "local_node_id", md_get_cur_node()));
    dcf_role_t role = elc_get_node_role(stream_id);
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddStringToObject(obj, "role", md_get_rolename_by_type(role)));

    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "term", elc_get_current_term(stream_id)));
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "run_mode", elc_stream_get_run_mode()));
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "work_mode", elc_get_work_mode(stream_id)));

    param_value_t elc_timeout;
    param_value_t auto_elc_pri_en;
    param_value_t hb_interval;
    param_value_t elc_switch_thd;
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_ELECTION_TIMEOUT, &elc_timeout));
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_AUTO_ELC_PRIORITY_EN, &auto_elc_pri_en));
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_HEARTBEAT_INTERVAL, &hb_interval));
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_ELECTION_SWITCH_THRESHOLD, &elc_switch_thd));
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "hb_interval", hb_interval.value_hb_interval));
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "elc_timeout", elc_timeout.value_elc_timeout));
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "auto_elc_pri_en",
        auto_elc_pri_en.value_auto_elc_priority_en));
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "elc_switch_thd",
        elc_switch_thd.value_elc_switch_thd));

    elc_stream_lock_s(stream_id);
    uint32 my_group = elc_stream_get_my_group(stream_id);
    uint64 my_prio = elc_stream_get_priority(stream_id);
    uint32 leader_group = elc_stream_get_leader_group(stream_id);
    elc_stream_unlock(stream_id);
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "group", my_group));
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "priority", my_prio));
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "leader_group", leader_group));

    bool32 is_in_major = elc_is_in_majority(stream_id);
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "is_in_major", is_in_major));

    uint64 index = stg_get_applied_index(stream_id);
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "applied_index", index));
    index = rep_get_commit_index(stream_id);
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "commit_index", index));
    index = stg_first_index(stream_id);
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "first_index", index));
    index = stg_last_index(stream_id);
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "last_index", index));

    if (elc_get_node_role(stream_id) == DCF_ROLE_LEADER) {
        CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "cluster_min_apply_idx",
            rep_get_cluster_min_apply_idx(stream_id)));
    }

    return CM_SUCCESS;
}

static bool32 is_node_leader(uint32 stream_id, uint32 node_id)
{
    if (node_id == CM_INVALID_NODE_ID) {
        return CM_FALSE;
    }

    uint32 votefor = elc_get_votefor(stream_id);
    uint32 cur_node = md_get_cur_node();
    param_value_t value;
    dcf_work_mode_t work_mode = elc_get_work_mode(stream_id);
    uint32 old_leader = elc_get_old_leader(stream_id);
    bool32 cond = (node_id == votefor);
    if (md_get_param(DCF_PARAM_RUN_MODE, &value) != CM_SUCCESS) {
        return CM_FALSE;
    }
    if (cur_node == node_id) {
        return (cond && (elc_get_node_role(stream_id) == DCF_ROLE_LEADER));
    }
    if (value.value_mode == ELECTION_AUTO && work_mode == WM_NORMAL) {
        cond = cond && (node_id == old_leader) && mec_is_ready(stream_id, node_id, PRIV_HIGH);
    }
    return cond;
}

static status_t append_leader_node(unsigned int stream_id, cJSON *obj)
{
    uint32 node_id = elc_get_votefor(stream_id);
    if (!is_node_leader(stream_id, node_id)) {
        CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNullToObject(obj, "leader_id"));
        CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNullToObject(obj, "leader_ip"));
        CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNullToObject(obj, "leader_port"));
        return CM_SUCCESS;
    }
    dcf_node_t node_item;
    CM_RETURN_IFERR(md_get_node(node_id, &node_item));
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "leader_id", node_item.node_id));
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddStringToObject(obj, "leader_ip", node_item.ip));
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "leader_port", node_item.port));
    return CM_SUCCESS;
}

static status_t append_stream_node_detail(unsigned int stream_id, cJSON *obj)
{
    uint32 node_list[CM_MAX_NODE_COUNT];
    uint32 node_count;
    cJSON *node_array = cJSON_CreateArray();

    CM_RETURN_IFERR(md_get_stream_nodes(stream_id, node_list, &node_count));
    for (uint32 i = 0; i < node_count; i++) {
        uint32 node_id = node_list[i];
        dcf_node_t node_item;
        CM_RETURN_IFERR(md_get_node(node_id, &node_item));

        cJSON *node = cJSON_CreateObject();
        CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(node, "node_id", node_item.node_id));
        CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddStringToObject(node, "ip", node_item.ip));
        CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(node, "port", node_item.port));
        if (is_node_leader(stream_id, node_id)) {
            CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddStringToObject(node, "role",
                md_get_rolename_by_type(DCF_ROLE_LEADER)));
        } else {
            CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddStringToObject(node, "role",
                md_get_rolename_by_type((node_item.default_role == DCF_ROLE_LEADER)
                                        ? DCF_ROLE_FOLLOWER : node_item.default_role)));
        }

        if (elc_get_node_role(stream_id) == DCF_ROLE_LEADER) {
            log_id_t match_idx = rep_leader_get_match_index(stream_id, node_id);
            CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(node, "next_index",
                rep_leader_get_next_index(stream_id, node_id)));
            CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(node, "match_index", match_idx.index));
            CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(node, "apply_index",
                rep_leader_get_apply_index(stream_id, node_id)));
        }

        if (cJSON_AddItemToArray(node_array, node) == CM_FALSE) {
            LOG_DEBUG_ERR("cJSON AddItemToArray fail when append_stream_node_detail");
            return CM_ERROR;
        }
    }

    if (cJSON_AddItemToObject(obj, "nodes", node_array) == CM_FALSE) {
        LOG_DEBUG_ERR("cJSON AddItemToObject fail when append_stream_node_detail");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t append_stream_info(unsigned int stream_id, cJSON *obj)
{
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "stream_id", stream_id));
    CM_RETURN_IFERR(append_local_node(stream_id, obj));
    CM_RETURN_IFERR(append_leader_node(stream_id, obj));
    CM_RETURN_IFERR(append_stream_node_detail(stream_id, obj));
    return CM_SUCCESS;
}

static status_t append_cluster_info(cJSON *obj)
{
    uint32 current_node_id = md_get_cur_node();
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "local_node_id", current_node_id));

    uint32 stream_list[CM_MAX_STREAM_COUNT];
    uint32 stream_count;
    CM_RETURN_IFERR(md_get_streams_by_node(current_node_id, stream_list, &stream_count));
    cJSON *stream_array = cJSON_CreateArray();
    for (uint32 i = 0; i < stream_count; i++) {
        uint32 stream_id = stream_list[i];
        cJSON *stream_obj = cJSON_CreateObject();
        if (append_stream_info(stream_id, stream_obj) != CM_SUCCESS) {
            cJSON_Delete(stream_obj);
            cJSON_Delete(stream_array);
            return CM_ERROR;
        }
        if (cJSON_AddItemToArray(stream_array, stream_obj) == CM_FALSE) {
            LOG_DEBUG_ERR("cJSON AddItemToArray fail when append_cluster_info");
            cJSON_Delete(stream_obj);
            cJSON_Delete(stream_array);
            return CM_ERROR;
        }
    }
    if (cJSON_AddItemToObject(obj, "stream_list", stream_array) == CM_FALSE) {
        LOG_DEBUG_ERR("cJSON AddItemToObject fail when append_cluster_info");
        cJSON_Delete(stream_array);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

int dcf_query_cluster_info(char* buffer, unsigned int length)
{
    cm_reset_error();

    if (buffer == NULL || length == 0) {
        LOG_DEBUG_ERR("buffer=%p or length=%u invalid", buffer, length);
        CM_THROW_ERROR(ERR_NULL_PTR);
        return 0;
    }

    int error_no = memset_s(buffer, length, 0, length);
    if (error_no != EOK) {
        LOG_DEBUG_ERR("dcf_query_cluster_info, memset_s return failed, errno=%d", error_no);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, error_no);
        return 0;
    }

    cJSON *obj = cJSON_CreateObject();
    status_t ret = append_cluster_info(obj);
    if (ret != CM_SUCCESS) {
        CM_THROW_ERROR(ERR_QUERY_DCF_INFO_ERR, "append_cluster_info failed", ret);
        LOG_DEBUG_ERR("dcf_query_cluster_info, %s, error code=%d", "append_cluster_info failed", ret);
        cJSON_Delete(obj);
        return 0;
    }
    error_no = cJSON_PrintPreallocated(obj, buffer, length, 0);
    if (!error_no) {
        CM_THROW_ERROR(ERR_QUERY_DCF_INFO_ERR, "cJSON_PrintPreallocated failed", error_no);
        LOG_DEBUG_ERR("dcf_query_cluster_info, cJSON_PrintPreallocated failed");
        cJSON_Delete(obj);
        return 0;
    }
    cJSON_Delete(obj);
    return (strlen(buffer) + 1);
}

int dcf_query_stream_info(unsigned int stream_id, char* buffer, unsigned int length)
{
    cm_reset_error();
    if (!check_if_node_inited(stream_id)) {
        CM_THROW_ERROR(ERR_QUERY_DCF_INFO_ERR, "check_if_node_inited failed", -1);
        return 0;
    }

    if (buffer == NULL || length == 0) {
        LOG_DEBUG_ERR("buffer=%p or length=%u invalid", buffer, length);
        CM_THROW_ERROR(ERR_NULL_PTR);
        return 0;
    }

    int error_no = memset_s(buffer, length, 0, length);
    if (error_no != EOK) {
        LOG_DEBUG_ERR("dcf_query_stream_info, memset_s return failed, errno=%d", error_no);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, error_no);
        return 0;
    }

    cJSON *obj = cJSON_CreateObject();
    status_t ret = append_stream_info(stream_id, obj);
    if (ret != CM_SUCCESS) {
        CM_THROW_ERROR(ERR_QUERY_DCF_INFO_ERR, "dcf_query_stream_info failed", ret);
        LOG_DEBUG_ERR("dcf_query_stream_info, %s, error code=%d", "append_stream_info failed", ret);
        cJSON_Delete(obj);
        return 0;
    }

    error_no = cJSON_PrintPreallocated(obj, buffer, length, 0);
    if (!error_no) {
        CM_THROW_ERROR(ERR_QUERY_DCF_INFO_ERR, "dcf_query_stream_info failed", error_no);
        LOG_DEBUG_ERR("dcf_query_stream_info, cJSON_PrintPreallocated failed");
        cJSON_Delete(obj);
        return 0;
    }

    cJSON_Delete(obj);
    return (strlen(buffer) + 1);
}

int dcf_query_leader_info(unsigned int stream_id, char *ip, unsigned int ip_len, unsigned int *port,
    unsigned int *node_id)
{
    cm_reset_error();

    if (!check_if_node_inited(stream_id)) {
        CM_THROW_ERROR(ERR_QUERY_DCF_INFO_ERR, "check_if_node_inited failed", CM_ERROR);
        return CM_ERROR;
    }

    if (ip == NULL || ip_len == 0 || port == NULL || node_id == NULL) {
        CM_THROW_ERROR(ERR_NULL_PTR);
        LOG_DEBUG_ERR("ip=%p or ip_len=%u or port=%p or node_id=%p invalid", ip, ip_len, port, node_id);
        return CM_ERROR;
    }

    uint32 votefor = elc_get_votefor(stream_id);
    if (votefor == CM_INVALID_NODE_ID) {
        ip[0] = '\0';
        *port = 0;
    } else {
        dcf_node_t node_item;
        CM_RETURN_IFERR(md_get_node(votefor, &node_item));
        MEMS_RETURN_IFERR(strncpy_sp(ip, ip_len, node_item.ip, strlen(node_item.ip)));
        *port = node_item.port;
        *node_id = node_item.node_id;
    }
    return CM_SUCCESS;
}

int dcf_query_statistics_info(char *buffer, unsigned int length)
{
    if (buffer == NULL || length == 0) {
        return CM_ERROR;
    }
    cm_reset_error();

    MEMS_RETURN_IFERR(memset_s(buffer, length, 0, length));
    cJSON *obj = cJSON_CreateObject();
    status_t ret = util_append_statistics_info(obj);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("DCF query statistics info failed, %s, error code=%d", "append cluster info failed", ret);
        cJSON_Delete(obj);
        return 0;
    }
    if (!cJSON_PrintPreallocated(obj, buffer, length, 0)) {
        cJSON_Delete(obj);
        return 0;
    }
    cJSON_Delete(obj);
    return (strlen(buffer) + 1);
}

int dcf_get_errorno()
{
    return cm_get_error_code();
}

const char* dcf_get_error(int code)
{
    return cm_get_errormsg(code);
}

status_t add_member_request(unsigned int stream_id, unsigned int node_id, const char* ip, unsigned int port,
    unsigned int role)
{
    dcf_node_t node;
    node.node_id = node_id;
    MEMS_RETURN_IFERR(strncpy_s(node.ip, CM_MAX_IP_LEN, ip, strlen(ip) + 1));
    node.port = port;
    node.default_role = role;
    node.voting_weight = CM_ELC_NORS_WEIGHT;
    node.group = CM_DEFAULT_GROUP_ID;
    node.priority = CM_DEFAULT_ELC_PRIORITY;

    CM_RETURN_IFERR(md_add_stream_member(stream_id, &node));
    uint32 size;
    char *md_buf = (char *)malloc(CM_METADATA_DEF_MAX_LEN);
    if (md_buf == NULL) {
        LOG_DEBUG_ERR("add_member_request malloc failed");
        return CM_ERROR;
    }
    CM_RETURN_IFERR_EX(md_to_string(md_buf, CM_METADATA_DEF_MAX_LEN, &size), CM_FREE_PTR(md_buf));
    CM_RETURN_IFERR_EX(rep_write(stream_id, md_buf, size, CFG_LOG_KEY(CM_NODE_ID_ALL, OP_FLAG_ADD),
        ENTRY_TYPE_CONF, NULL), CM_FREE_PTR(md_buf));
    CM_FREE_PTR(md_buf);
    return CM_SUCCESS;
}

#define SLEEP_TIME_PER 100
#define MIN_SLEEP_TIME 3000
status_t wait_process(unsigned int wait_timeout_ms)
{
    uint32 wait_time = (wait_timeout_ms < MIN_SLEEP_TIME) ? MIN_SLEEP_TIME : wait_timeout_ms;
    timespec_t begin = cm_clock_now();
    do {
        cm_sleep(SLEEP_TIME_PER);
        if (md_get_status() == META_NORMAL) {
            return CM_SUCCESS;
        }
    } while (((uint64)(cm_clock_now() - begin)) / MICROSECS_PER_MILLISEC < wait_time);

    if (md_get_status() == META_NORMAL) {
        return CM_SUCCESS;
    }
    LOG_DEBUG_ERR("timeout, wait_time=%u ms", wait_time);
    return CM_TIMEDOUT;
}
int dcf_add_member(unsigned int stream_id, unsigned int node_id, const char *ip, unsigned int port,
    dcf_role_t role, unsigned int wait_timeout_ms)
{
    LOG_OPER("dcf add member, stream_id=%u node_id=%u ip=%s port=%u role=%d wait_timeout_ms=%u",
        stream_id, node_id, ip, port, role, wait_timeout_ms);

    cm_reset_error();
    CM_RETURN_IF_FALSE(check_if_node_inited(stream_id));
    if (node_id == CM_INVALID_NODE_ID || node_id >= CM_MAX_NODE_COUNT) {
        LOG_DEBUG_ERR("node_id=%u invalid", node_id);
        return CM_ERROR;
    }
    if (ip == NULL) {
        LOG_DEBUG_ERR("ip is null");
        return CM_ERROR;
    }
    if (cm_check_ip_valid(ip) != CM_TRUE) {
        LOG_DEBUG_ERR("ip=%s invalid", ip);
        return CM_ERROR;
    }
    if (elc_get_node_role(stream_id) != DCF_ROLE_LEADER) {
        LOG_DEBUG_ERR("current node is not leader.");
        return CM_ERROR;
    }
    CM_RETURN_IFERR(md_set_status(META_CATCH_UP));
    if (add_member_request(stream_id, node_id, ip, port, role) != CM_SUCCESS) {
        CM_RETURN_IFERR(md_set_status(META_NORMAL));
        return CM_ERROR;
    }
    return wait_process(wait_timeout_ms);
}

status_t remove_member_request(unsigned int stream_id, unsigned int node_id)
{
    CM_RETURN_IFERR(md_remove_stream_member(stream_id, node_id));
    uint32 size;
    char *md_buf = (char *)malloc(CM_METADATA_DEF_MAX_LEN);
    if (md_buf == NULL) {
        LOG_DEBUG_ERR("remove_member_request malloc failed");
        return CM_ERROR;
    }
    CM_RETURN_IFERR_EX(md_to_string(md_buf, CM_METADATA_DEF_MAX_LEN, &size), CM_FREE_PTR(md_buf));
    CM_RETURN_IFERR_EX(rep_write(stream_id, md_buf, size, CFG_LOG_KEY(CM_NODE_ID_ALL, OP_FLAG_REMOVE),
        ENTRY_TYPE_CONF, NULL), CM_FREE_PTR(md_buf));
    CM_FREE_PTR(md_buf);
    return CM_SUCCESS;
}

int dcf_remove_member(unsigned int stream_id, unsigned int node_id, unsigned int wait_timeout_ms)
{
    LOG_OPER("dcf remove member, stream_id=%u node_id=%u wait_timeout_ms=%u",
        stream_id, node_id, wait_timeout_ms);

    cm_reset_error();
    CM_RETURN_IF_FALSE(check_if_node_inited(stream_id));
    if (elc_get_node_role(stream_id) != DCF_ROLE_LEADER) {
        LOG_DEBUG_ERR("current node is not leader.");
        return CM_ERROR;
    }
    CM_RETURN_IFERR(md_set_status(META_CATCH_UP));
    if (remove_member_request(stream_id, node_id) != CM_SUCCESS) {
        CM_RETURN_IFERR(md_set_status(META_NORMAL));
        LOG_DEBUG_ERR("remove_member fail, stream_id=%u, node_id=%u", stream_id, node_id);
        return CM_ERROR;
    }
    return wait_process(wait_timeout_ms);
}

status_t change_member_request(uint32 stream_id, uint32 node_id, dcf_change_member_t *change_info)
{
    CM_RETURN_IFERR(md_change_stream_member(stream_id, node_id, change_info));
    uint32 size;
    char *md_buf = (char *)malloc(CM_METADATA_DEF_MAX_LEN);
    if (md_buf == NULL) {
        LOG_DEBUG_ERR("change_member_role_request malloc failed");
        return CM_ERROR;
    }
    CM_RETURN_IFERR_EX(md_to_string(md_buf, CM_METADATA_DEF_MAX_LEN, &size), CM_FREE_PTR(md_buf));
    CM_RETURN_IFERR_EX(rep_write(stream_id, md_buf, size, CFG_LOG_KEY(node_id, change_info->op_type),
        ENTRY_TYPE_CONF, NULL), CM_FREE_PTR(md_buf));
    CM_FREE_PTR(md_buf);
    return CM_SUCCESS;
}

status_t decode_change_member_req(mec_message_t *pack, dcf_change_member_t *change_info)
{
    CM_RETURN_IFERR(mec_get_int32(pack, (int32*)&change_info->op_type));
    CM_RETURN_IFERR(mec_get_int32(pack, (int32*)&change_info->new_role));
    CM_RETURN_IFERR(mec_get_int32(pack, (int32*)&change_info->new_group));
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&change_info->new_priority));
    return CM_SUCCESS;
}

status_t encode_change_member_req(mec_message_t *pack, const dcf_change_member_t *change_info)
{
    CM_RETURN_IFERR(mec_put_int32(pack, change_info->op_type));
    CM_RETURN_IFERR(mec_put_int32(pack, change_info->new_role));
    CM_RETURN_IFERR(mec_put_int32(pack, change_info->new_group));
    CM_RETURN_IFERR(mec_put_int64(pack, change_info->new_priority));
    return CM_SUCCESS;
}

status_t change_member_req(uint32 stream_id, uint32 leader_id, dcf_change_member_t *change_info)
{
    mec_message_t pack;
    uint32 src_node = md_get_cur_node();
    if (mec_alloc_pack(&pack, MEC_CMD_CHANGE_MEMBER_RPC_REQ, src_node, leader_id, stream_id) != CM_SUCCESS) {
        LOG_DEBUG_ERR("change_member_req:mec_alloc_pack failed.stream_id=%u,leader_id=%u,src_node=%u",
            stream_id, leader_id, src_node);
        return CM_ERROR;
    }

    if (encode_change_member_req(&pack, change_info) != CM_SUCCESS) {
        mec_release_pack(&pack);
        LOG_DEBUG_ERR("change_member_req, encode fail.");
        return CM_ERROR;
    }

    LOG_DEBUG_INF("send change_member_req: stream=%u,src=%u,leader_id=%u,op_type=%u.",
        stream_id, src_node, leader_id, change_info->op_type);
    status_t ret = mec_send_data(&pack);
    mec_release_pack(&pack);
    return ret;
}

status_t leader_change_member_nowait(uint32 stream_id, uint32 node_id, dcf_change_member_t *change_info)
{
    /* voter_num must >3 before change node to passive */
    if (NEED_CHANGE_ROLE(change_info->op_type) && change_info->new_role == DCF_ROLE_PASSIVE) {
        uint32 voter_num = 0;
        if (md_get_voter_num(stream_id, &voter_num) != CM_SUCCESS) {
            LOG_DEBUG_ERR("get voter_num failed.");
            return CM_ERROR;
        }
        if (voter_num <= CM_LEAST_VOTER) {
            LOG_DEBUG_ERR("voter_num=%u is not enough, can't change node=%u to passive.", voter_num, node_id);
            return CM_ERROR;
        }
    }

    CM_RETURN_IFERR(md_set_status(META_CATCH_UP));
    if (change_member_request(stream_id, node_id, change_info) != CM_SUCCESS) {
        LOG_DEBUG_ERR("change node[%u]'s member failed.", node_id);
        CM_RETURN_IFERR(md_set_status(META_NORMAL));
        return CM_ERROR;
    }

    LOG_DEBUG_INF("change_member end, node_id=%u, op_type=%u.", node_id, change_info->op_type);
    return CM_SUCCESS;
}

status_t change_member_req_proc(mec_message_t *pack)
{
    uint32 stream_id = pack->head->stream_id;
    uint32 src_node_id = pack->head->src_inst;
    LOG_DEBUG_INF("recv change_member_req: stream_id=%u, src_node=%u", stream_id, src_node_id);

    if (!I_AM_LEADER(stream_id)) {
        LOG_DEBUG_ERR("I'm not leader now, can't change node[%u]'s member.", src_node_id);
        return CM_ERROR;
    }

    dcf_change_member_t change_info;
    CM_RETURN_IFERR(decode_change_member_req(pack, &change_info));
    if (NEED_CHANGE_ROLE(change_info.op_type) && src_node_id == md_get_cur_node()) {
        LOG_DEBUG_ERR("src_node[%u] is leader now, can't change role.", src_node_id);
        return CM_ERROR;
    }

    return leader_change_member_nowait(stream_id, src_node_id, &change_info);
}

status_t leader_change_member_process(uint32 stream_id, uint32 node_id, dcf_change_member_t *change_info,
    unsigned int wait_timeout_ms)
{
    CM_RETURN_IFERR(leader_change_member_nowait(stream_id, node_id, change_info));
    return wait_process(wait_timeout_ms);
}

status_t nonleader_change_member_process(uint32 stream_id, uint32 leader, uint32 node_id,
    dcf_change_member_t *change_info, unsigned int wait_timeout_ms)
{
    if (md_get_cur_node() != node_id) {
        LOG_DEBUG_ERR("nonleader can only change self's member, node_id=%u.", node_id);
        return CM_ERROR;
    }

    CM_RETURN_IFERR(md_set_status(META_CATCH_UP));
    CM_RETURN_IFERR_EX(change_member_req(stream_id, leader, change_info), md_set_status(META_NORMAL));
    timespec_t begin = cm_clock_now();
    uint32 op_type = change_info->op_type;
    while (((uint64)(cm_clock_now() - begin)) / MICROSECS_PER_MILLISEC < wait_timeout_ms) {
        cm_sleep(CM_SLEEP_10_FIXED);
        if ((NEED_CHANGE_ROLE(op_type) && elc_get_node_role(stream_id) != change_info->new_role) ||
            (NEED_CHANGE_GROUP(op_type) && elc_get_my_group(stream_id) != change_info->new_group) ||
            (NEED_CHANGE_PRIORITY(op_type) && elc_get_my_priority(stream_id) != change_info->new_priority)) {
            continue;
        }
        LOG_DEBUG_INF("change self's member success, op_type=%u", op_type);
        return CM_SUCCESS;
    }
    LOG_DEBUG_ERR("change self's member timeout, wait_time=%u ms", wait_timeout_ms);
    CM_RETURN_IFERR(md_set_status(META_NORMAL));
    return CM_TIMEDOUT;
}

int dcf_change_member(const char *change_str, unsigned int wait_timeout_ms)
{
    uint32 stream_id = CM_INVALID_STREAM_ID;
    uint32 node_id = CM_INVALID_NODE_ID;
    dcf_change_member_t change_info = {0};

    cm_reset_error();
    CM_CHECK_NULL_PTR(change_str);
    LOG_OPER("dcf change member, change_str=%s wait_timeout_ms=%u", change_str, wait_timeout_ms);

    CM_RETURN_IFERR(parse_change_member_str(change_str, &stream_id, &node_id, &change_info));
    CM_RETURN_IF_FALSE(check_if_node_inited(stream_id));
    if (NEED_CHANGE_ROLE(change_info.op_type) &&
        (change_info.new_role != DCF_ROLE_FOLLOWER && change_info.new_role != DCF_ROLE_PASSIVE)) {
        LOG_DEBUG_ERR("change member's role to (%u) is not support.", change_info.new_role);
        return CM_ERROR;
    }
    dcf_node_t node_info;
    CM_RETURN_IFERR(md_get_stream_node_ext(stream_id, node_id, &node_info));
    if (NEED_CHANGE_ROLE(change_info.op_type) && node_info.default_role == DCF_ROLE_LOGGER) {
        LOG_DEBUG_ERR("change LOGGER's role is not support.");
        return CM_ERROR;
    }

    uint32 leader = elc_get_votefor(stream_id);
    if (leader == CM_INVALID_NODE_ID) {
        LOG_DEBUG_ERR("leader=%d invalid, can't change member now.", CM_INVALID_NODE_ID);
        return CM_ERROR;
    }
    if (NEED_CHANGE_ROLE(change_info.op_type) && node_id == leader) {
        LOG_DEBUG_ERR("node_id (%u) is leader, can't change role.", node_id);
        return CM_ERROR;
    }

    if (I_AM_LEADER(stream_id)) {
        LOG_DEBUG_INF("I'm leader, change node[%u]'s member now.", node_id);
        return leader_change_member_process(stream_id, node_id, &change_info, wait_timeout_ms);
    } else {
        LOG_DEBUG_INF("I'm not leader, change node[%u]'s member now.", node_id);
        return nonleader_change_member_process(stream_id, leader, node_id, &change_info, wait_timeout_ms);
    }
}

#define CHANGE_ROLE_BUFFER_SIZE   (uint32)256

int dcf_change_member_role(unsigned int stream_id, unsigned int node_id, dcf_role_t new_role,
    unsigned int wait_timeout_ms)
{
    char change_str[CHANGE_ROLE_BUFFER_SIZE] = {0};
    PRTS_RETURN_IFERR(snprintf_s(change_str, CHANGE_ROLE_BUFFER_SIZE, CHANGE_ROLE_BUFFER_SIZE - 1,
        "[{\"stream_id\":%u,\"node_id\":%u,\"role\":\"%s\"}]", stream_id, node_id, md_get_rolename_by_type(new_role)));
    return dcf_change_member(change_str, wait_timeout_ms);
}

int dcf_set_applied_index(unsigned int stream_id, unsigned long long index)
{
    cm_reset_error();
    LOG_OPER("dcf set applied index, stream_id=%u index=%llu", stream_id, index);
    if (stream_id == CM_INVALID_STREAM_ID || stream_id >= CM_MAX_STREAM_COUNT) {
        return CM_ERROR;
    }
    return stg_set_applied_index(stream_id, index);
}

int dcf_get_cluster_min_applied_idx(unsigned int stream_id, unsigned long long* index)
{
    CM_RETURN_IF_FALSE(check_if_node_inited(stream_id));

    if (index == NULL) {
        LOG_DEBUG_ERR("index is null");
        return CM_ERROR;
    }

    *index = rep_get_cluster_min_apply_idx(stream_id);
    return CM_SUCCESS;
}

int dcf_get_leader_last_index(unsigned int stream_id, unsigned long long* index)
{
    CM_RETURN_IF_FALSE(check_if_node_inited(stream_id));

    if (index == NULL) {
        LOG_DEBUG_ERR("index is null");
        return CM_ERROR;
    }

    *index = rep_get_leader_last_index(stream_id);
    if (*index == CM_INVALID_INDEX_ID) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

int dcf_get_last_index(unsigned int stream_id, unsigned long long* index)
{
    CM_RETURN_IF_FALSE(check_if_node_inited(stream_id));

    if (index == NULL) {
        LOG_DEBUG_ERR("index is null");
        return CM_ERROR;
    }

    *index = rep_get_last_index(stream_id);
    if (*index == CM_INVALID_INDEX_ID) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

int dcf_get_node_last_disk_index(unsigned int stream_id, unsigned int node_id, unsigned long long* index)
{
    CM_RETURN_IF_FALSE(check_if_node_inited(stream_id));

    if (index == NULL) {
        LOG_DEBUG_ERR("index is null");
        return CM_ERROR;
    }

    /* check if stream node_id exist */
    CM_RETURN_IFERR(md_check_stream_node_exist(stream_id, node_id));

    if (elc_get_node_role(stream_id) != DCF_ROLE_LEADER) {
        LOG_DEBUG_ERR("current node is not leader.");
        return CM_ERROR;
    }

    *index = rep_leader_get_match_index(stream_id, node_id).index;
    return CM_SUCCESS;
}

#define CHECK_IF_ROLE_CHANGE(stream_id, old_role)           \
    do {                               \
        dcf_role_t _new_role_ = elc_get_node_role(stream_id); \
        if (SECUREC_UNLIKELY(_new_role_ != (old_role))) { \
            LOG_DEBUG_ERR("node role changed, old_role=%d, new_role=%d.", old_role, _new_role_); \
            return CM_ERROR; \
        } \
    } while (0)

bool32 log_catch_up(uint32 stream_id, uint32 node_id)
{
    uint64 my_idx;
    uint64 cmp_idx;
    my_idx = stg_last_log_id(stream_id).index;
    if (I_AM_LEADER(stream_id)) {
        cmp_idx = rep_leader_get_match_index(stream_id, node_id).index;
    } else {
        cmp_idx = rep_follower_get_leader_last_idx(stream_id);
        cmp_idx = MAX(get_block_last_index(stream_id), cmp_idx);
    }

    return ((my_idx == cmp_idx) && (my_idx != 0));
}

int dcf_promote_leader(unsigned int stream_id, unsigned int node_id, unsigned int wait_timeout_ms)
{
    CM_RETURN_IF_FALSE(check_if_node_inited(stream_id));

    LOG_OPER("dcf promote leader, stream_id=%u node_id=%u wait_timeout_ms=%u",
        stream_id, node_id, wait_timeout_ms);

    /* PASSIVE and LOGGER can't be promoted */
    dcf_node_t node_info;
    CM_RETURN_IFERR(md_get_stream_node_ext(stream_id, node_id, &node_info));
    dcf_role_t role = node_info.default_role;
    if (role == DCF_ROLE_PASSIVE || role == DCF_ROLE_LOGGER) {
        LOG_DEBUG_ERR("promote role (%d) to leader is not support.", role);
        return CM_ERROR;
    }

    uint32 leader = elc_get_votefor(stream_id);
    if (leader == CM_INVALID_NODE_ID) {
        LOG_DEBUG_ERR("leader=%d invalid, can't promote now.", CM_INVALID_NODE_ID);
        return CM_ERROR;
    }
    if (node_id == leader) {
        LOG_DEBUG_INF("node_id (%u) is already leader.", node_id);
        return CM_SUCCESS;
    }

    dcf_role_t original_role = elc_get_node_role(stream_id);
    if (original_role != DCF_ROLE_LEADER && md_get_cur_node() != node_id) {
        LOG_DEBUG_ERR("follower can only promote self now, node_id=%u.", node_id);
        return CM_ERROR;
    }

    if (wait_timeout_ms == 0) {
        LOG_DEBUG_INF("wait_timeout_ms is 0, promote directly.");
        return elc_promote_leader(stream_id, node_id);
    }

    set_block_ack(stream_id, NO_ACK, CM_INVALID_INDEX_ID);
    CM_RETURN_IFERR(block_node_req(stream_id, leader, wait_timeout_ms));
    timespec_t begin = cm_clock_now();
    block_ack_t ack = get_block_ack(stream_id);
    while (((uint64)(cm_clock_now() - begin)) / MICROSECS_PER_MILLISEC < wait_timeout_ms) {
        if (ack == ERROR_ACK) {
            LOG_DEBUG_ERR("recv error ack, ack=%d.", ack);
            return CM_ERROR;
        } else if (ack == SUCCESS_ACK) {
            if (log_catch_up(stream_id, node_id)) {
                LOG_DEBUG_INF("catch_up leader, promote now.");
                return elc_promote_leader(stream_id, node_id);
            }
        }
        CHECK_IF_ROLE_CHANGE(stream_id, original_role);
        cm_sleep(CM_SLEEP_1_FIXED);
        ack = get_block_ack(stream_id);
    }

    LOG_DEBUG_ERR("not yet catchup or block_ack timeout, ack=%d.", ack);
    return CM_ERROR;
}

int dcf_timeout_notify(unsigned int stream_id)
{
    CM_RETURN_IF_FALSE(check_if_node_inited(stream_id));

    timespec_t now = cm_clock_now();
    uint32 elc_times = elc_stream_get_elc_timeout_ms() * MICROSECS_PER_MILLISEC;

    if (stream_id != 0) {
        return elc_stream_set_timeout(stream_id, now - elc_times);
    } else {
        uint32 stream_list[CM_MAX_STREAM_COUNT];
        uint32 stream_count;
        CM_RETURN_IFERR(md_get_stream_list(stream_list, &stream_count));
        for (uint32 i = 0; i < stream_count; i++) {
            (void)elc_stream_set_timeout(stream_list[i], now - elc_times);
        }
        return CM_SUCCESS;
    }
}

int dcf_node_is_healthy(unsigned int stream_id, dcf_role_t* node_role, unsigned int* is_healthy)
{
    CM_RETURN_IF_FALSE(check_if_node_inited(stream_id));
    return elc_node_is_healthy(stream_id, node_role, is_healthy);
}

int dcf_set_work_mode(unsigned int stream_id, dcf_work_mode_t work_mode, unsigned int vote_num)
{
    CM_RETURN_IF_FALSE(check_if_node_inited(stream_id));

    LOG_OPER("dcf set work mode, stream_id=%u work_mode=%d vote_num=%u", stream_id, work_mode, vote_num);

    return elc_set_work_mode(stream_id, work_mode, vote_num);
}

int dcf_check_if_all_logs_applied(unsigned int stream_id, unsigned int *all_applied)
{
    CM_RETURN_IF_FALSE(check_if_node_inited(stream_id));

    if (all_applied == NULL) {
        LOG_DEBUG_ERR("all_applied pointer is null");
        return CM_ERROR;
    }

    /* check if stream node_id exist */
    CM_RETURN_IFERR(md_check_stream_node_exist(stream_id, md_get_cur_node()));

    *all_applied = rep_get_can_write_flag(stream_id);
    LOG_DEBUG_INF("all_applied_flag=%u", *all_applied);

    return CM_SUCCESS;
}

/*
    Internal Invocation
*/
void dcf_set_exception(int stream_id, dcf_exception_t exception)
{
    g_dcf_exception.stream_id = (uint32)stream_id;
    g_dcf_exception.exception = exception;
}

int dcf_send_msg(unsigned int stream_id, unsigned int dest_node_id, const char* msg, unsigned int msg_size)
{
    CM_RETURN_IF_FALSE(check_if_node_inited(stream_id));
    if (dest_node_id == CM_INVALID_NODE_ID || dest_node_id >= CM_MAX_NODE_COUNT) {
        LOG_DEBUG_ERR("The msg parameter from dest_node_id is invalid.");
        return CM_ERROR;
    }

    if (msg == NULL || msg_size == 0) {
        LOG_DEBUG_ERR("The msg parameter from dcf_send_msg is invalid.");
        return CM_ERROR;
    }
    if (msg_size > SIZE_K(512)) {
        LOG_DEBUG_ERR("The size of msg exceed 512K.");
        return CM_ERROR;
    }
    uint32 src_node_id = md_get_cur_node();
    mec_message_t pack;
    CM_RETURN_IFERR(mec_alloc_pack(&pack, MEC_CMD_SEND_COMMON_MSG, src_node_id, dest_node_id, stream_id));
    if (mec_put_bin(&pack, msg_size, msg) != CM_SUCCESS) {
        LOG_DEBUG_ERR("Put msg into pack failed.");
        mec_release_pack(&pack);
        return CM_ERROR;
    }
    status_t status = mec_send_data(&pack);
    mec_release_pack(&pack);
    return status;
}

status_t get_stream_node_list(uint32 stream_id, uint64* inst_bits)
{
    uint32 node_list[CM_MAX_NODE_COUNT];
    uint32 node_count;
    CM_RETURN_IFERR(md_get_stream_nodes(stream_id, node_list, &node_count));
    uint32 current_node_id = md_get_cur_node();
    for (uint32 i = 0; i < node_count; i++) {
        uint32 id = node_list[i];
        if (id != current_node_id) {
            MEC_SET_BRD_INST(inst_bits, id);
        }
    }
    return CM_SUCCESS;
}

int dcf_broadcast_msg(unsigned int stream_id, const char* msg, unsigned int msg_size)
{
    CM_RETURN_IF_FALSE(check_if_node_inited(stream_id));
    if (msg == NULL || msg_size == 0) {
        LOG_DEBUG_ERR("The msg parameter from dcf_send_msg is invalid.");
        return CM_ERROR;
    }
    if (msg_size > SIZE_K(512)) {
        LOG_DEBUG_ERR("The size of msg exceed 512K.");
        return CM_ERROR;
    }
    uint64 inst_bits[INSTS_BIT_SZ] = {0};
    uint64 success_inst[INSTS_BIT_SZ];
    /* get all follow node id */
    CM_RETURN_IFERR(get_stream_node_list(stream_id, inst_bits));
    uint32 src_node_id = md_get_cur_node();
    mec_message_t pack;
    CM_RETURN_IFERR(mec_alloc_pack(&pack, MEC_CMD_SEND_COMMON_MSG, src_node_id, CM_INVALID_NODE_ID, stream_id));
    if (mec_put_bin(&pack, msg_size, msg) != CM_SUCCESS) {
        LOG_DEBUG_ERR("Put msg into pack failed.");
        mec_release_pack(&pack);
        return CM_ERROR;
    }
    mec_broadcast(stream_id, inst_bits, &pack, success_inst);
    LOG_DEBUG_INF("Send msg broadcast, local node_id=%d, stream_id=%u", src_node_id, stream_id);
    mec_release_pack(&pack);
    return CM_SUCCESS;
}

#define DCF_PAUSE_TIME 1000000
/*
    Suspend replication log for this node
*/
int dcf_pause_rep(unsigned int stream_id, unsigned int node_id, unsigned int time_us)
{
    CM_RETURN_IF_FALSE(check_if_node_inited(stream_id));
    if (node_id == CM_INVALID_NODE_ID || node_id >= CM_MAX_NODE_COUNT) {
        LOG_DEBUG_ERR("The msg parameter from node_id is invalid.");
        return CM_ERROR;
    }
    LOG_OPER("dcf set pausing time for replication, stream_id=%u node_id=%d time_us=%u", stream_id, node_id, time_us);
    if (time_us > DCF_PAUSE_TIME) {
        LOG_DEBUG_ERR("time_us %u is greater than 1000000.", time_us);
        return CM_ERROR;
    }
    if (!I_AM_LEADER(stream_id)) {
        return CM_ERROR;
    }
    rep_set_pause_time(stream_id, node_id, time_us);

    return CM_SUCCESS;
}

int dcf_demote_follower(unsigned int stream_id)
{
    cm_reset_error();
    CM_RETURN_IF_FALSE(check_if_node_inited(stream_id));
    LOG_OPER("dcf demote follower, stream_id=%u", stream_id);
    return elc_demote_follower(stream_id);
}

#define UNIVERSAL_WAIT_TIME_OUT 3000

static uint32 alloc_req_id(dcf_parallel_msg_t* parallel_msg)
{
    uint32 req_id = MAX_PARALLEL_MAX_NUM;
    cm_spin_lock(&parallel_msg->lock, NULL);
    for (int i = 0; i < MAX_PARALLEL_MAX_NUM; i++) {
        uint32 cur_id = parallel_msg->cursor;
        parallel_msg->cursor = (cur_id + 1) % MAX_PARALLEL_MAX_NUM;
        if (parallel_msg->req_id_status[cur_id] == 0) {
            parallel_msg->req_id_status[cur_id] = 1;
            req_id = cur_id;
            break;
        }
    }
    cm_spin_unlock(&parallel_msg->lock);
    return req_id;
}

static inline void free_req_id(dcf_parallel_msg_t* parallel_msg, uint32 req_id)
{
    cm_spin_lock(&parallel_msg->lock, NULL);
    parallel_msg->req_id_status[req_id] = 0;
    cm_spin_unlock(&parallel_msg->lock);
}

static inline uint64 get_commit_index_result(uint32 req_id)
{
    return (uint64)cm_atomic_get(&g_consensus_hc_info.ack_result[req_id]);
}

static inline void set_commit_index_result(uint32 req_id, uint64 result)
{
    (void)cm_atomic_set(&g_consensus_hc_info.ack_result[req_id], result);
}

status_t send_fetching_commit_index_remote_req(unsigned int stream_id, uint32 is_consensus, uint32 req_id)
{
    uint32 leader_node = elc_get_votefor(stream_id);
    if (leader_node == CM_INVALID_NODE_ID) {
        LOG_DEBUG_ERR("[DCF]leader=%d invalid, can't send consensus msg req now.", CM_INVALID_NODE_ID);
        return CM_ERROR;
    }

    uint32 src_node = md_get_cur_node();
    mec_message_t pack;
    CM_RETURN_IFERR(mec_alloc_pack(&pack, MEC_CMD_GET_COMMIT_INDEX_REQ, src_node, leader_node, stream_id));
    if (mec_put_int32(&pack, req_id) != CM_SUCCESS || mec_put_int32(&pack, is_consensus) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[DCF]consensus health-check encode failed, src_node=%u, leader=%u.", src_node, leader_node);
        mec_release_pack(&pack);
        return CM_ERROR;
    }
    status_t ret = mec_send_data(&pack);
    mec_release_pack(&pack);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[DCF]send consensus health-check req failed, src_node=%u, leader=%u.", src_node, leader_node);
    }
    return ret;
}

static inline uint64 get_universal_write_index(uint32 req_id)
{
    return (uint64)cm_atomic_get(&g_universal_write_info.ack_result[req_id]);
}

static inline void set_universal_write_index(uint32 req_id, uint64 index)
{
    (void)cm_atomic_set(&g_universal_write_info.ack_result[req_id], index);
}

status_t send_universal_write_req(unsigned int stream_id, const char *buffer, unsigned int length,
    unsigned long long key, uint32 req_id)
{
    uint32 leader = elc_get_votefor(stream_id);
    if (leader == CM_INVALID_NODE_ID) {
        LOG_DEBUG_ERR("[DCF]leader=%d invalid, can't send universal write req now.", CM_INVALID_NODE_ID);
        return CM_ERROR;
    }

    uint32 src_node = md_get_cur_node();
    mec_message_t pack;
    CM_RETURN_IFERR(mec_alloc_pack(&pack, MEC_CMD_UNIVERSAL_WRITE_REQ, src_node, leader, stream_id));
    if (mec_put_int32(&pack, req_id) != CM_SUCCESS
        || mec_put_int64(&pack, key) != CM_SUCCESS
        || mec_put_bin(&pack, length, buffer) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[DCF]universal write encode failed, src_node=%u, leader=%u.", src_node, leader);
        mec_release_pack(&pack);
        return CM_ERROR;
    }
    status_t ret = mec_send_data(&pack);
    mec_release_pack(&pack);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[DCF]send universal write req failed, src_node=%u, leader=%u.", src_node, leader);
    }
    return ret;
}

int dcf_universal_write(unsigned int stream_id, const char *buffer, unsigned int length,
    unsigned long long key, unsigned long long *index)
{
    cm_reset_error();
    CM_RETURN_IF_FALSE(check_if_node_inited(stream_id));

    if (buffer == NULL || length == 0) {
        LOG_DEBUG_ERR("[DCF]buffer(%p) or length(%d) error.", buffer, length);
        return CM_ERROR;
    }

    if (I_AM_LEADER(stream_id)) {
        LOG_DEBUG_INF("[DCF]I am leader, write directly.");
        return dcf_write(stream_id, buffer, length, key, index);
    }

    uint32 req_id = alloc_req_id(&g_universal_write_info);
    if (req_id >= MAX_PARALLEL_MAX_NUM) {
        LOG_DEBUG_ERR("[DCF]req_id=%d invalid, try later.", req_id);
        return CM_ERROR;
    }
    uint64 last_write_index = 0;
    set_universal_write_index(req_id, last_write_index);
    CM_RETURN_IFERR_EX(send_universal_write_req(stream_id, buffer, length, key, req_id),
        free_req_id(&g_universal_write_info, req_id));

    timespec_t begin = cm_clock_now();
    uint64 ack_index;
    while (((uint64)(cm_clock_now() - begin)) / MICROSECS_PER_MILLISEC < UNIVERSAL_WAIT_TIME_OUT) {
        ack_index = get_universal_write_index(req_id);
        if (ack_index > last_write_index) {
            LOG_DEBUG_INF("[DCF]universal write succeed, stream_id=%u buflength=%u key=%llu index=%llu req_id=%u",
                stream_id, length, key, ack_index, req_id);
            free_req_id(&g_universal_write_info, req_id);
            if (index != NULL) {
                *index = ack_index;
            }
            return CM_SUCCESS;
        }
        (void)cm_event_timedwait(&g_universal_write_info.event[req_id], CM_SLEEP_1_FIXED);
    }
    LOG_DEBUG_ERR("[DCF]universal write timeout %u ms, stream_id=%u buflength=%u key=%llu index=%llu req_id=%u",
        UNIVERSAL_WAIT_TIME_OUT, stream_id, length, key, ack_index, req_id);
    free_req_id(&g_universal_write_info, req_id);
    return CM_TIMEDOUT;
}

status_t universal_write_req_proc(mec_message_t *pack)
{
    uint32 stream_id = pack->head->stream_id;
    uint32 src_node = pack->head->src_inst;
    LOG_DEBUG_INF("[DCF]recv universal_write_req: stream_id=%u, src_node=%u", stream_id, src_node);

    uint32 req_id;
    CM_RETURN_IFERR(mec_get_int32(pack, (int32*)&req_id));
    uint64 key;
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&key));
    char *buf = NULL;
    uint32 len = 0;
    CM_RETURN_IFERR(mec_get_bin(pack, &len, (void **)&buf));

    uint64 write_index;
    if (dcf_write(stream_id, buf, len, key, &write_index) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[DCF]recv universal_write_req: dcf write failed.");
        return CM_ERROR;
    }

    mec_message_t ack_pack;
    CM_RETURN_IFERR(mec_alloc_pack(&ack_pack, MEC_CMD_UNIVERSAL_WRITE_ACK, md_get_cur_node(), src_node, stream_id));
    if (mec_put_int32(&ack_pack, req_id) != CM_SUCCESS
        || mec_put_int64(&ack_pack, write_index) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[DCF]recv universal_write_req: encode failed,write_index=%llu.", write_index);
        mec_release_pack(&ack_pack);
        return CM_ERROR;
    }
    status_t ret = mec_send_data(&ack_pack);
    mec_release_pack(&ack_pack);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[DCF]recv universal_write_req: send data failed.");
    }
    return ret;
}

status_t universal_write_ack_proc(mec_message_t *pack)
{
    uint32 stream_id = pack->head->stream_id;
    uint32 req_id;
    CM_RETURN_IFERR(mec_get_int32(pack, (int32*)&req_id));
    uint64 ack_write_index;
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&ack_write_index));
    LOG_DEBUG_INF("[DCF]recv universal_write_ack: stream_id=%u, req_id=%u, writeindex=%llu.",
        stream_id, req_id, ack_write_index);
    if (req_id < MAX_PARALLEL_MAX_NUM) {
        set_universal_write_index(req_id, ack_write_index);
        cm_event_notify(&g_universal_write_info.event[req_id]);
    } else {
        LOG_DEBUG_ERR("[DCF]recv universal_write_ack: req_id=%u error, writeindex=%llu.", req_id, ack_write_index);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static status_t dcf_get_commit_index_local(unsigned int stream_id, unsigned int is_consensus,
    unsigned long long* commit_index)
{
    dcf_role_t node_role = DCF_ROLE_UNKNOWN;
    unsigned int is_healthy = CM_FALSE;
    if (is_consensus) {
        if (dcf_node_is_healthy(stream_id, &node_role, &is_healthy) != CM_SUCCESS || !is_healthy) {
            LOG_DEBUG_ERR("[DCF]Health check failed or the node is not healthy for geting commit index.");
            return CM_ERROR;
        }
    }
    *commit_index = rep_get_data_commit_index(stream_id);
    LOG_DEBUG_INF("[DCF] dcf get local data commit index:%llu", *commit_index);

    return CM_SUCCESS;
}

status_t dcf_get_commit_index_req_proc(mec_message_t *pack)
{
    uint32 src_node = pack->head->src_inst;
    uint32 stream_id = pack->head->stream_id;
    uint64 commit_index = 0;
    LOG_DEBUG_INF("[DCF]Recv dcf_health_check_req: stream_id=%u, src_node=%u", stream_id, src_node);

    uint32 req_id;
    CM_RETURN_IFERR(mec_get_int32(pack, (int32*)&req_id));
    uint32 is_consensus = 0;
    CM_RETURN_IFERR(mec_get_int32(pack, (int32*)&is_consensus));

    if (I_AM_LEADER(stream_id)) {
        if (dcf_get_commit_index_local(stream_id, is_consensus, &commit_index) != CM_SUCCESS) {
            // the node is not leader, so send commit_index(0) to remote.
            LOG_DEBUG_ERR("[DCF]Recv get_commit_index_req: check health failed, so send commit_index(0) to remote.");
        }
    } else {
        // the node is not leader, so send commit_index(0) to remote.
        LOG_DEBUG_ERR("[DCF]Recv get_commit_index_req: it's not leader now.");
    }

    mec_message_t ack_pack;
    CM_RETURN_IFERR(mec_alloc_pack(&ack_pack, MEC_CMD_GET_COMMIT_INDEX_ACK, md_get_cur_node(), src_node, stream_id));
    if (mec_put_int32(&ack_pack, req_id) != CM_SUCCESS
        || mec_put_int64(&ack_pack, commit_index) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[DCF]Recv get_commit_index_req: encode failed, commit_index=%llu.", commit_index);
        mec_release_pack(&ack_pack);
        return CM_ERROR;
    }
    status_t ret = mec_send_data(&ack_pack);
    mec_release_pack(&ack_pack);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[DCF]Recv get_commit_index_req: send data failed.");
    }
    return ret;
}

status_t dcf_get_commit_index_ack_proc(mec_message_t *pack)
{
    uint32 stream_id = pack->head->stream_id;
    uint32 req_id;
    CM_RETURN_IFERR(mec_get_int32(pack, (int32*)&req_id));
    uint64 commit_index;
    CM_RETURN_IFERR(mec_get_int64(pack, (int64*)&commit_index));
    LOG_DEBUG_INF("[DCF]Recv get_commit_index_ack: stream_id=%u, req_id=%u, commit_index=%llu.",
        stream_id, req_id, commit_index);
    if (req_id < MAX_PARALLEL_MAX_NUM) {
        set_commit_index_result(req_id, commit_index);
        cm_event_notify(&g_consensus_hc_info.event[req_id]);
    } else {
        LOG_DEBUG_ERR("[DCF]recv get_commit_index_ack: req_id=%u error, commit_index=%llu.", req_id, commit_index);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

static int dcf_get_commit_index_remote(unsigned int stream_id, unsigned int is_consensus,
    unsigned long long* commit_index)
{
    uint32 req_id = alloc_req_id(&g_consensus_hc_info);
    if (req_id >= MAX_PARALLEL_MAX_NUM) {
        LOG_DEBUG_ERR("[DCF]Check health using req_id=%d invalid, try later.", req_id);
        return CM_ERROR;
    }
    int64 index_default = -1;
    set_commit_index_result(req_id, index_default);
    CM_RETURN_IFERR_EX(send_fetching_commit_index_remote_req(stream_id, is_consensus, req_id),
        free_req_id(&g_consensus_hc_info, req_id));

    timespec_t begin = cm_clock_now();
    uint64 result;
    while (((uint64)(cm_clock_now() - begin)) / MICROSECS_PER_MILLISEC < UNIVERSAL_WAIT_TIME_OUT) {
        result = get_commit_index_result(req_id);
        if ((int64)result != index_default) {
            free_req_id(&g_consensus_hc_info, req_id);

            LOG_DEBUG_INF("[DCF]leader check health succeed, stream_id=%u result=%llu req_id=%u",
                stream_id, result, req_id);
            *commit_index = result;
            return CM_SUCCESS;
        }
        (void)cm_event_timedwait(&g_consensus_hc_info.event[req_id], CM_SLEEP_1_FIXED);
    }
    LOG_DEBUG_ERR("[DCF]Waiting health-check timeout %u ms, stream_id=%u req_id=%u",
        UNIVERSAL_WAIT_TIME_OUT, stream_id, req_id);
    free_req_id(&g_consensus_hc_info, req_id);
    return CM_TIMEDOUT;
}

int dcf_get_data_commit_index(unsigned int stream_id, dcf_commit_index_type_t index_type, unsigned long long* index)
{
    CM_RETURN_IF_FALSE(check_if_node_inited(stream_id));
    if (index == NULL) {
        LOG_DEBUG_ERR("[DCF]The parameter index is null for geting commit index.");
        return CM_ERROR;
    }
    unsigned int is_consensus = CM_FALSE;

    if (index_type == DCF_LOCAL_COMMIT_INDEX) {
        return dcf_get_commit_index_local(stream_id, CM_FALSE, index);
    } else if (index_type == DCF_LEADER_COMMIT_INDEX) {
        is_consensus = CM_FALSE;
    } else if (index_type == DCF_CONSENSUS_COMMIT_INDEX) {
        is_consensus = CM_TRUE;
    } else {
        LOG_DEBUG_ERR("[DCF]Getting commit index for index_type=%d is over range.", index_type);
        return CM_ERROR;
    }

    if (I_AM_LEADER(stream_id)) {
        LOG_DEBUG_INF("[DCF]I am leader, and get commit index directly.");
        return dcf_get_commit_index_local(stream_id, is_consensus, index);
    } else {
        int ret = dcf_get_commit_index_remote(stream_id, is_consensus, index);
        if (ret != CM_SUCCESS) {
            LOG_DEBUG_ERR("[DCF]It's failed or timeout from leader for geting commit index.");
            return ret;
        }
    }

    return CM_SUCCESS;
}

int dcf_get_current_term_and_role(unsigned int stream_id, unsigned long long* term, dcf_role_t* role)
{
    CM_RETURN_IF_FALSE(check_if_node_inited(stream_id));
    if (term == NULL || role == NULL) {
        LOG_DEBUG_ERR("[DCF]term(%p) or role(%p) error.", term, role);
        return CM_ERROR;
    }
    return elc_get_current_term_and_role(stream_id, term, role);
}

int dcf_set_election_priority(unsigned int stream_id, unsigned long long priority)
{
    static date_t last[CM_MAX_STREAM_COUNT] = {0};
    if (stream_id >= CM_MAX_STREAM_COUNT) {
        LOG_DEBUG_ERR("[DCF]stream_id=%u invalid", stream_id);
        return CM_ERROR;
    }

    date_t now = g_timer()->now;
    if (now - last[stream_id] < MICROSECS_PER_SECOND) {
        LOG_DEBUG_INF("[DCF]interval too small.stream_id=%u priority=%llu can't set this time.", stream_id, priority);
        return CM_SUCCESS;
    }
    last[stream_id] = now;

    if (!elc_stream_get_auto_elc_pri_en()) {
        LOG_DEBUG_INF("[DCF]auto_priority disabled.stream_id=%u priority=%llu can't set.", stream_id, priority);
        return CM_SUCCESS;
    }

    CM_RETURN_IF_FALSE(check_if_node_inited(stream_id));
    elc_set_my_priority(stream_id, priority);
    return CM_SUCCESS;
}

#ifdef WIN32
const char *dcf_get_version()
{
    return "NONE";
}
#else
extern const char *dcf_get_version();
#endif

void dcf_set_timer(void *timer)
{
    cm_set_timer((gs_timer_t *)timer);
}

#ifdef __cplusplus
}
#endif
