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
#include "util_perf_stat.h"
#include "cm_ip.h"
#include "cJSON.h"
#include "util_profile_stat.h"
#include "stream.h"
#include "cb_func.h"
#include "mec_reactor.h"
#include "mec_instance.h"

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
    thread_t thread;
    cm_event_t event;
} block_info_t;

typedef struct st_dcf_status {
    node_status_t status;
    block_info_t block;
    latch_t latch;
} dcf_status_t;

typedef struct st_dcf_exception_report {
    cm_event_t      exception_event;
    thread_t        exception_thread;
    uint32          stream_id;
    dcf_exception_t exception;
    bool32          exception_init_flag;
} dcf_exception_report_t;

static dcf_status_t g_node_status[CM_MAX_STREAM_COUNT] = {{0}};

static latch_t    g_dcf_latch = {0};
static bool32     g_dcf_inited = CM_FALSE;

static usr_cb_msg_proc_t            g_cb_send_msg_notify = NULL;
static usr_cb_exception_notify_t    g_cb_exception_notify = NULL;
static dcf_exception_report_t       g_dcf_exception;
static bool32    g_node_inited = CM_FALSE;

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

static inline uint32 get_block_time(uint32 stream_id)
{
    dcf_status_t *node_status = &g_node_status[stream_id];
    cm_latch_s(&node_status->latch, 0, CM_FALSE, NULL);
    uint32 block_time = node_status->block.block_time_ms;
    cm_unlatch(&node_status->latch, NULL);
    return block_time;
}

static inline void set_block_ack(uint32 stream_id, block_ack_t ack)
{
    dcf_status_t *node_status = &g_node_status[stream_id];
    cm_latch_x(&node_status->latch, 0, NULL);
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
    mec_message_t pack;
    uint32 src_node = md_get_cur_node();
    CM_RETURN_IFERR(mec_alloc_pack(&pack, MEC_CMD_BLOCK_NODE_RPC_ACK, src_node, node_id, stream_id));
    if (mec_put_int32(&pack, ack) != CM_SUCCESS) {
        mec_release_pack(&pack);
        LOG_DEBUG_ERR("block node ack, encode fail.");
        return CM_ERROR;
    }
    LOG_DEBUG_INF("send blockack: stream=%u,src=%u,dst=%u,ack=%d.", stream_id, src_node, node_id, ack);
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
    LOG_DEBUG_INF("recv blockack: stream_id=%u, ack=%d.", stream_id, ack);

    ack = (ack == SUCCESS_ACK) ? SUCCESS_ACK : ERROR_ACK;
    set_block_ack(stream_id, ack);
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
            date_t begin = g_timer()->now;
            uint32 block_time_ms = get_block_time(stream_id);
            while (((uint64)(g_timer()->now - begin)) / MICROSECS_PER_MILLISEC < block_time_ms) {
                cm_sleep(1);
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

status_t change_role_req_proc(mec_message_t *pack);

status_t init_node_status()
{
    uint32 streams[CM_MAX_STREAM_COUNT];
    uint32 stream_count;

    if (g_node_inited) {
        LOG_RUN_INF("init_node_status already sucessful");
        return CM_SUCCESS;
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
    register_msg_process(MEC_CMD_CHANGE_ROLE_RPC_REQ, change_role_req_proc, PRIV_HIGH);
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
        date_t begin = g_timer()->now;
        while (status == NODE_BLOCKED) {
            if ((g_timer()->now - begin) > MICROSECS_PER_SECOND) {
                LOG_DEBUG_WAR("node is blocked now, waiting...");
                begin = g_timer()->now;
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

    LOG_OPER("dcf set param, param_name=%s param_value=%s", param_name, param_value);

    CM_RETURN_IFERR(md_verify_param(param_name, param_value, &param_type, &out_value));
    return md_set_param(param_type, &out_value);
}

int dcf_get_param(const char *param_name, char *param_value, unsigned int size)
{
    CM_CHECK_NULL_PTR(param_name);
    cm_reset_error();
    init_dcf_errno_desc();

    LOG_OPER("dcf get param, param_name=%s", param_name);

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

    status_t ret = init_main_threads(node_id, cfg_str);
    if (ret != CM_SUCCESS) {
        clear_resource();
        cm_unlatch(&g_dcf_latch, NULL);
        return CM_ERROR;
    }

    ret = init_tool_threads();
    if (ret != CM_SUCCESS) {
        clear_resource();
        cm_unlatch(&g_dcf_latch, NULL);
        return CM_ERROR;
    }

    ret = add_manual_notify_item();
    if (ret != CM_SUCCESS) {
        clear_resource();
        cm_unlatch(&g_dcf_latch, NULL);
        return CM_ERROR;
    }

    LOG_RUN_INF("dcf start succeed.");
    g_dcf_inited = CM_TRUE;
    cm_unlatch(&g_dcf_latch, NULL);
    return CM_SUCCESS;
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

    status_t ret = rep_write(stream_id, buffer, length, key, ENTRY_TYPE_LOG, &index_in);
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
    uint32 current_node_id = md_get_cur_node();
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "local_node_id", current_node_id));
    dcf_role_t role = elc_get_node_role(stream_id);
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddStringToObject(obj, "role", md_get_rolename_by_type(role)));

    uint64 term = elc_get_current_term(stream_id);
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "term", term));

    param_run_mode_t run_mode = elc_stream_get_run_mode();
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "run_mode", run_mode));

    dcf_work_mode_t work_mode = elc_get_work_mode(stream_id);
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "work_mode", work_mode));

    param_value_t elc_timeout;
    param_value_t hb_interval;
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_ELECTION_TIMEOUT, &elc_timeout));
    CM_RETURN_IFERR(md_get_param(DCF_PARAM_HEARTBEAT_INTERVAL, &hb_interval));
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "hb_interval", hb_interval.value_hb_interval));
    CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "elc_timeout", elc_timeout.value_elc_timeout));

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

static status_t append_leader_node(unsigned int stream_id, cJSON *obj)
{
    uint32 node_id = elc_get_votefor(stream_id);
    if (node_id == CM_INVALID_NODE_ID) {
        CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNullToObject(obj, "leader_id"));
        CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNullToObject(obj, "leader_ip"));
        CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNullToObject(obj, "leader_port"));
    } else {
        dcf_node_t node_item;
        CM_RETURN_IFERR(md_get_node(node_id, &node_item));
        CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "leader_id", node_item.node_id));
        CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddStringToObject(obj, "leader_ip", node_item.ip));
        CM_CHECK_CJSON_OPER_ERR_AND_RETURN(cJSON_AddNumberToObject(obj, "leader_port", node_item.port));
    }

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
        if (node_id == elc_get_votefor(stream_id)) {
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

    CM_RETURN_IFERR(md_add_stream_member(stream_id, &node));
    uint32 size;
    char *md_buf = (char *)malloc(CM_METADATA_DEF_MAX_LEN);
    if (md_buf == NULL) {
        LOG_DEBUG_ERR("add_member_request malloc failed");
        return CM_ERROR;
    }
    CM_RETURN_IFERR_EX(md_to_string(md_buf, CM_METADATA_DEF_MAX_LEN, &size), CM_FREE_PTR(md_buf));
    CM_RETURN_IFERR_EX(rep_write(stream_id, md_buf, size, 0, ENTRY_TYPE_CONF, NULL), CM_FREE_PTR(md_buf));
    CM_FREE_PTR(md_buf);
    return CM_SUCCESS;
}

#define SLEEP_TIME_PER 100
#define MIN_SLEEP_TIME 3000
status_t wait_process(unsigned int wait_timeout_ms)
{
    uint32 wait_time = (wait_timeout_ms < MIN_SLEEP_TIME) ? MIN_SLEEP_TIME : wait_timeout_ms;
    date_t begin = g_timer()->now;
    do {
        cm_sleep(SLEEP_TIME_PER);
        if (md_get_status() == META_NORMAL) {
            return CM_SUCCESS;
        }
    } while (((uint64)(g_timer()->now - begin)) / MICROSECS_PER_MILLISEC < wait_time);

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
    CM_RETURN_IFERR_EX(rep_write(stream_id, md_buf, size, 0, ENTRY_TYPE_CONF, NULL), CM_FREE_PTR(md_buf));
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

status_t change_member_role_request(unsigned int stream_id, unsigned int node_id, unsigned int role)
{
    CM_RETURN_IFERR(md_change_stream_member_role(stream_id, node_id, role));
    uint32 size;
    char *md_buf = (char *)malloc(CM_METADATA_DEF_MAX_LEN);
    if (md_buf == NULL) {
        LOG_DEBUG_ERR("change_member_role_request malloc failed");
        return CM_ERROR;
    }
    CM_RETURN_IFERR_EX(md_to_string(md_buf, CM_METADATA_DEF_MAX_LEN, &size), CM_FREE_PTR(md_buf));
    CM_RETURN_IFERR_EX(rep_write(stream_id, md_buf, size, 0, ENTRY_TYPE_CONF, NULL), CM_FREE_PTR(md_buf));
    CM_FREE_PTR(md_buf);
    return CM_SUCCESS;
}

status_t change_role_req(uint32 stream_id, uint32 leader_id, dcf_role_t new_role)
{
    mec_message_t pack;
    uint32 src_node = md_get_cur_node();
    if (mec_alloc_pack(&pack, MEC_CMD_CHANGE_ROLE_RPC_REQ, src_node, leader_id, stream_id) != CM_SUCCESS) {
        LOG_DEBUG_ERR("change_role_req:mec_alloc_pack failed.stream_id=%u,leader_id=%u,src_node=%u",
            stream_id, leader_id, src_node);
        return CM_ERROR;
    }
    if (mec_put_int32(&pack, new_role) != CM_SUCCESS) {
        mec_release_pack(&pack);
        LOG_DEBUG_ERR("change_role_req, encode fail.");
        return CM_ERROR;
    }
    LOG_DEBUG_INF("send change_role_req: stream=%u,src=%u,leader_id=%u,new_role=%u.",
        stream_id, src_node, leader_id, new_role);
    status_t ret = mec_send_data(&pack);
    mec_release_pack(&pack);
    return ret;
}

status_t leader_change_role_nowait(uint32 stream_id, uint32 node_id, dcf_role_t new_role)
{
    /* voter_num must >3 before change node to passive */
    if (new_role == DCF_ROLE_PASSIVE) {
        uint32 voter_num = 0;
        if (md_get_voter_num(stream_id, &voter_num) != CM_SUCCESS) {
            LOG_DEBUG_ERR("get voter_num fail.");
            return CM_ERROR;
        }
        if (voter_num <= CM_LEAST_VOTER) {
            LOG_DEBUG_ERR("voter_num=%u is not enough, can't change node=%u to passive.", voter_num, node_id);
            return CM_ERROR;
        }
    }

    CM_RETURN_IFERR(md_set_status(META_CATCH_UP));
    if (change_member_role_request(stream_id, node_id, new_role) != CM_SUCCESS) {
        LOG_DEBUG_ERR("change node[%u]'s role to new_role[%u] fail.", node_id, new_role);
        CM_RETURN_IFERR(md_set_status(META_NORMAL));
        return CM_ERROR;
    }

    LOG_DEBUG_INF("change_member_role end, node_id=%u, new_role=%u.", node_id, new_role);
    return CM_SUCCESS;
}


status_t change_role_req_proc(mec_message_t *pack)
{
    uint32 stream_id = pack->head->stream_id;
    uint32 src_node_id = pack->head->src_inst;
    LOG_DEBUG_INF("recv change_role_req: stream_id=%u, src_node=%u", stream_id, src_node_id);

    if (!I_AM_LEADER(stream_id)) {
        LOG_DEBUG_ERR("I'm not leader now, can't change node[%u]'s role.", src_node_id);
        return CM_ERROR;
    }

    if (src_node_id == md_get_cur_node()) {
        LOG_DEBUG_ERR("src_node[%u] is leader now, can't change role.", src_node_id);
        return CM_ERROR;
    }

    uint32 new_role;
    CM_RETURN_IFERR(mec_get_int32(pack, (int32*)&new_role));

    return leader_change_role_nowait(stream_id, src_node_id, new_role);
}

status_t leader_change_role_process(uint32 stream_id, uint32 node_id, dcf_role_t new_role, unsigned int wait_timeout_ms)
{
    CM_RETURN_IFERR(leader_change_role_nowait(stream_id, node_id, new_role));
    return wait_process(wait_timeout_ms);
}

status_t nonleader_change_role_process(uint32 stream_id, uint32 leader, uint32 node_id,
    dcf_role_t new_role, unsigned int wait_timeout_ms)
{
    if (md_get_cur_node() != node_id) {
        LOG_DEBUG_ERR("nonleader can only change self's role now, node_id=%u.", node_id);
        return CM_ERROR;
    }

    CM_RETURN_IFERR(md_set_status(META_CATCH_UP));
    CM_RETURN_IFERR_EX(change_role_req(stream_id, leader, new_role), md_set_status(META_NORMAL));
    date_t begin = g_timer()->now;
    while (((uint64)(g_timer()->now - begin)) / MICROSECS_PER_MILLISEC < wait_timeout_ms) {
        if (elc_get_node_role(stream_id) == new_role) {
            LOG_DEBUG_INF("change self's role to new_role[%u] success.", new_role);
            return CM_SUCCESS;
        }
        cm_sleep(1);
    }
    LOG_DEBUG_ERR("change self's role to new_role[%u] timeout, wait_time=%u ms", new_role, wait_timeout_ms);
    CM_RETURN_IFERR(md_set_status(META_NORMAL));
    return CM_TIMEDOUT;
}

int dcf_change_member_role(unsigned int stream_id, unsigned int node_id, dcf_role_t new_role,
    unsigned int wait_timeout_ms)
{
    LOG_OPER("dcf change member role, stream_id=%u node_id=%u new_role=%d wait_timeout_ms=%u",
        stream_id, node_id, new_role, wait_timeout_ms);
    cm_reset_error();
    CM_RETURN_IF_FALSE(check_if_node_inited(stream_id));
    if (new_role != DCF_ROLE_FOLLOWER && new_role != DCF_ROLE_PASSIVE) {
        LOG_DEBUG_ERR("change member's role to (%u) is not support.", new_role);
        return CM_ERROR;
    }

    dcf_node_t node_info;
    CM_RETURN_IFERR(md_get_stream_node_ext(stream_id, node_id, &node_info));
    if (node_info.default_role == DCF_ROLE_LOGGER) {
        LOG_DEBUG_ERR("change LOGGER's role is not support.");
        return CM_ERROR;
    }

    uint32 leader = elc_get_votefor(stream_id);
    if (leader == CM_INVALID_NODE_ID) {
        LOG_DEBUG_ERR("leader=%d invalid, can't change role now.", CM_INVALID_NODE_ID);
        return CM_ERROR;
    }
    if (node_id == leader) {
        LOG_DEBUG_ERR("node_id (%u) is leader, can't change role.", node_id);
        return CM_ERROR;
    }

    if (I_AM_LEADER(stream_id)) {
        LOG_DEBUG_INF("I'm leader, change node[%u]'s role now.", node_id);
        return leader_change_role_process(stream_id, node_id, new_role, wait_timeout_ms);
    } else {
        LOG_DEBUG_INF("I'm not leader, change node[%u]'s role now.", node_id);
        return nonleader_change_role_process(stream_id, leader, node_id, new_role, wait_timeout_ms);
    }
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

    set_block_ack(stream_id, NO_ACK);
    CM_RETURN_IFERR(block_node_req(stream_id, leader, wait_timeout_ms));
    date_t begin = g_timer()->now;
    block_ack_t ack = get_block_ack(stream_id);
    while (((uint64)(g_timer()->now - begin)) / MICROSECS_PER_MILLISEC < wait_timeout_ms) {
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
        cm_sleep(1);
        ack = get_block_ack(stream_id);
    }

    LOG_DEBUG_ERR("not yet catchup or block_ack timeout, ack=%d.", ack);
    return CM_ERROR;
}

int dcf_timeout_notify(unsigned int stream_id, unsigned int node_id)
{
    CM_RETURN_IF_FALSE(check_if_node_inited(stream_id));

    date_t now = g_timer()->now;
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


#ifdef WIN32
const char *dcf_get_version()
{
    return "NONE";
}
#else
extern const char *dcf_get_version();
#endif

#ifdef __cplusplus
}
#endif
