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
 * mec_instance.h
 *    mec process
 *
 * IDENTIFICATION
 *    src/network/mec/mec_instance.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __MEC_INSTANCE_H__
#define __MEC_INSTANCE_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_mec_instance {
    mec_profile_t      profile;
    mq_context_t       send_mq;
    mq_context_t       recv_mq;
    mec_context_t      mec_ctx;
    fragment_ctx_t     fragment_ctx;
    thread_t           daemon_thread;
    reactor_pool_t     reactor_pool[PRIV_CEIL];
    agent_pool_t       agent_pool[PRIV_CEIL];
    ssl_ctx_t         *ssl_acceptor_fd;
    ssl_ctx_t         *ssl_connector_fd;
} mec_instance_t;

#ifndef WIN32
pthread_key_t* addr_of_thread_key();
void delete_thread_key();
#endif
mem_pool_t* get_mem_pool();
mec_instance_t* get_mec_ptr();
thread_t* get_daemon_thread();
mq_context_t* get_send_mq_ctx();
mq_context_t* get_recv_mq_ctx();
mec_context_t* get_mec_ctx();
mec_profile_t* get_mec_profile();
fragment_ctx_t* get_fragment_ctx();
reactor_pool_t* get_mec_reactor(msg_priv_t priv);
agent_pool_t* get_mec_agent(msg_priv_t priv);

status_t mec_extend_pack(mec_message_t *pack);
status_t mec_send_fragment(mec_message_t *pack, const char *data, uint32 size);
bool32 mec_check_last(const uint64 inst_bits[INSTS_BIT_SZ], uint32 inst_id);
status_t mec_scale_out(uint32 inst_id, uint32 channel_id);
void compress_ctx_destructor(void *data);
status_t init_mec_profile(mec_profile_t *profile);
status_t mec_init_reactor();
status_t mec_init_core();
void mec_deinit_reactor();
void mec_pause_lsnr(lsnr_type_t type);
void mec_deinit_mq();
void fragment_ctx_deinit();
void mec_stop_lsnr();
void mec_destory_channels();
void mec_deinit_ssl();
status_t mec_put_msg_queue(const void *msg, bool32 is_send);
void get_broadcast_insts(const uint64 inst_bits[INSTS_BIT_SZ], char *buffer, uint32 buff_size);

#ifdef __cplusplus
}
#endif

#endif
