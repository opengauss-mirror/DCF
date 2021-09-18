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
 * test_main.c
 *    DCF test main
 *
 * IDENTIFICATION
 *    test/test_main/test_main.c
 *
 * -------------------------------------------------------------------------
 */
#include "stdio.h"
#include "stdlib.h"
#include "time.h"
#include "string.h"
#include "dcf_interface.h"
#ifdef WIN32
#include <windows.h>
#define cm_sleep(ms) Sleep(ms)
#else
#include <signal.h>
static inline void cm_sleep(int ms)
{
    struct timespec tq, tr;
    tq.tv_sec = ms / 1000;
    tq.tv_nsec = (ms % 1000) * 1000000;

    (void)nanosleep(&tq, &tr);
}
#endif


#ifndef _WIN32
static void sig_proc(int signal)
{
    exit(0);
}
#endif

int usr_cb_after_writer(unsigned int stream_id, unsigned long long index,
                        const char *buf, unsigned int size, unsigned long long key, int error_no)
{
    //printf("in usr_cb_after_writer, stream_id=%u, index=%lld \n", stream_id, index);
    return dcf_set_applied_index(stream_id, index);
}

int usr_cb_consensus_notify(unsigned int stream_id, unsigned long long index,
                            const char *buf, unsigned int size, unsigned long long key)
{
    //printf("in usr_cb_consensus_notify, stream_id=%u, index=%lld \n", stream_id, index);
    return dcf_set_applied_index(stream_id, index);
}

int usr_cb_status_changed_notify(unsigned int stream_id, dcf_role_t new_role)
{
    printf("in usr_cb_status_changed_notify, stream_id=%u, new_role=%u \n", stream_id, new_role);
    return 0;
}

int main(int argc, char *argv[])
{
    #ifndef _WIN32
        if (signal(SIGUSR1, sig_proc) == SIG_ERR) {
            printf("register SIGUSR1 sig_proc failed!\n");
        }
        if (signal(SIGUSR2, sig_proc) == SIG_ERR) {
            printf("register SIGUSR2 sig_proc failed!\n");
        }
    #endif

    const char * cfg_str;
    int node_id = 1;
    if (argc >= 2) {
        char* err = NULL;
        node_id =  (int)strtoll(argv[1], &err, 10);
        printf("current nodeid=%d\n", node_id);
    }
    if (argc >= 3) {
        cfg_str = argv[2];
        printf("cluster nodes:%s\n", cfg_str);
    } else {
        printf("no cluster nodes info\n");
        return 0;
    }

    printf("dcf lib version: %s\r\n", dcf_get_version());
    int ret = 0;
    if (node_id == 1) {
        ret = dcf_set_param("DATA_PATH", "./node1");
    } else if (node_id == 2) {
        ret = dcf_set_param("DATA_PATH", "./node2");
    } else if (node_id == 3) {
        ret = dcf_set_param("DATA_PATH", "./node3");
    } else if (node_id == 4) {
        ret = dcf_set_param("DATA_PATH", "./node4");
    } else if (node_id == 5) {
        ret = dcf_set_param("DATA_PATH", "./node5");
    }

    if (ret !=0) {
        printf("set param DATA_PATH fail\n");
    }

    ret = dcf_set_param("FLOW_CONTROL_CPU_THRESHOLD", "80");
    if (ret !=0) {
        printf("set param FLOW_CONTROL_CPU_THRESHOLD fail\n");
    }
    ret = dcf_set_param("FLOW_CONTROL_NET_QUEUE_MESSAGE_NUM_THRESHOLD", "100");
    if (ret !=0) {
        printf("set param FLOW_CONTROL_NET_QUEUE_MESSAGE_NUM_THRESHOLD fail\n");
    }
    ret = dcf_set_param("FLOW_CONTROL_DISK_RAWAIT_THRESHOLD", "12000");
    if (ret !=0) {
        printf("set param FLOW_CONTROL_DISK_RAWAIT_THRESHOLD fail\n");
    }

    //dcf_set_param("SSL_CA", "/opt/data/huxl/protect/cacert.pem");
    //dcf_set_param("SSL_KEY", "/opt/data/huxl/protect/server.key");
    //dcf_set_param("SSL_CERT", "/opt/data/huxl/protect/server.crt");
    //dcf_set_param("SSL_PWD_PLAINTEXT", "Gauss_234");

    if (dcf_register_after_writer(usr_cb_after_writer) !=0) {
        printf("dcf_register_after_writer fail\n");
    }
    if (dcf_register_consensus_notify(usr_cb_consensus_notify) !=0) {
        printf("dcf_register_consensus_notify fail\n");
    }
    if (dcf_register_status_notify(usr_cb_status_changed_notify) !=0) {
        printf("dcf_register_status_notify fail\n");
    }

    printf("after add stream\n");

    if (dcf_start(node_id, cfg_str) == 0) {
        printf("start success, node_id=%d\n", node_id);
    } else {
         printf("start fail,node_id=%d\n", node_id);
         return -1;
    }

    char buffer[2001] = {0};
    dcf_query_cluster_info(buffer, 2000);
    printf("cluster info=%s\n", buffer);

    dcf_query_stream_info(1, buffer, 2000);
    printf("cluster stream info=%s\n", buffer);
    char* str = "str0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
        "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";

    int max_len = (int)strlen(str);
    long long count = 0;
    do {
        int size = rand() % (max_len-1) + 1;
        if(dcf_write(1,str,size, 0, NULL) != 0){
            printf("write fail.\n");
        } else{
            printf("write succeed,size=%d\n",size);
        }
        if ((++count) % 10000 == 0) {
            if (dcf_truncate(1, count/2) != 0) {
                printf("truncate fail.\n");
            } else {
                printf("truncate succeed index = %lld.\n", count/2);
            }
        }

        cm_sleep(200);
    } while (1);
    return 0;
}