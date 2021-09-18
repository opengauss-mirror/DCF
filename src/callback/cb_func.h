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
 * cb_func.h
 *    Headfile of dcf callback function implementation.
 *
 * IDENTIFICATION
 *    src/callback/cb_func.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DCF_CALLBACK_FUNC_H__
#define __DCF_CALLBACK_FUNC_H__

#ifdef __cplusplus
extern "C" {
#endif

usr_cb_thread_memctx_init_t get_dcf_worker_memctx_init_cb();

int cb_register_thread_memctx_init(usr_cb_thread_memctx_init_t cb_func);

#ifdef __cplusplus
}
#endif

#endif
