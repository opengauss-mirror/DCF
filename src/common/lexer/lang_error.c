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
 * lang_error.c
 *
 *
 * IDENTIFICATION
 *    src/common/lexer/lang_error.c
 *
 * -------------------------------------------------------------------------
 */

#include "lang_error.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
    __declspec(thread) src_loc_t g_tls_errloc = { 0 };
#else
    __thread src_loc_t g_tls_errloc = { 0 };
#endif

void lang_set_error_loc(src_loc_t loc)
{
    g_tls_errloc = loc;
}

static void register_errors()
{
    cm_register_error((uint16)ERR_LEX_SYNTAX_ERROR, "Syntax error : %s");
    cm_register_error((uint16)ERR_LEX_INVALID_NUMBER, "Invalid number : %s");
    cm_register_error((uint16)ERR_LEX_INVALID_ARRAY_FORMAT, "Invalid array format : %s");
}

static bool32 g_initialized = 0;
static spinlock_t lock;
void lang_error_init()
{
    if (!g_initialized) {
        cm_spin_lock(&lock, NULL);
        if (!g_initialized) {
            register_errors();
            g_initialized = CM_TRUE;
        }
        cm_spin_unlock(&lock);
    }
}

#ifdef __cplusplus
}
#endif
