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
 * cm_debug.h
 *
 *
 * IDENTIFICATION
 *    src/common/cm_utils/cm_debug.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_DEBUG_H_
#define __CM_DEBUG_H_

#include <stdio.h>
#include "cm_types.h"
#include "cm_log.h"


static inline void cm_assert(bool32 condition)
{
    if (!condition) {
        *((uint32 *)NULL) = 1;
    }
}

#ifdef DB_DEBUG_VERSION
#define CM_ASSERT(expr) cm_assert((bool32)(expr))
#else
#define CM_ASSERT(expr) ((void)(expr))
#endif

#ifdef WIN32
#define CM_STATIC_ASSERT(cond) typedef char __static_assert_t[!!(cond)]
#else
#define CM_STATIC_ASSERT(cond) typedef char __static_assert_t[1 - 2*(!!!(cond))]
#endif

static inline void cm_exit(int32 exitcode)
{
    _exit(exitcode);
}

#ifdef DB_DEBUG_VERSION
#define CM_MAGIC_DECLARE    uint32    cm_magic;
#define CM_MAGIC_SET(obj_declare, obj_struct) ((obj_declare)->cm_magic = obj_struct##_MAGIC)
#define CM_MAGIC_CHECK(obj_declare, obj_struct)                                         \
    do {                                                                                \
        if ((obj_declare) == NULL || ((obj_declare)->cm_magic != obj_struct##_MAGIC)) { \
            LOG_RUN_ERR("[FATAL] COMMON Halt!");                                    \
            CM_ASSERT(0);                                                               \
        }                                                                               \
    } while (0);

#define CM_MAGIC_CHECK_EX(obj_declare, obj_struct)                                      \
    do {                                                                                \
        if ((obj_declare) != NULL && ((obj_declare)->cm_magic != obj_struct##_MAGIC)) { \
            LOG_RUN_ERR("[FATAL] COMMON Halt!");                                    \
            CM_ASSERT(0);                                                               \
        }                                                                               \
    } while (0);
#else
#define CM_MAGIC_DECLARE
#define CM_MAGIC_SET(obj_declare, obj_struct) {}
#define CM_MAGIC_CHECK(obj_declare, obj_struct) {}
#define CM_MAGIC_CHECK_EX(obj_declare, obj_struct) {}
#endif

#endif
