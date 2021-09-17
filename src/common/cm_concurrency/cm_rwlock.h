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
 * cm_rwlock.h
 *
 *
 * IDENTIFICATION
 *    src/common/cm_concurrency/cm_rwlock.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CM_RWLOCK_H__
#define __CM_RWLOCK_H__

#include "cm_defs.h"
#include "cm_error.h"

#ifdef WIN32
#include "cm_latch.h"

typedef latch_t  rwlock_t;

static inline status_t cm_rwlock_init(rwlock_t *rwlock)
{
    cm_latch_init(rwlock);
    return CM_SUCCESS;
}

static inline void cm_rwlock_rlock(rwlock_t *rwlock)
{
    cm_latch_s(rwlock, 0, CM_FALSE, NULL);
}

static inline void cm_rwlock_wlock(rwlock_t *rwlock)
{
    cm_latch_x(rwlock, 0, NULL);
}

static inline void cm_rwlock_unlock(rwlock_t *rwlock)
{
    cm_unlatch(rwlock, NULL);
}

static inline void cm_rwlock_deinit(rwlock_t *rwlock)
{
    return;
}
#else
#include <pthread.h>

typedef pthread_rwlock_t rwlock_t;

static inline status_t cm_rwlock_init(rwlock_t *rwlock)
{
    return pthread_rwlock_init(rwlock, NULL);
}

static inline void cm_rwlock_rlock(rwlock_t *rwlock)
{
    (void)pthread_rwlock_rdlock(rwlock);
}

static inline void cm_rwlock_wlock(rwlock_t *rwlock)
{
    (void)pthread_rwlock_wrlock(rwlock);
}

static inline void cm_rwlock_unlock(rwlock_t *rwlock)
{
    (void)pthread_rwlock_unlock(rwlock);
}

static inline void cm_rwlock_deinit(rwlock_t *rwlock)
{
    (void)pthread_rwlock_destroy(rwlock);
}

#endif

#endif