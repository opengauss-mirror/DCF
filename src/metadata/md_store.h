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
 * md_store.h
 *    metadata process
 *
 * IDENTIFICATION
 *    src/metadata/md_store.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __MD_STORE_H__
#define __MD_STORE_H__

#include "cm_defs.h"
#include "cm_file.h"

status_t md_store_init();

status_t md_store_write(char *buf, int32 size);

// buf need be freed by invoker
status_t md_store_read(char **buf, int32 *size);

#endif