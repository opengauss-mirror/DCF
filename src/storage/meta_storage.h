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
 * meta_storage.h
 *    meta storage
 *
 * IDENTIFICATION
 *    src/storage/meta_storage.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __META_STORAGE_H__
#define __META_STORAGE_H__

#include "cm_defs.h"
#include "cm_file.h"
#include "cm_latch.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_stg_meta {
    char     *home;
    uint32    votedfor;
    uint64    version;
    uint64    curr_term;
    latch_t   latch;
} stg_meta_t;

// format of ctrl file
// | ------------------ meta version (64bits) ---------------------|
// | ------------------ current term (64bits) ---------------------|
// | -----------votedfor (32bits) | checksum (32bits) -------------|
#define META_OF_VERSION    0
#define META_OF_CURR_TERM  8
#define META_OF_VOTEDFOR   16
#define META_OF_CHECKSUM   20
#define STG_META_LENGTH    24

#define STG_RAFT_META_01  "dcf_ctrl_01"
#define STG_RAFT_META_02  "dcf_ctrl_02"

status_t read_meta_file(char *file_name, char *buf, bool32 *exists, bool32 *valid);
status_t init_stg_meta(stg_meta_t *stg_meta, char *home);
uint64 meta_get_current_term(stg_meta_t *stg_meta);
status_t meta_set_current_term(stg_meta_t *stg_meta, uint64 term);
uint32 meta_get_votedfor(stg_meta_t *stg_meta);
status_t meta_set_votedfor(stg_meta_t *stg_meta, uint32 votedfor);

#ifdef __cplusplus
}
#endif

#endif