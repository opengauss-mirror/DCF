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
 * cm_binary.h
 *
 *
 * IDENTIFICATION
 *    src/common/cm_types/cm_binary.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_BINARY_H_
#define __CM_BINARY_H_

#include "cm_defs.h"
#include "cm_text.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_binary {
    uint8  *bytes;
    uint32  size;
} binary_t;

extern const uint8 g_hex2byte_map[];
extern const char  g_hex_map[];

static inline uint8 cm_hex2int8(uchar c)
{
    return g_hex2byte_map[c];
}

static inline void cm_rtrim0_binary(binary_t *bin)
{
    while (bin->size > 0 && (bin->bytes[bin->size - 1] == 0)) {
        --bin->size;
    }
}

status_t cm_verify_hex_string(const text_t *text);
status_t cm_bin2str(const binary_t *bin, bool32 hex_prefix, char *str, uint32 buf_len);
status_t cm_bin2text(const binary_t *bin, bool32 hex_prefix, text_t *text);
status_t cm_str2bin(const char *str, bool32 hex_prefix, binary_t *bin, uint32 bin_max_sz);
status_t cm_text2bin(const text_t *text, bool32 hex_prefix, binary_t *bin, uint32 bin_max_sz);
int32 cm_compare_bin(const binary_t *left, const binary_t *right);
status_t cm_concat_bin(binary_t *bin, uint32 bin_len, const binary_t *part);


#ifdef __cplusplus
}
#endif

#endif
