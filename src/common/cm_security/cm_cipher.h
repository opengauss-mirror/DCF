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
 * cm_cipher.h
 *
 *
 * IDENTIFICATION
 *    src/common/cm_security/cm_cipher.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CM_CIPHER_H__
#define __CM_CIPHER_H__

#include <fcntl.h>
#include <sys/stat.h>
#include "cm_types.h"
#include "cm_error.h"
#include "cm_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RANDOM_LEN 16
#define ITERATE_TIMES 10000

typedef struct st_cipher {
    uchar  rand[RANDOM_LEN + 1];   /* rand used to derive key */
    uchar  salt[RANDOM_LEN + 1];   /* salt used to derive key */
    uchar  IV[RANDOM_LEN + 1];     /* IV used to encrypt/decrypt text */
    uchar  cipher_text[CM_PASSWORD_BUFFER_SIZE]; /* cipher text */
    uint32 cipher_len;             /* cipher text length */
} cipher_t;

status_t cm_encrypt_pwd(uchar *plain_text, uint32 plain_len, cipher_t *cipher);
status_t cm_decrypt_pwd(cipher_t *cipher, uchar *plain_text, uint32 *plain_len);
status_t cm_rand(uchar *buf, uint32 len);

#ifdef __cplusplus
}
#endif

#endif
