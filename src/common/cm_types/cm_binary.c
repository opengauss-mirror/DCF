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
 * cm_binary.c
 *
 *
 * IDENTIFICATION
 *    src/common/cm_types/cm_binary.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_binary.h"

#ifdef __cplusplus
extern "C" {
#endif

const char g_hex_map[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

const uint8 g_hex2byte_map[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

status_t cm_str2bin(const char *str, bool32 hex_prefix, binary_t *bin, uint32 bin_max_sz)
{
    text_t text;
    cm_str2text((char *)str, &text);
    return cm_text2bin(&text, hex_prefix, bin, bin_max_sz);
}

status_t cm_verify_hex_string(const text_t *text)
{
    // if the prefix exists, the text->len must be >= 2
    bool32 has_prefix = (text->len >= 2) && ((text->str[0] == '\\') || (text->str[0] == '0')) &&
                        ((text->str[1] == 'x') || (text->str[1] == 'X'));
    if (has_prefix) {
        if (text->len < 3) {  // min hex string is 0x0
            CM_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "hex");
            return CM_ERROR;
        }
    }

    uint32 i = has_prefix ? 2 : 0;
    uint8 half_byte = 0;
    for (; i < text->len; i++) {
        half_byte = cm_hex2int8((uint8)text->str[i]);
        if (half_byte == 0xFF) {
            CM_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "hex");
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

status_t cm_text2bin(const text_t *text, bool32 hex_prefix, binary_t *bin, uint32 bin_max_sz)
{
    uint32 pos = 0;

    if (hex_prefix) {
        if (text->len < 3) {  // min hex string is 0x0
            CM_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "hex");
            return CM_ERROR;
        }
    }

    // set the starting position
    uint32 i = hex_prefix ? 2 : 0;
    uint32 len = text->len;
    bool32 is_quotes = (text->str[0] == 'X') && (text->str[1] == '\'');
    if (is_quotes) {
        len = text->len - 1;
    }

    if (len % 2 == 1) {  // handle odd length hex string
        if (pos >= bin_max_sz) {
            CM_THROW_ERROR(ERR_BUFFER_OVERFLOW, pos, bin_max_sz);
            return CM_ERROR;
        }

        bin->bytes[pos] = cm_hex2int8((uint8)text->str[i]);
        if (bin->bytes[pos] == 0xFF) {
            CM_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "hex");
            return CM_ERROR;
        }
        pos++;
        i++;
    }

    for (; i < len; i += 2) {  // 1 byte needs 2 chars to express
        uint8 half_byte = cm_hex2int8((uint8)text->str[i]);
        if (half_byte == 0xFF) {
            CM_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "hex");
            return CM_ERROR;
        }

        if (pos >= bin_max_sz) {
            CM_THROW_ERROR(ERR_BUFFER_OVERFLOW, pos, bin_max_sz);
            return CM_ERROR;
        }

        bin->bytes[pos] = (uint8)(half_byte << 4);

        half_byte = cm_hex2int8((uint8)text->str[i + 1]);
        if (half_byte == 0xFF) {
            CM_THROW_ERROR(ERR_TEXT_FORMAT_ERROR, "hex");
            return CM_ERROR;
        }

        bin->bytes[pos] += half_byte;
        pos++;
    }

    bin->size = pos;

    return CM_SUCCESS;
}

status_t cm_bin2text(const binary_t *bin, bool32 hex_prefix, text_t *text)
{
    uint32 i, pos;
    uint32 buf_len;

    char *str = text->str;
    buf_len = text->len;
    if (hex_prefix) {
        if (bin->size * 2 + 2 > buf_len) {  // 1 byte needs 2 chars
            CM_THROW_ERROR(ERR_COVNERT_FORMAT_ERROR, "string");
            return CM_ERROR;
        }

        str[0] = '0';
        str[1] = 'x';

        pos = 2;  // if the prefix exists, the position must start from 2
    } else {
        if (bin->size * 2 > buf_len) { // 1 byte needs 2 chars
            CM_THROW_ERROR(ERR_COVNERT_FORMAT_ERROR, "string");
            return CM_ERROR;
        }

        pos = 0;
    }

    for (i = 0; i < bin->size; i++) {
        str[pos] = g_hex_map[(bin->bytes[i] & 0xF0) >> 4];
        pos++;
        str[pos] = g_hex_map[bin->bytes[i] & 0x0F];
        pos++;
    }

    text->len = pos;
    return CM_SUCCESS;
}

status_t cm_bin2str(const binary_t *bin, bool32 hex_prefix, char *str, uint32 buf_len)
{
    text_t tmp_text = {
        .str = str,
        .len = buf_len
    };

    if (cm_bin2text(bin, hex_prefix, &tmp_text) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (tmp_text.len >= buf_len) {
        CM_THROW_ERROR(ERR_BUFFER_OVERFLOW, tmp_text.len + 1, buf_len);
        return CM_ERROR;
    }
    str[tmp_text.len] = '\0';
    return CM_SUCCESS;
}


int32 cm_compare_bin(const binary_t *left, const binary_t *right)
{
    uint32 i, cmp_len;
    uchar c1, c2;

    cmp_len = (left->size < right->size) ? left->size : right->size;
    for (i = 0; i < cmp_len; i++) {
        c1 = (uchar)left->bytes[i];
        c2 = (uchar)right->bytes[i];

        if (c1 > c2) {
            return 1;
        } else if (c1 < c2) {
            return -1;
        }
    }

    return (left->size > right->size) ? 1 : ((left->size == right->size) ? 0 : -1);
}

status_t cm_concat_bin(binary_t *bin, uint32 bin_len, const binary_t *part)
{
    if (part->size != 0) {
        MEMS_RETURN_IFERR(memcpy_sp(bin->bytes + bin->size, (size_t)(bin_len - bin->size),
            part->bytes, (size_t)part->size));
    }
    bin->size += part->size;
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
