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
 * compress.h
 *    compress process
 *
 * IDENTIFICATION
 *    src/network/compress/compress.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __COMPRESS_H__
#define __COMPRESS_H__

#include "util_defs.h"
#include "zstd.h"
#include "lz4.h"
#include "lz4frame.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IN_CHUNK_SIZE  (16*1024)


typedef struct st_compress {
    union {
        struct {
            union {
                ZSTD_CStream *zstd_cstream;
                ZSTD_DStream *zstd_dstream;
            };
        };
        struct {
            union {
                LZ4F_compressionContext_t lz4f_cstream;
                LZ4F_decompressionContext_t lz4f_dstream;
            };
        };
    };
    bool32 is_compress;
    size_t write_len;
    compress_algorithm_t algorithm;
    uint32 level;
    char *in_buf;
    size_t in_chunk_size;
    size_t in_buf_capcity;
    char *out_buf;
    size_t out_buf_capcity;
    uint32 frag_size;
} compress_t;

typedef status_t(*compress_write_t)(compress_t *ctx, void *channel, void *head, bool32 is_end);
typedef status_t(*decompress_write_t)(void *buffer, size_t buffer_size);

static inline const char *bak_compress_algorithm_name(compress_algorithm_t algorithm)
{
    switch (algorithm) {
        case COMPRESS_ZSTD:
            return "zstd";
        case COMPRESS_LZ4:
            return "lz4";
        default:
            return "NONE";
    }
}
void compress_free(compress_t *ctx);
static inline void free_compress_ctx(compress_t *ctx)
{
    if (ctx->algorithm == COMPRESS_NONE) {
        return;
    }
    compress_free(ctx);
    CM_FREE_PTR(ctx->in_buf);
    ctx->in_chunk_size = 0;
    ctx->in_buf_capcity = 0;
    CM_FREE_PTR(ctx->out_buf);
    ctx->out_buf_capcity = 0;
    ctx->algorithm = COMPRESS_NONE;
}

status_t compress_init(compress_t *ctx);
status_t compress_alloc(compress_t *ctx);
status_t compress_flush(compress_t *ctx);
status_t compress_stream(compress_t *ctx, char *write_buf, size_t write_buf_len);
status_t compress_begin(compress_t *ctx);
status_t compress_alloc_buff(compress_t *ctx);
status_t decompress_stream(compress_t *ctx, char *write_buf, size_t *buf_len);


#ifdef __cplusplus
}
#endif

#endif
