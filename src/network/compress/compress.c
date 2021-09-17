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
 * compress.c
 *    compress process
 *
 * IDENTIFICATION
 *    src/network/compress/compress.c
 *
 * -------------------------------------------------------------------------
 */

#include "compress.h"
#include "cm_log.h"
#include "cm_file.h"
#include "cm_list.h"
#include "util_error.h"

#ifdef __cplusplus
extern "C" {
#endif

static LZ4F_preferences_t g_kPrefs = {
    { LZ4F_max256KB, LZ4F_blockLinked, LZ4F_noContentChecksum, LZ4F_frame, 0, 0, LZ4F_noBlockChecksum },
    1, 0, 0, { 0, 0, 0 },
};

status_t lz4f_alloc(compress_t *ctx)
{
    size_t ret;

    if (ctx->is_compress) {
        ret = LZ4F_createCompressionContext(&(ctx->lz4f_cstream), LZ4F_VERSION);
    } else {
        ret = LZ4F_createDecompressionContext(&(ctx->lz4f_dstream), LZ4F_VERSION);
    }

    if (LZ4F_isError(ret)) {
        CM_THROW_ERROR(ERR_COMPRESS_INIT_ERROR, "lz4f", ret, LZ4F_getErrorName(ret));
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t lz4f_init(compress_t *ctx)
{
    // lz4's compression will init the resource in the end of each subtask automatically,
    // so we do not need to do the initialization of compression here
    if (!ctx->is_compress) {
        LZ4F_resetDecompressionContext(ctx->lz4f_dstream);
    }

    return CM_SUCCESS;
}

status_t zstd_alloc(compress_t *ctx)
{
    bool32 created;
    if (ctx->is_compress) {
        ctx->zstd_cstream = ZSTD_createCStream();
        created = (ctx->zstd_cstream != NULL);
    } else {
        ctx->zstd_dstream = ZSTD_createDStream();
        created = (ctx->zstd_dstream != NULL);
    }

    if (!created) {
        CM_THROW_ERROR(ERR_COMPRESS_INIT_ERROR, "zstd", 0, "Create zstd stream failed.");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t zstd_init(compress_t *ctx)
{
    size_t ret;
    if (ctx->is_compress) {
        ret = ZSTD_initCStream(ctx->zstd_cstream, ctx->level);
    } else {
        ret = ZSTD_initDStream(ctx->zstd_dstream);
    }

    if (ZSTD_isError(ret)) {
        CM_THROW_ERROR(ERR_COMPRESS_INIT_ERROR, "zstd", ret, ZSTD_getErrorName(ret));
        return CM_ERROR;
    }

    return CM_SUCCESS;
}


status_t compress_init(compress_t *ctx)
{
    ctx->in_chunk_size = 0;
    ctx->write_len = 0;
    switch (ctx->algorithm) {
        case COMPRESS_ZSTD:
            return zstd_init(ctx);
        case COMPRESS_LZ4:
            return lz4f_init(ctx);
        default:
            break;
    }

    return CM_SUCCESS;
}


static status_t zstd_compress(compress_t *ctx, char *write_buf, size_t write_buf_len)
{
    size_t buff_in_size = ZSTD_CStreamInSize();
    size_t remain_size = ctx->in_chunk_size;
    size_t copy_size;
    bool32 last_chunk;
    /* stream data */
    do {
        copy_size = MIN(buff_in_size, remain_size);
        last_chunk = copy_size <= buff_in_size;
        ZSTD_EndDirective const mode = last_chunk ? ZSTD_e_end : ZSTD_e_continue;
        ZSTD_inBuffer input = { ctx->in_buf + ctx->in_chunk_size - remain_size, copy_size, 0 };
        bool32 finished;
        do {
            /* Compress into the output buffer and write all of the output to
             * the file so we can reuse the buffer next iteration.
             */
            ZSTD_outBuffer output = { ctx->out_buf, ctx->out_buf_capcity, 0 };
            size_t const res = ZSTD_compressStream2(ctx->zstd_cstream, &output, &input, mode);
            if (LZ4F_isError(res)) {
                CM_THROW_ERROR(ERR_COMPRESS_ERROR, "zstd", res, ZSTD_getErrorName(res));
                return CM_ERROR;
            }

            if (output.pos != 0) {
                errno_t ret = memcpy_sp(write_buf + ctx->write_len, write_buf_len - ctx->write_len,
                    output.dst, output.pos);
                MEMS_RETURN_IFERR(ret);
            }
            ctx->write_len += output.pos;
            /* If we're on the last chunk we're finished when zstd returns 0,
             * which means its consumed all the input AND finished the frame.
             * Otherwise, we're finished when we've consumed all the input.
             */
            finished = last_chunk ? (res == 0) : (input.pos == input.size);
        } while (!finished);

        remain_size -= copy_size;
    } while (remain_size != 0);

    return CM_SUCCESS;
}


static status_t lz4f_compress(compress_t *ctx, char *write_buf, size_t write_buf_len)
{
    size_t remain_size = ctx->in_chunk_size;
    size_t copy_size;
    /* stream data */
    do {
        copy_size = MIN(IN_CHUNK_SIZE, remain_size);
        size_t res = LZ4F_compressUpdate(ctx->lz4f_cstream,
                                         ctx->out_buf, ctx->out_buf_capcity,
                                         ctx->in_buf + ctx->in_chunk_size - remain_size, copy_size, NULL);
        if (LZ4F_isError(res)) {
            CM_THROW_ERROR(ERR_COMPRESS_ERROR, "lz4f", res, LZ4F_getErrorName(res));
            return CM_ERROR;
        }

        if (res != 0) {
            errno_t ret = memcpy_sp(write_buf + ctx->write_len, write_buf_len - ctx->write_len, ctx->out_buf, res);
            MEMS_RETURN_IFERR(ret);
        }
        ctx->write_len += res;
        remain_size -= copy_size;
    } while (remain_size != 0);

    return CM_SUCCESS;
}

static status_t lz4f_compress_end(compress_t *ctx)
{
    size_t res = LZ4F_compressEnd(ctx->lz4f_cstream, ctx->out_buf, ctx->out_buf_capcity, NULL);
    if (LZ4F_isError(res)) {
        CM_THROW_ERROR(ERR_COMPRESS_ERROR, "lz4f", res, LZ4F_getErrorName(res));
        return CM_ERROR;
    }

    ctx->write_len += res;

    return CM_SUCCESS;
}

status_t zstd_decompress(compress_t *ctx, char *write_buf, size_t *write_buf_len)
{
    size_t copy_size;
    size_t remain_size = ctx->in_chunk_size;
    size_t const buff_in_size = ZSTD_DStreamInSize();

    do {
        copy_size = MIN(buff_in_size, remain_size);
        ZSTD_inBuffer input = { ctx->in_buf + ctx->in_chunk_size - remain_size, copy_size, 0 };
        while (input.pos < input.size) {
            ZSTD_outBuffer output = {ctx->out_buf, ctx->out_buf_capcity, 0};
            /* Any data within dst has been flushed at this stage */
            size_t const ret = ZSTD_decompressStream(ctx->zstd_dstream, &output, &input);
            if (ZSTD_isError(ret)) {
                CM_THROW_ERROR(ERR_DECOMPRESS_ERROR, "zstd", ret, ZSTD_getErrorName(ret));
                return CM_ERROR;
            }
            if (output.pos != 0) {
                MEMS_RETURN_IFERR(memcpy_sp(write_buf + ctx->write_len, *write_buf_len - ctx->write_len,
                    ctx->out_buf, output.pos));
            }
            ctx->write_len += output.pos;
        }
        remain_size -= copy_size;
    } while (remain_size);

    *write_buf_len = ctx->write_len;
    return CM_SUCCESS;
}


status_t lz4f_decompress(compress_t *ctx, char *write_buf, size_t *write_buf_len)
{
    size_t buf_size = *write_buf_len;
    size_t copy_size;
    size_t remain_size = ctx->in_chunk_size;

    do {
        copy_size = MIN(IN_CHUNK_SIZE, remain_size);
        const void* src_ptr = (const char*)ctx->in_buf + ctx->in_chunk_size - remain_size;
        const void * const src_end = (const char*)src_ptr + copy_size;

        while (src_ptr < src_end) {
            /* Any data within dst has been flushed at this stage */
            size_t dst_size = ctx->out_buf_capcity;
            size_t src_size = (const char*)src_end - (const char*)src_ptr;
            size_t ret = LZ4F_decompress(ctx->lz4f_dstream, ctx->out_buf, &dst_size, src_ptr, &src_size, NULL);
            if (LZ4F_isError(ret)) {
                CM_THROW_ERROR(ERR_COMPRESS_ERROR, "lz4f", ret, LZ4F_getErrorName(ret));
                return CM_ERROR;
            }
            if (dst_size != 0) {
                MEMS_RETURN_IFERR(memcpy_sp(write_buf + ctx->write_len, buf_size - ctx->write_len,
                    ctx->out_buf, dst_size));
            }
            ctx->write_len += dst_size;
            src_ptr = (const char*)src_ptr + src_size;
        }

        CM_ASSERT(src_ptr == src_end);
        remain_size -= copy_size;
    } while (remain_size);

    *write_buf_len = ctx->write_len;

    return CM_SUCCESS;
}

status_t decompress_stream(compress_t *ctx, char *write_buf, size_t *buf_len)
{
    switch (ctx->algorithm) {
        case COMPRESS_ZSTD:
            return zstd_decompress(ctx, write_buf, buf_len);
        case COMPRESS_LZ4:
            return lz4f_decompress(ctx, write_buf, buf_len);
        default:
            break;
    }

    return CM_SUCCESS;
}

status_t compress_begin(compress_t *ctx)
{
    switch (ctx->algorithm) {
        case COMPRESS_ZSTD:
            return CM_SUCCESS;
        case COMPRESS_LZ4:
            g_kPrefs.compressionLevel = ctx->level;
            size_t header_size = LZ4F_compressBegin(ctx->lz4f_cstream, ctx->out_buf, ctx->out_buf_capcity, &g_kPrefs);
            if (LZ4F_isError(header_size)) {
                CM_THROW_ERROR(ERR_COMPRESS_ERROR, "lz4f", header_size, LZ4F_getErrorName(header_size));
                return CM_ERROR;
            }
            ctx->write_len = header_size;
            break;
        default:
            return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t compress_flush(compress_t *ctx)
{
    switch (ctx->algorithm) {
        case COMPRESS_ZSTD:
            return CM_SUCCESS;
        case COMPRESS_LZ4:
            if (lz4f_compress_end(ctx) != CM_SUCCESS) {
                return CM_ERROR;
            }
            break;
        default:
            return CM_ERROR;
    }
    return CM_SUCCESS;
}


status_t compress_stream(compress_t *ctx, char *write_buf, size_t write_buf_len)
{
    switch (ctx->algorithm) {
        case COMPRESS_ZSTD:
            return zstd_compress(ctx, write_buf, write_buf_len);
        case COMPRESS_LZ4:
            return lz4f_compress(ctx, write_buf, write_buf_len);
        default:
            break;
    }

    return CM_SUCCESS;
}

/*
 * Alloc resource needed by compression or decompression.
 * @param the attributes of backup or restore
 * @param compress context
 * @param the action is backup or restore
 * @return
 * - CM_SUCCESS
 * _ CM_ERROR
 * @note must call in the begining of the backup or restore task
 */
status_t compress_alloc(compress_t *ctx)
{
    switch (ctx->algorithm) {
        case COMPRESS_ZSTD:
            return zstd_alloc(ctx);
        case COMPRESS_LZ4:
            return lz4f_alloc(ctx);
        default:
            break;
    }

    return CM_SUCCESS;
}

status_t compress_alloc_buff(compress_t *ctx)
{
    switch (ctx->algorithm) {
        case COMPRESS_ZSTD:
            if (ctx->is_compress) {
                ctx->in_buf_capcity = ZSTD_CStreamInSize();
                ctx->out_buf_capcity = ZSTD_CStreamOutSize();
            } else {
                ctx->in_buf_capcity = ZSTD_DStreamInSize();
                ctx->out_buf_capcity = ZSTD_DStreamOutSize();
            }
            break;
        case COMPRESS_LZ4:
            ctx->in_buf_capcity = IN_CHUNK_SIZE;
            ctx->out_buf_capcity = LZ4F_compressBound(IN_CHUNK_SIZE, &g_kPrefs);
            break;
        default:
            return CM_ERROR;
    }
    ctx->in_buf_capcity = MAX(ctx->in_buf_capcity, ctx->frag_size);
    ctx->in_buf = (char *)malloc(ctx->in_buf_capcity);
    if (ctx->in_buf == NULL) {
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)ctx->in_buf_capcity, "compress in buffer memory");
        return CM_ERROR;
    }
    ctx->out_buf = (char *)malloc(ctx->out_buf_capcity);
    if (ctx->out_buf == NULL) {
        CM_FREE_PTR(ctx->in_buf);
        CM_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)ctx->out_buf_capcity, "compress out buffer memory");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}


static void zstd_end(compress_t *zctx)
{
    size_t ret;
    if (zctx->is_compress) {
        ret = ZSTD_freeCStream(zctx->zstd_cstream);
    } else {
        ret = ZSTD_freeDStream(zctx->zstd_dstream);
    }

    zctx->zstd_cstream = NULL;

    if (ZSTD_isError(ret)) {
        CM_THROW_ERROR(ERR_COMPRESS_FREE_ERROR, "ZSTD", ret, ZSTD_getErrorName(ret));
    }
}

static void lz4f_end(compress_t *zctx)
{
    size_t ret;
    if (zctx->is_compress) {
        ret = LZ4F_freeCompressionContext(zctx->lz4f_cstream);
    } else {
        ret = LZ4F_freeDecompressionContext(zctx->lz4f_dstream);
    }

    zctx->lz4f_cstream = NULL;

    if (LZ4F_isError(ret)) {
        CM_THROW_ERROR(ERR_COMPRESS_FREE_ERROR, "LZ4F", ret, LZ4F_getErrorName(ret));
    }
}

/*
 * Free the resource of the compression or decompression.
 * @param the attributes of backup or restore
 * @param compress context
 * @param the action is backup or restore
 * @return
 * - CM_SUCCESS
 * _ CM_ERROR
 * @note must call in the end of the backup or restore task
 */
void compress_free(compress_t *ctx)
{
    switch (ctx->algorithm) {
        case COMPRESS_ZSTD:
            zstd_end(ctx);
            break;
        case COMPRESS_LZ4:
            lz4f_end(ctx);
            break;
        default:
            break;
    }
}

#ifdef __cplusplus
}
#endif
