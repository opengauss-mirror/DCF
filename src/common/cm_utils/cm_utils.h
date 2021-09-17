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
 * cm_utils.h
 *
 *
 * IDENTIFICATION
 *    src/common/cm_utils/cm_utils.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_UTILS_H__
#define __CM_UTILS_H__
#include <time.h>
#include "cm_defs.h"
#include "cm_log.h"
#ifndef WIN32
#include "dlfcn.h"
#endif

#ifdef WIN32
#ifndef ENABLE_INTSAFE_SIGNED_FUNCTIONS
#define ENABLE_INTSAFE_SIGNED_FUNCTIONS
#endif
#include <intsafe.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif


uint32 cm_random(uint32 range);
static inline status_t realpath_file(const char *filename, char *realfile, uint32 real_path_len)
{
#ifdef WIN32
    if (!_fullpath(realfile, filename, real_path_len - 1)) {
        CM_THROW_ERROR(ERR_OPEN_FILE, filename, errno);
        return CM_ERROR;
    }
#else
    errno_t errcode;
    char resolved_path[PATH_MAX] = { 0 };

    if (!realpath(filename, resolved_path)) {
        if (errno != ENOENT && errno != EACCES) {
            CM_THROW_ERROR(ERR_OPEN_FILE, filename, errno);
            return CM_ERROR;
        }
    }

    errcode = strncpy_s(realfile, real_path_len, resolved_path, real_path_len - 1);
    if (errcode != EOK) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, (errcode));
        return CM_ERROR;
    }
#endif
    return CM_SUCCESS;
}


status_t cm_load_symbol(void *lib_handle, char *symbol, void **sym_lib_handle);
status_t cm_open_dl(void **lib_handle, char *symbol);
void cm_close_dl(void *lib_handle);

status_t cm_watch_file_init(int32 *i_fd, int32 *e_fd);
status_t cm_add_file_watch(int32 i_fd, const char *dirname, int32 *wd);
status_t cm_rm_file_watch(int32 i_fd, int32 *wd);
status_t cm_watch_file_event(int32 i_fd, int32 e_fd, int32 *wd);
void cm_dump_mem(void *dump_addr, uint32 dump_len);


#ifdef __cplusplus
}
#endif

#endif
