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
 * cm_utils.c
 *    Implement of utils
 *
 * IDENTIFICATION
 *    src/common/cm_utils/cm_utils.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_utils.h"
#include "cm_text.h"
#include "cm_timer.h"
#include "cm_epoll.h"
#include "cm_log.h"
#include "cm_cipher.h"
#ifndef WIN32
#include <sys/inotify.h>
#endif


#define IS_SPECIAL_CHAR(c) ((' ' <= (c) && (c) <= '/') || (':' <= (c) && (c) <= '@') ||  \
        ('[' <= (c) && (c) <= '`') || ('{' <= (c) && (c) <= '~'))
#define IS_NUM_CHAR(c)     ((c) >= '0' && (c) <= '9')
#define IS_UPPER_LETTER(c) ((c) >= 'A' && (c) <= 'Z')
#define IS_LOWER_LETTER(c) ((c) >= 'a' && (c) <= 'z')
#define IS_LETTER(c)       (IS_UPPER_LETTER(c) || IS_LOWER_LETTER(c))


const static uint64 RAND_P1 = 0x5DEECE66DL;
const static uint64 RAND_P2 = 0xBL;
const static uint64 RAND_P3 = 0XFFFFFFFFFFFFL;

static inline uint32 cm_rand_next(int64 *seed, uint32 bits)
{
    int64 old_seed, next_seed;
    atomic_t cur_seed = *seed;
    do {
        old_seed = cm_atomic_get(&cur_seed);
        next_seed = (int64)(((uint64)old_seed * RAND_P1 + RAND_P2) & RAND_P3);
    } while (!cm_atomic_cas(&cur_seed, old_seed, next_seed));
    *seed = cur_seed;
    return (uint32)((uint64)next_seed >> (48 - bits));
}

uint32 cm_random(uint32 range)
{
    int64 seed;
    uint32 r_next, r_mask, value;

    (void)cm_rand((uchar *)&seed, sizeof(int64));
    r_next = cm_rand_next(&seed, 31);
    r_mask = range - 1;

    if ((range & r_mask) == 0) {
        r_next = (uint32)(((uint64)range * r_next) >> 31);
    } else {
        value = r_next;
        r_next = value % range;
        while (value + r_mask < r_next) {
            r_next = value % range;
            value = cm_rand_next(&seed, 31);
        }
    }
    return r_next;
}


status_t cm_load_symbol(void *lib_handle, char *symbol, void **sym_lib_handle)
{
#ifndef WIN32
    const char *dlsym_err = NULL;

    *sym_lib_handle = dlsym(lib_handle, symbol);
    dlsym_err = dlerror();
    if (dlsym_err != NULL) {
        CM_THROW_ERROR(ERR_LOAD_SYMBOL, symbol, dlsym_err);
        return CM_ERROR;
    }
#endif // !WIN32
    return CM_SUCCESS;
}

status_t cm_open_dl(void **lib_handle, char *symbol)
{
#ifdef WIN32
    CM_THROW_ERROR(ERR_LOAD_LIBRARY, symbol, cm_get_os_error());
    return CM_ERROR;
#else
    *lib_handle = dlopen(symbol, RTLD_LAZY);
    if (*lib_handle == NULL) {
        CM_THROW_ERROR(ERR_LOAD_LIBRARY, symbol, cm_get_os_error());
        return CM_ERROR;
    }
    return CM_SUCCESS;
#endif
}

void cm_close_dl(void *lib_handle)
{
#ifndef WIN32
    (void)dlclose(lib_handle);
#endif
}

status_t cm_watch_file_init(int32 *watch_fd, int32 *epoll_fd)
{
#ifndef WIN32
    struct epoll_event ev;

    *epoll_fd = epoll_create1(0);
    if (*epoll_fd < 0) {
        return CM_ERROR;
    }

    *watch_fd = inotify_init();
    if (*watch_fd < 0) {
        return CM_ERROR;
    }

    ev.events = EPOLLIN;
    ev.data.fd = *watch_fd;

    if (epoll_ctl(*epoll_fd, EPOLL_CTL_ADD, *watch_fd, &ev) != 0) {
        return CM_ERROR;
    }
#else
    *watch_fd = CM_INVALID_ID32;
    *epoll_fd = CM_INVALID_ID32;
#endif
    return CM_SUCCESS;
}

status_t cm_add_file_watch(int32 fd, const char *file_name, int32 *wd)
{
#ifndef WIN32
    *wd = inotify_add_watch(fd, file_name, IN_DELETE_SELF | IN_ATTRIB | IN_MOVE_SELF);
    if (*wd < 0) {
        return CM_ERROR;
    }
#endif
    return CM_SUCCESS;
}

status_t cm_rm_file_watch(int32 fd, int32 *wd)
{
#ifndef WIN32
    if (inotify_rm_watch(fd, *wd) < 0) {
        return CM_ERROR;
    }
    *wd = -1;
#endif
    return CM_SUCCESS;
}

status_t cm_watch_file_event(int32 watch_fd, int32 epoll_fd, int32 *wd)
{
#ifndef WIN32
    int32 event_num, read_size;
    char buf[1024];
    struct epoll_event e_event;
    struct inotify_event *i_event = NULL;
    char *tmp = NULL;

    event_num = epoll_wait(epoll_fd, &e_event, 1, 200);
    if (event_num <= 0) {
        return CM_ERROR;
    }

    /* handle inotify event */
    if (e_event.data.fd == watch_fd) {
        read_size = read(watch_fd, buf, sizeof(buf));
        if (read_size <= 0) {
            return CM_ERROR;
        }

        for (tmp = buf; tmp < buf + read_size; tmp += sizeof(struct inotify_event) + i_event->len) {
            i_event = (struct inotify_event *)tmp;

            if (((i_event->mask & IN_ATTRIB) && !(i_event->mask & IN_DELETE_SELF)) || (i_event->mask & IN_MOVE_SELF)) {
                /* could not get name of  that has been removed/unlinked, so return wd */
                *wd = i_event->wd;
                return CM_SUCCESS;
            }
        }
    }
#endif
    return CM_ERROR;
}


static void build_mec_head(char *buf, uint32 buf_size, const char *module_name)
{
    int tz;
    char date[CM_MAX_TIME_STRLEN] = {0};
    errno_t errcode;

    (void)cm_date2str(g_timer()->now, "yyyy-mm-dd hh24:mi:ss.ff3", date, CM_MAX_TIME_STRLEN);
    tz = g_timer()->tz;
    if (tz >= 0) {
        // truncation CM_MAX_LOG_HEAD_LENGTH content
        errcode = snprintf_s(buf, (size_t)buf_size, CM_MAX_LOG_HEAD_LENGTH - 1, "UTC+%d %s|%s|%u|", tz, date,
            module_name, cm_get_current_thread_id());
    } else {
        // truncation CM_MAX_LOG_HEAD_LENGTH content
        errcode = snprintf_s(buf, (size_t)buf_size, CM_MAX_LOG_HEAD_LENGTH - 1, "UTC%d %s|%s|%u|", tz, date,
            module_name, cm_get_current_thread_id());
    }

    if (SECUREC_UNLIKELY(errcode == -1)) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
        return;
    }
}


void cm_dump_mem(void *dump_addr, uint32 dump_len)
{
    uint32 index;
    uchar row_data[16] = {0};
    uint32  row_index = 0;
    char buf[CM_MAX_LOG_HEAD_LENGTH];
    log_file_handle_t *handle = cm_log_logger_file(LOG_MEC);
    uchar *dump_loc = (uchar*)dump_addr;
    if (!LOG_MEC_ON) {
        return;
    }

    build_mec_head(buf, CM_MAX_LOG_HEAD_LENGTH, LOG_MODULE_NAME);
    LOG_MEC("\r\n%s [DUMP] dump_addr %p, dump_len %u", buf, dump_addr, dump_len);
    if ((dump_addr == NULL) || (dump_len == 0)) {
        LOG_MEC("[DUMP] dump memory Fail, dump_addr or dump_len equal zero\r\n");
        return;
    }

    for (index = 0; index < dump_len; dump_loc++, index++, row_index++) {
        if ((index % 16) == 0) {
            for (row_index = 0; ((row_index < 16) && (index != 0)); row_index++) {
                LOG_MEC("%c", row_data[row_index]);
                row_data[row_index] = 0;
            }

            row_index = 0;
            LOG_MEC("\r\n %p: ", dump_loc);
        } else if ((index % 4) == 0) {
            LOG_MEC(" ");
        }

        row_data[row_index] = *dump_loc;
        LOG_MEC("%2x ", *dump_loc);
    }

    if ((index % 16) != 0) {
        while ((index % 16) != 0) {
            if (((index % 4) == 0) && ((index % 16) != 0)) {
                LOG_MEC(" ");
            }

            LOG_MEC("   ");
            row_data[row_index] = 0;
            index++;
            row_index++;
        }

        for (row_index = 0; row_index < 16; row_index++) {
            LOG_MEC("%c", row_data[row_index]);
        }
    }
    LOG_MEC("\r\n");
#ifndef WIN32
    (void)fsync(handle->file_handle);
#endif

    return;
}
