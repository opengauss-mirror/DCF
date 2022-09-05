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
 * cm_log.h
 *
 *
 * IDENTIFICATION
 *    src/common/cm_utils/cm_log.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_LOG_H__
#define __CM_LOG_H__

#include "cm_types.h"
#include "cm_defs.h"
#include "cm_spinlock.h"
#include "cm_error.h"
#include "cm_thread.h"
#include "cm_hash.h"
#include "dcf_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_log_level {
    LEVEL_ERROR = 0,  // error conditions
    LEVEL_WARN,       // warning conditions
    LEVEL_INFO,       // informational messages
} log_level_t;

typedef enum en_log_type {
    LOG_RUN = 0,
    LOG_DEBUG,
    LOG_ALARM,
    LOG_AUDIT,
    LOG_OPER,
    LOG_MEC,
    LOG_TRACE,
    LOG_PROFILE,
    LOG_COUNT  // LOG COUNT
} log_type_t;

#define CM_MAX_LOG_MODULE_NAME      10

typedef struct st_log_param {
    char log_home[CM_MAX_LOG_HOME_LEN];
    char log_module_name[CM_MAX_LOG_MODULE_NAME];
    uint32 log_file_permissions;
    uint32 log_bak_file_permissions;
    uint32 log_path_permissions;
    volatile uint32 log_filename_format;
    volatile uint32 log_level;
    volatile uint32 log_backup_file_count;
    volatile uint32 audit_backup_file_count;
    volatile uint64 max_log_file_size;
    volatile uint64 max_audit_file_size;
    bool32 log_instance_startup;
    usr_cb_log_output_t log_write;
    bool32 log_suppress_enable;
    char instance_name[CM_MAX_NAME_LEN];
} log_param_t;

/* _log_level */
#define LOG_NONE              0x00000000
#define LOG_RUN_ERR_LEVEL     0x00000001
#define LOG_RUN_WAR_LEVEL     0x00000002
#define LOG_RUN_INF_LEVEL     0x00000004
#define LOG_DEBUG_ERR_LEVEL   0x00000010
#define LOG_DEBUG_WAR_LEVEL   0x00000020
#define LOG_DEBUG_INF_LEVEL   0x00000040
#define LOG_MEC_LEVEL         0x00000080
#define LOG_OPER_LEVEL        0x00000100
#define LOG_TRACE_LEVEL       0x00000200
#define LOG_PROFILE_LEVEL     0x00000400

#define DEFAULT_LOG_LEVEL   ((LOG_RUN_ERR_LEVEL) | (LOG_RUN_WAR_LEVEL) | (LOG_RUN_INF_LEVEL) | \
                            (LOG_DEBUG_ERR_LEVEL) | (LOG_OPER_LEVEL) | (LOG_PROFILE_LEVEL))
#define MAX_LOG_LEVEL       ((LOG_RUN_ERR_LEVEL) | (LOG_RUN_WAR_LEVEL) | (LOG_RUN_INF_LEVEL) | \
                            (LOG_DEBUG_ERR_LEVEL) | (LOG_DEBUG_WAR_LEVEL) | (LOG_DEBUG_INF_LEVEL) | \
                            (LOG_OPER_LEVEL) | (LOG_MEC_LEVEL) | (LOG_TRACE_LEVEL) | \
                            (LOG_PROFILE_LEVEL))
log_param_t *cm_log_param_instance(void);


#define LOG_RUN_ERR_ON   (cm_log_param_instance()->log_level & (LOG_RUN_ERR_LEVEL))
#define LOG_RUN_WAR_ON   (cm_log_param_instance()->log_level & (LOG_RUN_WAR_LEVEL))
#define LOG_RUN_INF_ON   (cm_log_param_instance()->log_level & (LOG_RUN_INF_LEVEL))
#define LOG_DEBUG_ERR_ON (cm_log_param_instance()->log_level & (LOG_DEBUG_ERR_LEVEL))
#define LOG_DEBUG_WAR_ON (cm_log_param_instance()->log_level & (LOG_DEBUG_WAR_LEVEL))
#define LOG_DEBUG_INF_ON (cm_log_param_instance()->log_level & (LOG_DEBUG_INF_LEVEL))
#define LOG_OPER_ON      (cm_log_param_instance()->log_level & (LOG_OPER_LEVEL))
#define LOG_MEC_ON       (cm_log_param_instance()->log_level & (LOG_MEC_LEVEL))
#define LOG_TRACE_ON     (cm_log_param_instance()->log_level & (LOG_TRACE_LEVEL))
#define LOG_PROFILE_ON   (cm_log_param_instance()->log_level & (LOG_PROFILE_LEVEL))

#define LOG_ON (cm_log_param_instance()->log_level > 0)
#define LOG_REG_CB (cm_log_param_instance()->log_write != NULL)
#define LOG_INITED (cm_log_param_instance()->log_instance_startup)

#define LOG_MODULE_NAME (cm_log_param_instance()->log_module_name)

typedef struct st_log_file_handle {
    spinlock_t lock;
    char file_name[CM_FULL_PATH_BUFFER_SIZE];  // log file with the path
    int file_handle;
    uint32 file_inode;
    log_type_t log_type;
} log_file_handle_t;

typedef void (*cm_log_write_func_t)(log_file_handle_t *log_file_handle, char *buf, uint32 size);

#define CM_MIN_LOG_FILE_SIZE        SIZE_M(1)                  // this value can not be less than 1M
#define CM_MAX_LOG_FILE_SIZE        ((uint64)SIZE_M(1024) * 4) // this value can not be larger than 4G
#define CM_MAX_LOG_FILE_COUNT       128                        // this value can not be larger than 128
#define CM_MAX_LOG_CONTENT_LENGTH   CM_MESSAGE_BUFFER_SIZE
#define CM_MAX_LOG_HEAD_LENGTH      100     // UTC+8 2019-01-16 22:40:15.292|CM|00000|140084283451136|INFO> 65
#define CM_MAX_LOG_NEW_BUFFER_SIZE  1048576 // (1024 * 1024)
#define CM_MAX_LOG_PERMISSIONS      777
#define CM_DEF_LOG_PATH_PERMISSIONS 700
#define CM_DEF_LOG_FILE_PERMISSIONS 600

#define CM_MAX_TIME_STRLEN            (uint32)(48)

log_file_handle_t *cm_log_logger_file(uint32 log_count);
status_t cm_log_init(log_type_t log_type, const char *file_name);
void cm_log_set_path_permissions(uint16 val);
void cm_log_set_file_permissions(uint16 val);
void cm_log_open_file(log_file_handle_t *log_file_handle);

void cm_write_audit_log(const char *format, ...) CM_CHECK_FMT(1, 2);
void cm_write_alarm_log(uint32 warn_id, const char *format, ...) CM_CHECK_FMT(2, 3);

void cm_write_normal_log(log_type_t log_type, log_level_t log_level, const char *code_file_name, uint32 code_line_num,
    const char *module_name, bool32 need_rec_filelog, const char *format, ...) CM_CHECK_FMT(7, 8);
void cm_write_trace_log(uint64 tracekey, const char *format, ...);
void cm_fync_logfile(void);
void cm_close_logfile(void);
status_t cm_set_log_module_name(const char* module_name, int32 len);


#define LOG_DEBUG_INF(format, ...)                                                                               \
    do {                                                                                                         \
        if (LOG_DEBUG_INF_ON) {                                                                                  \
            if (LOG_REG_CB) {                                                                                    \
                cm_log_param_instance()->log_write(LOG_DEBUG, LEVEL_INFO, (char *)__FILE__, (uint32)__LINE__,    \
                    LOG_MODULE_NAME, format, ##__VA_ARGS__);                                                         \
            } else if (LOG_INITED) {                                                                                 \
                cm_write_normal_log(LOG_DEBUG, LEVEL_INFO, (char *)__FILE__, (uint32)__LINE__, LOG_MODULE_NAME,  \
                    CM_TRUE, format, ##__VA_ARGS__);                                                                 \
            }                                                                                                    \
        }                                                                                                        \
    } while (0)

#define LOG_DEBUG_WAR(format, ...)                                                                               \
    do {                                                                                                         \
        if (LOG_DEBUG_WAR_ON) {                                                                                  \
            if (LOG_REG_CB) {                                                                                    \
                cm_log_param_instance()->log_write(LOG_DEBUG, LEVEL_WARN, (char *)__FILE__, (uint32)__LINE__,    \
                    LOG_MODULE_NAME, format, ##__VA_ARGS__);                                                         \
            } else if (LOG_INITED) {                                                                                 \
                cm_write_normal_log(LOG_DEBUG, LEVEL_WARN, (char *)__FILE__, (uint32)__LINE__, LOG_MODULE_NAME, \
                    CM_TRUE, format, ##__VA_ARGS__);                                                                 \
            }                                                                                                    \
        }                                                                                                        \
    } while (0)

#define LOG_DEBUG_ERR(format, ...)                                                                                \
    do {                                                                                                          \
        if (LOG_DEBUG_ERR_ON) {                                                                                   \
            if (LOG_REG_CB) {                                                                                    \
                cm_log_param_instance()->log_write(LOG_DEBUG, LEVEL_ERROR, (char *)__FILE__, (uint32)__LINE__,    \
                    LOG_MODULE_NAME, format, ##__VA_ARGS__);                                                         \
            } else if (LOG_INITED) {                                                                                 \
                cm_write_normal_log(LOG_DEBUG, LEVEL_ERROR, (char *)__FILE__, (uint32)__LINE__, LOG_MODULE_NAME, \
                    CM_TRUE, format, ##__VA_ARGS__);                                                               \
            }                                                                                                     \
        }                                                                                                         \
    } while (0)

// 10s print 5 times
#define LOG_DEBUG_ERR_EX(format, ...)                                                                               \
    do {                                                                                                            \
        static thread_local_var uint64 log_count = 0;                                                               \
        static thread_local_var uint64 pre_log_time = 0;                                                            \
        static thread_local_var uint64 real_log_count = 0;                                                          \
        log_count++;                                                                                                \
        if (g_timer()->now - pre_log_time < 10000 * 1000) {                                                         \
            if (real_log_count < 5) {                                                                               \
                LOG_DEBUG_ERR(format, ##__VA_ARGS__);                                                               \
                real_log_count++;                                                                                   \
            }                                                                                                       \
        } else {                                                                                                    \
            if (log_count - real_log_count > 0) {                                                                   \
                LOG_DEBUG_ERR("discard: %llu.", log_count - real_log_count);                                        \
            } else {                                                                                                \
                LOG_DEBUG_ERR(format, ##__VA_ARGS__);                                                               \
                real_log_count++;                                                                                   \
            }                                                                                                       \
            pre_log_time = g_timer()->now;                                                                          \
            log_count = 0;                                                                                          \
            real_log_count = 0;                                                                                     \
        }                                                                                                           \
    } while (0)

#define LOG_RUN_INF(format, ...)                                                                                 \
    do {                                                                                                         \
        if (LOG_RUN_INF_ON) {                                                                                    \
            if (LOG_REG_CB) {                                                                                    \
                cm_log_param_instance()->log_write(LOG_RUN, LEVEL_INFO, (char *)__FILE__, (uint32)__LINE__,      \
                    LOG_MODULE_NAME, format, ##__VA_ARGS__);                                                         \
            } else if (LOG_INITED) {                                                                                  \
                cm_write_normal_log(LOG_RUN, LEVEL_INFO, (char *)__FILE__, (uint32)__LINE__, LOG_MODULE_NAME, CM_TRUE, \
                    format, ##__VA_ARGS__);                                                                          \
                if (LOG_DEBUG_INF_ON){                                                                              \
                    cm_write_normal_log(LOG_DEBUG, LEVEL_INFO, (char *)__FILE__, (uint32)__LINE__,               \
                        LOG_MODULE_NAME, CM_TRUE,    format, ##__VA_ARGS__);                                         \
                }                                                                                               \
            }                                                                                                    \
        }                                                                                                        \
    } while (0)
#define LOG_RUN_WAR(format, ...)                                                                                 \
    do {                                                                                                         \
        if (LOG_RUN_WAR_ON) {                                                                                    \
            if (LOG_REG_CB) {                                                                                    \
                cm_log_param_instance()->log_write(LOG_RUN, LEVEL_WARN, (char *)__FILE__, (uint32)__LINE__,      \
                    LOG_MODULE_NAME, format, ##__VA_ARGS__);                                                         \
            } else if (LOG_INITED) {                                                                                 \
                cm_write_normal_log(LOG_RUN, LEVEL_WARN, (char *)__FILE__, (uint32)__LINE__, LOG_MODULE_NAME, CM_TRUE, \
                    format, ##__VA_ARGS__);                                                                         \
                if (LOG_DEBUG_WAR_ON){                                                                              \
                    cm_write_normal_log(LOG_DEBUG, LEVEL_WARN, (char *)__FILE__, (uint32)__LINE__,           \
                        LOG_MODULE_NAME, CM_TRUE,  format, ##__VA_ARGS__);                                         \
                }                                                                                                \
            }                                                                                                    \
        }                                                                                                        \
    } while (0)
#define LOG_RUN_ERR(format, ...)                                                                                 \
    do {                                                                                                         \
        if (LOG_RUN_ERR_ON) {                                                                                    \
            if (LOG_REG_CB) {                                                                             \
                cm_log_param_instance()->log_write(LOG_RUN, LEVEL_ERROR, (char *)__FILE__, (uint32)__LINE__,      \
                    LOG_MODULE_NAME, format, ##__VA_ARGS__);                                                         \
            } else if (LOG_INITED) {                                                                                 \
                cm_write_normal_log(LOG_RUN, LEVEL_ERROR, (char *)__FILE__, (uint32)__LINE__, LOG_MODULE_NAME, \
                    CM_TRUE, format, ##__VA_ARGS__);                                                                 \
                if (LOG_DEBUG_ERR_ON){                                                                              \
                    cm_write_normal_log(LOG_DEBUG, LEVEL_ERROR, (char *)__FILE__, (uint32)__LINE__,                 \
                        LOG_MODULE_NAME, CM_TRUE, format, ##__VA_ARGS__);                                              \
                }                                                                                                \
            }                                                                                                       \
        }                                                                                                           \
    } while (0)

#define LOG_AUDIT(format, ...)                                                                               \
    do {                                                                                                     \
        if (LOG_REG_CB) {                                                                                    \
            cm_log_param_instance()->log_write(LOG_AUDIT, 0, (char *)__FILE__, (uint32)__LINE__,             \
                LOG_MODULE_NAME, format, ##__VA_ARGS__);                                                         \
        } else if (LOG_INITED) {                                                                                    \
            cm_write_audit_log(format, ##__VA_ARGS__)                                                        \
        }                                                                                                    \
    } while (0)

#define LOG_ALARM(warn_id, format, ...)                                     \
    do {                                                                    \
        if (LOG_ON) {                                                       \
            if (LOG_REG_CB) {                                                                                    \
                cm_log_param_instance()->log_write(LOG_ALARM, warn_id, (char *)__FILE__, (uint32)__LINE__,       \
                    LOG_MODULE_NAME, format"|1", ##__VA_ARGS__);                                                     \
            } else if (LOG_INITED) {                                                                                 \
                cm_write_alarm_log(warn_id, format"|1", ##__VA_ARGS__);                                          \
            }                                                                                                    \
        }                                                                                                        \
    } while (0)

#define LOG_ALARM_RECOVER(warn_id, format, ...)                             \
    do {                                                                    \
        if (LOG_ON) {                                                       \
            if (LOG_REG_CB) {                                                                                    \
                cm_log_param_instance()->log_write(LOG_ALARM, warn_id, (char *)__FILE__, (uint32)__LINE__,       \
                    LOG_MODULE_NAME, format"|2", ##__VA_ARGS__);                                                     \
            } else if (LOG_INITED) {                                                                                 \
                cm_write_alarm_log(warn_id, format"|2", ##__VA_ARGS__);                                          \
            }                                                                                                    \
        }                                                                                                        \
    } while (0)

/* no need to print error info in file add/remove log  */
#define LOG_RUN_FILE_INF(need_record_file_log, format, ...)                                              \
    do {                                                                                                 \
        if (LOG_RUN_INF_ON) {                                                                            \
            if (LOG_REG_CB) {                                                                                    \
                if (need_record_file_log) {                                                                      \
                    cm_log_param_instance()->log_write(LOG_RUN, LEVEL_INFO, (char *)__FILE__, (uint32)__LINE__,  \
                        LOG_MODULE_NAME, format, ##__VA_ARGS__);                                                     \
                }                                                                                                \
            } else if (LOG_INITED) {                                                                                 \
                cm_write_normal_log(LOG_RUN, LEVEL_INFO, (char *)__FILE__, (uint32)__LINE__, LOG_MODULE_NAME,        \
                    need_record_file_log, format, ##__VA_ARGS__);                                                \
            }                                                                                                    \
        }                                                                                                        \
    } while (0);

void cm_write_mec_log(const char *format, ...);


#define LOG_MEC(format, ...)                                      \
    do {                                                          \
        if (LOG_MEC_ON && LOG_INITED) {                                         \
            cm_write_mec_log(format, ##__VA_ARGS__);              \
        }                                                         \
    } while (0)

#define LOG_TRACE(tracekey, format, ...)                          \
    do {                                                          \
        if (LOG_TRACE_ON && LOG_INITED) {                                       \
            cm_write_trace_log(tracekey, format, ##__VA_ARGS__);  \
        }                                                         \
    } while (0)

#define LOG_PROFILE(format, ...)                                                                                     \
    do {                                                                                                             \
        if (LOG_PROFILE_ON) {                                                                                        \
            if (LOG_REG_CB) {                                                                                        \
                cm_log_param_instance()->log_write(LOG_PROFILE, LEVEL_INFO, (char *)__FILE__, (uint32)__LINE__,      \
                    LOG_MODULE_NAME, format, ##__VA_ARGS__);                                                         \
            } else if (LOG_INITED) {                                                                                 \
                cm_write_normal_log(LOG_PROFILE, LEVEL_INFO, (char *)__FILE__, (uint32)__LINE__,                     \
                LOG_MODULE_NAME, CM_TRUE, format, ##__VA_ARGS__);                                                    \
            }                                                                                                        \
        }                                                                                                            \
    } while (0)

void cm_write_oper_log(const char *format, ...);

#define LOG_OPER(format, ...)                                                                                        \
    do {                                                                                                             \
        if (LOG_OPER_ON) {                                                                                           \
            if (LOG_REG_CB) {                                                                                        \
                cm_log_param_instance()->log_write(LOG_OPER, LEVEL_INFO, (char *)__FILE__, (uint32)__LINE__,         \
                    LOG_MODULE_NAME, format, ##__VA_ARGS__);                                                         \
            } else if (LOG_INITED) {                                                                                 \
                cm_write_oper_log(format, ##__VA_ARGS__);                                                            \
            }                                                                                                        \
        }                                                                                                            \
    } while (0)

void set_trace_key(uint64 tracekey);
uint64 get_trace_key(void);
bool8 is_trace_key(uint64 tracekey);
void unset_trace_key(void);

#define LOG_TIME_BEGIN(name) \
uint64 __##name##begin = g_timer()->now

#define LOG_TIME_END(name) \
do { \
    static thread_local_var uint64 __##name##total = 0; \
    static thread_local_var uint64 __##name##count = 0; \
    static thread_local_var uint64 __##name##pre_total = 0; \
    static thread_local_var uint64 __##name##pre_count = 0; \
    static thread_local_var uint64 __##name##log_time = 0; \
    __##name##total += (g_timer()->now - __##name##begin); \
    __##name##count++; \
    if (g_timer()->now - __##name##log_time > 5*1000000) \
    { \
        __##name##log_time = g_timer()->now; \
        uint64 __##name##this_total = __##name##total - __##name##pre_total; \
        uint64 __##name##this_count = __##name##count - __##name##pre_count; \
        __##name##pre_total = __##name##total; \
        __##name##pre_count = __##name##count; \
        LOG_PROFILE("[TIME][%u]%-30s%10llu(us),count:%10llu,avg:%10llu(us)", \
            cm_get_current_thread_id(), \
            #name, __##name##this_total, __##name##this_count, \
            __##name##this_count == 0 ? 0 :__##name##this_total / __##name##this_count); \
    } \
} while (0);
/*
 * warning id is composed of source + module + object + code
 * source -- DN(10)/CM(11)/OM(12)/DM(20)
 * module -- File(01)/Transaction(02)/HA(03)/Log(04)/Buffer(05)/Space(06)/Server(07)
 * object -- Host Resource(01)/Run Environment(02)/Cluster Status(03)/
 *           Instance Status(04)/Database Status(05)/Database Object(06)
 * code   -- 0001 and so on
 */
/*
 * one warn must modify  warn_id_t
 *                       warn_name_t
 *                       g_warn_id
 *                       g_warning_desc
 */
typedef enum st_warn_id {
    WARN_FILEDESC_ID = 1001010001,
} warn_id_t;

typedef enum st_warn_name {
    WARN_FILEDESC,          /* Too many open files in %s */
} warn_name_t;

#ifdef __cplusplus
}
#endif
#endif
