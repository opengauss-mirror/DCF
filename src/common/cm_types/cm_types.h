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
 * cm_types.h
 *    the header of types
 *
 * IDENTIFICATION
 *    src/common/cm_types/cm_types.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CM_TYPES_H__
#define __CM_TYPES_H__

#ifndef CM_TYPES_DEFINED
#define CM_TYPES_DEFINED 1

typedef unsigned char uchar;
typedef unsigned long ulong;
typedef unsigned int bool32;

#ifndef HAVE_INT8
#define HAVE_INT8
typedef char int8;
typedef short int16;
typedef int int32;
#endif

#ifndef HAVE_UINT8
#define HAVE_UINT8
typedef unsigned char uint8;
typedef unsigned char bool8;
typedef unsigned int uint32;
typedef unsigned short uint16;
#endif

#ifdef WIN32
typedef __int64 int64;
typedef unsigned __int64 uint64;
#ifdef _WIN64
typedef unsigned __int64 socket_t;
#else
typedef unsigned int socket_t;
typedef int pid_t;
#endif

#else
#ifndef HAVE_INT64
#define HAVE_INT64
typedef long long int64;
#endif
#ifndef HAVE_UINT64
#define HAVE_UINT64
typedef unsigned long long uint64;
#endif
typedef int socket_t;
#endif

typedef void *pointer_t;
typedef void *handle_t;

#define UINT32_BITS 32
#define UINT16_BITS 16
#define UINT8_BITS 8

typedef enum en_cm_type {
    CM_TYPE_UNKNOWN = -1,
    CM_TYPE_BASE = 20000,
    CM_TYPE_INTEGER = CM_TYPE_BASE + 1,    /* native 32 bits integer */
    CM_TYPE_BIGINT = CM_TYPE_BASE + 2,     /* native 64 bits integer */
    CM_TYPE_REAL = CM_TYPE_BASE + 3,       /* 8-byte native double */
    CM_TYPE_NUMBER = CM_TYPE_BASE + 4,     /* number */
    CM_TYPE_DECIMAL = CM_TYPE_BASE + 5,    /* decimal, internal used */
    CM_TYPE_DATE = CM_TYPE_BASE + 6,       /* datetime */
    CM_TYPE_TIMESTAMP = CM_TYPE_BASE + 7,  /* timestamp */
    CM_TYPE_CHAR = CM_TYPE_BASE + 8,       /* char(n) */
    CM_TYPE_VARCHAR = CM_TYPE_BASE + 9,    /* varchar, varchar2 */
    CM_TYPE_STRING = CM_TYPE_BASE + 10,    /* native char * */
    CM_TYPE_BINARY = CM_TYPE_BASE + 11,    /* binary */
    CM_TYPE_VARBINARY = CM_TYPE_BASE + 12, /* varbinary */
    CM_TYPE_CLOB = CM_TYPE_BASE + 13,      /* clob */
    CM_TYPE_BLOB = CM_TYPE_BASE + 14,      /* blob */
    CM_TYPE_CURSOR = CM_TYPE_BASE + 15,    /* resultset, for stored procedure */
    CM_TYPE_COLUMN = CM_TYPE_BASE + 16,    /* column type, internal used */
    CM_TYPE_BOOLEAN = CM_TYPE_BASE + 17,

    /* timestamp with time zone ,this type is fake, it is abandoned now,
    * you can treat it as CM_TYPE_TIMESTAMP just for compatibility */
    CM_TYPE_TIMESTAMP_TZ_FAKE = CM_TYPE_BASE + 18,
    CM_TYPE_TIMESTAMP_LTZ = CM_TYPE_BASE + 19, /* timestamp with local time zone */
    CM_TYPE_INTERVAL = CM_TYPE_BASE + 20,      /* interval of Postgre style, no use */
    CM_TYPE_INTERVAL_YM = CM_TYPE_BASE + 21,   /* interval YEAR TO MONTH */
    CM_TYPE_INTERVAL_DS = CM_TYPE_BASE + 22,   /* interval DAY TO SECOND */
    CM_TYPE_RAW = CM_TYPE_BASE + 23,           /* raw */
    CM_TYPE_IMAGE = CM_TYPE_BASE + 24,         /* image, equals to longblob */
    CM_TYPE_UINT32 = CM_TYPE_BASE + 25,        /* unsigned integer */
    CM_TYPE_UINT64 = CM_TYPE_BASE + 26,        /* unsigned bigint */
    CM_TYPE_SMALLINT = CM_TYPE_BASE + 27,      /* 16-bit integer */
    CM_TYPE_USMALLINT = CM_TYPE_BASE + 28,     /* unsigned 16-bit integer */
    CM_TYPE_TINYINT = CM_TYPE_BASE + 29,       /* 8-bit integer */
    CM_TYPE_UTINYINT = CM_TYPE_BASE + 30,      /* unsigned 8-bit integer */
    CM_TYPE_FLOAT = CM_TYPE_BASE + 31,         /* 4-byte float */

    // !!!add new member must ensure not exceed the limitation of g_type_maps in sql_oper_func.c
    /* the real tz type , CM_TYPE_TIMESTAMP_TZ_FAKE will be not used , it will be the same as CM_TYPE_TIMESTAMP */
    CM_TYPE_TIMESTAMP_TZ = CM_TYPE_BASE + 32, /* timestamp with time zone */
    CM_TYPE_ARRAY = CM_TYPE_BASE + 33,         /* array */
    /* com */
    /* caution: SCALAR type must defined above */
    CM_TYPE_OPERAND_CEIL = CM_TYPE_BASE + 40,   // ceil of operand type

    /* The datatype can't used in datatype caculation system. only used for
    * decl in/out param in pl/sql */
    CM_TYPE_RECORD = CM_TYPE_BASE + 41,
    CM_TYPE_COLLECTION = CM_TYPE_BASE + 42,

    /* The datatype below the CM_TYPE__DO_NOT_USE can be used as database DATATYPE.
    * In some extend, CM_TYPE__DO_NOT_USE represents the maximal number
    * of DATATYPE that Zenith are supported. The newly adding datatype
    * must before CM_TYPE__DO_NOT_USE, and the type_id must be consecutive */
    CM_TYPE__DO_NOT_USE = CM_TYPE_BASE + 44,

    /* The following datatypes are functional datatypes, which can help
    * to implement some features when needed. Note that they can not be
    * used as database DATATYPE */
    /* to present a datatype node, for example cast(para1, typenode),
    * the second argument is an expr_node storing the information of
    * a datatype, such as length, precision, scale, etc.. */
    CM_TYPE_FUNC_BASE = CM_TYPE_BASE + 200,
    CM_TYPE_TYPMODE = CM_TYPE_FUNC_BASE + 1,

    /* This datatype only be used in winsort aggr */
    CM_TYPE_VM_ROWID = CM_TYPE_FUNC_BASE + 2,
    CM_TYPE_ITVL_UNIT = CM_TYPE_FUNC_BASE + 3,
    CM_TYPE_UNINITIALIZED = CM_TYPE_FUNC_BASE + 4,

    /* The following datatypes be used for native date or timestamp type value to bind */
    CM_TYPE_NATIVE_DATE = CM_TYPE_FUNC_BASE + 5,      // native datetime, internal used
    CM_TYPE_NATIVE_TIMESTAMP = CM_TYPE_FUNC_BASE + 6, // native timestamp, internal used
    CM_TYPE_LOGIC_TRUE = CM_TYPE_FUNC_BASE + 7,      // native true, internal used
} cm_type_t;

#endif /* CM_TYPES_DEFINED */

#endif /* __CM_TYPES_H__ */

