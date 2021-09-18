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
 * dcf_version.c
 *    DCF version
 *
 * IDENTIFICATION
 *    src/dcf_version.c
 *
 * -------------------------------------------------------------------------
 */

#include <stdarg.h>
#ifdef __cplusplus
extern "C" {
#endif


#ifdef WIN32
#define EXPORT_API __declspec(dllexport)
#else
#define EXPORT_API __attribute__ ((visibility ("default")))
#endif

DCF_LIB_VERSION;
EXPORT_API const char *GETLIBVERSION()
{
#ifdef WIN32
    return NULL;
#else
    return str_DCF_LIB_VERSION;
#endif
}

#ifdef __cplusplus
}
#endif
