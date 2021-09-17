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
 * cm_timezone.c
 *
 *
 * IDENTIFICATION
 *    src/common/cm_time/cm_timezone.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_log.h"
#include "cm_text.h"
#include "cm_timezone.h"

#ifdef WIN32
#include <Winbase.h>
#endif

const char *g_default_tzoffset_fmt = "%c%02d:%02d";
