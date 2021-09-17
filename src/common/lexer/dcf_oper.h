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
 * dcf_oper.h
 *
 *
 * IDENTIFICATION
 *    src/common/lexer/dcf_oper.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DCF_OPER_H__
#define __DCF_OPER_H__

#ifdef __cplusplus
extern "C" {
#endif

    typedef enum en_operator_type {
        OPER_TYPE_ROOT = 0,  // UNARY OPERATOR
        OPER_TYPE_PRIOR = 1,
        OPER_TYPE_MUL = 2,
        OPER_TYPE_DIV = 3,
        OPER_TYPE_MOD = 4,
        OPER_TYPE_ADD = 5,
        OPER_TYPE_SUB = 6,
        OPER_TYPE_LSHIFT = 7,
        OPER_TYPE_RSHIFT = 8,
        OPER_TYPE_BITAND = 9,
        OPER_TYPE_BITXOR = 10,
        OPER_TYPE_BITOR = 11,
        OPER_TYPE_CAT = 12,

        // !!!add new member must ensure not exceed the limitation 'OPER_TYPE_CEIL'
        OPER_TYPE_CEIL = 13
    } operator_type_t;

#ifdef __cplusplus
}
#endif

#endif