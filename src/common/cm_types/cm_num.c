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
 * cm_num.c
 *    Implement of num
 *
 * IDENTIFICATION
 *    src/common/cm_types/cm_num.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_num.h"
#include "cm_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

static digitext_t g_int16_ceil = { "65535", 5 };

/* The numeric text of the max and the min integer */
static digitext_t g_pos_int32_ceil = { "2147483647", 10 };
static digitext_t g_neg_int32_ceil = { "2147483648", 10 };
static digitext_t g_uint32_ceil = { "4294967295", 10 };
/* The numeric text of the max and the min bigint */
static digitext_t g_pos_bigint_ceil = { "9223372036854775807",  19 };
static digitext_t g_neg_bigint_ceil = { "9223372036854775808",  19 };
static digitext_t g_uint64_ceil = { "18446744073709551615", 20 };

/** The text value of the maximal double 1.7976931348623158e+308, see DBL_MAX */
static digitext_t g_double_ceil = { "179769313486231", 15 };

const char *g_num_errinfos[NERR__NOT_USED__] = {
    [NERR_SUCCESS] = "",
    [NERR_ERROR] = "",
    [NERR_INVALID_LEN] = "-- text is empty or too long",
    [NERR_NO_DIGIT] = "",
    [NERR_UNEXPECTED_CHAR] = "-- unexpected character",
    [NERR_NO_EXPN_DIGIT] = "-- no digits in exponent",
    [NERR_EXPN_WITH_NCHAR] = "-- unexpected character in exponent",
    [NERR_EXPN_TOO_LONG] = "-- exponent text is too long (< 6)",
    [NERR_EXPN_OVERFLOW] = "-- exponent overflow",
    [NERR_OVERFLOW] = "-- overflow",
    [NERR_UNALLOWED_NEG] = "-- minus sign is not allowed",
    [NERR_UNALLOWED_DOT] = "-- decimal point is not allowed",
    [NERR_UNALLOWED_EXPN] = "-- exponent is not allowed",
    [NERR_MULTIPLE_DOTS] = "-- existing multiple decimal points",
    [NERR_EXPECTED_INTEGER] = "-- integer is expected",
    [NERR_EXPECTED_POS_INT] = "-- non-negative integer is expected",
};

static bool32 cm_diag_int(const text_t *text, const digitext_t *dtext, num_part_t *np)
{
    uint32 i;
    bool32 is_neg = CM_FALSE;
    text_t num_text = *text;

    cm_trim_text(&num_text);

    if (num_text.len == 0) {
        return CM_FALSE;
    }

    if (CM_IS_SIGN_CHAR(num_text.str[0])) {
        is_neg = ('-' == num_text.str[0]);
        CM_REMOVE_FIRST(&num_text);
    }

    // skipping leading zeros
    cm_text_ltrim_zero(&num_text);

    for (i = 0; i < num_text.len; i++) {
        if (i >= dtext->len || !CM_IS_DIGIT(num_text.str[i])) {
            return CM_FALSE;
        }
    }

    text_t num_dtext = {
        .str = (char *)dtext->str,
        .len = dtext->len };
    if (num_text.len == dtext->len && cm_compare_text(&num_text, &num_dtext) > 0) {
        return CM_FALSE;
    }

    if (np != NULL) {
        cm_text2digitext(&num_text, &np->digit_text);
        np->digit_text.len = num_text.len;
        np->has_dot = CM_FALSE;
        np->has_expn = CM_FALSE;
        np->is_neg = is_neg;
    }

    return CM_TRUE;
}

bool32 cm_is_short(const text_t *text)
{
    return cm_diag_int(text, &g_int16_ceil, NULL);
}

/* Decide whether the num_part is REAL or DECIMAL type, if overflow,
* return false. */
static inline num_errno_t cm_decide_decimal_type(const num_part_t *np, cm_type_t *type)
{
    if (np->sci_expn < CM_MAX_REAL_EXPN) {
        // Rule 2.1: if sci_exp > MAX_NUMERIC_EXPN, then it is a double type
        // Rule 2.2: if sci_exp < MIN_NUMERIC_EXPN, then it is a double zero
        // Rule 2.3: used as decimal type
        *type = (np->sci_expn > CM_MAX_NUM_EXPN || np->sci_expn < CM_MIN_NUM_EXPN) ? CM_TYPE_REAL : CM_TYPE_NUMBER;
        return NERR_SUCCESS;
    } else if (np->sci_expn == CM_MAX_REAL_EXPN) {
        if (cm_compare_digitext(&np->digit_text, &g_double_ceil) > 0) {
            return NERR_OVERFLOW;
        }
        // less than the maximal representable double
        *type = CM_TYPE_REAL;
        return NERR_SUCCESS;
    }

    // sci_exp > GS_MAX_REAL_EXPN
    return NERR_OVERFLOW;
}

/* Decide type of an integer num_part, if the num_part is
* + in the range of an int32, type = CM_TYPE_INTEGER;
* + in the range of an bigint, type = CM_TYPE_BIGINT;
* + else, return number type */
static inline num_errno_t cm_decide_integer_type(const num_part_t *np, cm_type_t *type)
{
    const digitext_t *cmp_text = NULL;
    /* Rule 4: no dot and no expn */
    /* Rule 4.1: the precision less than the maximal length of an int32 */
    if (np->digit_text.len < CM_MAX_INT32_PREC) {
        *type = CM_TYPE_INTEGER;
        return NERR_SUCCESS;
    }
    /* Rule 4.2: the precision equal to the maximal length of an int32 */
    if (np->digit_text.len == CM_MAX_INT32_PREC) {
        cmp_text = np->is_neg ? &g_neg_int32_ceil : &g_pos_int32_ceil;
        *type = (cm_compare_digitext(&np->digit_text, cmp_text) > 0) ? CM_TYPE_BIGINT : CM_TYPE_INTEGER;
        return NERR_SUCCESS;
    }
    /* Rule 4.3: the precision less than the maximal length of an int64 */
    if (np->digit_text.len < CM_MAX_INT64_PREC) {
        *type = CM_TYPE_BIGINT;
        return NERR_SUCCESS;
    }

    /* Rule 4.3: the precision equal to the maximal length of an int64 */
    if (np->digit_text.len == CM_MAX_INT64_PREC) {
        cmp_text = np->is_neg ? &g_neg_bigint_ceil : &g_pos_bigint_ceil;
        *type = (cm_compare_digitext(&np->digit_text, cmp_text) > 0) ? CM_TYPE_NUMBER : CM_TYPE_BIGINT;
        return NERR_SUCCESS;
    }

    return NERR_ERROR;
}

num_errno_t cm_decide_numtype(const num_part_t *np, cm_type_t *type)
{
    // Decide the datatype of numeric text
    // Rule 1: if the base part is zero(s), return integer 0
    if (NUMPART_IS_ZERO(np)) {
        *type = CM_TYPE_INTEGER;
        return NERR_SUCCESS;
    }

    // Rule 2: if expn or dot exist, or the text is too long
    if (np->has_expn || np->has_dot || np->digit_text.len > CM_MAX_INT64_PREC) {
        return cm_decide_decimal_type(np, type);
    }

    return cm_decide_integer_type(np, type);
}

num_errno_t cm_numpart2int(num_part_t *np, int32 *value)
{
    if (np->digit_text.len > CM_MAX_INT32_PREC ||
        np->has_dot || np->has_expn) {
        return NERR_ERROR;
    }

    if (np->digit_text.len == CM_MAX_INT32_PREC) {
        int32 cmp_ret = cm_compare_digitext(&np->digit_text,
                                            np->is_neg ? &g_neg_int32_ceil : &g_pos_int32_ceil);
        if (cmp_ret > 0) {
            return NERR_OVERFLOW;
        } else if (cmp_ret == 0) {
            *value = np->is_neg ? CM_MIN_INT32 : CM_MAX_INT32;
            return NERR_SUCCESS;
        }
    }

    CM_NULL_TERM(&np->digit_text);
    *value = atoi(np->digit_text.str);

    if (*value < 0) {
        CM_THROW_ERROR_EX(ERR_ASSERT_ERROR, "*value(%d) >= 0", *value);
        return NERR_ERROR;
    }

    if (np->is_neg) {
        *value = -(*value);
    }
    return NERR_SUCCESS;
}

num_errno_t cm_numpart2uint32(const num_part_t *np, uint32 *value)
{
    if (np->digit_text.len > CM_MAX_UINT32_PREC ||
        np->has_dot || np->has_expn || np->is_neg) {
        return NERR_ERROR;
    }

    if (np->digit_text.len == CM_MAX_UINT32_PREC) {
        int32 cmp_ret = cm_compare_digitext(&np->digit_text, &g_uint32_ceil);
        if (cmp_ret > 0) {
            return NERR_OVERFLOW;
        } else if (cmp_ret == 0) {
            *value = CM_MAX_UINT32;
            return NERR_SUCCESS;
        }
    }

    *value = 0;
    for (uint32 i = 0; i < np->digit_text.len; ++i) {
        *value = (*value) * CM_DEFAULT_DIGIT_RADIX + CM_C2D(np->digit_text.str[i]);
    }

    return NERR_SUCCESS;
}

num_errno_t cm_numpart2uint64(const num_part_t *np, uint64 *value)
{
    if (np->digit_text.len > CM_MAX_UINT64_PREC ||
        np->has_dot || np->is_neg || np->has_expn) {
        return NERR_ERROR;
    }

    if (np->digit_text.len == CM_MAX_UINT64_PREC) {
        int32 cmp_ret = cm_compare_digitext(&np->digit_text, &g_uint64_ceil);
        if (cmp_ret > 0) {
            return NERR_OVERFLOW;
        } else if (cmp_ret == 0) {
            *value = CM_MAX_UINT64;
            return NERR_SUCCESS;
        }
    }

    *value = 0;
    for (uint32 i = 0; i < np->digit_text.len; ++i) {
        if (!CM_IS_DIGIT(np->digit_text.str[i])) {
            CM_THROW_ERROR_EX(ERR_ASSERT_ERROR, "np->digit_text.str(%c) should be a digit", np->digit_text.str[i]);
            return NERR_ERROR;
        }
        *value = (*value) * CM_DEFAULT_DIGIT_RADIX + CM_C2D(np->digit_text.str[i]);
    }

    return NERR_SUCCESS;
}

num_errno_t cm_numpart2size(const num_part_t *np, int64 *value)
{
    int64 unit;
    num_errno_t err_no = cm_numpart2bigint(np, value);
    CM_CHECK_NUM_ERRNO(err_no);

    if (*value < 0) {
        return NERR_EXPECTED_POS_INT;
    }

    unit = 0;
    switch (np->sz_indicator) {
        case 'k':
        case 'K':
            unit = 10;
            break;

        case 'm':
        case 'M':
            unit = 20;
            break;

        case 'g':
        case 'G':
            unit = 30;
            break;

        case 't':
        case 'T':
            unit = 40;
            break;

        case 'p':
        case 'P':
            unit = 50;
            break;

        case 'e':
        case 'E':
            unit = 60;
            break;

        default:
        case 'b':
        case 'B':
            break;
    }

    // overflow
    if (*value > (CM_MAX_INT64 >> unit)) {
        return NERR_OVERFLOW;
    }

    *value = *value << unit;
    return NERR_SUCCESS;
}

/*  The maximal buff size for parsing a decimal, The MAX_NUMERIC_BUFF is
*  set to be greater than MAX_NUM_PRECISION, which can be captured
*  more significant digits, and thus can promote high calculation accuracy.
*  The bigger the value is, the more accuracy it can be improved, but may
*  weaken the performance.
*/
#define MAX_NUMERIC_BUFF 40

/** recording the significant digits into num_part */
static inline void cm_record_digit(num_part_t *np, int32 *precision, int32 *prec_offset, int32 pos, char c)
{
    if (*precision >= 0) {
        ++(*precision);
        if (*precision > (MAX_NUMERIC_BUFF + 1)) {
            // if the buff is full, ignoring the later digits
            return;
        } else if (*precision == (MAX_NUMERIC_BUFF + 1)) {
            // mark the rounding mode is needed
            np->do_round = (c >= '5');
            return;
        }
    } else {
        *precision = 1;
    }

    if (*precision == 1) {
        // if found the first significant digit, records its position
        *prec_offset = pos;
    }
    CM_TEXT_APPEND(&np->digit_text, c);
}

/** calculate expn of the significant digits */
static inline int32 cm_calc_significand_expn(int32 dot_offset, int32 prec_offset, int32 precision)
{
    // Step 3.1. compute the sci_exp
    if (dot_offset >= 0) { /* if a dot exists */
        /* Now, prec_offset records the distance from the first significant digit to the dot.
        * dot_offset > 0 means dot is counted, thus this means the sci_exp should subtract one.  */
        dot_offset -= prec_offset;
        return ((dot_offset > 0) ? dot_offset - 1 : dot_offset);
    } else {
        return precision - 1;
    }
}

/** CM_MAX_EXPN must greater than the maximal exponent that DB can capacity.
* In current system, the maximal exponent is 308 for double. Therefore, the
* value is set to 99999999 is reasonable. */
#define CM_MAX_EXPN 99999999

/**
* Parse an exponent from the numeric text *dec_text*, i is the offset
* of exponent. When unexpected character occur or the exponent overflow,
* an error will be returned.
*/
static inline num_errno_t cm_parse_num_expn(const text_t *expn_text, int32 *expn)
{
    char c;
    int32 tmp_exp;
    bool32 is_negexp = CM_FALSE;
    uint32 i = 0;

    // handle the sign of exponent
    c = expn_text->str[i];
    if (CM_IS_SIGN_CHAR(c)) {
        is_negexp = (c == '-');
        c = expn_text->str[++i];  // move to next character
    }
    if (i >= expn_text->len) { /* if no exponent digits, return error  */
        CM_THROW((i >= expn_text->len), NERR_NO_EXPN_DIGIT);
    }

    // skip leading zeros in the exponent
    while (CM_IS_ZERO(c)) {
        ++i;
        if (i >= expn_text->len) {
            *expn = 0;
            return NERR_SUCCESS;
        }
        c = expn_text->str[i];
    }

    // too many nonzero exponent digits
    tmp_exp = 0;
    for (;;) {
        CM_THROW((!CM_IS_DIGIT(c)), NERR_EXPN_WITH_NCHAR);

        if (tmp_exp < CM_MAX_EXPN) {  // to avoid int32 overflow
            tmp_exp = tmp_exp * CM_DEFAULT_DIGIT_RADIX + CM_C2D(c);
        }

        ++i;
        if (i >= expn_text->len) {
            break;
        }
        c = expn_text->str[i];
    }

    // check exponent overflow on positive integer
    CM_THROW((!is_negexp && tmp_exp > CM_MAX_EXPN), NERR_OVERFLOW);

    *expn = is_negexp ? -tmp_exp : tmp_exp;

    return NERR_SUCCESS;
}

static inline num_errno_t cm_num_fetch_sign(num_part_t* np, int32* i, text_t* text)
{
    if ((*text).str[*i] == '-') {  // leading minus means negative
        // if negative sign is not allowed
        if (np->excl_flag & NF_NEGATIVE_SIGN) {
            return NERR_UNALLOWED_NEG;
        }
        np->is_neg = CM_TRUE;
        (*i)++;
    } else if ((*text).str[*i] == '+') {  // leading + allowed
        (*i)++;
    }
    return NERR_SUCCESS;
}

static inline num_errno_t cm_num_cal_expn(const text_t* num_text, num_part_t* np, int32 dot_offset, int32 prec_offset,
    int32 precision)
{
    if (precision < 0) {
        return NERR_NO_DIGIT;
    }

    if (precision == 0) {
        CM_ZERO_NUMPART(np);
        return NERR_SUCCESS;
    }

    // Step 3: Calculate the scale of the total number text
    np->sci_expn += cm_calc_significand_expn(dot_offset, prec_offset, precision);

    if (np->digit_text.len > num_text->len || np->digit_text.len >= CM_MAX_NUM_PART_BUFF) {
        CM_THROW_ERROR_EX(ERR_ASSERT_ERROR,
                          "np->digit_text.len(%u) <= num_text->len(%u) and "
                          "np->digit_text.len(%u) < CM_MAX_NUM_PART_BUFF(%d)",
                          np->digit_text.len, num_text->len, np->digit_text.len, CM_MAX_NUM_PART_BUFF);
        return NERR_ERROR;
    }
    return NERR_SUCCESS;
}

num_errno_t cm_split_num_text(const text_t *num_text, num_part_t *np)
{
    int32 i = 0;
    char c;
    text_t text;                   /** the temporary text */
    int32 dot_offset = -1;         /** '.' offset, -1 if none */
    int32 prec_offset = -1;        /** the offset of the first significant digit, -1 if none */
    int32 precision = -1;          /** see comments of the function */
    bool32 leading_flag = CM_TRUE; /** used to ignore leading zeros */

    /* When the number of significant digits exceeds the digit_buf
    * Then, a round happens when the MAX_NUMERIC_BUFF+1 significant
    * digit is equal and greater than '5' */
    INIT_NUMPART(np);

    text = *num_text;
    cm_trim_text(&text);

    CM_THROW((text.len == 0 || text.len >= SIZE_M(1)), NERR_INVALID_LEN); // text.len > 2^15

    /* Step 1. fetch the sign of the decimal */
    num_errno_t fetch_num_errno = cm_num_fetch_sign(np, &i, &text);
    CM_CHECK_NUM_ERRNO(fetch_num_errno);

    /* check again */
    CM_THROW((i >= (int32)text.len), NERR_NO_DIGIT);

    /* Step 2. parse the scale, exponent, precision, Significant value of the decimal */
    for (; i < (int32)text.len; ++i) {
        c = text.str[i];
        if (leading_flag) {  // ignoring leading zeros
            if (CM_IS_ZERO(c)) {
                precision = 0;
                continue;
            } else if (c != '.') {
                leading_flag = CM_FALSE;
            }
        }

        if (CM_IS_DIGIT(c)) {  // recording the significant
            cm_record_digit(np, &precision, &prec_offset, i, c);
            continue;
        } else if (CM_IS_DOT(c)) {
            // check is allowed dot
            CM_THROW((np->excl_flag & NF_DOT), NERR_UNALLOWED_DOT);

            // check is more than one dot
            CM_THROW((dot_offset >= 0), NERR_MULTIPLE_DOTS);

            dot_offset = i;
            np->has_dot = CM_TRUE;
            continue;
        } else if (!CM_IS_EXPN_CHAR(c)) {         // begin to handle and fetch exponent
            return NERR_UNEXPECTED_CHAR;
        }

        // Exclude: 'E0012', '.E0012', '-E0012', '+.E0012', .etc
        CM_THROW((precision < 0), NERR_UNEXPECTED_CHAR);

        // check is exponent
        CM_THROW((np->excl_flag & NF_EXPN), NERR_UNALLOWED_EXPN);

        // redirect text pointing to expn part
        text.str += (i + 1);
        text.len -= (i + 1);
        num_errno_t nerr = cm_parse_num_expn(&text, &np->sci_expn);
        CM_CHECK_NUM_ERRNO(nerr);
        np->has_expn = CM_TRUE;
        break;
    }  // end for

    // Step 3: Calculate the scale of the total number text
    return cm_num_cal_expn(num_text, np, dot_offset, prec_offset, precision);
}

static bool32 cm_is_err(const char *err)
{
    if (err == NULL) {
        return CM_FALSE;
    }

    while (*err != '\0') {
        if (*err != ' ') {
            return CM_TRUE;
        }
        err++;
    }

    return CM_FALSE;
}

status_t cm_str2uint16(const char *str, uint16 *value)
{
    char *err = NULL;
    int64 val_int64 = strtol(str, &err, CM_DEFAULT_DIGIT_RADIX);
    if (cm_is_err(err)) {
        CM_THROW_ERROR_EX(ERR_VALUE_ERROR, "Convert uint16 failed, text = %s", str);
        return CM_ERROR;
    }

    if (val_int64 > USHRT_MAX || val_int64 < 0) {
        CM_THROW_ERROR_EX(ERR_VALUE_ERROR,
                          "Convert uint16 failed, the number text is not in the range of uint16, text = %s", str);
        return CM_ERROR;
    }

    *value = (uint16)val_int64;
    return CM_SUCCESS;
}

status_t cm_str2uint32(const char *str, uint32 *value)
{
    char *err = NULL;
    int ret = cm_check_is_number(str);
    if (ret != CM_SUCCESS) {
        return CM_ERROR;
    }

    int64 val_int64 = strtoll(str, &err, CM_DEFAULT_DIGIT_RADIX);
    if (cm_is_err(err)) {
        CM_THROW_ERROR_EX(ERR_VALUE_ERROR, "Convert uint32 failed, text = %s", str);
        return CM_ERROR;
    }

    if (val_int64 > UINT_MAX || val_int64 < 0) {
        CM_THROW_ERROR_EX(ERR_VALUE_ERROR,
                          "Convert uint32 failed, the number text is not in the range of uint32, text = %s", str);
        return CM_ERROR;
    }

    *value = (uint32)val_int64;
    return CM_SUCCESS;
}

status_t cm_str2uint64(const char *str, uint64 *value)
{
    char *err = NULL;
    int ret = cm_check_is_number(str);
    if (ret != CM_SUCCESS) {
        return CM_ERROR;
    }

    *value = strtoull(str, &err, CM_DEFAULT_DIGIT_RADIX);
    if (cm_is_err(err)) {
        CM_THROW_ERROR_EX(ERR_VALUE_ERROR, "Convert uint64 failed, text = %s", str);
        return CM_ERROR;
    }

    if (*value == UINT64_MAX) {  // if str = "18446744073709551616", *value will be ULLONG_MAX
        if (cm_compare_str(str, (const char *)UINT64_MAX) != 0) {
            CM_THROW_ERROR_EX(ERR_VALUE_ERROR,
                "Convert int64 failed, the number text is not in the range of unsigned long long, text = %s", str);
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

status_t cm_text2uint16(const text_t *text_src, uint16 *value)
{
    char buf[CM_MAX_NUMBER_LEN + 1] = { 0 };
    text_t text = *text_src;

    cm_trim_text(&text);

    if (text.len > CM_MAX_NUMBER_LEN) {
        CM_THROW_ERROR_EX(ERR_VALUE_ERROR, "Convert uint16 failed, the length of text can't be larger than %u",
                          CM_MAX_NUMBER_LEN);
        return CM_ERROR;
    }
    CM_RETURN_IFERR(cm_text2str(&text, buf, CM_MAX_NUMBER_LEN + 1));

    return cm_str2uint16(buf, value);
}

status_t cm_text2uint32(const text_t *text_src, uint32 *value)
{
    char buf[CM_MAX_NUMBER_LEN + 1] = { 0 };  // '00000000000000000000001'
    text_t text = *text_src;

    cm_trim_text(&text);

    if (text.len > CM_MAX_NUMBER_LEN) {
        CM_THROW_ERROR_EX(ERR_VALUE_ERROR,
                          "Convert uint32 failed, the length of text can't be larger than %u",
                          CM_MAX_NUMBER_LEN);
        return CM_ERROR;
    }
    CM_RETURN_IFERR(cm_text2str(&text, buf, CM_MAX_NUMBER_LEN + 1));

    return cm_str2uint32(buf, value);
}

num_errno_t cm_numpart2bigint(const num_part_t *np, int64 *i64)
{
    if (np->digit_text.len > CM_MAX_INT64_PREC || np->has_dot || np->has_expn) {
        return NERR_ERROR;
    }

    if (np->digit_text.len == CM_MAX_INT64_PREC) {
        int32 cmp_ret = cm_compare_digitext(&np->digit_text,
                                            np->is_neg ? &g_neg_bigint_ceil : &g_pos_bigint_ceil);
        if (cmp_ret > 0) {
            return NERR_OVERFLOW;
        } else if (cmp_ret == 0) {
            *i64 = np->is_neg ? CM_MIN_INT64 : CM_MAX_INT64;
            return NERR_SUCCESS;
        }
    }

    int64 val = 0;
    for (uint32 i = 0; i < np->digit_text.len; ++i) {
        if (!CM_IS_DIGIT(np->digit_text.str[i])) {
            CM_THROW_ERROR_EX(ERR_ASSERT_ERROR, "np->digit_text.str(%c) should be a digit", np->digit_text.str[i]);
            return NERR_ERROR;
        }
        val = val * CM_DEFAULT_DIGIT_RADIX + CM_C2D(np->digit_text.str[i]);
    }

    *i64 = np->is_neg ? -val : val;
    return NERR_SUCCESS;
}

status_t cm_check_is_number(const char *str)
{
    int len = strlen(str);
    if (len == 0) {
        return CM_ERROR;
    }

    for (int i = 0; i < len; i++) {
        if (!CM_IS_DIGIT(str[i])) {
            return CM_ERROR;
        }
    }
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
