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
 * ddes_lexer.c
 *
 *
 * IDENTIFICATION
 *    src/common/lexer/ddes_lexer.c
 *
 * -------------------------------------------------------------------------
 */

#include "string.h"
#include "cm_defs.h"
#include "util_error.h"
#include "cm_num.h"
#include "cm_binary.h"
#include "dcf_oper.h"
#include "ddes_lexer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SPILTTER_CHAR     (char)1
#define NAMABLE_CHAR      (char)2
#define VARIANT_HEAD_CHAR (char)3

static const char g_char_map[] = {
    0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x00, 0x02, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00,
    0x00, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x01, 0x01, 0x01, 0x01, 0x03,
    0x00, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00,
    /* unicode , GBK all zero; Chinese all 0x3 except 255p. */
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x00
};

#define IS_SPLITTER(c) (g_char_map[(uint8)(c)] == SPILTTER_CHAR)
#define IS_NAMABLE(c)  (g_char_map[(uint8)(c)] >= NAMABLE_CHAR)
#define IS_NUM(c)  (g_char_map[(uint8)(c)] == NAMABLE_CHAR)
/** [int|bigint]size_indicator */
#define IS_SIZE_INDICATOR(c)                                                                                      \
    ((c) == 'B' || (c) == 'K' || (c) == 'M' || (c) == 'G' || (c) == 'T' || (c) == 'P' || (c) == 'E' || (c) == 'S')
#define IS_MICROSECOND(c)                                                                                         \
    ((c) == 'M')
#define IS_VARIANT_HEAD(c)  (g_char_map[(uint8)(c)] == VARIANT_HEAD_CHAR)


bool32 is_splitter(char c)
{
    return IS_SPLITTER(c);
}

bool32 is_nameble(char c)
{
    return IS_NAMABLE(c);
}

bool32 is_variant_head(char c)
{
    return IS_VARIANT_HEAD(c);
}

static word_type_t lex_diagnose_word_type_by_colon(lex_t *lex)
{
    bool32 result = CM_FALSE;
    char c2 = LEX_NEXT;

    if (c2 == ':') {
        return WORD_TYPE_ANCHOR;
    }

    if (c2 == '=') {
        return WORD_TYPE_PL_SETVAL;
    }

    if (lex_try_fetch(lex, ":NEW.", &result) != CM_SUCCESS) {
        return WORD_TYPE_ERROR;
    }

    if (result) {
        return WORD_TYPE_PL_NEW_COL;
    }

    if (lex_try_fetch(lex, ":OLD.", &result) != CM_SUCCESS) {
        return WORD_TYPE_ERROR;
    }

    if (result) {
        return WORD_TYPE_PL_OLD_COL;
    }

    return WORD_TYPE_PARAM;
}

static inline word_type_t lex_diagnose_word_type1(lex_t *lex, char c1, char c2)
{
    switch (c1) {
        case '(':
        case '{':
        case '[':
            return WORD_TYPE_BRACKET;

        case '.':
            return (c2 >= '0' && c2 <= '9') ? WORD_TYPE_NUMBER : ((c2 == '.') ?
                WORD_TYPE_PL_RANGE : WORD_TYPE_SPEC_CHAR);

        case ',':
            return WORD_TYPE_SPEC_CHAR;

        case '\'':
            return WORD_TYPE_STRING;

        case '*':
        case '+':
            return WORD_TYPE_OPERATOR;

        case '/':
            return c2 == '*' ? WORD_TYPE_COMMENT : WORD_TYPE_OPERATOR;

        case '%':
            return WORD_TYPE_OPERATOR;

        case '-':
            return c2 == '-' ? WORD_TYPE_COMMENT : WORD_TYPE_OPERATOR;
        case '!':
            return c2 == '=' ? WORD_TYPE_COMPARE : WORD_TYPE_ERROR;

        case '<':
            return c2 == '<' ? WORD_TYPE_OPERATOR : WORD_TYPE_COMPARE;

        case '>':
            return c2 == '>' ? WORD_TYPE_OPERATOR : WORD_TYPE_COMPARE;

        case '=':
            return WORD_TYPE_COMPARE;

        case '?':
        case '$':
            return WORD_TYPE_PARAM;

        case ':':
            return lex_diagnose_word_type_by_colon(lex);

        case '|':
        case '&':
        case '^':
            return WORD_TYPE_OPERATOR;

        case '`':
        case '\"':
            return WORD_TYPE_DQ_STRING;

        case ';':
            return WORD_TYPE_PL_TERM;

        case '#':
            return WORD_TYPE_VARIANT;

        default:
            break;
    }

    return WORD_TYPE_ERROR;
}

static word_type_t lex_diagnose_word_type(lex_t *lex)
{
    char c1 = LEX_CURR;
    char c2 = LEX_NEXT;

    if (g_char_map[(uint8)c1] == VARIANT_HEAD_CHAR) {
        if (c1 == 'X' && c2 == '\'') {
            return WORD_TYPE_HEXADECIMAL;
        }

        if ((c1 == 'C' || c1 == 'c') &&
            (c2 == 'O' || c2 == 'o') &&
            lex->curr_text->len >= sizeof("CONNECT_BY_ROOT") - 1 &&
            cm_strcmpni(lex->curr_text->str, "CONNECT_BY_ROOT", sizeof("CONNECT_BY_ROOT") - 1) == 0) {
            return WORD_TYPE_OPERATOR;
        }

        if (lex->curr_text->len >= sizeof("ARRAY[]") - 1 &&
            cm_strcmpni(lex->curr_text->str, "ARRAY[", sizeof("ARRAY[") - 1) == 0) {
            return WORD_TYPE_ARRAY;
        }

        return WORD_TYPE_VARIANT;
    }

    if (c1 >= '0' && c1 <= '9') {
        if (c1 == '0' && c2 == 'x') {
            return WORD_TYPE_HEXADECIMAL;
        }
        return WORD_TYPE_NUMBER;
    }

    return lex_diagnose_word_type1(lex, c1, c2);
}

/** diagnosis whether a word is a NUMBER type or a SIZE type */
static inline bool32 lex_diag_num_word(word_t *word, text_t *text, num_part_t *np)
{
    char c = CM_TEXT_END(&word->text);
    char second2last;
    second2last = CM_TEXT_SECONDTOLAST(&word->text);

    if (CM_IS_DIGIT(c) || CM_IS_DOT(c)) {
        word->type = WORD_TYPE_NUMBER;
        text->str = word->text.str;
        text->len = word->text.len;
    } else {
        c = UPPER(c);
        second2last = UPPER(second2last);

        if (IS_SIZE_INDICATOR(c)) {
            if (np->is_neg || np->has_dot || np->has_expn ||
                word->text.len < 2) {  // the SIZE must be positive, no dot and its length GEQ 2
                return CM_FALSE;
            }

            word->type = WORD_TYPE_SIZE;
            text->str = word->text.str;
            if (IS_MICROSECOND(second2last)) {
                text->len = word->text.len - 2;
                // size must be non-negative, has no dot and expn
                np->excl_flag |= (NF_NEGATIVE_SIGN | NF_DOT | NF_EXPN);
                np->sz_indicator = second2last;
            } else {
                text->len = word->text.len - 1;
                // size must be non-negative, has no dot and expn
                np->excl_flag |= (NF_NEGATIVE_SIGN | NF_DOT | NF_EXPN);
                np->sz_indicator = c;
            }
        } else {  // unexpected character
            return CM_FALSE;
        }
    }

    return CM_TRUE;
}

/**
* To fetch a number without deciding its datatype. The number can be an
* integer, bigint, uint32, uint64, real and decimal;
* This function can also fetch a SIZE WORD with format "[+][int|bigint]size_indicator"
* The definition of excl_flag can refer to the definition of *num_flag_t*
* @see lex_fetch_num
* */
static num_errno_t lex_fetch_numpart(lex_t *lex, word_t *word)
{
    text_t text;
    char c;
    uint32 i = 0;
    num_errno_t err_no;
    num_part_t *np = &word->np;

    np->is_neg = CM_FALSE;
    np->has_dot = CM_FALSE;
    np->has_expn = CM_FALSE;

    // Step 1. simple scan
    if (lex->curr_text->len == 0) return NERR_ERROR;

    c = lex->curr_text->str[i];
    if (c == '-') {
        // if negative sign not allowed
        if (np->excl_flag & NF_NEGATIVE_SIGN) return NERR_UNALLOWED_NEG;
        np->is_neg = CM_TRUE;
        i++;
    } else if (c == '+') {
        i++;
    }
    /* check again */
    if (i >= lex->curr_text->len) return NERR_ERROR;

    for (; i < lex->curr_text->len; i++) {
        c = lex->curr_text->str[i];
        if (CM_IS_DOT(c)) {
            char n;
            // dot not allowed or more than one dot
            if (np->excl_flag & NF_DOT) return NERR_UNALLOWED_DOT;
            if (np->has_dot) return NERR_MULTIPLE_DOTS;

            n = ((i + 1) < lex->curr_text->len) ? lex->curr_text->str[i + 1] : '\0';
            if (CM_IS_DOT(n)) {
                // when meet two dot, back and return.
                break;
            }

            np->has_dot = CM_TRUE;
            continue;
        }
        if (IS_SPLITTER(c)) {
            // +/- are two splitter chars
            // handle scientific 21321E+3213 or 2132E-2323
            if (CM_IS_SIGN_CHAR(c)) {
                if (CM_IS_EXPN_CHAR(lex->curr_text->str[i - 1])) {
                    // expn 'E' or 'e' not allowed
                    if (np->has_expn) return NERR_EXPN_WITH_NCHAR;
                    if (np->excl_flag & NF_EXPN) return NERR_UNALLOWED_EXPN;
                    np->has_expn = CM_TRUE;
                    continue;
                }
            }
            break;
        }

        if (word->type == WORD_TYPE_NUMBER && IS_VARIANT_HEAD(c) && (lex->flags & LEX_IN_COND)) {
            if (CM_IS_EXPN_CHAR(c)) {
                if (CM_IS_SIGN_CHAR(lex->curr_text->str[i + 1]) || IS_NUM(lex->curr_text->str[i + 1])) {
                    continue;
                }
            }
            break;
        }
    }
    // check again
    if (i == 0) return NERR_NO_DIGIT;
    word->text.len = i;

    if (!lex_diag_num_word(word, &text, np)) {
        return NERR_ERROR;
    }

    err_no = cm_split_num_text(&text, np);
    CM_CHECK_NUM_ERRNO(err_no);

    (void)lex_skip(lex, word->text.len);
    return NERR_SUCCESS;
}

/**
 * To fetch a number. The number can be an integer, bigint, real and decimal;
 * This function can also fetch a SIZE WORD with format "[int|bigint]size_indicator"
 * in which the size_indicator can be (capital and lowercase) 'B' (bytes), 'K'(kilobyte)
 * 'M', 'G', 'T', 'P', and 'E' (Exabyte);
 * To allow this function to parse a real/decimal number with scientific format also with
 * the indicator 'E' or 'e'. Obviously, this conflicts with the size indicator 'E',
 * therefore we the indicator E must be specially handled.
 *
 * + If 'E' in the middle of the word, then the word is a number word;
 * + If 'E' is at the end of the word, the word is a size word;
 * + If two or more indicators are found, an error will be returned.
 */
static status_t lex_fetch_num(lex_t *lex, word_t *word)
{
    num_errno_t err_no;
    word->np.excl_flag = NF_NONE;

    err_no = lex_fetch_numpart(lex, word);
    if (err_no != NERR_SUCCESS) {
        LEX_THROW_ERROR_EX(word->loc, ERR_LEX_INVALID_NUMBER, cm_get_num_errinfo(err_no), "fetch number failed");
        return CM_ERROR;
    }

    // process the fetched numeric word, and decide its type
    if (lex->infer_numtype) {
        err_no = cm_decide_numtype(&word->np, (cm_type_t *)&word->id);
        if (err_no != NERR_SUCCESS) {
            LEX_THROW_ERROR_EX(word->loc, ERR_LEX_SYNTAX_ERROR, "invalid number");
            return CM_ERROR;
        }
    } else {
        word->id = CM_TYPE_NUMBER;
    }

    return CM_SUCCESS;
}

static void lex_cmp2any_type(word_t *word)
{
    switch (word->id) {
        case CMP_TYPE_EQUAL:
            word->id = CMP_TYPE_EQUAL_ANY;
            break;
        case CMP_TYPE_NOT_EQUAL:
            // As long as there is a difference, return true, Instead equals all returns false
            word->id = CMP_TYPE_NOT_EQUAL_ANY;
            break;
        case CMP_TYPE_GREAT_EQUAL:
            word->id = CMP_TYPE_GREAT_EQUAL_ANY;
            break;
        case CMP_TYPE_GREAT:
            word->id = CMP_TYPE_GREAT_ANY;
            break;
        case CMP_TYPE_LESS:
            word->id = CMP_TYPE_LESS_ANY;
            break;
        case CMP_TYPE_LESS_EQUAL:
            word->id = CMP_TYPE_LESS_EQUAL_ANY;
            break;
        default:
            break;
    }
}

static void lex_cmp2all_type(word_t *word)
{
    switch (word->id) {
        case CMP_TYPE_EQUAL:
            word->id = CMP_TYPE_EQUAL_ALL;
            break;
        case CMP_TYPE_NOT_EQUAL:
            // As long as one is the same, it returns false, and the other is true.
            word->id = CMP_TYPE_NOT_EQUAL_ALL;
            break;
        case CMP_TYPE_GREAT_EQUAL:
            word->id = CMP_TYPE_GREAT_EQUAL_ALL;
            break;
        case CMP_TYPE_GREAT:
            word->id = CMP_TYPE_GREAT_ALL;
            break;
        case CMP_TYPE_LESS:
            word->id = CMP_TYPE_LESS_ALL;
            break;
        case CMP_TYPE_LESS_EQUAL:
            word->id = CMP_TYPE_LESS_EQUAL_ALL;
            break;
        default:
            break;
    }
}

static status_t lex_fetch_cmp(lex_t *lex, word_t *word)
{
    char curr, next;
    uint32 match_id;

    curr = CM_TEXT_BEGIN(lex->curr_text);
    next = lex_skip(lex, 1);

    if (curr == '<') {
        word->id = (uint32)CMP_TYPE_LESS;
        if (next == '=') {
            (void)lex_skip(lex, 1);
            word->id = (uint32)CMP_TYPE_LESS_EQUAL;
        } else if (next == '>') {
            (void)lex_skip(lex, 1);
            word->id = (uint32)CMP_TYPE_NOT_EQUAL;
        }
    } else if (curr == '>') {
        word->id = CMP_TYPE_GREAT;
        if (next == '=') {
            (void)lex_skip(lex, 1);
            word->id = (uint32)CMP_TYPE_GREAT_EQUAL;
        }
    } else if (curr == '!') {
        if (next != '=') {
            LEX_THROW_ERROR_EX(lex->loc, ERR_LEX_SYNTAX_ERROR, "next == '='");
            return CM_ERROR;
        }
        (void)lex_skip(lex, 1);
        word->id = (uint32)CMP_TYPE_NOT_EQUAL;
    } else {
        word->id = (uint32)CMP_TYPE_EQUAL;
    }

    word->text.len = (uint32)(lex->curr_text->str - word->text.str);

    if (lex_try_fetch_1of3(lex, "ANY", "ALL", "SOME", &match_id) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (match_id == 0 || match_id == 2) {
        lex_cmp2any_type(word);
    } else if (match_id == 1) {
        lex_cmp2all_type(word);
    }

    return CM_SUCCESS;
}

static void lex_fetch_anchor(lex_t *lex, word_t *word)
{
    char c, next;

    c = CM_TEXT_BEGIN(lex->curr_text);
    next = lex_skip(lex, 1);

    switch (c) {
        case ':':
            if (next == ':') {
                (void)lex_skip(lex, 1);
            }
            break;
        default:
            break;
    }
    word->text.len = (uint32)(lex->curr_text->str - word->text.str);
}

static void lex_fetch_oper(lex_t *lex, word_t *word)
{
    char c, next;

    c = CM_TEXT_BEGIN(lex->curr_text);
    next = lex_skip(lex, 1);

    switch (c) {
        case 'c':
        case 'C':
            (void)lex_skip(lex, (uint32)strlen("CONNECT_BY_ROOT") - 1);
            word->id = (uint32)OPER_TYPE_ROOT;
            break;
        case '|':
            if (next == '|') {
                (void)lex_skip(lex, 1);
                word->id = (uint32)OPER_TYPE_CAT;
            } else {
                word->id = (uint32)OPER_TYPE_BITOR;
            }
            break;

        case '+':
            word->id = (uint32)OPER_TYPE_ADD;
            break;

        case '-':
            word->id = (uint32)OPER_TYPE_SUB;
            break;

        case '*':
            word->id = (uint32)OPER_TYPE_MUL;
            break;

        case '/':
            word->id = (uint32)OPER_TYPE_DIV;
            break;

        case '%':
            word->id = (uint32)OPER_TYPE_MOD;
            break;

        case '&':
            word->id = (uint32)OPER_TYPE_BITAND;
            break;
        case '^':
            word->id = (uint32)OPER_TYPE_BITXOR;
            break;
        case '<':
            if (next == '<') {
                (void)lex_skip(lex, 1);
                word->id = (uint32)OPER_TYPE_LSHIFT;
            }
            break;
        case '>':
            if (next == '>') {
                (void)lex_skip(lex, 1);
                word->id = (uint32)OPER_TYPE_RSHIFT;
            }
            break;
        default:
            break;
    }

    word->text.len = (uint32)(lex->curr_text->str - word->text.str);
}

static status_t lex_fetch_comment(lex_t *lex, word_t *word)
{
    char curr, next;
    bool32 finished = CM_FALSE;

    curr = CM_TEXT_BEGIN(lex->curr_text);
    (void)lex_skip(lex, 2);

    if (curr == '-') {       // parse COMMENT LINE
        if (word != NULL) {  // word is not null
            word->id = (uint32)COMMENT_TYPE_LINE;
        }
        curr = LEX_CURR;
        while (curr != '\n' && curr != LEX_END) {
            curr = lex_skip(lex, 1);
        }

        finished = CM_TRUE;
    } else {                 // parse COMMENT SECTION
        if (word != NULL) {  // word is not null
            word->id = (uint32)COMMENT_TYPE_SECTION;
        }
        for (;;) {
            curr = LEX_CURR;
            next = LEX_NEXT;

            if (curr == LEX_END || next == LEX_END) {
                break;
            }

            if (curr == '*' && next == '/') {
                (void)lex_skip(lex, 2);
                finished = CM_TRUE;
                break;
            }

            if (curr == '\n') {
                (void)lex_skip_line_breaks(lex);
            } else {
                (void)lex_skip(lex, 1);
            }
        }
    }

    if (!finished) {
        LEX_THROW_ERROR_EX(LEX_LOC, ERR_LEX_SYNTAX_ERROR, "text is not completed");
        return CM_ERROR;
    }

    if (word != NULL) {  // word is not null
        word->text.len = (uint32)(lex->curr_text->str - word->text.str);
    }

    return CM_SUCCESS;
}

static void lex_fetch_special_char(lex_t *lex, word_t *word)
{
    (void)lex_skip(lex, 1);
    word->text.len = 1;
}

static status_t lex_fetch_name(lex_t *lex, word_t *word)
{
    char c;
    c = lex_skip(lex, 1);

    while (c != LEX_END && c != '@') {
        if (IS_SPLITTER(c)) {
            break;
        }

        if (!IS_NAMABLE(c)) {
            LEX_THROW_ERROR_EX(LEX_LOC, ERR_LEX_SYNTAX_ERROR, "namable char expected but %c found", c);
            return CM_ERROR;
        }

        c = lex_skip(lex, 1);
    }

    word->text.len = (uint32)(lex->curr_text->str - word->text.str);

    if (word->text.len > CM_MAX_NAME_LEN) {
        LEX_THROW_ERROR_EX(word->text.loc, ERR_LEX_SYNTAX_ERROR, "Invalid name, length exceed limit");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t lex_fetch_param(lex_t *lex, word_t *word)
{
    if (CM_TEXT_BEGIN(lex->curr_text) == '?') {
        lex_fetch_special_char(lex, word);
        return CM_SUCCESS;
    } else {
        return lex_fetch_name(lex, word);
    }
}

static status_t lex_expected_fetch_extra(lex_t *lex, word_t *ex_word)
{
    bool32 result = CM_FALSE;
    uint32 flags = lex->flags;

    lex->flags = LEX_SINGLE_WORD;

    if (lex_fetch(lex, ex_word) != CM_SUCCESS) {
        lex->flags = flags;
        return CM_ERROR;
    }

    lex->flags = flags;

    result = IS_VARIANT(ex_word) || (ex_word->type == WORD_TYPE_RESERVED && (ex_word->namable ||
        ex_word->id == RES_WORD_ROWID || ex_word->id == RES_WORD_ROWSCN));
    if (!result) {
        LEX_THROW_ERROR_EX(LEX_LOC, ERR_LEX_SYNTAX_ERROR, "expression expected but '%s' found", W2S(ex_word));
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static bool32 lex_is_unnamable_function(const word_t *word)
{
    return (word->type == WORD_TYPE_DATATYPE && cm_strcmpni(word->text.str, "char", strlen("char")) == 0) ||
           (word->type == WORD_TYPE_KEYWORD && cm_strcmpni(word->text.str, "insert", strlen("insert")) == 0) ||
           (word->type == WORD_TYPE_KEYWORD && cm_strcmpni(word->text.str, "values", strlen("values")) == 0);
}

static status_t lex_fetch_variant(lex_t *lex, word_t *word, bool32 in_hint)
{
    uint32 flags = lex->flags;
    word_t ex_word;
    bool32 result = CM_FALSE;

    CM_RETURN_IFERR(lex_fetch_name(lex, word));

    if (SECUREC_UNLIKELY(in_hint)) {
        return lex_match_hint_keyword(lex, word);
    }

    word->namable = CM_TRUE;
    if (word->type != WORD_TYPE_PL_ATTR) {
        CM_RETURN_IFERR(lex_match_keyword(lex, word));
    }

    if (!word->namable && !lex_is_unnamable_function(word)) {
        return CM_SUCCESS;
    }

    if (lex->ext_flags != 0) {
        flags = lex->ext_flags;
    }

    // If word is prior, don't need fetch arg.
    if ((flags & LEX_WITH_ARG) && (word->id != OPER_TYPE_PRIOR)) {
        CM_RETURN_IFERR(lex_try_fetch_rbrackets(lex, &ex_word, &result));

        if (result) {
            cm_trim_text(&ex_word.text.txt);

            if (ex_word.text.len == 1 && ex_word.text.str[0] == '+') {
                word->type = WORD_TYPE_JOIN_COL;
            } else {
                word->ex_words[word->ex_count].type = ex_word.type;
                word->ex_words[word->ex_count].text = ex_word.text;
                word->ex_count++;
                word->type = WORD_TYPE_FUNCTION;
            }
        }
    }
    lex->ext_flags = 0;

    return CM_SUCCESS;
}

static status_t lex_fetch_quota(lex_t *lex, word_t *word, char quota)
{
    bool32 finished = CM_FALSE;
    char curr, next;

    curr = lex_move(lex);

    char charcurr = LEX_CURR;
    char charnext = LEX_NEXT;
    if (charcurr == '0' && charnext == 'x') {
        word->id = CM_TYPE_BINARY;
    }

    while (curr != LEX_END) {
        if (curr == quota) {
            next = LEX_NEXT;

            if (next == quota) {  // a''b => a'b
                curr = lex_skip(lex, 2);
                continue;
            }

            (void)lex_skip(lex, 1);
            finished = CM_TRUE;
            break;
        }

        curr = lex_move(lex);
    }

    if (!finished) {
        LEX_THROW_ERROR_EX(LEX_LOC, ERR_LEX_SYNTAX_ERROR, "text is not completed");
        return CM_ERROR;
    }

    word->text.len = (uint32)(lex->curr_text->str - word->text.str);

    return CM_SUCCESS;
}

static status_t lex_fetch_dquota(lex_t *lex, word_t *word)
{
    word_t ex_word;
    bool32 result = CM_FALSE;

    if (lex_fetch_quota(lex, word, '"') != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (word->text.len <= 2) {
        LEX_THROW_ERROR_EX(word->loc, ERR_LEX_SYNTAX_ERROR, "invalid identifier, length 0");
        return CM_ERROR;
    }

    CM_REMOVE_ENCLOSED_CHAR(&word->text);

    if (word->text.len > CM_MAX_NAME_LEN) {
        LEX_THROW_ERROR_EX(word->text.loc, ERR_LEX_SYNTAX_ERROR, "text is too long, max is %d",
            CM_MAX_NAME_LEN);
        return CM_ERROR;
    }

    if (lex->flags & LEX_WITH_ARG) {
        if (lex_try_fetch_rbrackets(lex, &ex_word, &result) != CM_SUCCESS) {
            return CM_ERROR;
        }

        if (result) {
            word->ex_words[word->ex_count].text = ex_word.text;
            word->ex_count++;
            word->ori_type = word->type;
            word->type = WORD_TYPE_FUNCTION;
        }
    }

    return CM_SUCCESS;
}

status_t lex_try_fetch_dquota(lex_t *lex, word_t *word, bool32 *result)
{
    lang_text_t *text = lex->curr_text;
    if (lex_skip_comments(lex, word) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (!(text->len > 0 && *text->str == DOUBLE_QUOTATION)) {
        *result = CM_FALSE;
        return CM_SUCCESS;
    }
    *result = CM_TRUE;
    return lex_fetch_dquota(lex, word);
}

static status_t lex_fetch_string(lex_t *lex, word_t *word)
{
    status_t ret = lex_fetch_quota(lex, word, SINGLE_QUOTATION);
    CM_REMOVE_ENCLOSED_CHAR(&word->text);
    return ret;
}

static status_t lex_fetch_brackets(lex_t *lex, word_t *word, const char *brackets)
{
    char c;
    bool32 in_squota = CM_FALSE;
    bool32 in_dquota = CM_FALSE;
    uint32 depth = 1;

    c = lex_move(lex);

    while (c != LEX_END) {
        if (c == SINGLE_QUOTATION) {
            in_squota = !in_squota;
            c = lex_move(lex);
            continue;
        }
        if (in_squota) {
            c = lex_move(lex);
            continue;
        }

        if (c == DOUBLE_QUOTATION) {
            in_dquota = !in_dquota;
            c = lex_move(lex);
            continue;
        }

        if (in_dquota) {
            c = lex_move(lex);
            continue;
        }

        if (c == LBRACKET(brackets)) {
            depth++;
        } else if (c == RBRACKET(brackets)) {
            depth--;
            if (depth == 0) {
                (void)lex_skip(lex, 1);
                break;
            }
        }

        c = lex_move(lex);
    }

    if (in_dquota || in_squota || depth != 0) {
        LEX_THROW_ERROR_EX(LEX_LOC, ERR_LEX_SYNTAX_ERROR, "text is not completed");
        return CM_ERROR;
    }

    word->text.len = (uint32)(lex->curr_text->str - word->text.str);
    return CM_SUCCESS;
}

status_t lex_try_fetch_brackets(lex_t *lex, word_t *word, const char *brackets, bool32 *result)
{
    lang_text_t *text = lex->curr_text;
    if (lex_skip_comments(lex, word) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (!(text->len > 0 && *text->str == LBRACKET(brackets))) {
        *result = CM_FALSE;
        return CM_SUCCESS;
    }
    *result = CM_TRUE;
    word->type = WORD_TYPE_BRACKET;
    return lex_fetch_brackets(lex, word, brackets);
}

status_t lex_try_fetch_rbrackets(lex_t *lex, word_t *word, bool32 *result)
{
    status_t ret;
    ret = lex_try_fetch_brackets(lex, word, ROUND_BRACKETS, result);
    if (result) {
        lex_remove_brackets(&word->text, ROUND_BRACKETS);
    }
    return ret;
}

status_t lex_try_fetch_sbrackets(lex_t *lex, word_t *word, bool32 *result)
{
    status_t ret;
    ret = lex_try_fetch_brackets(lex, word, SQUARE_BRACKETS, result);
    if (result) {
        lex_remove_brackets(&word->text, SQUARE_BRACKETS);
    }
    return ret;
}

status_t lex_try_fetch_cbrackets(lex_t *lex, word_t *word, bool32 *result)
{
    status_t ret;
    ret = lex_try_fetch_brackets(lex, word, CURLY_BRACKETS, result);
    if (result) {
        lex_remove_brackets(&word->text, CURLY_BRACKETS);
    }
    return ret;
}

static status_t lex_fetch_pl_setval(lex_t *lex, word_t *word)
{
    word->text.str = lex->curr_text->str;
    word->text.len = 2;
    (void)lex_move(lex);
    (void)lex_move(lex);
    return CM_SUCCESS;
}

status_t lex_fetch_pl_label(lex_t *lex, word_t *word)
{
    bool32 finished = CM_FALSE;
    char curr, next;

    curr = *lex->curr_text->str;
    word->text.str = lex->curr_text->str;
    LEX_SAVE(lex);

    do {
        next = LEX_NEXT;
        if ((curr == '>') && (next == '>')) {  // a''b => a'b
            (void)lex_move(lex);
            (void)lex_move(lex);
            finished = CM_TRUE;
            break;
        }
        curr = lex_move(lex);
    } while (next != LEX_END);

    if (!finished) {
        LEX_THROW_ERROR_EX(LEX_LOC, ERR_LEX_SYNTAX_ERROR, "text is not completed");
        return CM_ERROR;
    }

    LEX_RESTORE(lex);

    if (lex_expected_fetch(lex, word) != CM_SUCCESS) {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t lex_fetch_new_or_old_col(lex_t *lex, word_t *word)
{
    word_t ex_word;

    if (lex_expected_fetch_extra(lex, &ex_word) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (ex_word.ex_count > 0) {
        LEX_THROW_ERROR_EX(word->loc, ERR_LEX_SYNTAX_ERROR, "invalid column");
        return CM_ERROR;
    }

    word->ex_words[0].text = ex_word.text;
    word->ex_words[0].type = ex_word.type;
    word->ex_count = 1;
    word->text.len = (uint32)(lex->curr_text->str - word->text.str);
    cm_rtrim_text(&word->text.txt);
    return CM_SUCCESS;
}

static status_t lex_fetch_hexadecimal_val(lex_t *lex, word_t *word)
{
    char curr = LEX_CURR;
    char next = LEX_NEXT;

    if ((curr == 'X' && next == '\'') || (curr == '0' && next == 'x')) {
        (void)lex_skip(lex, 2);

        for (;;) {
            curr = LEX_CURR;

            if (curr == LEX_END) {
                break;
            }

            if (!((curr >= '0' && curr <= '9') || (curr >= 'a' && curr <= 'f') || (curr >= 'A' && curr <= 'F') ||
                  curr == '\'')) {
                break;
            }

            (void)lex_skip(lex, 1);
        }

        word->text.len = (uint32)(lex->curr_text->str - word->text.str);
        word->id = CM_TYPE_BINARY;
    }
    return CM_SUCCESS;
}

status_t lex_try_match_array(lex_t *lex, uint8 *is_array)
{
    uint32 num;
    bool32 result = CM_FALSE;

    LEX_SAVE(lex);
    *is_array = CM_FALSE;

    if (lex_try_fetch(lex, "[", &result) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (result) {
        if (lex_try_fetch(lex, "]", &result) != CM_SUCCESS) {
            return CM_ERROR;
        }

        if (result) {
            *is_array = CM_TRUE;
        } else {
            if (lex_expected_fetch_uint32(lex, &num) != CM_SUCCESS) {
                LEX_RESTORE(lex);
                return CM_ERROR;
            }

            if (lex_expected_fetch_word(lex, "]") != CM_SUCCESS) {
                LEX_RESTORE(lex);
                return CM_ERROR;
            }

            *is_array = CM_TRUE;
        }
    } else {
        LEX_RESTORE(lex);
        return CM_SUCCESS;
    }

    return CM_SUCCESS;
}

status_t lex_try_fetch_subscript(lex_t *lex, int32 *ss_start, int32 *ss_end)
{
    int32 start;
    int32 end;
    bool32 result;
    LEX_SAVE(lex);

    if (lex_try_fetch(lex, "[", &result) != CM_SUCCESS) {
        return CM_ERROR;
    }

    do {
        if (result) {
            if (lex_expected_fetch_int32(lex, &start) != CM_SUCCESS) {
                LEX_RESTORE(lex);
                cm_reset_error();
                break;
            }
            if (start <= 0) {
                LEX_THROW_ERROR(LEX_LOC, ERR_LEX_SYNTAX_ERROR, "invalid array subscript");
                return CM_ERROR;
            }
            if (lex_try_fetch(lex, "]", &result) != CM_SUCCESS) {
                return CM_ERROR;
            }

            /* f1[m] */
            if (result) {
                *ss_start = start;
                *ss_end = CM_INVALID_ID32;
                return CM_SUCCESS;
            }

            /* f1[m:n] */
            if (lex_expected_fetch_word(lex, ":") != CM_SUCCESS) {
                LEX_RESTORE(lex);
                cm_reset_error();
                break;
            }

            if (lex_expected_fetch_int32(lex, &end) != CM_SUCCESS) {
                LEX_RESTORE(lex);
                cm_reset_error();
                break;
            }

            if (end <= 0) {
                LEX_THROW_ERROR(LEX_LOC, ERR_LEX_SYNTAX_ERROR, "invalid array subscript");
                return CM_ERROR;
            }

            if (lex_expected_fetch_word(lex, "]") != CM_SUCCESS) {
                LEX_RESTORE(lex);
                cm_reset_error();
                break;
            }

            *ss_start = start;
            *ss_end = end;
            return CM_SUCCESS;
        }
    }while (0);

    *ss_start = (int32)CM_INVALID_ID32;
    *ss_end = (int32)CM_INVALID_ID32;
    return CM_SUCCESS;
}

status_t lex_fetch_array(lex_t *lex, word_t *word)
{
    char curr;
    word_t tmp_word;
    word->ex_count = 0;

    (void)lex_skip(lex, sizeof("ARRAY[") - 1);

    /* fetch the array content inside the [] */
    lex_begin_fetch(lex, word);
    curr = LEX_CURR;
    while (curr != LEX_END && curr != ']') {
        if (curr == '\'' || curr == '"') {
            if (lex_fetch_quota(lex, &tmp_word, curr) != CM_SUCCESS) {
                return CM_ERROR;
            }
            curr = LEX_CURR;
        } else {
            curr = lex_move(lex);
        }
    }

    if (curr != ']') {
        LEX_THROW_ERROR(LEX_LOC, ERR_LEX_INVALID_ARRAY_FORMAT, "not end character ]");
        return CM_ERROR;
    } else {
        word->text.len = (uint32)(lex->curr_text->str - word->text.str);
        word->id = CM_TYPE_ARRAY;
        (void)lex_skip(lex, 1); // skip ]
    }

    return CM_SUCCESS;
}

static void lex_fetch_range_char(lex_t *lex, word_t *word)
{
    (void)lex_skip(lex, 2);
    word->text.len = 2;
}

static status_t lex_fetch_word(lex_t *lex, word_t *word, bool32 in_hint)
{
    status_t status;

    if (lex->stack.depth == 0) {
        word->type = WORD_TYPE_EOF;
        return CM_SUCCESS;
    }

    word->namable = CM_TRUE;
    word->id = CM_INVALID_ID32;
    word->ex_count = 0;
    word->ori_type = WORD_TYPE_UNKNOWN;

    lex_begin_fetch(lex, word);

    if (lex->curr_text->len == 0) {
        word->type = WORD_TYPE_EOF;
        return CM_SUCCESS;
    }

    /* diagnose the word type preliminarily */
    word->type = lex_diagnose_word_type(lex);
    status = CM_SUCCESS;

    switch (word->type) {
        case WORD_TYPE_NUMBER:
            status = lex_fetch_num(lex, word);
            word->namable = CM_FALSE;
            break;

        case WORD_TYPE_COMPARE:
            status = lex_fetch_cmp(lex, word);
            word->namable = CM_FALSE;
            break;

        case WORD_TYPE_OPERATOR:
            lex_fetch_oper(lex, word);
            word->namable = CM_FALSE;
            break;

        case WORD_TYPE_COMMENT:
            status = lex_fetch_comment(lex, word);
            word->namable = CM_FALSE;
            break;

        case WORD_TYPE_PARAM:
            status = lex_fetch_param(lex, word);
            word->namable = CM_FALSE;
            break;

        case WORD_TYPE_PL_RANGE:
            lex_fetch_range_char(lex, word);
            word->namable = CM_FALSE;
            break;

        case WORD_TYPE_PL_TERM:
        case WORD_TYPE_SPEC_CHAR:
            lex_fetch_special_char(lex, word);
            word->namable = CM_FALSE;
            break;

        case WORD_TYPE_STRING:
            status = lex_fetch_string(lex, word);
            break;

        case WORD_TYPE_BRACKET:
            status = lex_fetch_brackets(lex, word, DIAGNOSE_BRACKETS(LEX_CURR));
            word->namable = CM_FALSE;
            break;

        case WORD_TYPE_VARIANT:
            status = lex_fetch_variant(lex, word, in_hint);
            break;

        case WORD_TYPE_ANCHOR:
            lex_fetch_anchor(lex, word);
            word->namable = CM_FALSE;
            break;

        case WORD_TYPE_DQ_STRING:
            status = lex_fetch_dquota(lex, word);
            break;

        case WORD_TYPE_PL_SETVAL:
            status = lex_fetch_pl_setval(lex, word);
            break;

        case WORD_TYPE_PL_NEW_COL:
        case WORD_TYPE_PL_OLD_COL:
            status = lex_fetch_new_or_old_col(lex, word);
            break;

        case WORD_TYPE_HEXADECIMAL:
            status = lex_fetch_hexadecimal_val(lex, word);
            word->namable = CM_FALSE;
            break;

        case WORD_TYPE_ARRAY:
            word->text.len = sizeof("array") - 1;
            status = CM_SUCCESS;
            break;

        default:
            LEX_THROW_ERROR_EX(LEX_LOC, ERR_LEX_SYNTAX_ERROR, "text is incorrect");
            return CM_ERROR;
    }

    return status;
}

status_t lex_fetch(lex_t *lex, word_t *word)
{
    do {
        if (lex_fetch_word(lex, word, CM_FALSE) != CM_SUCCESS) {
            return CM_ERROR;
        }
    } while (word->type == WORD_TYPE_COMMENT);

    return CM_SUCCESS;
}

status_t lex_fetch_in_hint(lex_t *lex, word_t *word)
{
    do {
        if (lex_fetch_word(lex, word, CM_TRUE) != CM_SUCCESS) {
            return CM_ERROR;
        }
    } while (word->type == WORD_TYPE_COMMENT);

    return CM_SUCCESS;
}

bool32 lex_match_head(lang_text_t *text, const char *word, uint32 *len)
{
    uint32 i;
    for (i = 0; i < text->len; i++) {
        if (word[i] == '\0') {
            *len = i;
            return (bool32)(IS_SPLITTER(text->str[i]) || IS_SPLITTER(word[i - 1]));
        }

        if (UPPER(word[i]) != UPPER(text->str[i])) {
            return CM_FALSE;
        }
    }

    *len = text->len;
    return (bool32)(word[i] == '\0');
}

status_t lex_extract_first(lang_text_t *text, word_t *word)
{
    lang_text_t ex_text = *text;
    lex_t lex;

    while (ex_text.len > 0 && CM_TEXT_BEGIN(&ex_text) == '(') {
        ex_text.str++;
        ex_text.len--;
        lex_trim(&ex_text);
    }

    lex_init(&lex, &ex_text);
    return lex_expected_fetch(&lex, word);
}

status_t lex_extract_first_ex(const lang_text_t *text, word_t *word)
{
    lex_t lex;

    lex_init(&lex, text);
    return lex_expected_fetch(&lex, word);
}

status_t lex_expected_fetch(lex_t *lex, word_t *word)
{
    word->ex_count = 0;

    if (lex_fetch(lex, word) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (word->type == WORD_TYPE_EOF) {
        LEX_THROW_ERROR_EX(LEX_LOC, ERR_LEX_SYNTAX_ERROR, "more text expected but terminated");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t lex_expected_fetch_word(lex_t *lex, const char *word)
{
    bool32 result = CM_FALSE;

    if (lex_try_fetch(lex, word, &result) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (!result) {
        LEX_THROW_ERROR_EX(LEX_LOC, ERR_LEX_SYNTAX_ERROR, "%s expected", word);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

/**
* Expect to fetch two continuous words.
* @note the comments are allowed among in these words
* @author
*/
status_t lex_expected_fetch_word2(lex_t *lex, const char *word1, const char *word2)
{
    bool32 result = CM_FALSE;

    if (lex_try_fetch2(lex, word1, word2, &result) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (!result) {
        LEX_THROW_ERROR_EX(LEX_LOC, ERR_LEX_SYNTAX_ERROR, "'%s %s' expected", word1, word2);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

/**
* Expect to fetch three continuous words.
* @note the comments are allowed among in these words
* @author
*/
status_t lex_expected_fetch_word3(lex_t *lex, const char *word1, const char *word2, const char *word3)
{
    bool32 result = CM_FALSE;
    if (lex_try_fetch3(lex, word1, word2, word3, &result) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (!result) {
        LEX_THROW_ERROR_EX(LEX_LOC, ERR_LEX_SYNTAX_ERROR, "'%s %s %s' expected", word1, word2, word3);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t lex_try_fetch_1of2(lex_t *lex, const char *word1, const char *word2, uint32 *matched_id)
{
    bool32 result = CM_FALSE;

    if (lex_try_fetch(lex, word1, &result) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (result) {
        *matched_id = 0;
        return CM_SUCCESS;
    }

    if (lex_try_fetch(lex, word2, &result) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (result) {
        *matched_id = 1;
        return CM_SUCCESS;
    }

    *matched_id = CM_INVALID_ID32;
    return CM_SUCCESS;
}

status_t lex_try_fetch_1of3(lex_t *lex, const char *word1, const char *word2, const char *word3,
                            uint32 *matched_id)
{
    bool32 result = CM_FALSE;

    if (lex_try_fetch_1of2(lex, word1, word2, matched_id) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (*matched_id != CM_INVALID_ID32) {
        return CM_SUCCESS;
    }

    if (lex_try_fetch(lex, word3, &result) != CM_SUCCESS) {
        return CM_ERROR;
    }

    *matched_id = result ? 2 : CM_INVALID_ID32;
    return CM_SUCCESS;
}

status_t lex_try_fetch_1ofn(lex_t *lex, uint32 *matched_id, int num, ...)
{
    bool32 result = CM_FALSE;
    va_list ap;
    int i = num;
    uint32 j = 0;

    va_start(ap, num);
    while (i > 0) {
        const char *word = (const char *)va_arg(ap, const char *);

        if (lex_try_fetch(lex, word, &result) != CM_SUCCESS) {
            va_end(ap);
            return CM_ERROR;
        }

        if (result) {
            *matched_id = j;
            va_end(ap);
            return CM_SUCCESS;
        }

        j++;
        i--;
    }
    va_end(ap);

    *matched_id = CM_INVALID_ID32;
    return CM_SUCCESS;
}

status_t lex_expected_fetch_1of2(lex_t *lex, const char *word1, const char *word2, uint32 *matched_id)
{
    if (lex_try_fetch_1of2(lex, word1, word2, matched_id) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (*matched_id == CM_INVALID_ID32) {
        LEX_THROW_ERROR_EX(LEX_LOC, ERR_LEX_SYNTAX_ERROR, "%s or %s expected", word1, word2);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t lex_expected_fetch_1of3(lex_t *lex, const char *word1, const char *word2, const char *word3,
                                 uint32 *matched_id)
{
    if (lex_try_fetch_1of3(lex, word1, word2, word3, matched_id) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (*matched_id == CM_INVALID_ID32) {
        LEX_THROW_ERROR_EX(LEX_LOC, ERR_LEX_SYNTAX_ERROR, "%s or %s or %s expected", word1, word2, word3);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t lex_expected_fetch_1ofn(lex_t *lex, uint32 *matched_id, int num, ...)
{
    int iret_snprintf;
    va_list ap;
    bool32 result = CM_FALSE;
    uint32 msg_len, remain_msg_len;
    int i = num;
    uint32 j = 0;
    char message[CM_MESSAGE_BUFFER_SIZE] = { 0 };

    va_start(ap, num);
    while (i > 0) {
        const char *word = (const char *)va_arg(ap, const char *);

        if (lex_try_fetch(lex, word, &result) != CM_SUCCESS) {
            va_end(ap);
            return CM_ERROR;
        }

        if (result) {
            *matched_id = j;
            va_end(ap);
            return CM_SUCCESS;
        }

        msg_len = (uint32)strlen(message);
        remain_msg_len = CM_MESSAGE_BUFFER_SIZE - msg_len;
        if (i != 1) {
            iret_snprintf = snprintf_s(message + msg_len, remain_msg_len, remain_msg_len - 1, "%s or ", word);
        } else {
            iret_snprintf = snprintf_s(message + msg_len, remain_msg_len, remain_msg_len - 1, "%s", word);
        }
        if (iret_snprintf == -1) {
            va_end(ap);
            CM_THROW_ERROR(ERR_SYSTEM_CALL, iret_snprintf);
            return CM_ERROR;
        }

        j++;
        i--;
    }
    va_end(ap);

    *matched_id = CM_INVALID_ID32;
    LEX_THROW_ERROR_EX(LEX_LOC, ERR_LEX_SYNTAX_ERROR, "%s expected", message);
    return CM_ERROR;
}

static inline num_errno_t lex_parse_size(lex_t *lex, word_t *word, int64 *size)
{
    num_errno_t err_no;

    word->np.excl_flag = NF_DOT | NF_EXPN | NF_NEGATIVE_SIGN;
    word->type = WORD_TYPE_EOF;
    err_no = lex_fetch_numpart(lex, word);
    CM_CHECK_NUM_ERRNO(err_no);

    err_no = cm_decide_numtype(&word->np, (cm_type_t *)&word->id);
    CM_CHECK_NUM_ERRNO(err_no);

    if (!CM_IS_INTEGER_TYPE(word->id)) {
        return NERR_EXPECTED_INTEGER;
    }

    if (word->type == WORD_TYPE_NUMBER) {
        return cm_numpart2bigint(&word->np, size);
    } else if (word->type == WORD_TYPE_SIZE) {
        return cm_numpart2size(&word->np, size);
    }

    return NERR_ERROR;
}

status_t lex_expected_fetch_size(lex_t *lex, int64 *size, int64 min_size, int64 max_size)
{
    word_t word;
    num_errno_t err_no;

    if (CM_INVALID_INT64 != min_size && CM_INVALID_INT64 != max_size) {
        if (min_size > max_size) {
            return CM_ERROR;
        }
    }

    if (lex_skip_comments(lex, &word) != CM_SUCCESS) {
        return CM_ERROR;
    }

    err_no = lex_parse_size(lex, &word, size);
    if (err_no != NERR_SUCCESS) {
        LEX_THROW_ERROR_EX(word.loc, ERR_LEX_SYNTAX_ERROR, "size must be a positive long integer");
        return CM_ERROR;
    }

    if (CM_INVALID_INT64 != min_size && *size < min_size) {
        LEX_THROW_ERROR_EX(word.text.loc, ERR_LEX_SYNTAX_ERROR, "size value is smaller "
                              "than minimun(" PRINT_FMT_INT64 ") required",
                              min_size);
        return CM_ERROR;
    }

    if (CM_INVALID_INT64 != max_size && *size > max_size) {
        LEX_THROW_ERROR_EX(word.text.loc, ERR_LEX_SYNTAX_ERROR, "size value is bigger "
                              "than maximum(" PRINT_FMT_INT64 ") required",
                              max_size);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t lex_expected_fetch_int32(lex_t *lex, int32 *size)
{
    word_t word;
    num_errno_t err_no;

    if (lex_skip_comments(lex, &word) != CM_SUCCESS) {
        return CM_ERROR;
    }

    // for an integer dot, expn, size are not allowed
    word.np.excl_flag = NF_DOT | NF_EXPN | NF_SZ_INDICATOR;
    word.type = WORD_TYPE_EOF;
    err_no = lex_fetch_numpart(lex, &word);
    if (err_no != NERR_SUCCESS) {
        LEX_THROW_ERROR_EX(word.loc, ERR_LEX_SYNTAX_ERROR, "invalid integer");
        return CM_ERROR;
    }

    if (word.type != WORD_TYPE_NUMBER) {
        LEX_THROW_ERROR_EX(word.loc, ERR_LEX_SYNTAX_ERROR, "invalid integer");
        return CM_ERROR;
    }

    err_no = cm_numpart2int(&word.np, size);
    if (err_no != NERR_SUCCESS) {
        LEX_THROW_ERROR_EX(word.loc, ERR_LEX_SYNTAX_ERROR, "invalid integer");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t lex_expected_fetch_uint32(lex_t *lex, uint32 *num)
{
    word_t word;
    num_errno_t err_no;

    if (lex_skip_comments(lex, &word) != CM_SUCCESS) {
        return CM_ERROR;
    }

    // for an integer dot, expn, size are not allowed
    word.np.excl_flag = NF_DOT | NF_EXPN | NF_SZ_INDICATOR | NF_NEGATIVE_SIGN;
    word.type = WORD_TYPE_EOF;
    err_no = lex_fetch_numpart(lex, &word);
    if (err_no != NERR_SUCCESS) {
        LEX_THROW_ERROR_EX(word.loc, ERR_LEX_SYNTAX_ERROR, "unsigned integer expected");
        return CM_ERROR;
    }

    if (word.type != WORD_TYPE_NUMBER) {
        LEX_THROW_ERROR_EX(word.loc, ERR_LEX_SYNTAX_ERROR, "unsigned integer expected");
        return CM_ERROR;
    }

    err_no = cm_numpart2uint32(&word.np, num);
    if (err_no != NERR_SUCCESS) {
        LEX_THROW_ERROR_EX(word.loc, ERR_LEX_SYNTAX_ERROR, "unsigned integer expected");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t lex_expected_fetch_int64(lex_t *lex, int64 *size)
{
    word_t word;
    num_errno_t err_no;

    if (lex_skip_comments(lex, &word) != CM_SUCCESS) {
        return CM_ERROR;
    }

    word.np.excl_flag = NF_DOT | NF_EXPN | NF_SZ_INDICATOR;
    word.type = WORD_TYPE_EOF;
    err_no = lex_fetch_numpart(lex, &word);
    if (err_no != NERR_SUCCESS) {
        LEX_THROW_ERROR_EX(word.loc, ERR_LEX_SYNTAX_ERROR, "invalid bigint");
        return CM_ERROR;
    }

    if (word.type != WORD_TYPE_NUMBER) {
        LEX_THROW_ERROR_EX(word.loc, ERR_LEX_SYNTAX_ERROR, "invalid bigint");
        return CM_ERROR;
    }

    err_no = cm_numpart2bigint(&word.np, size);
    if (err_no != NERR_SUCCESS) {
        LEX_THROW_ERROR_EX(word.loc, ERR_LEX_SYNTAX_ERROR, "invalid bigint");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t lex_expected_fetch_uint64(lex_t *lex, uint64 *size)
{
    word_t word;
    num_errno_t err_no;

    if (lex_skip_comments(lex, &word) != CM_SUCCESS) {
        return CM_ERROR;
    }

    // for an uint64, dot, negative, expn, size are not allowed
    word.np.excl_flag = NF_DOT | NF_NEGATIVE_SIGN | NF_EXPN | NF_SZ_INDICATOR;
    word.type = WORD_TYPE_EOF;
    err_no = lex_fetch_numpart(lex, &word);
    if (err_no != NERR_SUCCESS) {
        LEX_THROW_ERROR_EX(word.loc, ERR_LEX_SYNTAX_ERROR, "invalid uint64");
        return CM_ERROR;
    }

    if (word.type != WORD_TYPE_NUMBER) {
        LEX_THROW_ERROR_EX(word.loc, ERR_LEX_SYNTAX_ERROR, "invalid uint64");
        return CM_ERROR;
    }

    err_no = cm_numpart2uint64(&word.np, size);
    if (err_no != NERR_SUCCESS) {
        LEX_THROW_ERROR_EX(word.loc, ERR_LEX_SYNTAX_ERROR, "invalid uint64");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

/**
 * convert 0x00 ~ 0x7F to an ASCII char
 */
static inline status_t lex_word2hexchar(word_t *word, char *c)
{
    uint32 val;
    do {
        if (word->text.txt.len != 4) {
            break;
        }
        if (!CM_IS_HEX(word->text.txt.str[2]) || !CM_IS_HEX(word->text.txt.str[3])) {
            break;
        }
        val = cm_hex2int8(word->text.txt.str[2]);
        val <<= 4;
        val += cm_hex2int8(word->text.txt.str[3]);
        if (val > 127) {
            break;
        }
        *c = (char)val;
        return CM_SUCCESS;
    } while (0);

    LEX_THROW_ERROR_EX(word->loc, ERR_LEX_SYNTAX_ERROR, "invalid hexdecimal character format, \\x00 ~ \\x7F is ok");
    return CM_ERROR;
}

/**
 * conver string 0x00 ~ 0x7F to an ASCII char
 *
 */
static inline status_t lex_str2hexchar(const char *str, char *c)
{
    uint32 val;
    do {
        if (strlen(str) != 4) {
            break;
        }
        if (!CM_IS_HEX(str[2]) || !CM_IS_HEX(str[3])) {
            break;
        }
        val = cm_hex2int8(str[2]);
        val <<= 4;
        val += cm_hex2int8(str[3]);
        if (val > 127) {
            break;
        }
        *c = (char)val;
        return CM_SUCCESS;
    } while (0);

    return CM_ERROR;
}

typedef struct {
    char *key;
    char value;
} char_map_t;

#define GS_MAX_KEY_STR_LEN  6  // "\\\""

static const char_map_t g_supported_escape_char[] = {
    { "\\a",  '\a' },
    { "\\t",  '\t' },
    { "\\n",  '\n' },
    { "\\r",  '\r' },
    { "\\?",  '?' },
    { "\\\"", '\"' },
    { "\\o",  '\0' },
    { "\\0",  '\0' },
    { "\\v",  '\v' },
    { "\\f",  '\f' },
};

/**
 * Parsing string into one character
 */
status_t lex_expected_fetch_asciichar(lex_t *lex, char *c, bool32 allow_empty_char)
{
    word_t word;
    bool32 cond = CM_FALSE;

    do {
        if (lex_expected_fetch_string(lex, &word) != CM_SUCCESS) break;

        if (CM_IS_EMPTY(&word.text.txt)) {
            if (!allow_empty_char) break;
            *c = CM_INVALID_INT8;
            return CM_SUCCESS;
        }

        if (word.text.len == 1) {
            if (!CM_IS_ASCII(word.text.str[0])) break;
            *c = word.text.str[0];
            return CM_SUCCESS;
        }

        // escaped char = '
        cond = (word.text.len == 2)
               && CM_TEXT_BEGIN(&word.text.txt) == '\''
               && CM_TEXT_SECOND(&word.text.txt) == '\'';
        if (cond) {
            *c = '\'';
            return CM_SUCCESS;
        }

        // handing escaped char  \0x
        cond = CM_TEXT_BEGIN(&word.text.txt) == '\\'
               && CM_TEXT_SECOND(&word.text.txt) == 'x';
        if (cond) {
            return lex_word2hexchar(&word, c);
        }

        // handing escaped char  \,  ascii_char = g_supported_escape_char
        cond = CM_TEXT_BEGIN(&word.text.txt) == '\\' && word.text.txt.len < GS_MAX_KEY_STR_LEN;
        if (cond) {
            for (uint32 i = 0; i < sizeof(g_supported_escape_char) / sizeof(char_map_t); i++) {
                if (cm_compare_text_str_ins(&word.text.txt, g_supported_escape_char[i].key) == 0) {
                    *c = g_supported_escape_char[i].value;
                    return CM_SUCCESS;
                }
            }
        }
    } while (0);

    LEX_THROW_ERROR_EX(word.loc, ERR_LEX_SYNTAX_ERROR, "single ASCII character expected");
    return CM_ERROR;
}

/**
 * Parsing string, Specially hex (\x00 ~ \x7F), escape characters(like \a \t)
 */
status_t lex_expected_fetch_str(lex_t *lex, char *str, uint32 str_max_length, char *key_word_info)
{
    word_t word;
    uint32 i;
    uint32 j = 0;
    do {
        if (lex_expected_fetch_string(lex, &word) != CM_SUCCESS) break;
        if (CM_IS_EMPTY(&word.text.txt)) break;

        if (word.text.len > str_max_length) {
            LEX_THROW_ERROR_EX(word.loc, ERR_LEX_SYNTAX_ERROR, "%s is too long, max length is %d", key_word_info,
                str_max_length);
            return CM_ERROR;
        }

        for (i = 0; i < word.text.len; i++) {
            // Process hex characters
            // Note: \x00 ~ \x7F will be resolved to a char, others (like \x80~\xFF  \xGG) will not be changed.
            if (word.text.str[i] == '\\' && i + 3 < word.text.len && word.text.str[i + 1] == 'x') {
                char hex_str[5];
                hex_str[0] = '\\';
                hex_str[1] = 'x';
                hex_str[2] = word.text.str[i + 2];
                hex_str[3] = word.text.str[i + 3];
                hex_str[4] = '\0';

                char ret_c;

                // if resolve hex to char successfully, skip 3 characters.
                // otherwise, these four characters will be resolved as common characters
                if (CM_SUCCESS == lex_str2hexchar(hex_str, &ret_c)) {
                    str[j] = ret_c;
                    j++;

                    i += 3;
                    continue;
                }
            }
            // Note:others (like \x80~\xFF  \xGG) will not be changed, so there is no else
            // Process escape characters
            if (word.text.str[i] == '\\' && i + 1 < word.text.len) {
                char key[3];
                key[0] = '\\';
                key[1] = word.text.str[i + 1];
                key[2] = '\0';

                text_t key_text;
                key_text.str = key;
                key_text.len = (uint32)strlen(key);

                bool32 key_in_map = 0;

                for (uint32 temp = 0; temp < sizeof(g_supported_escape_char) / sizeof(char_map_t); temp++) {
                    if (cm_compare_text_str_ins(&key_text, g_supported_escape_char[temp].key) == 0) {
                        str[j] = g_supported_escape_char[temp].value;
                        j++;

                        // Notice: One character must be skipped, because it has been handled.
                        i++;

                        key_in_map = 1;

                        break;
                    }
                }

                if (!key_in_map) {
                    str[j] = word.text.str[i];
                    j++;
                }
            } else {
                // Process common characters
                str[j] = word.text.str[i];
                j++;
            }
        }
        str[j] = '\0';

        return CM_SUCCESS;
    } while (0);

    LEX_THROW_ERROR_EX(word.loc, ERR_LEX_SYNTAX_ERROR, "fetch %s failed.", key_word_info);
    return CM_ERROR;
}

status_t lex_expected_fetch_string(lex_t *lex, word_t *word)
{
    if (lex_expected_fetch(lex, word) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (word->type != WORD_TYPE_STRING) {
        LEX_THROW_ERROR_EX(LEX_LOC, ERR_LEX_SYNTAX_ERROR, "'...' expected but %s found", W2S(word));
        return CM_ERROR;
    }

    LEX_REMOVE_WRAP(word);
    return CM_SUCCESS;
}

status_t lex_expected_fetch_dqstring(lex_t *lex, word_t *word)
{
    lex_begin_fetch(lex, word);

    if (lex_fetch_dquota(lex, word) != CM_SUCCESS) {
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

/* Fetch a string that enclosed by ("), ('), (`) */
status_t lex_expected_fetch_enclosed_string(lex_t *lex, word_t *word)
{
    lex_begin_fetch(lex, word);

    char qchar = LEX_CURR;
    if (qchar != '"' && qchar != '\'' && qchar != '`') {
        LEX_THROW_ERROR_EX(lex->loc, ERR_LEX_SYNTAX_ERROR, "expected an enclosed char: (\"), (\'), (`)");
        return CM_ERROR;
    }

    if (lex_fetch_quota(lex, word, qchar) != CM_SUCCESS) {
        return CM_ERROR;
    }

    CM_REMOVE_ENCLOSED_CHAR(&word->text);
    return CM_SUCCESS;
}

/**
 * fetch   schema.table
 * + word  The word representation of schema.table
 */
status_t lex_expected_fetch_name(lex_t *lex, word_t *word, text_buf_t *tbl_textbuf)
{
    bool32 result = CM_FALSE;
    word_t ex_word = { 0 };

    word->ex_count = 0;
    CM_RETURN_IFERR(lex_expected_fetch_variant(lex, word));
    CM_RETURN_IFERR(lex_try_fetch_char(lex, '.', &result));

    if (result) {  // dot is found
        if (lex_expected_fetch_extra(lex, &ex_word) != CM_SUCCESS) {
            return CM_ERROR;
        }
        word->ex_words[word->ex_count].text = ex_word.text;
        word->ex_words[word->ex_count].type = ex_word.type;
        word->ex_count++;
    }

    // if textbuf is not null, set the buf with user.tbl_name
    if (tbl_textbuf == NULL) {
        return CM_SUCCESS;
    }

    do {
        if (word->type == WORD_TYPE_DQ_STRING) {
            if (!cm_buf_append_char(tbl_textbuf, *word->begin_addr)) break;
        }
        if (!cm_buf_append_text(tbl_textbuf, &word->text.txt)) break;
        if (word->type == WORD_TYPE_DQ_STRING) {
            if (!cm_buf_append_char(tbl_textbuf, *word->begin_addr)) break;
        }
        if (result) {
            if (!cm_buf_append_str(tbl_textbuf, ".")) break;
            if (ex_word.type == WORD_TYPE_DQ_STRING) {
                if (!cm_buf_append_char(tbl_textbuf, *ex_word.begin_addr)) break;
            }
            if (!cm_buf_append_text(tbl_textbuf, &ex_word.text.txt)) break;
            if (ex_word.type == WORD_TYPE_DQ_STRING) {
                if (!cm_buf_append_char(tbl_textbuf, *ex_word.begin_addr)) break;
            }
        }
        return CM_SUCCESS;
    } while (0);

    LEX_THROW_ERROR_EX(word->text.loc, ERR_LEX_SYNTAX_ERROR, "object name is too long");
    return CM_ERROR;
}

status_t lex_expected_fetch_variant(lex_t *lex, word_t *word)
{
    if (lex_expected_fetch(lex, word) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (!IS_VARIANT(word)) {
        LEX_THROW_ERROR_EX(word->text.loc, ERR_LEX_SYNTAX_ERROR, "invalid variant/object name was found");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t lex_expected_fetch_num(lex_t *lex, word_t *word)
{
    if (lex_fetch(lex, word) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (word->type != WORD_TYPE_NUMBER) {
        LEX_THROW_ERROR_EX(LEX_LOC, ERR_LEX_SYNTAX_ERROR, "number expected but %s found", W2S(word));
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t lex_expected_fetch_comp(lex_t *lex, word_t *word)
{
    if (lex_expected_fetch(lex, word) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (word->type != WORD_TYPE_COMPARE) {
        LEX_THROW_ERROR_EX(LEX_LOC, ERR_LEX_SYNTAX_ERROR, "= expected but %s found", W2S(word));
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t lex_expected_end(lex_t *lex)
{
    word_t word;
    if (lex_fetch(lex, &word) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (word.type != WORD_TYPE_EOF) {
        LEX_THROW_ERROR_EX(LEX_LOC, ERR_LEX_SYNTAX_ERROR, "expected end but %s found", W2S(&word));
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t lex_try_fetch_comment(lex_t *lex, word_t *word, bool32 *result)
{
    lang_text_t *text = lex->curr_text;
    lex_trim(text);

    *result = CM_FALSE;
    if (text->len < 2) {
        return CM_SUCCESS;
    }

    if ((*text->str == '-' && text->str[1] == '-') || (*text->str == '/' && text->str[1] == '*')) {
        *result = CM_TRUE;
        return lex_fetch_comment(lex, word);
    }

    return CM_SUCCESS;
}

static inline void lex_extract_hint_content(word_t *word)
{
    word->text.len -= 5;  // hint header /* + */
    word->text.str += 3;
    word->text.loc.column += 3;
    lex_trim(&word->text);
}

status_t lex_try_fetch_hint_comment(lex_t *lex, word_t *word, bool32 *result)
{
    lang_text_t *text = lex->curr_text;
    lex_trim(text);

    *result = CM_FALSE;

    // hint format: /* +[space][hint_items][space] */
    if (text->len < 5) {
        return CM_SUCCESS;
    }
    if (*text->str == '/' && text->str[1] == '*' && text->str[2] == '+') {
        *result = CM_TRUE;
        lex_begin_fetch(lex, word);
        if (lex_fetch_comment(lex, word) != CM_SUCCESS) {
            return CM_ERROR;
        }
        lex_extract_hint_content(word);
    }

    return CM_SUCCESS;
}

status_t lex_try_fetch_variant(lex_t *lex, word_t *word, bool32 *result)
{
    if (lex_fetch(lex, word) != CM_SUCCESS) {
        return CM_ERROR;
    }

    *result = IS_VARIANT(word);

    if (!(*result)) {
        lex_back(lex, word);
    }

    return CM_SUCCESS;
}

status_t lex_try_fetch_variant_excl(lex_t *lex, word_t *word, uint32 excl, bool32 *result)
{
    if (lex_fetch(lex, word) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (word->type & excl) {
        lex_back(lex, word);
        *result = CM_FALSE;
        return CM_SUCCESS;
    }

    *result = IS_VARIANT(word);

    if (!(*result)) {
        lex_back(lex, word);
    }

    return CM_SUCCESS;
}

status_t lex_skip_comments(lex_t *lex, word_t *word)
{
    bool32 result = CM_FALSE;

    do {
        if (lex_try_fetch_comment(lex, word, &result) != CM_SUCCESS) {
            return CM_ERROR;
        }
    } while (result);

    lex_begin_fetch(lex, word);
    return CM_SUCCESS;
}

status_t lex_try_fetch_char(lex_t *lex, char c, bool32 *result)
{
    lang_text_t *text = lex->curr_text;
    if (lex_skip_comments(lex, NULL) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (text->len == 0 || *text->str != c) {
        *result = CM_FALSE;
        return CM_SUCCESS;
    }

    if ((c == '.') && (LEX_NEXT == '.')) {
        *result = CM_FALSE;
        return CM_SUCCESS;
    }

    (void)lex_skip(lex, 1);
    *result = CM_TRUE;
    return CM_SUCCESS;
}

status_t lex_try_fetch(lex_t *lex, const char *word, bool32 *result)
{
    uint32 len;

    if (lex_skip_comments(lex, NULL) != CM_SUCCESS) {
        return CM_ERROR;
    }

    if (lex_match_head(lex->curr_text, word, &len)) {
        *result = CM_TRUE;
        (void)lex_skip(lex, len);
    } else {
        *result = CM_FALSE;
    }

    return CM_SUCCESS;
}

/**
* Try to fetch n continuous words.
* @note the comments are allowed among in these words
* @author
*/
status_t lex_try_fetch_n(lex_t *lex, uint32 n, const char **words, bool32 *result)
{
    LEX_SAVE(lex);

    for (uint32 i = 0; i < n; i++) {
        if (lex_try_fetch(lex, words[i], result) != CM_SUCCESS) {
            return CM_ERROR;
        }
        if (!(*result)) {
            LEX_RESTORE(lex);
            return CM_SUCCESS;
        }
    }

    return CM_SUCCESS;
}

status_t lex_try_fetch_anyone(lex_t *lex, uint32 n, const char **words, bool32 *result)
{
    LEX_SAVE(lex);

    for (uint32 i = 0; i < n; i++) {
        if (lex_try_fetch(lex, words[i], result) != CM_SUCCESS) {
            return CM_ERROR;
        }
        if ((*result)) {
            return CM_SUCCESS;
        }
    }

    LEX_RESTORE(lex);
    return CM_SUCCESS;
}

/**
 * Try to fetch two continuous words.
 * @note the comments are allowed among in these words
 * @author
 */
status_t lex_try_fetch2(lex_t *lex, const char *word1, const char *word2, bool32 *result)
{
    const char *words[2] = { word1, word2 };
    return lex_try_fetch_n(lex, 2, (const char **)words, result);
}

/**
* Try to fetch three continuous words.
* @note the comments are allowed among in these words
* @author
*/
status_t lex_try_fetch3(lex_t *lex, const char *word1, const char *word2, const char *word3, bool32 *result)
{
    const char *words[3] = { word1, word2, word3 };
    return lex_try_fetch_n(lex, 3, (const char **)words, result);
}
/**
* Try to fetch four continuous words.
* @note the comments are allowed among in these words
* @author
*/
status_t lex_try_fetch4(lex_t *lex, const char *word1, const char *word2, const char *word3, const char *word4,
                        bool32 *result)
{
    const char *words[4] = { word1, word2, word3, word4 };
    return lex_try_fetch_n(lex, 4, (const char **)words, result);
}

status_t lex_try_match_records(lex_t *lex, const word_record_t *records, uint32 num, uint32 *matched_id)
{
    bool32 result = CM_FALSE;

    for (uint32 i = 0; i < num; i++) {
        if (lex_try_fetch_tuple(lex, &records[i].tuple, &result) != CM_SUCCESS) {
            return CM_ERROR;
        }
        if (result) {
            *matched_id = records[i].id;
            return CM_SUCCESS;
        }
    }

    *matched_id = CM_INVALID_ID32;
    return CM_SUCCESS;
}

status_t lex_fetch_to_char(lex_t *lex, word_t *word, char c)
{
    do {
        if (lex_fetch_word(lex, word, CM_FALSE) != CM_SUCCESS) {
            return CM_ERROR;
        }
    } while (!(word->type == WORD_TYPE_EOF || IS_SPEC_CHAR(word, c)));

    return CM_SUCCESS;
}

status_t lex_inc_special_word(lex_t *lex, const char *word, bool32 *result)
{
    word_t tmp_word;

    LEX_SAVE(lex);
    *result = CM_FALSE;

    do {
        if (lex_fetch(lex, &tmp_word) != CM_SUCCESS) {
            LEX_RESTORE(lex);
            return CM_ERROR;
        }

        if (cm_text_str_equal_ins(&tmp_word.text.txt, word)) {
            LEX_RESTORE(lex);
            *result = CM_TRUE;
            return CM_SUCCESS;
        }
    } while (!(tmp_word.type == WORD_TYPE_EOF));

    LEX_RESTORE(lex);
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
