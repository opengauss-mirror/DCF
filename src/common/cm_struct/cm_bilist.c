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
 * cm_bilist.c
 *
 *
 * IDENTIFICATION
 *    src/common/cm_struct/cm_bilist.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_bilist.h"
#include "cm_log.h"

void cm_bilist_del_tail(bilist_t *bilist)
{
    if (cm_bilist_pop_back(bilist) == NULL) {
        LOG_DEBUG_INF("list is null");
    }
}

bilist_node_t* cm_bilist_pop_back(bilist_t *bilist)
{
    if (bilist->count == 0) {
        return NULL;
    }

    bilist_node_t *tail = bilist->tail;

    if (bilist->head != bilist->tail) {
        bilist->tail = bilist->tail->prev;
        bilist->tail->next = NULL;
    } else {
        bilist->head = NULL;
        bilist->tail = NULL;
    }
    bilist->count--;
    tail->prev = NULL;
    tail->next = NULL;
    return tail;
}

void cm_bilist_del_head(bilist_t *bilist)
{
    if (cm_bilist_pop_first(bilist) == NULL) {
        LOG_DEBUG_INF("list is null");
    }
}

bilist_node_t* cm_bilist_pop_first(bilist_t *bilist)
{
    if (bilist->count == 0) {
        return NULL;
    }
    bilist_node_t *head = bilist->head;
    if (bilist->head != bilist->tail) {
        bilist->head = bilist->head->next;
        bilist->head->prev = NULL;
    } else {
        bilist->head = NULL;
        bilist->tail = NULL;
    }
    head->prev = NULL;
    head->next = NULL;
    bilist->count--;
    return head;
}

void cm_bilist_del(bilist_node_t *node, bilist_t *bilist)
{
    if (node == bilist->head) {
        cm_bilist_del_head(bilist);
        return;
    }

    if (node == bilist->tail) {
        cm_bilist_del_tail(bilist);
        return;
    }

    if (node->prev == NULL || node->next == NULL) {
        return;
    }
    CM_ASSERT(bilist->count > 0);
    node->prev->next = node->next;
    node->next->prev = node->prev;
    node->prev = NULL;
    node->next = NULL;
    bilist->count--;
}

void cm_bilist_add_tail(bilist_node_t *node, bilist_t *bilist)
{
    if (bilist->tail != NULL) {
        node->prev = bilist->tail;
        node->next = NULL;
        bilist->tail->next = node;
        bilist->tail = node;
    } else {
        node->next = NULL;
        node->prev = NULL;
        bilist->head = node;
        bilist->tail = node;
    }
    bilist->count++;
}

void cm_bilist_add_head(bilist_node_t *node, bilist_t *bilist)
{
    if (bilist->head != NULL) {
        node->next = bilist->head;
        node->prev = NULL;
        bilist->head->prev = node;
        bilist->head = node;
    } else {
        node->next = NULL;
        node->prev = NULL;
        bilist->head = node;
        bilist->tail = node;
    }
    bilist->count++;
}

void cm_bilist_add_prev(bilist_node_t *node, bilist_node_t *where, bilist_t *bilist)
{
    if (where == bilist->head) {
        cm_bilist_add_head(node, bilist);
        return;
    }
    node->prev = where->prev;
    node->next = where;
    where->prev = node;
    node->prev->next = node;
    bilist->count++;
}

void cm_bilist_add_next(bilist_node_t *node, bilist_node_t *where, bilist_t *bilist)
{
    if (where == bilist->tail) {
        cm_bilist_add_tail(node, bilist);
        return;
    }
    node->next = where->next;
    node->prev = where;
    where->next = node;
    node->next->prev = node;
    bilist->count++;
}
