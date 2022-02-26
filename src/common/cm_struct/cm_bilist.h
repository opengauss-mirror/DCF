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
 * cm_bilist.h
 *
 *
 * IDENTIFICATION
 *    src/common/cm_struct/cm_bilist.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_BILIST_H__
#define __CM_BILIST_H__

#include "cm_debug.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BILIST_NODE_OF(type, node, field) ((type *)((char *)(node)-OFFSET_OF(type, field)))

typedef struct st_bilist_node {
    struct st_bilist_node *prev;
    struct st_bilist_node *next;
} bilist_node_t;

typedef struct st_bilist {
    bilist_node_t *head;
    bilist_node_t *tail;
    uint32 count;
} bilist_t;

#define BINODE_NEXT(node) (node)->next
#define BINODE_PREV(node) (node)->prev

static inline void cm_bilist_init(bilist_t *bilist)
{
    bilist->count = 0;
    bilist->head = bilist->tail = NULL;
}

static inline bilist_node_t *cm_bilist_tail(bilist_t *bilist)
{
    return bilist->tail;
}

static inline bilist_node_t *cm_bilist_head(bilist_t *bilist)
{
    return bilist->head;
}

static inline bool32 cm_bilist_empty(const bilist_t *bilist)
{
    return bilist->count == 0;
}

static inline void cm_bilist_concat(bilist_t *bilist1, bilist_t *bilist2)
{
    if (bilist1->count == 0) {
        *bilist1 = *bilist2;
        return;
    }
    bilist1->tail->next = bilist2->head;
    if (bilist2->head != NULL) {
        bilist2->head->prev = bilist1->tail;
    }

    bilist1->tail = bilist2->tail;
    bilist1->count += bilist2->count;
}

void cm_bilist_del_tail(bilist_t *bilist);
void cm_bilist_del_head(bilist_t *bilist);
void cm_bilist_del(bilist_node_t *node, bilist_t *bilist);
void cm_bilist_add_tail(bilist_node_t *node, bilist_t *bilist);
void cm_bilist_add_head(bilist_node_t *node, bilist_t *bilist);
void cm_bilist_add_prev(bilist_node_t *node, bilist_node_t *where, bilist_t *bilist);
void cm_bilist_add_next(bilist_node_t *node, bilist_node_t *where, bilist_t *bilist);
bilist_node_t* cm_bilist_pop_back(bilist_t *bilist);
bilist_node_t* cm_bilist_pop_first(bilist_t *bilist);

#ifdef __cplusplus
}
#endif

#endif
